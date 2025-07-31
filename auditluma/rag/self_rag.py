"""
Self-RAG (自检索增强生成) 模块实现
提供代码审计过程中的上下文检索和知识增强功能
"""

import os
from typing import List, Dict, Any, Optional, Tuple, Union
import json
import numpy as np
from pathlib import Path
import hashlib
from dataclasses import dataclass, field
import asyncio

from loguru import logger
from auditluma.config import Config

# 导入可选依赖，如果不可用则提供优雅的退化
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logger.warning("FAISS 未安装，将使用简单向量存储")

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False
    logger.warning("Tiktoken 未安装，将使用简单分词器")

from auditluma.models.code import SourceFile, CodeUnit


@dataclass
class Document:
    """表示知识库中的文档"""
    id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None


class SimpleEmbedder:
    """一个简单的嵌入模型，当没有更高级的模型可用时使用"""
    def __init__(self, dimensions: int = 128):
        self.dimensions = dimensions
    
    def embed(self, text: str) -> List[float]:
        """从文本生成一个简单的嵌入向量"""
        # 使用文本的哈希值生成伪随机向量
        hash_obj = hashlib.md5(text.encode('utf-8'))
        seed = int(hash_obj.hexdigest(), 16) % (2**32)
        np.random.seed(seed)
        
        # 归一化向量
        embedding = np.random.randn(self.dimensions).astype(np.float32)
        embedding = embedding / np.linalg.norm(embedding)
        
        return embedding.tolist()
    
    async def aembed(self, text: str) -> List[float]:
        """异步嵌入方法（实际上就是调用同步方法）"""
        return self.embed(text)


class OpenAIEmbedder:
    """使用OpenAI API的嵌入模型"""
    def __init__(self, model_name: str = "text-embedding-3-small", provider: str = None):
        # 从model_name中解析模型名称和提供商（如果使用了model@provider格式）
        parsed_model, parsed_provider = Config.parse_model_spec(model_name)
        
        # 如果从model_name解析出了提供商，优先使用它
        if parsed_provider:
            self.model_name = parsed_model
            provider = parsed_provider
            logger.info(f"从模型规范'{model_name}'中解析出模型名称'{parsed_model}'和提供商'{parsed_provider}'")
        else:
            self.model_name = model_name
        
        # 使用指定的提供商或默认提供商
        provider = provider or Config.agent.default_provider
        provider_config = Config.get_llm_provider_config(provider)
        self.api_key = provider_config.api_key
        self.base_url = provider_config.base_url
        
        # 初始化API客户端，禁用自动检测功能
        import httpx
        from openai import AsyncOpenAI
        
        # 创建带有超时设置的httpx客户端
        timeout_settings = httpx.Timeout(
            connect=30.0,
            read=60.0,
            write=30.0,
            pool=15.0
        )
        http_client = httpx.AsyncClient(timeout=timeout_settings)
        
        # 直接使用指定提供商初始化客户端，不通过init_llm_client函数
        self.client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            http_client=http_client,
            max_retries=3
        )
        
        logger.info(f"初始化嵌入模型: {self.model_name}, 使用提供商: {provider}")
    
    async def aembed(self, text: str) -> List[float]:
        """异步生成嵌入向量"""
        response = await self.client.embeddings.create(
            model=self.model_name,
            input=text
        )
        return response.data[0].embedding


class OllamaEmbedder:
    """使用Ollama本地API的嵌入模型"""
    def __init__(self, model_name: str = "mxbai-embed-large:latest", provider: str = None):
        # 从model_name中解析模型名称和提供商（如果使用了model@provider格式）
        parsed_model, parsed_provider = Config.parse_model_spec(model_name)
        
        # 如果从model_name解析出了提供商，优先使用它
        if parsed_provider:
            self.model_name = parsed_model
            provider = parsed_provider
            logger.info(f"从模型规范'{model_name}'中解析出模型名称'{parsed_model}'和提供商'{parsed_provider}'")
        else:
            self.model_name = model_name
        
        # 使用指定的提供商或默认使用ollama_emd提供商
        provider = provider or "ollama_emd"
        provider_config = Config.get_llm_provider_config(provider)

        # 从配置中获取API端点
        self.base_url = provider_config.base_url
        
        # 初始化API客户端
        import httpx
        
        # 创建带有超时设置的httpx客户端
        timeout_settings = httpx.Timeout(
            connect=30.0,
            read=60.0,
            write=30.0,
            pool=15.0
        )
        self.http_client = httpx.AsyncClient(timeout=timeout_settings)
        
        logger.info(f"初始化Ollama嵌入模型: {self.model_name}, API地址: {self.base_url}")
    
    async def aembed(self, text: str) -> List[float]:
        """异步生成嵌入向量且带有重试机制"""
        # 检查是否启用了模拟模式
        import os
        if os.environ.get("AUDITLUMA_MOCK_LLM", "").lower() in ["true", "1", "yes"]:
            logger.info("检测到模拟模式已启用，生成模拟嵌入向量")
            # 生成模拟嵌入向量
            import random
            random.seed(hash(text) % (2**32))  # 使用文本哈希作为种子，确保相同文本得到相同向量
            embedding = [random.uniform(-1, 1) for _ in range(1024)]
            # 归一化向量
            magnitude = sum(x*x for x in embedding) ** 0.5
            if magnitude > 0:
                embedding = [x/magnitude for x in embedding]
            logger.info(f"生成模拟嵌入向量，长度: {len(embedding)}")
            return embedding

        # Ollama的embeddings API格式
        payload = {
            "model": self.model_name,
            "input": text
        }
        
        # 尝试不同的API格式
        alternative_payloads = [
            # 标准格式
            {
                "model": self.model_name,
                "prompt": text
            },
            # 备选格式1，使用input而非prompt
            {
                "model": self.model_name,
                "input": text
            },
            # 备选格式2，添加额外参数
            {
                "model": self.model_name,
                "prompt": text,
                "options": {"temperature": 0.0}
            }
        ]
        
        # 最大重试次数
        max_retries = 3
        retry_delay = 2  # 初始重试延迟（秒）
        
        # 首先尝试标准格式
        current_payload = alternative_payloads[0]
        
        # 实现指数退避（exponential backoff）重试机制
        for attempt in range(max_retries):
            try:
                # 发送POST请求到Ollama API
                response = await self.http_client.post(
                    self.base_url,
                    json=current_payload,
                    timeout=30.0  # 增加超时时间
                )
                
                # 检查响应状态
                response.raise_for_status()
                response_data = response.json()
                
                # 从响应中提取嵌入向量
                # Ollama API返回的是 {"embedding": [...]} 格式
                if "embedding" in response_data:
                    logger.info(f"成功生成嵌入向量，长度: {len(response_data['embedding'])}")
                    return response_data["embedding"]
                else:
                    logger.error(f"Ollama嵌入响应格式错误: {response_data}")
                    raise ValueError("嵌入响应中没有找到embedding字段")
                    
            except Exception as e:
                error_str = str(e)
                
                # 如果是最后一次尝试或者已经尝试了所有可选格式
                if attempt == max_retries - 1:
                    logger.error(f"生成Ollama嵌入时出错 (重试{attempt+1}/{max_retries}): {e}")
                    
                    # 检查错误类型并提供详细信息
                    if "500" in error_str:
                        logger.error("服务器内部错误: 可能是模型不存在或配置错误 (尝试 'ollama pull mxbai-embed-large')")
                    elif "503" in error_str:
                        logger.error("服务不可用错误: 请确保Ollama正在运行且已加载嵌入模型")

                    # 如果还有其他可选格式可以尝试
                    payload_index = alternative_payloads.index(current_payload) + 1
                    if payload_index < len(alternative_payloads):
                        current_payload = alternative_payloads[payload_index]
                        logger.info(f"尝试备选API格式 {payload_index}")
                        # 重置尝试计数器
                        attempt = 0
                        continue
                    else:
                        # 所有格式均已尝试失败，检查是否可以使用模拟模式（默认为 false）
                        import os
                        mock_mode = os.environ.get("AUDITLUMA_MOCK_LLM", "false").lower()
                        if mock_mode in ["true", "1", "yes"]:
                            logger.info("Ollama嵌入API失败，使用模拟嵌入向量")
                            # 生成模拟嵌入向量
                            import random
                            random.seed(hash(text) % (2**32))  # 使用文本哈希作为种子，确保相同文本得到相同向量
                            embedding = [random.uniform(-1, 1) for _ in range(1024)]
                            # 归一化向量
                            magnitude = sum(x*x for x in embedding) ** 0.5
                            if magnitude > 0:
                                embedding = [x/magnitude for x in embedding]
                            logger.info(f"生成模拟嵌入向量，长度: {len(embedding)}")
                            return embedding
                        else:
                            # 所有格式均已尝试失败
                            raise
                
                # 否则记录错误并准备重试
                logger.warning(f"生成Ollama嵌入失败 (重试{attempt+1}/{max_retries}): {e}")
                
                # 等待一段时间后重试，并且使用指数退避算法增加重试间隔
                import asyncio
                await asyncio.sleep(retry_delay * (2 ** attempt))  # 2, 4, 8秒
                
                # 根据错误类型调整等待时间
                if "503" in error_str:
                    logger.info(f"检测到503错误，可能是模型正在加载，等待额外时间...")
                    await asyncio.sleep(5)  # 额外等待5秒
                elif "500" in error_str:
                    logger.info(f"检测到500错误，可能是请求格式错误，尝试不同格式...")
                    # 如果连续出现500错误，尝试切换请求格式
                    payload_index = alternative_payloads.index(current_payload) + 1
                    if payload_index < len(alternative_payloads):
                        current_payload = alternative_payloads[payload_index]
                        logger.info(f"切换到备选API格式 {payload_index}")
                        # 不重置尝试计数器，继续正常重试流程


class SimpleVectorStore:
    """一个简单的向量存储，当FAISS不可用时使用"""
    def __init__(self):
        self.documents: List[Document] = []
    
    def add(self, documents: List[Document]) -> None:
        """添加文档到存储"""
        self.documents.extend(documents)
    
    def search(self, query_embedding: List[float], k: int = 5) -> List[Tuple[Document, float]]:
        """搜索最相似的文档"""
        if not self.documents:
            return []
        
        query_embedding_np = np.array(query_embedding, dtype=np.float32)
        
        results = []
        for doc in self.documents:
            if doc.embedding:
                doc_embedding_np = np.array(doc.embedding, dtype=np.float32)
                # 计算余弦相似度
                similarity = np.dot(query_embedding_np, doc_embedding_np) / (
                    np.linalg.norm(query_embedding_np) * np.linalg.norm(doc_embedding_np)
                )
                results.append((doc, float(similarity)))
        
        # 按相似度排序
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:k]
    
    def save(self, path: str) -> None:
        """保存向量存储到文件"""
        data = {
            "documents": [
                {
                    "id": doc.id,
                    "content": doc.content,
                    "metadata": doc.metadata,
                    "embedding": doc.embedding
                }
                for doc in self.documents
            ]
        }
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def load(self, path: str) -> None:
        """从文件加载向量存储"""
        if not os.path.exists(path):
            logger.warning(f"向量存储文件不存在: {path}")
            return
        
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        self.documents = [
            Document(
                id=doc["id"],
                content=doc["content"],
                metadata=doc["metadata"],
                embedding=doc["embedding"]
            )
            for doc in data["documents"]
        ]
        
        logger.info(f"已加载 {len(self.documents)} 个文档到向量存储")


class FAISSVectorStore:
    """使用FAISS的高性能向量存储"""
    def __init__(self, dimensions: int = 1536):
        if not FAISS_AVAILABLE:
            raise ImportError("FAISS 未安装，请安装 faiss-cpu 或 faiss-gpu")
        
        self.dimensions = dimensions
        self.index = faiss.IndexFlatL2(dimensions)
        self.documents: List[Document] = []
        self.doc_ids_map: Dict[int, str] = {}  # 映射FAISS索引到文档ID
    
    def add(self, documents: List[Document]) -> None:
        """添加文档到FAISS索引"""
        if not documents:
            return
        
        vectors = []
        for i, doc in enumerate(documents):
            if doc.embedding:
                vectors.append(np.array(doc.embedding, dtype=np.float32))
                self.doc_ids_map[len(self.documents) + i] = doc.id
        
        if vectors:
            vectors_np = np.vstack(vectors).astype(np.float32)
            self.index.add(vectors_np)
            self.documents.extend(documents)
            logger.debug(f"添加了 {len(vectors)} 个向量到FAISS索引")
    
    def search(self, query_embedding: List[float], k: int = 5) -> List[Tuple[Document, float]]:
        """使用FAISS搜索最相似的文档"""
        if self.index.ntotal == 0:
            return []
        
        query_embedding_np = np.array([query_embedding], dtype=np.float32)
        distances, indices = self.index.search(query_embedding_np, k)
        
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.documents):
                doc = self.documents[idx]
                # 转换L2距离为相似度分数 (越小越相似，所以用1减去归一化值)
                similarity = 1.0 - (distances[0][i] / 100.0)  # 简单归一化
                # 确保在0-1范围内
                similarity = max(0.0, min(1.0, similarity))
                results.append((doc, float(similarity)))
        
        return results
    
    def save(self, path: str) -> None:
        """保存FAISS索引和文档到文件"""
        # 创建目录（如果不存在）
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # 保存FAISS索引
        index_path = f"{path}.index"
        faiss.write_index(self.index, index_path)
        
        # 保存文档和映射
        data = {
            "documents": [
                {
                    "id": doc.id,
                    "content": doc.content,
                    "metadata": doc.metadata,
                    # 不保存嵌入，因为它们已经在FAISS索引中
                }
                for doc in self.documents
            ],
            "doc_ids_map": self.doc_ids_map
        }
        
        with open(f"{path}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        logger.info(f"已保存FAISS索引和 {len(self.documents)} 个文档到 {path}")
    
    def load(self, path: str) -> None:
        """从文件加载FAISS索引和文档"""
        index_path = f"{path}.index"
        data_path = f"{path}.json"
        
        if not os.path.exists(index_path) or not os.path.exists(data_path):
            logger.warning(f"FAISS索引或数据文件不存在: {path}")
            return
        
        # 加载FAISS索引
        self.index = faiss.read_index(index_path)
        
        # 加载文档和映射
        with open(data_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        self.documents = [
            Document(
                id=doc["id"],
                content=doc["content"],
                metadata=doc["metadata"],
                embedding=None  # 嵌入存储在FAISS索引中
            )
            for doc in data["documents"]
        ]
        
        self.doc_ids_map = {int(k): v for k, v in data["doc_ids_map"].items()}
        
        logger.info(f"已加载FAISS索引和 {len(self.documents)} 个文档")


class SelfRAG:
    """Self-RAG 实现，提供自检索增强生成功能"""
    def __init__(self):
        self.config = Config.self_rag
        
        # 初始化嵌入模型
        embedding_model = self.config.embedding_model
        
        try:
            # 解析嵌入模型名称和提供商
            model_name, provider = Config.parse_model_spec(embedding_model)
            
            # 根据提供商类型选择合适的嵌入模型
            if provider == "ollama_emd":
                # 尝试使用Ollama嵌入模型，但也准备了简单嵌入器作为后备
                self.embedder = OllamaEmbedder(model_name=model_name, provider=provider)
                # 创建后备嵌入器
                self.fallback_embedder = SimpleEmbedder()
                logger.info(f"📚 传统Self-RAG系统 - 使用Ollama嵌入模型: {model_name} (已准备后备嵌入器)")
            else:
                # 默认使用OpenAI兼容的嵌入模型
                self.embedder = OpenAIEmbedder(model_name=embedding_model)
                # 从配置中获取模型名称，可能已在OpenAIEmbedder中通过parse_model_spec解析
                model_name = self.embedder.model_name
                logger.info(f"📚 传统Self-RAG系统 - 使用嵌入模型: {model_name}")
        except Exception as e:
            logger.warning(f"无法初始化嵌入模型: {e}")
            self.embedder = SimpleEmbedder()
            logger.info("回退到简单嵌入模型")
        
        # 确定嵌入维度 - Ollama mxbai-embed-large 使用1024维，OpenAI通常是1536维
        embedding_dimensions = 1024 if provider == "ollama_emd" else 1536
        
        # 初始化向量存储
        if self.config.vector_store == "faiss" and FAISS_AVAILABLE:
            self.vector_store = FAISSVectorStore(dimensions=embedding_dimensions)
            logger.info(f"使用FAISS向量存储 (维度: {embedding_dimensions})")
        else:
            self.vector_store = SimpleVectorStore()
            logger.info("使用简单向量存储")
        
        # 加载数据目录
        data_dir = Path("./data/kb")
        os.makedirs(data_dir, exist_ok=True)
        
        # 跟踪已处理的文件
        self.processed_files = set()
    
    async def add_source_file(self, file: SourceFile) -> None:
        """将源文件添加到知识库"""
        if file.id in self.processed_files:
            logger.debug(f"文件已存在于知识库中: {file.id}")
            return
        
        # 将文件分块
        chunks = self._chunk_text(file.content, self.config.chunk_size, self.config.chunk_overlap)
        
        # 创建文档
        documents = []
        for i, chunk in enumerate(chunks):
            doc_id = f"{file.id}_{i}"
            doc = Document(
                id=doc_id,
                content=chunk,
                metadata={
                    "file_id": file.id,
                    "file_path": str(file.path),
                    "file_name": file.name,
                    "chunk_index": i,
                    "file_type": file.file_type,
                    "chunk_start": i * (self.config.chunk_size - self.config.chunk_overlap)
                }
            )
            documents.append(doc)
        
        # 使用并发生成嵌入
        async def generate_embedding(doc):
            try:
                # 尝试使用主要嵌入器
                doc.embedding = await self.embedder.aembed(doc.content)
                return doc
            except Exception as e:
                logger.error(f"为文档生成嵌入时出错: {doc.id}, {e}")
                
                # 检查是否有后备嵌入器可用
                if hasattr(self, "fallback_embedder") and self.fallback_embedder is not None:
                    try:
                        logger.warning(f"尝试使用后备嵌入器生成嵌入: {doc.id}")
                        doc.embedding = await self.fallback_embedder.aembed(doc.content)
                        return doc
                    except Exception as fallback_error:
                        logger.error(f"后备嵌入器也失败: {fallback_error}")
                
                # 如果后备也失败或没有后备，返回None
                return None

        # 使用信号量限制并发数量，避免过多并发请求
        semaphore = asyncio.Semaphore(10)  # 控制最大并发数
        
        async def bounded_generate_embedding(doc):
            async with semaphore:
                return await generate_embedding(doc)
        
        # 并发生成所有文档的嵌入
        embedding_tasks = [bounded_generate_embedding(doc) for doc in documents]
        embedded_docs = await asyncio.gather(*embedding_tasks)
        
        # 过滤出成功生成嵌入的文档
        valid_docs = [doc for doc in embedded_docs if doc and doc.embedding]
        
        # 添加到向量存储
        if valid_docs:
            self.vector_store.add(valid_docs)
            self.processed_files.add(file.id)
            logger.info(f"已将文件添加到知识库: {file.id} ({len(valid_docs)}/{len(chunks)}个块)")
        else:
            logger.warning(f"文件 {file.id} 没有生成有效的嵌入，将作为无嵌入文件记录")
            self.register_file_without_embedding(file)
    
    def register_file_without_embedding(self, file: SourceFile) -> None:
        """仅记录文件但不生成嵌入
        
        在嵌入API调用失败或超时的情况下使用，允许系统继续分析而不阻塞
        
        Args:
            file: 要记录的源文件
        """
        if file.id in self.processed_files:
            return
            
        # 只将文件ID添加到已处理文件集合，不创建嵌入
        self.processed_files.add(file.id)
        logger.info(f"已记录文件(无嵌入): {file.id}")
    
    async def add_code_unit(self, unit: CodeUnit) -> None:
        """将代码单元添加到知识库"""
        if unit.id in self.processed_files:
            return
        
        # 创建文档
        doc = Document(
            id=unit.id,
            content=unit.content,
            metadata={
                "unit_id": unit.id,
                "unit_name": unit.name,
                "unit_type": unit.type,
                "file_id": unit.source_file.id,
                "file_path": str(unit.source_file.path),
                "start_line": unit.start_line,
                "end_line": unit.end_line
            }
        )
        
        # 生成嵌入（加入错误处理和后备机制）
        try:
            # 尝试使用主要嵌入器
            doc.embedding = await self.embedder.aembed(doc.content)
        except Exception as e:
            logger.error(f"生成嵌入时出错: {unit.id}, {e}")
            
            # 检查是否有后备嵌入器可用
            if hasattr(self, "fallback_embedder") and self.fallback_embedder is not None:
                try:
                    logger.warning(f"尝试使用后备嵌入器: {unit.id}")
                    doc.embedding = await self.fallback_embedder.aembed(doc.content)
                except Exception as fallback_error:
                    logger.error(f"后备嵌入器也失败: {fallback_error}")
                    # 如果后备也失败，使用空向量或抛出异常
                    raise
        
        # 确保嵌入向量存在再添加到向量存储
        if doc.embedding is not None:
            # 添加到向量存储
            try:
                self.vector_store.add([doc])
                self.processed_files.add(unit.id)
                logger.debug(f"成功添加代码单元到知识库: {unit.id}")
            except Exception as store_error:
                logger.error(f"添加到向量存储时出错: {unit.id}, {store_error}")
                raise
        else:
            # 如果没有嵌入向量，仍然记录该文件为已处理
            self.processed_files.add(unit.id)
            logger.warning(f"添加了没有嵌入的代码单元: {unit.id}")
        
        logger.debug(f"已将代码单元添加到知识库: {unit.id}")
    
    async def add_batch_code_units(self, units: List[CodeUnit], max_concurrency: int = 20) -> None:
        """批量将代码单元添加到知识库
        
        Args:
            units: 要添加的代码单元列表
            max_concurrency: 最大并发数
        """
        if not units:
            return
            
        # 过滤掉已处理的单元
        units_to_process = [unit for unit in units if unit.id not in self.processed_files]
        
        if not units_to_process:
            logger.debug(f"没有新的代码单元需要添加到知识库")
            return
            
        logger.info(f"批量添加 {len(units_to_process)} 个代码单元到知识库")
        
        # 限制并发数
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def process_unit(unit):
            async with semaphore:
                try:
                    await self.add_code_unit(unit)
                    return True
                except Exception as e:
                    logger.error(f"添加代码单元到知识库时出错: {unit.id}, {e}")
                    return False
        
        # 并发处理所有单元，但允许失败而不中断整个批处理
        tasks = [process_unit(unit) for unit in units_to_process]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        
        # 计算成功的单元数量（返回 True 的结果数）
        success_count = sum(1 for r in results if r is True)
        logger.info(f"成功添加 {success_count}/{len(units_to_process)} 个代码单元到知识库")
        
        # 即使有错误也继续处理，而不中断整个流程
    
    async def retrieve(self, query: str, k: int = 5) -> List[Tuple[Document, float]]:
        """检索与查询相关的文档"""
        # 生成查询嵌入
        query_embedding = await self.embedder.aembed(query)
        
        # 搜索相关文档
        results = self.vector_store.search(query_embedding, k=k)
        
        # 过滤低相似度结果
        filtered_results = [(doc, score) for doc, score in results if score >= self.config.relevance_threshold]
        
        logger.debug(f"检索到 {len(filtered_results)}/{len(results)} 个相关文档")
        return filtered_results
    
    def save_knowledge_base(self, path: str = "./data/kb/knowledge_base") -> None:
        """保存知识库到文件"""
        self.vector_store.save(path)
        
        # 保存处理过的文件列表
        with open(f"{path}_processed.json", "w", encoding="utf-8") as f:
            json.dump(list(self.processed_files), f, ensure_ascii=False, indent=2)
        
        logger.info(f"已保存知识库到 {path}")
    
    def load_knowledge_base(self, path: str = "./data/kb/knowledge_base") -> None:
        """从文件加载知识库"""
        self.vector_store.load(path)
        
        # 加载处理过的文件列表
        processed_path = f"{path}_processed.json"
        if os.path.exists(processed_path):
            with open(processed_path, "r", encoding="utf-8") as f:
                self.processed_files = set(json.load(f))
        
        logger.info(f"已加载知识库，{len(self.processed_files)}个处理过的文件")
    
    def _chunk_text(self, text: str, chunk_size: int, chunk_overlap: int) -> List[str]:
        """将文本分割成重叠的块"""
        if not text:
            return []
        
        # 如果有tiktoken，使用它进行分词
        if TIKTOKEN_AVAILABLE:
            tokenizer = tiktoken.get_encoding("cl100k_base")
            tokens = tokenizer.encode(text)
            chunks = []
            
            i = 0
            while i < len(tokens):
                # 获取当前块的结束位置
                end = min(i + chunk_size, len(tokens))
                # 解码当前块
                chunk = tokenizer.decode(tokens[i:end])
                chunks.append(chunk)
                # 移动到下一个起始位置，考虑重叠
                i += (chunk_size - chunk_overlap)
            
            return chunks
        
        # 简单按字符分块
        chunks = []
        for i in range(0, len(text), chunk_size - chunk_overlap):
            chunks.append(text[i:i + chunk_size])
            if i + chunk_size >= len(text):
                break
        
        return chunks


# 全局Self-RAG实例
self_rag = SelfRAG()
