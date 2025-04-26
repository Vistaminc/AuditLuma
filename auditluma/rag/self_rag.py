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

from loguru import logger

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

from auditluma.config import Config
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
        self.model_name = model_name
        
        # 使用指定的提供商或默认提供商
        provider = provider or Config.agent.default_provider
        provider_config = Config.get_llm_provider_config(provider)
        self.api_key = provider_config.api_key
        self.base_url = provider_config.base_url
        
        # 获取共享的API客户端实例以提高性能
        from auditluma.utils import init_llm_client
        self.client = init_llm_client(self.model_name)
        
        logger.info(f"初始化嵌入模型，使用提供商: {provider}")
    
    async def aembed(self, text: str) -> List[float]:
        """异步生成嵌入向量"""
        response = await self.client.embeddings.create(
            model=self.model_name,
            input=text
        )
        return response.data[0].embedding


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
        
        # 初始化嵌入模型 - 使用与聊天模型相同的提供商
        default_provider = Config.agent.default_provider
        try:
            # 尝试使用指定的嵌入模型
            self.embedder = OpenAIEmbedder(
                model_name=self.config.embedding_model,
                provider=default_provider
            )
            logger.info(f"使用{default_provider}嵌入模型: {self.config.embedding_model}")
        except Exception as e:
            logger.warning(f"无法初始化嵌入模型: {e}")
            self.embedder = SimpleEmbedder()
            logger.info("回退到简单嵌入模型")
        
        # 初始化向量存储
        if self.config.vector_store == "faiss" and FAISS_AVAILABLE:
            self.vector_store = FAISSVectorStore()
            logger.info("使用FAISS向量存储")
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
        
        # 生成嵌入
        for doc in documents:
            doc.embedding = await self.embedder.aembed(doc.content)
        
        # 添加到向量存储
        self.vector_store.add(documents)
        self.processed_files.add(file.id)
        
        logger.info(f"已将文件添加到知识库: {file.id} ({len(chunks)}个块)")
    
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
        
        # 生成嵌入
        doc.embedding = await self.embedder.aembed(doc.content)
        
        # 添加到向量存储
        self.vector_store.add([doc])
        self.processed_files.add(unit.id)
        
        logger.debug(f"已将代码单元添加到知识库: {unit.id}")
    
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
