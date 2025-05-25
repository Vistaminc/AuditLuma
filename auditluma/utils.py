"""
工具类实用函数 - 提供系统所需的各种辅助功能
"""

import os
import sys
import time
import uuid
import hashlib
import json
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import logging
from datetime import datetime
import re

from loguru import logger
from auditluma.config import Config


def setup_logging(log_level: str = "INFO") -> None:
    """设置日志系统"""
    # 移除所有默认处理器
    logger.remove()
    
    # 添加标准输出处理器
    log_format = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    
    # 设置日志级别
    level = getattr(logging, log_level.upper())
    
    # 添加控制台输出
    logger.add(sys.stderr, format=log_format, level=level, colorize=True)
    
    # 创建logs目录（如果不存在）
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # 生成日志文件名，格式为：年+月+日+时间（精确到ms）
    current_time = datetime.now()
    log_filename = current_time.strftime("%Y%m%d_%H-%M-%S_%f")[:-3]  # 去掉最后3位，保留毫秒
    log_file_path = logs_dir / f"auditluma.{log_filename}.log"
    
    # 添加文件输出
    logger.add(
        str(log_file_path), 
        format=log_format, 
        level=level, 
        rotation="10 MB", 
        compression="zip",
        retention="2 weeks"
    )
    
    logger.info(f"日志系统初始化完成，级别: {log_level}, 文件: {log_file_path}")


def calculate_project_hash(directory_path: str) -> str:
    """计算项目的唯一哈希值（用于缓存和标识）"""
    try:
        path = Path(directory_path)
        if not path.exists() or not path.is_dir():
            logger.error(f"目录不存在: {directory_path}")
            return hashlib.md5(directory_path.encode()).hexdigest()
        
        # 收集所有文件路径和修改时间
        files_info = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = Path(root) / file
                try:
                    # 收集文件路径和修改时间
                    mod_time = file_path.stat().st_mtime
                    rel_path = file_path.relative_to(path)
                    files_info.append(f"{rel_path}:{mod_time}")
                except Exception as e:
                    logger.warning(f"处理文件时出错: {file_path}, {e}")
        
        # 对文件信息进行排序并合并
        files_info.sort()
        content_to_hash = "\n".join(files_info)
        
        # 计算MD5哈希
        hash_value = hashlib.md5(content_to_hash.encode()).hexdigest()
        
        logger.debug(f"计算项目哈希值: {hash_value}")
        return hash_value
        
    except Exception as e:
        logger.error(f"计算项目哈希值时出错: {e}")
        # 使用目录路径作为后备
        return hashlib.md5(directory_path.encode()).hexdigest()


def load_json_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """加载JSON文件内容"""
    path = Path(file_path)
    if not path.exists():
        logger.error(f"文件不存在: {file_path}")
        return {}
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"加载JSON文件时出错: {file_path}, {e}")
        return {}


def save_json_file(data: Dict[str, Any], file_path: Union[str, Path]) -> bool:
    """保存数据到JSON文件"""
    path = Path(file_path)
    
    # 确保目录存在
    os.makedirs(path.parent, exist_ok=True)
    
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.debug(f"数据已保存到: {file_path}")
        return True
    except Exception as e:
        logger.error(f"保存JSON文件时出错: {file_path}, {e}")
        return False


def write_text_file(content: str, file_path: Union[str, Path]) -> bool:
    """写入文本内容到文件"""
    path = Path(file_path)
    
    # 确保目录存在
    os.makedirs(path.parent, exist_ok=True)
    
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.debug(f"文本已写入到: {file_path}")
        return True
    except Exception as e:
        logger.error(f"写入文本文件时出错: {file_path}, {e}")
        return False


def append_text_file(content: str, file_path: Union[str, Path]) -> bool:
    """追加文本内容到文件"""
    path = Path(file_path)
    
    # 确保目录存在
    os.makedirs(path.parent, exist_ok=True)
    
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"追加文本文件时出错: {file_path}, {e}")
        return False


def read_text_file(file_path: Union[str, Path]) -> Optional[str]:
    """读取文本文件内容"""
    path = Path(file_path)
    if not path.exists():
        logger.error(f"文件不存在: {file_path}")
        return None
    
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        logger.error(f"读取文本文件时出错: {file_path}, {e}")
        return None


def generate_uuid() -> str:
    """生成唯一标识符"""
    return str(uuid.uuid4())


def get_timestamp() -> float:
    """获取当前时间戳"""
    return time.time()


def get_formatted_time(format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """获取格式化的当前时间"""
    return datetime.now().strftime(format_str)


def sanitize_filename(filename: str) -> str:
    """清理文件名，移除不安全的字符"""
    # 移除不允许在文件名中使用的字符
    sanitized = re.sub(r'[\\/*?:"<>|]', "_", filename)
    
    # 避免文件名过长
    if len(sanitized) > 200:
        name_parts = sanitized.split(".")
        if len(name_parts) > 1:
            extension = name_parts[-1]
            basename = ".".join(name_parts[:-1])
            sanitized = f"{basename[:190]}.{extension}"
        else:
            sanitized = sanitized[:200]
    
    return sanitized


def count_tokens(text: str) -> int:
    """简单估计文本中的令牌数量"""
    # 这是一个粗略的估计，不同的分词器会有不同的结果
    # 对于英文文本，单词数乘以1.3是一个合理的估计
    # 对于中文文本，字符数除以1.5是一个合理的估计
    
    # 检测文本是否主要为中文
    chinese_char_count = len(re.findall(r'[\u4e00-\u9fff]', text))
    if chinese_char_count > len(text) * 0.5:
        # 中文文本
        return int(len(text) / 1.5)
    else:
        # 英文或混合文本
        words = re.findall(r'\b\w+\b', text)
        return int(len(words) * 1.3)


def split_into_chunks(text: str, max_chunk_size: int, overlap: int = 0) -> List[str]:
    """将文本分割成大小适中的块"""
    if not text:
        return []
    
    # 按段落分割
    paragraphs = text.split('\n\n')
    
    chunks = []
    current_chunk = []
    current_size = 0
    
    for paragraph in paragraphs:
        # 估计段落的标记数
        paragraph_size = count_tokens(paragraph)
        
        # 如果当前段落超过最大块大小，则需要拆分
        if paragraph_size > max_chunk_size:
            # 先处理现有的块
            if current_chunk:
                chunks.append('\n\n'.join(current_chunk))
                # 如果需要重叠，保留最后几个段落
                if overlap > 0 and len(current_chunk) > 0:
                    # 找到适合重叠的段落
                    overlap_size = 0
                    overlap_paragraphs = []
                    for p in reversed(current_chunk):
                        p_size = count_tokens(p)
                        if overlap_size + p_size <= overlap:
                            overlap_paragraphs.insert(0, p)
                            overlap_size += p_size
                        else:
                            break
                    current_chunk = overlap_paragraphs
                else:
                    current_chunk = []
                current_size = sum(count_tokens(p) for p in current_chunk)
            
            # 拆分大段落
            sentences = re.split(r'(?<=[.!?])\s+', paragraph)
            temp_chunk = []
            temp_size = 0
            
            for sentence in sentences:
                sentence_size = count_tokens(sentence)
                
                if temp_size + sentence_size <= max_chunk_size:
                    temp_chunk.append(sentence)
                    temp_size += sentence_size
                else:
                    if temp_chunk:
                        chunks.append(' '.join(temp_chunk))
                    temp_chunk = [sentence]
                    temp_size = sentence_size
            
            if temp_chunk:
                chunks.append(' '.join(temp_chunk))
                
        # 如果当前块加上这个段落不超过限制，则添加到当前块
        elif current_size + paragraph_size <= max_chunk_size:
            current_chunk.append(paragraph)
            current_size += paragraph_size
        # 否则，开始一个新块
        else:
            if current_chunk:
                chunks.append('\n\n'.join(current_chunk))
                # 处理重叠
                if overlap > 0:
                    # 找到适合重叠的段落
                    overlap_size = 0
                    overlap_paragraphs = []
                    for p in reversed(current_chunk):
                        p_size = count_tokens(p)
                        if overlap_size + p_size <= overlap:
                            overlap_paragraphs.insert(0, p)
                            overlap_size += p_size
                        else:
                            break
                    current_chunk = overlap_paragraphs
                    current_size = overlap_size
                else:
                    current_chunk = []
                    current_size = 0
            
            current_chunk.append(paragraph)
            current_size += paragraph_size
    
    # 添加最后一个块
    if current_chunk:
        chunks.append('\n\n'.join(current_chunk))
    
    return chunks


def truncate_text(text: str, max_length: int, add_ellipsis: bool = True) -> str:
    """截断文本到指定长度"""
    if len(text) <= max_length:
        return text
    
    truncated = text[:max_length]
    if add_ellipsis:
        # 保留最后一行的完整性
        last_newline = truncated.rfind('\n')
        if last_newline > 0 and (max_length - last_newline) < 50:
            truncated = truncated[:last_newline]
        
        truncated += "..."
    
    return truncated


def extract_code_from_markdown(markdown_text: str) -> List[Dict[str, str]]:
    """从Markdown文本中提取代码块"""
    pattern = r'```(\w*)\n(.*?)```'
    matches = re.finditer(pattern, markdown_text, re.DOTALL)
    
    code_blocks = []
    for match in matches:
        language = match.group(1).strip() or 'text'
        code = match.group(2)
        code_blocks.append({
            'language': language,
            'code': code
        })
    
    return code_blocks


def detect_provider_from_model(model_name: str) -> str:
    """根据模型名称自动检测提供商
    
    Args:
        model_name: 模型名称
        
    Returns:
        推测的提供商名称
    """
    model_name = model_name.lower()
    
    # 模型名前缀到提供商的映射
    model_prefixes = {
        "gpt-": "openai",
        "text-embedding-": "openai",
        "deepseek-": "deepseek",
        "moonshot-": "moonshot",
        "qwen-": "qwen",
        "baichuan": "baichuan",
        "glm-": "zhipu",
        "chatglm": "zhipu",
        "mxbai-embed": "ollama_emd",  # Ollama的嵌入模型
    }
    
    for prefix, provider in model_prefixes.items():
        if model_name.startswith(prefix):
            return provider
    
    # 特殊模型名称的映射
    special_models = {
        "gpt4": "openai",
        "gpt3": "openai",
        "embedding-bert": "deepseek",
        "yi-": "01ai",
        "claude": "anthropic",
        "llama": "meta",
        "mxbai": "ollama_emd",  # Ollama的mxbai嵌入模型
    }
    
    for model_part, provider in special_models.items():
        if model_part in model_name:
            return provider
    
    # 检测是否为Ollama模型
    if any(model_part in model_name for model_part in ["llama", "mistral", "qwen", "gemma"]):
        # 如果带有:latest之类的标签，可能是Ollama本地部署的模型
        if ":" in model_name or model_name.endswith((".bin", ".gguf")):
            return "ollama"
    
    # 默认情况下返回openai
    logger.warning(f"无法检测模型 '{model_name}' 的提供商，默认使用OpenAI")
    return "openai"


class OllamaClient:
    """自定义Ollama客户端，模拟OpenAI客户端接口"""
    
    def __init__(self, model_name: str):
        """初始化Ollama客户端"""
        from auditluma.config import Config
        
        self.model_name = model_name
        import httpx
        
        # 创建带有超时设置的httpx客户端
        timeout_settings = httpx.Timeout(
            connect=30.0,
            read=120.0,      # 增加读取超时时间
            write=30.0,
            pool=15.0
        )
        self.http_client = httpx.AsyncClient(timeout=timeout_settings)
        
        # 使用配置中的base_url，如果不存在则使用默认值
        self.base_url = getattr(Config.ollama, 'base_url', 'http://localhost:11434/api')
        self.chat = self.ChatCompletion(self)
        logger.info(f"初始化Ollama客户端，模型: {model_name}, API地址: {self.base_url}")
    
    class ChatCompletion:
        """模拟OpenAI的ChatCompletion类"""
        
        def __init__(self, parent):
            self.parent = parent
            # 创建 completions 属性，使其结构与OpenAI客户端一致
            self.completions = self
        
        async def create(self, model=None, messages=None, temperature=0.7, max_tokens=None, **kwargs):
            """调用Ollama聊天接口"""
            model = model or self.parent.model_name
            
            # 转换OpenAI格式的消息到Ollama格式
            try:
                # 简化消息格式以兼容Ollama API
                prompt = ""
                
                # 如果提供了消息数组，处理消息格式
                if messages and isinstance(messages, list):
                    for msg in messages:
                        role = msg.get("role", "")
                        content = msg.get("content", "")
                        
                        if role == "system":
                            prompt += f"System: {content}\n\n"
                        elif role == "user":
                            prompt += f"User: {content}\n\n"
                        elif role == "assistant":
                            prompt += f"Assistant: {content}\n\n"
                
                # 尝试两种请求格式，兼容不同版本的Ollama API
                # 格式1: 完整的聊天接口
                payload_chat = {
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "stream": False
                }
                
                # 格式2: 使用 prompt 参数的简化接口
                payload_completion = {
                    "model": model,
                    "prompt": prompt.strip(),
                    "temperature": temperature,
                    "stream": False
                }
                
                if max_tokens:
                    payload_chat["max_tokens"] = max_tokens
                    payload_completion["max_tokens"] = max_tokens
                
                # Ollama只支持一种格式，使用自定义的完整API路径
                try:
                    # 构建更完整的消息格式
                    logger.debug(f"发送请求到Ollama API: {payload_chat}")
                    
                    # 使用正确的Ollama API端点
                    response = await self.parent.http_client.post(
                        "http://localhost:11434/api/chat",  # 直接使用完整URL路径
                        json=payload_chat,
                        timeout=120.0
                    )
                    
                    # 检查响应状态
                    response.raise_for_status()
                    response_data = response.json()
                    logger.info(f"成功从 Ollama 获取响应")
                    logger.debug(f"收到Ollama响应: {response_data}")
                    
                    # 转换Ollama响应为OpenAI格式
                    return OllamaResponse(response_data)
                    
                except Exception as e:
                    logger.error(f"Ollama API调用失败: {e}")
                    # 重新抛出异常以便于高层捕获
                    raise Exception(f"Ollama API调用失败: {e}")
                
            except Exception as e:
                logger.error(f"Ollama API调用出错: {e}")
                # 重新包装异常，以便于调用者处理
                raise Exception(f"Connection error: {e}")


class OllamaResponse:
    """模拟OpenAI的响应对象"""
    
    class Message:
        """消息对象类"""
        def __init__(self, content, role="assistant"):
            self.content = content
            self.role = role
    
    class Choice:
        """选择对象类"""
        def __init__(self, message, finish_reason="stop", index=0):
            self.message = message
            self.finish_reason = finish_reason
            self.index = index
    
    def __init__(self, ollama_response):
        self.ollama_response = ollama_response
        self.model = ollama_response.get("model", "")
        
        # 调试输出，查看实际的响应格式
        logger.debug(f"Ollama原始响应: {ollama_response}")
        
        # 检查响应结构，适配不同的Ollama API响应格式
        content = ""
        if "message" in ollama_response and isinstance(ollama_response["message"], dict):
            # 标准Ollama格式
            content = ollama_response["message"].get("content", "")
        elif "response" in ollama_response:
            # 另一种Ollama响应格式
            content = ollama_response["response"]
        
        # 创建消息对象
        message = self.Message(content=content)
        
        # 创建选择对象
        choice = self.Choice(message=message)
        
        # 设置选择列表
        self.choices = [choice]


def init_llm_client(model: Optional[str] = None) -> Any:
    """初始化LLM客户端
    
    根据配置初始化不同提供商的LLM客户端
    
    Args:
        model: 可选的模型名称，支持"model@provider"格式指定提供商
    
    Returns:
        LLM客户端实例
    """
    import os  # 添加导入，确保os模块在函数内可用
    
    # 检查是否启用模拟模式
    if os.environ.get("AUDITLUMA_MOCK_LLM", "").lower() in ["true", "1", "yes"]:
        logger.info("LLM模拟模式已启用，将使用模拟响应")
        from auditluma.mocks.llm_client import MockLLMClient
        return MockLLMClient()
        
    from openai import AsyncOpenAI
    
    # 解析模型规范，如果提供了模型名称
    model_name = ""
    provider_name = ""
    if model:
        model_name, provider_from_model = Config.parse_model_spec(model)
        # 如果模型指定了提供商，使用它
        if provider_from_model:
            provider_name = provider_from_model
            logger.info(f"使用模型规范中指定的提供商: {provider_name}")
    
    # 如果未从模型中指定提供商，使用默认提供商
    if not provider_name:
        provider_name = Config.agent.default_provider
        logger.info(f"使用配置中的默认提供商: {provider_name}")
    
    # 如果没有指定模型名称，这是一个错误
    if not model_name:
        logger.error(f"必须指定模型名称，格式为'model@provider'")
        raise ValueError("初始化LLM客户端时缺少模型名称")
    
    # 获取提供商配置
    provider_config = Config.get_llm_provider_config(provider_name)
    base_url = provider_config.base_url
    api_key = provider_config.api_key
    
    # 特殊处理Ollama API
    if provider_name == "ollama":
        # 创建一个自定义的Ollama客户端
        return OllamaClient(model_name)
    
    # 如果API密钥未在配置中设置，尝试从环境变量获取
    if not api_key:
        api_key = os.environ.get("AUDITLUMA_API_KEY", "")
        if not api_key:
            logger.warning("未设置API密钥，LLM功能可能无法正常工作")
    
    # 所有提供商都使用OpenAI兼容客户端
    import httpx
    # 创建带有超时设置和重试策略的httpx客户端
    timeout_settings = httpx.Timeout(
        connect=30.0,       # 连接超时时间
        read=60.0,          # 读取超时时间
        write=30.0,         # 写入超时时间
        pool=15.0           # 连接池超时时间
    )
    http_client = httpx.AsyncClient(timeout=timeout_settings)
    
    # 使用自定义HTTP客户端初始化OpenAI客户端
    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        http_client=http_client,
        max_retries=3       # 添加重试机制
    )
    
    logger.info(f"已初始化LLM客户端，提供商: {provider_name}，模型: {model_name}")
    
    return client
