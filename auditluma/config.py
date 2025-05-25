"""
AuditLuma 的配置模块
"""

from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field
import yaml
from pathlib import Path
from enum import Enum
import os
import logging

logger = logging.getLogger(__name__)

class LLMProvider(str, Enum):
    """LLM提供商枚举"""
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    MOONSHOT = "moonshot"  # 硅基流动
    QWEN = "qwen"         # 通义千问
    BAICHUAN = "baichuan"
    ZHIPU = "zhipu"        # 智谱AI
    AZURE = "azure"
    OLLAMA = "ollama"      # Ollama本地模型
    OLLAMA_EMD = "ollama_emd"  # Ollama本地嵌入模型


class GlobalConfig(BaseModel):
    """全局配置设置"""
    show_thinking: bool = False
    language: str = "zh-CN"
    target_dir: str = "./goalfile"
    report_dir: str = "./reports"
    report_format: str = "html"


class LLMProviderConfig(BaseModel):
    """LLM提供商配置基类"""
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 8000
    temperature: float = 0.1
    
    def get_client_config(self) -> Dict[str, Any]:
        """获取LLM客户端配置"""
        return {
            "api_key": self.api_key,
            "base_url": self.base_url
        }


class OpenAIConfig(LLMProviderConfig):
    """OpenAI专用配置"""
    base_url: str = "https://api.openai.com/v1"


class DeepSeekConfig(LLMProviderConfig):
    """DeepSeek专用配置"""
    base_url: str = "https://api.deepseek.com/v1"


class MoonshotConfig(LLMProviderConfig):
    """硅基流动专用配置"""
    base_url: str = "https://api.moonshot.cn/v1"


class QwenConfig(LLMProviderConfig):
    """通义千问专用配置"""
    base_url: str = "https://dashscope.aliyuncs.com/api/v1"


class ZhipuConfig(LLMProviderConfig):
    """智谱AI专用配置"""
    base_url: str = "https://open.bigmodel.cn/api/paas/v4"


class BaichuanConfig(LLMProviderConfig):
    """百度千帆专用配置"""
    base_url: str = "https://api.baichuan-ai.com/v1"


class OllamaConfig(LLMProviderConfig):
    """Ollama本地模型配置"""
    base_url: str = "http://localhost:11434/api"


class OllamaEmdConfig(LLMProviderConfig):
    """Ollama本地嵌入模型配置"""
    base_url: str = "http://localhost:11434/api/embeddings"


class AgentConfig(BaseModel):
    """代理配置设置"""
    default_provider: str = "openai"
    system_prompt: str = "你是一个专业的代码安全审计助手，将帮助用户分析代码中的安全漏洞"
    memory_limit: int = 10


class ToolsConfig(BaseModel):
    """工具配置设置"""
    enabled: List[str] = Field(default_factory=list)


class UIConfig(BaseModel):
    """UI配置设置"""
    theme: str = "blue"
    use_colors: bool = True
    verbosity: str = "normal"


class MCPAgentConfig(BaseModel):
    """智能体配置设置"""
    name: str
    description: str
    type: str
    priority: int
    model: str = ""  # 智能体使用的模型，格式为"model@provider"


class MCPConfig(BaseModel):
    """多智能体协作协议配置"""
    enabled: bool = True
    agents: List[MCPAgentConfig] = Field(default_factory=list)


class ProjectConfig(BaseModel):
    """项目配置"""
    name: str = "AuditLuma项目"
    max_file_size: int = 1000000
    max_batch_size: int = 20
    ignored_extensions: List[str] = Field(default_factory=list)
    ignored_directories: List[str] = Field(default_factory=list)


class SelfRAGConfig(BaseModel):
    """Self-RAG 配置设置"""
    enabled: bool = True
    vector_store: str = "faiss"
    embedding_model: str = ""
    chunk_size: int = 1000
    chunk_overlap: int = 200
    max_documents: int = 10000
    retrieval_k: int = 5
    relevance_threshold: float = 0.75


class VulnerabilityDBConfig(BaseModel):
    """漏洞数据库配置"""
    sources: List[str] = Field(default_factory=list)
    update_frequency: str = "weekly"
    local_storage: str = "./data/vulnerability_db"


class OutputConfig(BaseModel):
    """输出配置"""
    formats: List[str] = Field(default_factory=list)
    visualization: bool = True
    graph_format: str = "d3"
    max_results: int = 100
    severity_levels: List[str] = Field(default_factory=list)


class DefaultModelsConfig(BaseModel):
    """默认模型配置"""
    code_analysis: str = "gpt-4-turbo-preview"
    security_audit: str = "gpt-4-turbo-preview"
    remediation: str = "gpt-4-turbo-preview"
    summarization: str = "gpt-3.5-turbo"


class Config:
    """全局配置类，从config.yaml加载"""
    global_config = GlobalConfig()
    openai = OpenAIConfig()
    deepseek = DeepSeekConfig()
    moonshot = MoonshotConfig()
    qwen = QwenConfig()
    zhipu = ZhipuConfig()
    baichuan = BaichuanConfig()
    ollama = OllamaConfig()
    ollama_emd = OllamaEmdConfig()
    agent = AgentConfig()
    tools = ToolsConfig()
    ui = UIConfig()
    project = ProjectConfig()
    self_rag = SelfRAGConfig()
    mcp = MCPConfig()
    vulnerability_db = VulnerabilityDBConfig()
    output = OutputConfig()
    default_models = DefaultModelsConfig()
    
    @classmethod
    def load_from_dict(cls, config_data: Dict[str, Any]) -> None:
        """从字典加载配置"""
        # 加载全局配置
        if "global" in config_data:
            cls.global_config = GlobalConfig(**config_data["global"])
        
        # 加载各LLM提供商配置
        if "openai" in config_data:
            cls.openai = OpenAIConfig(**config_data["openai"])
        
        if "deepseek" in config_data:
            cls.deepseek = DeepSeekConfig(**config_data["deepseek"])
        
        if "moonshot" in config_data:
            cls.moonshot = MoonshotConfig(**config_data["moonshot"])
        
        if "qwen" in config_data:
            cls.qwen = QwenConfig(**config_data["qwen"])
        
        if "zhipu" in config_data:
            cls.zhipu = ZhipuConfig(**config_data["zhipu"])
        
        if "baichuan" in config_data:
            cls.baichuan = BaichuanConfig(**config_data["baichuan"])
        
        if "ollama" in config_data:
            cls.ollama = OllamaConfig(**config_data["ollama"])
        
        if "ollama_emd" in config_data:
            cls.ollama_emd = OllamaEmdConfig(**config_data["ollama_emd"])
        
        # 加载代理配置
        if "agent" in config_data:
            cls.agent = AgentConfig(**config_data["agent"])
        
        # 加载工具配置
        if "tools" in config_data:
            cls.tools = ToolsConfig(**config_data["tools"])
        
        # 加载UI配置
        if "ui" in config_data:
            cls.ui = UIConfig(**config_data["ui"])
        
        # 加载项目配置
        if "project" in config_data:
            cls.project = ProjectConfig(**config_data["project"])
        
        # 加载Self-RAG配置
        if "self_rag" in config_data:
            cls.self_rag = SelfRAGConfig(**config_data["self_rag"])
        
        # 加载MCP配置
        if "mcp" in config_data and "agents" in config_data["mcp"]:
            agents = [MCPAgentConfig(**agent) for agent in config_data["mcp"]["agents"]]
            enabled = config_data["mcp"].get("enabled", True)
            cls.mcp = MCPConfig(enabled=enabled, agents=agents)
        
        # 加载漏洞数据库配置
        if "vulnerability_db" in config_data:
            cls.vulnerability_db = VulnerabilityDBConfig(**config_data["vulnerability_db"])
        
        # 加载输出配置
        if "output" in config_data:
            cls.output = OutputConfig(**config_data["output"])
        
        # 加载默认模型配置
        if "default_models" in config_data:
            cls.default_models = DefaultModelsConfig(**config_data["default_models"])
    
    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """将配置转换为字典"""
        return {
            "global": cls.global_config.dict(),
            "openai": cls.openai.dict(),
            "deepseek": cls.deepseek.dict(),
            "moonshot": cls.moonshot.dict(),
            "qwen": cls.qwen.dict(),
            "zhipu": cls.zhipu.dict(),
            "baichuan": cls.baichuan.dict(),
            "ollama": cls.ollama.dict(),
            "ollama_emd": cls.ollama_emd.dict(),
            "agent": cls.agent.dict(),
            "tools": cls.tools.dict(),
            "ui": cls.ui.dict(),
            "project": cls.project.dict(),
            "self_rag": cls.self_rag.dict(),
            "mcp": cls.mcp.dict(),
            "vulnerability_db": cls.vulnerability_db.dict(),
            "output": cls.output.dict(),
            "default_models": cls.default_models.dict()
        }
    
    @classmethod
    def get_llm_provider_config(cls, provider_name: str) -> LLMProviderConfig:
        """获取指定提供商的配置"""
        provider_map = {
            "openai": cls.openai,
            "deepseek": cls.deepseek,
            "moonshot": cls.moonshot,
            "qwen": cls.qwen,
            "zhipu": cls.zhipu,
            "baichuan": cls.baichuan,
            "ollama": cls.ollama,
            "ollama_emd": cls.ollama_emd
        }
        
        if provider_name in provider_map:
            return provider_map[provider_name]
        
        # 默认返回OpenAI配置
        return cls.openai
    
    @classmethod
    def get_target_dir(cls) -> str:
        """获取目标目录"""
        return cls.global_config.target_dir
    
    @classmethod
    def get_report_dir(cls) -> str:
        """获取报告目录"""
        return cls.global_config.report_dir
    
    @classmethod
    def get_report_format(cls) -> str:
        """获取报告格式"""
        return cls.global_config.report_format

    @classmethod
    def parse_model_spec(cls, model_spec: str) -> Tuple[str, str]:
        """解析模型规范，从形如"model@provider"的格式中提取模型名称和提供商
        
        Args:
            model_spec: 模型规范字符串，如"deepseek-chat@deepseek"
            
        Returns:
            包含模型名称和提供商的元组 (model_name, provider_name)
        """
        if not model_spec:
            return "", ""
            
        # 检查是否包含@符号
        if "@" in model_spec:
            model_name, provider_name = model_spec.split("@", 1)
            return model_name.strip(), provider_name.strip()
        
        # 如果没有@符号，使用自动检测提供商的函数
        from auditluma.utils import detect_provider_from_model
        model_name = model_spec.strip()
        provider_name = detect_provider_from_model(model_name)
        
        return model_name, provider_name


def load_config(config_path: str = "./config/config.yaml") -> None:
    """加载配置文件并更新全局配置"""
    try:
        # 尝试多个可能的配置文件路径
        paths_to_try = [
            config_path,  # 首先尝试传入的路径
            Path(config_path),  # 作为Path对象尝试
            Path(".") / "config" / "config.yaml",  # 当前目录下的config目录
            Path("..") / "config" / "config.yaml",  # 上级目录的config目录
            Path(__file__).parent.parent / "config" / "config.yaml"  # 相对于模块的路径
        ]
        
        for path in paths_to_try:
            try:
                path_str = str(path)
                if os.path.exists(path_str):
                    with open(path_str, 'r', encoding='utf-8') as file:
                        config_data = yaml.safe_load(file)
                        Config.load_from_dict(config_data)
                        logger.info(f"从 {path_str} 加载了配置")
                        return
            except Exception as e:
                logger.debug(f"尝试从 {path} 加载配置失败: {e}")
                continue
        
        # 如果所有路径都失败，记录警告
        logger.warning(f"未能从任何路径加载配置文件，使用默认配置")
    except Exception as e:
        logger.error(f"加载配置文件过程中发生错误: {e}")
        # 使用默认配置
        pass

# 初始化配置
load_config()
