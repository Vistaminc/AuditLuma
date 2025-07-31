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
    temp_dir: str = "./temp"  # 临时文件目录


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


class HaystackConfig(BaseModel):
    """Haystack编排层配置"""
    enabled: bool = True
    max_workers: int = 10
    task_timeout: int = 300  # 任务超时时间（秒）
    retry_attempts: int = 3
    retry_delay: float = 1.0
    enable_parallel_execution: bool = True
    load_balancing: bool = True
    performance_monitoring: bool = True
    
    # Haystack-AI管道配置
    use_haystack_ai: bool = True  # 是否使用官方Haystack-AI库
    max_tokens: int = 2000
    temperature: float = 0.1
    top_k: int = 5
    similarity_threshold: float = 0.7
    enable_embeddings: bool = True
    enable_ranking: bool = True
    enable_document_splitting: bool = True
    
    # 错误处理和回退
    enable_fallback: bool = True  # 启用回退到传统方法
    fallback_on_error: bool = True  # 出错时回退
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: int = 5
    
    def get_task_model(self, task_type: str) -> str:
        """获取特定任务类型的模型"""
        # 从主配置获取模型配置
        if hasattr(Config, 'hierarchical_rag_models'):
            models_config = Config.hierarchical_rag_models
            if models_config and models_config.get('enabled', False):
                haystack_models = models_config.get('haystack', {})
                task_models = haystack_models.get('task_models', {})
                
                # 返回任务特定模型或默认模型
                return task_models.get(task_type) or haystack_models.get('default_model', 'gpt-3.5-turbo@openai')
        
        # 回退到默认模型
        return 'gpt-3.5-turbo@openai'
    
    def get_task_config(self, task_type: str) -> Dict[str, Any]:
        """获取特定任务类型的配置"""
        # 任务特定参数配置
        task_params = {
            "security_scan": {
                "max_tokens": 2500,
                "temperature": 0.05
            },
            "syntax_check": {
                "max_tokens": 1500,
                "temperature": 0.0
            },
            "logic_analysis": {
                "max_tokens": 2000,
                "temperature": 0.1
            },
            "dependency_analysis": {
                "max_tokens": 1800,
                "temperature": 0.1
            }
        }
        
        task_config = task_params.get(task_type, {})
        
        # 合并配置
        merged_config = {
            "model_name": self.get_task_model(task_type),
            "max_tokens": task_config.get("max_tokens", self.max_tokens),
            "temperature": task_config.get("temperature", self.temperature),
            "top_k": self.top_k,
            "similarity_threshold": self.similarity_threshold,
            "enable_embeddings": self.enable_embeddings,
            "enable_ranking": self.enable_ranking
        }
        
        return merged_config


class TxtaiConfig(BaseModel):
    """txtai知识检索层配置"""
    enabled: bool = True
    cve_database_url: str = "https://cve.circl.lu/api"
    cve_cache_ttl: int = 3600  # CVE缓存时间（秒）
    best_practices_sources: List[str] = Field(default_factory=lambda: ["owasp", "sans", "nist"])
    historical_cases_limit: int = 100
    similarity_threshold: float = 0.8
    retrieval_timeout: int = 30
    enable_incremental_update: bool = True
    knowledge_cache_size: int = 1000


class R2RConfig(BaseModel):
    """R2R上下文增强层配置"""
    enabled: bool = True
    max_call_depth: int = 10
    enable_cross_file_analysis: bool = True
    enable_data_flow_analysis: bool = True
    enable_taint_analysis: bool = True
    context_window_size: int = 500
    semantic_similarity_threshold: float = 0.7
    impact_assessment_enabled: bool = True
    context_expansion_enabled: bool = True


class SelfRAGValidationConfig(BaseModel):
    """Self-RAG验证层配置"""
    enabled: bool = True
    cross_validation_enabled: bool = True
    confidence_threshold: float = 0.7
    false_positive_filter_enabled: bool = True
    quality_assessment_enabled: bool = True
    validation_timeout: int = 60
    min_consensus_score: float = 0.6
    explanation_required: bool = True


class CacheConfig(BaseModel):
    """缓存系统配置"""
    enabled: bool = True
    l1_cache_size: str = "256MB"  # 内存缓存大小
    l2_cache_size: str = "2GB"    # 磁盘缓存大小
    distributed_cache_enabled: bool = False
    redis_url: str = "redis://localhost:6379"
    cache_ttl: int = 3600
    cache_compression: bool = True


class MonitoringConfig(BaseModel):
    """监控系统配置"""
    enabled: bool = True
    performance_tracking: bool = True
    quality_tracking: bool = True
    health_check_interval: int = 60  # 健康检查间隔（秒）
    metrics_retention_days: int = 30
    alert_thresholds: Dict[str, float] = Field(default_factory=lambda: {
        "processing_time": 300.0,
        "error_rate": 0.1,
        "confidence_score": 0.5
    })
    log_level: str = "INFO"


class SecurityConfig(BaseModel):
    """安全配置"""
    enabled: bool = True
    data_encryption: bool = False
    access_control: bool = False
    audit_logging: bool = True
    rate_limiting: bool = True
    max_requests_per_minute: int = 100
    api_key_required: bool = False
    secure_headers: bool = True


class HierarchicalRAGConfig(BaseModel):
    """层级RAG架构配置"""
    enabled: bool = False  # 默认关闭，需要显式启用
    architecture_mode: str = "hierarchical"  # "traditional" 或 "hierarchical"
    
    # 各层配置
    haystack: HaystackConfig = Field(default_factory=HaystackConfig)
    txtai: TxtaiConfig = Field(default_factory=TxtaiConfig)
    r2r: R2RConfig = Field(default_factory=R2RConfig)
    self_rag_validation: SelfRAGValidationConfig = Field(default_factory=SelfRAGValidationConfig)
    
    # 系统配置
    cache: CacheConfig = Field(default_factory=CacheConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    
    # 兼容性配置
    backward_compatibility: bool = True
    migration_enabled: bool = True
    ab_testing_enabled: bool = False
    fallback_to_traditional: bool = True
    
    def is_layer_enabled(self, layer_name: str) -> bool:
        """检查指定层是否启用"""
        if not self.enabled:
            return False
        
        layer_map = {
            "haystack": self.haystack.enabled,
            "txtai": self.txtai.enabled,
            "r2r": self.r2r.enabled,
            "self_rag_validation": self.self_rag_validation.enabled
        }
        
        return layer_map.get(layer_name, False)
    
    def get_layer_config(self, layer_name: str) -> Optional[BaseModel]:
        """获取指定层的配置"""
        layer_map = {
            "haystack": self.haystack,
            "txtai": self.txtai,
            "r2r": self.r2r,
            "self_rag_validation": self.self_rag_validation,
            "cache": self.cache,
            "monitoring": self.monitoring,
            "security": self.security
        }
        
        return layer_map.get(layer_name)
    
    def validate_configuration(self) -> List[str]:
        """验证配置的有效性，返回错误列表"""
        errors = []
        
        if self.enabled:
            # 检查至少有一个处理层启用
            processing_layers = [
                self.haystack.enabled,
                self.txtai.enabled,
                self.r2r.enabled,
                self.self_rag_validation.enabled
            ]
            
            if not any(processing_layers):
                errors.append("至少需要启用一个处理层")
            
            # 检查Haystack配置
            if self.haystack.enabled:
                if self.haystack.max_workers <= 0:
                    errors.append("Haystack max_workers 必须大于0")
                if self.haystack.task_timeout <= 0:
                    errors.append("Haystack task_timeout 必须大于0")
            
            # 检查txtai配置
            if self.txtai.enabled:
                if self.txtai.similarity_threshold < 0 or self.txtai.similarity_threshold > 1:
                    errors.append("txtai similarity_threshold 必须在0-1之间")
            
            # 检查R2R配置
            if self.r2r.enabled:
                if self.r2r.max_call_depth <= 0:
                    errors.append("R2R max_call_depth 必须大于0")
            
            # 检查Self-RAG验证配置
            if self.self_rag_validation.enabled:
                if (self.self_rag_validation.confidence_threshold < 0 or 
                    self.self_rag_validation.confidence_threshold > 1):
                    errors.append("Self-RAG confidence_threshold 必须在0-1之间")
        
        return errors


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


class HierarchicalRAGModelsConfig(BaseModel):
    """层级RAG架构模型配置"""
    enabled: bool = True
    
    # Haystack编排层配置
    haystack: Dict[str, Any] = Field(default_factory=lambda: {
        "orchestrator_type": "ai",  # 默认使用Haystack-AI编排器
        "default_model": "gpt-3.5-turbo@openai",
        "task_models": {
            "security_scan": "gpt-4@openai",
            "syntax_check": "gpt-3.5-turbo@openai",
            "logic_analysis": "gpt-3.5-turbo@openai",
            "dependency_analysis": "gpt-3.5-turbo@openai"
        }
    })
    
    # txtai知识检索层模型配置
    txtai: Dict[str, str] = Field(default_factory=lambda: {
        "retrieval_model": "gpt-3.5-turbo@openai",
        "embedding_model": "text-embedding-ada-002@openai"
    })
    
    # R2R上下文增强层模型配置
    r2r: Dict[str, str] = Field(default_factory=lambda: {
        "context_model": "gpt-3.5-turbo@openai",
        "enhancement_model": "gpt-3.5-turbo@openai"
    })
    
    # Self-RAG验证层模型配置
    self_rag_validation: Dict[str, Any] = Field(default_factory=lambda: {
        "validation_model": "gpt-3.5-turbo@openai",
        "cross_validation_models": [
            "gpt-4@openai",
            "deepseek-chat@deepseek",
            "gpt-3.5-turbo@openai"
        ]
    })
    
    def get_model_for_layer(self, layer: str, model_type: str = "default") -> str:
        """获取指定层的模型"""
        layer_config = getattr(self, layer, {})
        
        if layer == "haystack":
            if model_type == "default":
                return layer_config.get("default_model", "gpt-3.5-turbo@openai")
            else:
                return layer_config.get("task_models", {}).get(model_type, layer_config.get("default_model", "gpt-3.5-turbo@openai"))
        else:
            return layer_config.get(f"{model_type}_model", layer_config.get("default_model", "gpt-3.5-turbo@openai"))
    
    def get_task_model(self, task_type: str) -> str:
        """获取特定任务类型的模型"""
        return self.get_model_for_layer("haystack", task_type)
    
    def get_orchestrator_type(self) -> str:
        """获取编排器类型"""
        return self.haystack.get("orchestrator_type", "ai")


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
    hierarchical_rag_models = HierarchicalRAGModelsConfig()
    hierarchical_rag = HierarchicalRAGConfig()
    
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
        
        # 加载层级RAG模型配置
        if "hierarchical_rag_models" in config_data:
            cls.hierarchical_rag_models = HierarchicalRAGModelsConfig(**config_data["hierarchical_rag_models"])
        
        # 加载层级RAG配置
        if "hierarchical_rag" in config_data:
            cls.hierarchical_rag = HierarchicalRAGConfig(**config_data["hierarchical_rag"])
    
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
            "default_models": cls.default_models.dict(),
            "hierarchical_rag_models": cls.hierarchical_rag_models.dict(),
            "hierarchical_rag": cls.hierarchical_rag.dict()
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
    
    @classmethod
    def is_hierarchical_rag_enabled(cls) -> bool:
        """检查层级RAG是否启用"""
        return cls.hierarchical_rag.enabled
    
    @classmethod
    def get_architecture_mode(cls) -> str:
        """获取架构模式"""
        return cls.hierarchical_rag.architecture_mode
    
    @classmethod
    def validate_hierarchical_rag_config(cls) -> List[str]:
        """验证层级RAG配置"""
        return cls.hierarchical_rag.validate_configuration()
    
    @classmethod
    def get_hierarchical_layer_config(cls, layer_name: str) -> Optional[BaseModel]:
        """获取层级RAG指定层的配置"""
        return cls.hierarchical_rag.get_layer_config(layer_name)
    
    @classmethod
    def is_hierarchical_layer_enabled(cls, layer_name: str) -> bool:
        """检查层级RAG指定层是否启用"""
        return cls.hierarchical_rag.is_layer_enabled(layer_name)
    
    @classmethod
    def get_hierarchical_model(cls, layer: str, model_type: str = "default") -> str:
        """获取层级RAG指定层的模型"""
        return cls.hierarchical_rag_models.get_model_for_layer(layer, model_type)
    
    @classmethod
    def get_task_model(cls, task_type: str) -> str:
        """获取特定任务类型的模型"""
        return cls.hierarchical_rag_models.get_task_model(task_type)
    
    @classmethod
    def get_layer_model(cls, layer: str, model_type: str) -> str:
        """获取指定层的指定类型模型"""
        return cls.hierarchical_rag_models.get_model_for_layer(layer, model_type)
    
    @classmethod
    def get_txtai_models(cls) -> Dict[str, str]:
        """获取txtai层的模型配置"""
        return cls.hierarchical_rag_models.txtai
    
    @classmethod
    def get_r2r_models(cls) -> Dict[str, str]:
        """获取R2R层的模型配置"""
        return cls.hierarchical_rag_models.r2r
    
    @classmethod
    def get_self_rag_models(cls) -> Dict[str, Any]:
        """获取Self-RAG层的模型配置"""
        return cls.hierarchical_rag_models.self_rag_validation
    
    @classmethod
    def is_hierarchical_models_enabled(cls) -> bool:
        """检查层级RAG模型配置是否启用"""
        return cls.hierarchical_rag_models.enabled


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
