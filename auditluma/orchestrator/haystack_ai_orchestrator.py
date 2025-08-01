"""
Haystack-AI主编排框架 - 层级RAG架构第一层
基于官方Haystack-AI库实现的智能编排系统
负责任务分发、流程编排和结果汇总
"""

import asyncio
import uuid
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import time
from pathlib import Path
import json

from loguru import logger
import requests
import socket

# Haystack AI imports
try:
    from haystack import Pipeline, Document
    from haystack.components.builders import PromptBuilder
    from haystack.components.generators import OpenAIGenerator
    from haystack.components.retrievers import InMemoryBM25Retriever
    from haystack.components.embedders import OpenAIDocumentEmbedder, OpenAITextEmbedder
    from haystack.document_stores.in_memory import InMemoryDocumentStore
    from haystack.components.routers import ConditionalRouter
    from haystack.components.joiners import DocumentJoiner
    from haystack.components.preprocessors import DocumentSplitter
    from haystack.components.rankers import TransformersSimilarityRanker
    HAYSTACK_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Haystack-AI not available: {e}")
    HAYSTACK_AVAILABLE = False
    # 创建占位符类
    class Pipeline: pass
    class Document: pass
    class PromptBuilder: pass
    class OpenAIGenerator: pass

from auditluma.config import Config
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult
from auditluma.rag.txtai_retriever import TxtaiRetriever
from auditluma.rag.r2r_enhancer import R2REnhancer
from auditluma.rag.self_rag_validator import SelfRAGValidator
from auditluma.orchestrator.task_decomposer import TaskDecomposer, TaskCollection, TaskType, AuditTask
from auditluma.orchestrator.parallel_executor import ParallelProcessingManager, TaskScheduler
from auditluma.orchestrator.result_integrator import ResultIntegrator, ConflictResolutionStrategy

# Import UnifiedGenerator and HaystackPipelineBuilder for enhanced support
try:
    from auditluma.components.unified_generator import UnifiedGenerator
    from auditluma.components.pipeline_builder import HaystackPipelineBuilder
    UNIFIED_GENERATOR_AVAILABLE = True
except (ImportError, AttributeError) as e:
    logger.warning(f"UnifiedGenerator not available: {e}")
    UNIFIED_GENERATOR_AVAILABLE = False
    class UnifiedGenerator: 
        def __init__(self, *args, **kwargs):
            pass
    class HaystackPipelineBuilder:
        def __init__(self, *args, **kwargs):
            pass


@dataclass
class HaystackPipelineConfig:
    """Haystack管道配置"""
    model_name: str = "gpt-3.5-turbo"
    max_tokens: int = 2000
    temperature: float = 0.1
    top_k: int = 5
    similarity_threshold: float = 0.7
    enable_embeddings: bool = True
    enable_ranking: bool = True
    
    # Ollama特定配置
    ollama_base_url: str = "http://localhost:11434/api"  # 默认值，会从配置文件覆盖
    ollama_timeout: float = 60.0
    ollama_max_retries: int = 3
    ollama_retry_delay: float = 2.0
    
    @classmethod
    def from_config(cls, config_dict: Dict[str, Any] = None) -> 'HaystackPipelineConfig':
        """从配置字典创建配置对象"""
        if config_dict is None:
            # 直接从hierarchical_rag_models配置获取Haystack配置
            try:
                haystack_config = Config.hierarchical_rag_models.haystack
                default_model = haystack_config.get("default_model", "gpt-3.5-turbo")
                
                # 从配置文件读取Ollama设置
                ollama_base_url = Config.ollama.base_url if hasattr(Config, 'ollama') else 'http://localhost:11434/api'
                
                logger.info(f"从配置加载Haystack管道模型: {default_model}")
                logger.info(f"从配置加载Ollama服务地址: {ollama_base_url}")
                
                return cls(
                    model_name=default_model,
                    max_tokens=2000,
                    temperature=0.1,
                    top_k=5,
                    similarity_threshold=0.7,
                    enable_embeddings=True,
                    enable_ranking=True,
                    ollama_base_url=ollama_base_url,
                    ollama_timeout=60.0,
                    ollama_max_retries=3,
                    ollama_retry_delay=2.0
                )
            except Exception as e:
                logger.warning(f"加载Haystack配置失败: {e}，使用默认配置")
                return cls()  # 使用默认值
        
        return cls(
            model_name=config_dict.get("model_name", "gpt-3.5-turbo"),
            max_tokens=config_dict.get("max_tokens", 2000),
            temperature=config_dict.get("temperature", 0.1),
            top_k=config_dict.get("top_k", 5),
            similarity_threshold=config_dict.get("similarity_threshold", 0.7),
            enable_embeddings=config_dict.get("enable_embeddings", True),
            enable_ranking=config_dict.get("enable_ranking", True)
        )


@dataclass
class TaskResult:
    """任务执行结果"""
    task_id: str
    task_type: TaskType
    vulnerabilities: List[VulnerabilityResult]
    execution_time: float
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditResult:
    """综合审计结果"""
    vulnerabilities: List[VulnerabilityResult]
    task_results: List[TaskResult]
    execution_summary: Dict[str, Any]
    confidence_score: float
    processing_time: float


class HaystackPipelineBuilder:
    """Haystack管道构建器"""
    
    def __init__(self, config: HaystackPipelineConfig):
        """初始化管道构建器"""
        self.config = config
        self.document_store = InMemoryDocumentStore()
        
        if not HAYSTACK_AVAILABLE:
            logger.error("Haystack-AI not available, pipeline functionality will be limited")
    
    def _is_openai_compatible_model(self, model_name: str) -> bool:
        """检查模型是否兼容OpenAI API"""
        # 首先检查是否为Ollama模型，如果是则不兼容OpenAI API
        if self._is_ollama_model(model_name):
            return False
        
        # 提取提供商信息
        if "@" in model_name:
            _, provider = model_name.split("@", 1)
        else:
            # 根据模型名称推断提供商
            if "gpt-" in model_name.lower():
                provider = "openai"
            elif "deepseek" in model_name.lower():
                provider = "deepseek"
            elif "qwen" in model_name.lower():
                provider = "qwen"
            elif "moonshot" in model_name.lower():
                provider = "moonshot"
            elif "zhipu" in model_name.lower() or "glm" in model_name.lower():
                provider = "zhipu"
            elif "baichuan" in model_name.lower():
                provider = "baichuan"
            else:
                provider = "unknown"
        
        # Haystack的OpenAIGenerator支持OpenAI兼容的API
        openai_compatible_providers = ["openai", "deepseek", "moonshot", "qwen", "zhipu", "baichuan"]
        
        return provider in openai_compatible_providers
    
    def _get_ollama_config(self, model_name: str, base_config: Dict[str, Any]) -> Dict[str, Any]:
        """获取Ollama特定配置"""
        # 从配置文件重新读取最新的Ollama设置
        try:
            if hasattr(Config, 'ollama') and hasattr(Config.ollama, 'base_url'):
                base_url = Config.ollama.base_url
            else:
                base_url = self.config.ollama_base_url
        except Exception as e:
            logger.debug(f"从配置文件读取Ollama设置失败: {e}")
            base_url = self.config.ollama_base_url
        
        # 确保base_url是完整的API地址
        if not base_url.endswith('/api') and not base_url.endswith('/api/'):
            if base_url.endswith('/'):
                base_url = base_url + 'api'
            else:
                base_url = base_url + '/api'
        
        ollama_config = {
            "model": model_name.replace("@ollama", ""),  # 移除@ollama后缀
            "base_url": base_url,
            "timeout": self.config.ollama_timeout,
            "max_retries": self.config.ollama_max_retries,
            "retry_delay": self.config.ollama_retry_delay,
            "generation_kwargs": {
                "max_tokens": base_config.get("max_tokens", self.config.max_tokens),
                "temperature": base_config.get("temperature", self.config.temperature)
            }
        }
        
        # 从环境变量获取自定义Ollama设置（优先级最高）
        try:
            import os
            if "OLLAMA_BASE_URL" in os.environ:
                env_base_url = os.environ["OLLAMA_BASE_URL"]
                # 确保环境变量的URL也是完整的API地址
                if not env_base_url.endswith('/api') and not env_base_url.endswith('/api/'):
                    if env_base_url.endswith('/'):
                        env_base_url = env_base_url + 'api'
                    else:
                        env_base_url = env_base_url + '/api'
                ollama_config["base_url"] = env_base_url
                logger.debug(f"使用环境变量OLLAMA_BASE_URL: {env_base_url}")
            if "OLLAMA_TIMEOUT" in os.environ:
                ollama_config["timeout"] = float(os.environ["OLLAMA_TIMEOUT"])
        except Exception as e:
            logger.debug(f"获取Ollama环境变量配置时出错: {e}")
        
        return ollama_config
    
    def _get_openai_config(self, model_name: str) -> Dict[str, Any]:
        """获取OpenAI兼容模型的配置"""
        # 从配置文件读取OpenAI设置
        try:
            openai_config = getattr(Config, 'openai', {})
            api_key = openai_config.api_key if hasattr(openai_config, 'api_key') else ""
            base_url = openai_config.base_url if hasattr(openai_config, 'base_url') else ""
            
            config = {
                "api_key": api_key,
                "base_url": base_url
            }
            
            # 从环境变量获取覆盖设置，或将配置设置为环境变量
            import os
            if "OPENAI_API_KEY" in os.environ:
                config["api_key"] = os.environ["OPENAI_API_KEY"]
            elif config["api_key"]:
                # 如果配置文件中有API key但环境变量中没有，设置环境变量
                os.environ["OPENAI_API_KEY"] = config["api_key"]
                
            if "OPENAI_BASE_URL" in os.environ:
                config["base_url"] = os.environ["OPENAI_BASE_URL"]
            elif config["base_url"]:
                # 如果配置文件中有base_url但环境变量中没有，设置环境变量
                os.environ["OPENAI_BASE_URL"] = config["base_url"]
            
            logger.debug(f"OpenAI配置: api_key={'***' if config['api_key'] else 'None'}, base_url={config['base_url']}")
            return config
            
        except Exception as e:
            logger.debug(f"获取OpenAI配置失败: {e}")
            return {"api_key": "", "base_url": ""}
    
    def _handle_ollama_error(self, error: Exception, model_name: str, operation: str) -> bool:
        """
        处理Ollama特定错误
        
        Args:
            error: 发生的异常
            model_name: 模型名称
            operation: 操作类型
            
        Returns:
            bool: 是否应该回退到传统执行方式
        """
        error_type = type(error).__name__
        error_msg = str(error)
        
        # 连接错误处理
        if isinstance(error, (requests.ConnectionError, socket.error)):
            logger.error(f"🔌 Ollama服务连接失败 - 模型: {model_name}, 操作: {operation}")
            logger.error(f"   错误详情: {error_msg}")
            logger.info(f"   请检查Ollama服务是否在 {self.config.ollama_base_url} 运行")
            logger.info(f"   建议: 启动Ollama服务或检查网络连接")
            return True  # 回退到传统执行
        
        # 超时错误处理
        elif isinstance(error, requests.Timeout):
            logger.error(f"⏰ Ollama请求超时 - 模型: {model_name}, 操作: {operation}")
            logger.error(f"   超时时间: {self.config.ollama_timeout}秒")
            logger.info(f"   建议: 增加超时时间或检查模型是否需要下载")
            return True  # 回退到传统执行
        
        # HTTP错误处理
        elif isinstance(error, requests.HTTPError):
            status_code = getattr(error.response, 'status_code', 'unknown')
            if status_code == 404:
                logger.error(f"🚫 Ollama模型未找到 - 模型: {model_name}")
                logger.info(f"   建议: 运行 'ollama pull {model_name}' 下载模型")
            elif status_code == 500:
                logger.error(f"💥 Ollama服务内部错误 - 模型: {model_name}")
                logger.info(f"   建议: 检查Ollama服务状态和日志")
            else:
                logger.error(f"🌐 Ollama HTTP错误 - 状态码: {status_code}, 模型: {model_name}")
            return True  # 回退到传统执行
        
        # Haystack集成错误处理
        elif "haystack" in error_msg.lower() or "__haystack_" in error_msg:
            logger.warning(f"🔧 Haystack集成问题 - 模型: {model_name}, 操作: {operation}")
            logger.warning(f"   错误详情: {error_msg}")
            logger.info(f"   系统将回退到传统执行方式")
            return True  # 回退到传统执行
        
        # 其他UnifiedGenerator错误
        elif "UnifiedGenerator" in error_msg:
            logger.error(f"⚙️ UnifiedGenerator错误 - 模型: {model_name}, 操作: {operation}")
            logger.error(f"   错误详情: {error_msg}")
            logger.info(f"   系统将回退到传统执行方式")
            return True  # 回退到传统执行
        
        # 未知错误
        else:
            logger.error(f"❓ 未知Ollama错误 - 类型: {error_type}, 模型: {model_name}")
            logger.error(f"   错误详情: {error_msg}")
            logger.info(f"   系统将回退到传统执行方式")
            return True  # 回退到传统执行
    
    def _check_ollama_service_health(self, base_url: str) -> bool:
        """
        检查Ollama服务健康状态
        
        Args:
            base_url: Ollama服务地址
            
        Returns:
            bool: 服务是否健康
        """
        try:
            # 尝试访问Ollama API健康检查端点
            health_url = f"{base_url.rstrip('/')}/api/tags"
            response = requests.get(health_url, timeout=5)
            
            if response.status_code == 200:
                logger.debug(f"✅ Ollama服务健康检查通过: {base_url}")
                return True
            else:
                logger.warning(f"⚠️ Ollama服务响应异常: {response.status_code}")
                return False
                
        except Exception as e:
            logger.warning(f"❌ Ollama服务健康检查失败: {e}")
            return False
    
    def _log_provider_execution_path(self, model_name: str, provider_type: str, pipeline_type: str):
        """
        记录提供商执行路径的详细日志
        
        Args:
            model_name: 模型名称
            provider_type: 提供商类型 (ollama/openai)
            pipeline_type: 管道类型
        """
        if provider_type == "ollama":
            logger.info(f"🦙 Ollama执行路径 - 管道: {pipeline_type}")
            logger.info(f"   模型: {model_name}")
            logger.info(f"   服务地址: {self.config.ollama_base_url}")
            logger.info(f"   超时设置: {self.config.ollama_timeout}秒")
            logger.info(f"   重试设置: {self.config.ollama_max_retries}次")
        elif provider_type == "openai":
            logger.info(f"🤖 OpenAI兼容执行路径 - 管道: {pipeline_type}")
            logger.info(f"   模型: {model_name}")
            logger.info(f"   使用Haystack OpenAIGenerator")
        else:
            logger.info(f"❓ 未知提供商执行路径 - 管道: {pipeline_type}")
            logger.info(f"   模型: {model_name}")
    
    def _implement_graceful_fallback(self, model_name: str, task_type: str, error: Exception) -> bool:
        """
        实现优雅的回退机制
        
        Args:
            model_name: 模型名称
            task_type: 任务类型
            error: 发生的错误
            
        Returns:
            bool: 是否成功设置回退
        """
        logger.warning(f"🔄 启动优雅回退机制")
        logger.warning(f"   原始模型: {model_name}")
        logger.warning(f"   任务类型: {task_type}")
        logger.warning(f"   错误原因: {str(error)}")
        
        # 记录回退决策
        if self._is_ollama_model(model_name):
            logger.info(f"   回退策略: Ollama模型 -> 传统执行方式")
            logger.info(f"   影响: 将使用非Haystack管道执行任务")
        else:
            logger.info(f"   回退策略: OpenAI兼容模型 -> 传统执行方式")
            logger.info(f"   影响: 将跳过Haystack管道，使用传统方法")
        
        # 提供用户建议
        if "connection" in str(error).lower():
            logger.info(f"💡 建议: 检查网络连接和服务状态")
        elif "timeout" in str(error).lower():
            logger.info(f"💡 建议: 增加超时时间或检查服务性能")
        elif "not found" in str(error).lower():
            logger.info(f"💡 建议: 确认模型已正确安装和配置")
        
        return True
    
    def _is_ollama_model(self, model_name: str) -> bool:
        """检查模型是否为Ollama模型"""
        # 检查是否有明确的@ollama后缀
        if "@ollama" in model_name:
            return True
        
        # 检查是否为常见的Ollama模型名称模式
        # Ollama模型通常使用 model:tag 格式，如 llama2:7b, qwen:32b 等
        if ":" in model_name and "@" not in model_name:
            # 常见的Ollama模型前缀
            ollama_model_prefixes = [
                "llama", "llama2", "llama3", "codellama", "vicuna", "alpaca",
                "mistral", "mixtral", "qwen", "qwen2", "deepseek", "yi",
                "gemma", "phi", "tinyllama", "orca", "wizard", "solar"
            ]
            
            model_base = model_name.split(":")[0].lower()
            return any(model_base.startswith(prefix) for prefix in ollama_model_prefixes)
        
        return False
    
    def _create_unified_generator(self, model_name: str, config: Dict[str, Any]) -> Any:
        """创建UnifiedGenerator实例，包含增强的错误处理"""
        if not UNIFIED_GENERATOR_AVAILABLE:
            logger.error("❌ UnifiedGenerator不可用，无法创建Ollama生成器")
            return None
        
        try:
            # 确定提供商和配置
            if self._is_ollama_model(model_name):
                provider = "ollama"
                # 获取Ollama特定配置
                ollama_config = self._get_ollama_config(model_name, config)
                clean_model_name = ollama_config["model"]
                
                # 检查Ollama服务健康状态
                if not self._check_ollama_service_health(ollama_config["base_url"]):
                    logger.warning(f"⚠️ Ollama服务健康检查失败，但仍尝试创建生成器")
                
                # 记录详细的配置信息
                logger.debug(f"🔧 创建Ollama UnifiedGenerator配置:")
                logger.debug(f"   模型: {clean_model_name}")
                logger.debug(f"   服务地址: {ollama_config['base_url']}")
                logger.debug(f"   超时: {ollama_config['timeout']}秒")
                logger.debug(f"   最大重试: {ollama_config['max_retries']}次")
                logger.debug(f"   重试延迟: {ollama_config['retry_delay']}秒")
                
                # 创建UnifiedGenerator实例，使用Ollama配置
                generator = UnifiedGenerator(
                    model=clean_model_name,
                    provider=provider,
                    base_url=ollama_config["base_url"],
                    generation_kwargs=ollama_config["generation_kwargs"],
                    timeout=ollama_config["timeout"],
                    max_retries=ollama_config["max_retries"],
                    retry_delay=ollama_config["retry_delay"],
                    enable_monitoring=True
                )
                
                logger.info(f"✅ 成功创建Ollama UnifiedGenerator")
                logger.info(f"   模型: {clean_model_name}")
                logger.info(f"   服务地址: {ollama_config['base_url']}")
                
            else:
                # 非Ollama模型，检测提供商类型
                if "@" in model_name:
                    clean_model_name, provider = model_name.split("@", 1)
                else:
                    clean_model_name = model_name
                    provider = "openai"  # 默认为OpenAI兼容
                
                logger.debug(f"🔧 创建{provider}UnifiedGenerator配置:")
                logger.debug(f"   模型: {clean_model_name}")
                logger.debug(f"   提供商: {provider}")
                
                # 为OpenAI兼容模型准备配置
                generator_config = {
                    "generation_kwargs": {
                        "max_tokens": config.get("max_tokens", 2000),
                        "temperature": config.get("temperature", 0.1)
                    },
                    "timeout": config.get("timeout", 30.0),
                    "max_retries": config.get("max_retries", 3),
                    "enable_monitoring": True
                }
                
                # 如果是OpenAI兼容模型，添加API配置
                if provider == "openai":
                    openai_config = self._get_openai_config(model_name)
                    if openai_config.get("api_key"):
                        generator_config["api_key"] = openai_config["api_key"]
                    if openai_config.get("base_url"):
                        generator_config["base_url"] = openai_config["base_url"]
                
                generator = UnifiedGenerator(
                    model=clean_model_name,
                    provider=provider,
                    **generator_config
                )
                
                logger.info(f"✅ 成功创建{provider}UnifiedGenerator，模型: {clean_model_name}")
            
            return generator
            
        except Exception as e:
            # 使用增强的错误处理
            should_fallback = self._handle_ollama_error(e, model_name, "generator_creation")
            if should_fallback:
                logger.info(f"🔄 UnifiedGenerator创建失败，系统将回退到传统执行方式")
            return None
    
    def build_security_scan_pipeline(self, task_config: Dict[str, Any] = None) -> Pipeline:
        """构建安全扫描管道"""
        if not HAYSTACK_AVAILABLE:
            return None
        
        # 使用任务特定配置或默认配置
        config = task_config or {
            "model_name": self.config.model_name,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature
        }
        
        # 检查模型类型并选择合适的生成器
        model_name = config["model_name"]
        is_ollama = self._is_ollama_model(model_name)
        is_openai_compatible = self._is_openai_compatible_model(model_name)
        
        if not is_ollama and not is_openai_compatible:
            logger.info(f"模型 {model_name} 既不是Ollama模型也不兼容OpenAI API，将跳过Haystack管道构建")
            return None
        
        # 安全扫描提示模板
        security_prompt_template = """
        对以下代码进行安全漏洞分析：
        
        代码内容：
        {{ code_content }}
        
        文件路径：{{ file_path }}
        编程语言：{{ language }}
        
        相关知识库信息：
        {{ knowledge_context }}
        
        请检查以下安全问题：
        1. SQL注入漏洞
        2. XSS跨站脚本
        3. 命令注入
        4. 路径遍历
        5. 权限绕过
        6. 敏感信息泄露
        7. 不安全的加密
        8. 输入验证缺失
        
        对每个发现的问题，请提供：
        - 漏洞类型
        - 严重程度（critical/high/medium/low）
        - 具体位置（行号）
        - 详细描述
        - 修复建议
        - 置信度评分（0-1）
        
        返回JSON格式的结果。
        """
        
        pipeline = Pipeline()
        
        # 提示构建组件
        pipeline.add_component("prompt_builder", PromptBuilder(
            template=security_prompt_template,
            required_variables=["code_content", "file_path", "language", "knowledge_context"]
        ))
        
        # 使用UnifiedGenerator支持所有提供商
        try:
            # 记录执行路径
            provider = "ollama" if is_ollama else "openai"
            self._log_provider_execution_path(model_name, provider, "security_scan")
            
            # 获取并设置配置（对于OpenAI兼容模型）
            if not is_ollama:
                openai_config = self._get_openai_config(model_name)
            
            # 创建UnifiedGenerator
            generator = self._create_unified_generator(model_name, config)
            if generator is None:
                logger.error(f"❌ 无法创建生成器，模型: {model_name}")
                self._implement_graceful_fallback(model_name, "security_scan", Exception("Generator creation failed"))
                return None
            
            pipeline.add_component("llm", generator)
            logger.info(f"✅ 使用UnifiedGenerator创建安全扫描管道，模型: {model_name} ({provider})")
            
        except Exception as e:
            logger.error(f"❌ UnifiedGenerator创建失败: {e}")
            # 对于Ollama错误，尝试特殊处理
            if is_ollama:
                should_fallback = self._handle_ollama_error(e, model_name, "pipeline_integration")
                if should_fallback:
                    self._implement_graceful_fallback(model_name, "security_scan", e)
                return None
            else:
                self._implement_graceful_fallback(model_name, "security_scan", e)
                return None
        
        pipeline.connect("prompt_builder", "llm")
        
        return pipeline
    
    def build_syntax_check_pipeline(self, task_config: Dict[str, Any] = None) -> Pipeline:
        """构建语法检查管道"""
        if not HAYSTACK_AVAILABLE:
            return None
        
        # 使用任务特定配置或默认配置
        config = task_config or {
            "model_name": self.config.model_name,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature
        }
        
        # 检查模型类型并选择合适的生成器
        model_name = config["model_name"]
        is_ollama = self._is_ollama_model(model_name)
        is_openai_compatible = self._is_openai_compatible_model(model_name)
        
        if not is_ollama and not is_openai_compatible:
            logger.info(f"模型 {model_name} 既不是Ollama模型也不兼容OpenAI API，将跳过Haystack管道构建")
            return None
        
        syntax_prompt_template = """
        分析以下代码的语法问题：
        
        代码内容：
        {{ code_content }}
        
        文件路径：{{ file_path }}
        编程语言：{{ language }}
        
        请检查：
        1. 语法错误
        2. 缩进问题
        3. 括号匹配
        4. 变量声明
        5. 导入语句
        
        返回JSON格式的结果，包含发现的问题列表。
        """
        
        pipeline = Pipeline()
        
        # 提示构建组件
        pipeline.add_component("prompt_builder", PromptBuilder(
            template=syntax_prompt_template,
            required_variables=["code_content", "file_path", "language"]
        ))
        
        # 使用UnifiedGenerator支持所有提供商
        try:
            # 记录执行路径
            provider = "ollama" if is_ollama else "openai"
            self._log_provider_execution_path(model_name, provider, "syntax_check")
            
            # 获取并设置配置（对于OpenAI兼容模型）
            if not is_ollama:
                openai_config = self._get_openai_config(model_name)
            
            # 创建UnifiedGenerator
            generator = self._create_unified_generator(model_name, config)
            if generator is None:
                logger.error(f"❌ 无法创建生成器，模型: {model_name}")
                self._implement_graceful_fallback(model_name, "syntax_check", Exception("Generator creation failed"))
                return None
            
            pipeline.add_component("llm", generator)
            logger.info(f"✅ 使用UnifiedGenerator创建语法检查管道，模型: {model_name} ({provider})")
            
        except Exception as e:
            logger.error(f"❌ UnifiedGenerator创建失败: {e}")
            # 对于Ollama错误，尝试特殊处理
            if is_ollama:
                should_fallback = self._handle_ollama_error(e, model_name, "pipeline_integration")
                if should_fallback:
                    self._implement_graceful_fallback(model_name, "syntax_check", e)
                return None
            else:
                self._implement_graceful_fallback(model_name, "syntax_check", e)
                return None
        
        pipeline.connect("prompt_builder", "llm")
        return pipeline
    
    def build_logic_analysis_pipeline(self, task_config: Dict[str, Any] = None) -> Pipeline:
        """构建逻辑分析管道"""
        if not HAYSTACK_AVAILABLE:
            return None
        
        # 使用任务特定配置或默认配置
        config = task_config or {
            "model_name": self.config.model_name,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature
        }
        
        # 检查模型类型并选择合适的生成器
        model_name = config["model_name"]
        is_ollama = self._is_ollama_model(model_name)
        is_openai_compatible = self._is_openai_compatible_model(model_name)
        
        if not is_ollama and not is_openai_compatible:
            logger.info(f"模型 {model_name} 既不是Ollama模型也不兼容OpenAI API，将跳过Haystack管道构建")
            return None
        
        logic_prompt_template = """
        分析以下代码的逻辑问题：
        
        代码内容：
        {{ code_content }}
        
        文件路径：{{ file_path }}
        编程语言：{{ language }}
        
        上下文信息：
        {{ context_info }}
        
        请检查：
        1. 逻辑错误
        2. 死代码
        3. 无限循环
        4. 空指针引用
        5. 资源泄露
        6. 并发问题
        7. 异常处理
        8. 边界条件
        
        返回JSON格式的结果，包含发现的逻辑问题。
        """
        
        pipeline = Pipeline()
        
        # 提示构建组件
        pipeline.add_component("prompt_builder", PromptBuilder(
            template=logic_prompt_template,
            required_variables=["code_content", "file_path", "language", "context_info"]
        ))
        
        # 使用UnifiedGenerator支持所有提供商
        try:
            # 记录执行路径
            provider = "ollama" if is_ollama else "openai"
            self._log_provider_execution_path(model_name, provider, "logic_analysis")
            
            # 获取并设置配置（对于OpenAI兼容模型）
            if not is_ollama:
                openai_config = self._get_openai_config(model_name)
            
            # 创建UnifiedGenerator
            generator = self._create_unified_generator(model_name, config)
            if generator is None:
                logger.error(f"❌ 无法创建生成器，模型: {model_name}")
                self._implement_graceful_fallback(model_name, "logic_analysis", Exception("Generator creation failed"))
                return None
            
            pipeline.add_component("llm", generator)
            logger.info(f"✅ 使用UnifiedGenerator创建逻辑分析管道，模型: {model_name} ({provider})")
            
        except Exception as e:
            logger.error(f"❌ UnifiedGenerator创建失败: {e}")
            # 对于Ollama错误，尝试特殊处理
            if is_ollama:
                should_fallback = self._handle_ollama_error(e, model_name, "pipeline_integration")
                if should_fallback:
                    self._implement_graceful_fallback(model_name, "logic_analysis", e)
                return None
            else:
                self._implement_graceful_fallback(model_name, "logic_analysis", e)
                return None
        
        pipeline.connect("prompt_builder", "llm")
        return pipeline
    
    def build_dependency_analysis_pipeline(self, task_config: Dict[str, Any] = None) -> Pipeline:
        """构建依赖分析管道"""
        if not HAYSTACK_AVAILABLE:
            return None
        
        # 使用任务特定配置或默认配置
        config = task_config or {
            "model_name": self.config.model_name,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature
        }
        
        # 检查模型类型并选择合适的生成器
        model_name = config["model_name"]
        is_ollama = self._is_ollama_model(model_name)
        is_openai_compatible = self._is_openai_compatible_model(model_name)
        
        if not is_ollama and not is_openai_compatible:
            logger.info(f"模型 {model_name} 既不是Ollama模型也不兼容OpenAI API，将跳过Haystack管道构建")
            return None
        
        dependency_prompt_template = """
        分析以下代码的依赖关系问题：
        
        代码内容：
        {{ code_content }}
        
        文件路径：{{ file_path }}
        编程语言：{{ language }}
        
        依赖信息：
        {{ dependency_info }}
        
        请检查：
        1. 过时的依赖
        2. 安全漏洞的依赖
        3. 循环依赖
        4. 未使用的依赖
        5. 版本冲突
        6. 许可证问题
        
        返回JSON格式的结果。
        """
        
        pipeline = Pipeline()
        
        # 提示构建组件
        pipeline.add_component("prompt_builder", PromptBuilder(
            template=dependency_prompt_template,
            required_variables=["code_content", "file_path", "language", "dependency_info"]
        ))
        
        # 使用UnifiedGenerator支持所有提供商
        try:
            # 记录执行路径
            provider = "ollama" if is_ollama else "openai"
            self._log_provider_execution_path(model_name, provider, "dependency_analysis")
            
            # 获取并设置配置（对于OpenAI兼容模型）
            if not is_ollama:
                openai_config = self._get_openai_config(model_name)
            
            # 创建UnifiedGenerator
            generator = self._create_unified_generator(model_name, config)
            if generator is None:
                logger.error(f"❌ 无法创建生成器，模型: {model_name}")
                self._implement_graceful_fallback(model_name, "dependency_analysis", Exception("Generator creation failed"))
                return None
            
            pipeline.add_component("llm", generator)
            logger.info(f"✅ 使用UnifiedGenerator创建依赖分析管道，模型: {model_name} ({provider})")
            
        except Exception as e:
            logger.error(f"❌ UnifiedGenerator创建失败: {e}")
            # 对于Ollama错误，尝试特殊处理
            if is_ollama:
                should_fallback = self._handle_ollama_error(e, model_name, "pipeline_integration")
                if should_fallback:
                    self._implement_graceful_fallback(model_name, "dependency_analysis", e)
                return None
            else:
                self._implement_graceful_fallback(model_name, "dependency_analysis", e)
                return None
        
        pipeline.connect("prompt_builder", "llm")
        return pipeline

class HaystackAIOrchestrator:
    """基于Haystack-AI的主编排器 - 层级RAG架构的核心编排组件"""
    
    def __init__(self, workers: int = None, pipeline_config: HaystackPipelineConfig = None):
        """初始化编排器"""
        # 从配置获取默认值
        haystack_config = Config.get_hierarchical_layer_config("haystack")
        
        if workers is None:
            self.workers = haystack_config.max_workers if haystack_config else 10
        else:
            self.workers = workers
            
        if pipeline_config is None:
            self.pipeline_config = HaystackPipelineConfig.from_config()
        else:
            self.pipeline_config = pipeline_config
        
        # 初始化各层组件
        self.txtai_retriever = TxtaiRetriever()
        self.r2r_enhancer = R2REnhancer()
        self.self_rag_validator = SelfRAGValidator()
        
        # 初始化任务分解器、并行执行器和结果整合器
        self.task_decomposer = TaskDecomposer()
        self.parallel_executor = ParallelProcessingManager(max_workers=workers)
        self.task_scheduler = TaskScheduler()
        self.result_integrator = ResultIntegrator()
        
        # 初始化Haystack管道构建器
        self.pipeline_builder = HaystackPipelineBuilder(self.pipeline_config)
        
        # 构建各种分析管道
        self.pipelines = {}
        if HAYSTACK_AVAILABLE:
            self._build_pipelines()
        
        # 性能监控
        self.performance_metrics = {
            "tasks_completed": 0,
            "total_execution_time": 0.0,
            "layer_performance": {
                "haystack": {"calls": 0, "total_time": 0.0},
                "txtai": {"calls": 0, "total_time": 0.0},
                "r2r": {"calls": 0, "total_time": 0.0},
                "self_rag": {"calls": 0, "total_time": 0.0}
            }
        }
        
        # 兼容性支持
        self.agents = {}
        self.code_units = []
        
        logger.info(f"Haystack-AI编排器初始化完成，工作线程数: {self.workers}, Haystack可用: {HAYSTACK_AVAILABLE}")
    
    def _get_task_specific_config(self, task_type: TaskType) -> Dict[str, Any]:
        """获取任务特定的配置"""
        # 从统一模型配置获取模型
        model_name = Config.get_task_model(task_type.value)
        
        logger.info(f"🚀 Haystack编排层 - 任务 {task_type.value} 使用模型: {model_name}")
        
        # 获取Haystack层配置
        try:
            # 直接从hierarchical_rag_models获取配置
            haystack_config = Config.hierarchical_rag_models.haystack
            task_models = haystack_config.get("task_models", {})
            
            if task_type.value in task_models:
                # 使用任务特定模型
                task_model = task_models[task_type.value]
                config = {
                    "model_name": task_model,
                    "max_tokens": self.pipeline_config.max_tokens,
                    "temperature": self.pipeline_config.temperature,
                    "top_k": self.pipeline_config.top_k,
                }
                logger.debug(f"Haystack任务 {task_type.value} 配置: {config}")
                return config
        except Exception as e:
            logger.warning(f"获取Haystack任务配置失败: {e}，使用默认配置")
        
        # 回退到默认配置
        config = {
            "model_name": model_name,
            "max_tokens": self.pipeline_config.max_tokens,
            "temperature": self.pipeline_config.temperature,
            "top_k": self.pipeline_config.top_k,
            "similarity_threshold": self.pipeline_config.similarity_threshold,
            "enable_embeddings": self.pipeline_config.enable_embeddings,
            "enable_ranking": self.pipeline_config.enable_ranking
        }
        logger.debug(f"Haystack任务 {task_type.value} 使用默认配置: {config}")
        return config
    
    def _build_pipelines(self):
        """构建Haystack分析管道"""
        try:
            self.pipelines = {}
            
            # 为每种任务类型构建管道，使用任务特定配置
            for task_type in TaskType:
                task_config = self._get_task_specific_config(task_type)
                
                if task_type == TaskType.SYNTAX_CHECK:
                    pipeline = self.pipeline_builder.build_syntax_check_pipeline(task_config)
                elif task_type == TaskType.SECURITY_SCAN:
                    pipeline = self.pipeline_builder.build_security_scan_pipeline(task_config)
                elif task_type == TaskType.LOGIC_ANALYSIS:
                    pipeline = self.pipeline_builder.build_logic_analysis_pipeline(task_config)
                elif task_type == TaskType.DEPENDENCY_ANALYSIS:
                    pipeline = self.pipeline_builder.build_dependency_analysis_pipeline(task_config)
                else:
                    continue
                
                if pipeline:
                    self.pipelines[task_type] = pipeline
                    logger.debug(f"成功构建 {task_type.value} 管道")
                else:
                    logger.info(f"跳过 {task_type.value} 管道构建（模型不兼容或其他原因）")
            
            if self.pipelines:
                logger.info(f"Haystack分析管道构建完成，共构建 {len(self.pipelines)} 个管道")
            else:
                logger.info("未构建任何Haystack管道，将使用传统方式执行任务")
            
        except Exception as e:
            logger.error(f"构建Haystack管道失败: {e}")
            self.pipelines = {}
    
    async def orchestrate_audit(self, source_files: List[SourceFile]) -> AuditResult:
        """主编排流程 - 执行完整的层级RAG审计"""
        start_time = time.time()
        logger.info(f"🚀 开始Haystack-AI层级RAG审计，文件数: {len(source_files)}")
        
        try:
            # 1. 任务分解
            task_collection = await self._decompose_audit_tasks(source_files)
            logger.info(f"📋 任务分解完成，生成 {len(task_collection)} 个审计任务")
            
            # 2. 并行执行各类任务（使用Haystack管道）
            task_results = await self._execute_tasks_parallel(task_collection.tasks)
            logger.info(f"⚡ 并行任务执行完成，获得 {len(task_results)} 个结果")
            
            # 3. 收集所有漏洞
            all_vulnerabilities = []
            for result in task_results:
                all_vulnerabilities.extend(result.vulnerabilities)
            
            # 4. txtai层：知识检索增强
            enhanced_vulnerabilities = await self._apply_txtai_enhancement(all_vulnerabilities)
            logger.info(f"🔍 txtai知识检索完成，增强了 {len(enhanced_vulnerabilities)} 个漏洞")
            
            # 5. R2R层：上下文增强
            context_enhanced_vulnerabilities = await self._apply_r2r_enhancement(
                enhanced_vulnerabilities, source_files
            )
            logger.info(f"🔗 R2R上下文增强完成，处理了 {len(context_enhanced_vulnerabilities)} 个漏洞")
            
            # 6. Self-RAG层：验证与过滤
            validated_vulnerabilities = await self._apply_self_rag_validation(
                context_enhanced_vulnerabilities
            )
            logger.info(f"✅ Self-RAG验证完成，验证了 {len(validated_vulnerabilities)} 个漏洞")
            
            # 7. 结果整合
            audit_result = await self._integrate_results(
                validated_vulnerabilities, task_results, start_time
            )
            
            # 8. 更新性能指标
            self._update_performance_metrics(audit_result.processing_time)
            
            logger.info(f"🎉 Haystack-AI层级RAG审计完成，耗时: {audit_result.processing_time:.2f}秒")
            logger.info(f"📊 发现漏洞: {len(audit_result.vulnerabilities)}，置信度: {audit_result.confidence_score:.2f}")
            
            # 9. 输出模型使用统计
            try:
                from auditluma.monitoring.model_usage_logger import model_usage_logger
                logger.info("📊 生成模型使用统计摘要...")
                model_usage_logger.print_session_summary()
            except Exception as e:
                logger.warning(f"生成模型使用统计失败: {e}")
            
            return audit_result
            
        except Exception as e:
            logger.error(f"❌ Haystack-AI编排过程中出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise
    
    async def _decompose_audit_tasks(self, source_files: List[SourceFile]) -> TaskCollection:
        """任务分解"""
        return await self.task_decomposer.decompose_audit_tasks(source_files)
    
    async def _execute_tasks_parallel(self, tasks: List[AuditTask]) -> List[TaskResult]:
        """并行执行任务 - 使用Haystack管道"""
        if not tasks:
            return []
        
        # 调度任务执行顺序
        scheduled_tasks = self.task_scheduler.schedule_tasks(
            TaskCollection(tasks=tasks), strategy="hybrid"
        )
        
        # 创建任务执行器（使用Haystack管道）
        async def haystack_task_executor(task: AuditTask):
            """Haystack任务执行器"""
            try:
                start_time = time.time()
                
                # 使用对应的Haystack管道执行任务
                vulnerabilities = await self._execute_with_haystack_pipeline(task)
                
                execution_time = time.time() - start_time
                confidence = self._calculate_task_confidence(task, vulnerabilities)
                
                # 更新Haystack层性能指标
                self.performance_metrics["layer_performance"]["haystack"]["calls"] += 1
                self.performance_metrics["layer_performance"]["haystack"]["total_time"] += execution_time
                
                return TaskResult(
                    task_id=task.id,
                    task_type=task.task_type,
                    vulnerabilities=vulnerabilities,
                    execution_time=execution_time,
                    confidence=confidence,
                    metadata={
                        **task.metadata,
                        "haystack_pipeline_used": True,
                        "pipeline_type": task.task_type.value
                    }
                )
            except Exception as e:
                logger.error(f"Haystack任务执行失败: {task.id}, {e}")
                return TaskResult(
                    task_id=task.id,
                    task_type=task.task_type,
                    vulnerabilities=[],
                    execution_time=0.0,
                    confidence=0.0,
                    metadata={"error": str(e), "haystack_pipeline_used": False}
                )
        
        # 使用并行执行引擎执行任务
        execution_result = await self.parallel_executor.execute_tasks(
            scheduled_tasks, haystack_task_executor
        )
        
        # 转换执行结果为TaskResult列表
        task_results = []
        for task_execution in execution_result.task_executions:
            if task_execution.result and isinstance(task_execution.result, TaskResult):
                task_execution.result.execution_time = task_execution.execution_time
                task_results.append(task_execution.result)
            else:
                # 创建失败的TaskResult
                task_result = TaskResult(
                    task_id=task_execution.task.id,
                    task_type=task_execution.task.task_type,
                    vulnerabilities=[],
                    execution_time=task_execution.execution_time,
                    confidence=0.0,
                    metadata={
                        "status": task_execution.status.value,
                        "error": str(task_execution.error) if task_execution.error else None,
                        "haystack_pipeline_used": False
                    }
                )
                task_results.append(task_result)
        
        logger.info(f"Haystack并行执行统计: 成功 {execution_result.successful_tasks}, "
                   f"失败 {execution_result.failed_tasks}")
        
        return task_results
    
    async def _execute_with_haystack_pipeline(self, task: AuditTask) -> List[VulnerabilityResult]:
        """使用Haystack管道执行任务"""
        if not HAYSTACK_AVAILABLE or not self.pipelines:
            logger.info(f"Haystack不可用或管道为空，使用传统方式执行任务: {task.id}")
            return await self._execute_traditional_task(task)
        
        try:
            pipeline = self.pipelines.get(task.task_type)
            if not pipeline:
                logger.warning(f"未找到任务类型 {task.task_type} 的Haystack管道，使用传统方式")
                return await self._execute_traditional_task(task)
            
            vulnerabilities = []
            
            # 为每个源文件执行管道
            for source_file in task.source_files:
                try:
                    # 准备管道输入
                    pipeline_input = {
                        "code_content": source_file.content,
                        "file_path": str(source_file.path),
                        "language": getattr(source_file, 'language', 'unknown'),
                        "task_type": task.task_type.value
                    }
                    
                    # 添加上下文信息
                    if task.task_type == TaskType.SECURITY_SCAN:
                        knowledge_context = await self._get_knowledge_context(source_file)
                        pipeline_input["knowledge_context"] = knowledge_context
                    elif task.task_type == TaskType.LOGIC_ANALYSIS:
                        context_info = await self._get_context_info(source_file, task.code_units)
                        pipeline_input["context_info"] = context_info
                    elif task.task_type == TaskType.DEPENDENCY_ANALYSIS:
                        dependency_info = await self._get_dependency_info(source_file)
                        pipeline_input["dependency_info"] = dependency_info
                    
                    # 获取任务配置以记录使用的模型
                    task_config = self._get_task_specific_config(task.task_type)
                    model_name = task_config.get("model_name", "unknown")
                    
                    logger.info(f"🚀 Haystack编排层 - 执行 {task.task_type.value} 管道，文件: {source_file.path}")
                    logger.info(f"🚀 Haystack编排层 - 使用模型: {model_name}")
                    logger.debug(f"管道输入参数: {list(pipeline_input.keys())}")
                    
                    # 执行管道（添加超时保护）
                    try:
                        # 使用线程池执行同步管道调用，避免阻塞事件循环
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future = executor.submit(pipeline.run, pipeline_input)
                            result = await asyncio.get_event_loop().run_in_executor(
                                None, lambda: future.result(timeout=30)  # 30秒超时
                            )
                    except concurrent.futures.TimeoutError:
                        logger.error(f"Haystack管道执行超时: {task.task_type.value}, 文件: {source_file.path}")
                        continue
                    except Exception as pipeline_error:
                        logger.error(f"Haystack管道执行异常: {task.task_type.value}, 文件: {source_file.path}, 错误: {pipeline_error}")
                        continue
                    
                    logger.info(f"✅ Haystack编排层 - {task.task_type.value} 管道执行完成，模型: {model_name}")
                    
                    # 解析结果
                    file_vulnerabilities = await self._parse_pipeline_result(
                        result, source_file, task.task_type
                    )
                    vulnerabilities.extend(file_vulnerabilities)
                    
                    logger.info(f"✅ Haystack编排层 - 文件 {source_file.path} 发现 {len(file_vulnerabilities)} 个漏洞")
                    
                except Exception as e:
                    logger.error(f"Haystack管道执行失败，文件: {source_file.path}, 错误: {e}")
                    continue
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Haystack管道执行出错: {e}")
            return await self._execute_traditional_task(task)
    
    async def _execute_traditional_task(self, task: AuditTask) -> List[VulnerabilityResult]:
        """传统任务执行方式（回退方案）"""
        vulnerabilities = []
        
        for code_unit in task.code_units:
            if task.task_type == TaskType.SYNTAX_CHECK:
                if await self._has_syntax_issues(code_unit):
                    vuln = VulnerabilityResult(
                        id=f"syntax_{uuid.uuid4().hex[:8]}",
                        vulnerability_type="Syntax Error",
                        severity="low",
                        description="代码语法问题",
                        file_path=str(code_unit.source_file.path),
                        start_line=code_unit.start_line,
                        end_line=code_unit.end_line,
                        snippet=code_unit.content[:200],
                        confidence=0.9
                    )
                    vulnerabilities.append(vuln)
            
            elif task.task_type == TaskType.SECURITY_SCAN:
                security_vulns = await self._basic_security_scan(code_unit)
                vulnerabilities.extend(security_vulns)
        
        return vulnerabilities
    
    async def _get_knowledge_context(self, source_file: SourceFile) -> str:
        """获取知识库上下文"""
        try:
            # 添加超时防止卡住
            knowledge_info = await asyncio.wait_for(
                self.txtai_retriever.retrieve_vulnerability_info(
                    "security_scan", source_file.content[:500]
                ),
                timeout=10.0  # 10秒超时
            )
            
            context_parts = []
            if knowledge_info.best_practices:
                context_parts.append("最佳实践:")
                context_parts.extend(knowledge_info.best_practices[:3])
            
            return "\n".join(context_parts)
            
        except asyncio.TimeoutError:
            logger.warning("获取知识库上下文超时")
            return "知识库上下文获取超时"
        except Exception as e:
            logger.warning(f"获取知识库上下文失败: {e}")
            return "无可用知识库上下文"
    
    async def _get_context_info(self, source_file: SourceFile, code_units: List[CodeUnit]) -> str:
        """获取代码上下文信息"""
        try:
            context_parts = [f"文件: {source_file.path}"]
            
            functions = [unit for unit in code_units if unit.type == "function"]
            if functions:
                context_parts.append("函数列表:")
                for func in functions[:5]:
                    context_parts.append(f"- {func.name} (行 {func.start_line}-{func.end_line})")
            
            return "\n".join(context_parts)
            
        except Exception as e:
            logger.warning(f"获取上下文信息失败: {e}")
            return f"文件: {source_file.path}"
    
    async def _get_dependency_info(self, source_file: SourceFile) -> str:
        """获取依赖信息"""
        try:
            content = source_file.content
            dependencies = []
            
            # Python imports
            import_lines = [line.strip() for line in content.split('\n') 
                          if line.strip().startswith(('import ', 'from '))]
            dependencies.extend(import_lines[:10])
            
            if dependencies:
                return "依赖关系:\n" + "\n".join(dependencies)
            else:
                return "未检测到明显的依赖关系"
                
        except Exception as e:
            logger.warning(f"获取依赖信息失败: {e}")
            return "依赖信息不可用"
    
    async def _parse_pipeline_result(self, result: Dict[str, Any], 
                                   source_file: SourceFile, 
                                   task_type: TaskType) -> List[VulnerabilityResult]:
        """解析Haystack管道结果"""
        vulnerabilities = []
        
        try:
            # 从管道结果中提取生成的文本
            generated_text = ""
            if "llm" in result and "replies" in result["llm"]:
                generated_text = result["llm"]["replies"][0] if result["llm"]["replies"] else ""
            
            if not generated_text:
                logger.warning(f"Haystack管道未返回有效结果，任务类型: {task_type}")
                return vulnerabilities
            
            # 尝试解析JSON结果
            try:
                json_start = generated_text.find('{')
                json_end = generated_text.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    json_text = generated_text[json_start:json_end]
                    parsed_result = json.loads(json_text)
                    
                    vulnerabilities = self._extract_vulnerabilities_from_parsed_result(
                        parsed_result, source_file, task_type
                    )
                else:
                    vulnerabilities = self._extract_vulnerabilities_from_text(
                        generated_text, source_file, task_type
                    )
                    
            except json.JSONDecodeError:
                vulnerabilities = self._extract_vulnerabilities_from_text(
                    generated_text, source_file, task_type
                )
            
        except Exception as e:
            logger.error(f"解析Haystack管道结果失败: {e}")
        
        return vulnerabilities
    
    def _extract_vulnerabilities_from_parsed_result(self, parsed_result: Dict[str, Any], 
                                                  source_file: SourceFile, 
                                                  task_type: TaskType) -> List[VulnerabilityResult]:
        """从解析的JSON结果中提取漏洞"""
        vulnerabilities = []
        
        try:
            issues = []
            if "issues" in parsed_result:
                issues = parsed_result["issues"]
            elif "vulnerabilities" in parsed_result:
                issues = parsed_result["vulnerabilities"]
            elif isinstance(parsed_result, list):
                issues = parsed_result
            
            for issue in issues:
                if isinstance(issue, dict):
                    vuln = VulnerabilityResult(
                        id=f"{task_type.value}_{uuid.uuid4().hex[:8]}",
                        vulnerability_type=issue.get("type", f"{task_type.value}_issue"),
                        severity=issue.get("severity", "medium").lower(),
                        description=issue.get("description", ""),
                        file_path=str(source_file.path),
                        start_line=issue.get("line", 1),
                        end_line=issue.get("end_line", issue.get("line", 1)),
                        snippet=issue.get("code", ""),
                        confidence=float(issue.get("confidence", 0.7)),
                        recommendation=issue.get("fix", issue.get("recommendation", ""))
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"从JSON结果提取漏洞失败: {e}")
        
        return vulnerabilities
    
    def _extract_vulnerabilities_from_text(self, text: str, 
                                         source_file: SourceFile, 
                                         task_type: TaskType) -> List[VulnerabilityResult]:
        """从文本结果中提取漏洞"""
        vulnerabilities = []
        
        try:
            lines = text.split('\n')
            current_issue = {}
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                if any(keyword in line.lower() for keyword in ['vulnerability', 'issue', 'problem', 'error']):
                    if current_issue:
                        vuln = self._create_vulnerability_from_text_issue(
                            current_issue, source_file, task_type
                        )
                        if vuln:
                            vulnerabilities.append(vuln)
                    
                    current_issue = {"description": line}
                
                elif current_issue:
                    current_issue["description"] = current_issue.get("description", "") + " " + line
            
            if current_issue:
                vuln = self._create_vulnerability_from_text_issue(
                    current_issue, source_file, task_type
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"从文本结果提取漏洞失败: {e}")
        
        return vulnerabilities
    
    def _create_vulnerability_from_text_issue(self, issue: Dict[str, str], 
                                            source_file: SourceFile, 
                                            task_type: TaskType) -> Optional[VulnerabilityResult]:
        """从文本问题创建漏洞对象"""
        try:
            description = issue.get("description", "")
            
            severity = "medium"
            if any(word in description.lower() for word in ['critical', 'severe']):
                severity = "critical"
            elif any(word in description.lower() for word in ['high', 'important']):
                severity = "high"
            elif any(word in description.lower() for word in ['low', 'minor']):
                severity = "low"
            
            import re
            line_match = re.search(r'line\s+(\d+)', description, re.IGNORECASE)
            line_number = int(line_match.group(1)) if line_match else 1
            
            return VulnerabilityResult(
                id=f"{task_type.value}_{uuid.uuid4().hex[:8]}",
                vulnerability_type=f"{task_type.value}_issue",
                severity=severity,
                description=description,
                file_path=str(source_file.path),
                start_line=line_number,
                end_line=line_number,
                snippet="",
                confidence=0.6
            )
            
        except Exception as e:
            logger.error(f"创建漏洞对象失败: {e}")
            return None   
 # 层级RAG处理方法
    async def _apply_txtai_enhancement(self, vulnerabilities: List[VulnerabilityResult]) -> List[VulnerabilityResult]:
        """应用txtai层知识检索增强"""
        start_time = time.time()
        
        enhanced_vulnerabilities = []
        for vuln in vulnerabilities:
            try:
                knowledge_info = await self.txtai_retriever.retrieve_vulnerability_info(
                    vuln.vulnerability_type, vuln.snippet
                )
                
                enhanced_vuln = await self.txtai_retriever.enhance_vulnerability(
                    vuln, knowledge_info
                )
                enhanced_vulnerabilities.append(enhanced_vuln)
                
            except Exception as e:
                logger.warning(f"txtai增强失败: {vuln.id}, {e}")
                enhanced_vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        self.performance_metrics["layer_performance"]["txtai"]["calls"] += 1
        self.performance_metrics["layer_performance"]["txtai"]["total_time"] += execution_time
        
        return enhanced_vulnerabilities
    
    async def _apply_r2r_enhancement(self, vulnerabilities: List[VulnerabilityResult], 
                                   source_files: List[SourceFile]) -> List[VulnerabilityResult]:
        """应用R2R层上下文增强"""
        start_time = time.time()
        
        global_context = await self.r2r_enhancer.build_global_context(source_files)
        
        enhanced_vulnerabilities = []
        for vuln in vulnerabilities:
            try:
                enhanced_context = await self.r2r_enhancer.enhance_context(
                    vuln, global_context
                )
                
                enhanced_vuln = await self.r2r_enhancer.apply_context_enhancement(
                    vuln, enhanced_context
                )
                enhanced_vulnerabilities.append(enhanced_vuln)
                
            except Exception as e:
                logger.warning(f"R2R增强失败: {vuln.id}, {e}")
                enhanced_vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        self.performance_metrics["layer_performance"]["r2r"]["calls"] += 1
        self.performance_metrics["layer_performance"]["r2r"]["total_time"] += execution_time
        
        return enhanced_vulnerabilities
    
    async def _apply_self_rag_validation(self, vulnerabilities: List[VulnerabilityResult]) -> List[VulnerabilityResult]:
        """应用Self-RAG层验证与过滤"""
        start_time = time.time()
        
        validated_vulnerabilities = []
        for vuln in vulnerabilities:
            try:
                validation_result = await self.self_rag_validator.validate_vulnerability(vuln)
                
                if validation_result.is_valid:
                    vuln.confidence = validation_result.confidence_score
                    vuln.validation_metadata = validation_result.metadata
                    validated_vulnerabilities.append(vuln)
                else:
                    logger.debug(f"漏洞被Self-RAG过滤: {vuln.id}")
                
            except Exception as e:
                logger.warning(f"Self-RAG验证失败: {vuln.id}, {e}")
                validated_vulnerabilities.append(vuln)
        
        execution_time = time.time() - start_time
        self.performance_metrics["layer_performance"]["self_rag"]["calls"] += 1
        self.performance_metrics["layer_performance"]["self_rag"]["total_time"] += execution_time
        
        return validated_vulnerabilities
    
    async def _integrate_results(self, vulnerabilities: List[VulnerabilityResult], 
                               task_results: List[TaskResult], start_time: float) -> AuditResult:
        """结果整合"""
        processing_time = time.time() - start_time
        
        integration_result = await self.result_integrator.integrate_results(
            task_results, ConflictResolutionStrategy.CONSENSUS
        )
        
        final_vulnerabilities = integration_result.integrated_vulnerabilities
        
        if final_vulnerabilities:
            confidence_score = sum(v.confidence for v in final_vulnerabilities) / len(final_vulnerabilities)
        else:
            confidence_score = 1.0
        
        execution_summary = {
            "total_tasks": len(task_results),
            "successful_tasks": len([r for r in task_results if not r.metadata.get("error")]),
            "total_vulnerabilities": len(final_vulnerabilities),
            "original_vulnerabilities": len(vulnerabilities),
            "duplicate_count": integration_result.duplicate_count,
            "conflict_count": integration_result.conflict_count,
            "processing_time": processing_time,
            "integration_time": integration_result.processing_time,
            "layer_performance": self.performance_metrics["layer_performance"],
            "task_breakdown": {
                task_type.value: len([r for r in task_results if r.task_type == task_type])
                for task_type in TaskType
            },
            "quality_metrics": integration_result.quality_metrics,
            "integration_metadata": integration_result.integration_metadata,
            "haystack_enabled": HAYSTACK_AVAILABLE,
            "haystack_pipelines_used": sum(1 for r in task_results if r.metadata.get("haystack_pipeline_used", False))
        }
        
        return AuditResult(
            vulnerabilities=final_vulnerabilities,
            task_results=task_results,
            execution_summary=execution_summary,
            confidence_score=confidence_score,
            processing_time=processing_time
        )
    
    # 辅助方法
    def _calculate_task_confidence(self, task: AuditTask, vulnerabilities: List[VulnerabilityResult]) -> float:
        """计算任务置信度"""
        if not vulnerabilities:
            return 1.0
        
        base_confidence = 0.8
        
        type_multipliers = {
            TaskType.SYNTAX_CHECK: 0.95,
            TaskType.LOGIC_ANALYSIS: 0.85,
            TaskType.SECURITY_SCAN: 0.80,
            TaskType.DEPENDENCY_ANALYSIS: 0.90
        }
        
        multiplier = type_multipliers.get(task.task_type, 0.8)
        
        # 如果使用了Haystack管道，提高置信度
        if HAYSTACK_AVAILABLE and self.pipelines.get(task.task_type):
            multiplier *= 1.1
        
        return min(1.0, base_confidence * multiplier)
    
    async def _has_syntax_issues(self, code_unit: CodeUnit) -> bool:
        """检查代码单元是否有语法问题"""
        content = code_unit.content
        
        syntax_issues = [
            'SyntaxError',
            'IndentationError',
            'TabError',
            'unexpected EOF',
            'invalid syntax'
        ]
        
        return any(issue in content for issue in syntax_issues)
    
    async def _basic_security_scan(self, code_unit: CodeUnit) -> List[VulnerabilityResult]:
        """基础安全扫描"""
        vulnerabilities = []
        content = code_unit.content.lower()
        
        security_patterns = {
            "sql injection": ["select", "insert", "update", "delete", "drop"],
            "xss": ["<script", "javascript:", "eval("],
            "command injection": ["system(", "exec(", "shell_exec"],
            "path traversal": ["../", "..\\", "path.join"]
        }
        
        for vuln_type, patterns in security_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    vuln = VulnerabilityResult(
                        id=f"security_{uuid.uuid4().hex[:8]}",
                        vulnerability_type=vuln_type,
                        severity="medium",
                        description=f"检测到潜在的{vuln_type}问题",
                        file_path=str(code_unit.source_file.path),
                        start_line=code_unit.start_line,
                        end_line=code_unit.end_line,
                        snippet=code_unit.content[:200],
                        confidence=0.6
                    )
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    def _update_performance_metrics(self, processing_time: float):
        """更新性能指标"""
        self.performance_metrics["tasks_completed"] += 1
        self.performance_metrics["total_execution_time"] += processing_time
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """获取性能摘要"""
        total_tasks = self.performance_metrics["tasks_completed"]
        if total_tasks == 0:
            return {"message": "尚未执行任何任务"}
        
        avg_execution_time = self.performance_metrics["total_execution_time"] / total_tasks
        
        layer_summary = {}
        for layer, metrics in self.performance_metrics["layer_performance"].items():
            if metrics["calls"] > 0:
                layer_summary[layer] = {
                    "calls": metrics["calls"],
                    "avg_time": metrics["total_time"] / metrics["calls"],
                    "total_time": metrics["total_time"]
                }
        
        return {
            "total_tasks_completed": total_tasks,
            "average_execution_time": avg_execution_time,
            "total_execution_time": self.performance_metrics["total_execution_time"],
            "layer_performance": layer_summary,
            "haystack_enabled": HAYSTACK_AVAILABLE,
            "pipelines_available": len(self.pipelines) if self.pipelines else 0
        } 
   # ==================== 兼容性接口 ====================
    # 以下方法提供与现有AgentOrchestrator的兼容性
    
    async def initialize_agents(self) -> None:
        """初始化智能体 - 兼容性方法"""
        logger.info("Haystack-AI编排器：智能体初始化（兼容性模式）")
        self.agents = {
            "haystack_ai_orchestrator": self,
            "txtai_retriever": self.txtai_retriever,
            "r2r_enhancer": self.r2r_enhancer,
            "self_rag_validator": self.self_rag_validator,
            "haystack_pipelines": self.pipelines
        }
        logger.info(f"Haystack-AI编排器：已初始化 {len(self.agents)} 个组件")
    
    async def extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """提取代码单元 - 兼容性方法"""
        logger.info(f"Haystack-AI编排器：提取代码单元，文件数: {len(source_files)}")
        
        try:
            from auditluma.parsers.code_parser import CodeParser
            
            code_units = []
            parser = CodeParser()
            
            for source_file in source_files:
                try:
                    file_units = await parser.parse_file_async(source_file)
                    code_units.extend(file_units)
                except Exception as e:
                    logger.warning(f"解析文件失败: {source_file.path}, {e}")
            
            self.code_units = code_units
            return code_units
            
        except ImportError:
            logger.warning("代码解析器不可用，使用简化的代码单元提取")
            return self._simple_extract_code_units(source_files)
    
    def _simple_extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """简化的代码单元提取"""
        code_units = []
        
        for source_file in source_files:
            import hashlib
            unit = CodeUnit(
                id=f"file_{hashlib.md5(str(source_file.path).encode()).hexdigest()[:8]}",
                name=source_file.path.name,
                type="file",
                content=source_file.content,
                source_file=source_file,
                start_line=1,
                end_line=len(source_file.content.splitlines())
            )
            code_units.append(unit)
        
        self.code_units = code_units
        return code_units
    
    async def run_security_analysis(self, source_files: List[SourceFile], 
                                   skip_cross_file: bool = False, 
                                   enhanced_analysis: bool = False) -> List[VulnerabilityResult]:
        """运行安全分析 - 兼容性方法，使用Haystack-AI层级RAG架构"""
        logger.info(f"Haystack-AI编排器：开始层级RAG安全分析，文件数: {len(source_files)}")
        
        try:
            audit_result = await self.orchestrate_audit(source_files)
            logger.info(f"Haystack-AI编排器：层级RAG分析完成，发现漏洞: {len(audit_result.vulnerabilities)}")
            return audit_result.vulnerabilities
            
        except Exception as e:
            logger.error(f"Haystack-AI编排器：安全分析失败: {e}")
            return []
    
    async def run_code_structure_analysis(self, code_units: List[CodeUnit]) -> Dict[str, Any]:
        """运行代码结构分析 - 兼容性方法"""
        logger.info(f"Haystack-AI编排器：代码结构分析，代码单元数: {len(code_units)}")
        
        structure_info = {
            "total_units": len(code_units),
            "unit_types": {},
            "file_distribution": {},
            "complexity_metrics": {},
            "haystack_enabled": HAYSTACK_AVAILABLE
        }
        
        for unit in code_units:
            unit_type = getattr(unit, 'type', 'unknown')
            structure_info["unit_types"][unit_type] = structure_info["unit_types"].get(unit_type, 0) + 1
            
            file_path = str(unit.source_file.path)
            structure_info["file_distribution"][file_path] = structure_info["file_distribution"].get(file_path, 0) + 1
        
        logger.info(f"Haystack-AI编排器：结构分析完成，单元类型: {len(structure_info['unit_types'])}")
        return structure_info
    
    async def generate_remediations(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """生成修复建议 - 兼容性方法"""
        logger.info(f"Haystack-AI编排器：生成修复建议，漏洞数: {len(vulnerabilities)}")
        
        if not vulnerabilities:
            return {
                "summary": "未发现需要修复的漏洞",
                "remediation_count": 0,
                "remediations": []
            }
        
        remediations = []
        
        for vuln in vulnerabilities:
            try:
                remediation_info = await self.txtai_retriever.get_remediation_suggestions(
                    vuln.vulnerability_type, vuln.description
                )
                
                remediation = {
                    "vulnerability_id": vuln.id,
                    "vulnerability_type": vuln.vulnerability_type,
                    "suggestions": remediation_info.get("suggestions", []),
                    "best_practices": remediation_info.get("best_practices", []),
                    "code_examples": remediation_info.get("code_examples", []),
                    "haystack_enhanced": HAYSTACK_AVAILABLE
                }
                remediations.append(remediation)
                
            except Exception as e:
                logger.warning(f"生成修复建议失败: {vuln.id}, {e}")
                remediation = {
                    "vulnerability_id": vuln.id,
                    "vulnerability_type": vuln.vulnerability_type,
                    "suggestions": [f"请修复 {vuln.vulnerability_type} 漏洞"],
                    "best_practices": ["遵循安全编码规范"],
                    "code_examples": [],
                    "haystack_enhanced": False
                }
                remediations.append(remediation)
        
        return {
            "summary": f"为 {len(vulnerabilities)} 个漏洞生成了修复建议",
            "remediation_count": len(remediations),
            "remediations": remediations,
            "haystack_enabled": HAYSTACK_AVAILABLE
        }
    
    async def run_analysis(self, source_files: List[SourceFile]) -> List[VulnerabilityResult]:
        """运行分析 - 兼容性方法"""
        logger.info(f"Haystack-AI编排器：运行完整分析，文件数: {len(source_files)}")
        return await self.run_security_analysis(source_files)
    
    async def generate_summary(self, vulnerabilities: List[VulnerabilityResult], 
                             assessment: Dict[str, Any] = None) -> str:
        """生成摘要 - 兼容性方法"""
        if not vulnerabilities:
            return "未发现安全漏洞。"
        
        # 按严重程度分类
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # 按类型分类
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        # 生成摘要
        summary_parts = [
            f"🔍 Haystack-AI层级RAG安全分析摘要",
            f"📊 发现漏洞总数: {len(vulnerabilities)}",
            "",
            "📈 严重程度分布:"
        ]
        
        for severity, count in sorted(severity_counts.items()):
            summary_parts.append(f"  - {severity}: {count}")
        
        summary_parts.extend([
            "",
            "🏷️ 漏洞类型分布:"
        ])
        
        for vuln_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            summary_parts.append(f"  - {vuln_type}: {count}")
        
        # 添加性能信息
        perf_summary = self.get_performance_summary()
        if "total_tasks_completed" in perf_summary:
            summary_parts.extend([
                "",
                "⚡ 性能指标:",
                f"  - 完成任务数: {perf_summary['total_tasks_completed']}",
                f"  - 平均执行时间: {perf_summary.get('average_execution_time', 0):.2f}秒",
                f"  - Haystack管道: {'启用' if perf_summary.get('haystack_enabled') else '禁用'}",
                f"  - 可用管道数: {perf_summary.get('pipelines_available', 0)}"
            ])
        
        return "\n".join(summary_parts)
    
    async def generate_audit_report(self, audit_result: AuditResult) -> str:
        """生成详细的审计报告"""
        try:
            integration_result_mock = type('IntegrationResult', (), {
                'integrated_vulnerabilities': audit_result.vulnerabilities,
                'duplicate_count': audit_result.execution_summary.get('duplicate_count', 0),
                'conflict_count': audit_result.execution_summary.get('conflict_count', 0),
                'clusters': [],
                'integration_metadata': audit_result.execution_summary.get('integration_metadata', {}),
                'quality_metrics': audit_result.execution_summary.get('quality_metrics', {}),
                'processing_time': audit_result.processing_time
            })()
            
            report = await self.result_integrator.generate_audit_report(
                integration_result_mock, audit_result.task_results
            )
            
            # 格式化报告
            report_text = f"""
{report.title} (Haystack-AI增强版)
{'=' * (len(report.title) + 15)}

生成时间: {report.generated_at}
报告ID: {report.report_id}
处理时间: {report.processing_time:.2f}秒
Haystack-AI: {'启用' if HAYSTACK_AVAILABLE else '禁用'}
管道数量: {len(self.pipelines) if self.pipelines else 0}

{report.summary}

"""
            
            for section in report.sections:
                report_text += f"""
{section.title}
{'-' * len(section.title)}
{section.content}

"""
            
            if report.recommendations:
                report_text += """
建议
----
"""
                for i, rec in enumerate(report.recommendations, 1):
                    report_text += f"{i}. {rec}\n"
            
            # 添加Haystack-AI特定信息
            if HAYSTACK_AVAILABLE:
                report_text += f"""

Haystack-AI技术细节
------------------
• 使用的管道类型: {list(self.pipelines.keys()) if self.pipelines else '无'}
• 管道执行成功率: {audit_result.execution_summary.get('haystack_pipelines_used', 0)}/{audit_result.execution_summary.get('total_tasks', 0)}
• 层级RAG架构: txtai → R2R → Self-RAG → 结果整合
• 智能冲突解决: 共识算法
• 自动去重: {audit_result.execution_summary.get('duplicate_count', 0)} 个重复项
"""
            
            return report_text
            
        except Exception as e:
            logger.error(f"生成Haystack-AI审计报告失败: {e}")
            return self.generate_summary(audit_result.vulnerabilities, audit_result.execution_summary)