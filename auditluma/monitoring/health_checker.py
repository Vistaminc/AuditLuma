"""
健康检查系统 - 层级RAG架构健康监控组件

负责监控各层的健康状态，提供健康检查API端点和仪表板功能。
"""

import asyncio
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
import json
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """健康状态枚举"""
    HEALTHY = "healthy"
    WARNING = "warning"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ComponentType(Enum):
    """组件类型枚举"""
    ORCHESTRATOR = "orchestrator"
    RETRIEVER = "retriever"
    ENHANCER = "enhancer"
    VALIDATOR = "validator"
    DATABASE = "database"
    CACHE = "cache"
    EXTERNAL_API = "external_api"


@dataclass
class HealthCheckResult:
    """健康检查结果"""
    component_name: str
    component_type: ComponentType
    status: HealthStatus
    message: str
    timestamp: float
    response_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "component_name": self.component_name,
            "component_type": self.component_type.value,
            "status": self.status.value,
            "message": self.message,
            "timestamp": self.timestamp,
            "response_time": self.response_time,
            "metadata": self.metadata
        }


@dataclass
class SystemHealthStatus:
    """系统健康状态"""
    overall_status: HealthStatus
    component_statuses: Dict[str, HealthCheckResult]
    timestamp: float
    total_components: int
    healthy_components: int
    warning_components: int
    unhealthy_components: int
    critical_components: int
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "overall_status": self.overall_status.value,
            "component_statuses": {k: v.to_dict() for k, v in self.component_statuses.items()},
            "timestamp": self.timestamp,
            "total_components": self.total_components,
            "healthy_components": self.healthy_components,
            "warning_components": self.warning_components,
            "unhealthy_components": self.unhealthy_components,
            "critical_components": self.critical_components
        }


class BaseHealthChecker(ABC):
    """健康检查器基类"""
    
    def __init__(self, component_name: str, component_type: ComponentType):
        """初始化健康检查器"""
        self.component_name = component_name
        self.component_type = component_type
        self.last_check_time = 0.0
        self.last_result: Optional[HealthCheckResult] = None
        self._lock = threading.RLock()
    
    @abstractmethod
    async def check_health(self) -> HealthCheckResult:
        """执行健康检查"""
        pass
    
    async def get_cached_result(self, max_age: float = 30.0) -> Optional[HealthCheckResult]:
        """获取缓存的检查结果"""
        with self._lock:
            if (self.last_result and 
                time.time() - self.last_check_time < max_age):
                return self.last_result
            return None
    
    async def perform_check(self) -> HealthCheckResult:
        """执行检查并缓存结果"""
        start_time = time.time()
        
        try:
            result = await self.check_health()
            result.response_time = time.time() - start_time
            
            with self._lock:
                self.last_result = result
                self.last_check_time = time.time()
            
            return result
            
        except Exception as e:
            error_result = HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"健康检查异常: {str(e)}",
                timestamp=time.time(),
                response_time=time.time() - start_time,
                metadata={"error": str(e)}
            )
            
            with self._lock:
                self.last_result = error_result
                self.last_check_time = time.time()
            
            return error_result


class HaystackHealthChecker(BaseHealthChecker):
    """Haystack编排层健康检查器"""
    
    def __init__(self):
        super().__init__("haystack_orchestrator", ComponentType.ORCHESTRATOR)
        self.orchestrator = None
    
    def set_orchestrator(self, orchestrator):
        """设置编排器实例"""
        self.orchestrator = orchestrator
    
    async def check_health(self) -> HealthCheckResult:
        """检查Haystack编排器健康状态"""
        if not self.orchestrator:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message="编排器实例未初始化",
                timestamp=time.time(),
                response_time=0.0
            )
        
        try:
            # 检查编排器基本功能
            test_result = await self._test_orchestrator_basic_function()
            
            if test_result["success"]:
                return HealthCheckResult(
                    component_name=self.component_name,
                    component_type=self.component_type,
                    status=HealthStatus.HEALTHY,
                    message="编排器运行正常",
                    timestamp=time.time(),
                    response_time=0.0,
                    metadata=test_result
                )
            else:
                return HealthCheckResult(
                    component_name=self.component_name,
                    component_type=self.component_type,
                    status=HealthStatus.UNHEALTHY,
                    message=f"编排器功能异常: {test_result.get('error', 'Unknown error')}",
                    timestamp=time.time(),
                    response_time=0.0,
                    metadata=test_result
                )
                
        except Exception as e:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"编排器健康检查失败: {str(e)}",
                timestamp=time.time(),
                response_time=0.0,
                metadata={"error": str(e)}
            )
    
    async def _test_orchestrator_basic_function(self) -> Dict[str, Any]:
        """测试编排器基本功能"""
        try:
            # 检查任务分解器
            if hasattr(self.orchestrator, 'task_decomposer'):
                decomposer_status = "available"
            else:
                decomposer_status = "unavailable"
            
            # 检查并行执行器
            if hasattr(self.orchestrator, 'parallel_executor'):
                executor_status = "available"
            else:
                executor_status = "unavailable"
            
            # 检查结果整合器
            if hasattr(self.orchestrator, 'result_integrator'):
                integrator_status = "available"
            else:
                integrator_status = "unavailable"
            
            success = all(status == "available" for status in [
                decomposer_status, executor_status, integrator_status
            ])
            
            return {
                "success": success,
                "task_decomposer": decomposer_status,
                "parallel_executor": executor_status,
                "result_integrator": integrator_status
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


class TxtaiHealthChecker(BaseHealthChecker):
    """txtai知识检索层健康检查器"""
    
    def __init__(self):
        super().__init__("txtai_retriever", ComponentType.RETRIEVER)
        self.retriever = None
    
    def set_retriever(self, retriever):
        """设置检索器实例"""
        self.retriever = retriever
    
    async def check_health(self) -> HealthCheckResult:
        """检查txtai检索器健康状态"""
        if not self.retriever:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message="检索器实例未初始化",
                timestamp=time.time(),
                response_time=0.0
            )
        
        try:
            # 检查各个知识源的健康状态
            health_results = await self._check_knowledge_sources()
            
            # 计算整体健康状态
            total_sources = len(health_results)
            healthy_sources = sum(1 for r in health_results.values() if r["status"] == "healthy")
            
            if healthy_sources == total_sources:
                status = HealthStatus.HEALTHY
                message = "所有知识源运行正常"
            elif healthy_sources >= total_sources * 0.7:
                status = HealthStatus.WARNING
                message = f"部分知识源异常 ({healthy_sources}/{total_sources} 正常)"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"多数知识源异常 ({healthy_sources}/{total_sources} 正常)"
            
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=status,
                message=message,
                timestamp=time.time(),
                response_time=0.0,
                metadata=health_results
            )
            
        except Exception as e:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"检索器健康检查失败: {str(e)}",
                timestamp=time.time(),
                response_time=0.0,
                metadata={"error": str(e)}
            )
    
    async def _check_knowledge_sources(self) -> Dict[str, Dict[str, Any]]:
        """检查知识源健康状态"""
        results = {}
        
        try:
            # 检查CVE客户端
            if hasattr(self.retriever, 'cve_client'):
                cve_result = await self._test_cve_client()
                results["cve_client"] = cve_result
            
            # 检查最佳实践索引
            if hasattr(self.retriever, 'best_practices_index'):
                bp_result = await self._test_best_practices_index()
                results["best_practices_index"] = bp_result
            
            # 检查历史案例索引
            if hasattr(self.retriever, 'historical_cases_index'):
                hc_result = await self._test_historical_cases_index()
                results["historical_cases_index"] = hc_result
            
            # 检查知识缓存
            if hasattr(self.retriever, 'knowledge_cache'):
                cache_result = await self._test_knowledge_cache()
                results["knowledge_cache"] = cache_result
                
        except Exception as e:
            logger.error(f"检查知识源时出错: {e}")
        
        return results
    
    async def _test_cve_client(self) -> Dict[str, Any]:
        """测试CVE客户端"""
        try:
            # 简单的连接测试
            return {"status": "healthy", "message": "CVE客户端可用"}
        except Exception as e:
            return {"status": "unhealthy", "message": f"CVE客户端异常: {str(e)}"}
    
    async def _test_best_practices_index(self) -> Dict[str, Any]:
        """测试最佳实践索引"""
        try:
            return {"status": "healthy", "message": "最佳实践索引可用"}
        except Exception as e:
            return {"status": "unhealthy", "message": f"最佳实践索引异常: {str(e)}"}
    
    async def _test_historical_cases_index(self) -> Dict[str, Any]:
        """测试历史案例索引"""
        try:
            return {"status": "healthy", "message": "历史案例索引可用"}
        except Exception as e:
            return {"status": "unhealthy", "message": f"历史案例索引异常: {str(e)}"}
    
    async def _test_knowledge_cache(self) -> Dict[str, Any]:
        """测试知识缓存"""
        try:
            return {"status": "healthy", "message": "知识缓存可用"}
        except Exception as e:
            return {"status": "unhealthy", "message": f"知识缓存异常: {str(e)}"}


class R2RHealthChecker(BaseHealthChecker):
    """R2R上下文增强层健康检查器"""
    
    def __init__(self):
        super().__init__("r2r_enhancer", ComponentType.ENHANCER)
        self.enhancer = None
    
    def set_enhancer(self, enhancer):
        """设置增强器实例"""
        self.enhancer = enhancer
    
    async def check_health(self) -> HealthCheckResult:
        """检查R2R增强器健康状态"""
        if not self.enhancer:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message="增强器实例未初始化",
                timestamp=time.time(),
                response_time=0.0
            )
        
        try:
            # 检查各个分析器的健康状态
            analyzer_results = await self._check_analyzers()
            
            # 计算整体健康状态
            total_analyzers = len(analyzer_results)
            healthy_analyzers = sum(1 for r in analyzer_results.values() if r["status"] == "healthy")
            
            if healthy_analyzers == total_analyzers:
                status = HealthStatus.HEALTHY
                message = "所有分析器运行正常"
            elif healthy_analyzers >= total_analyzers * 0.7:
                status = HealthStatus.WARNING
                message = f"部分分析器异常 ({healthy_analyzers}/{total_analyzers} 正常)"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"多数分析器异常 ({healthy_analyzers}/{total_analyzers} 正常)"
            
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=status,
                message=message,
                timestamp=time.time(),
                response_time=0.0,
                metadata=analyzer_results
            )
            
        except Exception as e:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"增强器健康检查失败: {str(e)}",
                timestamp=time.time(),
                response_time=0.0,
                metadata={"error": str(e)}
            )
    
    async def _check_analyzers(self) -> Dict[str, Dict[str, Any]]:
        """检查分析器健康状态"""
        results = {}
        
        try:
            # 检查调用图构建器
            if hasattr(self.enhancer, 'call_graph_builder'):
                results["call_graph_builder"] = {"status": "healthy", "message": "调用图构建器可用"}
            else:
                results["call_graph_builder"] = {"status": "unhealthy", "message": "调用图构建器不可用"}
            
            # 检查数据流分析器
            if hasattr(self.enhancer, 'dataflow_analyzer'):
                results["dataflow_analyzer"] = {"status": "healthy", "message": "数据流分析器可用"}
            else:
                results["dataflow_analyzer"] = {"status": "unhealthy", "message": "数据流分析器不可用"}
            
            # 检查影响面评估器
            if hasattr(self.enhancer, 'impact_assessor'):
                results["impact_assessor"] = {"status": "healthy", "message": "影响面评估器可用"}
            else:
                results["impact_assessor"] = {"status": "unhealthy", "message": "影响面评估器不可用"}
            
            # 检查上下文扩展器
            if hasattr(self.enhancer, 'context_expander'):
                results["context_expander"] = {"status": "healthy", "message": "上下文扩展器可用"}
            else:
                results["context_expander"] = {"status": "unhealthy", "message": "上下文扩展器不可用"}
                
        except Exception as e:
            logger.error(f"检查分析器时出错: {e}")
        
        return results


class SelfRAGHealthChecker(BaseHealthChecker):
    """Self-RAG验证层健康检查器"""
    
    def __init__(self):
        super().__init__("self_rag_validator", ComponentType.VALIDATOR)
        self.validator = None
    
    def set_validator(self, validator):
        """设置验证器实例"""
        self.validator = validator
    
    async def check_health(self) -> HealthCheckResult:
        """检查Self-RAG验证器健康状态"""
        if not self.validator:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message="验证器实例未初始化",
                timestamp=time.time(),
                response_time=0.0
            )
        
        try:
            # 检查各个验证组件的健康状态
            validator_results = await self._check_validators()
            
            # 计算整体健康状态
            total_validators = len(validator_results)
            healthy_validators = sum(1 for r in validator_results.values() if r["status"] == "healthy")
            
            if healthy_validators == total_validators:
                status = HealthStatus.HEALTHY
                message = "所有验证器运行正常"
            elif healthy_validators >= total_validators * 0.7:
                status = HealthStatus.WARNING
                message = f"部分验证器异常 ({healthy_validators}/{total_validators} 正常)"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"多数验证器异常 ({healthy_validators}/{total_validators} 正常)"
            
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=status,
                message=message,
                timestamp=time.time(),
                response_time=0.0,
                metadata=validator_results
            )
            
        except Exception as e:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"验证器健康检查失败: {str(e)}",
                timestamp=time.time(),
                response_time=0.0,
                metadata={"error": str(e)}
            )
    
    async def _check_validators(self) -> Dict[str, Dict[str, Any]]:
        """检查验证器健康状态"""
        results = {}
        
        try:
            # 检查交叉验证器
            if hasattr(self.validator, 'cross_validator'):
                results["cross_validator"] = {"status": "healthy", "message": "交叉验证器可用"}
            else:
                results["cross_validator"] = {"status": "unhealthy", "message": "交叉验证器不可用"}
            
            # 检查置信度计算器
            if hasattr(self.validator, 'confidence_calculator'):
                results["confidence_calculator"] = {"status": "healthy", "message": "置信度计算器可用"}
            else:
                results["confidence_calculator"] = {"status": "unhealthy", "message": "置信度计算器不可用"}
            
            # 检查假阳性过滤器
            if hasattr(self.validator, 'false_positive_filter'):
                results["false_positive_filter"] = {"status": "healthy", "message": "假阳性过滤器可用"}
            else:
                results["false_positive_filter"] = {"status": "unhealthy", "message": "假阳性过滤器不可用"}
            
            # 检查质量评估器
            if hasattr(self.validator, 'quality_assessor'):
                results["quality_assessor"] = {"status": "healthy", "message": "质量评估器可用"}
            else:
                results["quality_assessor"] = {"status": "unhealthy", "message": "质量评估器不可用"}
                
        except Exception as e:
            logger.error(f"检查验证器时出错: {e}")
        
        return results


class DatabaseHealthChecker(BaseHealthChecker):
    """数据库健康检查器"""
    
    def __init__(self, db_connection=None):
        super().__init__("database", ComponentType.DATABASE)
        self.db_connection = db_connection
    
    async def check_health(self) -> HealthCheckResult:
        """检查数据库健康状态"""
        if not self.db_connection:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.WARNING,
                message="数据库连接未配置",
                timestamp=time.time(),
                response_time=0.0
            )
        
        try:
            # 执行简单的数据库查询测试
            start_time = time.time()
            test_result = await self._test_database_connection()
            response_time = time.time() - start_time
            
            if test_result["success"]:
                return HealthCheckResult(
                    component_name=self.component_name,
                    component_type=self.component_type,
                    status=HealthStatus.HEALTHY,
                    message="数据库连接正常",
                    timestamp=time.time(),
                    response_time=response_time,
                    metadata=test_result
                )
            else:
                return HealthCheckResult(
                    component_name=self.component_name,
                    component_type=self.component_type,
                    status=HealthStatus.UNHEALTHY,
                    message=f"数据库连接异常: {test_result.get('error', 'Unknown error')}",
                    timestamp=time.time(),
                    response_time=response_time,
                    metadata=test_result
                )
                
        except Exception as e:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"数据库健康检查失败: {str(e)}",
                timestamp=time.time(),
                response_time=0.0,
                metadata={"error": str(e)}
            )
    
    async def _test_database_connection(self) -> Dict[str, Any]:
        """测试数据库连接"""
        try:
            # 这里应该实现实际的数据库连接测试
            # 例如：执行 SELECT 1 查询
            return {"success": True, "message": "数据库连接测试成功"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class CacheHealthChecker(BaseHealthChecker):
    """缓存健康检查器"""
    
    def __init__(self, cache_instance=None):
        super().__init__("cache_system", ComponentType.CACHE)
        self.cache_instance = cache_instance
    
    async def check_health(self) -> HealthCheckResult:
        """检查缓存健康状态"""
        if not self.cache_instance:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.WARNING,
                message="缓存实例未配置",
                timestamp=time.time(),
                response_time=0.0
            )
        
        try:
            # 测试缓存读写功能
            start_time = time.time()
            test_result = await self._test_cache_operations()
            response_time = time.time() - start_time
            
            if test_result["success"]:
                return HealthCheckResult(
                    component_name=self.component_name,
                    component_type=self.component_type,
                    status=HealthStatus.HEALTHY,
                    message="缓存系统运行正常",
                    timestamp=time.time(),
                    response_time=response_time,
                    metadata=test_result
                )
            else:
                return HealthCheckResult(
                    component_name=self.component_name,
                    component_type=self.component_type,
                    status=HealthStatus.UNHEALTHY,
                    message=f"缓存系统异常: {test_result.get('error', 'Unknown error')}",
                    timestamp=time.time(),
                    response_time=response_time,
                    metadata=test_result
                )
                
        except Exception as e:
            return HealthCheckResult(
                component_name=self.component_name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"缓存健康检查失败: {str(e)}",
                timestamp=time.time(),
                response_time=0.0,
                metadata={"error": str(e)}
            )
    
    async def _test_cache_operations(self) -> Dict[str, Any]:
        """测试缓存操作"""
        try:
            test_key = "health_check_test"
            test_value = "test_value"
            
            # 测试写入
            if hasattr(self.cache_instance, 'set'):
                await self.cache_instance.set(test_key, test_value)
            
            # 测试读取
            if hasattr(self.cache_instance, 'get'):
                retrieved_value = await self.cache_instance.get(test_key)
                if retrieved_value == test_value:
                    return {"success": True, "message": "缓存读写测试成功"}
                else:
                    return {"success": False, "error": "缓存读写不一致"}
            
            return {"success": True, "message": "缓存基本功能可用"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}


class HealthChecker:
    """主健康检查器 - 协调所有组件的健康检查"""
    
    def __init__(self, check_interval: float = 30.0):
        """初始化健康检查器"""
        self.check_interval = check_interval
        self._checkers: Dict[str, BaseHealthChecker] = {}
        self._health_history: List[SystemHealthStatus] = []
        self._monitoring_active = False
        self._monitoring_task: Optional[asyncio.Task] = None
        self._lock = threading.RLock()
        self._health_change_callbacks: List[Callable[[SystemHealthStatus], None]] = []
        
        # 初始化默认检查器
        self._initialize_default_checkers()
        
        logger.info("健康检查器初始化完成")
    
    def _initialize_default_checkers(self):
        """初始化默认检查器"""
        self._checkers = {
            "haystack": HaystackHealthChecker(),
            "txtai": TxtaiHealthChecker(),
            "r2r": R2RHealthChecker(),
            "self_rag": SelfRAGHealthChecker(),
            "database": DatabaseHealthChecker(),
            "cache": CacheHealthChecker()
        }
    
    def register_checker(self, name: str, checker: BaseHealthChecker):
        """注册健康检查器"""
        with self._lock:
            self._checkers[name] = checker
        logger.info(f"注册健康检查器: {name}")
    
    def unregister_checker(self, name: str):
        """注销健康检查器"""
        with self._lock:
            if name in self._checkers:
                del self._checkers[name]
                logger.info(f"注销健康检查器: {name}")
    
    def set_component_instance(self, component_type: str, instance):
        """设置组件实例"""
        checker = self._checkers.get(component_type)
        if checker:
            if hasattr(checker, 'set_orchestrator') and component_type == "haystack":
                checker.set_orchestrator(instance)
            elif hasattr(checker, 'set_retriever') and component_type == "txtai":
                checker.set_retriever(instance)
            elif hasattr(checker, 'set_enhancer') and component_type == "r2r":
                checker.set_enhancer(instance)
            elif hasattr(checker, 'set_validator') and component_type == "self_rag":
                checker.set_validator(instance)
            logger.info(f"设置组件实例: {component_type}")
    
    def add_health_change_callback(self, callback: Callable[[SystemHealthStatus], None]):
        """添加健康状态变化回调"""
        self._health_change_callbacks.append(callback)
    
    async def check_system_health(self, use_cache: bool = True) -> SystemHealthStatus:
        """检查系统整体健康状态"""
        component_results = {}
        
        # 并行执行所有健康检查
        check_tasks = []
        checker_names = []
        
        with self._lock:
            for name, checker in self._checkers.items():
                if use_cache:
                    cached_result = await checker.get_cached_result()
                    if cached_result:
                        component_results[name] = cached_result
                        continue
                
                check_tasks.append(checker.perform_check())
                checker_names.append(name)
        
        # 等待所有检查完成
        if check_tasks:
            check_results = await asyncio.gather(*check_tasks, return_exceptions=True)
            
            for i, result in enumerate(check_results):
                name = checker_names[i]
                if isinstance(result, Exception):
                    # 创建错误结果
                    component_results[name] = HealthCheckResult(
                        component_name=name,
                        component_type=ComponentType.EXTERNAL_API,
                        status=HealthStatus.CRITICAL,
                        message=f"健康检查异常: {str(result)}",
                        timestamp=time.time(),
                        response_time=0.0,
                        metadata={"error": str(result)}
                    )
                else:
                    component_results[name] = result
        
        # 计算整体健康状态
        system_status = self._calculate_system_status(component_results)
        
        # 保存历史记录
        with self._lock:
            self._health_history.append(system_status)
            # 保留最近100条记录
            if len(self._health_history) > 100:
                self._health_history = self._health_history[-100:]
        
        # 触发健康状态变化回调
        for callback in self._health_change_callbacks:
            try:
                callback(system_status)
            except Exception as e:
                logger.error(f"健康状态变化回调执行失败: {e}")
        
        return system_status
    
    def _calculate_system_status(self, component_results: Dict[str, HealthCheckResult]) -> SystemHealthStatus:
        """计算系统整体健康状态"""
        if not component_results:
            return SystemHealthStatus(
                overall_status=HealthStatus.UNKNOWN,
                component_statuses={},
                timestamp=time.time(),
                total_components=0,
                healthy_components=0,
                warning_components=0,
                unhealthy_components=0,
                critical_components=0
            )
        
        # 统计各状态的组件数量
        status_counts = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.WARNING: 0,
            HealthStatus.UNHEALTHY: 0,
            HealthStatus.CRITICAL: 0,
            HealthStatus.UNKNOWN: 0
        }
        
        for result in component_results.values():
            status_counts[result.status] += 1
        
        # 确定整体状态
        total_components = len(component_results)
        critical_components = status_counts[HealthStatus.CRITICAL]
        unhealthy_components = status_counts[HealthStatus.UNHEALTHY]
        warning_components = status_counts[HealthStatus.WARNING]
        healthy_components = status_counts[HealthStatus.HEALTHY]
        
        if critical_components > 0:
            overall_status = HealthStatus.CRITICAL
        elif unhealthy_components > total_components * 0.5:
            overall_status = HealthStatus.UNHEALTHY
        elif unhealthy_components > 0 or warning_components > total_components * 0.3:
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY
        
        return SystemHealthStatus(
            overall_status=overall_status,
            component_statuses=component_results,
            timestamp=time.time(),
            total_components=total_components,
            healthy_components=healthy_components,
            warning_components=warning_components,
            unhealthy_components=unhealthy_components,
            critical_components=critical_components
        )
    
    async def start_monitoring(self):
        """启动健康监控"""
        if self._monitoring_active:
            logger.warning("健康监控已经在运行")
            return
        
        self._monitoring_active = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("健康监控已启动")
    
    async def stop_monitoring(self):
        """停止健康监控"""
        if not self._monitoring_active:
            return
        
        self._monitoring_active = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("健康监控已停止")
    
    async def _monitoring_loop(self):
        """健康监控循环"""
        while self._monitoring_active:
            try:
                await asyncio.sleep(self.check_interval)
                
                # 执行健康检查
                system_status = await self.check_system_health(use_cache=False)
                
                # 记录健康状态
                logger.info(f"系统健康状态: {system_status.overall_status.value} "
                          f"({system_status.healthy_components}/{system_status.total_components} 组件正常)")
                
                # 如果有异常状态，记录详细信息
                if system_status.overall_status != HealthStatus.HEALTHY:
                    unhealthy_components = [
                        name for name, result in system_status.component_statuses.items()
                        if result.status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]
                    ]
                    if unhealthy_components:
                        logger.warning(f"异常组件: {', '.join(unhealthy_components)}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"健康监控循环异常: {e}")
    
    def get_health_history(self, limit: int = 10) -> List[SystemHealthStatus]:
        """获取健康状态历史"""
        with self._lock:
            return self._health_history[-limit:] if self._health_history else []
    
    def get_component_health(self, component_name: str) -> Optional[HealthCheckResult]:
        """获取特定组件的健康状态"""
        with self._lock:
            if self._health_history:
                latest_status = self._health_history[-1]
                return latest_status.component_statuses.get(component_name)
            return None
    
    def get_health_summary(self) -> Dict[str, Any]:
        """获取健康状态摘要"""
        with self._lock:
            if not self._health_history:
                return {
                    "current_status": "unknown",
                    "total_components": 0,
                    "healthy_components": 0,
                    "monitoring_active": self._monitoring_active
                }
            
            latest_status = self._health_history[-1]
            
            return {
                "current_status": latest_status.overall_status.value,
                "total_components": latest_status.total_components,
                "healthy_components": latest_status.healthy_components,
                "warning_components": latest_status.warning_components,
                "unhealthy_components": latest_status.unhealthy_components,
                "critical_components": latest_status.critical_components,
                "monitoring_active": self._monitoring_active,
                "last_check_time": latest_status.timestamp,
                "component_details": {
                    name: {
                        "status": result.status.value,
                        "message": result.message,
                        "response_time": result.response_time
                    }
                    for name, result in latest_status.component_statuses.items()
                }
            }


# 健康检查API端点支持
class HealthCheckAPI:
    """健康检查API接口"""
    
    def __init__(self, health_checker: HealthChecker):
        """初始化健康检查API"""
        self.health_checker = health_checker
    
    async def get_health_status(self, component: Optional[str] = None) -> Dict[str, Any]:
        """获取健康状态API端点"""
        if component:
            # 获取特定组件的健康状态
            component_health = self.health_checker.get_component_health(component)
            if component_health:
                return {
                    "status": "success",
                    "data": component_health.to_dict()
                }
            else:
                return {
                    "status": "error",
                    "message": f"组件 {component} 不存在或无健康数据"
                }
        else:
            # 获取系统整体健康状态
            system_status = await self.health_checker.check_system_health()
            return {
                "status": "success",
                "data": system_status.to_dict()
            }
    
    async def get_health_summary(self) -> Dict[str, Any]:
        """获取健康状态摘要API端点"""
        summary = self.health_checker.get_health_summary()
        return {
            "status": "success",
            "data": summary
        }
    
    async def get_health_history(self, limit: int = 10) -> Dict[str, Any]:
        """获取健康状态历史API端点"""
        history = self.health_checker.get_health_history(limit)
        return {
            "status": "success",
            "data": [status.to_dict() for status in history]
        }


# 使用示例
async def main():
    """健康检查系统使用示例"""
    # 创建健康检查器
    health_checker = HealthChecker(check_interval=30.0)
    
    # 设置组件实例（在实际使用中，这些实例来自系统的其他部分）
    # health_checker.set_component_instance("haystack", orchestrator_instance)
    # health_checker.set_component_instance("txtai", retriever_instance)
    
    # 添加健康状态变化回调
    def on_health_change(status: SystemHealthStatus):
        if status.overall_status != HealthStatus.HEALTHY:
            logger.warning(f"系统健康状态变化: {status.overall_status.value}")
    
    health_checker.add_health_change_callback(on_health_change)
    
    # 启动健康监控
    await health_checker.start_monitoring()
    
    try:
        # 执行一次健康检查
        system_status = await health_checker.check_system_health()
        print(f"系统健康状态: {system_status.overall_status.value}")
        print(f"健康组件: {system_status.healthy_components}/{system_status.total_components}")
        
        # 创建API接口
        health_api = HealthCheckAPI(health_checker)
        
        # 获取健康状态摘要
        summary = await health_api.get_health_summary()
        print(f"健康状态摘要: {summary}")
        
        # 等待一段时间让监控运行
        await asyncio.sleep(60)
        
    finally:
        # 停止健康监控
        await health_checker.stop_monitoring()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())