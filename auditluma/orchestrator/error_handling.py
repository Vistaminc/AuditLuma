"""
层级RAG架构错误处理和容错机制

提供分层错误处理、断路器模式、重试策略和故障恢复机制
"""

import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Callable, Union
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import traceback
import json

logger = logging.getLogger(__name__)


class ErrorSeverity(str, Enum):
    """错误严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(str, Enum):
    """错误类别"""
    NETWORK = "network"
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    PROCESSING = "processing"
    RESOURCE = "resource"
    CONFIGURATION = "configuration"
    EXTERNAL_SERVICE = "external_service"
    UNKNOWN = "unknown"


class CircuitBreakerState(str, Enum):
    """断路器状态"""
    CLOSED = "closed"      # 正常状态
    OPEN = "open"          # 断路状态
    HALF_OPEN = "half_open"  # 半开状态


@dataclass
class ErrorInfo:
    """错误信息"""
    error_id: str
    layer: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    exception: Optional[Exception] = None
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    stack_trace: Optional[str] = None
    
    def __post_init__(self):
        if self.exception and not self.stack_trace:
            self.stack_trace = traceback.format_exception(
                type(self.exception), self.exception, self.exception.__traceback__
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'error_id': self.error_id,
            'layer': self.layer,
            'category': self.category.value,
            'severity': self.severity.value,
            'message': self.message,
            'context': self.context,
            'timestamp': self.timestamp.isoformat(),
            'stack_trace': self.stack_trace
        }


@dataclass
class RetryPolicy:
    """重试策略"""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_backoff: bool = True
    jitter: bool = True
    retryable_exceptions: List[type] = field(default_factory=list)
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """判断是否应该重试"""
        if attempt >= self.max_attempts:
            return False
        
        if not self.retryable_exceptions:
            return True
        
        return any(isinstance(exception, exc_type) for exc_type in self.retryable_exceptions)
    
    def get_delay(self, attempt: int) -> float:
        """获取重试延迟时间"""
        if self.exponential_backoff:
            delay = self.base_delay * (2 ** attempt)
        else:
            delay = self.base_delay
        
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            import random
            delay *= (0.5 + random.random() * 0.5)
        
        return delay


@dataclass
class CircuitBreakerConfig:
    """断路器配置"""
    failure_threshold: int = 5  # 失败阈值
    recovery_timeout: float = 60.0  # 恢复超时时间（秒）
    success_threshold: int = 3  # 半开状态下成功阈值
    timeout: float = 30.0  # 操作超时时间


class CircuitBreaker:
    """断路器实现"""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.last_success_time: Optional[datetime] = None
    
    def is_open(self) -> bool:
        """检查断路器是否打开"""
        if self.state == CircuitBreakerState.OPEN:
            # 检查是否可以转为半开状态
            if (self.last_failure_time and 
                datetime.now() - self.last_failure_time > timedelta(seconds=self.config.recovery_timeout)):
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                logger.info(f"断路器 {self.name} 转为半开状态")
                return False
            return True
        return False
    
    def record_success(self):
        """记录成功"""
        self.last_success_time = datetime.now()
        
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                logger.info(f"断路器 {self.name} 恢复为关闭状态")
        elif self.state == CircuitBreakerState.CLOSED:
            self.failure_count = 0
    
    def record_failure(self):
        """记录失败"""
        self.last_failure_time = datetime.now()
        self.failure_count += 1
        
        if self.state == CircuitBreakerState.CLOSED:
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitBreakerState.OPEN
                logger.warning(f"断路器 {self.name} 打开，失败次数: {self.failure_count}")
        elif self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            logger.warning(f"断路器 {self.name} 重新打开")
    
    def get_state_info(self) -> Dict[str, Any]:
        """获取状态信息"""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'last_success_time': self.last_success_time.isoformat() if self.last_success_time else None
        }


class CircuitBreakerOpenError(Exception):
    """断路器打开异常"""
    pass


class LayerErrorHandler:
    """层级错误处理器基类"""
    
    def __init__(self, layer_name: str):
        self.layer_name = layer_name
        self.error_history: List[ErrorInfo] = []
        self.max_history_size = 1000
    
    async def handle(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """处理错误"""
        error_info = self._create_error_info(error, context)
        self._record_error(error_info)
        
        # 执行具体的错误处理逻辑
        return await self._handle_specific_error(error_info)
    
    def _create_error_info(self, error: Exception, context: Dict[str, Any]) -> ErrorInfo:
        """创建错误信息"""
        category = self._categorize_error(error)
        severity = self._assess_severity(error, category)
        
        return ErrorInfo(
            error_id=f"{self.layer_name}_{int(time.time() * 1000)}",
            layer=self.layer_name,
            category=category,
            severity=severity,
            message=str(error),
            exception=error,
            context=context
        )
    
    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """错误分类"""
        error_type = type(error).__name__
        
        if "timeout" in error_type.lower() or "timeout" in str(error).lower():
            return ErrorCategory.TIMEOUT
        elif "network" in error_type.lower() or "connection" in error_type.lower():
            return ErrorCategory.NETWORK
        elif "validation" in error_type.lower() or "invalid" in str(error).lower():
            return ErrorCategory.VALIDATION
        elif "resource" in error_type.lower() or "memory" in str(error).lower():
            return ErrorCategory.RESOURCE
        elif "config" in error_type.lower():
            return ErrorCategory.CONFIGURATION
        else:
            return ErrorCategory.UNKNOWN
    
    def _assess_severity(self, error: Exception, category: ErrorCategory) -> ErrorSeverity:
        """评估错误严重程度"""
        if category in [ErrorCategory.NETWORK, ErrorCategory.TIMEOUT]:
            return ErrorSeverity.HIGH
        elif category in [ErrorCategory.VALIDATION, ErrorCategory.CONFIGURATION]:
            return ErrorSeverity.MEDIUM
        elif category == ErrorCategory.RESOURCE:
            return ErrorSeverity.HIGH
        elif category == ErrorCategory.EXTERNAL_SERVICE:
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _record_error(self, error_info: ErrorInfo):
        """记录错误"""
        self.error_history.append(error_info)
        
        # 限制历史记录大小
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]
        
        # 记录日志
        log_level = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL
        }.get(error_info.severity, logging.ERROR)
        
        logger.log(log_level, f"[{self.layer_name}] {error_info.message}", 
                  extra={'error_info': error_info.to_dict()})
    
    async def _handle_specific_error(self, error_info: ErrorInfo) -> Dict[str, Any]:
        """处理特定错误（子类实现）"""
        return {
            'handled': True,
            'action': 'logged',
            'error_id': error_info.error_id
        }
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """获取错误统计"""
        if not self.error_history:
            return {'total_errors': 0}
        
        category_counts = {}
        severity_counts = {}
        
        for error in self.error_history:
            category_counts[error.category.value] = category_counts.get(error.category.value, 0) + 1
            severity_counts[error.severity.value] = severity_counts.get(error.severity.value, 0) + 1
        
        return {
            'total_errors': len(self.error_history),
            'category_distribution': category_counts,
            'severity_distribution': severity_counts,
            'recent_errors': [error.to_dict() for error in self.error_history[-10:]]
        }


class HaystackErrorHandler(LayerErrorHandler):
    """Haystack层错误处理器"""
    
    def __init__(self):
        super().__init__("haystack")
    
    async def _handle_specific_error(self, error_info: ErrorInfo) -> Dict[str, Any]:
        """处理Haystack层特定错误"""
        if error_info.category == ErrorCategory.TIMEOUT:
            return {
                'handled': True,
                'action': 'task_timeout_handled',
                'recommendation': 'increase_task_timeout',
                'error_id': error_info.error_id
            }
        elif error_info.category == ErrorCategory.RESOURCE:
            return {
                'handled': True,
                'action': 'resource_limit_handled',
                'recommendation': 'reduce_parallel_tasks',
                'error_id': error_info.error_id
            }
        
        return await super()._handle_specific_error(error_info)


class TxtaiErrorHandler(LayerErrorHandler):
    """txtai层错误处理器"""
    
    def __init__(self):
        super().__init__("txtai")
    
    async def _handle_specific_error(self, error_info: ErrorInfo) -> Dict[str, Any]:
        """处理txtai层特定错误"""
        if error_info.category == ErrorCategory.NETWORK:
            return {
                'handled': True,
                'action': 'fallback_to_cache',
                'recommendation': 'check_network_connectivity',
                'error_id': error_info.error_id
            }
        elif error_info.category == ErrorCategory.EXTERNAL_SERVICE:
            return {
                'handled': True,
                'action': 'use_alternative_source',
                'recommendation': 'check_service_status',
                'error_id': error_info.error_id
            }
        
        return await super()._handle_specific_error(error_info)


class R2RErrorHandler(LayerErrorHandler):
    """R2R层错误处理器"""
    
    def __init__(self):
        super().__init__("r2r")
    
    async def _handle_specific_error(self, error_info: ErrorInfo) -> Dict[str, Any]:
        """处理R2R层特定错误"""
        if error_info.category == ErrorCategory.PROCESSING:
            return {
                'handled': True,
                'action': 'reduce_context_window',
                'recommendation': 'optimize_analysis_scope',
                'error_id': error_info.error_id
            }
        
        return await super()._handle_specific_error(error_info)


class SelfRAGErrorHandler(LayerErrorHandler):
    """Self-RAG层错误处理器"""
    
    def __init__(self):
        super().__init__("self_rag")
    
    async def _handle_specific_error(self, error_info: ErrorInfo) -> Dict[str, Any]:
        """处理Self-RAG层特定错误"""
        if error_info.category == ErrorCategory.VALIDATION:
            return {
                'handled': True,
                'action': 'skip_validation',
                'recommendation': 'review_validation_rules',
                'error_id': error_info.error_id
            }
        
        return await super()._handle_specific_error(error_info)


class FallbackStrategy:
    """回退策略基类"""
    
    def __init__(self, name: str):
        self.name = name
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行回退策略"""
        raise NotImplementedError


class CacheFallbackStrategy(FallbackStrategy):
    """缓存回退策略"""
    
    def __init__(self):
        super().__init__("cache_fallback")
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """使用缓存数据作为回退"""
        return {
            'strategy': self.name,
            'action': 'use_cached_data',
            'data': context.get('cached_data', {}),
            'timestamp': datetime.now().isoformat()
        }


class DefaultValueFallbackStrategy(FallbackStrategy):
    """默认值回退策略"""
    
    def __init__(self, default_values: Dict[str, Any]):
        super().__init__("default_value_fallback")
        self.default_values = default_values
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """使用默认值作为回退"""
        return {
            'strategy': self.name,
            'action': 'use_default_values',
            'data': self.default_values,
            'timestamp': datetime.now().isoformat()
        }


class FallbackStrategies:
    """回退策略管理器"""
    
    def __init__(self):
        self.strategies: Dict[str, FallbackStrategy] = {
            'haystack': DefaultValueFallbackStrategy({
                'vulnerabilities': [],
                'processing_time': 0.0,
                'confidence_score': 0.0
            }),
            'txtai': CacheFallbackStrategy(),
            'r2r': DefaultValueFallbackStrategy({
                'enhanced_context': {},
                'completeness_score': 0.0
            }),
            'self_rag': DefaultValueFallbackStrategy({
                'validated_results': [],
                'confidence_score': 0.5
            })
        }
    
    def get_strategy(self, layer: str) -> FallbackStrategy:
        """获取指定层的回退策略"""
        return self.strategies.get(layer, self.strategies['haystack'])
    
    def add_strategy(self, layer: str, strategy: FallbackStrategy):
        """添加回退策略"""
        self.strategies[layer] = strategy


class HierarchicalErrorHandler:
    """层级错误处理器"""
    
    def __init__(self):
        self.layer_handlers: Dict[str, LayerErrorHandler] = {
            'haystack': HaystackErrorHandler(),
            'txtai': TxtaiErrorHandler(),
            'r2r': R2RErrorHandler(),
            'self_rag': SelfRAGErrorHandler()
        }
        self.fallback_strategies = FallbackStrategies()
        self.global_error_history: List[ErrorInfo] = []
    
    async def handle_error(self, error: Exception, layer: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """处理特定层的错误"""
        handler = self.layer_handlers.get(layer)
        if handler:
            result = await handler.handle(error, context)
            
            # 记录到全局错误历史
            if handler.error_history:
                self.global_error_history.append(handler.error_history[-1])
            
            return result
        
        # 使用通用错误处理
        return await self._handle_generic_error(error, layer, context)
    
    async def _handle_generic_error(self, error: Exception, layer: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """通用错误处理"""
        error_info = ErrorInfo(
            error_id=f"generic_{int(time.time() * 1000)}",
            layer=layer,
            category=ErrorCategory.UNKNOWN,
            severity=ErrorSeverity.MEDIUM,
            message=str(error),
            exception=error,
            context=context
        )
        
        self.global_error_history.append(error_info)
        
        logger.error(f"[{layer}] 未处理的错误: {error}", exc_info=True)
        
        return {
            'handled': False,
            'error_id': error_info.error_id,
            'message': str(error)
        }
    
    async def apply_fallback(self, layer: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """应用回退策略"""
        strategy = self.fallback_strategies.get_strategy(layer)
        return await strategy.execute(context)
    
    def get_global_error_statistics(self) -> Dict[str, Any]:
        """获取全局错误统计"""
        layer_stats = {}
        for layer, handler in self.layer_handlers.items():
            layer_stats[layer] = handler.get_error_statistics()
        
        return {
            'global_error_count': len(self.global_error_history),
            'layer_statistics': layer_stats,
            'recent_global_errors': [error.to_dict() for error in self.global_error_history[-20:]]
        }


class FaultToleranceManager:
    """容错管理器"""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.retry_policies: Dict[str, RetryPolicy] = {}
        self.health_checkers: Dict[str, Callable] = {}
        self.error_handler = HierarchicalErrorHandler()
        
        # 初始化默认配置
        self._initialize_default_configs()
    
    def _initialize_default_configs(self):
        """初始化默认配置"""
        # 默认断路器配置
        default_cb_config = CircuitBreakerConfig()
        
        layers = ['haystack', 'txtai', 'r2r', 'self_rag']
        for layer in layers:
            self.circuit_breakers[layer] = CircuitBreaker(layer, default_cb_config)
            self.retry_policies[layer] = RetryPolicy()
    
    def add_circuit_breaker(self, name: str, config: CircuitBreakerConfig):
        """添加断路器"""
        self.circuit_breakers[name] = CircuitBreaker(name, config)
    
    def add_retry_policy(self, name: str, policy: RetryPolicy):
        """添加重试策略"""
        self.retry_policies[name] = policy
    
    def add_health_checker(self, name: str, checker: Callable):
        """添加健康检查器"""
        self.health_checkers[name] = checker
    
    async def execute_with_tolerance(self, func: Callable, layer: str, *args, **kwargs) -> Any:
        """带容错的执行"""
        circuit_breaker = self.circuit_breakers.get(layer)
        retry_policy = self.retry_policies.get(layer)
        
        # 检查断路器状态
        if circuit_breaker and circuit_breaker.is_open():
            logger.warning(f"断路器 {layer} 已打开，使用回退策略")
            return await self.error_handler.apply_fallback(layer, kwargs)
        
        # 执行重试逻辑
        last_exception = None
        for attempt in range(retry_policy.max_attempts if retry_policy else 1):
            try:
                # 执行函数
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # 记录成功
                if circuit_breaker:
                    circuit_breaker.record_success()
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # 记录失败
                if circuit_breaker:
                    circuit_breaker.record_failure()
                
                # 处理错误
                error_result = await self.error_handler.handle_error(e, layer, kwargs)
                
                # 检查是否应该重试
                if retry_policy and retry_policy.should_retry(e, attempt + 1):
                    delay = retry_policy.get_delay(attempt)
                    logger.info(f"重试 {layer} 操作，延迟 {delay:.2f} 秒 (尝试 {attempt + 1}/{retry_policy.max_attempts})")
                    await asyncio.sleep(delay)
                    continue
                else:
                    # 不再重试，使用回退策略
                    logger.error(f"{layer} 操作失败，使用回退策略")
                    return await self.error_handler.apply_fallback(layer, kwargs)
        
        # 所有重试都失败，抛出最后的异常
        raise last_exception
    
    async def check_health(self) -> Dict[str, Any]:
        """检查系统健康状态"""
        health_status = {}
        
        for name, checker in self.health_checkers.items():
            try:
                if asyncio.iscoroutinefunction(checker):
                    status = await checker()
                else:
                    status = checker()
                health_status[name] = {'healthy': True, 'details': status}
            except Exception as e:
                health_status[name] = {'healthy': False, 'error': str(e)}
        
        # 添加断路器状态
        circuit_breaker_status = {}
        for name, cb in self.circuit_breakers.items():
            circuit_breaker_status[name] = cb.get_state_info()
        
        return {
            'health_checks': health_status,
            'circuit_breakers': circuit_breaker_status,
            'error_statistics': self.error_handler.get_global_error_statistics()
        }
    
    def get_fault_tolerance_metrics(self) -> Dict[str, Any]:
        """获取容错指标"""
        metrics = {
            'circuit_breakers': {},
            'retry_policies': {},
            'error_statistics': self.error_handler.get_global_error_statistics()
        }
        
        # 断路器指标
        for name, cb in self.circuit_breakers.items():
            metrics['circuit_breakers'][name] = cb.get_state_info()
        
        # 重试策略指标
        for name, policy in self.retry_policies.items():
            metrics['retry_policies'][name] = {
                'max_attempts': policy.max_attempts,
                'base_delay': policy.base_delay,
                'exponential_backoff': policy.exponential_backoff
            }
        
        return metrics


# 便捷函数
def create_default_fault_tolerance_manager() -> FaultToleranceManager:
    """创建默认的容错管理器"""
    return FaultToleranceManager()


def create_retry_policy(max_attempts: int = 3, base_delay: float = 1.0, 
                       exponential_backoff: bool = True) -> RetryPolicy:
    """创建重试策略"""
    return RetryPolicy(
        max_attempts=max_attempts,
        base_delay=base_delay,
        exponential_backoff=exponential_backoff
    )


def create_circuit_breaker_config(failure_threshold: int = 5, 
                                recovery_timeout: float = 60.0) -> CircuitBreakerConfig:
    """创建断路器配置"""
    return CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout=recovery_timeout
    )


# 全局容错管理器实例
global_fault_tolerance_manager = create_default_fault_tolerance_manager()


# 装饰器
def with_fault_tolerance(layer: str):
    """容错装饰器"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            return await global_fault_tolerance_manager.execute_with_tolerance(
                func, layer, *args, **kwargs
            )
        return wrapper
    return decorator