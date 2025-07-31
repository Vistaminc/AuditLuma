"""
Retry manager for the unified Haystack generator component.

This module provides comprehensive retry mechanisms including exponential backoff,
circuit breaker patterns, timeout handling, and error classification.
"""

import asyncio
import logging
import time
import random
from typing import Any, Dict, List, Optional, Callable, Union, Type
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from .exceptions import (
    UnifiedGeneratorError, APIError, AuthenticationError, RateLimitError,
    TimeoutError, ValidationError, RetryExhaustedError, ServiceUnavailableError,
    is_retryable_error
)

logger = logging.getLogger(__name__)


class RetryStrategy(str, Enum):
    """重试策略类型"""
    FIXED = "fixed"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    FIBONACCI = "fibonacci"


class CircuitBreakerState(str, Enum):
    """断路器状态"""
    CLOSED = "closed"      # 正常状态，允许请求通过
    OPEN = "open"          # 断路状态，拒绝请求
    HALF_OPEN = "half_open"  # 半开状态，允许少量请求测试


@dataclass
class RetryConfig:
    """重试配置"""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    jitter: bool = True
    jitter_range: float = 0.1
    timeout: Optional[float] = None
    retryable_exceptions: Optional[List[Type[Exception]]] = None
    non_retryable_exceptions: Optional[List[Type[Exception]]] = None
    
    def __post_init__(self):
        """初始化后处理"""
        # 只有在两个列表都为None时才设置默认值
        if self.retryable_exceptions is None and self.non_retryable_exceptions is None:
            self.retryable_exceptions = [
                TimeoutError,
                ServiceUnavailableError,
                RateLimitError,
                ConnectionError,
                OSError,
            ]
            
            self.non_retryable_exceptions = [
                AuthenticationError,
                ValidationError,
                ValueError,
                TypeError,
            ]


@dataclass
class CircuitBreakerConfig:
    """断路器配置"""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    success_threshold: int = 3
    timeout: float = 30.0
    half_open_max_calls: int = 5


@dataclass
class RetryAttempt:
    """重试尝试记录"""
    attempt_number: int
    timestamp: datetime
    exception: Optional[Exception] = None
    delay: float = 0.0
    success: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'attempt_number': self.attempt_number,
            'timestamp': self.timestamp.isoformat(),
            'exception': str(self.exception) if self.exception else None,
            'exception_type': type(self.exception).__name__ if self.exception else None,
            'delay': self.delay,
            'success': self.success
        }


class CircuitBreaker:
    """断路器实现"""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        """
        初始化断路器
        
        Args:
            name: 断路器名称
            config: 断路器配置
        """
        self.name = name
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.last_success_time: Optional[datetime] = None
        self.half_open_calls = 0
        self._lock = asyncio.Lock()
    
    async def is_call_allowed(self) -> bool:
        """检查是否允许调用"""
        async with self._lock:
            if self.state == CircuitBreakerState.CLOSED:
                return True
            
            elif self.state == CircuitBreakerState.OPEN:
                # 检查是否可以转为半开状态
                if (self.last_failure_time and 
                    datetime.now() - self.last_failure_time > timedelta(seconds=self.config.recovery_timeout)):
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.half_open_calls = 0
                    self.success_count = 0
                    logger.info(f"断路器 {self.name} 转为半开状态")
                    return True
                return False
            
            elif self.state == CircuitBreakerState.HALF_OPEN:
                # 半开状态下限制调用次数
                if self.half_open_calls < self.config.half_open_max_calls:
                    self.half_open_calls += 1
                    return True
                return False
            
            return False
    
    async def record_success(self):
        """记录成功调用"""
        async with self._lock:
            self.last_success_time = datetime.now()
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self.state = CircuitBreakerState.CLOSED
                    self.failure_count = 0
                    logger.info(f"断路器 {self.name} 恢复为关闭状态")
            
            elif self.state == CircuitBreakerState.CLOSED:
                self.failure_count = 0
    
    async def record_failure(self):
        """记录失败调用"""
        async with self._lock:
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
            'half_open_calls': self.half_open_calls,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'last_success_time': self.last_success_time.isoformat() if self.last_success_time else None,
            'config': {
                'failure_threshold': self.config.failure_threshold,
                'recovery_timeout': self.config.recovery_timeout,
                'success_threshold': self.config.success_threshold
            }
        }


class RetryManager:
    """重试管理器"""
    
    def __init__(self, config: Optional[RetryConfig] = None):
        """
        初始化重试管理器
        
        Args:
            config: 重试配置
        """
        self.config = config or RetryConfig()
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.retry_history: List[RetryAttempt] = []
        self.max_history_size = 1000
    
    def add_circuit_breaker(self, name: str, config: CircuitBreakerConfig):
        """
        添加断路器
        
        Args:
            name: 断路器名称
            config: 断路器配置
        """
        self.circuit_breakers[name] = CircuitBreaker(name, config)
    
    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """
        获取断路器
        
        Args:
            name: 断路器名称
            
        Returns:
            断路器实例或None
        """
        return self.circuit_breakers.get(name)
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """
        判断是否应该重试
        
        Args:
            exception: 异常实例
            attempt: 当前尝试次数
            
        Returns:
            是否应该重试
        """
        # 检查尝试次数
        if attempt >= self.config.max_attempts:
            return False
        
        # 检查非重试异常
        if self.config.non_retryable_exceptions:
            for exc_type in self.config.non_retryable_exceptions:
                if isinstance(exception, exc_type):
                    return False
        
        # 检查重试异常 - 如果指定了重试异常列表，只重试列表中的异常
        if self.config.retryable_exceptions:
            for exc_type in self.config.retryable_exceptions:
                if isinstance(exception, exc_type):
                    return True
            # 如果指定了重试异常列表但异常不在列表中，则不重试
            return False
        
        # 如果没有指定重试异常列表，使用通用重试判断逻辑
        return is_retryable_error(exception)
    
    def calculate_delay(self, attempt: int) -> float:
        """
        计算重试延迟
        
        Args:
            attempt: 尝试次数（从0开始）
            
        Returns:
            延迟时间（秒）
        """
        if self.config.strategy == RetryStrategy.FIXED:
            delay = self.config.base_delay
        
        elif self.config.strategy == RetryStrategy.LINEAR:
            delay = self.config.base_delay * (attempt + 1)
        
        elif self.config.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.config.base_delay * (2 ** attempt)
        
        elif self.config.strategy == RetryStrategy.FIBONACCI:
            delay = self.config.base_delay * self._fibonacci(attempt + 1)
        
        else:
            delay = self.config.base_delay
        
        # 应用最大延迟限制
        delay = min(delay, self.config.max_delay)
        
        # 应用抖动
        if self.config.jitter:
            jitter_amount = delay * self.config.jitter_range
            delay += random.uniform(-jitter_amount, jitter_amount)
            delay = max(0, delay)  # 确保延迟不为负数
        
        return delay
    
    def _fibonacci(self, n: int) -> int:
        """计算斐波那契数列第n项"""
        if n <= 0:
            return 0
        elif n == 1:
            return 1
        a, b = 0, 1
        for _ in range(2, n + 1):
            a, b = b, a + b
        return b
    
    async def execute_with_retry(
        self,
        func: Callable,
        *args,
        circuit_breaker_name: Optional[str] = None,
        **kwargs
    ) -> Any:
        """
        执行带重试的函数调用
        
        Args:
            func: 要执行的函数
            *args: 函数参数
            circuit_breaker_name: 断路器名称
            **kwargs: 函数关键字参数
            
        Returns:
            函数执行结果
            
        Raises:
            RetryExhaustedError: 重试次数耗尽
            Exception: 其他异常
        """
        circuit_breaker = None
        if circuit_breaker_name:
            circuit_breaker = self.get_circuit_breaker(circuit_breaker_name)
        
        last_exception = None
        attempts = []
        
        for attempt in range(self.config.max_attempts):
            # 检查断路器状态
            if circuit_breaker:
                if not await circuit_breaker.is_call_allowed():
                    raise ServiceUnavailableError(
                        f"Circuit breaker {circuit_breaker_name} is open",
                        provider=circuit_breaker_name
                    )
            
            try:
                # 执行函数
                start_time = time.time()
                
                if asyncio.iscoroutinefunction(func):
                    if self.config.timeout:
                        result = await asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=self.config.timeout
                        )
                    else:
                        result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                execution_time = time.time() - start_time
                
                # 记录成功尝试
                attempt_record = RetryAttempt(
                    attempt_number=attempt + 1,
                    timestamp=datetime.now(),
                    success=True
                )
                attempts.append(attempt_record)
                self._record_attempt(attempt_record)
                
                # 记录断路器成功
                if circuit_breaker:
                    await circuit_breaker.record_success()
                
                logger.debug(f"函数执行成功，尝试次数: {attempt + 1}, 执行时间: {execution_time:.2f}s")
                return result
                
            except asyncio.TimeoutError as e:
                last_exception = TimeoutError(
                    f"Operation timed out after {self.config.timeout}s",
                    timeout_duration=self.config.timeout
                )
                
            except Exception as e:
                last_exception = e
            
            # 记录失败尝试
            attempt_record = RetryAttempt(
                attempt_number=attempt + 1,
                timestamp=datetime.now(),
                exception=last_exception,
                success=False
            )
            attempts.append(attempt_record)
            self._record_attempt(attempt_record)
            
            # 记录断路器失败
            if circuit_breaker:
                await circuit_breaker.record_failure()
            
            # 检查是否应该重试
            if not self.should_retry(last_exception, attempt + 1):
                logger.info(f"不重试异常: {type(last_exception).__name__}: {last_exception}")
                break
            
            # 计算延迟时间
            if attempt < self.config.max_attempts - 1:  # 最后一次尝试不需要延迟
                delay = self.calculate_delay(attempt)
                attempt_record.delay = delay
                
                logger.info(f"重试第 {attempt + 1} 次失败，{delay:.2f}s 后重试: {last_exception}")
                await asyncio.sleep(delay)
        
        # 所有重试都失败了
        raise RetryExhaustedError(
            f"All {self.config.max_attempts} retry attempts failed",
            original_error=last_exception,
            retry_count=len(attempts)
        )
    
    def _record_attempt(self, attempt: RetryAttempt):
        """记录重试尝试"""
        self.retry_history.append(attempt)
        
        # 限制历史记录大小
        if len(self.retry_history) > self.max_history_size:
            self.retry_history = self.retry_history[-self.max_history_size:]
    
    def get_retry_statistics(self) -> Dict[str, Any]:
        """获取重试统计信息"""
        if not self.retry_history:
            return {
                'total_attempts': 0,
                'success_rate': 0.0,
                'average_attempts_per_operation': 0.0
            }
        
        total_attempts = len(self.retry_history)
        successful_attempts = sum(1 for attempt in self.retry_history if attempt.success)
        
        # 按操作分组统计
        operations = {}
        current_operation = []
        
        for attempt in self.retry_history:
            current_operation.append(attempt)
            if attempt.success or attempt.attempt_number == self.config.max_attempts:
                # 操作结束
                operation_key = f"op_{len(operations)}"
                operations[operation_key] = current_operation
                current_operation = []
        
        success_rate = successful_attempts / total_attempts if total_attempts > 0 else 0.0
        avg_attempts = len(operations) / len(operations) if operations else 0.0
        
        return {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'failed_attempts': total_attempts - successful_attempts,
            'success_rate': success_rate,
            'total_operations': len(operations),
            'average_attempts_per_operation': avg_attempts,
            'recent_attempts': [attempt.to_dict() for attempt in self.retry_history[-10:]],
            'circuit_breaker_states': {
                name: cb.get_state_info() 
                for name, cb in self.circuit_breakers.items()
            }
        }
    
    def reset_statistics(self):
        """重置统计信息"""
        self.retry_history.clear()
        for circuit_breaker in self.circuit_breakers.values():
            circuit_breaker.failure_count = 0
            circuit_breaker.success_count = 0
            circuit_breaker.state = CircuitBreakerState.CLOSED


class ErrorClassifier:
    """错误分类器"""
    
    @staticmethod
    def classify_api_error(status_code: int, response_body: str = "") -> Type[Exception]:
        """
        根据HTTP状态码分类API错误
        
        Args:
            status_code: HTTP状态码
            response_body: 响应体内容
            
        Returns:
            对应的异常类型
        """
        if status_code == 401:
            return AuthenticationError
        elif status_code == 429:
            return RateLimitError
        elif status_code == 408 or status_code == 504:
            return TimeoutError
        elif 500 <= status_code < 600:
            return ServiceUnavailableError
        elif 400 <= status_code < 500:
            return ValidationError
        else:
            return APIError
    
    @staticmethod
    def extract_retry_after(headers: Dict[str, str]) -> Optional[int]:
        """
        从响应头中提取重试延迟时间
        
        Args:
            headers: HTTP响应头
            
        Returns:
            重试延迟时间（秒）
        """
        retry_after = headers.get('Retry-After') or headers.get('retry-after')
        if retry_after:
            try:
                return int(retry_after)
            except ValueError:
                pass
        return None


# 预定义的重试配置
DEFAULT_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=60.0,
    strategy=RetryStrategy.EXPONENTIAL,
    jitter=True
)

AGGRESSIVE_RETRY_CONFIG = RetryConfig(
    max_attempts=5,
    base_delay=0.5,
    max_delay=30.0,
    strategy=RetryStrategy.EXPONENTIAL,
    jitter=True
)

CONSERVATIVE_RETRY_CONFIG = RetryConfig(
    max_attempts=2,
    base_delay=2.0,
    max_delay=120.0,
    strategy=RetryStrategy.LINEAR,
    jitter=False
)

# 预定义的断路器配置
DEFAULT_CIRCUIT_BREAKER_CONFIG = CircuitBreakerConfig(
    failure_threshold=5,
    recovery_timeout=60.0,
    success_threshold=3
)

SENSITIVE_CIRCUIT_BREAKER_CONFIG = CircuitBreakerConfig(
    failure_threshold=3,
    recovery_timeout=30.0,
    success_threshold=2
)


def create_retry_manager(
    config: Optional[RetryConfig] = None,
    circuit_breakers: Optional[Dict[str, CircuitBreakerConfig]] = None
) -> RetryManager:
    """
    创建重试管理器
    
    Args:
        config: 重试配置
        circuit_breakers: 断路器配置字典
        
    Returns:
        重试管理器实例
    """
    manager = RetryManager(config or DEFAULT_RETRY_CONFIG)
    
    if circuit_breakers:
        for name, cb_config in circuit_breakers.items():
            manager.add_circuit_breaker(name, cb_config)
    
    return manager


# 装饰器
def with_retry(
    config: Optional[RetryConfig] = None,
    circuit_breaker_name: Optional[str] = None
):
    """
    重试装饰器
    
    Args:
        config: 重试配置
        circuit_breaker_name: 断路器名称
    """
    def decorator(func):
        retry_manager = RetryManager(config or DEFAULT_RETRY_CONFIG)
        
        async def async_wrapper(*args, **kwargs):
            return await retry_manager.execute_with_retry(
                func, *args, circuit_breaker_name=circuit_breaker_name, **kwargs
            )
        
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator