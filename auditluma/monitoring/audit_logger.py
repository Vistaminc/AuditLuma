"""
日志和审计系统 - 层级RAG架构日志和审计组件

扩展现有日志系统支持层级RAG，实现结构化日志、审计跟踪、日志聚合和分析功能。
"""

import asyncio
import time
import threading
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set, Union
from collections import defaultdict, deque
from pathlib import Path
import logging
from datetime import datetime, timedelta

# 使用loguru作为底层日志系统
from loguru import logger

# 移除默认的loguru处理器，我们将添加自定义的
logger.remove()


class LogLevel(Enum):
    """日志级别"""
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditEventType(Enum):
    """审计事件类型"""
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    AUDIT_START = "audit_start"
    AUDIT_COMPLETE = "audit_complete"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    FALSE_POSITIVE_FILTERED = "false_positive_filtered"
    CONFIGURATION_CHANGED = "configuration_changed"
    SECURITY_VIOLATION = "security_violation"
    DATA_ACCESS = "data_access"
    API_CALL = "api_call"
    ERROR_OCCURRED = "error_occurred"
    PERFORMANCE_ALERT = "performance_alert"
    QUALITY_ALERT = "quality_alert"


class SecurityLevel(Enum):
    """安全级别"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class LogContext:
    """日志上下文"""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    layer: Optional[str] = None
    operation: Optional[str] = None
    component: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class StructuredLogEntry:
    """结构化日志条目"""
    timestamp: float
    level: LogLevel
    message: str
    context: LogContext
    metadata: Dict[str, Any] = field(default_factory=dict)
    exception: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        entry = {
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "level": self.level.value,
            "message": self.message,
            "context": self.context.to_dict(),
            "metadata": self.metadata
        }
        
        if self.exception:
            entry["exception"] = self.exception
        
        return entry
    
    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class AuditEvent:
    """审计事件"""
    event_id: str
    event_type: AuditEventType
    timestamp: float
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    resource: Optional[str]
    action: str
    result: str  # "success", "failure", "partial"
    security_level: SecurityLevel
    details: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
            "security_level": self.security_level.value,
            "details": self.details,
            "risk_score": self.risk_score
        }
    
    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)


class LogFormatter(ABC):
    """日志格式化器基类"""
    
    @abstractmethod
    def format(self, entry: StructuredLogEntry) -> str:
        """格式化日志条目"""
        pass


class JSONLogFormatter(LogFormatter):
    """JSON日志格式化器"""
    
    def format(self, entry: StructuredLogEntry) -> str:
        """格式化为JSON"""
        return entry.to_json()


class HumanReadableFormatter(LogFormatter):
    """人类可读格式化器"""
    
    def format(self, entry: StructuredLogEntry) -> str:
        """格式化为人类可读格式"""
        dt = datetime.fromtimestamp(entry.timestamp)
        context_str = ""
        
        if entry.context.layer:
            context_str += f"[{entry.context.layer}]"
        if entry.context.operation:
            context_str += f"[{entry.context.operation}]"
        if entry.context.request_id:
            context_str += f"[{entry.context.request_id[:8]}]"
        
        base_msg = f"{dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | {entry.level.value:8} | {context_str} {entry.message}"
        
        if entry.metadata:
            metadata_str = " | " + " | ".join([f"{k}={v}" for k, v in entry.metadata.items()])
            base_msg += metadata_str
        
        if entry.exception:
            base_msg += f"\n{entry.exception}"
        
        return base_msg


class LogHandler(ABC):
    """日志处理器基类"""
    
    def __init__(self, formatter: LogFormatter):
        self.formatter = formatter
    
    @abstractmethod
    async def handle(self, entry: StructuredLogEntry):
        """处理日志条目"""
        pass


class FileLogHandler(LogHandler):
    """文件日志处理器"""
    
    def __init__(self, formatter: LogFormatter, file_path: str, 
                 max_size: int = 100 * 1024 * 1024,  # 100MB
                 backup_count: int = 5):
        super().__init__(formatter)
        self.file_path = Path(file_path)
        self.max_size = max_size
        self.backup_count = backup_count
        self._lock = threading.Lock()
        
        # 确保目录存在
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
    
    async def handle(self, entry: StructuredLogEntry):
        """写入文件"""
        formatted_message = self.formatter.format(entry)
        
        with self._lock:
            # 检查文件大小并轮转
            if self.file_path.exists() and self.file_path.stat().st_size > self.max_size:
                self._rotate_logs()
            
            # 写入日志
            with open(self.file_path, 'a', encoding='utf-8') as f:
                f.write(formatted_message + '\n')
    
    def _rotate_logs(self):
        """轮转日志文件"""
        # 删除最旧的备份
        oldest_backup = self.file_path.with_suffix(f'.{self.backup_count}')
        if oldest_backup.exists():
            oldest_backup.unlink()
        
        # 移动现有备份
        for i in range(self.backup_count - 1, 0, -1):
            old_backup = self.file_path.with_suffix(f'.{i}')
            new_backup = self.file_path.with_suffix(f'.{i + 1}')
            if old_backup.exists():
                old_backup.rename(new_backup)
        
        # 移动当前文件
        if self.file_path.exists():
            backup_path = self.file_path.with_suffix('.1')
            self.file_path.rename(backup_path)


class ConsoleLogHandler(LogHandler):
    """控制台日志处理器"""
    
    def __init__(self, formatter: LogFormatter, min_level: LogLevel = LogLevel.INFO):
        super().__init__(formatter)
        self.min_level = min_level
        self._level_order = {
            LogLevel.TRACE: 0,
            LogLevel.DEBUG: 1,
            LogLevel.INFO: 2,
            LogLevel.SUCCESS: 3,
            LogLevel.WARNING: 4,
            LogLevel.ERROR: 5,
            LogLevel.CRITICAL: 6
        }
    
    async def handle(self, entry: StructuredLogEntry):
        """输出到控制台"""
        if self._level_order[entry.level] >= self._level_order[self.min_level]:
            formatted_message = self.formatter.format(entry)
            print(formatted_message)


class DatabaseLogHandler(LogHandler):
    """数据库日志处理器"""
    
    def __init__(self, formatter: LogFormatter, db_connection=None):
        super().__init__(formatter)
        self.db_connection = db_connection
        self._buffer = deque(maxlen=1000)
        self._lock = threading.Lock()
    
    async def handle(self, entry: StructuredLogEntry):
        """存储到数据库"""
        if self.db_connection:
            # 实际的数据库存储逻辑
            # 这里只是示例，实际实现需要根据具体的数据库类型
            pass
        else:
            # 如果没有数据库连接，缓存到内存
            with self._lock:
                self._buffer.append(entry)
    
    def get_buffered_entries(self) -> List[StructuredLogEntry]:
        """获取缓存的日志条目"""
        with self._lock:
            return list(self._buffer)


class AuditTrail:
    """审计跟踪"""
    
    def __init__(self, max_events: int = 10000):
        self.max_events = max_events
        self._events: deque = deque(maxlen=max_events)
        self._events_by_type: Dict[AuditEventType, List[AuditEvent]] = defaultdict(list)
        self._events_by_user: Dict[str, List[AuditEvent]] = defaultdict(list)
        self._lock = threading.RLock()
    
    def record_event(self, event: AuditEvent):
        """记录审计事件"""
        with self._lock:
            self._events.append(event)
            self._events_by_type[event.event_type].append(event)
            
            if event.user_id:
                self._events_by_user[event.user_id].append(event)
            
            # 限制每个分类的事件数量
            max_per_category = 1000
            if len(self._events_by_type[event.event_type]) > max_per_category:
                self._events_by_type[event.event_type] = self._events_by_type[event.event_type][-max_per_category:]
            
            if event.user_id and len(self._events_by_user[event.user_id]) > max_per_category:
                self._events_by_user[event.user_id] = self._events_by_user[event.user_id][-max_per_category:]
    
    def get_events(self, 
                   event_type: Optional[AuditEventType] = None,
                   user_id: Optional[str] = None,
                   since: Optional[float] = None,
                   limit: Optional[int] = None) -> List[AuditEvent]:
        """获取审计事件"""
        with self._lock:
            if event_type and user_id:
                # 获取特定类型和用户的事件
                events = [e for e in self._events_by_type.get(event_type, []) 
                         if e.user_id == user_id]
            elif event_type:
                events = self._events_by_type.get(event_type, [])
            elif user_id:
                events = self._events_by_user.get(user_id, [])
            else:
                events = list(self._events)
            
            # 时间过滤
            if since:
                events = [e for e in events if e.timestamp >= since]
            
            # 按时间排序（最新的在前）
            events.sort(key=lambda x: x.timestamp, reverse=True)
            
            # 限制数量
            if limit:
                events = events[:limit]
            
            return events
    
    def get_security_events(self, risk_threshold: float = 0.5) -> List[AuditEvent]:
        """获取安全相关事件"""
        with self._lock:
            security_events = []
            for event in self._events:
                if (event.event_type in [AuditEventType.SECURITY_VIOLATION, 
                                       AuditEventType.USER_LOGIN, 
                                       AuditEventType.USER_LOGOUT] or
                    event.risk_score >= risk_threshold):
                    security_events.append(event)
            
            return sorted(security_events, key=lambda x: x.timestamp, reverse=True)
    
    def get_audit_summary(self) -> Dict[str, Any]:
        """获取审计摘要"""
        with self._lock:
            events = list(self._events)
            
            summary = {
                "total_events": len(events),
                "by_type": defaultdict(int),
                "by_result": defaultdict(int),
                "by_security_level": defaultdict(int),
                "high_risk_events": 0,
                "recent_events": []
            }
            
            for event in events:
                summary["by_type"][event.event_type.value] += 1
                summary["by_result"][event.result] += 1
                summary["by_security_level"][event.security_level.value] += 1
                
                if event.risk_score >= 0.7:
                    summary["high_risk_events"] += 1
            
            # 最近的事件
            recent_time = time.time() - 3600  # 最近1小时
            recent_events = [e for e in events if e.timestamp >= recent_time]
            summary["recent_events"] = [e.to_dict() for e in recent_events[-10:]]
            
            return summary


class LogAggregator:
    """日志聚合器"""
    
    def __init__(self, aggregation_interval: float = 60.0):
        self.aggregation_interval = aggregation_interval
        self._log_buffer: deque = deque(maxlen=10000)
        self._aggregated_stats: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._aggregation_active = False
        self._aggregation_task: Optional[asyncio.Task] = None
    
    def add_log_entry(self, entry: StructuredLogEntry):
        """添加日志条目到聚合器"""
        with self._lock:
            self._log_buffer.append(entry)
    
    async def start_aggregation(self):
        """启动日志聚合"""
        if self._aggregation_active:
            return
        
        self._aggregation_active = True
        self._aggregation_task = asyncio.create_task(self._aggregation_loop())
    
    async def stop_aggregation(self):
        """停止日志聚合"""
        if not self._aggregation_active:
            return
        
        self._aggregation_active = False
        
        if self._aggregation_task:
            self._aggregation_task.cancel()
            try:
                await self._aggregation_task
            except asyncio.CancelledError:
                pass
    
    async def _aggregation_loop(self):
        """聚合循环"""
        while self._aggregation_active:
            try:
                await asyncio.sleep(self.aggregation_interval)
                await self._perform_aggregation()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"日志聚合循环异常: {e}")
    
    async def _perform_aggregation(self):
        """执行日志聚合"""
        current_time = time.time()
        aggregation_window = current_time - self.aggregation_interval
        
        with self._lock:
            # 获取聚合窗口内的日志
            window_logs = [entry for entry in self._log_buffer 
                          if entry.timestamp >= aggregation_window]
            
            if not window_logs:
                return
            
            # 按级别聚合
            level_counts = defaultdict(int)
            for entry in window_logs:
                level_counts[entry.level.value] += 1
            
            # 按层聚合
            layer_counts = defaultdict(int)
            for entry in window_logs:
                if entry.context.layer:
                    layer_counts[entry.context.layer] += 1
            
            # 按操作聚合
            operation_counts = defaultdict(int)
            for entry in window_logs:
                if entry.context.operation:
                    operation_counts[entry.context.operation] += 1
            
            # 错误统计
            error_logs = [entry for entry in window_logs 
                         if entry.level in [LogLevel.ERROR, LogLevel.CRITICAL]]
            
            # 更新聚合统计
            self._aggregated_stats = {
                "timestamp": current_time,
                "window_duration": self.aggregation_interval,
                "total_logs": len(window_logs),
                "level_distribution": dict(level_counts),
                "layer_distribution": dict(layer_counts),
                "operation_distribution": dict(operation_counts),
                "error_count": len(error_logs),
                "error_rate": len(error_logs) / len(window_logs) if window_logs else 0.0,
                "top_errors": [entry.message for entry in error_logs[:5]]
            }
    
    def get_aggregated_stats(self) -> Dict[str, Any]:
        """获取聚合统计"""
        with self._lock:
            return self._aggregated_stats.copy()


class HierarchicalRAGLogger:
    """层级RAG日志器 - 主要日志组件"""
    
    def __init__(self, 
                 log_dir: str = "logs",
                 enable_console: bool = True,
                 enable_file: bool = True,
                 enable_audit: bool = True,
                 enable_aggregation: bool = True):
        """初始化层级RAG日志器"""
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # 核心组件
        self._handlers: List[LogHandler] = []
        self._audit_trail = AuditTrail() if enable_audit else None
        self._log_aggregator = LogAggregator() if enable_aggregation else None
        self._context_stack: List[LogContext] = []
        self._lock = threading.RLock()
        
        # 初始化处理器
        if enable_console:
            console_handler = ConsoleLogHandler(HumanReadableFormatter())
            self._handlers.append(console_handler)
        
        if enable_file:
            # 应用日志
            app_log_handler = FileLogHandler(
                JSONLogFormatter(),
                str(self.log_dir / "application.jsonl")
            )
            self._handlers.append(app_log_handler)
            
            # 错误日志
            error_log_handler = FileLogHandler(
                HumanReadableFormatter(),
                str(self.log_dir / "errors.log")
            )
            self._handlers.append(error_log_handler)
        
        # 配置loguru
        self._configure_loguru()
        
        # 启动聚合器
        if self._log_aggregator:
            asyncio.create_task(self._log_aggregator.start_aggregation())
        
        logger.info("层级RAG日志系统初始化完成")
    
    def _configure_loguru(self):
        """配置loguru"""
        # 添加自定义处理器到loguru
        logger.add(
            self._loguru_handler,
            level="TRACE",
            format="{message}",
            enqueue=True
        )
    
    def _loguru_handler(self, record):
        """loguru处理器"""
        # 从loguru记录创建结构化日志条目
        level_map = {
            "TRACE": LogLevel.TRACE,
            "DEBUG": LogLevel.DEBUG,
            "INFO": LogLevel.INFO,
            "SUCCESS": LogLevel.SUCCESS,
            "WARNING": LogLevel.WARNING,
            "ERROR": LogLevel.ERROR,
            "CRITICAL": LogLevel.CRITICAL
        }
        
        level = level_map.get(record["level"].name, LogLevel.INFO)
        
        # 获取当前上下文
        current_context = self._get_current_context()
        
        # 创建结构化日志条目
        entry = StructuredLogEntry(
            timestamp=record["time"].timestamp(),
            level=level,
            message=record["message"],
            context=current_context,
            metadata=record.get("extra", {}),
            exception=record.get("exception")
        )
        
        # 异步处理日志条目
        asyncio.create_task(self._handle_log_entry(entry))
    
    def _get_current_context(self) -> LogContext:
        """获取当前日志上下文"""
        with self._lock:
            if self._context_stack:
                return self._context_stack[-1]
            else:
                return LogContext()
    
    async def _handle_log_entry(self, entry: StructuredLogEntry):
        """处理日志条目"""
        # 发送到所有处理器
        for handler in self._handlers:
            try:
                await handler.handle(entry)
            except Exception as e:
                print(f"日志处理器错误: {e}")
        
        # 添加到聚合器
        if self._log_aggregator:
            self._log_aggregator.add_log_entry(entry)
    
    def push_context(self, context: LogContext):
        """推入日志上下文"""
        with self._lock:
            self._context_stack.append(context)
    
    def pop_context(self) -> Optional[LogContext]:
        """弹出日志上下文"""
        with self._lock:
            if self._context_stack:
                return self._context_stack.pop()
            return None
    
    def with_context(self, **kwargs):
        """上下文管理器"""
        return LogContextManager(self, LogContext(**kwargs))
    
    def record_audit_event(self, event: AuditEvent):
        """记录审计事件"""
        if self._audit_trail:
            self._audit_trail.record_event(event)
            
            # 同时记录到日志
            logger.info(f"审计事件: {event.event_type.value} - {event.action} - {event.result}",
                       extra={
                           "audit_event": True,
                           "event_id": event.event_id,
                           "event_type": event.event_type.value,
                           "user_id": event.user_id,
                           "resource": event.resource,
                           "risk_score": event.risk_score
                       })
    
    def create_audit_event(self, 
                          event_type: AuditEventType,
                          action: str,
                          result: str = "success",
                          user_id: Optional[str] = None,
                          resource: Optional[str] = None,
                          security_level: SecurityLevel = SecurityLevel.INTERNAL,
                          **details) -> AuditEvent:
        """创建审计事件"""
        return AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=time.time(),
            user_id=user_id,
            session_id=None,  # 可以从上下文获取
            source_ip=None,   # 可以从上下文获取
            user_agent=None,  # 可以从上下文获取
            resource=resource,
            action=action,
            result=result,
            security_level=security_level,
            details=details,
            risk_score=self._calculate_risk_score(event_type, result, security_level)
        )
    
    def _calculate_risk_score(self, event_type: AuditEventType, 
                             result: str, security_level: SecurityLevel) -> float:
        """计算风险评分"""
        base_scores = {
            AuditEventType.SECURITY_VIOLATION: 0.9,
            AuditEventType.USER_LOGIN: 0.3,
            AuditEventType.USER_LOGOUT: 0.1,
            AuditEventType.CONFIGURATION_CHANGED: 0.6,
            AuditEventType.DATA_ACCESS: 0.4,
            AuditEventType.ERROR_OCCURRED: 0.5
        }
        
        result_multipliers = {
            "success": 1.0,
            "failure": 1.5,
            "partial": 1.2
        }
        
        security_multipliers = {
            SecurityLevel.PUBLIC: 0.5,
            SecurityLevel.INTERNAL: 1.0,
            SecurityLevel.CONFIDENTIAL: 1.5,
            SecurityLevel.RESTRICTED: 2.0
        }
        
        base_score = base_scores.get(event_type, 0.3)
        result_mult = result_multipliers.get(result, 1.0)
        security_mult = security_multipliers.get(security_level, 1.0)
        
        return min(1.0, base_score * result_mult * security_mult)
    
    def get_audit_events(self, **kwargs) -> List[AuditEvent]:
        """获取审计事件"""
        if self._audit_trail:
            return self._audit_trail.get_events(**kwargs)
        return []
    
    def get_security_events(self, risk_threshold: float = 0.5) -> List[AuditEvent]:
        """获取安全事件"""
        if self._audit_trail:
            return self._audit_trail.get_security_events(risk_threshold)
        return []
    
    def get_audit_summary(self) -> Dict[str, Any]:
        """获取审计摘要"""
        if self._audit_trail:
            return self._audit_trail.get_audit_summary()
        return {"total_events": 0}
    
    def get_log_stats(self) -> Dict[str, Any]:
        """获取日志统计"""
        stats = {
            "handlers_count": len(self._handlers),
            "context_stack_depth": len(self._context_stack),
            "audit_enabled": self._audit_trail is not None,
            "aggregation_enabled": self._log_aggregator is not None
        }
        
        if self._log_aggregator:
            stats["aggregated_stats"] = self._log_aggregator.get_aggregated_stats()
        
        if self._audit_trail:
            stats["audit_summary"] = self._audit_trail.get_audit_summary()
        
        return stats
    
    async def shutdown(self):
        """关闭日志系统"""
        if self._log_aggregator:
            await self._log_aggregator.stop_aggregation()
        
        logger.info("层级RAG日志系统已关闭")


class LogContextManager:
    """日志上下文管理器"""
    
    def __init__(self, rag_logger: HierarchicalRAGLogger, context: LogContext):
        self.rag_logger = rag_logger
        self.context = context
    
    def __enter__(self):
        self.rag_logger.push_context(self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.rag_logger.pop_context()


# 全局日志器实例
_global_logger: Optional[HierarchicalRAGLogger] = None


def get_logger() -> HierarchicalRAGLogger:
    """获取全局日志器实例"""
    global _global_logger
    if _global_logger is None:
        _global_logger = HierarchicalRAGLogger()
    return _global_logger


def init_logging(log_dir: str = "logs", **kwargs) -> HierarchicalRAGLogger:
    """初始化日志系统"""
    global _global_logger
    _global_logger = HierarchicalRAGLogger(log_dir=log_dir, **kwargs)
    return _global_logger


# 便利函数
def log_audit_event(event_type: AuditEventType, action: str, **kwargs):
    """记录审计事件的便利函数"""
    rag_logger = get_logger()
    event = rag_logger.create_audit_event(event_type, action, **kwargs)
    rag_logger.record_audit_event(event)


def with_log_context(**kwargs):
    """日志上下文装饰器"""
    def decorator(func):
        async def async_wrapper(*args, **func_kwargs):
            rag_logger = get_logger()
            with rag_logger.with_context(**kwargs):
                return await func(*args, **func_kwargs)
        
        def sync_wrapper(*args, **func_kwargs):
            rag_logger = get_logger()
            with rag_logger.with_context(**kwargs):
                return func(*args, **func_kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# 使用示例
async def main():
    """日志和审计系统使用示例"""
    # 初始化日志系统
    rag_logger = init_logging("logs")
    
    try:
        # 使用上下文记录日志
        with rag_logger.with_context(layer="haystack", operation="orchestrate"):
            logger.info("开始编排任务")
            
            # 记录审计事件
            log_audit_event(
                AuditEventType.AUDIT_START,
                "开始代码审计",
                user_id="user123",
                resource="project_abc",
                security_level=SecurityLevel.INTERNAL
            )
            
            # 模拟一些操作
            await asyncio.sleep(1)
            
            logger.success("编排任务完成")
            
            log_audit_event(
                AuditEventType.AUDIT_COMPLETE,
                "代码审计完成",
                user_id="user123",
                resource="project_abc",
                vulnerabilities_found=5
            )
        
        # 获取统计信息
        stats = rag_logger.get_log_stats()
        logger.info(f"日志统计: {json.dumps(stats, indent=2, ensure_ascii=False)}")
        
        # 获取审计摘要
        audit_summary = rag_logger.get_audit_summary()
        logger.info(f"审计摘要: {json.dumps(audit_summary, indent=2, ensure_ascii=False)}")
        
    finally:
        # 关闭日志系统
        await rag_logger.shutdown()


if __name__ == "__main__":
    asyncio.run(main())