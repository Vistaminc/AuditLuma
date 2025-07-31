"""
性能监控系统 - 层级RAG架构性能监控组件

负责收集、分析和报告各层性能指标，提供性能告警和自动调优机制。
"""

import asyncio
import time
import threading
import statistics
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
from collections import defaultdict, deque
import json
import logging

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """指标类型"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class AlertLevel(Enum):
    """告警级别"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class PerformanceMetric:
    """性能指标"""
    name: str
    value: float
    metric_type: MetricType
    timestamp: float
    layer: str
    operation: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "value": self.value,
            "type": self.metric_type.value,
            "timestamp": self.timestamp,
            "layer": self.layer,
            "operation": self.operation,
            "metadata": self.metadata
        }


@dataclass
class PerformanceAlert:
    """性能告警"""
    alert_id: str
    level: AlertLevel
    message: str
    metric_name: str
    current_value: float
    threshold: float
    timestamp: float
    layer: str
    operation: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "alert_id": self.alert_id,
            "level": self.level.value,
            "message": self.message,
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "threshold": self.threshold,
            "timestamp": self.timestamp,
            "layer": self.layer,
            "operation": self.operation,
            "metadata": self.metadata
        }


@dataclass
class LayerPerformanceStats:
    """层级性能统计"""
    layer_name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    throughput: float = 0.0  # 请求/秒
    error_rate: float = 0.0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0
    
    def update_response_time(self, response_time: float):
        """更新响应时间统计"""
        self.min_response_time = min(self.min_response_time, response_time)
        self.max_response_time = max(self.max_response_time, response_time)
    
    def calculate_error_rate(self):
        """计算错误率"""
        if self.total_requests > 0:
            self.error_rate = self.failed_requests / self.total_requests
        else:
            self.error_rate = 0.0


class MetricsCollector:
    """指标收集器"""
    
    def __init__(self, max_metrics: int = 10000):
        """初始化指标收集器"""
        self.max_metrics = max_metrics
        self._metrics: deque = deque(maxlen=max_metrics)
        self._metrics_by_layer: Dict[str, List[PerformanceMetric]] = defaultdict(list)
        self._metrics_by_operation: Dict[str, List[PerformanceMetric]] = defaultdict(list)
        self._lock = threading.RLock()
    
    def collect_metric(self, metric: PerformanceMetric):
        """收集指标"""
        with self._lock:
            self._metrics.append(metric)
            self._metrics_by_layer[metric.layer].append(metric)
            self._metrics_by_operation[metric.operation].append(metric)
            
            # 限制每层和每操作的指标数量
            if len(self._metrics_by_layer[metric.layer]) > 1000:
                self._metrics_by_layer[metric.layer] = self._metrics_by_layer[metric.layer][-1000:]
            
            if len(self._metrics_by_operation[metric.operation]) > 1000:
                self._metrics_by_operation[metric.operation] = self._metrics_by_operation[metric.operation][-1000:]
    
    def get_metrics(self, layer: Optional[str] = None, 
                   operation: Optional[str] = None,
                   since: Optional[float] = None) -> List[PerformanceMetric]:
        """获取指标"""
        with self._lock:
            if layer:
                metrics = self._metrics_by_layer.get(layer, [])
            elif operation:
                metrics = self._metrics_by_operation.get(operation, [])
            else:
                metrics = list(self._metrics)
            
            if since:
                metrics = [m for m in metrics if m.timestamp >= since]
            
            return metrics
    
    def get_latest_metrics(self, count: int = 100) -> List[PerformanceMetric]:
        """获取最新指标"""
        with self._lock:
            return list(self._metrics)[-count:]
    
    def clear_old_metrics(self, before_timestamp: float):
        """清理旧指标"""
        with self._lock:
            # 清理主指标列表
            self._metrics = deque([m for m in self._metrics if m.timestamp >= before_timestamp], 
                                maxlen=self.max_metrics)
            
            # 清理分层指标
            for layer in self._metrics_by_layer:
                self._metrics_by_layer[layer] = [
                    m for m in self._metrics_by_layer[layer] if m.timestamp >= before_timestamp
                ]
            
            # 清理分操作指标
            for operation in self._metrics_by_operation:
                self._metrics_by_operation[operation] = [
                    m for m in self._metrics_by_operation[operation] if m.timestamp >= before_timestamp
                ]


class PerformanceAnalyzer:
    """性能分析器"""
    
    def __init__(self):
        """初始化性能分析器"""
        self._response_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._lock = threading.RLock()
    
    def analyze_layer_performance(self, layer: str, 
                                metrics: List[PerformanceMetric]) -> LayerPerformanceStats:
        """分析层级性能"""
        if not metrics:
            return LayerPerformanceStats(layer_name=layer)
        
        stats = LayerPerformanceStats(layer_name=layer)
        response_times = []
        
        for metric in metrics:
            if metric.metric_type == MetricType.TIMER:
                response_times.append(metric.value)
                stats.update_response_time(metric.value)
            elif metric.name == "request_count":
                stats.total_requests += int(metric.value)
            elif metric.name == "success_count":
                stats.successful_requests += int(metric.value)
            elif metric.name == "error_count":
                stats.failed_requests += int(metric.value)
            elif metric.name == "memory_usage":
                stats.memory_usage = metric.value
            elif metric.name == "cpu_usage":
                stats.cpu_usage = metric.value
        
        # 计算统计值
        if response_times:
            stats.average_response_time = statistics.mean(response_times)
            if len(response_times) >= 20:  # 至少20个样本才计算百分位数
                stats.p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
                stats.p99_response_time = statistics.quantiles(response_times, n=100)[98]  # 99th percentile
        
        # 计算吞吐量
        if metrics:
            time_span = max(m.timestamp for m in metrics) - min(m.timestamp for m in metrics)
            if time_span > 0:
                stats.throughput = stats.total_requests / time_span
        
        # 计算错误率
        stats.calculate_error_rate()
        
        return stats
    
    def detect_performance_anomalies(self, layer: str, 
                                   current_stats: LayerPerformanceStats,
                                   historical_stats: List[LayerPerformanceStats]) -> List[str]:
        """检测性能异常"""
        anomalies = []
        
        if not historical_stats:
            return anomalies
        
        # 计算历史平均值
        avg_response_time = statistics.mean([s.average_response_time for s in historical_stats])
        avg_error_rate = statistics.mean([s.error_rate for s in historical_stats])
        avg_throughput = statistics.mean([s.throughput for s in historical_stats])
        
        # 响应时间异常检测
        if current_stats.average_response_time > avg_response_time * 2:
            anomalies.append(f"响应时间异常增长: {current_stats.average_response_time:.2f}s vs 历史平均 {avg_response_time:.2f}s")
        
        # 错误率异常检测
        if current_stats.error_rate > avg_error_rate * 3 and current_stats.error_rate > 0.05:
            anomalies.append(f"错误率异常增长: {current_stats.error_rate:.2%} vs 历史平均 {avg_error_rate:.2%}")
        
        # 吞吐量异常检测
        if current_stats.throughput < avg_throughput * 0.5 and avg_throughput > 0:
            anomalies.append(f"吞吐量异常下降: {current_stats.throughput:.2f} vs 历史平均 {avg_throughput:.2f}")
        
        return anomalies
    
    def calculate_performance_score(self, stats: LayerPerformanceStats) -> float:
        """计算性能评分（0-100）"""
        score = 100.0
        
        # 响应时间评分（权重40%）
        if stats.average_response_time > 10.0:  # 超过10秒
            score -= 40
        elif stats.average_response_time > 5.0:  # 超过5秒
            score -= 20
        elif stats.average_response_time > 1.0:  # 超过1秒
            score -= 10
        
        # 错误率评分（权重30%）
        if stats.error_rate > 0.1:  # 超过10%
            score -= 30
        elif stats.error_rate > 0.05:  # 超过5%
            score -= 15
        elif stats.error_rate > 0.01:  # 超过1%
            score -= 5
        
        # 吞吐量评分（权重20%）
        if stats.throughput < 1.0:  # 低于1请求/秒
            score -= 20
        elif stats.throughput < 5.0:  # 低于5请求/秒
            score -= 10
        
        # 资源使用评分（权重10%）
        if stats.memory_usage > 0.9:  # 超过90%
            score -= 10
        elif stats.memory_usage > 0.8:  # 超过80%
            score -= 5
        
        return max(0.0, score)


class AlertManager:
    """告警管理器"""
    
    def __init__(self, max_alerts: int = 1000):
        """初始化告警管理器"""
        self.max_alerts = max_alerts
        self._alerts: deque = deque(maxlen=max_alerts)
        self._alert_handlers: List[Callable[[PerformanceAlert], None]] = []
        self._alert_thresholds: Dict[str, Dict[str, float]] = {}
        self._lock = threading.RLock()
        
        # 默认告警阈值
        self._set_default_thresholds()
    
    def _set_default_thresholds(self):
        """设置默认告警阈值"""
        self._alert_thresholds = {
            "response_time": {
                "warning": 5.0,
                "error": 10.0,
                "critical": 30.0
            },
            "error_rate": {
                "warning": 0.05,
                "error": 0.1,
                "critical": 0.2
            },
            "memory_usage": {
                "warning": 0.8,
                "error": 0.9,
                "critical": 0.95
            },
            "cpu_usage": {
                "warning": 0.8,
                "error": 0.9,
                "critical": 0.95
            }
        }
    
    def add_alert_handler(self, handler: Callable[[PerformanceAlert], None]):
        """添加告警处理器"""
        self._alert_handlers.append(handler)
    
    def set_threshold(self, metric_name: str, level: str, threshold: float):
        """设置告警阈值"""
        if metric_name not in self._alert_thresholds:
            self._alert_thresholds[metric_name] = {}
        self._alert_thresholds[metric_name][level] = threshold
    
    def check_thresholds(self, stats: LayerPerformanceStats) -> List[PerformanceAlert]:
        """检查告警阈值"""
        alerts = []
        current_time = time.time()
        
        # 检查响应时间
        response_time_alerts = self._check_metric_threshold(
            "response_time", stats.average_response_time, 
            stats.layer_name, "response_time", current_time
        )
        alerts.extend(response_time_alerts)
        
        # 检查错误率
        error_rate_alerts = self._check_metric_threshold(
            "error_rate", stats.error_rate,
            stats.layer_name, "error_rate", current_time
        )
        alerts.extend(error_rate_alerts)
        
        # 检查内存使用
        memory_alerts = self._check_metric_threshold(
            "memory_usage", stats.memory_usage,
            stats.layer_name, "memory_usage", current_time
        )
        alerts.extend(memory_alerts)
        
        # 检查CPU使用
        cpu_alerts = self._check_metric_threshold(
            "cpu_usage", stats.cpu_usage,
            stats.layer_name, "cpu_usage", current_time
        )
        alerts.extend(cpu_alerts)
        
        return alerts
    
    def _check_metric_threshold(self, metric_name: str, value: float,
                              layer: str, operation: str, timestamp: float) -> List[PerformanceAlert]:
        """检查单个指标的阈值"""
        alerts = []
        thresholds = self._alert_thresholds.get(metric_name, {})
        
        for level_name, threshold in thresholds.items():
            if value >= threshold:
                alert_level = AlertLevel(level_name.lower())
                alert = PerformanceAlert(
                    alert_id=f"{layer}_{operation}_{metric_name}_{level_name}_{int(timestamp)}",
                    level=alert_level,
                    message=f"{layer} 层 {metric_name} 超过 {level_name} 阈值: {value:.2f} >= {threshold:.2f}",
                    metric_name=metric_name,
                    current_value=value,
                    threshold=threshold,
                    timestamp=timestamp,
                    layer=layer,
                    operation=operation
                )
                alerts.append(alert)
                break  # 只触发最高级别的告警
        
        return alerts
    
    def trigger_alert(self, alert: PerformanceAlert):
        """触发告警"""
        with self._lock:
            self._alerts.append(alert)
            
            # 调用告警处理器
            for handler in self._alert_handlers:
                try:
                    handler(alert)
                except Exception as e:
                    logger.error(f"告警处理器执行失败: {e}")
    
    def get_alerts(self, level: Optional[AlertLevel] = None,
                  layer: Optional[str] = None,
                  since: Optional[float] = None) -> List[PerformanceAlert]:
        """获取告警"""
        with self._lock:
            alerts = list(self._alerts)
            
            if level:
                alerts = [a for a in alerts if a.level == level]
            
            if layer:
                alerts = [a for a in alerts if a.layer == layer]
            
            if since:
                alerts = [a for a in alerts if a.timestamp >= since]
            
            return alerts
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """获取告警摘要"""
        with self._lock:
            alerts = list(self._alerts)
            
            summary = {
                "total_alerts": len(alerts),
                "by_level": defaultdict(int),
                "by_layer": defaultdict(int),
                "recent_alerts": []
            }
            
            for alert in alerts:
                summary["by_level"][alert.level.value] += 1
                summary["by_layer"][alert.layer] += 1
            
            # 最近的告警
            recent_time = time.time() - 3600  # 最近1小时
            recent_alerts = [a for a in alerts if a.timestamp >= recent_time]
            summary["recent_alerts"] = [a.to_dict() for a in recent_alerts[-10:]]
            
            return summary


class AutoTuner:
    """自动调优器"""
    
    def __init__(self):
        """初始化自动调优器"""
        self._tuning_rules: List[Callable[[LayerPerformanceStats], Dict[str, Any]]] = []
        self._tuning_history: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        
        # 注册默认调优规则
        self._register_default_rules()
    
    def _register_default_rules(self):
        """注册默认调优规则"""
        self._tuning_rules.extend([
            self._tune_worker_count,
            self._tune_timeout_settings,
            self._tune_cache_settings,
            self._tune_batch_size
        ])
    
    def add_tuning_rule(self, rule: Callable[[LayerPerformanceStats], Dict[str, Any]]):
        """添加调优规则"""
        self._tuning_rules.append(rule)
    
    def analyze_and_tune(self, stats: LayerPerformanceStats) -> Dict[str, Any]:
        """分析并生成调优建议"""
        recommendations = {
            "layer": stats.layer_name,
            "timestamp": time.time(),
            "recommendations": []
        }
        
        for rule in self._tuning_rules:
            try:
                rule_recommendations = rule(stats)
                if rule_recommendations:
                    recommendations["recommendations"].extend(rule_recommendations.get("recommendations", []))
            except Exception as e:
                logger.error(f"调优规则执行失败: {e}")
        
        if recommendations["recommendations"]:
            with self._lock:
                self._tuning_history.append(recommendations)
                # 保留最近100条调优记录
                if len(self._tuning_history) > 100:
                    self._tuning_history = self._tuning_history[-100:]
        
        return recommendations
    
    def _tune_worker_count(self, stats: LayerPerformanceStats) -> Dict[str, Any]:
        """调优工作线程数"""
        recommendations = {"recommendations": []}
        
        # 如果响应时间过长且CPU使用率不高，建议增加工作线程
        if stats.average_response_time > 5.0 and stats.cpu_usage < 0.7:
            recommendations["recommendations"].append({
                "type": "worker_count",
                "action": "increase",
                "current_value": "unknown",
                "suggested_value": "increase by 20%",
                "reason": f"响应时间过长({stats.average_response_time:.2f}s)且CPU使用率较低({stats.cpu_usage:.1%})"
            })
        
        # 如果CPU使用率过高，建议减少工作线程
        elif stats.cpu_usage > 0.9:
            recommendations["recommendations"].append({
                "type": "worker_count",
                "action": "decrease",
                "current_value": "unknown",
                "suggested_value": "decrease by 10%",
                "reason": f"CPU使用率过高({stats.cpu_usage:.1%})"
            })
        
        return recommendations
    
    def _tune_timeout_settings(self, stats: LayerPerformanceStats) -> Dict[str, Any]:
        """调优超时设置"""
        recommendations = {"recommendations": []}
        
        # 如果平均响应时间接近超时时间，建议增加超时
        if stats.average_response_time > 8.0:  # 假设默认超时是10秒
            recommendations["recommendations"].append({
                "type": "timeout",
                "action": "increase",
                "current_value": "10s",
                "suggested_value": f"{int(stats.average_response_time * 1.5)}s",
                "reason": f"平均响应时间({stats.average_response_time:.2f}s)接近超时阈值"
            })
        
        return recommendations
    
    def _tune_cache_settings(self, stats: LayerPerformanceStats) -> Dict[str, Any]:
        """调优缓存设置"""
        recommendations = {"recommendations": []}
        
        # 如果响应时间较长，建议增加缓存
        if stats.average_response_time > 3.0 and stats.throughput > 10:
            recommendations["recommendations"].append({
                "type": "cache",
                "action": "increase",
                "current_value": "unknown",
                "suggested_value": "increase cache size by 50%",
                "reason": f"响应时间较长({stats.average_response_time:.2f}s)且请求量较大({stats.throughput:.1f}/s)"
            })
        
        return recommendations
    
    def _tune_batch_size(self, stats: LayerPerformanceStats) -> Dict[str, Any]:
        """调优批处理大小"""
        recommendations = {"recommendations": []}
        
        # 如果吞吐量较低，建议增加批处理大小
        if stats.throughput < 5.0 and stats.average_response_time < 2.0:
            recommendations["recommendations"].append({
                "type": "batch_size",
                "action": "increase",
                "current_value": "unknown",
                "suggested_value": "increase by 50%",
                "reason": f"吞吐量较低({stats.throughput:.1f}/s)且响应时间正常({stats.average_response_time:.2f}s)"
            })
        
        return recommendations
    
    def get_tuning_history(self, layer: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取调优历史"""
        with self._lock:
            history = self._tuning_history.copy()
            
            if layer:
                history = [h for h in history if h.get("layer") == layer]
            
            return history


class PerformanceMonitor:
    """性能监控器 - 主要监控组件"""
    
    def __init__(self, collection_interval: float = 10.0,
                 analysis_interval: float = 60.0,
                 cleanup_interval: float = 3600.0):
        """初始化性能监控器"""
        self.collection_interval = collection_interval
        self.analysis_interval = analysis_interval
        self.cleanup_interval = cleanup_interval
        
        # 核心组件
        self.metrics_collector = MetricsCollector()
        self.performance_analyzer = PerformanceAnalyzer()
        self.alert_manager = AlertManager()
        self.auto_tuner = AutoTuner()
        
        # 层级性能统计
        self._layer_stats: Dict[str, LayerPerformanceStats] = {}
        self._layer_stats_history: Dict[str, List[LayerPerformanceStats]] = defaultdict(list)
        
        # 控制标志
        self._monitoring_active = False
        self._monitoring_tasks: List[asyncio.Task] = []
        self._lock = threading.RLock()
        
        # 注册默认告警处理器
        self.alert_manager.add_alert_handler(self._default_alert_handler)
        
        logger.info("性能监控器初始化完成")
    
    async def start_monitoring(self):
        """启动性能监控"""
        if self._monitoring_active:
            logger.warning("性能监控已经在运行")
            return
        
        self._monitoring_active = True
        
        # 启动监控任务
        self._monitoring_tasks = [
            asyncio.create_task(self._collection_loop()),
            asyncio.create_task(self._analysis_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
        logger.info("性能监控已启动")
    
    async def stop_monitoring(self):
        """停止性能监控"""
        if not self._monitoring_active:
            return
        
        self._monitoring_active = False
        
        # 取消监控任务
        for task in self._monitoring_tasks:
            task.cancel()
        
        # 等待任务完成
        try:
            await asyncio.gather(*self._monitoring_tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"停止监控任务时出错: {e}")
        
        self._monitoring_tasks.clear()
        logger.info("性能监控已停止")
    
    def record_metric(self, name: str, value: float, metric_type: MetricType,
                     layer: str, operation: str, metadata: Optional[Dict[str, Any]] = None):
        """记录性能指标"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            metric_type=metric_type,
            timestamp=time.time(),
            layer=layer,
            operation=operation,
            metadata=metadata or {}
        )
        
        self.metrics_collector.collect_metric(metric)
    
    def record_operation_time(self, layer: str, operation: str, duration: float,
                            success: bool = True, metadata: Optional[Dict[str, Any]] = None):
        """记录操作时间"""
        # 记录响应时间
        self.record_metric("response_time", duration, MetricType.TIMER, layer, operation, metadata)
        
        # 记录请求计数
        self.record_metric("request_count", 1, MetricType.COUNTER, layer, operation, metadata)
        
        # 记录成功/失败计数
        if success:
            self.record_metric("success_count", 1, MetricType.COUNTER, layer, operation, metadata)
        else:
            self.record_metric("error_count", 1, MetricType.COUNTER, layer, operation, metadata)
    
    def get_layer_stats(self, layer: str) -> Optional[LayerPerformanceStats]:
        """获取层级统计"""
        with self._lock:
            return self._layer_stats.get(layer)
    
    def get_all_layer_stats(self) -> Dict[str, LayerPerformanceStats]:
        """获取所有层级统计"""
        with self._lock:
            return self._layer_stats.copy()
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """获取性能摘要"""
        with self._lock:
            summary = {
                "timestamp": time.time(),
                "monitoring_active": self._monitoring_active,
                "layers": {},
                "overall": {
                    "total_requests": 0,
                    "total_errors": 0,
                    "average_response_time": 0.0,
                    "overall_error_rate": 0.0
                }
            }
            
            total_requests = 0
            total_errors = 0
            total_response_time = 0.0
            
            for layer_name, stats in self._layer_stats.items():
                summary["layers"][layer_name] = {
                    "requests": stats.total_requests,
                    "errors": stats.failed_requests,
                    "avg_response_time": stats.average_response_time,
                    "error_rate": stats.error_rate,
                    "throughput": stats.throughput,
                    "performance_score": self.performance_analyzer.calculate_performance_score(stats)
                }
                
                total_requests += stats.total_requests
                total_errors += stats.failed_requests
                total_response_time += stats.average_response_time * stats.total_requests
            
            # 计算整体统计
            if total_requests > 0:
                summary["overall"]["total_requests"] = total_requests
                summary["overall"]["total_errors"] = total_errors
                summary["overall"]["average_response_time"] = total_response_time / total_requests
                summary["overall"]["overall_error_rate"] = total_errors / total_requests
            
            return summary
    
    def get_alerts_summary(self) -> Dict[str, Any]:
        """获取告警摘要"""
        return self.alert_manager.get_alert_summary()
    
    def get_tuning_recommendations(self, layer: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取调优建议"""
        recommendations = []
        
        with self._lock:
            if layer:
                stats = self._layer_stats.get(layer)
                if stats:
                    recommendations.append(self.auto_tuner.analyze_and_tune(stats))
            else:
                for layer_name, stats in self._layer_stats.items():
                    recommendations.append(self.auto_tuner.analyze_and_tune(stats))
        
        return recommendations
    
    async def _collection_loop(self):
        """指标收集循环"""
        while self._monitoring_active:
            try:
                await asyncio.sleep(self.collection_interval)
                # 这里可以添加主动收集系统指标的逻辑
                # 例如：CPU使用率、内存使用率等
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"指标收集循环异常: {e}")
    
    async def _analysis_loop(self):
        """性能分析循环"""
        while self._monitoring_active:
            try:
                await asyncio.sleep(self.analysis_interval)
                await self._analyze_performance()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"性能分析循环异常: {e}")
    
    async def _cleanup_loop(self):
        """清理循环"""
        while self._monitoring_active:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                # 清理旧指标
                cleanup_time = time.time() - 24 * 3600  # 保留24小时
                self.metrics_collector.clear_old_metrics(cleanup_time)
                
                # 清理旧的层级统计历史
                with self._lock:
                    for layer in self._layer_stats_history:
                        self._layer_stats_history[layer] = [
                            stats for stats in self._layer_stats_history[layer]
                            if hasattr(stats, 'timestamp') and getattr(stats, 'timestamp', 0) >= cleanup_time
                        ]
                
                logger.info("性能监控数据清理完成")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"清理循环异常: {e}")
    
    async def _analyze_performance(self):
        """分析性能"""
        current_time = time.time()
        analysis_window = current_time - self.analysis_interval
        
        # 获取各层的指标
        layers = set()
        recent_metrics = self.metrics_collector.get_metrics(since=analysis_window)
        
        for metric in recent_metrics:
            layers.add(metric.layer)
        
        # 分析每一层的性能
        with self._lock:
            for layer in layers:
                layer_metrics = [m for m in recent_metrics if m.layer == layer]
                stats = self.performance_analyzer.analyze_layer_performance(layer, layer_metrics)
                
                # 添加时间戳
                stats.timestamp = current_time
                
                # 更新当前统计
                self._layer_stats[layer] = stats
                
                # 添加到历史记录
                self._layer_stats_history[layer].append(stats)
                
                # 限制历史记录数量
                if len(self._layer_stats_history[layer]) > 100:
                    self._layer_stats_history[layer] = self._layer_stats_history[layer][-100:]
                
                # 检查告警
                alerts = self.alert_manager.check_thresholds(stats)
                for alert in alerts:
                    self.alert_manager.trigger_alert(alert)
                
                # 检测异常
                historical_stats = self._layer_stats_history[layer][:-1]  # 排除当前统计
                anomalies = self.performance_analyzer.detect_performance_anomalies(
                    layer, stats, historical_stats
                )
                
                if anomalies:
                    logger.warning(f"检测到 {layer} 层性能异常: {anomalies}")
    
    def _default_alert_handler(self, alert: PerformanceAlert):
        """默认告警处理器"""
        level_colors = {
            AlertLevel.INFO: "INFO",
            AlertLevel.WARNING: "WARNING", 
            AlertLevel.ERROR: "ERROR",
            AlertLevel.CRITICAL: "CRITICAL"
        }
        
        color = level_colors.get(alert.level, "INFO")
        logger.log(
            getattr(logging, alert.level.value.upper(), logging.INFO),
            f"[{color}] {alert.message}"
        )


# 性能监控装饰器
def monitor_performance(layer: str, operation: str = None):
    """性能监控装饰器"""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            op_name = operation or func.__name__
            start_time = time.time()
            success = True
            error = None
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                error = e
                raise
            finally:
                duration = time.time() - start_time
                
                # 获取全局监控器实例
                monitor = get_global_monitor()
                if monitor:
                    metadata = {"error": str(error)} if error else None
                    monitor.record_operation_time(layer, op_name, duration, success, metadata)
        
        def sync_wrapper(*args, **kwargs):
            op_name = operation or func.__name__
            start_time = time.time()
            success = True
            error = None
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                error = e
                raise
            finally:
                duration = time.time() - start_time
                
                # 获取全局监控器实例
                monitor = get_global_monitor()
                if monitor:
                    metadata = {"error": str(error)} if error else None
                    monitor.record_operation_time(layer, op_name, duration, success, metadata)
        
        # 检查是否是异步函数
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# 全局监控器实例
_global_monitor: Optional[PerformanceMonitor] = None


def get_global_monitor() -> Optional[PerformanceMonitor]:
    """获取全局监控器实例"""
    return _global_monitor


def set_global_monitor(monitor: PerformanceMonitor):
    """设置全局监控器实例"""
    global _global_monitor
    _global_monitor = monitor


def create_default_monitor() -> PerformanceMonitor:
    """创建默认监控器"""
    return PerformanceMonitor()