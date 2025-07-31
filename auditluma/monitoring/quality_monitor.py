"""
质量监控系统 - 层级RAG架构质量监控组件

负责监控准确性、假阳性率、置信度等质量指标，提供质量趋势分析和报告生成功能。
"""

import asyncio
import time
import threading
import statistics
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from collections import defaultdict, deque
import json
import logging
import numpy as np
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class QualityMetricType(Enum):
    """质量指标类型"""
    ACCURACY = "accuracy"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    FALSE_NEGATIVE_RATE = "false_negative_rate"
    CONFIDENCE_SCORE = "confidence_score"
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"


class QualityLevel(Enum):
    """质量等级"""
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    CRITICAL = "critical"


@dataclass
class QualityMetric:
    """质量指标"""
    metric_type: QualityMetricType
    value: float
    timestamp: float
    layer: str
    operation: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "metric_type": self.metric_type.value,
            "value": self.value,
            "timestamp": self.timestamp,
            "layer": self.layer,
            "operation": self.operation,
            "metadata": self.metadata
        }


@dataclass
class QualityAssessment:
    """质量评估结果"""
    layer: str
    operation: str
    overall_score: float
    quality_level: QualityLevel
    metrics: Dict[QualityMetricType, float]
    timestamp: float
    assessment_details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "layer": self.layer,
            "operation": self.operation,
            "overall_score": self.overall_score,
            "quality_level": self.quality_level.value,
            "metrics": {k.value: v for k, v in self.metrics.items()},
            "timestamp": self.timestamp,
            "assessment_details": self.assessment_details
        }


@dataclass
class QualityTrend:
    """质量趋势"""
    metric_type: QualityMetricType
    layer: str
    operation: str
    trend_direction: str  # "improving", "stable", "declining"
    trend_strength: float  # 0.0 to 1.0
    current_value: float
    previous_value: float
    change_rate: float
    timestamp: float
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "metric_type": self.metric_type.value,
            "layer": self.layer,
            "operation": self.operation,
            "trend_direction": self.trend_direction,
            "trend_strength": self.trend_strength,
            "current_value": self.current_value,
            "previous_value": self.previous_value,
            "change_rate": self.change_rate,
            "timestamp": self.timestamp
        }


@dataclass
class QualityAlert:
    """质量告警"""
    alert_id: str
    metric_type: QualityMetricType
    layer: str
    operation: str
    current_value: float
    threshold: float
    severity: str  # "low", "medium", "high", "critical"
    message: str
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "alert_id": self.alert_id,
            "metric_type": self.metric_type.value,
            "layer": self.layer,
            "operation": self.operation,
            "current_value": self.current_value,
            "threshold": self.threshold,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


class QualityMetricsCollector:
    """质量指标收集器"""
    
    def __init__(self, max_metrics: int = 50000):
        """初始化质量指标收集器"""
        self.max_metrics = max_metrics
        self._metrics: deque = deque(maxlen=max_metrics)
        self._metrics_by_layer: Dict[str, List[QualityMetric]] = defaultdict(list)
        self._metrics_by_type: Dict[QualityMetricType, List[QualityMetric]] = defaultdict(list)
        self._lock = threading.RLock()
    
    def collect_metric(self, metric: QualityMetric):
        """收集质量指标"""
        with self._lock:
            self._metrics.append(metric)
            self._metrics_by_layer[metric.layer].append(metric)
            self._metrics_by_type[metric.metric_type].append(metric)
            
            # 限制每层和每类型的指标数量
            max_per_category = 5000
            if len(self._metrics_by_layer[metric.layer]) > max_per_category:
                self._metrics_by_layer[metric.layer] = self._metrics_by_layer[metric.layer][-max_per_category:]
            
            if len(self._metrics_by_type[metric.metric_type]) > max_per_category:
                self._metrics_by_type[metric.metric_type] = self._metrics_by_type[metric.metric_type][-max_per_category:]
    
    def get_metrics(self, 
                   layer: Optional[str] = None,
                   metric_type: Optional[QualityMetricType] = None,
                   since: Optional[float] = None,
                   limit: Optional[int] = None) -> List[QualityMetric]:
        """获取质量指标"""
        with self._lock:
            if layer and metric_type:
                # 获取特定层和类型的指标
                metrics = [m for m in self._metrics_by_layer.get(layer, []) 
                          if m.metric_type == metric_type]
            elif layer:
                metrics = self._metrics_by_layer.get(layer, [])
            elif metric_type:
                metrics = self._metrics_by_type.get(metric_type, [])
            else:
                metrics = list(self._metrics)
            
            # 时间过滤
            if since:
                metrics = [m for m in metrics if m.timestamp >= since]
            
            # 排序（最新的在前）
            metrics.sort(key=lambda x: x.timestamp, reverse=True)
            
            # 限制数量
            if limit:
                metrics = metrics[:limit]
            
            return metrics
    
    def get_latest_metrics(self, count: int = 100) -> List[QualityMetric]:
        """获取最新的质量指标"""
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
            
            # 清理分类型指标
            for metric_type in self._metrics_by_type:
                self._metrics_by_type[metric_type] = [
                    m for m in self._metrics_by_type[metric_type] if m.timestamp >= before_timestamp
                ]


class QualityAnalyzer:
    """质量分析器"""
    
    def __init__(self):
        """初始化质量分析器"""
        self._quality_thresholds = self._get_default_thresholds()
        self._lock = threading.RLock()
    
    def _get_default_thresholds(self) -> Dict[QualityMetricType, Dict[str, float]]:
        """获取默认质量阈值"""
        return {
            QualityMetricType.ACCURACY: {
                "excellent": 0.95,
                "good": 0.85,
                "acceptable": 0.70,
                "poor": 0.50
            },
            QualityMetricType.PRECISION: {
                "excellent": 0.90,
                "good": 0.80,
                "acceptable": 0.65,
                "poor": 0.45
            },
            QualityMetricType.RECALL: {
                "excellent": 0.90,
                "good": 0.80,
                "acceptable": 0.65,
                "poor": 0.45
            },
            QualityMetricType.F1_SCORE: {
                "excellent": 0.90,
                "good": 0.80,
                "acceptable": 0.65,
                "poor": 0.45
            },
            QualityMetricType.FALSE_POSITIVE_RATE: {
                "excellent": 0.05,
                "good": 0.10,
                "acceptable": 0.20,
                "poor": 0.35
            },
            QualityMetricType.CONFIDENCE_SCORE: {
                "excellent": 0.90,
                "good": 0.80,
                "acceptable": 0.65,
                "poor": 0.45
            }
        }
    
    def set_threshold(self, metric_type: QualityMetricType, level: str, threshold: float):
        """设置质量阈值"""
        with self._lock:
            if metric_type not in self._quality_thresholds:
                self._quality_thresholds[metric_type] = {}
            self._quality_thresholds[metric_type][level] = threshold
    
    def assess_quality(self, layer: str, operation: str, 
                      metrics: List[QualityMetric]) -> QualityAssessment:
        """评估质量"""
        if not metrics:
            return QualityAssessment(
                layer=layer,
                operation=operation,
                overall_score=0.0,
                quality_level=QualityLevel.CRITICAL,
                metrics={},
                timestamp=time.time()
            )
        
        # 按类型分组指标
        metrics_by_type = defaultdict(list)
        for metric in metrics:
            metrics_by_type[metric.metric_type].append(metric.value)
        
        # 计算每种类型的平均值
        avg_metrics = {}
        for metric_type, values in metrics_by_type.items():
            avg_metrics[metric_type] = statistics.mean(values)
        
        # 计算整体质量分数
        overall_score = self._calculate_overall_score(avg_metrics)
        
        # 确定质量等级
        quality_level = self._determine_quality_level(overall_score)
        
        # 生成评估详情
        assessment_details = self._generate_assessment_details(avg_metrics)
        
        return QualityAssessment(
            layer=layer,
            operation=operation,
            overall_score=overall_score,
            quality_level=quality_level,
            metrics=avg_metrics,
            timestamp=time.time(),
            assessment_details=assessment_details
        )
    
    def _calculate_overall_score(self, metrics: Dict[QualityMetricType, float]) -> float:
        """计算整体质量分数"""
        if not metrics:
            return 0.0
        
        # 权重配置
        weights = {
            QualityMetricType.ACCURACY: 0.25,
            QualityMetricType.PRECISION: 0.20,
            QualityMetricType.RECALL: 0.20,
            QualityMetricType.F1_SCORE: 0.15,
            QualityMetricType.FALSE_POSITIVE_RATE: -0.10,  # 负权重，越低越好
            QualityMetricType.CONFIDENCE_SCORE: 0.10
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for metric_type, value in metrics.items():
            weight = weights.get(metric_type, 0.0)
            if weight != 0.0:
                # 对于假阳性率，需要反转分数（1 - value）
                if metric_type == QualityMetricType.FALSE_POSITIVE_RATE:
                    normalized_value = 1.0 - min(1.0, max(0.0, value))
                    weighted_sum += abs(weight) * normalized_value
                else:
                    weighted_sum += weight * min(1.0, max(0.0, value))
                total_weight += abs(weight)
        
        if total_weight > 0:
            return min(1.0, max(0.0, weighted_sum / total_weight))
        else:
            return 0.0
    
    def _determine_quality_level(self, overall_score: float) -> QualityLevel:
        """确定质量等级"""
        if overall_score >= 0.90:
            return QualityLevel.EXCELLENT
        elif overall_score >= 0.80:
            return QualityLevel.GOOD
        elif overall_score >= 0.65:
            return QualityLevel.ACCEPTABLE
        elif overall_score >= 0.45:
            return QualityLevel.POOR
        else:
            return QualityLevel.CRITICAL
    
    def _generate_assessment_details(self, metrics: Dict[QualityMetricType, float]) -> Dict[str, Any]:
        """生成评估详情"""
        details = {
            "metric_assessments": {},
            "strengths": [],
            "weaknesses": [],
            "recommendations": []
        }
        
        for metric_type, value in metrics.items():
            thresholds = self._quality_thresholds.get(metric_type, {})
            
            # 确定该指标的等级
            metric_level = "critical"
            for level in ["excellent", "good", "acceptable", "poor"]:
                threshold = thresholds.get(level, 0.0)
                if metric_type == QualityMetricType.FALSE_POSITIVE_RATE:
                    # 假阳性率越低越好
                    if value <= threshold:
                        metric_level = level
                        break
                else:
                    # 其他指标越高越好
                    if value >= threshold:
                        metric_level = level
                        break
            
            details["metric_assessments"][metric_type.value] = {
                "value": value,
                "level": metric_level,
                "threshold": thresholds.get(metric_level, 0.0)
            }
            
            # 识别优势和劣势
            if metric_level in ["excellent", "good"]:
                details["strengths"].append(f"{metric_type.value}: {value:.3f} ({metric_level})")
            elif metric_level in ["poor", "critical"]:
                details["weaknesses"].append(f"{metric_type.value}: {value:.3f} ({metric_level})")
        
        # 生成改进建议
        details["recommendations"] = self._generate_recommendations(metrics)
        
        return details
    
    def _generate_recommendations(self, metrics: Dict[QualityMetricType, float]) -> List[str]:
        """生成改进建议"""
        recommendations = []
        
        # 准确性相关建议
        accuracy = metrics.get(QualityMetricType.ACCURACY, 0.0)
        if accuracy < 0.70:
            recommendations.append("考虑改进模型训练数据质量或调整模型参数以提高准确性")
        
        # 假阳性率相关建议
        fpr = metrics.get(QualityMetricType.FALSE_POSITIVE_RATE, 0.0)
        if fpr > 0.20:
            recommendations.append("假阳性率过高，建议优化过滤规则或提高检测阈值")
        
        # 置信度相关建议
        confidence = metrics.get(QualityMetricType.CONFIDENCE_SCORE, 0.0)
        if confidence < 0.65:
            recommendations.append("置信度较低，建议增强上下文分析或改进验证机制")
        
        # 精确率和召回率平衡建议
        precision = metrics.get(QualityMetricType.PRECISION, 0.0)
        recall = metrics.get(QualityMetricType.RECALL, 0.0)
        if precision > 0 and recall > 0:
            if precision - recall > 0.20:
                recommendations.append("精确率明显高于召回率，可能遗漏了一些问题，建议降低检测阈值")
            elif recall - precision > 0.20:
                recommendations.append("召回率明显高于精确率，可能存在过多误报，建议提高检测阈值")
        
        return recommendations
    
    def analyze_trends(self, metrics: List[QualityMetric], 
                      window_size: int = 10) -> List[QualityTrend]:
        """分析质量趋势"""
        if len(metrics) < window_size * 2:
            return []
        
        trends = []
        
        # 按类型和层分组
        grouped_metrics = defaultdict(lambda: defaultdict(list))
        for metric in metrics:
            grouped_metrics[metric.metric_type][metric.layer].append(metric)
        
        for metric_type, layer_metrics in grouped_metrics.items():
            for layer, layer_metric_list in layer_metrics.items():
                if len(layer_metric_list) >= window_size * 2:
                    # 按时间排序
                    layer_metric_list.sort(key=lambda x: x.timestamp)
                    
                    # 计算趋势
                    trend = self._calculate_trend(layer_metric_list, window_size, metric_type, layer)
                    if trend:
                        trends.append(trend)
        
        return trends
    
    def _calculate_trend(self, metrics: List[QualityMetric], window_size: int,
                        metric_type: QualityMetricType, layer: str) -> Optional[QualityTrend]:
        """计算单个指标的趋势"""
        if len(metrics) < window_size * 2:
            return None
        
        # 取最近的两个窗口
        recent_window = metrics[-window_size:]
        previous_window = metrics[-window_size*2:-window_size]
        
        # 计算平均值
        recent_avg = statistics.mean([m.value for m in recent_window])
        previous_avg = statistics.mean([m.value for m in previous_window])
        
        # 计算变化率
        if previous_avg != 0:
            change_rate = (recent_avg - previous_avg) / previous_avg
        else:
            change_rate = 0.0
        
        # 确定趋势方向和强度
        if abs(change_rate) < 0.05:  # 5%以内认为是稳定
            trend_direction = "stable"
            trend_strength = 0.0
        elif change_rate > 0:
            trend_direction = "improving"
            trend_strength = min(1.0, abs(change_rate))
        else:
            trend_direction = "declining"
            trend_strength = min(1.0, abs(change_rate))
        
        # 对于假阳性率，趋势方向需要反转
        if metric_type == QualityMetricType.FALSE_POSITIVE_RATE:
            if trend_direction == "improving":
                trend_direction = "declining"
            elif trend_direction == "declining":
                trend_direction = "improving"
        
        return QualityTrend(
            metric_type=metric_type,
            layer=layer,
            operation="overall",  # 可以根据需要细化
            trend_direction=trend_direction,
            trend_strength=trend_strength,
            current_value=recent_avg,
            previous_value=previous_avg,
            change_rate=change_rate,
            timestamp=time.time()
        )


class QualityAlertManager:
    """质量告警管理器"""
    
    def __init__(self, max_alerts: int = 1000):
        """初始化质量告警管理器"""
        self.max_alerts = max_alerts
        self._alerts: deque = deque(maxlen=max_alerts)
        self._alert_handlers: List[Callable[[QualityAlert], None]] = []
        self._alert_thresholds = self._get_default_alert_thresholds()
        self._lock = threading.RLock()
    
    def _get_default_alert_thresholds(self) -> Dict[QualityMetricType, Dict[str, float]]:
        """获取默认告警阈值"""
        return {
            QualityMetricType.ACCURACY: {
                "critical": 0.50,
                "high": 0.65,
                "medium": 0.75,
                "low": 0.85
            },
            QualityMetricType.FALSE_POSITIVE_RATE: {
                "critical": 0.40,
                "high": 0.25,
                "medium": 0.15,
                "low": 0.10
            },
            QualityMetricType.CONFIDENCE_SCORE: {
                "critical": 0.40,
                "high": 0.55,
                "medium": 0.70,
                "low": 0.80
            }
        }
    
    def add_alert_handler(self, handler: Callable[[QualityAlert], None]):
        """添加告警处理器"""
        self._alert_handlers.append(handler)
    
    def set_alert_threshold(self, metric_type: QualityMetricType, severity: str, threshold: float):
        """设置告警阈值"""
        with self._lock:
            if metric_type not in self._alert_thresholds:
                self._alert_thresholds[metric_type] = {}
            self._alert_thresholds[metric_type][severity] = threshold
    
    def check_quality_alerts(self, assessment: QualityAssessment) -> List[QualityAlert]:
        """检查质量告警"""
        alerts = []
        
        for metric_type, value in assessment.metrics.items():
            alert = self._check_metric_alert(metric_type, value, assessment.layer, assessment.operation)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _check_metric_alert(self, metric_type: QualityMetricType, value: float,
                           layer: str, operation: str) -> Optional[QualityAlert]:
        """检查单个指标的告警"""
        thresholds = self._alert_thresholds.get(metric_type, {})
        if not thresholds:
            return None
        
        # 确定告警级别
        alert_severity = None
        alert_threshold = None
        
        for severity in ["critical", "high", "medium", "low"]:
            threshold = thresholds.get(severity)
            if threshold is not None:
                # 对于假阳性率，值越高越严重
                if metric_type == QualityMetricType.FALSE_POSITIVE_RATE:
                    if value >= threshold:
                        alert_severity = severity
                        alert_threshold = threshold
                        break
                else:
                    # 对于其他指标，值越低越严重
                    if value <= threshold:
                        alert_severity = severity
                        alert_threshold = threshold
                        break
        
        if alert_severity:
            alert_id = f"{layer}_{operation}_{metric_type.value}_{alert_severity}_{int(time.time())}"
            message = self._generate_alert_message(metric_type, value, alert_threshold, alert_severity)
            
            return QualityAlert(
                alert_id=alert_id,
                metric_type=metric_type,
                layer=layer,
                operation=operation,
                current_value=value,
                threshold=alert_threshold,
                severity=alert_severity,
                message=message,
                timestamp=time.time()
            )
        
        return None
    
    def _generate_alert_message(self, metric_type: QualityMetricType, value: float,
                               threshold: float, severity: str) -> str:
        """生成告警消息"""
        if metric_type == QualityMetricType.FALSE_POSITIVE_RATE:
            return f"{metric_type.value} 过高: {value:.3f} >= {threshold:.3f} (严重程度: {severity})"
        else:
            return f"{metric_type.value} 过低: {value:.3f} <= {threshold:.3f} (严重程度: {severity})"
    
    def trigger_alert(self, alert: QualityAlert):
        """触发告警"""
        with self._lock:
            self._alerts.append(alert)
            
            # 调用告警处理器
            for handler in self._alert_handlers:
                try:
                    handler(alert)
                except Exception as e:
                    logger.error(f"质量告警处理器执行失败: {e}")
    
    def get_alerts(self, 
                  severity: Optional[str] = None,
                  layer: Optional[str] = None,
                  metric_type: Optional[QualityMetricType] = None,
                  since: Optional[float] = None) -> List[QualityAlert]:
        """获取告警"""
        with self._lock:
            alerts = list(self._alerts)
            
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            if layer:
                alerts = [a for a in alerts if a.layer == layer]
            
            if metric_type:
                alerts = [a for a in alerts if a.metric_type == metric_type]
            
            if since:
                alerts = [a for a in alerts if a.timestamp >= since]
            
            return alerts
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """获取告警摘要"""
        with self._lock:
            alerts = list(self._alerts)
            
            summary = {
                "total_alerts": len(alerts),
                "by_severity": defaultdict(int),
                "by_layer": defaultdict(int),
                "by_metric_type": defaultdict(int),
                "recent_alerts": []
            }
            
            for alert in alerts:
                summary["by_severity"][alert.severity] += 1
                summary["by_layer"][alert.layer] += 1
                summary["by_metric_type"][alert.metric_type.value] += 1
            
            # 最近的告警
            recent_time = time.time() - 3600  # 最近1小时
            recent_alerts = [a for a in alerts if a.timestamp >= recent_time]
            summary["recent_alerts"] = [a.to_dict() for a in recent_alerts[-10:]]
            
            return summary


class QualityReportGenerator:
    """质量报告生成器"""
    
    def __init__(self):
        """初始化质量报告生成器"""
        pass
    
    def generate_quality_report(self, 
                               assessments: List[QualityAssessment],
                               trends: List[QualityTrend],
                               alerts: List[QualityAlert],
                               time_range: Tuple[float, float]) -> Dict[str, Any]:
        """生成质量报告"""
        start_time, end_time = time_range
        
        report = {
            "report_id": f"quality_report_{int(time.time())}",
            "generated_at": time.time(),
            "time_range": {
                "start": start_time,
                "end": end_time,
                "duration_hours": (end_time - start_time) / 3600
            },
            "executive_summary": self._generate_executive_summary(assessments, trends, alerts),
            "layer_analysis": self._analyze_by_layer(assessments),
            "metric_analysis": self._analyze_by_metric(assessments),
            "trend_analysis": self._analyze_trends(trends),
            "alert_analysis": self._analyze_alerts(alerts),
            "recommendations": self._generate_recommendations(assessments, trends, alerts)
        }
        
        return report
    
    def _generate_executive_summary(self, assessments: List[QualityAssessment],
                                   trends: List[QualityTrend],
                                   alerts: List[QualityAlert]) -> Dict[str, Any]:
        """生成执行摘要"""
        if not assessments:
            return {
                "overall_quality": "unknown",
                "total_assessments": 0,
                "quality_distribution": {},
                "key_findings": []
            }
        
        # 计算整体质量分布
        quality_distribution = defaultdict(int)
        total_score = 0.0
        
        for assessment in assessments:
            quality_distribution[assessment.quality_level.value] += 1
            total_score += assessment.overall_score
        
        avg_score = total_score / len(assessments)
        
        # 确定整体质量等级
        if avg_score >= 0.90:
            overall_quality = "excellent"
        elif avg_score >= 0.80:
            overall_quality = "good"
        elif avg_score >= 0.65:
            overall_quality = "acceptable"
        elif avg_score >= 0.45:
            overall_quality = "poor"
        else:
            overall_quality = "critical"
        
        # 关键发现
        key_findings = []
        
        # 趋势分析
        improving_trends = [t for t in trends if t.trend_direction == "improving"]
        declining_trends = [t for t in trends if t.trend_direction == "declining"]
        
        if improving_trends:
            key_findings.append(f"发现 {len(improving_trends)} 个改善趋势")
        if declining_trends:
            key_findings.append(f"发现 {len(declining_trends)} 个下降趋势")
        
        # 告警分析
        critical_alerts = [a for a in alerts if a.severity == "critical"]
        if critical_alerts:
            key_findings.append(f"存在 {len(critical_alerts)} 个严重质量告警")
        
        return {
            "overall_quality": overall_quality,
            "average_score": avg_score,
            "total_assessments": len(assessments),
            "quality_distribution": dict(quality_distribution),
            "key_findings": key_findings
        }
    
    def _analyze_by_layer(self, assessments: List[QualityAssessment]) -> Dict[str, Any]:
        """按层分析质量"""
        layer_analysis = {}
        
        # 按层分组
        assessments_by_layer = defaultdict(list)
        for assessment in assessments:
            assessments_by_layer[assessment.layer].append(assessment)
        
        for layer, layer_assessments in assessments_by_layer.items():
            # 计算层级统计
            scores = [a.overall_score for a in layer_assessments]
            quality_levels = [a.quality_level.value for a in layer_assessments]
            
            layer_analysis[layer] = {
                "total_assessments": len(layer_assessments),
                "average_score": statistics.mean(scores),
                "min_score": min(scores),
                "max_score": max(scores),
                "quality_distribution": dict(defaultdict(int, 
                    {level: quality_levels.count(level) for level in set(quality_levels)})),
                "latest_assessment": max(layer_assessments, key=lambda x: x.timestamp).to_dict()
            }
        
        return layer_analysis
    
    def _analyze_by_metric(self, assessments: List[QualityAssessment]) -> Dict[str, Any]:
        """按指标分析质量"""
        metric_analysis = {}
        
        # 收集所有指标值
        all_metrics = defaultdict(list)
        for assessment in assessments:
            for metric_type, value in assessment.metrics.items():
                all_metrics[metric_type].append(value)
        
        for metric_type, values in all_metrics.items():
            if values:
                metric_analysis[metric_type.value] = {
                    "count": len(values),
                    "average": statistics.mean(values),
                    "min": min(values),
                    "max": max(values),
                    "median": statistics.median(values),
                    "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0
                }
        
        return metric_analysis
    
    def _analyze_trends(self, trends: List[QualityTrend]) -> Dict[str, Any]:
        """分析趋势"""
        if not trends:
            return {"total_trends": 0}
        
        trend_analysis = {
            "total_trends": len(trends),
            "by_direction": defaultdict(int),
            "by_layer": defaultdict(int),
            "by_metric_type": defaultdict(int),
            "strongest_trends": []
        }
        
        for trend in trends:
            trend_analysis["by_direction"][trend.trend_direction] += 1
            trend_analysis["by_layer"][trend.layer] += 1
            trend_analysis["by_metric_type"][trend.metric_type.value] += 1
        
        # 找出最强的趋势
        sorted_trends = sorted(trends, key=lambda x: x.trend_strength, reverse=True)
        trend_analysis["strongest_trends"] = [t.to_dict() for t in sorted_trends[:5]]
        
        return trend_analysis
    
    def _analyze_alerts(self, alerts: List[QualityAlert]) -> Dict[str, Any]:
        """分析告警"""
        if not alerts:
            return {"total_alerts": 0}
        
        alert_analysis = {
            "total_alerts": len(alerts),
            "by_severity": defaultdict(int),
            "by_layer": defaultdict(int),
            "by_metric_type": defaultdict(int),
            "recent_alerts": []
        }
        
        for alert in alerts:
            alert_analysis["by_severity"][alert.severity] += 1
            alert_analysis["by_layer"][alert.layer] += 1
            alert_analysis["by_metric_type"][alert.metric_type.value] += 1
        
        # 最近的告警
        recent_alerts = sorted(alerts, key=lambda x: x.timestamp, reverse=True)[:10]
        alert_analysis["recent_alerts"] = [a.to_dict() for a in recent_alerts]
        
        return alert_analysis
    
    def _generate_recommendations(self, assessments: List[QualityAssessment],
                                 trends: List[QualityTrend],
                                 alerts: List[QualityAlert]) -> List[str]:
        """生成改进建议"""
        recommendations = []
        
        # 基于评估结果的建议
        if assessments:
            poor_assessments = [a for a in assessments if a.quality_level in [QualityLevel.POOR, QualityLevel.CRITICAL]]
            if poor_assessments:
                poor_layers = set(a.layer for a in poor_assessments)
                recommendations.append(f"以下层需要重点关注质量改进: {', '.join(poor_layers)}")
        
        # 基于趋势的建议
        declining_trends = [t for t in trends if t.trend_direction == "declining" and t.trend_strength > 0.2]
        if declining_trends:
            declining_layers = set(t.layer for t in declining_trends)
            recommendations.append(f"以下层存在质量下降趋势，需要及时干预: {', '.join(declining_layers)}")
        
        # 基于告警的建议
        critical_alerts = [a for a in alerts if a.severity == "critical"]
        if critical_alerts:
            critical_layers = set(a.layer for a in critical_alerts)
            recommendations.append(f"以下层存在严重质量问题，需要立即处理: {', '.join(critical_layers)}")
        
        # 通用建议
        if not recommendations:
            recommendations.append("系统质量状况良好，建议继续保持当前的质量管理措施")
        
        return recommendations


class QualityMonitor:
    """质量监控器 - 主要质量监控组件"""
    
    def __init__(self, 
                 collection_interval: float = 60.0,
                 analysis_interval: float = 300.0,
                 report_interval: float = 3600.0):
        """初始化质量监控器"""
        self.collection_interval = collection_interval
        self.analysis_interval = analysis_interval
        self.report_interval = report_interval
        
        # 核心组件
        self.metrics_collector = QualityMetricsCollector()
        self.quality_analyzer = QualityAnalyzer()
        self.alert_manager = QualityAlertManager()
        self.report_generator = QualityReportGenerator()
        
        # 状态管理
        self._monitoring_active = False
        self._monitoring_tasks: List[asyncio.Task] = []
        self._quality_assessments: List[QualityAssessment] = []
        self._quality_trends: List[QualityTrend] = []
        self._lock = threading.RLock()
        
        # 注册默认告警处理器
        self.alert_manager.add_alert_handler(self._default_alert_handler)
        
        logger.info("质量监控器初始化完成")
    
    def record_quality_metric(self, metric_type: QualityMetricType, value: float,
                             layer: str, operation: str, metadata: Optional[Dict[str, Any]] = None):
        """记录质量指标"""
        metric = QualityMetric(
            metric_type=metric_type,
            value=value,
            timestamp=time.time(),
            layer=layer,
            operation=operation,
            metadata=metadata or {}
        )
        
        self.metrics_collector.collect_metric(metric)
    
    def record_audit_result(self, layer: str, operation: str,
                           true_positives: int, false_positives: int,
                           true_negatives: int, false_negatives: int,
                           confidence_scores: List[float],
                           response_time: float):
        """记录审计结果并计算质量指标"""
        total = true_positives + false_positives + true_negatives + false_negatives
        
        if total > 0:
            # 计算准确性
            accuracy = (true_positives + true_negatives) / total
            self.record_quality_metric(QualityMetricType.ACCURACY, accuracy, layer, operation)
            
            # 计算精确率
            if true_positives + false_positives > 0:
                precision = true_positives / (true_positives + false_positives)
                self.record_quality_metric(QualityMetricType.PRECISION, precision, layer, operation)
            
            # 计算召回率
            if true_positives + false_negatives > 0:
                recall = true_positives / (true_positives + false_negatives)
                self.record_quality_metric(QualityMetricType.RECALL, recall, layer, operation)
                
                # 计算F1分数
                if precision > 0 and recall > 0:
                    f1_score = 2 * (precision * recall) / (precision + recall)
                    self.record_quality_metric(QualityMetricType.F1_SCORE, f1_score, layer, operation)
            
            # 计算假阳性率
            if false_positives + true_negatives > 0:
                fpr = false_positives / (false_positives + true_negatives)
                self.record_quality_metric(QualityMetricType.FALSE_POSITIVE_RATE, fpr, layer, operation)
            
            # 计算假阴性率
            if false_negatives + true_positives > 0:
                fnr = false_negatives / (false_negatives + true_positives)
                self.record_quality_metric(QualityMetricType.FALSE_NEGATIVE_RATE, fnr, layer, operation)
        
        # 记录置信度
        if confidence_scores:
            avg_confidence = statistics.mean(confidence_scores)
            self.record_quality_metric(QualityMetricType.CONFIDENCE_SCORE, avg_confidence, layer, operation)
        
        # 记录响应时间
        self.record_quality_metric(QualityMetricType.RESPONSE_TIME, response_time, layer, operation)
    
    async def start_monitoring(self):
        """启动质量监控"""
        if self._monitoring_active:
            logger.warning("质量监控已经在运行")
            return
        
        self._monitoring_active = True
        
        # 启动监控任务
        self._monitoring_tasks = [
            asyncio.create_task(self._analysis_loop()),
            asyncio.create_task(self._report_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
        logger.info("质量监控已启动")
    
    async def stop_monitoring(self):
        """停止质量监控"""
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
            logger.error(f"停止质量监控任务时出错: {e}")
        
        self._monitoring_tasks.clear()
        logger.info("质量监控已停止")
    
    async def _analysis_loop(self):
        """质量分析循环"""
        while self._monitoring_active:
            try:
                await asyncio.sleep(self.analysis_interval)
                await self._perform_quality_analysis()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"质量分析循环异常: {e}")
    
    async def _report_loop(self):
        """质量报告循环"""
        while self._monitoring_active:
            try:
                await asyncio.sleep(self.report_interval)
                await self._generate_periodic_report()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"质量报告循环异常: {e}")
    
    async def _cleanup_loop(self):
        """清理循环"""
        while self._monitoring_active:
            try:
                await asyncio.sleep(3600)  # 每小时清理一次
                
                # 清理旧指标
                cleanup_time = time.time() - 7 * 24 * 3600  # 保留7天
                self.metrics_collector.clear_old_metrics(cleanup_time)
                
                # 清理旧评估和趋势
                with self._lock:
                    self._quality_assessments = [
                        a for a in self._quality_assessments if a.timestamp >= cleanup_time
                    ]
                    self._quality_trends = [
                        t for t in self._quality_trends if t.timestamp >= cleanup_time
                    ]
                
                logger.info("质量监控数据清理完成")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"质量监控清理循环异常: {e}")
    
    async def _perform_quality_analysis(self):
        """执行质量分析"""
        current_time = time.time()
        analysis_window = current_time - self.analysis_interval
        
        # 获取最近的指标
        recent_metrics = self.metrics_collector.get_metrics(since=analysis_window)
        
        if not recent_metrics:
            return
        
        # 按层和操作分组进行评估
        grouped_metrics = defaultdict(lambda: defaultdict(list))
        for metric in recent_metrics:
            grouped_metrics[metric.layer][metric.operation].append(metric)
        
        new_assessments = []
        
        for layer, operations in grouped_metrics.items():
            for operation, metrics in operations.items():
                # 执行质量评估
                assessment = self.quality_analyzer.assess_quality(layer, operation, metrics)
                new_assessments.append(assessment)
                
                # 检查告警
                alerts = self.alert_manager.check_quality_alerts(assessment)
                for alert in alerts:
                    self.alert_manager.trigger_alert(alert)
        
        # 保存评估结果
        with self._lock:
            self._quality_assessments.extend(new_assessments)
            # 保留最近1000个评估
            if len(self._quality_assessments) > 1000:
                self._quality_assessments = self._quality_assessments[-1000:]
        
        # 分析趋势
        all_metrics = self.metrics_collector.get_metrics(since=current_time - 3600)  # 最近1小时
        trends = self.quality_analyzer.analyze_trends(all_metrics)
        
        with self._lock:
            self._quality_trends.extend(trends)
            # 保留最近500个趋势
            if len(self._quality_trends) > 500:
                self._quality_trends = self._quality_trends[-500:]
        
        logger.info(f"质量分析完成: {len(new_assessments)} 个评估, {len(trends)} 个趋势")
    
    async def _generate_periodic_report(self):
        """生成定期报告"""
        current_time = time.time()
        report_window = current_time - self.report_interval
        
        # 获取报告期间的数据
        with self._lock:
            recent_assessments = [a for a in self._quality_assessments if a.timestamp >= report_window]
            recent_trends = [t for t in self._quality_trends if t.timestamp >= report_window]
        
        recent_alerts = self.alert_manager.get_alerts(since=report_window)
        
        # 生成报告
        report = self.report_generator.generate_quality_report(
            recent_assessments, recent_trends, recent_alerts, (report_window, current_time)
        )
        
        logger.info(f"生成质量报告: {report['report_id']}")
        
        # 这里可以添加报告保存或发送逻辑
        # 例如：保存到文件、发送邮件、推送到监控系统等
    
    def _default_alert_handler(self, alert: QualityAlert):
        """默认告警处理器"""
        logger.warning(f"质量告警: {alert.message}")
    
    def get_quality_summary(self) -> Dict[str, Any]:
        """获取质量摘要"""
        with self._lock:
            recent_assessments = self._quality_assessments[-10:] if self._quality_assessments else []
            recent_trends = self._quality_trends[-10:] if self._quality_trends else []
        
        recent_alerts = self.alert_manager.get_alerts(since=time.time() - 3600)
        
        if recent_assessments:
            avg_score = statistics.mean([a.overall_score for a in recent_assessments])
            quality_levels = [a.quality_level.value for a in recent_assessments]
            quality_distribution = {level: quality_levels.count(level) for level in set(quality_levels)}
        else:
            avg_score = 0.0
            quality_distribution = {}
        
        return {
            "monitoring_active": self._monitoring_active,
            "average_quality_score": avg_score,
            "quality_distribution": quality_distribution,
            "total_assessments": len(self._quality_assessments),
            "total_trends": len(self._quality_trends),
            "recent_alerts": len(recent_alerts),
            "alert_summary": self.alert_manager.get_alert_summary()
        }
    
    def get_layer_quality(self, layer: str) -> Dict[str, Any]:
        """获取特定层的质量信息"""
        with self._lock:
            layer_assessments = [a for a in self._quality_assessments if a.layer == layer]
            layer_trends = [t for t in self._quality_trends if t.layer == layer]
        
        layer_alerts = self.alert_manager.get_alerts(layer=layer)
        
        if layer_assessments:
            latest_assessment = max(layer_assessments, key=lambda x: x.timestamp)
            avg_score = statistics.mean([a.overall_score for a in layer_assessments])
        else:
            latest_assessment = None
            avg_score = 0.0
        
        return {
            "layer": layer,
            "latest_assessment": latest_assessment.to_dict() if latest_assessment else None,
            "average_score": avg_score,
            "total_assessments": len(layer_assessments),
            "total_trends": len(layer_trends),
            "total_alerts": len(layer_alerts),
            "recent_trends": [t.to_dict() for t in layer_trends[-5:]],
            "recent_alerts": [a.to_dict() for a in layer_alerts[-5:]]
        }


# 使用示例
async def main():
    """质量监控系统使用示例"""
    # 创建质量监控器
    quality_monitor = QualityMonitor(
        collection_interval=60.0,
        analysis_interval=300.0,
        report_interval=3600.0
    )
    
    # 启动质量监控
    await quality_monitor.start_monitoring()
    
    try:
        # 模拟记录一些质量指标
        quality_monitor.record_audit_result(
            layer="haystack",
            operation="syntax_check",
            true_positives=85,
            false_positives=5,
            true_negatives=90,
            false_negatives=10,
            confidence_scores=[0.85, 0.92, 0.78, 0.88, 0.91],
            response_time=2.5
        )
        
        quality_monitor.record_audit_result(
            layer="txtai",
            operation="knowledge_retrieval",
            true_positives=78,
            false_positives=12,
            true_negatives=88,
            false_negatives=8,
            confidence_scores=[0.82, 0.89, 0.75, 0.91, 0.86],
            response_time=3.2
        )
        
        # 等待一段时间让监控运行
        await asyncio.sleep(10)
        
        # 获取质量摘要
        summary = quality_monitor.get_quality_summary()
        print(f"质量摘要: {json.dumps(summary, indent=2, ensure_ascii=False)}")
        
        # 获取特定层的质量信息
        haystack_quality = quality_monitor.get_layer_quality("haystack")
        print(f"Haystack层质量: {json.dumps(haystack_quality, indent=2, ensure_ascii=False)}")
        
    finally:
        # 停止质量监控
        await quality_monitor.stop_monitoring()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())