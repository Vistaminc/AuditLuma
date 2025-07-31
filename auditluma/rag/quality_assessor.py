"""
质量评估器 - Self-RAG验证层组件

本模块实现了结果质量的多维度评估，用于评估验证结果的整体质量。
包括：
- 多维度质量评估
- 质量报告和改进建议生成
- 质量趋势分析
- 基准对比和评分
"""

import asyncio
import statistics
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import time
from datetime import datetime, timedelta
import json
import math

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import VulnerabilityResult
from auditluma.models.hierarchical_rag import (
    EnhancedContext, VulnerabilityKnowledge, ConfidenceScore,
    ValidationSummary, ValidatedResults
)
from auditluma.rag.cross_validator import CrossValidationResult
from auditluma.rag.false_positive_filter import FilterResult


class QualityDimension(str, Enum):
    """质量维度枚举"""
    ACCURACY = "accuracy"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    CONFIDENCE_CALIBRATION = "confidence_calibration"
    CONSISTENCY = "consistency"
    COMPLETENESS = "completeness"
    TIMELINESS = "timeliness"
    ROBUSTNESS = "robustness"


class QualityLevel(str, Enum):
    """质量等级枚举"""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


@dataclass
class QualityMetric:
    """质量指标"""
    dimension: QualityDimension
    score: float
    weight: float
    level: QualityLevel
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    benchmark_comparison: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'dimension': self.dimension.value,
            'score': self.score,
            'weight': self.weight,
            'level': self.level.value,
            'explanation': self.explanation,
            'evidence': self.evidence,
            'benchmark_comparison': self.benchmark_comparison
        }


@dataclass
class QualityAssessment:
    """质量评估结果"""
    overall_score: float
    overall_level: QualityLevel
    metrics: List[QualityMetric]
    assessment_time: float
    recommendations: List[str] = field(default_factory=list)
    trend_analysis: Dict[str, Any] = field(default_factory=dict)
    benchmark_scores: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'overall_score': self.overall_score,
            'overall_level': self.overall_level.value,
            'metrics': [metric.to_dict() for metric in self.metrics],
            'assessment_time': self.assessment_time,
            'recommendations': self.recommendations,
            'trend_analysis': self.trend_analysis,
            'benchmark_scores': self.benchmark_scores,
            'metadata': self.metadata
        }


@dataclass
class QualityBenchmark:
    """质量基准"""
    name: str
    dimension: QualityDimension
    target_score: float
    minimum_score: float
    description: str
    created_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'name': self.name,
            'dimension': self.dimension.value,
            'target_score': self.target_score,
            'minimum_score': self.minimum_score,
            'description': self.description,
            'created_at': self.created_at.isoformat()
        }


class QualityTrendAnalyzer:
    """质量趋势分析器"""
    
    def __init__(self, history_window_days: int = 30):
        """初始化趋势分析器"""
        self.history_window_days = history_window_days
        self.quality_history: List[Tuple[datetime, QualityAssessment]] = []
    
    def add_assessment(self, assessment: QualityAssessment):
        """添加质量评估记录"""
        self.quality_history.append((datetime.now(), assessment))
        
        # 清理过期记录
        cutoff_date = datetime.now() - timedelta(days=self.history_window_days)
        self.quality_history = [
            (timestamp, assessment) for timestamp, assessment in self.quality_history
            if timestamp > cutoff_date
        ]
    
    def analyze_trends(self) -> Dict[str, Any]:
        """分析质量趋势"""
        if len(self.quality_history) < 2:
            return {'trend': 'insufficient_data', 'message': '数据不足以进行趋势分析'}
        
        # 按时间排序
        sorted_history = sorted(self.quality_history, key=lambda x: x[0])
        
        # 提取时间序列数据
        timestamps = [timestamp for timestamp, _ in sorted_history]
        overall_scores = [assessment.overall_score for _, assessment in sorted_history]
        
        # 计算趋势
        trend_analysis = {
            'data_points': len(sorted_history),
            'time_span_days': (timestamps[-1] - timestamps[0]).days,
            'current_score': overall_scores[-1],
            'previous_score': overall_scores[-2] if len(overall_scores) > 1 else overall_scores[0],
            'score_change': overall_scores[-1] - overall_scores[-2] if len(overall_scores) > 1 else 0.0,
            'average_score': statistics.mean(overall_scores),
            'score_volatility': statistics.stdev(overall_scores) if len(overall_scores) > 1 else 0.0
        }
        
        # 计算线性趋势
        if len(overall_scores) >= 3:
            # 简单线性回归
            n = len(overall_scores)
            x_values = list(range(n))
            
            sum_x = sum(x_values)
            sum_y = sum(overall_scores)
            sum_xy = sum(x * y for x, y in zip(x_values, overall_scores))
            sum_x2 = sum(x * x for x in x_values)
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            intercept = (sum_y - slope * sum_x) / n
            
            trend_analysis['linear_trend'] = {
                'slope': slope,
                'intercept': intercept,
                'direction': 'improving' if slope > 0.01 else 'declining' if slope < -0.01 else 'stable'
            }
        
        # 分析各维度趋势
        dimension_trends = {}
        for dimension in QualityDimension:
            dimension_scores = []
            for _, assessment in sorted_history:
                for metric in assessment.metrics:
                    if metric.dimension == dimension:
                        dimension_scores.append(metric.score)
                        break
            
            if dimension_scores:
                dimension_trends[dimension.value] = {
                    'current': dimension_scores[-1],
                    'average': statistics.mean(dimension_scores),
                    'change': dimension_scores[-1] - dimension_scores[0] if len(dimension_scores) > 1 else 0.0,
                    'volatility': statistics.stdev(dimension_scores) if len(dimension_scores) > 1 else 0.0
                }
        
        trend_analysis['dimension_trends'] = dimension_trends
        
        return trend_analysis
    
    def get_quality_forecast(self, days_ahead: int = 7) -> Dict[str, Any]:
        """预测未来质量趋势"""
        trend_analysis = self.analyze_trends()
        
        if 'linear_trend' not in trend_analysis:
            return {'forecast': 'unavailable', 'message': '数据不足以进行预测'}
        
        slope = trend_analysis['linear_trend']['slope']
        current_score = trend_analysis['current_score']
        
        # 简单线性预测
        predicted_score = current_score + slope * days_ahead
        predicted_score = max(0.0, min(1.0, predicted_score))  # 限制在0-1范围内
        
        confidence = max(0.1, 1.0 - trend_analysis['score_volatility'])  # 波动性越大，预测置信度越低
        
        return {
            'predicted_score': predicted_score,
            'prediction_confidence': confidence,
            'days_ahead': days_ahead,
            'trend_direction': trend_analysis['linear_trend']['direction'],
            'current_score': current_score
        }


class QualityAssessor:
    """质量评估器 - 实现结果质量的多维度评估"""
    
    def __init__(self):
        """初始化质量评估器"""
        # 质量维度权重配置
        self.dimension_weights = {
            QualityDimension.ACCURACY: 0.25,
            QualityDimension.PRECISION: 0.20,
            QualityDimension.RECALL: 0.15,
            QualityDimension.F1_SCORE: 0.10,
            QualityDimension.CONFIDENCE_CALIBRATION: 0.10,
            QualityDimension.CONSISTENCY: 0.08,
            QualityDimension.COMPLETENESS: 0.07,
            QualityDimension.TIMELINESS: 0.03,
            QualityDimension.ROBUSTNESS: 0.02
        }
        
        # 从配置加载权重
        self._load_weights_from_config()
        
        # 质量等级阈值
        self.quality_thresholds = {
            QualityLevel.EXCELLENT: 0.9,
            QualityLevel.GOOD: 0.75,
            QualityLevel.FAIR: 0.6,
            QualityLevel.POOR: 0.4,
            QualityLevel.CRITICAL: 0.0
        }
        
        # 基准管理
        self.benchmarks: Dict[QualityDimension, QualityBenchmark] = {}
        self._initialize_benchmarks()
        
        # 趋势分析器
        self.trend_analyzer = QualityTrendAnalyzer()
        
        # 性能统计
        self.stats = {
            'assessments_performed': 0,
            'average_overall_score': 0.0,
            'dimension_averages': {dim.value: 0.0 for dim in QualityDimension},
            'quality_level_distribution': {level.value: 0 for level in QualityLevel},
            'average_assessment_time': 0.0
        }
        
        logger.info(f"质量评估器初始化完成")
        logger.info(f"维度权重: {self.dimension_weights}")
    
    def _load_weights_from_config(self):
        """从配置加载权重"""
        hierarchical_config = getattr(Config, 'hierarchical_rag', None)
        weight_config = {}
        
        # 如果有层级RAG配置，尝试获取质量评估配置
        if hierarchical_config and hasattr(hierarchical_config, 'self_rag_validation'):
            # 这里可以扩展为从配置中读取权重配置
            # 目前使用默认配置
            pass
        
        # 更新权重
        for dimension in QualityDimension:
            if dimension.value in weight_config:
                self.dimension_weights[dimension] = weight_config[dimension.value]
        
        # 归一化权重
        total_weight = sum(self.dimension_weights.values())
        if total_weight > 0:
            for dimension in self.dimension_weights:
                self.dimension_weights[dimension] /= total_weight
    
    def _initialize_benchmarks(self):
        """初始化质量基准"""
        default_benchmarks = [
            QualityBenchmark(
                name="accuracy_benchmark",
                dimension=QualityDimension.ACCURACY,
                target_score=0.95,
                minimum_score=0.85,
                description="准确性基准：目标95%，最低85%",
                created_at=datetime.now()
            ),
            QualityBenchmark(
                name="precision_benchmark",
                dimension=QualityDimension.PRECISION,
                target_score=0.90,
                minimum_score=0.80,
                description="精确率基准：目标90%，最低80%",
                created_at=datetime.now()
            ),
            QualityBenchmark(
                name="recall_benchmark",
                dimension=QualityDimension.RECALL,
                target_score=0.85,
                minimum_score=0.75,
                description="召回率基准：目标85%，最低75%",
                created_at=datetime.now()
            ),
            QualityBenchmark(
                name="consistency_benchmark",
                dimension=QualityDimension.CONSISTENCY,
                target_score=0.88,
                minimum_score=0.75,
                description="一致性基准：目标88%，最低75%",
                created_at=datetime.now()
            )
        ]
        
        for benchmark in default_benchmarks:
            self.benchmarks[benchmark.dimension] = benchmark
    
    async def assess_quality(self, 
                           validated_results: ValidatedResults,
                           cross_validation_results: Optional[List[CrossValidationResult]] = None,
                           filter_results: Optional[List[FilterResult]] = None,
                           ground_truth: Optional[List[bool]] = None) -> QualityAssessment:
        """评估验证结果的质量"""
        start_time = time.time()
        
        try:
            logger.debug(f"开始质量评估，验证结果数: {len(validated_results.validated_vulnerabilities)}")
            
            # 并行计算各维度质量指标
            metric_tasks = [
                self._assess_accuracy(validated_results, ground_truth),
                self._assess_precision(validated_results, ground_truth),
                self._assess_recall(validated_results, ground_truth),
                self._assess_f1_score(validated_results, ground_truth),
                self._assess_confidence_calibration(validated_results, ground_truth),
                self._assess_consistency(validated_results, cross_validation_results),
                self._assess_completeness(validated_results),
                self._assess_timeliness(validated_results),
                self._assess_robustness(validated_results, filter_results)
            ]
            
            metrics = await asyncio.gather(*metric_tasks, return_exceptions=True)
            
            # 处理异常结果
            valid_metrics = []
            for i, metric in enumerate(metrics):
                if isinstance(metric, QualityMetric):
                    valid_metrics.append(metric)
                else:
                    logger.warning(f"质量指标计算异常: {list(QualityDimension)[i]}, {metric}")
                    # 创建默认指标
                    valid_metrics.append(QualityMetric(
                        dimension=list(QualityDimension)[i],
                        score=0.5,
                        weight=self.dimension_weights.get(list(QualityDimension)[i], 0.1),
                        level=QualityLevel.FAIR,
                        explanation=f"计算异常: {str(metric)}"
                    ))
            
            # 计算总体质量分数
            overall_score = self._calculate_overall_score(valid_metrics)
            overall_level = self._determine_quality_level(overall_score)
            
            # 生成改进建议
            recommendations = self._generate_recommendations(valid_metrics, overall_score)
            
            # 进行趋势分析
            trend_analysis = self.trend_analyzer.analyze_trends()
            
            # 基准对比
            benchmark_scores = self._compare_with_benchmarks(valid_metrics)
            
            assessment_time = time.time() - start_time
            
            # 创建质量评估结果
            assessment = QualityAssessment(
                overall_score=overall_score,
                overall_level=overall_level,
                metrics=valid_metrics,
                assessment_time=assessment_time,
                recommendations=recommendations,
                trend_analysis=trend_analysis,
                benchmark_scores=benchmark_scores,
                metadata={
                    'validated_vulnerabilities_count': len(validated_results.validated_vulnerabilities),
                    'cross_validation_available': cross_validation_results is not None,
                    'filter_results_available': filter_results is not None,
                    'ground_truth_available': ground_truth is not None
                }
            )
            
            # 更新统计信息和趋势
            self._update_stats(assessment)
            self.trend_analyzer.add_assessment(assessment)
            
            logger.debug(f"质量评估完成，总体分数: {overall_score:.3f}, 等级: {overall_level.value}")
            
            return assessment
            
        except Exception as e:
            assessment_time = time.time() - start_time
            logger.error(f"质量评估失败: {e}")
            
            # 返回默认评估结果
            return QualityAssessment(
                overall_score=0.5,
                overall_level=QualityLevel.FAIR,
                metrics=[],
                assessment_time=assessment_time,
                recommendations=[f"质量评估失败: {str(e)}"],
                metadata={'error': str(e)}
            )
    
    async def _assess_accuracy(self, 
                             validated_results: ValidatedResults,
                             ground_truth: Optional[List[bool]]) -> QualityMetric:
        """评估准确性"""
        if not ground_truth:
            # 没有真实标签时，使用置信度作为代理指标
            confidences = [
                vv.confidence_score.overall_score 
                for vv in validated_results.validated_vulnerabilities
            ]
            
            if confidences:
                avg_confidence = statistics.mean(confidences)
                score = avg_confidence
                explanation = f"基于平均置信度的准确性估计: {avg_confidence:.3f}"
                evidence = {
                    'method': 'confidence_proxy',
                    'average_confidence': avg_confidence,
                    'confidence_std': statistics.stdev(confidences) if len(confidences) > 1 else 0.0
                }
            else:
                score = 0.5
                explanation = "无数据可用于准确性评估"
                evidence = {'method': 'no_data'}
        else:
            # 有真实标签时，计算实际准确性
            predictions = [
                vv.validation_status.value == 'validated'
                for vv in validated_results.validated_vulnerabilities
            ]
            
            if len(predictions) == len(ground_truth):
                correct_predictions = sum(1 for p, gt in zip(predictions, ground_truth) if p == gt)
                score = correct_predictions / len(ground_truth)
                explanation = f"准确性: {correct_predictions}/{len(ground_truth)} = {score:.3f}"
                evidence = {
                    'method': 'ground_truth',
                    'correct_predictions': correct_predictions,
                    'total_predictions': len(ground_truth),
                    'accuracy': score
                }
            else:
                score = 0.5
                explanation = "预测数量与真实标签数量不匹配"
                evidence = {
                    'method': 'mismatch',
                    'predictions_count': len(predictions),
                    'ground_truth_count': len(ground_truth)
                }
        
        level = self._determine_quality_level(score)
        
        return QualityMetric(
            dimension=QualityDimension.ACCURACY,
            score=score,
            weight=self.dimension_weights[QualityDimension.ACCURACY],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_precision(self, 
                              validated_results: ValidatedResults,
                              ground_truth: Optional[List[bool]]) -> QualityMetric:
        """评估精确率"""
        if not ground_truth:
            # 使用假阳性过滤率作为精确率的代理指标
            total_vulnerabilities = len(validated_results.validated_vulnerabilities)
            filtered_count = validated_results.filtered_count
            
            if total_vulnerabilities > 0:
                precision_proxy = 1.0 - (filtered_count / (total_vulnerabilities + filtered_count))
                score = precision_proxy
                explanation = f"基于假阳性过滤的精确率估计: {precision_proxy:.3f}"
                evidence = {
                    'method': 'false_positive_proxy',
                    'total_vulnerabilities': total_vulnerabilities,
                    'filtered_count': filtered_count,
                    'precision_proxy': precision_proxy
                }
            else:
                score = 0.5
                explanation = "无数据可用于精确率评估"
                evidence = {'method': 'no_data'}
        else:
            # 计算实际精确率
            predictions = [
                vv.validation_status.value == 'validated'
                for vv in validated_results.validated_vulnerabilities
            ]
            
            if len(predictions) == len(ground_truth):
                true_positives = sum(1 for p, gt in zip(predictions, ground_truth) if p and gt)
                predicted_positives = sum(predictions)
                
                if predicted_positives > 0:
                    score = true_positives / predicted_positives
                    explanation = f"精确率: {true_positives}/{predicted_positives} = {score:.3f}"
                    evidence = {
                        'method': 'ground_truth',
                        'true_positives': true_positives,
                        'predicted_positives': predicted_positives,
                        'precision': score
                    }
                else:
                    score = 1.0  # 没有正预测时，精确率为1
                    explanation = "没有正预测，精确率为1.0"
                    evidence = {'method': 'no_positive_predictions'}
            else:
                score = 0.5
                explanation = "预测数量与真实标签数量不匹配"
                evidence = {'method': 'mismatch'}
        
        level = self._determine_quality_level(score)
        
        return QualityMetric(
            dimension=QualityDimension.PRECISION,
            score=score,
            weight=self.dimension_weights[QualityDimension.PRECISION],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_recall(self, 
                           validated_results: ValidatedResults,
                           ground_truth: Optional[List[bool]]) -> QualityMetric:
        """评估召回率"""
        if not ground_truth:
            # 使用验证通过率作为召回率的代理指标
            total_vulnerabilities = len(validated_results.validated_vulnerabilities)
            validated_count = validated_results.validation_summary.validated_count
            
            if total_vulnerabilities > 0:
                recall_proxy = validated_count / total_vulnerabilities
                score = recall_proxy
                explanation = f"基于验证通过率的召回率估计: {recall_proxy:.3f}"
                evidence = {
                    'method': 'validation_rate_proxy',
                    'validated_count': validated_count,
                    'total_vulnerabilities': total_vulnerabilities,
                    'recall_proxy': recall_proxy
                }
            else:
                score = 0.5
                explanation = "无数据可用于召回率评估"
                evidence = {'method': 'no_data'}
        else:
            # 计算实际召回率
            predictions = [
                vv.validation_status.value == 'validated'
                for vv in validated_results.validated_vulnerabilities
            ]
            
            if len(predictions) == len(ground_truth):
                true_positives = sum(1 for p, gt in zip(predictions, ground_truth) if p and gt)
                actual_positives = sum(ground_truth)
                
                if actual_positives > 0:
                    score = true_positives / actual_positives
                    explanation = f"召回率: {true_positives}/{actual_positives} = {score:.3f}"
                    evidence = {
                        'method': 'ground_truth',
                        'true_positives': true_positives,
                        'actual_positives': actual_positives,
                        'recall': score
                    }
                else:
                    score = 1.0  # 没有实际正例时，召回率为1
                    explanation = "没有实际正例，召回率为1.0"
                    evidence = {'method': 'no_actual_positives'}
            else:
                score = 0.5
                explanation = "预测数量与真实标签数量不匹配"
                evidence = {'method': 'mismatch'}
        
        level = self._determine_quality_level(score)
        
        return QualityMetric(
            dimension=QualityDimension.RECALL,
            score=score,
            weight=self.dimension_weights[QualityDimension.RECALL],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_f1_score(self, 
                             validated_results: ValidatedResults,
                             ground_truth: Optional[List[bool]]) -> QualityMetric:
        """评估F1分数"""
        # 获取精确率和召回率
        precision_metric = await self._assess_precision(validated_results, ground_truth)
        recall_metric = await self._assess_recall(validated_results, ground_truth)
        
        precision = precision_metric.score
        recall = recall_metric.score
        
        # 计算F1分数
        if precision + recall > 0:
            f1_score = 2 * (precision * recall) / (precision + recall)
        else:
            f1_score = 0.0
        
        explanation = f"F1分数: 2*({precision:.3f}*{recall:.3f})/({precision:.3f}+{recall:.3f}) = {f1_score:.3f}"
        evidence = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'precision_method': precision_metric.evidence.get('method', 'unknown'),
            'recall_method': recall_metric.evidence.get('method', 'unknown')
        }
        
        level = self._determine_quality_level(f1_score)
        
        return QualityMetric(
            dimension=QualityDimension.F1_SCORE,
            score=f1_score,
            weight=self.dimension_weights[QualityDimension.F1_SCORE],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_confidence_calibration(self, 
                                           validated_results: ValidatedResults,
                                           ground_truth: Optional[List[bool]]) -> QualityMetric:
        """评估置信度校准"""
        confidences = [
            vv.confidence_score.overall_score 
            for vv in validated_results.validated_vulnerabilities
        ]
        
        if not confidences:
            return QualityMetric(
                dimension=QualityDimension.CONFIDENCE_CALIBRATION,
                score=0.5,
                weight=self.dimension_weights[QualityDimension.CONFIDENCE_CALIBRATION],
                level=QualityLevel.FAIR,
                explanation="无置信度数据可用于校准评估",
                evidence={'method': 'no_data'}
            )
        
        if not ground_truth or len(confidences) != len(ground_truth):
            # 没有真实标签时，评估置信度分布的合理性
            avg_confidence = statistics.mean(confidences)
            confidence_std = statistics.stdev(confidences) if len(confidences) > 1 else 0.0
            
            # 理想的置信度分布应该有适度的方差（不全是高置信度或低置信度）
            ideal_std = 0.2  # 理想标准差
            std_score = 1.0 - abs(confidence_std - ideal_std) / ideal_std
            std_score = max(0.0, min(1.0, std_score))
            
            # 平均置信度应该在合理范围内
            avg_score = 1.0 - abs(avg_confidence - 0.7) / 0.3  # 理想平均置信度0.7
            avg_score = max(0.0, min(1.0, avg_score))
            
            score = (std_score + avg_score) / 2
            explanation = f"置信度分布评估: 平均{avg_confidence:.3f}, 标准差{confidence_std:.3f}"
            evidence = {
                'method': 'distribution_analysis',
                'average_confidence': avg_confidence,
                'confidence_std': confidence_std,
                'std_score': std_score,
                'avg_score': avg_score
            }
        else:
            # 有真实标签时，计算校准误差
            predictions = [
                vv.validation_status.value == 'validated'
                for vv in validated_results.validated_vulnerabilities
            ]
            
            # 计算Brier分数（校准误差的一种度量）
            brier_score = sum(
                (conf - (1.0 if gt else 0.0)) ** 2
                for conf, gt in zip(confidences, ground_truth)
            ) / len(confidences)
            
            # 将Brier分数转换为质量分数（Brier分数越小越好）
            score = 1.0 - brier_score
            score = max(0.0, min(1.0, score))
            
            explanation = f"置信度校准(Brier分数): {brier_score:.3f}, 校准质量: {score:.3f}"
            evidence = {
                'method': 'brier_score',
                'brier_score': brier_score,
                'calibration_score': score,
                'confidence_count': len(confidences)
            }
        
        level = self._determine_quality_level(score)
        
        return QualityMetric(
            dimension=QualityDimension.CONFIDENCE_CALIBRATION,
            score=score,
            weight=self.dimension_weights[QualityDimension.CONFIDENCE_CALIBRATION],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_consistency(self, 
                                validated_results: ValidatedResults,
                                cross_validation_results: Optional[List[CrossValidationResult]]) -> QualityMetric:
        """评估一致性"""
        if not cross_validation_results:
            # 没有交叉验证结果时，评估置信度的一致性
            confidences = [
                vv.confidence_score.overall_score 
                for vv in validated_results.validated_vulnerabilities
            ]
            
            if len(confidences) > 1:
                confidence_std = statistics.stdev(confidences)
                # 标准差越小，一致性越好
                score = max(0.0, 1.0 - confidence_std * 2)  # 标准差0.5对应分数0
                explanation = f"置信度一致性: 标准差{confidence_std:.3f}, 一致性分数{score:.3f}"
                evidence = {
                    'method': 'confidence_consistency',
                    'confidence_std': confidence_std,
                    'confidence_count': len(confidences)
                }
            else:
                score = 1.0
                explanation = "单个结果，一致性为1.0"
                evidence = {'method': 'single_result'}
        else:
            # 有交叉验证结果时，评估模型间一致性
            consensus_scores = [result.consensus_score for result in cross_validation_results]
            consensus_reached_count = sum(1 for result in cross_validation_results if result.is_consensus_reached)
            
            if consensus_scores:
                avg_consensus = statistics.mean(consensus_scores)
                consensus_rate = consensus_reached_count / len(cross_validation_results)
                
                # 综合考虑平均共识分数和共识达成率
                score = (avg_consensus + consensus_rate) / 2
                explanation = f"交叉验证一致性: 平均共识{avg_consensus:.3f}, 共识率{consensus_rate:.3f}"
                evidence = {
                    'method': 'cross_validation',
                    'average_consensus': avg_consensus,
                    'consensus_rate': consensus_rate,
                    'consensus_reached_count': consensus_reached_count,
                    'total_validations': len(cross_validation_results)
                }
            else:
                score = 0.5
                explanation = "无交叉验证数据"
                evidence = {'method': 'no_cross_validation_data'}
        
        level = self._determine_quality_level(score)
        
        return QualityMetric(
            dimension=QualityDimension.CONSISTENCY,
            score=score,
            weight=self.dimension_weights[QualityDimension.CONSISTENCY],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_completeness(self, validated_results: ValidatedResults) -> QualityMetric:
        """评估完整性"""
        total_vulnerabilities = len(validated_results.validated_vulnerabilities)
        
        if total_vulnerabilities == 0:
            return QualityMetric(
                dimension=QualityDimension.COMPLETENESS,
                score=0.0,
                weight=self.dimension_weights[QualityDimension.COMPLETENESS],
                level=QualityLevel.CRITICAL,
                explanation="没有漏洞结果",
                evidence={'method': 'no_results'}
            )
        
        # 评估各个组件的完整性
        completeness_factors = []
        
        # 1. 置信度信息完整性
        confidence_complete_count = sum(
            1 for vv in validated_results.validated_vulnerabilities
            if vv.confidence_score and vv.confidence_score.overall_score > 0
        )
        confidence_completeness = confidence_complete_count / total_vulnerabilities
        completeness_factors.append(('confidence', confidence_completeness))
        
        # 2. 知识信息完整性
        knowledge_complete_count = sum(
            1 for vv in validated_results.validated_vulnerabilities
            if vv.knowledge and (vv.knowledge.cve_info or vv.knowledge.best_practices or vv.knowledge.historical_cases)
        )
        knowledge_completeness = knowledge_complete_count / total_vulnerabilities
        completeness_factors.append(('knowledge', knowledge_completeness))
        
        # 3. 增强上下文完整性
        context_complete_count = sum(
            1 for vv in validated_results.validated_vulnerabilities
            if vv.enhanced_context and vv.enhanced_context.completeness_score > 0.5
        )
        context_completeness = context_complete_count / total_vulnerabilities
        completeness_factors.append(('context', context_completeness))
        
        # 4. 验证状态完整性
        status_complete_count = sum(
            1 for vv in validated_results.validated_vulnerabilities
            if vv.validation_status and vv.validation_status.value != 'pending'
        )
        status_completeness = status_complete_count / total_vulnerabilities
        completeness_factors.append(('status', status_completeness))
        
        # 计算加权平均完整性
        weights = {'confidence': 0.3, 'knowledge': 0.25, 'context': 0.25, 'status': 0.2}
        weighted_completeness = sum(
            completeness * weights[factor_name]
            for factor_name, completeness in completeness_factors
        )
        
        score = weighted_completeness
        explanation = f"完整性评估: 置信度{confidence_completeness:.2f}, 知识{knowledge_completeness:.2f}, 上下文{context_completeness:.2f}, 状态{status_completeness:.2f}"
        evidence = {
            'method': 'component_completeness',
            'total_vulnerabilities': total_vulnerabilities,
            'confidence_completeness': confidence_completeness,
            'knowledge_completeness': knowledge_completeness,
            'context_completeness': context_completeness,
            'status_completeness': status_completeness,
            'weighted_completeness': weighted_completeness
        }
        
        level = self._determine_quality_level(score)
        
        return QualityMetric(
            dimension=QualityDimension.COMPLETENESS,
            score=score,
            weight=self.dimension_weights[QualityDimension.COMPLETENESS],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_timeliness(self, validated_results: ValidatedResults) -> QualityMetric:
        """评估及时性"""
        validation_time = validated_results.validation_summary.validation_time
        
        # 定义时间阈值（秒）
        excellent_threshold = 5.0
        good_threshold = 15.0
        fair_threshold = 30.0
        poor_threshold = 60.0
        
        if validation_time <= excellent_threshold:
            score = 1.0
            level = QualityLevel.EXCELLENT
        elif validation_time <= good_threshold:
            score = 0.8 + 0.2 * (good_threshold - validation_time) / (good_threshold - excellent_threshold)
            level = QualityLevel.GOOD
        elif validation_time <= fair_threshold:
            score = 0.6 + 0.2 * (fair_threshold - validation_time) / (fair_threshold - good_threshold)
            level = QualityLevel.FAIR
        elif validation_time <= poor_threshold:
            score = 0.4 + 0.2 * (poor_threshold - validation_time) / (poor_threshold - fair_threshold)
            level = QualityLevel.POOR
        else:
            score = max(0.0, 0.4 - (validation_time - poor_threshold) / poor_threshold)
            level = QualityLevel.CRITICAL
        
        explanation = f"验证时间: {validation_time:.2f}秒, 及时性分数: {score:.3f}"
        evidence = {
            'validation_time': validation_time,
            'excellent_threshold': excellent_threshold,
            'good_threshold': good_threshold,
            'fair_threshold': fair_threshold,
            'poor_threshold': poor_threshold
        }
        
        return QualityMetric(
            dimension=QualityDimension.TIMELINESS,
            score=score,
            weight=self.dimension_weights[QualityDimension.TIMELINESS],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    async def _assess_robustness(self, 
                               validated_results: ValidatedResults,
                               filter_results: Optional[List[FilterResult]]) -> QualityMetric:
        """评估鲁棒性"""
        total_vulnerabilities = len(validated_results.validated_vulnerabilities)
        
        if total_vulnerabilities == 0:
            return QualityMetric(
                dimension=QualityDimension.ROBUSTNESS,
                score=0.0,
                weight=self.dimension_weights[QualityDimension.ROBUSTNESS],
                level=QualityLevel.CRITICAL,
                explanation="没有漏洞结果用于鲁棒性评估",
                evidence={'method': 'no_results'}
            )
        
        robustness_factors = []
        
        # 1. 错误处理能力
        error_count = sum(
            1 for vv in validated_results.validated_vulnerabilities
            if 'error' in vv.validation_notes.lower() or 'exception' in vv.validation_notes.lower()
        )
        error_rate = error_count / total_vulnerabilities
        error_robustness = 1.0 - error_rate
        robustness_factors.append(('error_handling', error_robustness))
        
        # 2. 假阳性处理能力
        if filter_results:
            false_positive_count = sum(1 for fr in filter_results if fr.is_false_positive)
            false_positive_rate = false_positive_count / len(filter_results)
            # 适度的假阳性过滤率表明良好的鲁棒性
            optimal_fp_rate = 0.1  # 理想的假阳性率
            fp_robustness = 1.0 - abs(false_positive_rate - optimal_fp_rate) / optimal_fp_rate
            fp_robustness = max(0.0, min(1.0, fp_robustness))
            robustness_factors.append(('false_positive_handling', fp_robustness))
        else:
            robustness_factors.append(('false_positive_handling', 0.5))
        
        # 3. 置信度分布的稳定性
        confidences = [
            vv.confidence_score.overall_score 
            for vv in validated_results.validated_vulnerabilities
            if vv.confidence_score
        ]
        
        if len(confidences) > 1:
            confidence_std = statistics.stdev(confidences)
            # 适度的标准差表明稳定性
            optimal_std = 0.15
            confidence_robustness = 1.0 - abs(confidence_std - optimal_std) / optimal_std
            confidence_robustness = max(0.0, min(1.0, confidence_robustness))
            robustness_factors.append(('confidence_stability', confidence_robustness))
        else:
            robustness_factors.append(('confidence_stability', 0.5))
        
        # 计算加权平均鲁棒性
        weights = {'error_handling': 0.4, 'false_positive_handling': 0.35, 'confidence_stability': 0.25}
        weighted_robustness = sum(
            robustness * weights[factor_name]
            for factor_name, robustness in robustness_factors
        )
        
        score = weighted_robustness
        explanation = f"鲁棒性评估: 错误处理{robustness_factors[0][1]:.2f}, 假阳性处理{robustness_factors[1][1]:.2f}, 置信度稳定性{robustness_factors[2][1]:.2f}"
        evidence = {
            'method': 'multi_factor_robustness',
            'error_count': error_count,
            'error_rate': error_rate,
            'total_vulnerabilities': total_vulnerabilities,
            'robustness_factors': dict(robustness_factors),
            'weighted_robustness': weighted_robustness
        }
        
        if filter_results:
            evidence['false_positive_count'] = sum(1 for fr in filter_results if fr.is_false_positive)
            evidence['filter_results_count'] = len(filter_results)
        
        level = self._determine_quality_level(score)
        
        return QualityMetric(
            dimension=QualityDimension.ROBUSTNESS,
            score=score,
            weight=self.dimension_weights[QualityDimension.ROBUSTNESS],
            level=level,
            explanation=explanation,
            evidence=evidence
        )
    
    def _calculate_overall_score(self, metrics: List[QualityMetric]) -> float:
        """计算总体质量分数"""
        if not metrics:
            return 0.0
        
        weighted_sum = sum(metric.score * metric.weight for metric in metrics)
        total_weight = sum(metric.weight for metric in metrics)
        
        if total_weight == 0:
            return 0.0
        
        return weighted_sum / total_weight
    
    def _determine_quality_level(self, score: float) -> QualityLevel:
        """确定质量等级"""
        for level, threshold in sorted(self.quality_thresholds.items(), 
                                     key=lambda x: x[1], reverse=True):
            if score >= threshold:
                return level
        return QualityLevel.CRITICAL
    
    def _generate_recommendations(self, metrics: List[QualityMetric], overall_score: float) -> List[str]:
        """生成改进建议"""
        recommendations = []
        
        # 基于总体分数的建议
        if overall_score < 0.6:
            recommendations.append("总体质量较低，建议全面检查验证流程")
        elif overall_score < 0.8:
            recommendations.append("质量有待提升，重点关注低分维度")
        
        # 基于各维度的具体建议
        for metric in metrics:
            if metric.score < 0.6:
                if metric.dimension == QualityDimension.ACCURACY:
                    recommendations.append("准确性较低，建议优化模型或增加训练数据")
                elif metric.dimension == QualityDimension.PRECISION:
                    recommendations.append("精确率较低，建议加强假阳性过滤")
                elif metric.dimension == QualityDimension.RECALL:
                    recommendations.append("召回率较低，建议降低检测阈值或增加检测规则")
                elif metric.dimension == QualityDimension.CONSISTENCY:
                    recommendations.append("一致性较低，建议检查模型配置或增加交叉验证")
                elif metric.dimension == QualityDimension.COMPLETENESS:
                    recommendations.append("完整性不足，建议检查数据处理流程")
                elif metric.dimension == QualityDimension.TIMELINESS:
                    recommendations.append("处理时间过长，建议优化性能或增加并发")
                elif metric.dimension == QualityDimension.ROBUSTNESS:
                    recommendations.append("鲁棒性不足，建议加强错误处理和异常情况处理")
        
        # 基于基准对比的建议
        for metric in metrics:
            benchmark = self.benchmarks.get(metric.dimension)
            if benchmark and metric.score < benchmark.minimum_score:
                recommendations.append(f"{metric.dimension.value}低于最低基准({benchmark.minimum_score:.2f})，需要立即改进")
        
        return recommendations[:10]  # 限制建议数量
    
    def _compare_with_benchmarks(self, metrics: List[QualityMetric]) -> Dict[str, float]:
        """与基准进行对比"""
        benchmark_scores = {}
        
        for metric in metrics:
            benchmark = self.benchmarks.get(metric.dimension)
            if benchmark:
                # 计算相对于目标分数的比例
                relative_score = metric.score / benchmark.target_score
                benchmark_scores[metric.dimension.value] = relative_score
                
                # 更新指标的基准对比信息
                metric.benchmark_comparison = relative_score
        
        return benchmark_scores
    
    def _update_stats(self, assessment: QualityAssessment):
        """更新统计信息"""
        self.stats['assessments_performed'] += 1
        
        # 更新平均总体分数
        total_assessments = self.stats['assessments_performed']
        current_avg = self.stats['average_overall_score']
        self.stats['average_overall_score'] = (
            (current_avg * (total_assessments - 1) + assessment.overall_score) / total_assessments
        )
        
        # 更新维度平均分数
        for metric in assessment.metrics:
            dimension_name = metric.dimension.value
            current_dim_avg = self.stats['dimension_averages'][dimension_name]
            self.stats['dimension_averages'][dimension_name] = (
                (current_dim_avg * (total_assessments - 1) + metric.score) / total_assessments
            )
        
        # 更新质量等级分布
        self.stats['quality_level_distribution'][assessment.overall_level.value] += 1
        
        # 更新平均评估时间
        current_avg_time = self.stats['average_assessment_time']
        self.stats['average_assessment_time'] = (
            (current_avg_time * (total_assessments - 1) + assessment.assessment_time) / total_assessments
        )
    
    async def batch_assess_quality(self, 
                                 validated_results_list: List[ValidatedResults],
                                 cross_validation_results_list: Optional[List[List[CrossValidationResult]]] = None,
                                 filter_results_list: Optional[List[List[FilterResult]]] = None,
                                 ground_truth_list: Optional[List[List[bool]]] = None,
                                 max_concurrency: int = 5) -> List[QualityAssessment]:
        """批量质量评估"""
        logger.info(f"开始批量质量评估，结果集数: {len(validated_results_list)}")
        
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def assess_single(i, validated_results):
            async with semaphore:
                cross_validation_results = cross_validation_results_list[i] if cross_validation_results_list else None
                filter_results = filter_results_list[i] if filter_results_list else None
                ground_truth = ground_truth_list[i] if ground_truth_list else None
                
                return await self.assess_quality(
                    validated_results, cross_validation_results, filter_results, ground_truth
                )
        
        # 并发评估
        tasks = [assess_single(i, vr) for i, vr in enumerate(validated_results_list)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量质量评估异常: {i}, {result}")
                final_results.append(QualityAssessment(
                    overall_score=0.5,
                    overall_level=QualityLevel.FAIR,
                    metrics=[],
                    assessment_time=0.0,
                    recommendations=[f"评估异常: {str(result)}"],
                    metadata={'batch_error': str(result)}
                ))
            else:
                final_results.append(result)
        
        logger.info(f"批量质量评估完成，结果数: {len(final_results)}")
        return final_results
    
    def get_quality_statistics(self) -> Dict[str, Any]:
        """获取质量统计信息"""
        stats = self.stats.copy()
        
        # 添加基准信息
        stats['benchmarks'] = {
            dim.value: benchmark.to_dict() 
            for dim, benchmark in self.benchmarks.items()
        }
        
        # 添加趋势信息
        stats['trend_analysis'] = self.trend_analyzer.analyze_trends()
        
        return stats
    
    def update_benchmark(self, dimension: QualityDimension, target_score: float, minimum_score: float):
        """更新质量基准"""
        if dimension in self.benchmarks:
            benchmark = self.benchmarks[dimension]
            benchmark.target_score = target_score
            benchmark.minimum_score = minimum_score
            logger.info(f"更新基准 {dimension.value}: 目标{target_score}, 最低{minimum_score}")
        else:
            logger.warning(f"未找到维度 {dimension.value} 的基准")
    
    def export_quality_report(self, file_path: str, assessments: List[QualityAssessment]):
        """导出质量报告"""
        try:
            report_data = {
                'export_time': datetime.now().isoformat(),
                'assessments_count': len(assessments),
                'assessments': [assessment.to_dict() for assessment in assessments],
                'statistics': self.get_quality_statistics(),
                'benchmarks': {dim.value: benchmark.to_dict() for dim, benchmark in self.benchmarks.items()}
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"导出质量报告到 {file_path}")
            
        except Exception as e:
            logger.error(f"导出质量报告失败: {e}")
    
    def get_quality_forecast(self, days_ahead: int = 7) -> Dict[str, Any]:
        """获取质量预测"""
        return self.trend_analyzer.get_quality_forecast(days_ahead)