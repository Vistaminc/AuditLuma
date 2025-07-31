"""
置信度计算器 - Self-RAG验证层组件

本模块实现了多维度置信度评分算法，用于计算漏洞验证结果的置信度。
包括：
- 多维度置信度评分
- 置信度解释和可视化
- 动态权重调整
- 历史准确性跟踪
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
    EnhancedContext, VulnerabilityKnowledge, ConfidenceScore
)


class ConfidenceFactor(str, Enum):
    """置信度因子枚举"""
    CODE_QUALITY = "code_quality"
    PATTERN_MATCH = "pattern_match"
    CONTEXT_COMPLETENESS = "context_completeness"
    HISTORICAL_ACCURACY = "historical_accuracy"
    CROSS_VALIDATION = "cross_validation"
    KNOWLEDGE_RELEVANCE = "knowledge_relevance"
    SEMANTIC_COHERENCE = "semantic_coherence"
    IMPACT_ASSESSMENT = "impact_assessment"


@dataclass
class ConfidenceFactorResult:
    """置信度因子结果"""
    factor: ConfidenceFactor
    score: float
    weight: float
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'factor': self.factor.value,
            'score': self.score,
            'weight': self.weight,
            'explanation': self.explanation,
            'evidence': self.evidence
        }


@dataclass
class HistoricalAccuracyRecord:
    """历史准确性记录"""
    vulnerability_type: str
    predicted_confidence: float
    actual_result: bool
    timestamp: datetime
    context_similarity: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'vulnerability_type': self.vulnerability_type,
            'predicted_confidence': self.predicted_confidence,
            'actual_result': self.actual_result,
            'timestamp': self.timestamp.isoformat(),
            'context_similarity': self.context_similarity
        }


class ConfidenceCalculator:
    """置信度计算器 - 实现多维度置信度评分算法"""
    
    def __init__(self):
        """初始化置信度计算器"""
        # 默认权重配置
        self.default_weights = {
            ConfidenceFactor.CODE_QUALITY: 0.15,
            ConfidenceFactor.PATTERN_MATCH: 0.20,
            ConfidenceFactor.CONTEXT_COMPLETENESS: 0.15,
            ConfidenceFactor.HISTORICAL_ACCURACY: 0.15,
            ConfidenceFactor.CROSS_VALIDATION: 0.20,
            ConfidenceFactor.KNOWLEDGE_RELEVANCE: 0.10,
            ConfidenceFactor.SEMANTIC_COHERENCE: 0.05
        }
        
        # 从配置加载权重
        self.weights = self._load_weights_from_config()
        
        # 历史准确性数据
        self.historical_records: List[HistoricalAccuracyRecord] = []
        self.accuracy_cache: Dict[str, float] = {}
        
        # 动态权重调整参数
        self.weight_adaptation_enabled = True
        self.adaptation_learning_rate = 0.01
        self.min_weight = 0.01
        self.max_weight = 0.5
        
        # 性能统计
        self.stats = {
            'calculations_performed': 0,
            'average_confidence': 0.0,
            'factor_usage_count': {factor.value: 0 for factor in ConfidenceFactor},
            'weight_adjustments': 0,
            'cache_hits': 0
        }
        
        logger.info(f"置信度计算器初始化完成")
        logger.info(f"权重配置: {self.weights}")
        logger.info(f"动态权重调整: {'启用' if self.weight_adaptation_enabled else '禁用'}")
    
    def _load_weights_from_config(self) -> Dict[ConfidenceFactor, float]:
        """从配置加载权重"""
        hierarchical_config = getattr(Config, 'hierarchical_rag', None)
        weight_config = {}
        
        # 如果有层级RAG配置，尝试获取置信度计算配置
        if hierarchical_config and hasattr(hierarchical_config, 'self_rag_validation'):
            # 这里可以扩展为从配置中读取权重配置
            # 目前使用默认配置
            pass
        
        weights = {}
        total_weight = 0.0
        
        # 加载配置的权重
        for factor in ConfidenceFactor:
            weight = weight_config.get(factor.value, self.default_weights.get(factor, 0.1))
            weights[factor] = weight
            total_weight += weight
        
        # 归一化权重
        if total_weight > 0:
            for factor in weights:
                weights[factor] = weights[factor] / total_weight
        else:
            weights = self.default_weights.copy()
        
        return weights
    
    async def calculate_confidence(self, 
                                 vulnerability: VulnerabilityResult,
                                 enhanced_context: Optional[EnhancedContext] = None,
                                 knowledge: Optional[VulnerabilityKnowledge] = None,
                                 cross_validation_metadata: Optional[Dict[str, Any]] = None) -> ConfidenceScore:
        """计算综合置信度"""
        start_time = time.time()
        
        try:
            logger.debug(f"开始计算置信度: {vulnerability.id}")
            
            # 计算各个因子的置信度
            factor_results = await self._calculate_all_factors(
                vulnerability, enhanced_context, knowledge, cross_validation_metadata
            )
            
            # 计算加权平均置信度
            overall_score = self._calculate_weighted_average(factor_results)
            
            # 生成解释
            explanation = self._generate_explanation(factor_results, overall_score)
            
            # 提取影响因子
            factors = [result.factor.value for result in factor_results if result.score > 0.1]
            
            # 构建组件分数字典
            component_scores = {result.factor.value: result.score for result in factor_results}
            
            # 更新统计信息
            self._update_stats(overall_score, factor_results)
            
            # 如果启用了动态权重调整，记录此次计算
            if self.weight_adaptation_enabled:
                self._record_calculation_for_adaptation(factor_results, overall_score)
            
            calculation_time = time.time() - start_time
            
            confidence_score = ConfidenceScore(
                overall_score=overall_score,
                component_scores=component_scores,
                explanation=explanation,
                factors=factors
            )
            
            logger.debug(f"置信度计算完成: {vulnerability.id}, 分数: {overall_score:.3f}, 耗时: {calculation_time:.3f}s")
            
            return confidence_score
            
        except Exception as e:
            logger.error(f"置信度计算失败: {vulnerability.id}, {e}")
            return ConfidenceScore(
                overall_score=0.5,  # 默认中等置信度
                component_scores={},
                explanation=f"置信度计算失败: {str(e)}",
                factors=[]
            )
    
    async def _calculate_all_factors(self, 
                                   vulnerability: VulnerabilityResult,
                                   enhanced_context: Optional[EnhancedContext],
                                   knowledge: Optional[VulnerabilityKnowledge],
                                   cross_validation_metadata: Optional[Dict[str, Any]]) -> List[ConfidenceFactorResult]:
        """计算所有置信度因子"""
        factor_results = []
        
        # 并行计算各个因子
        tasks = [
            self._calculate_code_quality_factor(vulnerability),
            self._calculate_pattern_match_factor(vulnerability),
            self._calculate_context_completeness_factor(vulnerability, enhanced_context),
            self._calculate_historical_accuracy_factor(vulnerability),
            self._calculate_cross_validation_factor(cross_validation_metadata),
            self._calculate_knowledge_relevance_factor(vulnerability, knowledge),
            self._calculate_semantic_coherence_factor(vulnerability, enhanced_context)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果
        for i, result in enumerate(results):
            if isinstance(result, ConfidenceFactorResult):
                factor_results.append(result)
            else:
                logger.warning(f"因子计算异常: {list(ConfidenceFactor)[i]}, {result}")
                # 创建默认结果
                factor_results.append(ConfidenceFactorResult(
                    factor=list(ConfidenceFactor)[i],
                    score=0.5,
                    weight=self.weights.get(list(ConfidenceFactor)[i], 0.1),
                    explanation=f"计算异常: {str(result)}"
                ))
        
        return factor_results
    
    async def _calculate_code_quality_factor(self, vulnerability: VulnerabilityResult) -> ConfidenceFactorResult:
        """计算代码质量因子"""
        score = 0.5  # 基础分数
        evidence = {}
        
        snippet = vulnerability.snippet
        file_path = vulnerability.file_path
        
        # 1. 代码片段长度合理性 (20-500字符为合理范围)
        snippet_length = len(snippet)
        if 20 <= snippet_length <= 500:
            length_score = 1.0
        elif snippet_length < 20:
            length_score = snippet_length / 20.0
        else:
            length_score = max(0.3, 1.0 - (snippet_length - 500) / 1000.0)
        
        score += length_score * 0.2
        evidence['snippet_length'] = snippet_length
        evidence['length_score'] = length_score
        
        # 2. 代码结构完整性
        structure_indicators = ['{', '}', '(', ')', '[', ']', ';', '\n']
        structure_count = sum(1 for indicator in structure_indicators if indicator in snippet)
        structure_score = min(1.0, structure_count / 5.0)  # 至少5个结构指示符
        
        score += structure_score * 0.15
        evidence['structure_score'] = structure_score
        
        # 3. 关键信息包含度
        vuln_type_keywords = vulnerability.vulnerability_type.lower().split()
        keyword_matches = sum(1 for keyword in vuln_type_keywords if keyword in snippet.lower())
        keyword_score = min(1.0, keyword_matches / max(1, len(vuln_type_keywords)))
        
        score += keyword_score * 0.25
        evidence['keyword_matches'] = keyword_matches
        evidence['keyword_score'] = keyword_score
        
        # 4. 文件路径可信度
        suspicious_paths = ['test', 'example', 'demo', 'mock', 'temp']
        path_lower = file_path.lower()
        is_suspicious = any(suspicious in path_lower for suspicious in suspicious_paths)
        path_score = 0.3 if is_suspicious else 1.0
        
        score += path_score * 0.15
        evidence['is_suspicious_path'] = is_suspicious
        evidence['path_score'] = path_score
        
        # 5. 代码复杂度评估
        complexity_indicators = ['if', 'for', 'while', 'try', 'catch', 'function', 'class']
        complexity_count = sum(1 for indicator in complexity_indicators if indicator in snippet.lower())
        complexity_score = min(1.0, complexity_count / 3.0)  # 适度复杂度为好
        
        score += complexity_score * 0.25
        evidence['complexity_count'] = complexity_count
        evidence['complexity_score'] = complexity_score
        
        # 确保分数在0-1范围内
        final_score = max(0.0, min(1.0, score))
        
        explanation = f"代码质量评估: 片段长度({snippet_length}字符), 结构完整性({structure_score:.2f}), 关键词匹配({keyword_score:.2f}), 路径可信度({path_score:.2f}), 复杂度({complexity_score:.2f})"
        
        return ConfidenceFactorResult(
            factor=ConfidenceFactor.CODE_QUALITY,
            score=final_score,
            weight=self.weights[ConfidenceFactor.CODE_QUALITY],
            explanation=explanation,
            evidence=evidence
        )
    
    async def _calculate_pattern_match_factor(self, vulnerability: VulnerabilityResult) -> ConfidenceFactorResult:
        """计算模式匹配因子"""
        vuln_type = vulnerability.vulnerability_type.lower()
        snippet = vulnerability.snippet.lower()
        
        # 定义漏洞类型的特征模式
        vulnerability_patterns = {
            'sql injection': {
                'keywords': ['select', 'insert', 'update', 'delete', 'union', 'or', 'and', 'where', 'from'],
                'dangerous_patterns': ['or 1=1', 'union select', '; drop', '-- ', '/*'],
                'weight': 1.0
            },
            'xss': {
                'keywords': ['script', 'alert', 'document', 'window', 'eval', 'innerhtml', 'onclick'],
                'dangerous_patterns': ['<script>', 'javascript:', 'onerror=', 'onload='],
                'weight': 1.0
            },
            'command injection': {
                'keywords': ['system', 'exec', 'shell', 'cmd', 'subprocess', 'popen', 'os.'],
                'dangerous_patterns': ['system(', 'exec(', '`', '$(', '&&', '||', ';'],
                'weight': 1.0
            },
            'path traversal': {
                'keywords': ['../', '..\\', 'path', 'file', 'directory', 'readfile', 'include'],
                'dangerous_patterns': ['../../../', '..\\..\\..\\', '/etc/passwd', 'c:\\windows'],
                'weight': 1.0
            },
            'buffer overflow': {
                'keywords': ['strcpy', 'strcat', 'sprintf', 'gets', 'buffer', 'malloc', 'free'],
                'dangerous_patterns': ['strcpy(', 'gets(', 'sprintf(', 'strcat('],
                'weight': 1.0
            },
            'deserialization': {
                'keywords': ['deserialize', 'pickle', 'unserialize', 'json.loads', 'yaml.load'],
                'dangerous_patterns': ['pickle.loads', 'yaml.load', 'unserialize('],
                'weight': 1.0
            }
        }
        
        evidence = {}
        best_match_score = 0.0
        best_match_type = None
        
        # 寻找最佳匹配的漏洞类型
        for pattern_type, patterns in vulnerability_patterns.items():
            if pattern_type in vuln_type or any(word in vuln_type for word in pattern_type.split()):
                # 计算关键词匹配分数
                keyword_matches = sum(1 for keyword in patterns['keywords'] if keyword in snippet)
                keyword_score = keyword_matches / len(patterns['keywords'])
                
                # 计算危险模式匹配分数
                dangerous_matches = sum(1 for pattern in patterns['dangerous_patterns'] if pattern in snippet)
                dangerous_score = min(1.0, dangerous_matches / max(1, len(patterns['dangerous_patterns']) * 0.5))
                
                # 综合分数
                type_score = (keyword_score * 0.6 + dangerous_score * 0.4) * patterns['weight']
                
                if type_score > best_match_score:
                    best_match_score = type_score
                    best_match_type = pattern_type
                    evidence = {
                        'matched_type': pattern_type,
                        'keyword_matches': keyword_matches,
                        'keyword_score': keyword_score,
                        'dangerous_matches': dangerous_matches,
                        'dangerous_score': dangerous_score,
                        'total_keywords': len(patterns['keywords']),
                        'total_dangerous_patterns': len(patterns['dangerous_patterns'])
                    }
        
        # 如果没有找到匹配的模式，使用通用评估
        if best_match_score == 0.0:
            # 通用安全关键词
            generic_security_keywords = [
                'password', 'token', 'secret', 'key', 'auth', 'login', 'admin',
                'user', 'input', 'output', 'request', 'response', 'validate'
            ]
            generic_matches = sum(1 for keyword in generic_security_keywords if keyword in snippet)
            best_match_score = min(0.6, generic_matches / 10.0)  # 最高0.6分
            evidence = {
                'matched_type': 'generic',
                'generic_matches': generic_matches,
                'total_generic_keywords': len(generic_security_keywords)
            }
        
        explanation = f"模式匹配评估: 最佳匹配类型({best_match_type or 'generic'}), 匹配分数({best_match_score:.2f})"
        if evidence.get('keyword_matches'):
            explanation += f", 关键词匹配({evidence['keyword_matches']}/{evidence['total_keywords']})"
        if evidence.get('dangerous_matches'):
            explanation += f", 危险模式匹配({evidence['dangerous_matches']})"
        
        return ConfidenceFactorResult(
            factor=ConfidenceFactor.PATTERN_MATCH,
            score=best_match_score,
            weight=self.weights[ConfidenceFactor.PATTERN_MATCH],
            explanation=explanation,
            evidence=evidence
        )
    
    async def _calculate_context_completeness_factor(self, 
                                                   vulnerability: VulnerabilityResult,
                                                   enhanced_context: Optional[EnhancedContext]) -> ConfidenceFactorResult:
        """计算上下文完整性因子"""
        if not enhanced_context:
            return ConfidenceFactorResult(
                factor=ConfidenceFactor.CONTEXT_COMPLETENESS,
                score=0.3,  # 没有增强上下文时的默认分数
                weight=self.weights[ConfidenceFactor.CONTEXT_COMPLETENESS],
                explanation="没有提供增强上下文信息",
                evidence={'has_enhanced_context': False}
            )
        
        score = 0.0
        evidence = {}
        
        # 1. 调用链完整性 (25%)
        call_chain = enhanced_context.call_chain
        if call_chain.functions:
            call_chain_score = min(1.0, len(call_chain.functions) / 5.0)  # 5个函数为满分
            call_depth_bonus = min(0.2, call_chain.call_depth / 10.0)  # 深度奖励
            call_chain_score += call_depth_bonus
        else:
            call_chain_score = 0.0
        
        score += call_chain_score * 0.25
        evidence['call_chain_functions'] = len(call_chain.functions)
        evidence['call_depth'] = call_chain.call_depth
        evidence['call_chain_score'] = call_chain_score
        
        # 2. 数据流信息完整性 (25%)
        data_flow = enhanced_context.data_flow
        data_flow_score = 0.0
        
        if data_flow.taint_sources:
            data_flow_score += 0.4  # 有污点源
        if data_flow.taint_sinks:
            data_flow_score += 0.4  # 有污点汇
        if data_flow.data_paths:
            data_flow_score += 0.2  # 有数据路径
        
        score += data_flow_score * 0.25
        evidence['taint_sources'] = len(data_flow.taint_sources)
        evidence['taint_sinks'] = len(data_flow.taint_sinks)
        evidence['data_paths'] = len(data_flow.data_paths)
        evidence['data_flow_score'] = data_flow_score
        
        # 3. 影响范围评估完整性 (25%)
        impact_scope = enhanced_context.impact_scope
        impact_score = 0.0
        
        if impact_scope.affected_files:
            impact_score += min(0.4, len(impact_scope.affected_files) / 5.0)
        if impact_scope.affected_functions:
            impact_score += min(0.4, len(impact_scope.affected_functions) / 10.0)
        if impact_scope.impact_score > 0:
            impact_score += 0.2
        
        score += impact_score * 0.25
        evidence['affected_files'] = len(impact_scope.affected_files)
        evidence['affected_functions'] = len(impact_scope.affected_functions)
        evidence['impact_score_value'] = impact_scope.impact_score
        evidence['impact_score'] = impact_score
        
        # 4. 语义上下文完整性 (25%)
        semantic_context = enhanced_context.semantic_context
        semantic_score = 0.0
        
        if semantic_context.related_code_blocks:
            semantic_score += min(0.5, len(semantic_context.related_code_blocks) / 3.0)
        if semantic_context.expanded_context:
            semantic_score += 0.3
        if semantic_context.semantic_similarity_scores:
            avg_similarity = sum(semantic_context.semantic_similarity_scores.values()) / len(semantic_context.semantic_similarity_scores)
            semantic_score += avg_similarity * 0.2
        
        score += semantic_score * 0.25
        evidence['related_code_blocks'] = len(semantic_context.related_code_blocks)
        evidence['has_expanded_context'] = bool(semantic_context.expanded_context)
        evidence['similarity_scores_count'] = len(semantic_context.semantic_similarity_scores)
        evidence['semantic_score'] = semantic_score
        
        # 使用原始完整性分数作为额外参考
        if hasattr(enhanced_context, 'completeness_score'):
            original_completeness = enhanced_context.completeness_score
            score = score * 0.8 + original_completeness * 0.2  # 加权结合
            evidence['original_completeness'] = original_completeness
        
        final_score = max(0.0, min(1.0, score))
        
        explanation = f"上下文完整性评估: 调用链({call_chain_score:.2f}), 数据流({data_flow_score:.2f}), 影响范围({impact_score:.2f}), 语义上下文({semantic_score:.2f})"
        
        return ConfidenceFactorResult(
            factor=ConfidenceFactor.CONTEXT_COMPLETENESS,
            score=final_score,
            weight=self.weights[ConfidenceFactor.CONTEXT_COMPLETENESS],
            explanation=explanation,
            evidence=evidence
        )
    
    async def _calculate_historical_accuracy_factor(self, vulnerability: VulnerabilityResult) -> ConfidenceFactorResult:
        """计算历史准确性因子"""
        vuln_type = vulnerability.vulnerability_type.lower()
        
        # 检查缓存
        cache_key = f"historical_{vuln_type}"
        if cache_key in self.accuracy_cache:
            cached_score = self.accuracy_cache[cache_key]
            self.stats['cache_hits'] += 1
            return ConfidenceFactorResult(
                factor=ConfidenceFactor.HISTORICAL_ACCURACY,
                score=cached_score,
                weight=self.weights[ConfidenceFactor.HISTORICAL_ACCURACY],
                explanation=f"历史准确性(缓存): {cached_score:.2f}",
                evidence={'cached': True, 'cache_key': cache_key}
            )
        
        # 从历史记录计算准确性
        relevant_records = [
            record for record in self.historical_records
            if record.vulnerability_type.lower() == vuln_type
        ]
        
        if relevant_records:
            # 计算准确性
            correct_predictions = sum(
                1 for record in relevant_records
                if (record.predicted_confidence > 0.5) == record.actual_result
            )
            accuracy = correct_predictions / len(relevant_records)
            
            # 考虑时间衰减 (最近的记录权重更高)
            now = datetime.now()
            weighted_accuracy = 0.0
            total_weight = 0.0
            
            for record in relevant_records:
                days_ago = (now - record.timestamp).days
                time_weight = math.exp(-days_ago / 30.0)  # 30天半衰期
                
                is_correct = (record.predicted_confidence > 0.5) == record.actual_result
                weighted_accuracy += (1.0 if is_correct else 0.0) * time_weight
                total_weight += time_weight
            
            if total_weight > 0:
                final_accuracy = weighted_accuracy / total_weight
            else:
                final_accuracy = accuracy
            
            evidence = {
                'total_records': len(relevant_records),
                'correct_predictions': correct_predictions,
                'raw_accuracy': accuracy,
                'time_weighted_accuracy': final_accuracy,
                'oldest_record_days': (now - min(record.timestamp for record in relevant_records)).days,
                'newest_record_days': (now - max(record.timestamp for record in relevant_records)).days
            }
            
            explanation = f"历史准确性: {len(relevant_records)}条记录, 准确率{final_accuracy:.2f}"
            
        else:
            # 没有历史记录时，使用基于漏洞类型的默认准确性
            default_accuracies = {
                'sql injection': 0.85,
                'xss': 0.80,
                'command injection': 0.88,
                'path traversal': 0.75,
                'buffer overflow': 0.70,
                'deserialization': 0.82,
                'authentication bypass': 0.78,
                'privilege escalation': 0.73
            }
            
            final_accuracy = 0.65  # 默认准确性
            for pattern, accuracy in default_accuracies.items():
                if pattern in vuln_type:
                    final_accuracy = accuracy
                    break
            
            evidence = {
                'total_records': 0,
                'using_default': True,
                'default_accuracy': final_accuracy,
                'matched_pattern': pattern if pattern in vuln_type else None
            }
            
            explanation = f"历史准确性(默认): 无历史记录, 使用默认值{final_accuracy:.2f}"
        
        # 缓存结果
        self.accuracy_cache[cache_key] = final_accuracy
        
        return ConfidenceFactorResult(
            factor=ConfidenceFactor.HISTORICAL_ACCURACY,
            score=final_accuracy,
            weight=self.weights[ConfidenceFactor.HISTORICAL_ACCURACY],
            explanation=explanation,
            evidence=evidence
        )
    
    async def _calculate_cross_validation_factor(self, 
                                               cross_validation_metadata: Optional[Dict[str, Any]]) -> ConfidenceFactorResult:
        """计算交叉验证因子"""
        if not cross_validation_metadata:
            return ConfidenceFactorResult(
                factor=ConfidenceFactor.CROSS_VALIDATION,
                score=0.5,  # 没有交叉验证时的默认分数
                weight=self.weights[ConfidenceFactor.CROSS_VALIDATION],
                explanation="没有提供交叉验证信息",
                evidence={'has_cross_validation': False}
            )
        
        evidence = cross_validation_metadata.copy()
        
        # 提取关键指标
        consensus_reached = cross_validation_metadata.get('consensus_reached', False)
        models_used = cross_validation_metadata.get('models_used', 0)
        average_confidence = cross_validation_metadata.get('average_confidence', 0.5)
        individual_scores = cross_validation_metadata.get('individual_scores', [])
        
        score = 0.0
        
        # 1. 共识达成奖励 (40%)
        if consensus_reached:
            score += 0.4
        
        # 2. 模型数量奖励 (20%)
        model_score = min(1.0, models_used / 3.0)  # 3个模型为满分
        score += model_score * 0.2
        
        # 3. 平均置信度 (25%)
        score += average_confidence * 0.25
        
        # 4. 一致性奖励 (15%)
        if individual_scores and len(individual_scores) > 1:
            consistency = 1.0 - (statistics.stdev(individual_scores) / max(0.1, statistics.mean(individual_scores)))
            consistency = max(0.0, min(1.0, consistency))
            score += consistency * 0.15
            evidence['consistency_score'] = consistency
        
        final_score = max(0.0, min(1.0, score))
        
        explanation = f"交叉验证: {models_used}个模型, 共识{'达成' if consensus_reached else '未达成'}, 平均置信度{average_confidence:.2f}"
        if 'consistency_score' in evidence:
            explanation += f", 一致性{evidence['consistency_score']:.2f}"
        
        return ConfidenceFactorResult(
            factor=ConfidenceFactor.CROSS_VALIDATION,
            score=final_score,
            weight=self.weights[ConfidenceFactor.CROSS_VALIDATION],
            explanation=explanation,
            evidence=evidence
        )
    
    async def _calculate_knowledge_relevance_factor(self, 
                                                  vulnerability: VulnerabilityResult,
                                                  knowledge: Optional[VulnerabilityKnowledge]) -> ConfidenceFactorResult:
        """计算知识相关性因子"""
        if not knowledge:
            return ConfidenceFactorResult(
                factor=ConfidenceFactor.KNOWLEDGE_RELEVANCE,
                score=0.4,  # 没有知识时的默认分数
                weight=self.weights[ConfidenceFactor.KNOWLEDGE_RELEVANCE],
                explanation="没有提供知识信息",
                evidence={'has_knowledge': False}
            )
        
        score = 0.0
        evidence = {}
        
        # 1. CVE信息相关性 (40%)
        if knowledge.cve_info:
            cve_count = len(knowledge.cve_info)
            cve_score = min(1.0, cve_count / 3.0)  # 3个CVE为满分
            
            # 考虑CVE的严重程度
            high_severity_count = sum(
                1 for cve in knowledge.cve_info
                if cve.severity.lower() in ['high', 'critical']
            )
            severity_bonus = min(0.3, high_severity_count / max(1, cve_count))
            cve_score += severity_bonus
            
            score += min(1.0, cve_score) * 0.4
            evidence['cve_count'] = cve_count
            evidence['high_severity_cves'] = high_severity_count
            evidence['cve_score'] = cve_score
        
        # 2. 最佳实践匹配度 (30%)
        if knowledge.best_practices:
            bp_count = len(knowledge.best_practices)
            bp_score = min(1.0, bp_count / 2.0)  # 2个最佳实践为满分
            
            # 检查语言匹配
            file_ext = vulnerability.file_path.split('.')[-1].lower()
            language_matches = sum(
                1 for bp in knowledge.best_practices
                if bp.language.lower() in file_ext or file_ext in bp.language.lower()
            )
            if bp_count > 0:
                language_bonus = (language_matches / bp_count) * 0.2
                bp_score += language_bonus
            
            score += min(1.0, bp_score) * 0.3
            evidence['best_practices_count'] = bp_count
            evidence['language_matches'] = language_matches
            evidence['bp_score'] = bp_score
        
        # 3. 历史案例相似度 (30%)
        if knowledge.historical_cases:
            hc_count = len(knowledge.historical_cases)
            avg_similarity = sum(case.similarity_score for case in knowledge.historical_cases) / hc_count
            hc_score = avg_similarity  # 直接使用平均相似度
            
            score += hc_score * 0.3
            evidence['historical_cases_count'] = hc_count
            evidence['average_similarity'] = avg_similarity
            evidence['hc_score'] = hc_score
        
        # 4. 相关性分数 (如果提供)
        if knowledge.relevance_scores:
            max_relevance = max(knowledge.relevance_scores.values())
            avg_relevance = sum(knowledge.relevance_scores.values()) / len(knowledge.relevance_scores)
            
            # 使用最大相关性和平均相关性的加权平均
            relevance_score = max_relevance * 0.7 + avg_relevance * 0.3
            score = score * 0.8 + relevance_score * 0.2  # 与其他分数结合
            
            evidence['max_relevance'] = max_relevance
            evidence['avg_relevance'] = avg_relevance
            evidence['relevance_sources'] = len(knowledge.relevance_scores)
        
        final_score = max(0.0, min(1.0, score))
        
        explanation = f"知识相关性: CVE({evidence.get('cve_count', 0)}), 最佳实践({evidence.get('best_practices_count', 0)}), 历史案例({evidence.get('historical_cases_count', 0)})"
        if 'avg_relevance' in evidence:
            explanation += f", 平均相关性{evidence['avg_relevance']:.2f}"
        
        return ConfidenceFactorResult(
            factor=ConfidenceFactor.KNOWLEDGE_RELEVANCE,
            score=final_score,
            weight=self.weights[ConfidenceFactor.KNOWLEDGE_RELEVANCE],
            explanation=explanation,
            evidence=evidence
        )
    
    async def _calculate_semantic_coherence_factor(self, 
                                                 vulnerability: VulnerabilityResult,
                                                 enhanced_context: Optional[EnhancedContext]) -> ConfidenceFactorResult:
        """计算语义一致性因子"""
        score = 0.5  # 基础分数
        evidence = {}
        
        # 1. 漏洞描述与代码片段的一致性
        description = vulnerability.description.lower()
        snippet = vulnerability.snippet.lower()
        vuln_type = vulnerability.vulnerability_type.lower()
        
        # 提取描述中的关键词
        description_words = set(description.split())
        snippet_words = set(snippet.split())
        vuln_type_words = set(vuln_type.split())
        
        # 计算词汇重叠度
        desc_snippet_overlap = len(description_words & snippet_words) / max(1, len(description_words))
        type_snippet_overlap = len(vuln_type_words & snippet_words) / max(1, len(vuln_type_words))
        
        coherence_score = (desc_snippet_overlap + type_snippet_overlap) / 2
        score += coherence_score * 0.3
        
        evidence['desc_snippet_overlap'] = desc_snippet_overlap
        evidence['type_snippet_overlap'] = type_snippet_overlap
        evidence['coherence_score'] = coherence_score
        
        # 2. 如果有增强上下文，检查语义一致性
        if enhanced_context and enhanced_context.semantic_context:
            semantic_context = enhanced_context.semantic_context
            
            # 相关代码块的一致性
            if semantic_context.related_code_blocks:
                related_coherence = 0.0
                for block in semantic_context.related_code_blocks:
                    block_words = set(block.lower().split())
                    block_overlap = len(snippet_words & block_words) / max(1, len(snippet_words))
                    related_coherence += block_overlap
                
                related_coherence /= len(semantic_context.related_code_blocks)
                score += related_coherence * 0.2
                evidence['related_blocks_coherence'] = related_coherence
            
            # 语义相似度分数
            if semantic_context.semantic_similarity_scores:
                avg_similarity = sum(semantic_context.semantic_similarity_scores.values()) / len(semantic_context.semantic_similarity_scores)
                score += avg_similarity * 0.2
                evidence['avg_semantic_similarity'] = avg_similarity
        
        # 3. 文件路径与漏洞类型的一致性
        file_path = vulnerability.file_path.lower()
        path_coherence = 0.0
        
        # 检查文件扩展名是否与常见漏洞类型匹配
        file_ext = file_path.split('.')[-1] if '.' in file_path else ''
        
        type_ext_mapping = {
            'sql': ['sql', 'py', 'php', 'java', 'cs'],
            'xss': ['html', 'js', 'php', 'jsp', 'asp'],
            'command': ['py', 'sh', 'bat', 'php', 'rb'],
            'path': ['py', 'php', 'java', 'cs', 'rb'],
            'buffer': ['c', 'cpp', 'h', 'hpp']
        }
        
        for vuln_keyword, extensions in type_ext_mapping.items():
            if vuln_keyword in vuln_type and file_ext in extensions:
                path_coherence = 1.0
                break
        
        score += path_coherence * 0.1
        evidence['path_coherence'] = path_coherence
        evidence['file_extension'] = file_ext
        
        # 4. 严重程度与代码复杂度的一致性
        severity = vulnerability.severity.lower()
        complexity_indicators = ['if', 'for', 'while', 'try', 'function', 'class', 'import']
        complexity_count = sum(1 for indicator in complexity_indicators if indicator in snippet)
        
        # 高严重程度应该对应较高的代码复杂度
        severity_scores = {'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4}
        expected_complexity = severity_scores.get(severity, 0.5)
        actual_complexity = min(1.0, complexity_count / 5.0)
        
        complexity_coherence = 1.0 - abs(expected_complexity - actual_complexity)
        score += complexity_coherence * 0.1
        
        evidence['expected_complexity'] = expected_complexity
        evidence['actual_complexity'] = actual_complexity
        evidence['complexity_coherence'] = complexity_coherence
        
        final_score = max(0.0, min(1.0, score))
        
        explanation = f"语义一致性: 描述-代码重叠({desc_snippet_overlap:.2f}), 类型-代码重叠({type_snippet_overlap:.2f}), 路径一致性({path_coherence:.2f})"
        
        return ConfidenceFactorResult(
            factor=ConfidenceFactor.SEMANTIC_COHERENCE,
            score=final_score,
            weight=self.weights[ConfidenceFactor.SEMANTIC_COHERENCE],
            explanation=explanation,
            evidence=evidence
        )
    
    def _calculate_weighted_average(self, factor_results: List[ConfidenceFactorResult]) -> float:
        """计算加权平均置信度"""
        if not factor_results:
            return 0.5
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for result in factor_results:
            total_weighted_score += result.score * result.weight
            total_weight += result.weight
        
        if total_weight == 0:
            return 0.5
        
        return total_weighted_score / total_weight
    
    def _generate_explanation(self, factor_results: List[ConfidenceFactorResult], overall_score: float) -> str:
        """生成置信度解释"""
        explanation_parts = [f"综合置信度: {overall_score:.3f}"]
        
        # 按分数排序，显示主要影响因子
        sorted_results = sorted(factor_results, key=lambda x: x.score * x.weight, reverse=True)
        
        top_factors = sorted_results[:3]  # 显示前3个主要因子
        for result in top_factors:
            weighted_contribution = result.score * result.weight
            explanation_parts.append(f"{result.factor.value}({weighted_contribution:.3f})")
        
        # 添加关键洞察
        if overall_score >= 0.8:
            explanation_parts.append("高置信度")
        elif overall_score >= 0.6:
            explanation_parts.append("中等置信度")
        else:
            explanation_parts.append("低置信度")
        
        return "; ".join(explanation_parts)
    
    def _update_stats(self, overall_score: float, factor_results: List[ConfidenceFactorResult]):
        """更新统计信息"""
        self.stats['calculations_performed'] += 1
        
        # 更新平均置信度
        total_calculations = self.stats['calculations_performed']
        current_avg = self.stats['average_confidence']
        self.stats['average_confidence'] = (
            (current_avg * (total_calculations - 1) + overall_score) / total_calculations
        )
        
        # 更新因子使用统计
        for result in factor_results:
            self.stats['factor_usage_count'][result.factor.value] += 1
    
    def _record_calculation_for_adaptation(self, factor_results: List[ConfidenceFactorResult], overall_score: float):
        """记录计算结果用于权重自适应"""
        # 这里可以实现权重自适应逻辑
        # 基于结果的准确性来调整各因子的权重
        pass
    
    async def add_historical_record(self, 
                                  vulnerability_type: str,
                                  predicted_confidence: float,
                                  actual_result: bool,
                                  context_similarity: float = 0.0):
        """添加历史准确性记录"""
        record = HistoricalAccuracyRecord(
            vulnerability_type=vulnerability_type,
            predicted_confidence=predicted_confidence,
            actual_result=actual_result,
            timestamp=datetime.now(),
            context_similarity=context_similarity
        )
        
        self.historical_records.append(record)
        
        # 清理过期记录 (保留最近1年的记录)
        cutoff_date = datetime.now() - timedelta(days=365)
        self.historical_records = [
            record for record in self.historical_records
            if record.timestamp > cutoff_date
        ]
        
        # 清理相关缓存
        cache_key = f"historical_{vulnerability_type.lower()}"
        if cache_key in self.accuracy_cache:
            del self.accuracy_cache[cache_key]
        
        logger.debug(f"添加历史记录: {vulnerability_type}, 预测: {predicted_confidence:.2f}, 实际: {actual_result}")
    
    def update_weights(self, new_weights: Dict[str, float]):
        """更新权重配置"""
        total_weight = sum(new_weights.values())
        if total_weight <= 0:
            logger.warning("权重总和必须大于0")
            return
        
        # 归一化权重
        normalized_weights = {}
        for factor_name, weight in new_weights.items():
            try:
                factor = ConfidenceFactor(factor_name)
                normalized_weights[factor] = weight / total_weight
            except ValueError:
                logger.warning(f"未知的置信度因子: {factor_name}")
        
        if normalized_weights:
            self.weights.update(normalized_weights)
            self.stats['weight_adjustments'] += 1
            logger.info(f"更新权重配置: {normalized_weights}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = self.stats.copy()
        stats['weights'] = {factor.value: weight for factor, weight in self.weights.items()}
        stats['historical_records_count'] = len(self.historical_records)
        stats['cache_size'] = len(self.accuracy_cache)
        
        return stats
    
    def clear_cache(self):
        """清理缓存"""
        self.accuracy_cache.clear()
        logger.info("置信度计算器缓存已清理")
    
    async def batch_calculate_confidence(self, 
                                       vulnerabilities: List[VulnerabilityResult],
                                       enhanced_contexts: Optional[List[EnhancedContext]] = None,
                                       knowledge_list: Optional[List[VulnerabilityKnowledge]] = None,
                                       cross_validation_metadata_list: Optional[List[Dict[str, Any]]] = None,
                                       max_concurrency: int = 10) -> List[ConfidenceScore]:
        """批量计算置信度"""
        logger.info(f"开始批量置信度计算，漏洞数: {len(vulnerabilities)}")
        
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def calculate_single(i, vulnerability):
            async with semaphore:
                enhanced_context = enhanced_contexts[i] if enhanced_contexts else None
                knowledge = knowledge_list[i] if knowledge_list else None
                cross_validation_metadata = cross_validation_metadata_list[i] if cross_validation_metadata_list else None
                
                return await self.calculate_confidence(
                    vulnerability, enhanced_context, knowledge, cross_validation_metadata
                )
        
        # 并发计算
        tasks = [calculate_single(i, vuln) for i, vuln in enumerate(vulnerabilities)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量置信度计算异常: {vulnerabilities[i].id}, {result}")
                final_results.append(ConfidenceScore(
                    overall_score=0.5,
                    component_scores={},
                    explanation=f"计算异常: {str(result)}",
                    factors=[]
                ))
            else:
                final_results.append(result)
        
        logger.info(f"批量置信度计算完成，结果数: {len(final_results)}")
        return final_results