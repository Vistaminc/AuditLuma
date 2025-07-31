"""
交叉验证器 - Self-RAG验证层组件

本模块实现了多模型一致性检查和共识算法，用于提高验证结果的可靠性。
包括：
- 多模型交叉验证
- 一致性检查算法
- 共识机制
- 统计分析和报告
"""

import asyncio
import statistics
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import time
from datetime import datetime
import json

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import VulnerabilityResult
from auditluma.models.hierarchical_rag import EnhancedContext, VulnerabilityKnowledge


class ConsensusMethod(str, Enum):
    """共识方法枚举"""
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_AVERAGE = "weighted_average"
    CONFIDENCE_WEIGHTED = "confidence_weighted"
    UNANIMOUS = "unanimous"
    THRESHOLD_BASED = "threshold_based"


@dataclass
class ModelValidationResult:
    """单个模型的验证结果"""
    model_name: str
    confidence_score: float
    is_valid: bool
    reasoning: str
    processing_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'model_name': self.model_name,
            'confidence_score': self.confidence_score,
            'is_valid': self.is_valid,
            'reasoning': self.reasoning,
            'processing_time': self.processing_time,
            'metadata': self.metadata
        }


@dataclass
class CrossValidationResult:
    """交叉验证结果"""
    vulnerability_id: str
    model_results: List[ModelValidationResult]
    consensus_score: float
    consensus_method: ConsensusMethod
    is_consensus_reached: bool
    final_confidence: float
    final_validity: bool
    disagreement_analysis: Dict[str, Any] = field(default_factory=dict)
    statistical_summary: Dict[str, Any] = field(default_factory=dict)
    validation_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'vulnerability_id': self.vulnerability_id,
            'model_results': [mr.to_dict() for mr in self.model_results],
            'consensus_score': self.consensus_score,
            'consensus_method': self.consensus_method.value,
            'is_consensus_reached': self.is_consensus_reached,
            'final_confidence': self.final_confidence,
            'final_validity': self.final_validity,
            'disagreement_analysis': self.disagreement_analysis,
            'statistical_summary': self.statistical_summary,
            'validation_time': self.validation_time
        }


class ModelValidator:
    """单个模型验证器"""
    
    def __init__(self, model_name: str, model_config: Dict[str, Any]):
        self.model_name = model_name
        self.model_config = model_config
        self.weight = model_config.get('weight', 1.0)
        self.timeout = model_config.get('timeout', 30)
        
        # 模型特定的提示模板
        self.validation_prompt_template = model_config.get(
            'validation_prompt_template',
            self._get_default_validation_prompt()
        )
        
        # 性能统计
        self.stats = {
            'validations_performed': 0,
            'average_processing_time': 0.0,
            'success_rate': 0.0,
            'average_confidence': 0.0
        }
    
    def _get_default_validation_prompt(self) -> str:
        """获取默认验证提示模板"""
        return """
请验证以下代码漏洞是否为真实的安全问题：

漏洞类型: {vulnerability_type}
严重程度: {severity}
文件路径: {file_path}
代码片段:
{snippet}

描述: {description}

请分析：
1. 这是否为真实的安全漏洞？
2. 给出置信度评分（0-1）
3. 提供详细的推理过程

请以JSON格式回复：
{{
    "is_valid": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "详细推理过程"
}}
"""
    
    async def validate(self, 
                      vulnerability: VulnerabilityResult,
                      enhanced_context: Optional[EnhancedContext] = None,
                      knowledge: Optional[VulnerabilityKnowledge] = None) -> ModelValidationResult:
        """使用特定模型验证漏洞"""
        start_time = time.time()
        
        try:
            logger.debug(f"开始模型验证: {self.model_name} -> {vulnerability.id}")
            
            # 构建验证提示
            prompt = self._build_validation_prompt(vulnerability, enhanced_context, knowledge)
            
            # 调用模型进行验证
            response = await self._call_model(prompt)
            
            # 解析响应
            result = self._parse_model_response(response)
            
            processing_time = time.time() - start_time
            
            # 更新统计信息
            self._update_stats(result['confidence'], processing_time, True)
            
            return ModelValidationResult(
                model_name=self.model_name,
                confidence_score=result['confidence'],
                is_valid=result['is_valid'],
                reasoning=result['reasoning'],
                processing_time=processing_time,
                metadata={
                    'prompt_length': len(prompt),
                    'response_length': len(str(response)),
                    'model_config': self.model_config
                }
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"模型验证失败: {self.model_name} -> {vulnerability.id}, {e}")
            
            # 更新统计信息（失败）
            self._update_stats(0.0, processing_time, False)
            
            return ModelValidationResult(
                model_name=self.model_name,
                confidence_score=0.0,
                is_valid=False,
                reasoning=f"模型验证失败: {str(e)}",
                processing_time=processing_time,
                metadata={'error': str(e)}
            )
    
    def _build_validation_prompt(self, 
                               vulnerability: VulnerabilityResult,
                               enhanced_context: Optional[EnhancedContext] = None,
                               knowledge: Optional[VulnerabilityKnowledge] = None) -> str:
        """构建验证提示"""
        # 基础信息
        prompt_data = {
            'vulnerability_type': vulnerability.vulnerability_type,
            'severity': vulnerability.severity,
            'file_path': vulnerability.file_path,
            'snippet': vulnerability.snippet,
            'description': vulnerability.description
        }
        
        # 添加增强上下文信息
        if enhanced_context:
            context_info = []
            if enhanced_context.call_chain.functions:
                context_info.append(f"调用链: {' -> '.join(enhanced_context.call_chain.functions[:5])}")
            
            if enhanced_context.impact_scope.affected_functions:
                context_info.append(f"影响函数: {', '.join(enhanced_context.impact_scope.affected_functions[:3])}")
            
            if context_info:
                prompt_data['context'] = "\n".join(context_info)
        
        # 添加知识信息
        if knowledge:
            knowledge_info = []
            if knowledge.cve_info:
                cve_ids = [cve.cve_id for cve in knowledge.cve_info[:3]]
                knowledge_info.append(f"相关CVE: {', '.join(cve_ids)}")
            
            if knowledge.best_practices:
                bp_titles = [bp.title for bp in knowledge.best_practices[:2]]
                knowledge_info.append(f"最佳实践: {', '.join(bp_titles)}")
            
            if knowledge_info:
                prompt_data['knowledge'] = "\n".join(knowledge_info)
        
        return self.validation_prompt_template.format(**prompt_data)
    
    async def _call_model(self, prompt: str) -> str:
        """调用模型API"""
        # 这里应该根据模型类型调用相应的API
        # 为了演示，使用模拟的响应
        
        # 模拟不同模型的响应时间和准确性
        await asyncio.sleep(0.1 + (hash(self.model_name) % 10) * 0.05)  # 0.1-0.6秒
        
        # 基于模型名称生成不同的模拟响应
        model_bias = hash(self.model_name) % 100 / 100.0  # 0-1之间的偏差
        
        # 模拟响应
        mock_response = {
            "is_valid": model_bias > 0.3,  # 70%概率认为有效
            "confidence": 0.5 + model_bias * 0.4,  # 0.5-0.9之间
            "reasoning": f"基于{self.model_name}的分析，考虑了代码模式和安全风险评估"
        }
        
        return json.dumps(mock_response)
    
    def _parse_model_response(self, response: str) -> Dict[str, Any]:
        """解析模型响应"""
        try:
            # 尝试解析JSON响应
            parsed = json.loads(response)
            
            return {
                'is_valid': bool(parsed.get('is_valid', False)),
                'confidence': float(parsed.get('confidence', 0.0)),
                'reasoning': str(parsed.get('reasoning', ''))
            }
            
        except json.JSONDecodeError:
            # 如果不是JSON格式，尝试简单解析
            logger.warning(f"模型响应不是有效JSON: {self.model_name}")
            
            # 简单的文本解析逻辑
            response_lower = response.lower()
            is_valid = 'valid' in response_lower or 'true' in response_lower
            
            # 尝试提取置信度数字
            import re
            confidence_match = re.search(r'(\d+\.?\d*)', response)
            confidence = float(confidence_match.group(1)) if confidence_match else 0.5
            
            # 确保置信度在0-1范围内
            if confidence > 1.0:
                confidence = confidence / 100.0
            
            return {
                'is_valid': is_valid,
                'confidence': max(0.0, min(1.0, confidence)),
                'reasoning': response[:200]  # 截取前200字符作为推理
            }
    
    def _update_stats(self, confidence: float, processing_time: float, success: bool):
        """更新统计信息"""
        self.stats['validations_performed'] += 1
        
        # 更新平均处理时间
        total_validations = self.stats['validations_performed']
        current_avg_time = self.stats['average_processing_time']
        self.stats['average_processing_time'] = (
            (current_avg_time * (total_validations - 1) + processing_time) / total_validations
        )
        
        # 更新成功率
        if success:
            current_success_count = self.stats['success_rate'] * (total_validations - 1)
            self.stats['success_rate'] = (current_success_count + 1) / total_validations
            
            # 更新平均置信度（仅成功的验证）
            current_avg_conf = self.stats['average_confidence']
            success_count = int(self.stats['success_rate'] * total_validations)
            if success_count > 1:
                self.stats['average_confidence'] = (
                    (current_avg_conf * (success_count - 1) + confidence) / success_count
                )
            else:
                self.stats['average_confidence'] = confidence
        else:
            current_success_count = self.stats['success_rate'] * (total_validations - 1)
            self.stats['success_rate'] = current_success_count / total_validations
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.stats.copy()


class CrossValidator:
    """交叉验证器 - 实现多模型一致性检查和共识算法"""
    
    def __init__(self):
        """初始化交叉验证器"""
        # 从配置加载验证模型
        self.models = self._load_validation_models()
        
        # 共识配置
        self.consensus_threshold = 0.6  # 一致性阈值
        self.default_consensus_method = ConsensusMethod.CONFIDENCE_WEIGHTED
        self.min_models_for_consensus = 2
        
        # 性能统计
        self.stats = {
            'cross_validations_performed': 0,
            'consensus_reached_count': 0,
            'average_consensus_score': 0.0,
            'model_agreement_rate': 0.0,
            'average_validation_time': 0.0
        }
        
        logger.info(f"交叉验证器初始化完成，加载了 {len(self.models)} 个验证模型")
        logger.info(f"共识阈值: {self.consensus_threshold}, 最小模型数: {self.min_models_for_consensus}")
    
    def _load_validation_models(self) -> List[ModelValidator]:
        """加载验证模型配置"""
        models = []
        
        # 从配置中获取模型列表
        hierarchical_config = getattr(Config, 'hierarchical_rag', None)
        model_configs = {}
        
        # 如果有层级RAG配置，尝试获取交叉验证配置
        if hierarchical_config and hasattr(hierarchical_config, 'self_rag_validation'):
            # 这里可以扩展为从配置中读取模型配置
            # 目前使用默认配置
            pass
        
        # 如果没有配置，使用默认模型
        if not model_configs:
            model_configs = {
                'primary_security': {
                    'model_name': Config.default_models.security_audit,
                    'weight': 1.0,
                    'timeout': 30
                },
                'secondary_analysis': {
                    'model_name': Config.default_models.code_analysis,
                    'weight': 0.8,
                    'timeout': 25
                }
            }
        
        # 创建模型验证器
        for model_id, config in model_configs.items():
            try:
                validator = ModelValidator(model_id, config)
                models.append(validator)
                logger.debug(f"加载验证模型: {model_id}")
            except Exception as e:
                logger.error(f"加载验证模型失败: {model_id}, {e}")
        
        return models
    
    async def cross_validate(self, 
                           vulnerability: VulnerabilityResult,
                           enhanced_context: Optional[EnhancedContext] = None,
                           knowledge: Optional[VulnerabilityKnowledge] = None,
                           consensus_method: Optional[ConsensusMethod] = None) -> CrossValidationResult:
        """执行交叉验证"""
        start_time = time.time()
        
        logger.debug(f"开始交叉验证: {vulnerability.id}")
        
        # 使用指定的共识方法或默认方法
        consensus_method = consensus_method or self.default_consensus_method
        
        # 并行执行所有模型的验证
        validation_tasks = [
            model.validate(vulnerability, enhanced_context, knowledge)
            for model in self.models
        ]
        
        try:
            # 等待所有验证完成
            model_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
            
            # 过滤出成功的结果
            valid_results = []
            for result in model_results:
                if isinstance(result, ModelValidationResult):
                    valid_results.append(result)
                else:
                    logger.warning(f"模型验证异常: {result}")
            
            if len(valid_results) < self.min_models_for_consensus:
                logger.warning(f"有效模型结果不足: {len(valid_results)}/{self.min_models_for_consensus}")
                # 返回默认结果
                return self._create_default_result(vulnerability.id, valid_results, consensus_method)
            
            # 计算共识
            consensus_result = self._calculate_consensus(
                valid_results, consensus_method, vulnerability.id
            )
            
            # 执行分歧分析
            disagreement_analysis = self._analyze_disagreements(valid_results)
            
            # 生成统计摘要
            statistical_summary = self._generate_statistical_summary(valid_results)
            
            validation_time = time.time() - start_time
            
            # 更新统计信息
            self._update_stats(consensus_result, validation_time)
            
            result = CrossValidationResult(
                vulnerability_id=vulnerability.id,
                model_results=valid_results,
                consensus_score=consensus_result['consensus_score'],
                consensus_method=consensus_method,
                is_consensus_reached=consensus_result['is_consensus_reached'],
                final_confidence=consensus_result['final_confidence'],
                final_validity=consensus_result['final_validity'],
                disagreement_analysis=disagreement_analysis,
                statistical_summary=statistical_summary,
                validation_time=validation_time
            )
            
            logger.debug(f"交叉验证完成: {vulnerability.id}, 共识: {result.is_consensus_reached}")
            return result
            
        except Exception as e:
            logger.error(f"交叉验证失败: {vulnerability.id}, {e}")
            return self._create_error_result(vulnerability.id, str(e), consensus_method)
    
    def _calculate_consensus(self, 
                           model_results: List[ModelValidationResult],
                           consensus_method: ConsensusMethod,
                           vulnerability_id: str) -> Dict[str, Any]:
        """计算共识结果"""
        if not model_results:
            return {
                'consensus_score': 0.0,
                'is_consensus_reached': False,
                'final_confidence': 0.0,
                'final_validity': False
            }
        
        if consensus_method == ConsensusMethod.MAJORITY_VOTE:
            return self._majority_vote_consensus(model_results)
        elif consensus_method == ConsensusMethod.WEIGHTED_AVERAGE:
            return self._weighted_average_consensus(model_results)
        elif consensus_method == ConsensusMethod.CONFIDENCE_WEIGHTED:
            return self._confidence_weighted_consensus(model_results)
        elif consensus_method == ConsensusMethod.UNANIMOUS:
            return self._unanimous_consensus(model_results)
        elif consensus_method == ConsensusMethod.THRESHOLD_BASED:
            return self._threshold_based_consensus(model_results)
        else:
            logger.warning(f"未知的共识方法: {consensus_method}, 使用置信度加权")
            return self._confidence_weighted_consensus(model_results)
    
    def _majority_vote_consensus(self, model_results: List[ModelValidationResult]) -> Dict[str, Any]:
        """多数投票共识"""
        valid_votes = sum(1 for result in model_results if result.is_valid)
        total_votes = len(model_results)
        
        final_validity = valid_votes > total_votes / 2
        consensus_score = abs(valid_votes - (total_votes - valid_votes)) / total_votes
        is_consensus_reached = consensus_score >= self.consensus_threshold
        
        # 计算平均置信度
        avg_confidence = sum(result.confidence_score for result in model_results) / total_votes
        
        return {
            'consensus_score': consensus_score,
            'is_consensus_reached': is_consensus_reached,
            'final_confidence': avg_confidence,
            'final_validity': final_validity
        }
    
    def _weighted_average_consensus(self, model_results: List[ModelValidationResult]) -> Dict[str, Any]:
        """加权平均共识"""
        total_weight = 0.0
        weighted_confidence = 0.0
        weighted_validity = 0.0
        
        for result in model_results:
            # 从模型配置获取权重，默认为1.0
            weight = 1.0
            for model in self.models:
                if model.model_name == result.model_name:
                    weight = model.weight
                    break
            
            total_weight += weight
            weighted_confidence += result.confidence_score * weight
            weighted_validity += (1.0 if result.is_valid else 0.0) * weight
        
        if total_weight == 0:
            return self._create_zero_consensus()
        
        final_confidence = weighted_confidence / total_weight
        validity_score = weighted_validity / total_weight
        final_validity = validity_score > 0.5
        
        # 计算一致性分数（基于权重分布的标准差）
        variance = sum(
            ((1.0 if result.is_valid else 0.0) - validity_score) ** 2
            for result in model_results
        ) / len(model_results)
        consensus_score = 1.0 - min(1.0, variance)
        
        return {
            'consensus_score': consensus_score,
            'is_consensus_reached': consensus_score >= self.consensus_threshold,
            'final_confidence': final_confidence,
            'final_validity': final_validity
        }
    
    def _confidence_weighted_consensus(self, model_results: List[ModelValidationResult]) -> Dict[str, Any]:
        """置信度加权共识"""
        total_confidence_weight = sum(result.confidence_score for result in model_results)
        
        if total_confidence_weight == 0:
            return self._create_zero_consensus()
        
        # 使用置信度作为权重
        weighted_validity = sum(
            result.confidence_score * (1.0 if result.is_valid else 0.0)
            for result in model_results
        ) / total_confidence_weight
        
        # 计算加权平均置信度
        final_confidence = sum(
            result.confidence_score ** 2 for result in model_results
        ) / total_confidence_weight
        
        final_validity = weighted_validity > 0.5
        
        # 计算一致性分数
        consensus_score = 1.0 - statistics.stdev([
            result.confidence_score * (1.0 if result.is_valid else -1.0)
            for result in model_results
        ]) / 2.0 if len(model_results) > 1 else 1.0
        
        return {
            'consensus_score': max(0.0, consensus_score),
            'is_consensus_reached': consensus_score >= self.consensus_threshold,
            'final_confidence': final_confidence,
            'final_validity': final_validity
        }
    
    def _unanimous_consensus(self, model_results: List[ModelValidationResult]) -> Dict[str, Any]:
        """一致性共识（要求所有模型一致）"""
        all_valid = all(result.is_valid for result in model_results)
        all_invalid = all(not result.is_valid for result in model_results)
        
        is_consensus_reached = all_valid or all_invalid
        consensus_score = 1.0 if is_consensus_reached else 0.0
        
        final_validity = all_valid
        avg_confidence = sum(result.confidence_score for result in model_results) / len(model_results)
        
        return {
            'consensus_score': consensus_score,
            'is_consensus_reached': is_consensus_reached,
            'final_confidence': avg_confidence,
            'final_validity': final_validity
        }
    
    def _threshold_based_consensus(self, model_results: List[ModelValidationResult]) -> Dict[str, Any]:
        """基于阈值的共识"""
        high_confidence_results = [
            result for result in model_results 
            if result.confidence_score >= self.consensus_threshold
        ]
        
        if not high_confidence_results:
            return self._create_zero_consensus()
        
        # 只考虑高置信度的结果
        valid_count = sum(1 for result in high_confidence_results if result.is_valid)
        total_count = len(high_confidence_results)
        
        validity_ratio = valid_count / total_count
        final_validity = validity_ratio > 0.5
        
        consensus_score = abs(validity_ratio - 0.5) * 2  # 0.5时为0，1.0或0.0时为1
        is_consensus_reached = consensus_score >= self.consensus_threshold
        
        avg_confidence = sum(result.confidence_score for result in high_confidence_results) / total_count
        
        return {
            'consensus_score': consensus_score,
            'is_consensus_reached': is_consensus_reached,
            'final_confidence': avg_confidence,
            'final_validity': final_validity
        }
    
    def _create_zero_consensus(self) -> Dict[str, Any]:
        """创建零共识结果"""
        return {
            'consensus_score': 0.0,
            'is_consensus_reached': False,
            'final_confidence': 0.0,
            'final_validity': False
        }
    
    def _analyze_disagreements(self, model_results: List[ModelValidationResult]) -> Dict[str, Any]:
        """分析模型间的分歧"""
        if len(model_results) < 2:
            return {'disagreement_level': 'none', 'analysis': '模型数量不足以分析分歧'}
        
        # 计算有效性分歧
        validity_votes = [result.is_valid for result in model_results]
        validity_agreement = sum(validity_votes) / len(validity_votes)
        
        # 计算置信度分歧
        confidences = [result.confidence_score for result in model_results]
        confidence_std = statistics.stdev(confidences) if len(confidences) > 1 else 0.0
        confidence_range = max(confidences) - min(confidences)
        
        # 分析推理分歧
        reasoning_lengths = [len(result.reasoning) for result in model_results]
        avg_reasoning_length = sum(reasoning_lengths) / len(reasoning_lengths)
        
        # 确定分歧级别
        if abs(validity_agreement - 0.5) > 0.3 and confidence_std < 0.2:
            disagreement_level = 'low'
        elif abs(validity_agreement - 0.5) <= 0.3 or confidence_std >= 0.3:
            disagreement_level = 'high'
        else:
            disagreement_level = 'medium'
        
        return {
            'disagreement_level': disagreement_level,
            'validity_agreement_ratio': validity_agreement,
            'confidence_standard_deviation': confidence_std,
            'confidence_range': confidence_range,
            'average_reasoning_length': avg_reasoning_length,
            'models_in_agreement': len([r for r in model_results if r.is_valid]) if validity_agreement > 0.5 else len([r for r in model_results if not r.is_valid]),
            'analysis': f'模型间分歧级别: {disagreement_level}, 有效性一致度: {validity_agreement:.2f}, 置信度标准差: {confidence_std:.2f}'
        }
    
    def _generate_statistical_summary(self, model_results: List[ModelValidationResult]) -> Dict[str, Any]:
        """生成统计摘要"""
        if not model_results:
            return {}
        
        confidences = [result.confidence_score for result in model_results]
        processing_times = [result.processing_time for result in model_results]
        
        return {
            'model_count': len(model_results),
            'confidence_stats': {
                'mean': statistics.mean(confidences),
                'median': statistics.median(confidences),
                'std_dev': statistics.stdev(confidences) if len(confidences) > 1 else 0.0,
                'min': min(confidences),
                'max': max(confidences)
            },
            'processing_time_stats': {
                'mean': statistics.mean(processing_times),
                'median': statistics.median(processing_times),
                'total': sum(processing_times),
                'min': min(processing_times),
                'max': max(processing_times)
            },
            'validity_distribution': {
                'valid_count': sum(1 for result in model_results if result.is_valid),
                'invalid_count': sum(1 for result in model_results if not result.is_valid),
                'valid_percentage': sum(1 for result in model_results if result.is_valid) / len(model_results) * 100
            }
        }
    
    def _create_default_result(self, 
                             vulnerability_id: str,
                             partial_results: List[ModelValidationResult],
                             consensus_method: ConsensusMethod) -> CrossValidationResult:
        """创建默认结果（当模型数量不足时）"""
        if partial_results:
            # 使用现有结果的平均值
            avg_confidence = sum(r.confidence_score for r in partial_results) / len(partial_results)
            majority_valid = sum(1 for r in partial_results if r.is_valid) > len(partial_results) / 2
        else:
            avg_confidence = 0.5
            majority_valid = False
        
        return CrossValidationResult(
            vulnerability_id=vulnerability_id,
            model_results=partial_results,
            consensus_score=0.0,
            consensus_method=consensus_method,
            is_consensus_reached=False,
            final_confidence=avg_confidence,
            final_validity=majority_valid,
            disagreement_analysis={'analysis': '模型数量不足，无法进行完整的交叉验证'},
            statistical_summary=self._generate_statistical_summary(partial_results),
            validation_time=0.0
        )
    
    def _create_error_result(self, 
                           vulnerability_id: str,
                           error_message: str,
                           consensus_method: ConsensusMethod) -> CrossValidationResult:
        """创建错误结果"""
        return CrossValidationResult(
            vulnerability_id=vulnerability_id,
            model_results=[],
            consensus_score=0.0,
            consensus_method=consensus_method,
            is_consensus_reached=False,
            final_confidence=0.0,
            final_validity=False,
            disagreement_analysis={'error': error_message},
            statistical_summary={},
            validation_time=0.0
        )
    
    def _update_stats(self, consensus_result: Dict[str, Any], validation_time: float):
        """更新统计信息"""
        self.stats['cross_validations_performed'] += 1
        
        if consensus_result['is_consensus_reached']:
            self.stats['consensus_reached_count'] += 1
        
        # 更新平均共识分数
        total_validations = self.stats['cross_validations_performed']
        current_avg_consensus = self.stats['average_consensus_score']
        self.stats['average_consensus_score'] = (
            (current_avg_consensus * (total_validations - 1) + consensus_result['consensus_score']) / total_validations
        )
        
        # 更新平均验证时间
        current_avg_time = self.stats['average_validation_time']
        self.stats['average_validation_time'] = (
            (current_avg_time * (total_validations - 1) + validation_time) / total_validations
        )
        
        # 更新模型一致性率
        self.stats['model_agreement_rate'] = self.stats['consensus_reached_count'] / total_validations
    
    async def batch_cross_validate(self, 
                                 vulnerabilities: List[VulnerabilityResult],
                                 enhanced_contexts: Optional[List[EnhancedContext]] = None,
                                 knowledge_list: Optional[List[VulnerabilityKnowledge]] = None,
                                 max_concurrency: int = 5) -> List[CrossValidationResult]:
        """批量交叉验证"""
        logger.info(f"开始批量交叉验证，漏洞数: {len(vulnerabilities)}")
        
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def validate_single(i, vulnerability):
            async with semaphore:
                enhanced_context = enhanced_contexts[i] if enhanced_contexts else None
                knowledge = knowledge_list[i] if knowledge_list else None
                return await self.cross_validate(vulnerability, enhanced_context, knowledge)
        
        # 并发执行验证
        tasks = [validate_single(i, vuln) for i, vuln in enumerate(vulnerabilities)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量交叉验证异常: {vulnerabilities[i].id}, {result}")
                final_results.append(self._create_error_result(
                    vulnerabilities[i].id, str(result), self.default_consensus_method
                ))
            else:
                final_results.append(result)
        
        logger.info(f"批量交叉验证完成，结果数: {len(final_results)}")
        return final_results
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """获取验证统计信息"""
        base_stats = self.stats.copy()
        
        # 添加模型统计信息
        model_stats = {}
        for model in self.models:
            model_stats[model.model_name] = model.get_stats()
        
        base_stats['model_statistics'] = model_stats
        base_stats['total_models'] = len(self.models)
        
        return base_stats
    
    def update_consensus_threshold(self, new_threshold: float):
        """更新共识阈值"""
        if 0.0 <= new_threshold <= 1.0:
            self.consensus_threshold = new_threshold
            logger.info(f"更新共识阈值: {new_threshold}")
        else:
            logger.warning(f"无效的共识阈值: {new_threshold}")
    
    def add_validation_model(self, model_id: str, model_config: Dict[str, Any]):
        """添加新的验证模型"""
        try:
            validator = ModelValidator(model_id, model_config)
            self.models.append(validator)
            logger.info(f"添加验证模型: {model_id}")
        except Exception as e:
            logger.error(f"添加验证模型失败: {model_id}, {e}")
    
    def remove_validation_model(self, model_id: str):
        """移除验证模型"""
        self.models = [model for model in self.models if model.model_name != model_id]
        logger.info(f"移除验证模型: {model_id}")