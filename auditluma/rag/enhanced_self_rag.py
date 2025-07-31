"""
增强的Self-RAG系统 - 集成新的验证层架构

本模块提供了一个统一的接口，将新的Self-RAG验证层与现有的self_rag系统集成，
确保向后兼容性的同时提供增强的功能。
"""

import asyncio
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass
import time

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import VulnerabilityResult, SourceFile, CodeUnit
from auditluma.models.hierarchical_rag import (
    EnhancedContext, VulnerabilityKnowledge, ValidatedResults,
    ConfidenceScore, ValidationSummary, ValidatedVulnerability, ValidationStatus
)

# 导入现有的self_rag系统
from auditluma.rag.self_rag import self_rag, SelfRAG, Document

# 导入新的验证层组件
from auditluma.rag.self_rag_validator import SelfRAGValidator
from auditluma.rag.cross_validator import CrossValidator
from auditluma.rag.confidence_calculator import ConfidenceCalculator
from auditluma.rag.false_positive_filter import FalsePositiveFilter
from auditluma.rag.quality_assessor import QualityAssessor


class EnhancedSelfRAG:
    """增强的Self-RAG系统
    
    这个类提供了一个统一的接口，集成了：
    1. 现有的self_rag系统（知识检索和存储）
    2. 新的验证层（交叉验证、置信度计算、假阳性过滤、质量评估）
    
    确保向后兼容性的同时提供增强的验证功能。
    """
    
    def __init__(self):
        """初始化增强的Self-RAG系统"""
        # 现有的self_rag系统（用于知识检索和存储）
        self.knowledge_system = self_rag
        
        # 向后兼容：添加processed_files属性
        self.processed_files = self.knowledge_system.processed_files
        
        # 新的验证层组件
        self.validator = SelfRAGValidator()
        self.cross_validator = CrossValidator()
        self.confidence_calculator = ConfidenceCalculator()
        self.false_positive_filter = FalsePositiveFilter()
        self.quality_assessor = QualityAssessor()
        
        # 配置参数
        hierarchical_config = getattr(Config, 'hierarchical_rag', None)
        
        # 使用默认配置值
        self.enable_validation = True
        self.enable_quality_assessment = True
        self.batch_size = 10
        
        # 如果有层级RAG配置，尝试获取增强Self-RAG配置
        if hierarchical_config and hasattr(hierarchical_config, 'self_rag_validation'):
            validation_config = hierarchical_config.self_rag_validation
            if hasattr(validation_config, 'enabled'):
                self.enable_validation = validation_config.enabled
        
        # 性能统计
        self.stats = {
            'total_validations': 0,
            'validated_vulnerabilities': 0,
            'filtered_false_positives': 0,
            'average_confidence': 0.0,
            'quality_assessments': 0,
            'knowledge_retrievals': 0
        }
        
        logger.info("增强的Self-RAG系统初始化完成")
        logger.info(f"验证功能: {'启用' if self.enable_validation else '禁用'}")
        logger.info(f"质量评估: {'启用' if self.enable_quality_assessment else '禁用'}")
    
    # ==================== 向后兼容的接口 ====================
    
    async def add_source_file(self, file: SourceFile) -> None:
        """添加源文件到知识库（向后兼容）"""
        await self.knowledge_system.add_source_file(file)
        self.stats['knowledge_retrievals'] += 1
    
    async def add_code_unit(self, unit: CodeUnit) -> None:
        """添加代码单元到知识库（向后兼容）"""
        await self.knowledge_system.add_code_unit(unit)
    
    async def add_batch_code_units(self, units: List[CodeUnit], max_concurrency: int = 20) -> None:
        """批量添加代码单元到知识库（向后兼容）"""
        await self.knowledge_system.add_batch_code_units(units, max_concurrency)
    
    async def retrieve(self, query: str, k: int = 5) -> List[Tuple[Document, float]]:
        """检索相关文档（向后兼容）"""
        return await self.knowledge_system.retrieve(query, k)
    
    def save_knowledge_base(self, path: str = "./data/kb/knowledge_base") -> None:
        """保存知识库（向后兼容）"""
        self.knowledge_system.save_knowledge_base(path)
    
    def load_knowledge_base(self, path: str = "./data/kb/knowledge_base") -> None:
        """加载知识库（向后兼容）"""
        self.knowledge_system.load_knowledge_base(path)
    
    # ==================== 增强的验证接口 ====================
    
    async def validate_vulnerability(self, 
                                   vulnerability: VulnerabilityResult,
                                   enhanced_context: Optional[EnhancedContext] = None,
                                   knowledge: Optional[VulnerabilityKnowledge] = None) -> ValidatedVulnerability:
        """验证单个漏洞（增强功能）
        
        Args:
            vulnerability: 要验证的漏洞
            enhanced_context: 增强上下文信息（可选）
            knowledge: 漏洞知识信息（可选）
            
        Returns:
            验证后的漏洞结果
        """
        if not self.enable_validation:
            # 如果验证功能禁用，返回默认验证结果
            return ValidatedVulnerability(
                vulnerability=vulnerability,
                validation_status=ValidationStatus.VALIDATED,
                confidence_score=ConfidenceScore(overall_score=0.8),
                knowledge=knowledge or VulnerabilityKnowledge(),
                enhanced_context=enhanced_context or EnhancedContext(),
                validation_notes="验证功能已禁用，使用默认验证"
            )
        
        try:
            # 1. 使用现有系统检索知识（如果未提供）
            if knowledge is None:
                knowledge = await self._retrieve_vulnerability_knowledge(vulnerability)
            
            # 2. 增强上下文（如果未提供）
            if enhanced_context is None:
                enhanced_context = await self._enhance_vulnerability_context(vulnerability)
            
            # 3. 执行验证
            validation_result = await self.validator.validate_with_self_rag_integration(
                vulnerability, enhanced_context, knowledge
            )
            
            # 4. 计算置信度
            confidence_score = await self.confidence_calculator.calculate_confidence(
                vulnerability, enhanced_context, knowledge, validation_result.metadata
            )
            
            # 5. 确定验证状态
            if validation_result.is_valid:
                if confidence_score.overall_score >= 0.8:
                    validation_status = ValidationStatus.VALIDATED
                elif confidence_score.overall_score >= 0.5:
                    validation_status = ValidationStatus.NEEDS_REVIEW
                else:
                    validation_status = ValidationStatus.REJECTED
            else:
                validation_status = ValidationStatus.REJECTED
            
            # 6. 构建验证后的漏洞
            validated_vulnerability = ValidatedVulnerability(
                vulnerability=vulnerability,
                validation_status=validation_status,
                confidence_score=confidence_score,
                knowledge=knowledge,
                enhanced_context=enhanced_context,
                validation_notes=validation_result.rejection_reason or "验证通过"
            )
            
            # 更新统计信息
            self._update_validation_stats(validation_result, confidence_score)
            
            return validated_vulnerability
            
        except Exception as e:
            logger.error(f"验证漏洞失败: {vulnerability.id}, {e}")
            
            # 返回默认验证结果
            return ValidatedVulnerability(
                vulnerability=vulnerability,
                validation_status=ValidationStatus.NEEDS_REVIEW,
                confidence_score=ConfidenceScore(overall_score=0.5),
                knowledge=knowledge or VulnerabilityKnowledge(),
                enhanced_context=enhanced_context or EnhancedContext(),
                validation_notes=f"验证过程出错: {str(e)}"
            )
    
    async def batch_validate_vulnerabilities(self, 
                                           vulnerabilities: List[VulnerabilityResult],
                                           enhanced_contexts: Optional[List[EnhancedContext]] = None,
                                           knowledge_list: Optional[List[VulnerabilityKnowledge]] = None,
                                           max_concurrency: int = 10) -> ValidatedResults:
        """批量验证漏洞（增强功能）
        
        Args:
            vulnerabilities: 要验证的漏洞列表
            enhanced_contexts: 增强上下文列表（可选）
            knowledge_list: 知识信息列表（可选）
            max_concurrency: 最大并发数
            
        Returns:
            批量验证结果
        """
        if not vulnerabilities:
            return ValidatedResults()
        
        logger.info(f"开始批量验证 {len(vulnerabilities)} 个漏洞")
        start_time = time.time()
        
        # 使用信号量控制并发
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def validate_single(i, vulnerability):
            async with semaphore:
                enhanced_context = enhanced_contexts[i] if enhanced_contexts else None
                knowledge = knowledge_list[i] if knowledge_list else None
                return await self.validate_vulnerability(vulnerability, enhanced_context, knowledge)
        
        # 并发验证
        tasks = [validate_single(i, vuln) for i, vuln in enumerate(vulnerabilities)]
        validated_vulnerabilities = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        final_validated = []
        for i, result in enumerate(validated_vulnerabilities):
            if isinstance(result, Exception):
                logger.error(f"批量验证异常: {vulnerabilities[i].id}, {result}")
                # 创建默认验证结果
                final_validated.append(ValidatedVulnerability(
                    vulnerability=vulnerabilities[i],
                    validation_status=ValidationStatus.NEEDS_REVIEW,
                    confidence_score=ConfidenceScore(overall_score=0.5),
                    knowledge=VulnerabilityKnowledge(),
                    enhanced_context=EnhancedContext(),
                    validation_notes=f"批量验证异常: {str(result)}"
                ))
            else:
                final_validated.append(result)
        
        # 统计结果
        validated_count = sum(1 for vv in final_validated if vv.validation_status == ValidationStatus.VALIDATED)
        rejected_count = sum(1 for vv in final_validated if vv.validation_status == ValidationStatus.REJECTED)
        needs_review_count = sum(1 for vv in final_validated if vv.validation_status == ValidationStatus.NEEDS_REVIEW)
        
        # 计算平均置信度
        avg_confidence = sum(vv.confidence_score.overall_score for vv in final_validated) / len(final_validated)
        
        validation_time = time.time() - start_time
        
        # 创建验证摘要
        validation_summary = ValidationSummary(
            total_vulnerabilities=len(vulnerabilities),
            validated_count=validated_count,
            rejected_count=rejected_count,
            needs_review_count=needs_review_count,
            average_confidence=avg_confidence,
            validation_time=validation_time
        )
        
        # 构建结果
        validated_results = ValidatedResults(
            validated_vulnerabilities=final_validated,
            filtered_count=rejected_count,
            validation_summary=validation_summary,
            processing_metadata={
                'batch_size': len(vulnerabilities),
                'max_concurrency': max_concurrency,
                'validation_enabled': self.enable_validation
            }
        )
        
        logger.info(f"批量验证完成: {validated_count}个通过, {rejected_count}个拒绝, {needs_review_count}个需要审查")
        
        return validated_results
    
    async def assess_quality(self, 
                           validated_results: ValidatedResults,
                           ground_truth: Optional[List[bool]] = None) -> Dict[str, Any]:
        """评估验证结果的质量（增强功能）
        
        Args:
            validated_results: 验证结果
            ground_truth: 真实标签（可选）
            
        Returns:
            质量评估结果
        """
        if not self.enable_quality_assessment:
            return {
                'quality_assessment_enabled': False,
                'message': '质量评估功能已禁用'
            }
        
        try:
            quality_assessment = await self.quality_assessor.assess_quality(
                validated_results, ground_truth=ground_truth
            )
            
            self.stats['quality_assessments'] += 1
            
            return quality_assessment.to_dict()
            
        except Exception as e:
            logger.error(f"质量评估失败: {e}")
            return {
                'error': str(e),
                'quality_assessment_enabled': True,
                'message': '质量评估过程出错'
            }
    
    # ==================== 内部辅助方法 ====================
    
    async def _retrieve_vulnerability_knowledge(self, vulnerability: VulnerabilityResult) -> VulnerabilityKnowledge:
        """使用现有系统检索漏洞相关知识"""
        try:
            # 构建查询
            query = f"{vulnerability.vulnerability_type} {vulnerability.description}"
            
            # 使用现有的self_rag系统检索
            retrieved_docs = await self.knowledge_system.retrieve(query, k=5)
            
            # 转换为VulnerabilityKnowledge格式
            knowledge = VulnerabilityKnowledge()
            
            for doc, score in retrieved_docs:
                knowledge.relevance_scores[doc.id] = score
            
            knowledge.source_queries = [query]
            knowledge.retrieval_time = 0.1  # 简化的时间记录
            
            self.stats['knowledge_retrievals'] += 1
            
            return knowledge
            
        except Exception as e:
            logger.warning(f"检索漏洞知识失败: {e}")
            return VulnerabilityKnowledge()
    
    async def _enhance_vulnerability_context(self, vulnerability: VulnerabilityResult) -> EnhancedContext:
        """增强漏洞上下文信息"""
        try:
            # 构建上下文查询
            context_query = f"context {vulnerability.file_path} {vulnerability.snippet[:100]}"
            
            # 检索相关上下文
            context_docs = await self.knowledge_system.retrieve(context_query, k=3)
            
            # 构建增强上下文
            enhanced_context = EnhancedContext()
            
            for doc, score in context_docs:
                enhanced_context.semantic_context.related_code_blocks.append(doc.content)
                enhanced_context.semantic_context.semantic_similarity_scores[doc.id] = score
            
            enhanced_context.completeness_score = min(1.0, len(context_docs) / 3.0)
            enhanced_context.enhancement_time = 0.1  # 简化的时间记录
            
            return enhanced_context
            
        except Exception as e:
            logger.warning(f"增强上下文失败: {e}")
            return EnhancedContext()
    
    def _update_validation_stats(self, validation_result, confidence_score):
        """更新验证统计信息"""
        self.stats['total_validations'] += 1
        
        if validation_result.is_valid:
            self.stats['validated_vulnerabilities'] += 1
        else:
            self.stats['filtered_false_positives'] += 1
        
        # 更新平均置信度
        total_validations = self.stats['total_validations']
        current_avg = self.stats['average_confidence']
        self.stats['average_confidence'] = (
            (current_avg * (total_validations - 1) + confidence_score.overall_score) / total_validations
        )
    
    # ==================== 管理接口 ====================
    
    def get_system_statistics(self) -> Dict[str, Any]:
        """获取系统统计信息"""
        base_stats = self.stats.copy()
        
        # 添加子组件统计
        if self.enable_validation:
            base_stats['validator_stats'] = self.validator.get_validation_statistics()
            base_stats['cross_validator_stats'] = self.cross_validator.get_validation_statistics()
            base_stats['confidence_calculator_stats'] = self.confidence_calculator.get_statistics()
            base_stats['false_positive_filter_stats'] = self.false_positive_filter.get_filter_statistics()
        
        if self.enable_quality_assessment:
            base_stats['quality_assessor_stats'] = self.quality_assessor.get_quality_statistics()
        
        return base_stats
    
    def update_configuration(self, new_config: Dict[str, Any]):
        """更新系统配置"""
        if 'enable_validation' in new_config:
            self.enable_validation = new_config['enable_validation']
            logger.info(f"验证功能: {'启用' if self.enable_validation else '禁用'}")
        
        if 'enable_quality_assessment' in new_config:
            self.enable_quality_assessment = new_config['enable_quality_assessment']
            logger.info(f"质量评估: {'启用' if self.enable_quality_assessment else '禁用'}")
        
        if 'batch_size' in new_config:
            self.batch_size = new_config['batch_size']
            logger.info(f"批处理大小: {self.batch_size}")
        
        # 更新子组件配置
        if self.enable_validation:
            if 'validator_config' in new_config:
                self.validator.update_configuration(new_config['validator_config'])
            
            if 'false_positive_filter_config' in new_config:
                self.false_positive_filter.update_configuration(new_config['false_positive_filter_config'])
    
    async def learn_from_feedback(self, 
                                vulnerability: VulnerabilityResult,
                                predicted_result: bool,
                                actual_result: bool,
                                feedback: str):
        """从反馈中学习"""
        if not self.enable_validation:
            return
        
        try:
            # 让假阳性过滤器学习
            if predicted_result and not actual_result:  # 预测为真但实际为假（假阳性）
                await self.false_positive_filter.learn_from_feedback(
                    vulnerability, True, feedback
                )
            
            # 让置信度计算器学习
            await self.confidence_calculator.add_historical_record(
                vulnerability.vulnerability_type,
                0.8 if predicted_result else 0.2,  # 简化的置信度
                actual_result
            )
            
            logger.info(f"反馈学习完成: {vulnerability.id}")
            
        except Exception as e:
            logger.error(f"反馈学习失败: {e}")
    
    async def cleanup(self):
        """清理系统资源"""
        logger.info("开始清理增强Self-RAG系统资源")
        
        if self.enable_validation:
            await self.validator.cleanup()
            self.false_positive_filter.cleanup_resources()
        
        logger.info("增强Self-RAG系统资源清理完成")


# 创建全局实例，替代原有的self_rag
enhanced_self_rag = EnhancedSelfRAG()

# 为了向后兼容，提供原有接口的别名
self_rag_enhanced = enhanced_self_rag