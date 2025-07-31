"""
Self-RAG验证层 - 层级RAG架构第四层
负责结果验证与质量保证

本模块实现了Self-RAG验证器的基础架构，包括：
- 与现有self_rag系统的集成
- 异步验证处理流水线
- 验证结果的统一管理
"""

import asyncio
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from datetime import datetime, timedelta
import statistics
import time

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import VulnerabilityResult
from auditluma.models.hierarchical_rag import (
    EnhancedContext, VulnerabilityKnowledge, ValidatedResults,
    ConfidenceScore, ValidationSummary, ValidatedVulnerability, ValidationStatus
)
from auditluma.rag.self_rag import self_rag
from auditluma.rag.cross_validator import CrossValidator
from auditluma.rag.confidence_calculator import ConfidenceCalculator
from auditluma.rag.false_positive_filter import FalsePositiveFilter
from auditluma.rag.quality_assessor import QualityAssessor


class ValidationMethod(Enum):
    """验证方法枚举"""
    CROSS_VALIDATION = "cross_validation"
    CONSISTENCY_CHECK = "consistency_check"
    CONFIDENCE_ANALYSIS = "confidence_analysis"
    PATTERN_MATCHING = "pattern_matching"
    HISTORICAL_COMPARISON = "historical_comparison"


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: bool
    confidence_score: float
    validation_methods: List[ValidationMethod]
    rejection_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FalsePositivePattern:
    """假阳性模式"""
    pattern_id: str
    vulnerability_type: str
    code_pattern: str
    description: str
    confidence: float
    created_at: datetime
    usage_count: int = 0





class SelfRAGValidator:
    """Self-RAG验证器 - 层级RAG架构第四层核心组件
    
    负责对审计结果进行验证和质量保证，包括：
    - 与现有self_rag系统的集成
    - 异步验证处理流水线
    - 交叉验证和置信度计算
    - 假阳性过滤和质量评估
    """
    
    def __init__(self):
        """初始化Self-RAG验证器"""
        # 获取Self-RAG层的模型配置
        self.self_rag_models = Config.get_self_rag_models()
        self.validation_model = self.self_rag_models.get("validation_model", "gpt-3.5-turbo@openai")
        self.cross_validation_models = self.self_rag_models.get("cross_validation_models", [
            "gpt-4@openai",
            "deepseek-chat@deepseek", 
            "gpt-3.5-turbo@openai"
        ])
        
        logger.info(f"Self-RAG验证器使用模型 - 验证: {self.validation_model}")
        logger.info(f"交叉验证模型: {self.cross_validation_models}")
        
        # 初始化子组件
        self.cross_validator = CrossValidator()
        self.confidence_calculator = ConfidenceCalculator()
        self.false_positive_filter = FalsePositiveFilter()
        
        # 与现有self_rag系统集成
        self.self_rag_instance = self_rag
        
        # 配置参数
        hierarchical_config = getattr(Config, 'hierarchical_rag', None)
        
        # 使用默认配置值
        self.confidence_threshold = 0.75
        self.validation_timeout = 60
        self.max_concurrent_validations = 10
        
        # 如果有层级RAG配置，尝试获取Self-RAG验证配置
        if hierarchical_config and hasattr(hierarchical_config, 'self_rag_validation'):
            validation_config = hierarchical_config.self_rag_validation
            if hasattr(validation_config, 'confidence_threshold'):
                self.confidence_threshold = validation_config.confidence_threshold
            if hasattr(validation_config, 'validation_timeout'):
                self.validation_timeout = validation_config.validation_timeout
        
        # 异步处理流水线
        self.validation_queue = asyncio.Queue()
        self.result_queue = asyncio.Queue()
        self.processing_semaphore = asyncio.Semaphore(self.max_concurrent_validations)
        
        # 性能指标
        self.metrics = {
            "validations_performed": 0,
            "false_positives_filtered": 0,
            "average_confidence": 0.0,
            "validation_time": 0.0,
            "pipeline_throughput": 0.0,
            "integration_calls": 0
        }
        
        # 流水线状态
        self.pipeline_active = False
        self.pipeline_tasks = []
        
        logger.info(f"Self-RAG验证器初始化完成")
        logger.info(f"配置 - 置信度阈值: {self.confidence_threshold}, 超时: {self.validation_timeout}s")
        logger.info(f"配置 - 最大并发: {self.max_concurrent_validations}")
        logger.info(f"已集成现有self_rag系统: {type(self.self_rag_instance).__name__}")
    
    def get_validation_model(self) -> str:
        """获取验证模型"""
        return self.validation_model
    
    def get_cross_validation_models(self) -> List[str]:
        """获取交叉验证模型列表"""
        return self.cross_validation_models
    
    async def _call_validation_model(self, prompt: str, **kwargs) -> str:
        """调用验证模型"""
        start_time = time.time()
        
        try:
            from auditluma.utils import init_llm_client
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            
            logger.info(f"✅ Self-RAG验证层 - 调用主验证模型: {self.validation_model}")
            logger.debug(f"验证提示长度: {len(prompt)} 字符")
            
            # 使用配置的验证模型
            llm_client = init_llm_client(self.validation_model)
            response = await llm_client.generate_async(prompt, **kwargs)
            
            execution_time = time.time() - start_time
            
            # 记录模型使用
            model_usage_logger.log_model_usage(
                layer="self_rag_validation",
                component="SelfRAGValidator",
                model_name=self.validation_model,
                operation="validation",
                input_size=len(prompt),
                output_size=len(response),
                execution_time=execution_time,
                success=True
            )
            
            logger.info(f"✅ Self-RAG验证层 - 主验证模型 {self.validation_model} 调用成功，响应长度: {len(response)} 字符")
            return response
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # 记录失败的模型使用
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            model_usage_logger.log_model_usage(
                layer="self_rag_validation",
                component="SelfRAGValidator",
                model_name=self.validation_model,
                operation="validation",
                input_size=len(prompt),
                output_size=0,
                execution_time=execution_time,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"❌ Self-RAG验证层 - 调用主验证模型 {self.validation_model} 失败: {e}")
            return ""
    
    async def _call_cross_validation_models(self, prompt: str, **kwargs) -> List[str]:
        """调用交叉验证模型"""
        try:
            from auditluma.utils import init_llm_client
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            
            logger.info(f"✅ Self-RAG验证层 - 开始交叉验证，使用 {len(self.cross_validation_models)} 个模型")
            logger.debug(f"交叉验证模型列表: {self.cross_validation_models}")
            
            responses = []
            for i, model in enumerate(self.cross_validation_models, 1):
                start_time = time.time()
                
                try:
                    logger.info(f"✅ Self-RAG验证层 - 调用交叉验证模型 {i}/{len(self.cross_validation_models)}: {model}")
                    
                    llm_client = init_llm_client(model)
                    response = await llm_client.generate_async(prompt, **kwargs)
                    responses.append(response)
                    
                    execution_time = time.time() - start_time
                    
                    # 记录成功的模型使用
                    model_usage_logger.log_model_usage(
                        layer="self_rag_validation",
                        component="SelfRAGValidator",
                        model_name=model,
                        operation="cross_validation",
                        input_size=len(prompt),
                        output_size=len(response),
                        execution_time=execution_time,
                        success=True,
                        metadata={"model_index": i, "total_models": len(self.cross_validation_models)}
                    )
                    
                    logger.info(f"✅ Self-RAG验证层 - 交叉验证模型 {model} 调用成功，响应长度: {len(response)} 字符")
                    
                except Exception as e:
                    execution_time = time.time() - start_time
                    
                    # 记录失败的模型使用
                    model_usage_logger.log_model_usage(
                        layer="self_rag_validation",
                        component="SelfRAGValidator",
                        model_name=model,
                        operation="cross_validation",
                        input_size=len(prompt),
                        output_size=0,
                        execution_time=execution_time,
                        success=False,
                        error_message=str(e),
                        metadata={"model_index": i, "total_models": len(self.cross_validation_models)}
                    )
                    
                    logger.warning(f"⚠️ Self-RAG验证层 - 交叉验证模型 {model} 调用失败: {e}")
                    continue
            
            logger.info(f"✅ Self-RAG验证层 - 交叉验证完成，成功获得 {len(responses)}/{len(self.cross_validation_models)} 个响应")
            return responses
            
        except Exception as e:
            logger.error(f"❌ Self-RAG验证层 - 调用交叉验证模型失败: {e}")
            return []
    
    async def validate_vulnerability(self, vulnerability: VulnerabilityResult) -> ValidationResult:
        """验证漏洞 - 主要接口方法"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            logger.debug(f"开始Self-RAG验证: {vulnerability.id}")
            
            # 1. 假阳性过滤
            filter_result = await self.false_positive_filter.check_false_positive(
                vulnerability
            )
            
            if filter_result.is_false_positive:
                self.metrics["false_positives_filtered"] += 1
                return ValidationResult(
                    is_valid=False,
                    confidence_score=0.0,
                    validation_methods=[ValidationMethod.PATTERN_MATCHING],
                    rejection_reason=filter_result.explanation,
                    metadata={"filtered_as_false_positive": True}
                )
            
            # 2. 交叉验证
            cross_validation_score, cross_validation_metadata = await asyncio.wait_for(
                self.cross_validator.cross_validate(vulnerability),
                timeout=self.validation_timeout
            )
            
            # 3. 置信度计算
            confidence_score = await self.confidence_calculator.calculate_confidence(
                vulnerability, cross_validation_metadata
            )
            
            # 4. 综合判断
            is_valid = confidence_score >= self.confidence_threshold
            
            # 5. 构建验证结果
            validation_methods = [
                ValidationMethod.CROSS_VALIDATION,
                ValidationMethod.CONFIDENCE_ANALYSIS,
                ValidationMethod.PATTERN_MATCHING
            ]
            
            metadata = {
                "cross_validation": cross_validation_metadata,
                "confidence_breakdown": {
                    "cross_validation_score": cross_validation_score,
                    "final_confidence": confidence_score,
                    "threshold": self.confidence_threshold
                },
                "validation_time": asyncio.get_event_loop().time() - start_time
            }
            
            # 更新性能指标
            self._update_metrics(confidence_score, metadata["validation_time"])
            
            result = ValidationResult(
                is_valid=is_valid,
                confidence_score=confidence_score,
                validation_methods=validation_methods,
                rejection_reason=None if is_valid else f"置信度 {confidence_score:.2f} 低于阈值 {self.confidence_threshold}",
                metadata=metadata
            )
            
            logger.debug(f"Self-RAG验证完成: {vulnerability.id}, 有效: {is_valid}, 置信度: {confidence_score:.2f}")
            return result
            
        except asyncio.TimeoutError:
            logger.warning(f"Self-RAG验证超时: {vulnerability.id}")
            return ValidationResult(
                is_valid=False,
                confidence_score=0.0,
                validation_methods=[],
                rejection_reason="验证超时",
                metadata={"timeout": True}
            )
            
        except Exception as e:
            logger.error(f"Self-RAG验证失败: {vulnerability.id}, {e}")
            return ValidationResult(
                is_valid=True,  # 验证失败时默认通过，避免漏掉真实漏洞
                confidence_score=0.5,
                validation_methods=[],
                rejection_reason=None,
                metadata={"validation_error": str(e)}
            )
    
    async def batch_validate(self, vulnerabilities: List[VulnerabilityResult],
                           max_concurrency: int = 10) -> List[ValidationResult]:
        """批量验证漏洞"""
        logger.info(f"开始批量Self-RAG验证，漏洞数: {len(vulnerabilities)}")
        
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def validate_single(vuln):
            async with semaphore:
                return await self.validate_vulnerability(vuln)
        
        # 并发验证
        validation_tasks = [validate_single(vuln) for vuln in vulnerabilities]
        results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        # 处理异常结果
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量验证中的异常: {vulnerabilities[i].id}, {result}")
                # 创建默认结果
                final_results.append(ValidationResult(
                    is_valid=True,
                    confidence_score=0.5,
                    validation_methods=[],
                    rejection_reason=None,
                    metadata={"batch_validation_error": str(result)}
                ))
            else:
                final_results.append(result)
        
        # 统计结果
        valid_count = sum(1 for r in final_results if r.is_valid)
        avg_confidence = sum(r.confidence_score for r in final_results) / len(final_results)
        
        logger.info(f"批量Self-RAG验证完成，有效漏洞: {valid_count}/{len(vulnerabilities)}, 平均置信度: {avg_confidence:.2f}")
        
        return final_results
    
    async def learn_from_feedback(self, vulnerability: VulnerabilityResult,
                                validation_result: ValidationResult,
                                actual_result: bool, feedback: str):
        """从反馈中学习"""
        logger.info(f"接收验证反馈: {vulnerability.id}, 实际结果: {actual_result}")
        
        # 如果预测错误，学习假阳性模式
        if validation_result.is_valid and not actual_result:
            await self.false_positive_filter.learn_from_feedback(
                vulnerability, True, feedback
            )
        
        # 更新置信度计算器的历史准确性数据
        # 这里可以实现更复杂的学习逻辑
        
        logger.info(f"反馈学习完成: {vulnerability.id}")
    
    def _update_metrics(self, confidence_score: float, validation_time: float):
        """更新性能指标"""
        self.metrics["validations_performed"] += 1
        
        # 更新平均置信度
        total_validations = self.metrics["validations_performed"]
        current_avg = self.metrics["average_confidence"]
        self.metrics["average_confidence"] = (
            (current_avg * (total_validations - 1) + confidence_score) / total_validations
        )
        
        # 更新平均验证时间
        current_avg_time = self.metrics["validation_time"]
        self.metrics["validation_time"] = (
            (current_avg_time * (total_validations - 1) + validation_time) / total_validations
        )
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """获取验证统计信息"""
        base_stats = self.metrics.copy()
        
        # 添加假阳性过滤器统计
        fp_stats = self.false_positive_filter.get_filter_statistics()
        base_stats["false_positive_patterns"] = fp_stats
        
        # 计算过滤率
        if base_stats["validations_performed"] > 0:
            base_stats["false_positive_rate"] = (
                base_stats["false_positives_filtered"] / base_stats["validations_performed"]
            )
        else:
            base_stats["false_positive_rate"] = 0.0
        
        return base_stats
    
    def update_configuration(self, new_config: Dict[str, Any]):
        """更新配置"""
        if "confidence_threshold" in new_config:
            self.confidence_threshold = new_config["confidence_threshold"]
            logger.info(f"更新置信度阈值: {self.confidence_threshold}")
        
        if "validation_timeout" in new_config:
            self.validation_timeout = new_config["validation_timeout"]
            logger.info(f"更新验证超时时间: {self.validation_timeout}")
    
    async def start_validation_pipeline(self):
        """启动验证处理流水线"""
        if self.pipeline_active:
            logger.warning("验证流水线已经在运行")
            return
        
        self.pipeline_active = True
        logger.info("启动Self-RAG验证处理流水线")
        
        # 启动处理任务
        self.pipeline_tasks = [
            asyncio.create_task(self._validation_worker(f"worker-{i}"))
            for i in range(self.max_concurrent_validations)
        ]
        
        logger.info(f"已启动 {len(self.pipeline_tasks)} 个验证工作进程")
    
    async def stop_validation_pipeline(self):
        """停止验证处理流水线"""
        if not self.pipeline_active:
            return
        
        logger.info("停止Self-RAG验证处理流水线")
        self.pipeline_active = False
        
        # 取消所有工作任务
        for task in self.pipeline_tasks:
            task.cancel()
        
        # 等待任务完成
        await asyncio.gather(*self.pipeline_tasks, return_exceptions=True)
        self.pipeline_tasks.clear()
        
        logger.info("验证处理流水线已停止")
    
    async def _validation_worker(self, worker_id: str):
        """验证工作进程"""
        logger.debug(f"验证工作进程启动: {worker_id}")
        
        try:
            while self.pipeline_active:
                try:
                    # 从队列获取验证任务
                    validation_task = await asyncio.wait_for(
                        self.validation_queue.get(), timeout=1.0
                    )
                    
                    # 执行验证
                    result = await self._process_validation_task(validation_task)
                    
                    # 将结果放入结果队列
                    await self.result_queue.put(result)
                    
                    # 标记任务完成
                    self.validation_queue.task_done()
                    
                except asyncio.TimeoutError:
                    # 队列为空，继续等待
                    continue
                except Exception as e:
                    logger.error(f"验证工作进程 {worker_id} 出错: {e}")
                    continue
        
        except asyncio.CancelledError:
            logger.debug(f"验证工作进程 {worker_id} 被取消")
        except Exception as e:
            logger.error(f"验证工作进程 {worker_id} 异常退出: {e}")
    
    async def _process_validation_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """处理单个验证任务"""
        vulnerability = task['vulnerability']
        enhanced_context = task.get('enhanced_context')
        knowledge = task.get('knowledge')
        
        async with self.processing_semaphore:
            # 执行验证
            validation_result = await self.validate_vulnerability(vulnerability)
            
            return {
                'task_id': task.get('task_id'),
                'vulnerability_id': vulnerability.id,
                'validation_result': validation_result,
                'enhanced_context': enhanced_context,
                'knowledge': knowledge
            }
    
    async def validate_with_self_rag_integration(self, 
                                               vulnerability: VulnerabilityResult,
                                               enhanced_context: Optional[EnhancedContext] = None,
                                               knowledge: Optional[VulnerabilityKnowledge] = None) -> ValidationResult:
        """与现有self_rag系统集成的验证方法"""
        start_time = time.time()
        
        try:
            logger.debug(f"开始Self-RAG集成验证: {vulnerability.id}")
            
            # 1. 使用self_rag检索相关知识（如果没有提供）
            if knowledge is None:
                knowledge = await self._retrieve_knowledge_with_self_rag(vulnerability)
            
            # 2. 增强上下文信息（如果没有提供）
            if enhanced_context is None:
                enhanced_context = await self._enhance_context_with_self_rag(vulnerability)
            
            # 3. 执行标准验证流程
            validation_result = await self.validate_vulnerability(vulnerability)
            
            # 4. 使用self_rag的知识进行额外验证
            rag_validation = await self._validate_with_rag_knowledge(
                vulnerability, knowledge, enhanced_context
            )
            
            # 5. 整合验证结果
            final_result = self._integrate_validation_results(
                validation_result, rag_validation, enhanced_context, knowledge
            )
            
            # 更新集成调用指标
            self.metrics["integration_calls"] += 1
            integration_time = time.time() - start_time
            
            logger.debug(f"Self-RAG集成验证完成: {vulnerability.id}, 耗时: {integration_time:.2f}s")
            
            return final_result
            
        except Exception as e:
            logger.error(f"Self-RAG集成验证失败: {vulnerability.id}, {e}")
            # 回退到标准验证
            return await self.validate_vulnerability(vulnerability)
    
    async def _retrieve_knowledge_with_self_rag(self, 
                                              vulnerability: VulnerabilityResult) -> VulnerabilityKnowledge:
        """使用self_rag检索漏洞相关知识"""
        try:
            # 构建查询字符串
            query = f"{vulnerability.vulnerability_type} {vulnerability.description}"
            
            # 使用self_rag检索相关文档
            retrieved_docs = await self.self_rag_instance.retrieve(query, k=5)
            
            # 转换为VulnerabilityKnowledge格式
            knowledge = VulnerabilityKnowledge()
            
            for doc, score in retrieved_docs:
                # 根据文档元数据类型分类
                metadata = doc.metadata
                if metadata.get('type') == 'cve':
                    # 处理CVE信息
                    pass
                elif metadata.get('type') == 'best_practice':
                    # 处理最佳实践
                    pass
                elif metadata.get('type') == 'historical_case':
                    # 处理历史案例
                    pass
                
                # 记录相关性分数
                knowledge.relevance_scores[doc.id] = score
            
            knowledge.source_queries = [query]
            
            return knowledge
            
        except Exception as e:
            logger.warning(f"使用self_rag检索知识失败: {e}")
            return VulnerabilityKnowledge()
    
    async def _enhance_context_with_self_rag(self, 
                                           vulnerability: VulnerabilityResult) -> EnhancedContext:
        """使用self_rag增强上下文信息"""
        try:
            # 构建上下文查询
            context_query = f"context analysis {vulnerability.file_path} {vulnerability.snippet[:100]}"
            
            # 检索相关上下文
            context_docs = await self.self_rag_instance.retrieve(context_query, k=3)
            
            # 构建增强上下文
            enhanced_context = EnhancedContext()
            
            # 从检索结果中提取上下文信息
            for doc, score in context_docs:
                metadata = doc.metadata
                if metadata.get('file_path') == vulnerability.file_path:
                    # 同文件的上下文信息
                    enhanced_context.semantic_context.related_code_blocks.append(doc.content)
                    enhanced_context.semantic_context.semantic_similarity_scores[doc.id] = score
            
            enhanced_context.completeness_score = min(1.0, len(context_docs) / 3.0)
            
            return enhanced_context
            
        except Exception as e:
            logger.warning(f"使用self_rag增强上下文失败: {e}")
            return EnhancedContext()
    
    async def _validate_with_rag_knowledge(self, 
                                         vulnerability: VulnerabilityResult,
                                         knowledge: VulnerabilityKnowledge,
                                         enhanced_context: EnhancedContext) -> Dict[str, Any]:
        """使用RAG知识进行验证"""
        rag_validation = {
            'knowledge_relevance': 0.0,
            'context_support': 0.0,
            'historical_accuracy': 0.0,
            'overall_rag_confidence': 0.0
        }
        
        try:
            # 1. 评估知识相关性
            if knowledge.relevance_scores:
                rag_validation['knowledge_relevance'] = max(knowledge.relevance_scores.values())
            
            # 2. 评估上下文支持度
            if enhanced_context.semantic_context.semantic_similarity_scores:
                rag_validation['context_support'] = max(
                    enhanced_context.semantic_context.semantic_similarity_scores.values()
                )
            
            # 3. 评估历史准确性
            if knowledge.historical_cases:
                avg_similarity = sum(case.similarity_score for case in knowledge.historical_cases) / len(knowledge.historical_cases)
                rag_validation['historical_accuracy'] = avg_similarity
            
            # 4. 计算整体RAG置信度
            scores = [v for v in rag_validation.values() if v > 0]
            if scores:
                rag_validation['overall_rag_confidence'] = sum(scores) / len(scores)
            
        except Exception as e:
            logger.warning(f"RAG知识验证失败: {e}")
        
        return rag_validation
    
    def _integrate_validation_results(self, 
                                    standard_result: ValidationResult,
                                    rag_validation: Dict[str, Any],
                                    enhanced_context: EnhancedContext,
                                    knowledge: VulnerabilityKnowledge) -> ValidationResult:
        """整合标准验证和RAG验证结果"""
        # 计算整合后的置信度
        standard_confidence = standard_result.confidence_score
        rag_confidence = rag_validation.get('overall_rag_confidence', 0.0)
        
        # 加权平均（标准验证权重0.7，RAG验证权重0.3）
        integrated_confidence = standard_confidence * 0.7 + rag_confidence * 0.3
        
        # 更新验证方法列表
        validation_methods = standard_result.validation_methods.copy()
        if rag_confidence > 0:
            validation_methods.append(ValidationMethod.HISTORICAL_COMPARISON)
        
        # 更新元数据
        integrated_metadata = standard_result.metadata.copy()
        integrated_metadata.update({
            'rag_validation': rag_validation,
            'enhanced_context_completeness': enhanced_context.completeness_score,
            'knowledge_sources': len(knowledge.cve_info) + len(knowledge.best_practices) + len(knowledge.historical_cases),
            'integration_method': 'weighted_average'
        })
        
        # 重新评估有效性
        is_valid = integrated_confidence >= self.confidence_threshold
        
        return ValidationResult(
            is_valid=is_valid,
            confidence_score=integrated_confidence,
            validation_methods=validation_methods,
            rejection_reason=standard_result.rejection_reason if not is_valid else None,
            metadata=integrated_metadata
        )
    
    async def batch_validate_with_pipeline(self, 
                                         vulnerabilities: List[VulnerabilityResult],
                                         enhanced_contexts: Optional[List[EnhancedContext]] = None,
                                         knowledge_list: Optional[List[VulnerabilityKnowledge]] = None) -> List[ValidationResult]:
        """使用流水线进行批量验证"""
        if not self.pipeline_active:
            await self.start_validation_pipeline()
        
        logger.info(f"开始流水线批量验证，漏洞数: {len(vulnerabilities)}")
        
        # 准备验证任务
        tasks = []
        for i, vulnerability in enumerate(vulnerabilities):
            task = {
                'task_id': f"batch_{i}",
                'vulnerability': vulnerability,
                'enhanced_context': enhanced_contexts[i] if enhanced_contexts else None,
                'knowledge': knowledge_list[i] if knowledge_list else None
            }
            tasks.append(task)
        
        # 将任务加入队列
        for task in tasks:
            await self.validation_queue.put(task)
        
        # 收集结果
        results = []
        for _ in range(len(tasks)):
            result = await self.result_queue.get()
            results.append(result['validation_result'])
        
        # 按原始顺序排序结果
        results.sort(key=lambda x: int(x.metadata.get('task_id', '0').split('_')[1]))
        
        logger.info(f"流水线批量验证完成，结果数: {len(results)}")
        return results
    
    async def cleanup(self):
        """清理资源"""
        logger.info("开始清理Self-RAG验证器资源")
        
        # 停止验证流水线
        await self.stop_validation_pipeline()
        
        # 保存学习到的假阳性模式
        try:
            fp_stats = self.false_positive_filter.get_filter_statistics()
            logger.info(f"保存假阳性模式统计: {fp_stats['total_patterns']}个模式")
        except Exception as e:
            logger.warning(f"保存假阳性模式失败: {e}")
        
        # 清理缓存
        self.validation_queue = asyncio.Queue()
        self.result_queue = asyncio.Queue()
        
        logger.info("Self-RAG验证器清理完成")