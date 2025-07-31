"""
Haystack主编排框架 - 层级RAG架构第一层
负责任务分发、流程编排和结果汇总
"""

import asyncio
import uuid
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
from pathlib import Path

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult
from auditluma.rag.txtai_retriever import TxtaiRetriever
from auditluma.rag.r2r_enhancer import R2REnhancer
from auditluma.rag.self_rag_validator import SelfRAGValidator
from auditluma.orchestrator.task_decomposer import TaskDecomposer, TaskCollection
from auditluma.orchestrator.parallel_executor import ParallelProcessingManager, TaskScheduler
from auditluma.orchestrator.result_integrator import ResultIntegrator, ConflictResolutionStrategy


# Import data structures from task_decomposer
from auditluma.orchestrator.task_decomposer import TaskType, AuditTask


@dataclass
class TaskResult:
    """任务执行结果"""
    task_id: str
    task_type: TaskType
    vulnerabilities: List[VulnerabilityResult]
    execution_time: float
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditResult:
    """综合审计结果"""
    vulnerabilities: List[VulnerabilityResult]
    task_results: List[TaskResult]
    execution_summary: Dict[str, Any]
    confidence_score: float
    processing_time: float


class HaystackOrchestrator:
    """Haystack主编排器 - 层级RAG架构的核心编排组件"""
    
    def __init__(self, workers: int = 10):
        """初始化编排器"""
        self.workers = workers
        self.task_queue = asyncio.Queue()
        self.result_queue = asyncio.Queue()
        
        # 初始化各层组件
        self.txtai_retriever = TxtaiRetriever()
        self.r2r_enhancer = R2REnhancer()
        self.self_rag_validator = SelfRAGValidator()
        
        # 初始化任务分解器、并行执行器和结果整合器
        self.task_decomposer = TaskDecomposer()
        self.parallel_executor = ParallelProcessingManager(max_workers=workers)
        self.task_scheduler = TaskScheduler()
        self.result_integrator = ResultIntegrator()
        
        # 任务执行器映射
        from auditluma.orchestrator.task_decomposer import TaskType
        self.task_executors = {
            TaskType.SYNTAX_CHECK: self._execute_syntax_check,
            TaskType.LOGIC_ANALYSIS: self._execute_logic_analysis,
            TaskType.SECURITY_SCAN: self._execute_security_scan,
            TaskType.DEPENDENCY_ANALYSIS: self._execute_dependency_analysis
        }
        
        # 性能监控
        self.performance_metrics = {
            "tasks_completed": 0,
            "total_execution_time": 0.0,
            "layer_performance": {
                "txtai": {"calls": 0, "total_time": 0.0},
                "r2r": {"calls": 0, "total_time": 0.0},
                "self_rag": {"calls": 0, "total_time": 0.0}
            }
        }
        
        # 兼容性支持 - 模拟AgentOrchestrator的属性
        self.agents = {}
        self.code_units = []
        
        logger.info(f"Haystack编排器初始化完成，工作线程数: {workers}")
    
    async def orchestrate_audit(self, source_files: List[SourceFile]) -> AuditResult:
        """主编排流程 - 执行完整的层级RAG审计"""
        start_time = time.time()
        logger.info(f"🚀 开始Haystack层级RAG审计，文件数: {len(source_files)}")
        
        try:
            # 1. 任务分解
            task_collection = await self._decompose_audit_tasks(source_files)
            logger.info(f"📋 任务分解完成，生成 {len(task_collection)} 个审计任务")
            
            # 2. 并行执行各类任务
            task_results = await self._execute_tasks_parallel(task_collection.tasks)
            logger.info(f"⚡ 并行任务执行完成，获得 {len(task_results)} 个结果")
            
            # 3. 收集所有漏洞
            all_vulnerabilities = []
            for result in task_results:
                all_vulnerabilities.extend(result.vulnerabilities)
            
            # 4. txtai层：知识检索增强
            enhanced_vulnerabilities = await self._apply_txtai_enhancement(all_vulnerabilities)
            logger.info(f"🔍 txtai知识检索完成，增强了 {len(enhanced_vulnerabilities)} 个漏洞")
            
            # 5. R2R层：上下文增强
            context_enhanced_vulnerabilities = await self._apply_r2r_enhancement(
                enhanced_vulnerabilities, source_files
            )
            logger.info(f"🔗 R2R上下文增强完成，处理了 {len(context_enhanced_vulnerabilities)} 个漏洞")
            
            # 6. Self-RAG层：验证与过滤
            validated_vulnerabilities = await self._apply_self_rag_validation(
                context_enhanced_vulnerabilities
            )
            logger.info(f"✅ Self-RAG验证完成，验证了 {len(validated_vulnerabilities)} 个漏洞")
            
            # 7. 结果整合
            audit_result = await self._integrate_results(
                validated_vulnerabilities, task_results, start_time
            )
            
            # 8. 更新性能指标
            self._update_performance_metrics(audit_result.processing_time)
            
            logger.info(f"🎉 Haystack层级RAG审计完成，耗时: {audit_result.processing_time:.2f}秒")
            logger.info(f"📊 发现漏洞: {len(audit_result.vulnerabilities)}，置信度: {audit_result.confidence_score:.2f}")
            
            # 9. 输出模型使用统计
            try:
                from auditluma.monitoring.model_usage_logger import model_usage_logger
                logger.info("📊 生成模型使用统计摘要...")
                model_usage_logger.print_session_summary()
            except Exception as e:
                logger.warning(f"生成模型使用统计失败: {e}")
            
            return audit_result
            
        except Exception as e:
            logger.error(f"❌ Haystack编排过程中出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise
    
    async def _decompose_audit_tasks(self, source_files: List[SourceFile]) -> TaskCollection:
        """任务分解 - 使用专门的任务分解器"""
        return await self.task_decomposer.decompose_audit_tasks(source_files)
    
    async def _execute_tasks_parallel(self, tasks: List[AuditTask]) -> List[TaskResult]:
        """并行执行任务 - 使用专门的并行执行引擎"""
        if not tasks:
            return []
        
        # 调度任务执行顺序
        scheduled_tasks = self.task_scheduler.schedule_tasks(
            TaskCollection(tasks=tasks), strategy="hybrid"
        )
        
        # 创建任务执行器
        async def task_executor_wrapper(task: AuditTask):
            """任务执行器包装"""
            try:
                executor = self.task_executors[task.task_type]
                vulnerabilities = await executor(task)
                
                confidence = self._calculate_task_confidence(task, vulnerabilities)
                
                return TaskResult(
                    task_id=task.id,
                    task_type=task.task_type,
                    vulnerabilities=vulnerabilities,
                    execution_time=0.0,  # 将由并行执行器计算
                    confidence=confidence,
                    metadata=task.metadata
                )
            except Exception as e:
                logger.error(f"任务执行失败: {task.id}, {e}")
                return TaskResult(
                    task_id=task.id,
                    task_type=task.task_type,
                    vulnerabilities=[],
                    execution_time=0.0,
                    confidence=0.0,
                    metadata={"error": str(e)}
                )
        
        # 使用并行执行引擎执行任务
        execution_result = await self.parallel_executor.execute_tasks(
            scheduled_tasks, task_executor_wrapper
        )
        
        # 转换执行结果为TaskResult列表
        task_results = []
        for task_execution in execution_result.task_executions:
            if task_execution.result and isinstance(task_execution.result, TaskResult):
                # 更新执行时间
                task_execution.result.execution_time = task_execution.execution_time
                task_results.append(task_execution.result)
            else:
                # 创建失败的TaskResult
                task_result = TaskResult(
                    task_id=task_execution.task.id,
                    task_type=task_execution.task.task_type,
                    vulnerabilities=[],
                    execution_time=task_execution.execution_time,
                    confidence=0.0,
                    metadata={
                        "status": task_execution.status.value,
                        "error": str(task_execution.error) if task_execution.error else None,
                        "retry_count": task_execution.retry_count,
                        "worker_id": task_execution.worker_id
                    }
                )
                task_results.append(task_result)
        
        # 记录并行执行统计
        logger.info(f"并行执行统计: 成功 {execution_result.successful_tasks}, "
                   f"失败 {execution_result.failed_tasks}, "
                   f"超时 {execution_result.timeout_tasks}")
        
        return task_results
    
    async def _apply_txtai_enhancement(self, vulnerabilities: List[VulnerabilityResult]) -> List[VulnerabilityResult]:
        """应用txtai层知识检索增强"""
        start_time = time.time()
        
        enhanced_vulnerabilities = []
        for vuln in vulnerabilities:
            try:
                # 使用txtai检索相关知识
                knowledge_info = await self.txtai_retriever.retrieve_vulnerability_info(
                    vuln.vulnerability_type, vuln.snippet
                )
                
                # 增强漏洞信息
                enhanced_vuln = await self.txtai_retriever.enhance_vulnerability(
                    vuln, knowledge_info
                )
                enhanced_vulnerabilities.append(enhanced_vuln)
                
            except Exception as e:
                logger.warning(f"txtai增强失败: {vuln.id}, {e}")
                enhanced_vulnerabilities.append(vuln)  # 保留原始漏洞
        
        # 更新性能指标
        execution_time = time.time() - start_time
        self.performance_metrics["layer_performance"]["txtai"]["calls"] += 1
        self.performance_metrics["layer_performance"]["txtai"]["total_time"] += execution_time
        
        return enhanced_vulnerabilities
    
    async def _apply_r2r_enhancement(self, vulnerabilities: List[VulnerabilityResult], 
                                   source_files: List[SourceFile]) -> List[VulnerabilityResult]:
        """应用R2R层上下文增强"""
        start_time = time.time()
        
        # 构建全局上下文
        global_context = await self.r2r_enhancer.build_global_context(source_files)
        
        enhanced_vulnerabilities = []
        for vuln in vulnerabilities:
            try:
                # 增强代码上下文
                enhanced_context = await self.r2r_enhancer.enhance_context(
                    vuln, global_context
                )
                
                # 应用上下文增强
                enhanced_vuln = await self.r2r_enhancer.apply_context_enhancement(
                    vuln, enhanced_context
                )
                enhanced_vulnerabilities.append(enhanced_vuln)
                
            except Exception as e:
                logger.warning(f"R2R增强失败: {vuln.id}, {e}")
                enhanced_vulnerabilities.append(vuln)  # 保留原始漏洞
        
        # 更新性能指标
        execution_time = time.time() - start_time
        self.performance_metrics["layer_performance"]["r2r"]["calls"] += 1
        self.performance_metrics["layer_performance"]["r2r"]["total_time"] += execution_time
        
        return enhanced_vulnerabilities
    
    async def _apply_self_rag_validation(self, vulnerabilities: List[VulnerabilityResult]) -> List[VulnerabilityResult]:
        """应用Self-RAG层验证与过滤"""
        start_time = time.time()
        
        validated_vulnerabilities = []
        for vuln in vulnerabilities:
            try:
                # 执行验证
                validation_result = await self.self_rag_validator.validate_vulnerability(vuln)
                
                if validation_result.is_valid:
                    # 更新置信度和验证信息
                    vuln.confidence = validation_result.confidence_score
                    vuln.validation_metadata = validation_result.metadata
                    validated_vulnerabilities.append(vuln)
                else:
                    logger.debug(f"漏洞被Self-RAG过滤: {vuln.id}, 原因: {validation_result.rejection_reason}")
                
            except Exception as e:
                logger.warning(f"Self-RAG验证失败: {vuln.id}, {e}")
                validated_vulnerabilities.append(vuln)  # 保留原始漏洞
        
        # 更新性能指标
        execution_time = time.time() - start_time
        self.performance_metrics["layer_performance"]["self_rag"]["calls"] += 1
        self.performance_metrics["layer_performance"]["self_rag"]["total_time"] += execution_time
        
        return validated_vulnerabilities
    
    async def _integrate_results(self, vulnerabilities: List[VulnerabilityResult], 
                               task_results: List[TaskResult], start_time: float) -> AuditResult:
        """结果整合 - 使用专门的结果整合器"""
        processing_time = time.time() - start_time
        
        # 使用结果整合器进行智能整合
        integration_result = await self.result_integrator.integrate_results(
            task_results, ConflictResolutionStrategy.CONSENSUS
        )
        
        # 使用整合后的漏洞
        final_vulnerabilities = integration_result.integrated_vulnerabilities
        
        # 计算综合置信度
        if final_vulnerabilities:
            confidence_score = sum(v.confidence for v in final_vulnerabilities) / len(final_vulnerabilities)
        else:
            confidence_score = 1.0
        
        # 生成执行摘要
        execution_summary = {
            "total_tasks": len(task_results),
            "successful_tasks": len([r for r in task_results if not r.metadata.get("error")]),
            "total_vulnerabilities": len(final_vulnerabilities),
            "original_vulnerabilities": len(vulnerabilities),
            "duplicate_count": integration_result.duplicate_count,
            "conflict_count": integration_result.conflict_count,
            "processing_time": processing_time,
            "integration_time": integration_result.processing_time,
            "layer_performance": self.performance_metrics["layer_performance"],
            "task_breakdown": {
                task_type.value: len([r for r in task_results if r.task_type == task_type])
                for task_type in TaskType
            },
            "quality_metrics": integration_result.quality_metrics,
            "integration_metadata": integration_result.integration_metadata
        }
        
        return AuditResult(
            vulnerabilities=final_vulnerabilities,
            task_results=task_results,
            execution_summary=execution_summary,
            confidence_score=confidence_score,
            processing_time=processing_time
        )
    
    # 任务执行器实现
    async def _execute_syntax_check(self, task: AuditTask) -> List[VulnerabilityResult]:
        """执行语法检查任务"""
        # 这里可以集成现有的语法检查逻辑
        # 或者调用专门的语法检查代理
        vulnerabilities = []
        
        for code_unit in task.code_units:
            # 简化的语法检查逻辑
            if await self._has_syntax_issues(code_unit):
                vuln = VulnerabilityResult(
                    id=f"syntax_{uuid.uuid4().hex[:8]}",
                    vulnerability_type="Syntax Error",
                    severity="low",
                    description="代码语法问题",
                    file_path=str(code_unit.source_file.path),
                    start_line=code_unit.start_line,
                    end_line=code_unit.end_line,
                    snippet=code_unit.content[:200],
                    confidence=0.9
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _execute_logic_analysis(self, task: AuditTask) -> List[VulnerabilityResult]:
        """执行逻辑分析任务"""
        # 集成现有的逻辑分析功能
        from auditluma.agents.security_analyst import SecurityAnalystAgent
        
        agent = SecurityAnalystAgent(f"logic_analyst_{uuid.uuid4().hex[:6]}")
        await agent.start()
        
        vulnerabilities = []
        for code_unit in task.code_units:
            try:
                task_data = {
                    "code_unit": code_unit,
                    "analysis_type": "logic_analysis"
                }
                unit_vulns = await agent.execute_task("analyze_code_logic", task_data)
                vulnerabilities.extend(unit_vulns)
            except Exception as e:
                logger.warning(f"逻辑分析失败: {code_unit.id}, {e}")
        
        return vulnerabilities
    
    async def _execute_security_scan(self, task: AuditTask) -> List[VulnerabilityResult]:
        """执行安全扫描任务"""
        # 集成现有的安全扫描功能
        from auditluma.agents.security_analyst import SecurityAnalystAgent
        
        agent = SecurityAnalystAgent(f"security_analyst_{uuid.uuid4().hex[:6]}")
        await agent.start()
        
        vulnerabilities = []
        for code_unit in task.code_units:
            try:
                task_data = {
                    "code_unit": code_unit,
                    "analysis_type": "security_scan"
                }
                unit_vulns = await agent.execute_task("analyze_code_security", task_data)
                vulnerabilities.extend(unit_vulns)
            except Exception as e:
                logger.warning(f"安全扫描失败: {code_unit.id}, {e}")
        
        return vulnerabilities
    
    async def _execute_dependency_analysis(self, task: AuditTask) -> List[VulnerabilityResult]:
        """执行依赖分析任务"""
        # 集成现有的依赖分析功能
        from auditluma.agents.code_analyzer import CodeAnalyzerAgent
        
        agent = CodeAnalyzerAgent(f"dependency_analyzer_{uuid.uuid4().hex[:6]}")
        await agent.start()
        
        vulnerabilities = []
        try:
            task_data = {
                "code_units": task.code_units,
                "analysis_type": "dependency_analysis"
            }
            vulnerabilities = await agent.execute_task("analyze_dependencies", task_data)
        except Exception as e:
            logger.warning(f"依赖分析失败: {task.id}, {e}")
        
        return vulnerabilities
    
    # 辅助方法
    async def _extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """提取代码单元"""
        # 集成现有的代码单元提取逻辑
        from auditluma.parsers.code_parser import CodeParser
        
        code_units = []
        parser = CodeParser()
        
        for source_file in source_files:
            try:
                file_units = await parser.parse_file_async(source_file)
                code_units.extend(file_units)
            except Exception as e:
                logger.warning(f"解析文件失败: {source_file.path}, {e}")
        
        return code_units
    

    
    def _calculate_task_confidence(self, task: AuditTask, vulnerabilities: List[VulnerabilityResult]) -> float:
        """计算任务置信度"""
        if not vulnerabilities:
            return 1.0
        
        # 基于漏洞数量和类型计算置信度
        base_confidence = 0.8
        
        # 根据任务类型调整
        type_multipliers = {
            TaskType.SYNTAX_CHECK: 0.95,
            TaskType.LOGIC_ANALYSIS: 0.85,
            TaskType.SECURITY_SCAN: 0.80,
            TaskType.DEPENDENCY_ANALYSIS: 0.90
        }
        
        multiplier = type_multipliers.get(task.task_type, 0.8)
        return min(1.0, base_confidence * multiplier)
    
    async def _has_syntax_issues(self, code_unit: CodeUnit) -> bool:
        """检查代码单元是否有语法问题"""
        # 简化的语法检查逻辑
        content = code_unit.content
        
        # 检查常见语法问题
        syntax_issues = [
            'SyntaxError',
            'IndentationError',
            'TabError',
            'unexpected EOF',
            'invalid syntax'
        ]
        
        return any(issue in content for issue in syntax_issues)
    
    def _update_performance_metrics(self, processing_time: float):
        """更新性能指标"""
        self.performance_metrics["tasks_completed"] += 1
        self.performance_metrics["total_execution_time"] += processing_time
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """获取性能摘要"""
        total_tasks = self.performance_metrics["tasks_completed"]
        if total_tasks == 0:
            return {"message": "尚未执行任何任务"}
        
        avg_execution_time = self.performance_metrics["total_execution_time"] / total_tasks
        
        layer_summary = {}
        for layer, metrics in self.performance_metrics["layer_performance"].items():
            if metrics["calls"] > 0:
                layer_summary[layer] = {
                    "calls": metrics["calls"],
                    "avg_time": metrics["total_time"] / metrics["calls"],
                    "total_time": metrics["total_time"]
                }
        
        return {
            "total_tasks_completed": total_tasks,
            "average_execution_time": avg_execution_time,
            "total_execution_time": self.performance_metrics["total_execution_time"],
            "layer_performance": layer_summary
        }
    
    # ==================== 兼容性接口 ====================
    # 以下方法提供与现有AgentOrchestrator的兼容性
    
    async def initialize_agents(self) -> None:
        """初始化智能体 - 兼容性方法"""
        logger.info("Haystack编排器：智能体初始化（兼容性模式）")
        # Haystack编排器使用内置的层级组件，不需要单独的智能体
        # 但为了兼容性，我们模拟智能体的存在
        self.agents = {
            "haystack_orchestrator": self,
            "txtai_retriever": self.txtai_retriever,
            "r2r_enhancer": self.r2r_enhancer,
            "self_rag_validator": self.self_rag_validator
        }
        logger.info(f"Haystack编排器：已初始化 {len(self.agents)} 个组件")
    
    async def extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """提取代码单元 - 兼容性方法"""
        logger.info(f"Haystack编排器：提取代码单元，文件数: {len(source_files)}")
        self.code_units = await self._extract_code_units(source_files)
        return self.code_units
    
    async def run_security_analysis(self, source_files: List[SourceFile], 
                                   skip_cross_file: bool = False, 
                                   enhanced_analysis: bool = False) -> List[VulnerabilityResult]:
        """运行安全分析 - 兼容性方法，使用层级RAG架构"""
        logger.info(f"Haystack编排器：开始层级RAG安全分析，文件数: {len(source_files)}")
        
        try:
            # 使用层级RAG架构进行完整审计
            audit_result = await self.orchestrate_audit(source_files)
            
            logger.info(f"Haystack编排器：层级RAG分析完成，发现漏洞: {len(audit_result.vulnerabilities)}")
            return audit_result.vulnerabilities
            
        except Exception as e:
            logger.error(f"Haystack编排器：安全分析失败: {e}")
            return []
    
    async def run_code_structure_analysis(self, code_units: List[CodeUnit]) -> Dict[str, Any]:
        """运行代码结构分析 - 兼容性方法"""
        logger.info(f"Haystack编排器：代码结构分析，代码单元数: {len(code_units)}")
        
        # 在Haystack架构中，结构分析是任务分解的一部分
        structure_info = {
            "total_units": len(code_units),
            "unit_types": {},
            "file_distribution": {},
            "complexity_metrics": {}
        }
        
        # 统计代码单元类型
        for unit in code_units:
            unit_type = getattr(unit, 'type', 'unknown')
            structure_info["unit_types"][unit_type] = structure_info["unit_types"].get(unit_type, 0) + 1
            
            file_path = str(unit.source_file.path)
            structure_info["file_distribution"][file_path] = structure_info["file_distribution"].get(file_path, 0) + 1
        
        logger.info(f"Haystack编排器：结构分析完成，单元类型: {len(structure_info['unit_types'])}")
        return structure_info
    
    async def generate_remediations(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """生成修复建议 - 兼容性方法"""
        logger.info(f"Haystack编排器：生成修复建议，漏洞数: {len(vulnerabilities)}")
        
        if not vulnerabilities:
            return {
                "summary": "未发现需要修复的漏洞",
                "remediation_count": 0,
                "remediations": []
            }
        
        # 在层级RAG架构中，修复建议可以通过txtai层获取
        remediations = []
        
        for vuln in vulnerabilities:
            try:
                # 使用txtai检索修复建议
                remediation_info = await self.txtai_retriever.get_remediation_suggestions(
                    vuln.vulnerability_type, vuln.description
                )
                
                remediation = {
                    "vulnerability_id": vuln.id,
                    "vulnerability_type": vuln.vulnerability_type,
                    "suggestions": remediation_info.get("suggestions", []),
                    "best_practices": remediation_info.get("best_practices", []),
                    "code_examples": remediation_info.get("code_examples", [])
                }
                remediations.append(remediation)
                
            except Exception as e:
                logger.warning(f"生成修复建议失败: {vuln.id}, {e}")
                # 提供基本的修复建议
                remediation = {
                    "vulnerability_id": vuln.id,
                    "vulnerability_type": vuln.vulnerability_type,
                    "suggestions": [f"请修复 {vuln.vulnerability_type} 漏洞"],
                    "best_practices": ["遵循安全编码规范"],
                    "code_examples": []
                }
                remediations.append(remediation)
        
        return {
            "summary": f"为 {len(vulnerabilities)} 个漏洞生成了修复建议",
            "remediation_count": len(remediations),
            "remediations": remediations
        }
    
    async def run_analysis(self, source_files: List[SourceFile]) -> List[VulnerabilityResult]:
        """运行分析 - 兼容性方法，直接调用层级RAG架构"""
        logger.info(f"Haystack编排器：运行完整分析，文件数: {len(source_files)}")
        return await self.run_security_analysis(source_files)
    
    async def generate_summary(self, vulnerabilities: List[VulnerabilityResult], 
                             assessment: Dict[str, Any] = None) -> str:
        """生成摘要 - 兼容性方法"""
        if not vulnerabilities:
            return "未发现安全漏洞。"
        
        # 按严重程度分类
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # 按类型分类
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        # 生成摘要
        summary_parts = [
            f"🔍 Haystack层级RAG安全分析摘要",
            f"📊 发现漏洞总数: {len(vulnerabilities)}",
            "",
            "📈 严重程度分布:"
        ]
        
        for severity, count in sorted(severity_counts.items()):
            summary_parts.append(f"  - {severity}: {count}")
        
        summary_parts.extend([
            "",
            "🏷️ 漏洞类型分布:"
        ])
        
        for vuln_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            summary_parts.append(f"  - {vuln_type}: {count}")
        
        # 添加性能信息
        perf_summary = self.get_performance_summary()
        if "total_tasks_completed" in perf_summary:
            summary_parts.extend([
                "",
                "⚡ 性能指标:",
                f"  - 完成任务数: {perf_summary['total_tasks_completed']}",
                f"  - 平均执行时间: {perf_summary.get('average_execution_time', 0):.2f}秒"
            ])
        
        return "\n".join(summary_parts)
    
    async def generate_audit_report(self, audit_result: AuditResult) -> str:
        """生成详细的审计报告"""
        try:
            # 使用结果整合器生成报告
            integration_result_mock = type('IntegrationResult', (), {
                'integrated_vulnerabilities': audit_result.vulnerabilities,
                'duplicate_count': audit_result.execution_summary.get('duplicate_count', 0),
                'conflict_count': audit_result.execution_summary.get('conflict_count', 0),
                'clusters': [],
                'integration_metadata': audit_result.execution_summary.get('integration_metadata', {}),
                'quality_metrics': audit_result.execution_summary.get('quality_metrics', {}),
                'processing_time': audit_result.processing_time
            })()
            
            report = await self.result_integrator.generate_audit_report(
                integration_result_mock, audit_result.task_results
            )
            
            # 格式化报告
            report_text = f"""
{report.title}
{'=' * len(report.title)}

生成时间: {report.generated_at}
报告ID: {report.report_id}
处理时间: {report.processing_time:.2f}秒

{report.summary}

"""
            
            for section in report.sections:
                report_text += f"""
{section.title}
{'-' * len(section.title)}
{section.content}

"""
            
            if report.recommendations:
                report_text += """
建议
----
"""
                for i, rec in enumerate(report.recommendations, 1):
                    report_text += f"{i}. {rec}\n"
            
            return report_text
            
        except Exception as e:
            logger.error(f"生成审计报告失败: {e}")
            return self.generate_summary(audit_result.vulnerabilities, audit_result.execution_summary)