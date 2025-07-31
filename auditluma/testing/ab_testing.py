"""
A/B测试框架 - 用于对比传统RAG和层级RAG架构的性能和质量
支持自动化测试、统计分析和报告生成
"""

import asyncio
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
import statistics
from datetime import datetime, timedelta
import concurrent.futures

from loguru import logger

from auditluma.models.code import SourceFile, VulnerabilityResult
from auditluma.config import Config


class TestGroup(Enum):
    """测试组类型"""
    CONTROL = "control"  # 对照组（传统RAG）
    TREATMENT = "treatment"  # 实验组（层级RAG）


class TestMetric(Enum):
    """测试指标"""
    PROCESSING_TIME = "processing_time"
    VULNERABILITY_COUNT = "vulnerability_count"
    ACCURACY_SCORE = "accuracy_score"
    CONFIDENCE_SCORE = "confidence_score"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    THROUGHPUT = "throughput"


class TestStatus(Enum):
    """测试状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TestResult:
    """单次测试结果"""
    test_id: str
    group: TestGroup
    architecture: str  # "traditional" or "hierarchical"
    source_files: List[str]  # 文件路径列表
    vulnerabilities: List[VulnerabilityResult]
    metrics: Dict[TestMetric, float]
    execution_time: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class ABTestConfig:
    """A/B测试配置"""
    test_name: str
    description: str
    sample_size: int = 100  # 每组的样本数量
    confidence_level: float = 0.95  # 置信水平
    min_effect_size: float = 0.1  # 最小效应大小
    max_duration_hours: int = 24  # 最大测试时长
    parallel_executions: int = 5  # 并行执行数
    metrics_to_track: List[TestMetric] = field(default_factory=lambda: [
        TestMetric.PROCESSING_TIME,
        TestMetric.VULNERABILITY_COUNT,
        TestMetric.ACCURACY_SCORE,
        TestMetric.CONFIDENCE_SCORE
    ])
    enable_detailed_logging: bool = False
    save_intermediate_results: bool = True


@dataclass
class StatisticalResult:
    """统计分析结果"""
    metric: TestMetric
    control_mean: float
    treatment_mean: float
    control_std: float
    treatment_std: float
    effect_size: float
    p_value: float
    confidence_interval: Tuple[float, float]
    is_significant: bool
    statistical_power: float


@dataclass
class ABTestReport:
    """A/B测试报告"""
    test_id: str
    test_name: str
    start_time: datetime
    end_time: datetime
    total_duration: timedelta
    control_results: List[TestResult]
    treatment_results: List[TestResult]
    statistical_results: List[StatisticalResult]
    summary: Dict[str, Any]
    recommendations: List[str]
    raw_data_path: Optional[str] = None


class ABTestFramework:
    """A/B测试框架主类"""
    
    def __init__(self, results_dir: str = "./results/ab_testing"):
        """初始化A/B测试框架
        
        Args:
            results_dir: 结果保存目录
        """
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # 测试状态
        self.current_tests: Dict[str, Dict[str, Any]] = {}
        self.completed_tests: List[str] = []
        
        # 编排器实例
        self._traditional_orchestrator = None
        self._hierarchical_orchestrator = None
        
        # 性能监控
        self.performance_monitor = PerformanceMonitor()
        
        logger.info(f"A/B测试框架初始化完成，结果目录: {self.results_dir}")
    
    async def initialize_orchestrators(self) -> None:
        """初始化两种架构的编排器"""
        try:
            # 初始化传统编排器
            from auditluma.orchestrator import AgentOrchestrator
            self._traditional_orchestrator = AgentOrchestrator(workers=10)
            await self._traditional_orchestrator.initialize_agents()
            logger.info("传统编排器初始化完成")
            
            # 初始化层级编排器
            from auditluma.orchestrator.haystack_orchestrator import HaystackOrchestrator
            self._hierarchical_orchestrator = HaystackOrchestrator(workers=10)
            logger.info("层级编排器初始化完成")
            
        except Exception as e:
            logger.error(f"编排器初始化失败: {e}")
            raise
    
    async def run_ab_test(self, test_config: ABTestConfig, 
                         test_data: List[List[SourceFile]]) -> ABTestReport:
        """运行A/B测试
        
        Args:
            test_config: 测试配置
            test_data: 测试数据集，每个元素是一组源文件
            
        Returns:
            A/B测试报告
        """
        test_id = f"ab_test_{uuid.uuid4().hex[:8]}"
        start_time = datetime.now()
        
        logger.info(f"开始A/B测试: {test_config.test_name} (ID: {test_id})")
        
        # 注册测试
        self.current_tests[test_id] = {
            "config": test_config,
            "status": TestStatus.RUNNING,
            "start_time": start_time,
            "progress": {"control": 0, "treatment": 0}
        }
        
        try:
            # 确保编排器已初始化
            if not self._traditional_orchestrator or not self._hierarchical_orchestrator:
                await self.initialize_orchestrators()
            
            # 准备测试数据
            control_data, treatment_data = self._prepare_test_data(
                test_data, test_config.sample_size
            )
            
            # 并行运行两组测试
            control_task = asyncio.create_task(
                self._run_test_group(
                    test_id, TestGroup.CONTROL, control_data, test_config
                )
            )
            treatment_task = asyncio.create_task(
                self._run_test_group(
                    test_id, TestGroup.TREATMENT, treatment_data, test_config
                )
            )
            
            # 等待两组测试完成
            control_results, treatment_results = await asyncio.gather(
                control_task, treatment_task, return_exceptions=True
            )
            
            # 检查是否有异常
            if isinstance(control_results, Exception):
                raise control_results
            if isinstance(treatment_results, Exception):
                raise treatment_results
            
            # 执行统计分析
            statistical_results = self._perform_statistical_analysis(
                control_results, treatment_results, test_config
            )
            
            # 生成报告
            end_time = datetime.now()
            report = ABTestReport(
                test_id=test_id,
                test_name=test_config.test_name,
                start_time=start_time,
                end_time=end_time,
                total_duration=end_time - start_time,
                control_results=control_results,
                treatment_results=treatment_results,
                statistical_results=statistical_results,
                summary=self._generate_summary(control_results, treatment_results, statistical_results),
                recommendations=self._generate_recommendations(statistical_results)
            )
            
            # 保存结果
            await self._save_test_results(report)
            
            # 更新测试状态
            self.current_tests[test_id]["status"] = TestStatus.COMPLETED
            self.completed_tests.append(test_id)
            
            logger.info(f"A/B测试完成: {test_id}，耗时: {report.total_duration}")
            
            return report
            
        except Exception as e:
            logger.error(f"A/B测试失败: {e}")
            self.current_tests[test_id]["status"] = TestStatus.FAILED
            raise
    
    def _prepare_test_data(self, test_data: List[List[SourceFile]], 
                          sample_size: int) -> Tuple[List[List[SourceFile]], List[List[SourceFile]]]:
        """准备测试数据，确保两组数据相同"""
        # 限制样本大小
        limited_data = test_data[:sample_size * 2]  # 确保有足够的数据
        
        # 随机打乱并分组
        import random
        random.shuffle(limited_data)
        
        mid_point = len(limited_data) // 2
        control_data = limited_data[:mid_point]
        treatment_data = limited_data[mid_point:mid_point * 2]
        
        # 确保两组数据大小相等
        min_size = min(len(control_data), len(treatment_data), sample_size)
        control_data = control_data[:min_size]
        treatment_data = treatment_data[:min_size]
        
        logger.info(f"测试数据准备完成: 对照组 {len(control_data)} 个样本, 实验组 {len(treatment_data)} 个样本")
        
        return control_data, treatment_data
    
    async def _run_test_group(self, test_id: str, group: TestGroup, 
                            test_data: List[List[SourceFile]], 
                            config: ABTestConfig) -> List[TestResult]:
        """运行单个测试组"""
        results = []
        orchestrator = (
            self._traditional_orchestrator if group == TestGroup.CONTROL 
            else self._hierarchical_orchestrator
        )
        architecture = "traditional" if group == TestGroup.CONTROL else "hierarchical"
        
        logger.info(f"开始运行{group.value}组测试，样本数: {len(test_data)}")
        
        # 创建信号量控制并发数
        semaphore = asyncio.Semaphore(config.parallel_executions)
        
        async def run_single_test(source_files: List[SourceFile], index: int) -> TestResult:
            async with semaphore:
                return await self._execute_single_test(
                    test_id, group, architecture, source_files, orchestrator, index
                )
        
        # 创建所有测试任务
        tasks = [
            run_single_test(source_files, i) 
            for i, source_files in enumerate(test_data)
        ]
        
        # 执行测试并收集结果
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果和异常
        for i, result in enumerate(completed_results):
            if isinstance(result, Exception):
                logger.error(f"{group.value}组测试 {i} 失败: {result}")
                # 创建失败的测试结果
                failed_result = TestResult(
                    test_id=f"{test_id}_{group.value}_{i}",
                    group=group,
                    architecture=architecture,
                    source_files=[str(f.path) for f in test_data[i]],
                    vulnerabilities=[],
                    metrics={},
                    execution_time=0.0,
                    timestamp=datetime.now(),
                    errors=[str(result)]
                )
                results.append(failed_result)
            else:
                results.append(result)
            
            # 更新进度
            self.current_tests[test_id]["progress"][group.value] = len(results)
        
        logger.info(f"{group.value}组测试完成，成功: {len([r for r in results if not r.errors])}, "
                   f"失败: {len([r for r in results if r.errors])}")
        
        return results
    
    async def _execute_single_test(self, test_id: str, group: TestGroup, 
                                 architecture: str, source_files: List[SourceFile],
                                 orchestrator: Any, index: int) -> TestResult:
        """执行单个测试"""
        single_test_id = f"{test_id}_{group.value}_{index}"
        start_time = time.time()
        timestamp = datetime.now()
        
        try:
            # 开始性能监控
            self.performance_monitor.start_monitoring(single_test_id)
            
            # 执行安全分析
            if architecture == "hierarchical":
                # 层级架构使用orchestrate_audit
                audit_result = await orchestrator.orchestrate_audit(source_files)
                vulnerabilities = audit_result.vulnerabilities
                execution_metadata = audit_result.execution_summary
            else:
                # 传统架构使用run_security_analysis
                vulnerabilities = await orchestrator.run_security_analysis(source_files)
                execution_metadata = {}
            
            execution_time = time.time() - start_time
            
            # 停止性能监控并获取指标
            performance_metrics = self.performance_monitor.stop_monitoring(single_test_id)
            
            # 计算测试指标
            metrics = self._calculate_test_metrics(
                vulnerabilities, execution_time, performance_metrics, execution_metadata
            )
            
            # 创建测试结果
            result = TestResult(
                test_id=single_test_id,
                group=group,
                architecture=architecture,
                source_files=[str(f.path) for f in source_files],
                vulnerabilities=vulnerabilities,
                metrics=metrics,
                execution_time=execution_time,
                timestamp=timestamp,
                metadata={
                    "file_count": len(source_files),
                    "total_lines": sum(getattr(f, 'line_count', 0) for f in source_files),
                    "execution_metadata": execution_metadata,
                    "performance_metrics": performance_metrics
                }
            )
            
            logger.debug(f"测试 {single_test_id} 完成，耗时: {execution_time:.2f}秒，"
                        f"发现漏洞: {len(vulnerabilities)}")
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"测试 {single_test_id} 执行失败: {e}")
            
            return TestResult(
                test_id=single_test_id,
                group=group,
                architecture=architecture,
                source_files=[str(f.path) for f in source_files],
                vulnerabilities=[],
                metrics={},
                execution_time=execution_time,
                timestamp=timestamp,
                errors=[str(e)]
            )
    
    def _calculate_test_metrics(self, vulnerabilities: List[VulnerabilityResult],
                              execution_time: float, performance_metrics: Dict[str, Any],
                              execution_metadata: Dict[str, Any]) -> Dict[TestMetric, float]:
        """计算测试指标"""
        metrics = {}
        
        # 基本指标
        metrics[TestMetric.PROCESSING_TIME] = execution_time
        metrics[TestMetric.VULNERABILITY_COUNT] = len(vulnerabilities)
        
        # 置信度分数
        if vulnerabilities:
            confidence_scores = [v.confidence for v in vulnerabilities if hasattr(v, 'confidence')]
            if confidence_scores:
                metrics[TestMetric.CONFIDENCE_SCORE] = statistics.mean(confidence_scores)
            else:
                metrics[TestMetric.CONFIDENCE_SCORE] = 0.0
        else:
            metrics[TestMetric.CONFIDENCE_SCORE] = 1.0  # 没有漏洞时置信度为1
        
        # 准确性分数（基于置信度和漏洞类型分布）
        if vulnerabilities:
            # 简化的准确性计算：基于高置信度漏洞的比例
            high_confidence_vulns = [
                v for v in vulnerabilities 
                if hasattr(v, 'confidence') and v.confidence > 0.8
            ]
            metrics[TestMetric.ACCURACY_SCORE] = len(high_confidence_vulns) / len(vulnerabilities)
        else:
            metrics[TestMetric.ACCURACY_SCORE] = 1.0
        
        # 假阳性率（简化计算）
        if vulnerabilities:
            # 基于低置信度漏洞估算假阳性率
            low_confidence_vulns = [
                v for v in vulnerabilities 
                if hasattr(v, 'confidence') and v.confidence < 0.5
            ]
            metrics[TestMetric.FALSE_POSITIVE_RATE] = len(low_confidence_vulns) / len(vulnerabilities)
        else:
            metrics[TestMetric.FALSE_POSITIVE_RATE] = 0.0
        
        # 性能指标
        if performance_metrics:
            metrics[TestMetric.MEMORY_USAGE] = performance_metrics.get("peak_memory_mb", 0.0)
            metrics[TestMetric.CPU_USAGE] = performance_metrics.get("avg_cpu_percent", 0.0)
        
        # 吞吐量（每秒处理的文件数）
        if execution_time > 0:
            file_count = execution_metadata.get("file_count", 1)
            metrics[TestMetric.THROUGHPUT] = file_count / execution_time
        else:
            metrics[TestMetric.THROUGHPUT] = 0.0
        
        return metrics
    
    def _perform_statistical_analysis(self, control_results: List[TestResult],
                                    treatment_results: List[TestResult],
                                    config: ABTestConfig) -> List[StatisticalResult]:
        """执行统计分析"""
        statistical_results = []
        
        for metric in config.metrics_to_track:
            try:
                # 提取指标数据
                control_values = [
                    r.metrics.get(metric, 0.0) for r in control_results 
                    if not r.errors and metric in r.metrics
                ]
                treatment_values = [
                    r.metrics.get(metric, 0.0) for r in treatment_results 
                    if not r.errors and metric in r.metrics
                ]
                
                if len(control_values) < 2 or len(treatment_values) < 2:
                    logger.warning(f"指标 {metric.value} 的样本数量不足，跳过统计分析")
                    continue
                
                # 计算基本统计量
                control_mean = statistics.mean(control_values)
                treatment_mean = statistics.mean(treatment_values)
                control_std = statistics.stdev(control_values) if len(control_values) > 1 else 0.0
                treatment_std = statistics.stdev(treatment_values) if len(treatment_values) > 1 else 0.0
                
                # 计算效应大小（Cohen's d）
                pooled_std = ((control_std ** 2 + treatment_std ** 2) / 2) ** 0.5
                effect_size = (treatment_mean - control_mean) / pooled_std if pooled_std > 0 else 0.0
                
                # 执行t检验
                p_value, confidence_interval = self._perform_t_test(
                    control_values, treatment_values, config.confidence_level
                )
                
                # 判断显著性
                alpha = 1 - config.confidence_level
                is_significant = p_value < alpha and abs(effect_size) >= config.min_effect_size
                
                # 计算统计功效（简化）
                statistical_power = self._calculate_statistical_power(
                    len(control_values), len(treatment_values), effect_size, alpha
                )
                
                statistical_result = StatisticalResult(
                    metric=metric,
                    control_mean=control_mean,
                    treatment_mean=treatment_mean,
                    control_std=control_std,
                    treatment_std=treatment_std,
                    effect_size=effect_size,
                    p_value=p_value,
                    confidence_interval=confidence_interval,
                    is_significant=is_significant,
                    statistical_power=statistical_power
                )
                
                statistical_results.append(statistical_result)
                
                logger.info(f"指标 {metric.value}: 对照组均值={control_mean:.4f}, "
                           f"实验组均值={treatment_mean:.4f}, 效应大小={effect_size:.4f}, "
                           f"p值={p_value:.4f}, 显著性={is_significant}")
                
            except Exception as e:
                logger.error(f"指标 {metric.value} 的统计分析失败: {e}")
        
        return statistical_results
    
    def _perform_t_test(self, control_values: List[float], treatment_values: List[float],
                       confidence_level: float) -> Tuple[float, Tuple[float, float]]:
        """执行t检验"""
        try:
            import scipy.stats as stats
            
            # 执行独立样本t检验
            t_stat, p_value = stats.ttest_ind(control_values, treatment_values)
            
            # 计算置信区间
            control_mean = statistics.mean(control_values)
            treatment_mean = statistics.mean(treatment_values)
            diff_mean = treatment_mean - control_mean
            
            # 简化的置信区间计算
            pooled_se = (
                (statistics.variance(control_values) / len(control_values) +
                 statistics.variance(treatment_values) / len(treatment_values)) ** 0.5
            )
            
            alpha = 1 - confidence_level
            df = len(control_values) + len(treatment_values) - 2
            t_critical = stats.t.ppf(1 - alpha/2, df)
            
            margin_error = t_critical * pooled_se
            confidence_interval = (diff_mean - margin_error, diff_mean + margin_error)
            
            return abs(p_value), confidence_interval
            
        except ImportError:
            logger.warning("scipy不可用，使用简化的统计检验")
            # 简化的统计检验
            control_mean = statistics.mean(control_values)
            treatment_mean = statistics.mean(treatment_values)
            
            # 简化的p值估算
            diff = abs(treatment_mean - control_mean)
            pooled_std = (statistics.stdev(control_values) + statistics.stdev(treatment_values)) / 2
            z_score = diff / (pooled_std / (len(control_values) ** 0.5)) if pooled_std > 0 else 0
            
            # 粗略的p值估算
            if z_score > 2.58:  # 99%置信水平
                p_value = 0.01
            elif z_score > 1.96:  # 95%置信水平
                p_value = 0.05
            elif z_score > 1.64:  # 90%置信水平
                p_value = 0.10
            else:
                p_value = 0.5
            
            # 简化的置信区间
            margin = 1.96 * pooled_std / (len(control_values) ** 0.5)
            diff_mean = treatment_mean - control_mean
            confidence_interval = (diff_mean - margin, diff_mean + margin)
            
            return p_value, confidence_interval
    
    def _calculate_statistical_power(self, n1: int, n2: int, effect_size: float, alpha: float) -> float:
        """计算统计功效"""
        try:
            import scipy.stats as stats
            
            # 简化的功效计算
            pooled_n = (n1 + n2) / 2
            ncp = effect_size * (pooled_n ** 0.5)  # 非中心参数
            
            # 临界值
            t_critical = stats.t.ppf(1 - alpha/2, n1 + n2 - 2)
            
            # 功效计算（简化）
            power = 1 - stats.t.cdf(t_critical, n1 + n2 - 2, ncp)
            return max(0.0, min(1.0, power))
            
        except ImportError:
            # 简化的功效估算
            if abs(effect_size) > 0.8:  # 大效应
                return 0.9
            elif abs(effect_size) > 0.5:  # 中等效应
                return 0.7
            elif abs(effect_size) > 0.2:  # 小效应
                return 0.5
            else:
                return 0.3
    
    def _generate_summary(self, control_results: List[TestResult],
                         treatment_results: List[TestResult],
                         statistical_results: List[StatisticalResult]) -> Dict[str, Any]:
        """生成测试摘要"""
        # 基本统计
        control_success = len([r for r in control_results if not r.errors])
        treatment_success = len([r for r in treatment_results if not r.errors])
        
        # 显著性结果统计
        significant_improvements = [
            r for r in statistical_results 
            if r.is_significant and r.treatment_mean > r.control_mean
        ]
        significant_degradations = [
            r for r in statistical_results 
            if r.is_significant and r.treatment_mean < r.control_mean
        ]
        
        # 性能对比
        control_avg_time = statistics.mean([
            r.execution_time for r in control_results if not r.errors
        ]) if control_success > 0 else 0.0
        
        treatment_avg_time = statistics.mean([
            r.execution_time for r in treatment_results if not r.errors
        ]) if treatment_success > 0 else 0.0
        
        return {
            "test_execution": {
                "control_samples": len(control_results),
                "treatment_samples": len(treatment_results),
                "control_success_rate": control_success / len(control_results) if control_results else 0,
                "treatment_success_rate": treatment_success / len(treatment_results) if treatment_results else 0
            },
            "performance_comparison": {
                "control_avg_time": control_avg_time,
                "treatment_avg_time": treatment_avg_time,
                "time_improvement_percent": (
                    ((control_avg_time - treatment_avg_time) / control_avg_time * 100)
                    if control_avg_time > 0 else 0
                )
            },
            "statistical_significance": {
                "total_metrics_tested": len(statistical_results),
                "significant_improvements": len(significant_improvements),
                "significant_degradations": len(significant_degradations),
                "improvement_metrics": [r.metric.value for r in significant_improvements],
                "degradation_metrics": [r.metric.value for r in significant_degradations]
            },
            "effect_sizes": {
                r.metric.value: r.effect_size for r in statistical_results
            }
        }
    
    def _generate_recommendations(self, statistical_results: List[StatisticalResult]) -> List[str]:
        """生成建议"""
        recommendations = []
        
        # 分析显著改进
        significant_improvements = [
            r for r in statistical_results 
            if r.is_significant and r.treatment_mean > r.control_mean
        ]
        
        if significant_improvements:
            recommendations.append(
                f"层级RAG架构在以下指标上显著优于传统架构: "
                f"{', '.join([r.metric.value for r in significant_improvements])}"
            )
        
        # 分析显著退化
        significant_degradations = [
            r for r in statistical_results 
            if r.is_significant and r.treatment_mean < r.control_mean
        ]
        
        if significant_degradations:
            recommendations.append(
                f"层级RAG架构在以下指标上显著劣于传统架构: "
                f"{', '.join([r.metric.value for r in significant_degradations])}"
            )
        
        # 性能建议
        processing_time_result = next(
            (r for r in statistical_results if r.metric == TestMetric.PROCESSING_TIME), None
        )
        if processing_time_result:
            if processing_time_result.is_significant:
                if processing_time_result.treatment_mean < processing_time_result.control_mean:
                    recommendations.append("建议采用层级RAG架构以提高处理速度")
                else:
                    recommendations.append("传统架构在处理速度上更有优势")
            else:
                recommendations.append("两种架构在处理速度上无显著差异")
        
        # 质量建议
        accuracy_result = next(
            (r for r in statistical_results if r.metric == TestMetric.ACCURACY_SCORE), None
        )
        if accuracy_result and accuracy_result.is_significant:
            if accuracy_result.treatment_mean > accuracy_result.control_mean:
                recommendations.append("层级RAG架构在准确性上有显著提升")
            else:
                recommendations.append("需要进一步优化层级RAG架构的准确性")
        
        # 统计功效建议
        low_power_metrics = [r for r in statistical_results if r.statistical_power < 0.8]
        if low_power_metrics:
            recommendations.append(
                f"以下指标的统计功效较低，建议增加样本量: "
                f"{', '.join([r.metric.value for r in low_power_metrics])}"
            )
        
        if not recommendations:
            recommendations.append("两种架构在测试指标上无显著差异，可根据其他因素选择")
        
        return recommendations
    
    async def _save_test_results(self, report: ABTestReport) -> None:
        """保存测试结果"""
        try:
            # 保存详细报告
            report_file = self.results_dir / f"{report.test_id}_report.json"
            
            # 序列化报告（处理datetime和enum）
            report_dict = self._serialize_report(report)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_dict, f, indent=2, ensure_ascii=False)
            
            # 保存原始数据
            raw_data_file = self.results_dir / f"{report.test_id}_raw_data.json"
            raw_data = {
                "control_results": [self._serialize_test_result(r) for r in report.control_results],
                "treatment_results": [self._serialize_test_result(r) for r in report.treatment_results]
            }
            
            with open(raw_data_file, 'w', encoding='utf-8') as f:
                json.dump(raw_data, f, indent=2, ensure_ascii=False)
            
            report.raw_data_path = str(raw_data_file)
            
            logger.info(f"测试结果已保存: {report_file}")
            
        except Exception as e:
            logger.error(f"保存测试结果失败: {e}")
    
    def _serialize_report(self, report: ABTestReport) -> Dict[str, Any]:
        """序列化报告"""
        return {
            "test_id": report.test_id,
            "test_name": report.test_name,
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat(),
            "total_duration_seconds": report.total_duration.total_seconds(),
            "control_results_count": len(report.control_results),
            "treatment_results_count": len(report.treatment_results),
            "statistical_results": [
                {
                    "metric": r.metric.value,
                    "control_mean": r.control_mean,
                    "treatment_mean": r.treatment_mean,
                    "control_std": r.control_std,
                    "treatment_std": r.treatment_std,
                    "effect_size": r.effect_size,
                    "p_value": r.p_value,
                    "confidence_interval": r.confidence_interval,
                    "is_significant": r.is_significant,
                    "statistical_power": r.statistical_power
                }
                for r in report.statistical_results
            ],
            "summary": report.summary,
            "recommendations": report.recommendations,
            "raw_data_path": report.raw_data_path
        }
    
    def _serialize_test_result(self, result: TestResult) -> Dict[str, Any]:
        """序列化测试结果"""
        return {
            "test_id": result.test_id,
            "group": result.group.value,
            "architecture": result.architecture,
            "source_files": result.source_files,
            "vulnerability_count": len(result.vulnerabilities),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.vulnerability_type,
                    "severity": getattr(v, 'severity', 'unknown'),
                    "confidence": getattr(v, 'confidence', 0.0),
                    "file_path": v.file_path,
                    "line_range": f"{v.start_line}-{v.end_line}"
                }
                for v in result.vulnerabilities
            ],
            "metrics": {metric.value: value for metric, value in result.metrics.items()},
            "execution_time": result.execution_time,
            "timestamp": result.timestamp.isoformat(),
            "metadata": result.metadata,
            "errors": result.errors
        }
    
    def get_test_status(self, test_id: str) -> Optional[Dict[str, Any]]:
        """获取测试状态"""
        return self.current_tests.get(test_id)
    
    def list_completed_tests(self) -> List[str]:
        """列出已完成的测试"""
        return self.completed_tests.copy()
    
    async def load_test_report(self, test_id: str) -> Optional[ABTestReport]:
        """加载测试报告"""
        try:
            report_file = self.results_dir / f"{test_id}_report.json"
            if not report_file.exists():
                return None
            
            with open(report_file, 'r', encoding='utf-8') as f:
                report_dict = json.load(f)
            
            # 反序列化报告（简化版本）
            return self._deserialize_report(report_dict)
            
        except Exception as e:
            logger.error(f"加载测试报告失败: {e}")
            return None
    
    def _deserialize_report(self, report_dict: Dict[str, Any]) -> ABTestReport:
        """反序列化报告（简化版本）"""
        # 这里只返回基本信息，完整的反序列化需要更多工作
        return ABTestReport(
            test_id=report_dict["test_id"],
            test_name=report_dict["test_name"],
            start_time=datetime.fromisoformat(report_dict["start_time"]),
            end_time=datetime.fromisoformat(report_dict["end_time"]),
            total_duration=timedelta(seconds=report_dict["total_duration_seconds"]),
            control_results=[],  # 简化，不加载详细结果
            treatment_results=[],  # 简化，不加载详细结果
            statistical_results=[],  # 简化，不加载统计结果
            summary=report_dict["summary"],
            recommendations=report_dict["recommendations"],
            raw_data_path=report_dict.get("raw_data_path")
        )


class PerformanceMonitor:
    """性能监控器"""
    
    def __init__(self):
        self.monitoring_sessions: Dict[str, Dict[str, Any]] = {}
    
    def start_monitoring(self, session_id: str) -> None:
        """开始监控"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        self.monitoring_sessions[session_id] = {
            "start_time": time.time(),
            "start_memory": process.memory_info().rss / 1024 / 1024,  # MB
            "start_cpu": process.cpu_percent(),
            "peak_memory": process.memory_info().rss / 1024 / 1024,
            "cpu_samples": [process.cpu_percent()]
        }
    
    def stop_monitoring(self, session_id: str) -> Dict[str, Any]:
        """停止监控并返回指标"""
        if session_id not in self.monitoring_sessions:
            return {}
        
        try:
            import psutil
            import os
            
            session = self.monitoring_sessions[session_id]
            process = psutil.Process(os.getpid())
            
            end_time = time.time()
            end_memory = process.memory_info().rss / 1024 / 1024
            
            metrics = {
                "duration": end_time - session["start_time"],
                "start_memory_mb": session["start_memory"],
                "end_memory_mb": end_memory,
                "peak_memory_mb": session["peak_memory"],
                "memory_delta_mb": end_memory - session["start_memory"],
                "avg_cpu_percent": statistics.mean(session["cpu_samples"]) if session["cpu_samples"] else 0.0
            }
            
            del self.monitoring_sessions[session_id]
            return metrics
            
        except Exception as e:
            logger.warning(f"性能监控失败: {e}")
            return {}


# ==================== 便捷函数 ====================

async def run_simple_ab_test(test_data: List[List[SourceFile]], 
                            test_name: str = "Simple A/B Test",
                            sample_size: int = 50) -> ABTestReport:
    """运行简单的A/B测试"""
    framework = ABTestFramework()
    
    config = ABTestConfig(
        test_name=test_name,
        description="简单的传统RAG vs 层级RAG对比测试",
        sample_size=sample_size,
        parallel_executions=3
    )
    
    return await framework.run_ab_test(config, test_data)


def create_test_config(test_name: str, **kwargs) -> ABTestConfig:
    """创建测试配置"""
    return ABTestConfig(
        test_name=test_name,
        description=kwargs.get("description", "A/B测试"),
        sample_size=kwargs.get("sample_size", 100),
        confidence_level=kwargs.get("confidence_level", 0.95),
        min_effect_size=kwargs.get("min_effect_size", 0.1),
        max_duration_hours=kwargs.get("max_duration_hours", 24),
        parallel_executions=kwargs.get("parallel_executions", 5),
        metrics_to_track=kwargs.get("metrics_to_track", [
            TestMetric.PROCESSING_TIME,
            TestMetric.VULNERABILITY_COUNT,
            TestMetric.ACCURACY_SCORE,
            TestMetric.CONFIDENCE_SCORE
        ])
    )


if __name__ == "__main__":
    # 示例用法
    import argparse
    
    parser = argparse.ArgumentParser(description="A/B测试框架")
    parser.add_argument("--test-name", default="AB Test", help="测试名称")
    parser.add_argument("--sample-size", type=int, default=50, help="样本大小")
    parser.add_argument("--results-dir", default="./results/ab_testing", help="结果目录")
    
    args = parser.parse_args()
    
    print(f"A/B测试框架已准备就绪")
    print(f"测试名称: {args.test_name}")
    print(f"样本大小: {args.sample_size}")
    print(f"结果目录: {args.results_dir}")
    print("请在代码中调用相关函数来执行测试")