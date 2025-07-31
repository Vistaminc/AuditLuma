"""
结果整合器 - 层级RAG架构结果整合组件
负责多任务结果合并、冲突解决和最终报告生成
"""

import time
import uuid
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import statistics
import hashlib

from loguru import logger

from auditluma.models.code import VulnerabilityResult
from auditluma.orchestrator.task_decomposer import TaskType


class ConflictResolutionStrategy(Enum):
    """冲突解决策略"""
    HIGHEST_CONFIDENCE = "highest_confidence"
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_AVERAGE = "weighted_average"
    CONSENSUS = "consensus"
    MERGE_ALL = "merge_all"


class SeverityLevel(Enum):
    """严重程度级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityCluster:
    """漏洞聚类"""
    cluster_id: str
    vulnerabilities: List[VulnerabilityResult]
    representative: VulnerabilityResult  # 代表性漏洞
    confidence_scores: List[float]
    source_tasks: List[str]
    similarity_threshold: float = 0.8
    
    @property
    def average_confidence(self) -> float:
        """平均置信度"""
        if self.confidence_scores:
            return statistics.mean(self.confidence_scores)
        return 0.0
    
    @property
    def max_confidence(self) -> float:
        """最高置信度"""
        if self.confidence_scores:
            return max(self.confidence_scores)
        return 0.0
    
    @property
    def consensus_strength(self) -> float:
        """共识强度（基于发现该漏洞的任务数量）"""
        return len(set(self.source_tasks)) / len(self.source_tasks) if self.source_tasks else 0.0


@dataclass
class IntegrationResult:
    """整合结果"""
    integrated_vulnerabilities: List[VulnerabilityResult]
    duplicate_count: int
    conflict_count: int
    clusters: List[VulnerabilityCluster]
    integration_metadata: Dict[str, Any]
    quality_metrics: Dict[str, float]
    processing_time: float


@dataclass
class ReportSection:
    """报告章节"""
    title: str
    content: str
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    """审计报告"""
    report_id: str
    title: str
    summary: str
    sections: List[ReportSection]
    vulnerabilities: List[VulnerabilityResult]
    statistics: Dict[str, Any]
    recommendations: List[str]
    generated_at: str
    processing_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class VulnerabilitySimilarityCalculator:
    """漏洞相似度计算器"""
    
    def __init__(self):
        """初始化相似度计算器"""
        self.similarity_weights = {
            "type": 0.3,
            "location": 0.25,
            "description": 0.2,
            "code_pattern": 0.15,
            "severity": 0.1
        }
    
    def calculate_similarity(self, vuln1: VulnerabilityResult, 
                           vuln2: VulnerabilityResult) -> float:
        """计算两个漏洞的相似度"""
        try:
            scores = {}
            
            # 1. 类型相似度
            scores["type"] = self._calculate_type_similarity(vuln1, vuln2)
            
            # 2. 位置相似度
            scores["location"] = self._calculate_location_similarity(vuln1, vuln2)
            
            # 3. 描述相似度
            scores["description"] = self._calculate_description_similarity(vuln1, vuln2)
            
            # 4. 代码模式相似度
            scores["code_pattern"] = self._calculate_code_pattern_similarity(vuln1, vuln2)
            
            # 5. 严重程度相似度
            scores["severity"] = self._calculate_severity_similarity(vuln1, vuln2)
            
            # 计算加权平均
            weighted_score = sum(
                scores[key] * self.similarity_weights[key] 
                for key in scores
            )
            
            return min(1.0, max(0.0, weighted_score))
            
        except Exception as e:
            logger.warning(f"计算漏洞相似度失败: {e}")
            return 0.0
    
    def _calculate_type_similarity(self, vuln1: VulnerabilityResult, 
                                 vuln2: VulnerabilityResult) -> float:
        """计算类型相似度"""
        if vuln1.vulnerability_type == vuln2.vulnerability_type:
            return 1.0
        
        # 检查类型是否相关
        type1_lower = vuln1.vulnerability_type.lower()
        type2_lower = vuln2.vulnerability_type.lower()
        
        # 相关类型映射
        related_types = {
            "sql injection": ["database", "injection", "query"],
            "xss": ["cross-site", "scripting", "javascript"],
            "command injection": ["command", "execution", "system"],
            "path traversal": ["directory", "file", "path"]
        }
        
        for base_type, related in related_types.items():
            if base_type in type1_lower and any(r in type2_lower for r in related):
                return 0.7
            if base_type in type2_lower and any(r in type1_lower for r in related):
                return 0.7
        
        return 0.0
    
    def _calculate_location_similarity(self, vuln1: VulnerabilityResult, 
                                     vuln2: VulnerabilityResult) -> float:
        """计算位置相似度"""
        # 文件路径相似度
        if vuln1.file_path == vuln2.file_path:
            # 同一文件，检查行号接近程度
            line_diff = abs(vuln1.start_line - vuln2.start_line)
            if line_diff == 0:
                return 1.0
            elif line_diff <= 5:
                return 0.8
            elif line_diff <= 20:
                return 0.6
            else:
                return 0.4
        else:
            # 不同文件，检查文件名相似度
            file1 = vuln1.file_path.split('/')[-1] if '/' in vuln1.file_path else vuln1.file_path
            file2 = vuln2.file_path.split('/')[-1] if '/' in vuln2.file_path else vuln2.file_path
            
            if file1 == file2:
                return 0.3
            elif file1.split('.')[0] == file2.split('.')[0]:  # 同名不同扩展名
                return 0.2
            else:
                return 0.0
    
    def _calculate_description_similarity(self, vuln1: VulnerabilityResult, 
                                        vuln2: VulnerabilityResult) -> float:
        """计算描述相似度"""
        desc1 = vuln1.description.lower()
        desc2 = vuln2.description.lower()
        
        # 简单的词汇重叠计算
        words1 = set(desc1.split())
        words2 = set(desc2.split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1 & words2
        union = words1 | words2
        
        return len(intersection) / len(union) if union else 0.0
    
    def _calculate_code_pattern_similarity(self, vuln1: VulnerabilityResult, 
                                         vuln2: VulnerabilityResult) -> float:
        """计算代码模式相似度"""
        snippet1 = getattr(vuln1, 'snippet', '').lower()
        snippet2 = getattr(vuln2, 'snippet', '').lower()
        
        if not snippet1 or not snippet2:
            return 0.0
        
        # 检查关键代码模式
        patterns = [
            'select', 'insert', 'update', 'delete',  # SQL
            'eval', 'exec', 'system',  # 执行
            'include', 'require', 'import',  # 包含
            'http', 'request', 'response'  # 网络
        ]
        
        pattern1 = set(p for p in patterns if p in snippet1)
        pattern2 = set(p for p in patterns if p in snippet2)
        
        if pattern1 and pattern2:
            intersection = pattern1 & pattern2
            union = pattern1 | pattern2
            return len(intersection) / len(union)
        
        return 0.0
    
    def _calculate_severity_similarity(self, vuln1: VulnerabilityResult, 
                                     vuln2: VulnerabilityResult) -> float:
        """计算严重程度相似度"""
        severity1 = getattr(vuln1, 'severity', 'medium').lower()
        severity2 = getattr(vuln2, 'severity', 'medium').lower()
        
        if severity1 == severity2:
            return 1.0
        
        # 严重程度等级映射
        severity_levels = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        
        level1 = severity_levels.get(severity1, 3)
        level2 = severity_levels.get(severity2, 3)
        
        diff = abs(level1 - level2)
        return max(0.0, 1.0 - diff * 0.25)


class ConflictResolver:
    """冲突解决器"""
    
    def __init__(self):
        """初始化冲突解决器"""
        self.task_weights = {
            TaskType.SECURITY_SCAN: 1.0,
            TaskType.LOGIC_ANALYSIS: 0.8,
            TaskType.DEPENDENCY_ANALYSIS: 0.7,
            TaskType.SYNTAX_CHECK: 0.5
        }
    
    def resolve_conflicts(self, cluster: VulnerabilityCluster, 
                         strategy: ConflictResolutionStrategy) -> VulnerabilityResult:
        """解决漏洞冲突"""
        if len(cluster.vulnerabilities) == 1:
            return cluster.vulnerabilities[0]
        
        resolver_methods = {
            ConflictResolutionStrategy.HIGHEST_CONFIDENCE: self._resolve_by_highest_confidence,
            ConflictResolutionStrategy.MAJORITY_VOTE: self._resolve_by_majority_vote,
            ConflictResolutionStrategy.WEIGHTED_AVERAGE: self._resolve_by_weighted_average,
            ConflictResolutionStrategy.CONSENSUS: self._resolve_by_consensus,
            ConflictResolutionStrategy.MERGE_ALL: self._resolve_by_merge_all
        }
        
        resolver = resolver_methods.get(strategy, self._resolve_by_highest_confidence)
        return resolver(cluster)
    
    def _resolve_by_highest_confidence(self, cluster: VulnerabilityCluster) -> VulnerabilityResult:
        """按最高置信度解决冲突"""
        max_confidence_idx = cluster.confidence_scores.index(max(cluster.confidence_scores))
        best_vuln = cluster.vulnerabilities[max_confidence_idx]
        
        # 添加冲突解决元数据
        if not hasattr(best_vuln, 'metadata'):
            best_vuln.metadata = {}
        
        best_vuln.metadata.update({
            "conflict_resolution": "highest_confidence",
            "original_count": len(cluster.vulnerabilities),
            "confidence_range": [min(cluster.confidence_scores), max(cluster.confidence_scores)]
        })
        
        return best_vuln
    
    def _resolve_by_majority_vote(self, cluster: VulnerabilityCluster) -> VulnerabilityResult:
        """按多数投票解决冲突"""
        # 按漏洞类型投票
        type_votes = Counter(v.vulnerability_type for v in cluster.vulnerabilities)
        winning_type = type_votes.most_common(1)[0][0]
        
        # 选择该类型中置信度最高的
        type_vulns = [v for v in cluster.vulnerabilities if v.vulnerability_type == winning_type]
        type_confidences = [v.confidence for v in type_vulns]
        
        max_idx = type_confidences.index(max(type_confidences))
        best_vuln = type_vulns[max_idx]
        
        # 添加元数据
        if not hasattr(best_vuln, 'metadata'):
            best_vuln.metadata = {}
        
        best_vuln.metadata.update({
            "conflict_resolution": "majority_vote",
            "vote_count": type_votes[winning_type],
            "total_votes": len(cluster.vulnerabilities)
        })
        
        return best_vuln
    
    def _resolve_by_weighted_average(self, cluster: VulnerabilityCluster) -> VulnerabilityResult:
        """按加权平均解决冲突"""
        # 选择置信度最高的作为基础
        base_vuln = cluster.vulnerabilities[0]
        max_confidence = 0.0
        
        for vuln in cluster.vulnerabilities:
            if vuln.confidence > max_confidence:
                max_confidence = vuln.confidence
                base_vuln = vuln
        
        # 计算加权平均置信度
        weighted_confidence = cluster.average_confidence
        base_vuln.confidence = weighted_confidence
        
        # 添加元数据
        if not hasattr(base_vuln, 'metadata'):
            base_vuln.metadata = {}
        
        base_vuln.metadata.update({
            "conflict_resolution": "weighted_average",
            "original_confidences": cluster.confidence_scores,
            "weighted_confidence": weighted_confidence
        })
        
        return base_vuln
    
    def _resolve_by_consensus(self, cluster: VulnerabilityCluster) -> VulnerabilityResult:
        """按共识解决冲突"""
        # 只有当多个任务都发现相同漏洞时才保留
        if cluster.consensus_strength >= 0.6:  # 至少60%的任务一致
            return self._resolve_by_highest_confidence(cluster)
        else:
            # 共识不足，降低置信度
            best_vuln = self._resolve_by_highest_confidence(cluster)
            best_vuln.confidence *= cluster.consensus_strength
            
            if not hasattr(best_vuln, 'metadata'):
                best_vuln.metadata = {}
            
            best_vuln.metadata.update({
                "conflict_resolution": "consensus",
                "consensus_strength": cluster.consensus_strength,
                "confidence_adjusted": True
            })
            
            return best_vuln
    
    def _resolve_by_merge_all(self, cluster: VulnerabilityCluster) -> VulnerabilityResult:
        """合并所有信息"""
        # 选择最详细的漏洞作为基础
        base_vuln = max(cluster.vulnerabilities, key=lambda v: len(v.description))
        
        # 合并描述
        all_descriptions = [v.description for v in cluster.vulnerabilities]
        unique_descriptions = list(set(all_descriptions))
        merged_description = "\n\n".join(unique_descriptions)
        base_vuln.description = merged_description
        
        # 使用最高置信度
        base_vuln.confidence = max(cluster.confidence_scores)
        
        # 添加元数据
        if not hasattr(base_vuln, 'metadata'):
            base_vuln.metadata = {}
        
        base_vuln.metadata.update({
            "conflict_resolution": "merge_all",
            "merged_count": len(cluster.vulnerabilities),
            "source_tasks": cluster.source_tasks
        })
        
        return base_vuln


class ResultIntegrator:
    """结果整合器 - 核心结果整合组件"""
    
    def __init__(self, similarity_threshold: float = 0.8):
        """初始化结果整合器"""
        self.similarity_threshold = similarity_threshold
        self.similarity_calculator = VulnerabilitySimilarityCalculator()
        self.conflict_resolver = ConflictResolver()
        
        # 整合配置
        self.config = {
            "enable_deduplication": True,
            "enable_conflict_resolution": True,
            "default_resolution_strategy": ConflictResolutionStrategy.CONSENSUS,
            "min_confidence_threshold": 0.3,
            "max_clusters_per_type": 100
        }
        
        logger.info("结果整合器初始化完成")
    
    async def integrate_results(self, task_results: List[Any], 
                              strategy: ConflictResolutionStrategy = None) -> IntegrationResult:
        """整合任务结果 - 主要接口方法"""
        start_time = time.time()
        
        if not task_results:
            logger.warning("没有任务结果需要整合")
            return IntegrationResult(
                integrated_vulnerabilities=[],
                duplicate_count=0,
                conflict_count=0,
                clusters=[],
                integration_metadata={},
                quality_metrics={},
                processing_time=0.0
            )
        
        strategy = strategy or self.config["default_resolution_strategy"]
        logger.info(f"开始结果整合，任务结果数: {len(task_results)}, 策略: {strategy.value}")
        
        try:
            # 1. 提取所有漏洞
            all_vulnerabilities = self._extract_vulnerabilities(task_results)
            logger.info(f"提取漏洞总数: {len(all_vulnerabilities)}")
            
            # 2. 过滤低置信度漏洞
            filtered_vulnerabilities = self._filter_by_confidence(all_vulnerabilities)
            logger.info(f"置信度过滤后: {len(filtered_vulnerabilities)}")
            
            # 3. 漏洞聚类
            clusters = await self._cluster_vulnerabilities(filtered_vulnerabilities, task_results)
            logger.info(f"生成漏洞聚类: {len(clusters)}")
            
            # 4. 冲突解决
            integrated_vulnerabilities = await self._resolve_conflicts(clusters, strategy)
            logger.info(f"冲突解决后: {len(integrated_vulnerabilities)}")
            
            # 5. 质量评估
            quality_metrics = self._calculate_quality_metrics(
                all_vulnerabilities, integrated_vulnerabilities, clusters
            )
            
            # 6. 生成整合元数据
            integration_metadata = self._generate_integration_metadata(
                task_results, clusters, strategy
            )
            
            processing_time = time.time() - start_time
            
            result = IntegrationResult(
                integrated_vulnerabilities=integrated_vulnerabilities,
                duplicate_count=len(all_vulnerabilities) - len(integrated_vulnerabilities),
                conflict_count=sum(1 for c in clusters if len(c.vulnerabilities) > 1),
                clusters=clusters,
                integration_metadata=integration_metadata,
                quality_metrics=quality_metrics,
                processing_time=processing_time
            )
            
            logger.info(f"结果整合完成，耗时: {processing_time:.2f}秒")
            logger.info(f"最终漏洞数: {len(integrated_vulnerabilities)}, "
                       f"去重: {result.duplicate_count}, 冲突: {result.conflict_count}")
            
            return result
            
        except Exception as e:
            logger.error(f"结果整合过程中出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
            # 返回错误结果
            return IntegrationResult(
                integrated_vulnerabilities=[],
                duplicate_count=0,
                conflict_count=0,
                clusters=[],
                integration_metadata={"error": str(e)},
                quality_metrics={},
                processing_time=time.time() - start_time
            )
    
    def _extract_vulnerabilities(self, task_results: List[Any]) -> List[Tuple[VulnerabilityResult, str]]:
        """提取所有漏洞及其来源任务"""
        vulnerabilities_with_source = []
        
        for task_result in task_results:
            task_id = getattr(task_result, 'task_id', 'unknown')
            vulnerabilities = getattr(task_result, 'vulnerabilities', [])
            
            for vuln in vulnerabilities:
                vulnerabilities_with_source.append((vuln, task_id))
        
        return vulnerabilities_with_source
    
    def _filter_by_confidence(self, vulnerabilities_with_source: List[Tuple[VulnerabilityResult, str]]) -> List[Tuple[VulnerabilityResult, str]]:
        """按置信度过滤漏洞"""
        if not self.config["enable_deduplication"]:
            return vulnerabilities_with_source
        
        threshold = self.config["min_confidence_threshold"]
        filtered = []
        
        for vuln, source in vulnerabilities_with_source:
            confidence = getattr(vuln, 'confidence', 0.5)
            if confidence >= threshold:
                filtered.append((vuln, source))
            else:
                logger.debug(f"过滤低置信度漏洞: {vuln.id}, 置信度: {confidence}")
        
        return filtered
    
    async def _cluster_vulnerabilities(self, vulnerabilities_with_source: List[Tuple[VulnerabilityResult, str]], 
                                     task_results: List[Any]) -> List[VulnerabilityCluster]:
        """漏洞聚类"""
        if not vulnerabilities_with_source:
            return []
        
        clusters = []
        processed = set()
        
        for i, (vuln1, source1) in enumerate(vulnerabilities_with_source):
            if i in processed:
                continue
            
            # 创建新聚类
            cluster_vulnerabilities = [vuln1]
            cluster_sources = [source1]
            cluster_confidences = [getattr(vuln1, 'confidence', 0.5)]
            processed.add(i)
            
            # 查找相似漏洞
            for j, (vuln2, source2) in enumerate(vulnerabilities_with_source[i+1:], i+1):
                if j in processed:
                    continue
                
                similarity = self.similarity_calculator.calculate_similarity(vuln1, vuln2)
                
                if similarity >= self.similarity_threshold:
                    cluster_vulnerabilities.append(vuln2)
                    cluster_sources.append(source2)
                    cluster_confidences.append(getattr(vuln2, 'confidence', 0.5))
                    processed.add(j)
            
            # 创建聚类对象
            cluster = VulnerabilityCluster(
                cluster_id=f"cluster_{uuid.uuid4().hex[:8]}",
                vulnerabilities=cluster_vulnerabilities,
                representative=vuln1,  # 第一个作为代表
                confidence_scores=cluster_confidences,
                source_tasks=cluster_sources,
                similarity_threshold=self.similarity_threshold
            )
            
            clusters.append(cluster)
        
        return clusters
    
    async def _resolve_conflicts(self, clusters: List[VulnerabilityCluster], 
                               strategy: ConflictResolutionStrategy) -> List[VulnerabilityResult]:
        """解决冲突"""
        if not self.config["enable_conflict_resolution"]:
            # 不解决冲突，返回所有漏洞
            all_vulnerabilities = []
            for cluster in clusters:
                all_vulnerabilities.extend(cluster.vulnerabilities)
            return all_vulnerabilities
        
        integrated_vulnerabilities = []
        
        for cluster in clusters:
            try:
                resolved_vuln = self.conflict_resolver.resolve_conflicts(cluster, strategy)
                integrated_vulnerabilities.append(resolved_vuln)
            except Exception as e:
                logger.warning(f"解决聚类冲突失败: {cluster.cluster_id}, {e}")
                # 使用代表性漏洞
                integrated_vulnerabilities.append(cluster.representative)
        
        return integrated_vulnerabilities
    
    def _calculate_quality_metrics(self, original_vulnerabilities: List[Tuple[VulnerabilityResult, str]], 
                                 integrated_vulnerabilities: List[VulnerabilityResult],
                                 clusters: List[VulnerabilityCluster]) -> Dict[str, float]:
        """计算质量指标"""
        metrics = {}
        
        # 基本统计
        original_count = len(original_vulnerabilities)
        integrated_count = len(integrated_vulnerabilities)
        
        metrics["deduplication_rate"] = (original_count - integrated_count) / original_count if original_count > 0 else 0.0
        metrics["cluster_efficiency"] = len(clusters) / original_count if original_count > 0 else 0.0
        
        # 置信度统计
        if integrated_vulnerabilities:
            confidences = [getattr(v, 'confidence', 0.5) for v in integrated_vulnerabilities]
            metrics["average_confidence"] = statistics.mean(confidences)
            metrics["confidence_std"] = statistics.stdev(confidences) if len(confidences) > 1 else 0.0
            metrics["min_confidence"] = min(confidences)
            metrics["max_confidence"] = max(confidences)
        else:
            metrics.update({
                "average_confidence": 0.0,
                "confidence_std": 0.0,
                "min_confidence": 0.0,
                "max_confidence": 0.0
            })
        
        # 聚类质量
        if clusters:
            cluster_sizes = [len(c.vulnerabilities) for c in clusters]
            metrics["average_cluster_size"] = statistics.mean(cluster_sizes)
            metrics["max_cluster_size"] = max(cluster_sizes)
            
            # 共识强度
            consensus_strengths = [c.consensus_strength for c in clusters]
            metrics["average_consensus"] = statistics.mean(consensus_strengths)
        else:
            metrics.update({
                "average_cluster_size": 0.0,
                "max_cluster_size": 0.0,
                "average_consensus": 0.0
            })
        
        return metrics
    
    def _generate_integration_metadata(self, task_results: List[Any], 
                                     clusters: List[VulnerabilityCluster],
                                     strategy: ConflictResolutionStrategy) -> Dict[str, Any]:
        """生成整合元数据"""
        metadata = {
            "integration_strategy": strategy.value,
            "similarity_threshold": self.similarity_threshold,
            "task_count": len(task_results),
            "cluster_count": len(clusters),
            "config": self.config.copy()
        }
        
        # 任务类型统计
        task_types = []
        for task_result in task_results:
            task_type = getattr(task_result, 'task_type', None)
            if task_type:
                task_types.append(task_type.value if hasattr(task_type, 'value') else str(task_type))
        
        metadata["task_type_distribution"] = dict(Counter(task_types))
        
        # 聚类统计
        cluster_stats = {
            "single_vulnerability_clusters": sum(1 for c in clusters if len(c.vulnerabilities) == 1),
            "multi_vulnerability_clusters": sum(1 for c in clusters if len(c.vulnerabilities) > 1),
            "largest_cluster_size": max((len(c.vulnerabilities) for c in clusters), default=0)
        }
        metadata["cluster_statistics"] = cluster_stats
        
        return metadata
    
    async def generate_audit_report(self, integrated_result: IntegrationResult, 
                                  task_results: List[Any]) -> AuditReport:
        """生成审计报告"""
        report_id = f"audit_report_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        # 生成报告标题和摘要
        title = "Haystack层级RAG代码安全审计报告"
        summary = self._generate_report_summary(integrated_result)
        
        # 生成报告章节
        sections = await self._generate_report_sections(integrated_result, task_results)
        
        # 生成统计信息
        statistics = self._generate_report_statistics(integrated_result, task_results)
        
        # 生成建议
        recommendations = self._generate_recommendations(integrated_result)
        
        report = AuditReport(
            report_id=report_id,
            title=title,
            summary=summary,
            sections=sections,
            vulnerabilities=integrated_result.integrated_vulnerabilities,
            statistics=statistics,
            recommendations=recommendations,
            generated_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            processing_time=integrated_result.processing_time,
            metadata={
                "integration_metadata": integrated_result.integration_metadata,
                "quality_metrics": integrated_result.quality_metrics
            }
        )
        
        logger.info(f"审计报告生成完成: {report_id}")
        return report
    
    def _generate_report_summary(self, integrated_result: IntegrationResult) -> str:
        """生成报告摘要"""
        vuln_count = len(integrated_result.integrated_vulnerabilities)
        duplicate_count = integrated_result.duplicate_count
        conflict_count = integrated_result.conflict_count
        
        # 按严重程度统计
        severity_counts = Counter()
        for vuln in integrated_result.integrated_vulnerabilities:
            severity = getattr(vuln, 'severity', 'medium').lower()
            severity_counts[severity] += 1
        
        summary_parts = [
            f"本次审计共发现 {vuln_count} 个安全漏洞。",
            f"通过智能去重和冲突解决，处理了 {duplicate_count} 个重复项和 {conflict_count} 个冲突。"
        ]
        
        if severity_counts:
            severity_text = ", ".join([
                f"{severity}: {count}个" 
                for severity, count in severity_counts.most_common()
            ])
            summary_parts.append(f"漏洞严重程度分布：{severity_text}。")
        
        # 添加质量指标
        quality_metrics = integrated_result.quality_metrics
        if quality_metrics.get("average_confidence", 0) > 0:
            avg_confidence = quality_metrics["average_confidence"]
            summary_parts.append(f"平均置信度：{avg_confidence:.2f}。")
        
        return " ".join(summary_parts)
    
    async def _generate_report_sections(self, integrated_result: IntegrationResult, 
                                      task_results: List[Any]) -> List[ReportSection]:
        """生成报告章节"""
        sections = []
        
        # 1. 执行摘要
        sections.append(ReportSection(
            title="执行摘要",
            content=self._generate_executive_summary(integrated_result, task_results)
        ))
        
        # 2. 漏洞详情
        sections.append(ReportSection(
            title="漏洞详情",
            content=self._generate_vulnerability_details(integrated_result.integrated_vulnerabilities),
            vulnerabilities=integrated_result.integrated_vulnerabilities
        ))
        
        # 3. 质量分析
        sections.append(ReportSection(
            title="质量分析",
            content=self._generate_quality_analysis(integrated_result)
        ))
        
        # 4. 技术细节
        sections.append(ReportSection(
            title="技术细节",
            content=self._generate_technical_details(integrated_result, task_results)
        ))
        
        return sections
    
    def _generate_executive_summary(self, integrated_result: IntegrationResult, 
                                  task_results: List[Any]) -> str:
        """生成执行摘要"""
        parts = [
            f"审计处理时间：{integrated_result.processing_time:.2f}秒",
            f"任务执行数：{len(task_results)}",
            f"漏洞聚类数：{len(integrated_result.clusters)}",
            f"去重效率：{integrated_result.quality_metrics.get('deduplication_rate', 0):.2%}"
        ]
        
        return "\n".join(f"• {part}" for part in parts)
    
    def _generate_vulnerability_details(self, vulnerabilities: List[VulnerabilityResult]) -> str:
        """生成漏洞详情"""
        if not vulnerabilities:
            return "未发现安全漏洞。"
        
        # 按严重程度分组
        severity_groups = defaultdict(list)
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'medium').lower()
            severity_groups[severity].append(vuln)
        
        details = []
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            if severity in severity_groups:
                vulns = severity_groups[severity]
                details.append(f"\n{severity.upper()}级漏洞 ({len(vulns)}个):")
                
                for i, vuln in enumerate(vulns[:5], 1):  # 限制显示数量
                    details.append(f"  {i}. {vuln.vulnerability_type}")
                    details.append(f"     文件: {vuln.file_path}:{vuln.start_line}")
                    details.append(f"     置信度: {getattr(vuln, 'confidence', 0.5):.2f}")
                
                if len(vulns) > 5:
                    details.append(f"     ... 还有 {len(vulns) - 5} 个同级别漏洞")
        
        return "\n".join(details)
    
    def _generate_quality_analysis(self, integrated_result: IntegrationResult) -> str:
        """生成质量分析"""
        metrics = integrated_result.quality_metrics
        
        analysis = [
            f"平均置信度: {metrics.get('average_confidence', 0):.3f}",
            f"置信度标准差: {metrics.get('confidence_std', 0):.3f}",
            f"置信度范围: {metrics.get('min_confidence', 0):.3f} - {metrics.get('max_confidence', 0):.3f}",
            f"平均聚类大小: {metrics.get('average_cluster_size', 0):.2f}",
            f"最大聚类大小: {metrics.get('max_cluster_size', 0)}",
            f"平均共识强度: {metrics.get('average_consensus', 0):.3f}"
        ]
        
        return "\n".join(f"• {item}" for item in analysis)
    
    def _generate_technical_details(self, integrated_result: IntegrationResult, 
                                  task_results: List[Any]) -> str:
        """生成技术细节"""
        metadata = integrated_result.integration_metadata
        
        details = [
            f"整合策略: {metadata.get('integration_strategy', 'unknown')}",
            f"相似度阈值: {metadata.get('similarity_threshold', 0.8)}",
            f"任务类型分布: {metadata.get('task_type_distribution', {})}",
            f"聚类统计: {metadata.get('cluster_statistics', {})}"
        ]
        
        return "\n".join(f"• {item}" for item in details)
    
    def _generate_report_statistics(self, integrated_result: IntegrationResult, 
                                  task_results: List[Any]) -> Dict[str, Any]:
        """生成报告统计"""
        vulnerabilities = integrated_result.integrated_vulnerabilities
        
        stats = {
            "total_vulnerabilities": len(vulnerabilities),
            "duplicate_count": integrated_result.duplicate_count,
            "conflict_count": integrated_result.conflict_count,
            "processing_time": integrated_result.processing_time
        }
        
        # 严重程度统计
        severity_counts = Counter()
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'medium').lower()
            severity_counts[severity] += 1
        
        stats["severity_distribution"] = dict(severity_counts)
        
        # 类型统计
        type_counts = Counter()
        for vuln in vulnerabilities:
            type_counts[vuln.vulnerability_type] += 1
        
        stats["type_distribution"] = dict(type_counts.most_common(10))
        
        # 文件统计
        file_counts = Counter()
        for vuln in vulnerabilities:
            file_counts[vuln.file_path] += 1
        
        stats["file_distribution"] = dict(file_counts.most_common(10))
        
        return stats
    
    def _generate_recommendations(self, integrated_result: IntegrationResult) -> List[str]:
        """生成建议"""
        recommendations = []
        vulnerabilities = integrated_result.integrated_vulnerabilities
        
        if not vulnerabilities:
            recommendations.append("未发现安全漏洞，代码质量良好。")
            return recommendations
        
        # 按严重程度统计
        severity_counts = Counter()
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'medium').lower()
            severity_counts[severity] += 1
        
        # 基于严重程度的建议
        if severity_counts.get('critical', 0) > 0:
            recommendations.append(f"发现 {severity_counts['critical']} 个严重漏洞，建议立即修复。")
        
        if severity_counts.get('high', 0) > 0:
            recommendations.append(f"发现 {severity_counts['high']} 个高危漏洞，建议优先处理。")
        
        # 基于类型的建议
        type_counts = Counter()
        for vuln in vulnerabilities:
            type_counts[vuln.vulnerability_type] += 1
        
        common_types = type_counts.most_common(3)
        for vuln_type, count in common_types:
            if count > 1:
                recommendations.append(f"发现多个 {vuln_type} 漏洞({count}个)，建议进行专项检查。")
        
        # 质量建议
        quality_metrics = integrated_result.quality_metrics
        avg_confidence = quality_metrics.get('average_confidence', 0)
        
        if avg_confidence < 0.7:
            recommendations.append("部分漏洞置信度较低，建议人工复核确认。")
        
        # 通用建议
        recommendations.extend([
            "建议定期进行代码安全审计。",
            "建议建立安全编码规范和培训。",
            "建议集成自动化安全测试到CI/CD流程。"
        ])
        
        return recommendations