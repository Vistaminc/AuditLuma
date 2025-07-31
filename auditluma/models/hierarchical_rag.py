"""
层级RAG架构核心数据模型

本模块定义了层级RAG架构中使用的核心数据结构，包括审计结果、增强上下文、
漏洞知识和验证结果等关键数据模型。
"""

from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
import uuid
from pathlib import Path

from .code import VulnerabilityResult, SourceFile, CodeUnit


class TaskType(str, Enum):
    """审计任务类型"""
    SYNTAX_CHECK = "syntax_check"
    LOGIC_ANALYSIS = "logic_analysis"
    SECURITY_SCAN = "security_scan"
    DEPENDENCY_ANALYSIS = "dependency_analysis"


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ValidationStatus(str, Enum):
    """验证状态"""
    VALIDATED = "validated"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"
    PENDING = "pending"


@dataclass
class AuditTask:
    """审计任务定义"""
    id: str
    type: TaskType
    priority: int
    source_files: List[SourceFile]
    dependencies: List[str] = field(default_factory=list)
    timeout: int = 300  # 默认5分钟超时
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
    
    @property
    def duration(self) -> Optional[float]:
        """返回任务执行时长（秒）"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'id': self.id,
            'type': self.type.value,
            'priority': self.priority,
            'source_files': [f.relative_path for f in self.source_files],
            'dependencies': self.dependencies,
            'timeout': self.timeout,
            'metadata': self.metadata,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'duration': self.duration
        }


@dataclass
class TaskResult:
    """任务执行结果"""
    task_id: str
    task_type: TaskType
    status: TaskStatus
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)
    processing_time: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'task_id': self.task_id,
            'task_type': self.task_type.value,
            'status': self.status.value,
            'vulnerabilities': [v.__dict__ for v in self.vulnerabilities],
            'processing_time': self.processing_time,
            'error_message': self.error_message,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat()
        }


@dataclass
class CVEInfo:
    """CVE漏洞信息"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: datetime
    modified_date: datetime
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'published_date': self.published_date.isoformat(),
            'modified_date': self.modified_date.isoformat(),
            'references': self.references,
            'affected_products': self.affected_products,
            'cwe_ids': self.cwe_ids
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CVEInfo':
        """从字典反序列化"""
        return cls(
            cve_id=data['cve_id'],
            description=data['description'],
            severity=data['severity'],
            cvss_score=data['cvss_score'],
            published_date=datetime.fromisoformat(data['published_date']),
            modified_date=datetime.fromisoformat(data['modified_date']),
            references=data.get('references', []),
            affected_products=data.get('affected_products', []),
            cwe_ids=data.get('cwe_ids', [])
        )


@dataclass
class BestPractice:
    """最佳实践信息"""
    id: str
    title: str
    description: str
    category: str
    language: str
    source: str  # OWASP, SANS, NIST等
    code_pattern: str
    recommendation: str
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'language': self.language,
            'source': self.source,
            'code_pattern': self.code_pattern,
            'recommendation': self.recommendation,
            'references': self.references,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BestPractice':
        """从字典反序列化"""
        return cls(
            id=data['id'],
            title=data['title'],
            description=data['description'],
            category=data['category'],
            language=data['language'],
            source=data['source'],
            code_pattern=data['code_pattern'],
            recommendation=data['recommendation'],
            references=data.get('references', []),
            tags=data.get('tags', [])
        )


@dataclass
class HistoricalCase:
    """历史案例信息"""
    id: str
    title: str
    description: str
    code_pattern: str
    vulnerability_type: str
    solution: str
    similarity_score: float
    case_date: datetime
    source_project: str
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'code_pattern': self.code_pattern,
            'vulnerability_type': self.vulnerability_type,
            'solution': self.solution,
            'similarity_score': self.similarity_score,
            'case_date': self.case_date.isoformat(),
            'source_project': self.source_project,
            'references': self.references
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HistoricalCase':
        """从字典反序列化"""
        return cls(
            id=data['id'],
            title=data['title'],
            description=data['description'],
            code_pattern=data['code_pattern'],
            vulnerability_type=data['vulnerability_type'],
            solution=data['solution'],
            similarity_score=data['similarity_score'],
            case_date=datetime.fromisoformat(data['case_date']),
            source_project=data['source_project'],
            references=data.get('references', [])
        )


@dataclass
class VulnerabilityKnowledge:
    """漏洞知识集合"""
    cve_info: List[CVEInfo] = field(default_factory=list)
    best_practices: List[BestPractice] = field(default_factory=list)
    historical_cases: List[HistoricalCase] = field(default_factory=list)
    relevance_scores: Dict[str, float] = field(default_factory=dict)
    retrieval_time: float = 0.0
    source_queries: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'cve_info': [cve.to_dict() for cve in self.cve_info],
            'best_practices': [bp.to_dict() for bp in self.best_practices],
            'historical_cases': [hc.to_dict() for hc in self.historical_cases],
            'relevance_scores': self.relevance_scores,
            'retrieval_time': self.retrieval_time,
            'source_queries': self.source_queries
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnerabilityKnowledge':
        """从字典反序列化"""
        return cls(
            cve_info=[CVEInfo.from_dict(cve) for cve in data.get('cve_info', [])],
            best_practices=[BestPractice.from_dict(bp) for bp in data.get('best_practices', [])],
            historical_cases=[HistoricalCase.from_dict(hc) for hc in data.get('historical_cases', [])],
            relevance_scores=data.get('relevance_scores', {}),
            retrieval_time=data.get('retrieval_time', 0.0),
            source_queries=data.get('source_queries', [])
        )


@dataclass
class CallChain:
    """函数调用链"""
    functions: List[str] = field(default_factory=list)
    call_depth: int = 0
    cross_file_calls: List[Dict[str, str]] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'functions': self.functions,
            'call_depth': self.call_depth,
            'cross_file_calls': self.cross_file_calls,
            'entry_points': self.entry_points
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CallChain':
        """从字典反序列化"""
        return cls(
            functions=data.get('functions', []),
            call_depth=data.get('call_depth', 0),
            cross_file_calls=data.get('cross_file_calls', []),
            entry_points=data.get('entry_points', [])
        )


@dataclass
class DataFlowInfo:
    """数据流信息"""
    taint_sources: List[str] = field(default_factory=list)
    taint_sinks: List[str] = field(default_factory=list)
    data_paths: List[List[str]] = field(default_factory=list)
    variable_tracking: Dict[str, List[str]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'taint_sources': self.taint_sources,
            'taint_sinks': self.taint_sinks,
            'data_paths': self.data_paths,
            'variable_tracking': self.variable_tracking
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DataFlowInfo':
        """从字典反序列化"""
        return cls(
            taint_sources=data.get('taint_sources', []),
            taint_sinks=data.get('taint_sinks', []),
            data_paths=data.get('data_paths', []),
            variable_tracking=data.get('variable_tracking', {})
        )


@dataclass
class ImpactScope:
    """影响范围评估"""
    affected_files: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    risk_propagation_paths: List[List[str]] = field(default_factory=list)
    impact_score: float = 0.0
    criticality_level: str = "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'affected_files': self.affected_files,
            'affected_functions': self.affected_functions,
            'risk_propagation_paths': self.risk_propagation_paths,
            'impact_score': self.impact_score,
            'criticality_level': self.criticality_level
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ImpactScope':
        """从字典反序列化"""
        return cls(
            affected_files=data.get('affected_files', []),
            affected_functions=data.get('affected_functions', []),
            risk_propagation_paths=data.get('risk_propagation_paths', []),
            impact_score=data.get('impact_score', 0.0),
            criticality_level=data.get('criticality_level', 'low')
        )


@dataclass
class SemanticContext:
    """语义上下文"""
    related_code_blocks: List[str] = field(default_factory=list)
    semantic_similarity_scores: Dict[str, float] = field(default_factory=dict)
    context_window_size: int = 0
    expanded_context: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'related_code_blocks': self.related_code_blocks,
            'semantic_similarity_scores': self.semantic_similarity_scores,
            'context_window_size': self.context_window_size,
            'expanded_context': self.expanded_context
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SemanticContext':
        """从字典反序列化"""
        return cls(
            related_code_blocks=data.get('related_code_blocks', []),
            semantic_similarity_scores=data.get('semantic_similarity_scores', {}),
            context_window_size=data.get('context_window_size', 0),
            expanded_context=data.get('expanded_context', '')
        )


@dataclass
class EnhancedContext:
    """增强上下文信息"""
    call_chain: CallChain = field(default_factory=CallChain)
    data_flow: DataFlowInfo = field(default_factory=DataFlowInfo)
    impact_scope: ImpactScope = field(default_factory=ImpactScope)
    semantic_context: SemanticContext = field(default_factory=SemanticContext)
    completeness_score: float = 0.0
    enhancement_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'call_chain': self.call_chain.to_dict(),
            'data_flow': self.data_flow.to_dict(),
            'impact_scope': self.impact_scope.to_dict(),
            'semantic_context': self.semantic_context.to_dict(),
            'completeness_score': self.completeness_score,
            'enhancement_time': self.enhancement_time
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EnhancedContext':
        """从字典反序列化"""
        return cls(
            call_chain=CallChain.from_dict(data.get('call_chain', {})),
            data_flow=DataFlowInfo.from_dict(data.get('data_flow', {})),
            impact_scope=ImpactScope.from_dict(data.get('impact_scope', {})),
            semantic_context=SemanticContext.from_dict(data.get('semantic_context', {})),
            completeness_score=data.get('completeness_score', 0.0),
            enhancement_time=data.get('enhancement_time', 0.0)
        )


@dataclass
class ConfidenceScore:
    """置信度评分"""
    overall_score: float
    component_scores: Dict[str, float] = field(default_factory=dict)
    explanation: str = ""
    factors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'overall_score': self.overall_score,
            'component_scores': self.component_scores,
            'explanation': self.explanation,
            'factors': self.factors
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfidenceScore':
        """从字典反序列化"""
        return cls(
            overall_score=data['overall_score'],
            component_scores=data.get('component_scores', {}),
            explanation=data.get('explanation', ''),
            factors=data.get('factors', [])
        )


@dataclass
class ValidationSummary:
    """验证摘要"""
    total_vulnerabilities: int
    validated_count: int
    rejected_count: int
    needs_review_count: int
    average_confidence: float
    validation_time: float
    false_positive_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'total_vulnerabilities': self.total_vulnerabilities,
            'validated_count': self.validated_count,
            'rejected_count': self.rejected_count,
            'needs_review_count': self.needs_review_count,
            'average_confidence': self.average_confidence,
            'validation_time': self.validation_time,
            'false_positive_rate': self.false_positive_rate
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidationSummary':
        """从字典反序列化"""
        return cls(
            total_vulnerabilities=data['total_vulnerabilities'],
            validated_count=data['validated_count'],
            rejected_count=data['rejected_count'],
            needs_review_count=data['needs_review_count'],
            average_confidence=data['average_confidence'],
            validation_time=data['validation_time'],
            false_positive_rate=data.get('false_positive_rate', 0.0)
        )


@dataclass
class ValidatedVulnerability:
    """验证后的漏洞"""
    vulnerability: VulnerabilityResult
    validation_status: ValidationStatus
    confidence_score: ConfidenceScore
    knowledge: VulnerabilityKnowledge
    enhanced_context: EnhancedContext
    validation_notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'vulnerability': self.vulnerability.__dict__,
            'validation_status': self.validation_status.value,
            'confidence_score': self.confidence_score.to_dict(),
            'knowledge': self.knowledge.to_dict(),
            'enhanced_context': self.enhanced_context.to_dict(),
            'validation_notes': self.validation_notes
        }


@dataclass
class ValidatedResults:
    """验证后的结果集合"""
    validated_vulnerabilities: List[ValidatedVulnerability] = field(default_factory=list)
    filtered_count: int = 0
    confidence_distribution: Dict[str, int] = field(default_factory=dict)
    validation_summary: ValidationSummary = field(default_factory=lambda: ValidationSummary(0, 0, 0, 0, 0.0, 0.0))
    processing_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'validated_vulnerabilities': [vv.to_dict() for vv in self.validated_vulnerabilities],
            'filtered_count': self.filtered_count,
            'confidence_distribution': self.confidence_distribution,
            'validation_summary': self.validation_summary.to_dict(),
            'processing_metadata': self.processing_metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidatedResults':
        """从字典反序列化"""
        validated_vulnerabilities = []
        for vv_data in data.get('validated_vulnerabilities', []):
            # 这里需要重构VulnerabilityResult的反序列化
            # 暂时跳过复杂的反序列化逻辑
            pass
        
        return cls(
            validated_vulnerabilities=validated_vulnerabilities,
            filtered_count=data.get('filtered_count', 0),
            confidence_distribution=data.get('confidence_distribution', {}),
            validation_summary=ValidationSummary.from_dict(data.get('validation_summary', {})),
            processing_metadata=data.get('processing_metadata', {})
        )


@dataclass
class AuditResult:
    """最终审计结果"""
    id: str
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)
    processing_time: float = 0.0
    confidence_score: float = 0.0
    task_results: List[TaskResult] = field(default_factory=list)
    execution_summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    validated_results: Optional[ValidatedResults] = None
    created_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'id': self.id,
            'vulnerabilities': [v.__dict__ for v in self.vulnerabilities],
            'processing_time': self.processing_time,
            'confidence_score': self.confidence_score,
            'task_results': [tr.to_dict() for tr in self.task_results],
            'execution_summary': self.execution_summary,
            'metadata': self.metadata,
            'validated_results': self.validated_results.to_dict() if self.validated_results else None,
            'created_at': self.created_at.isoformat()
        }
    
    def to_json(self) -> str:
        """序列化为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditResult':
        """从字典反序列化"""
        # 这里需要重构VulnerabilityResult和TaskResult的反序列化
        # 暂时返回基本结构
        return cls(
            id=data['id'],
            processing_time=data.get('processing_time', 0.0),
            confidence_score=data.get('confidence_score', 0.0),
            execution_summary=data.get('execution_summary', {}),
            metadata=data.get('metadata', {}),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.now()
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AuditResult':
        """从JSON字符串反序列化"""
        data = json.loads(json_str)
        return cls.from_dict(data)


# 任务集合类
@dataclass
class TaskCollection:
    """任务集合"""
    tasks: List[AuditTask] = field(default_factory=list)
    
    @property
    def syntax_tasks(self) -> List[AuditTask]:
        """获取语法检查任务"""
        return [t for t in self.tasks if t.type == TaskType.SYNTAX_CHECK]
    
    @property
    def logic_tasks(self) -> List[AuditTask]:
        """获取逻辑分析任务"""
        return [t for t in self.tasks if t.type == TaskType.LOGIC_ANALYSIS]
    
    @property
    def security_tasks(self) -> List[AuditTask]:
        """获取安全扫描任务"""
        return [t for t in self.tasks if t.type == TaskType.SECURITY_SCAN]
    
    @property
    def dependency_tasks(self) -> List[AuditTask]:
        """获取依赖分析任务"""
        return [t for t in self.tasks if t.type == TaskType.DEPENDENCY_ANALYSIS]
    
    def add_task(self, task: AuditTask):
        """添加任务"""
        self.tasks.append(task)
    
    def get_task_by_id(self, task_id: str) -> Optional[AuditTask]:
        """根据ID获取任务"""
        for task in self.tasks:
            if task.id == task_id:
                return task
        return None
    
    def get_ready_tasks(self) -> List[AuditTask]:
        """获取可以执行的任务（依赖已满足）"""
        ready_tasks = []
        completed_task_ids = {t.id for t in self.tasks if t.status == TaskStatus.COMPLETED}
        
        for task in self.tasks:
            if task.status == TaskStatus.PENDING:
                if all(dep_id in completed_task_ids for dep_id in task.dependencies):
                    ready_tasks.append(task)
        
        return ready_tasks
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'tasks': [task.to_dict() for task in self.tasks]
        }