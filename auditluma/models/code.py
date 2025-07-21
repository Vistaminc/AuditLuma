"""
代码模型
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class FileType(str, Enum):
    """表示源代码文件类型"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    CPP = "cpp"
    C = "c"
    GO = "go"
    RUBY = "ruby"
    PHP = "php"
    RUST = "rust"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    LUA = "lua"
    SCALA = "scala"
    DART = "dart"
    BASH = "bash"
    POWERSHELL = "powershell"
    HTML = "html"
    CSS = "css"
    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    SQL = "sql"
    OTHER = "other"
    
    @classmethod
    def from_extension(cls, extension: str) -> 'FileType':
        """从文件扩展名获取文件类型"""
        mapping = {
            ".py": cls.PYTHON,
            ".js": cls.JAVASCRIPT,
            ".ts": cls.TYPESCRIPT,
            ".tsx": cls.TYPESCRIPT,
            ".jsx": cls.JAVASCRIPT,
            ".java": cls.JAVA,
            ".cs": cls.CSHARP,
            ".cpp": cls.CPP,
            ".cc": cls.CPP,
            ".c": cls.C,
            ".h": cls.C,
            ".hpp": cls.CPP,
            ".go": cls.GO,
            ".rb": cls.RUBY,
            ".php": cls.PHP,
            ".rs": cls.RUST,
            ".swift": cls.SWIFT,
            ".kt": cls.KOTLIN,
            ".lua": cls.LUA,
            ".scala": cls.SCALA,
            ".dart": cls.DART,
            ".sh": cls.BASH,
            ".bash": cls.BASH,
            ".ps1": cls.POWERSHELL,
            ".psm1": cls.POWERSHELL,
            ".html": cls.HTML,
            ".htm": cls.HTML,
            ".css": cls.CSS,
            ".json": cls.JSON,
            ".xml": cls.XML,
            ".yml": cls.YAML,
            ".yaml": cls.YAML,
            ".sql": cls.SQL,
        }
        return mapping.get(extension.lower(), cls.OTHER)


@dataclass
class SourceFile:
    """表示源代码文件"""
    path: Path
    relative_path: str
    name: str
    extension: str
    file_type: FileType
    size: int
    content: str
    modified_time: float
    
    @property
    def id(self) -> str:
        """返回文件的唯一标识符"""
        return str(self.relative_path)
    
    @classmethod
    def from_path(cls, path: Path, root_dir: Path) -> 'SourceFile':
        """从文件路径创建 SourceFile"""
        content = path.read_text(encoding='utf-8', errors='replace')
        relative_path = str(path.relative_to(root_dir))
        extension = path.suffix
        file_type = FileType.from_extension(extension)
        
        return cls(
            path=path,
            relative_path=relative_path,
            name=path.name,
            extension=extension,
            file_type=file_type,
            size=path.stat().st_size,
            content=content,
            modified_time=path.stat().st_mtime
        )


@dataclass
class CodeUnit:
    """表示代码单元（函数、类、方法等）"""
    id: str
    name: str
    type: str  # 'function', 'class', 'method', etc.
    source_file: SourceFile
    start_line: int
    end_line: int
    content: str
    parent_id: Optional[str] = None
    
    @property
    def full_name(self) -> str:
        """返回完整名称，包括父级层次结构"""
        return self.name


@dataclass
class CodeDependency:
    """表示两个代码单元之间的依赖关系"""
    source_id: str
    target_id: str
    source_unit: CodeUnit
    target_unit: Optional[CodeUnit]
    description: str
    type: str  # 'imports', 'calls', 'inherits', etc.
    line_number: int


class SeverityLevel(str, Enum):
    """表示漏洞的严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityResult:
    """表示检测到的漏洞"""
    id: str
    title: str
    description: str
    code_unit: CodeUnit
    file_path: str
    start_line: int
    end_line: int
    vulnerability_type: str
    severity: SeverityLevel
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = 1.0
    snippet: str = ""
    recommendation: str = ""
    references: List[str] = None
    metadata: Optional[Dict[str, Any]] = None
    cvss4_score: Optional[float] = None
    cvss4_vector: Optional[str] = None
    cvss4_severity: Optional[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.metadata is None:
            self.metadata = {}
    
    def set_cvss4_assessment(self, assessment: Dict[str, Any]) -> None:
        """设置CVSS 4.0评估结果，摒弃旧评级标准"""
        self.cvss4_score = assessment.get("base_score")
        self.cvss4_vector = assessment.get("vector_string")
        self.cvss4_severity = assessment.get("severity")  # 修正字段名
        
        # 根据CVSS 4.0严重程度更新传统严重程度等级（完全替换旧标准）
        if self.cvss4_severity:
            severity_mapping = {
                "CRITICAL": SeverityLevel.CRITICAL,
                "HIGH": SeverityLevel.HIGH,
                "MEDIUM": SeverityLevel.MEDIUM,
                "LOW": SeverityLevel.LOW,
                "NONE": SeverityLevel.INFO
            }
            # 强制使用CVSS 4.0评级，摒弃原有评级
            self.severity = severity_mapping.get(self.cvss4_severity, SeverityLevel.MEDIUM)
