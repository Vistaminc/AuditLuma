"""
AuditLuma API 数据模型
定义API请求和响应的Pydantic模型
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """扫描请求模型"""
    target_dir: str = Field(..., description="目标项目目录路径")
    output_dir: Optional[str] = Field(None, description="报告输出目录（默认使用配置值）")
    workers: Optional[int] = Field(None, description="并行工作线程数")
    report_format: Optional[str] = Field("html", description="报告格式 (html, pdf, json)")
    skip_deps: Optional[bool] = Field(False, description="跳过依赖分析")
    skip_remediation: Optional[bool] = Field(False, description="跳过生成修复建议")


class ScanResponse(BaseModel):
    """扫描响应模型"""
    scan_id: str = Field(..., description="扫描任务ID")
    status: str = Field(..., description="任务状态")
    message: str = Field(..., description="状态消息")


class ScanStatusResponse(BaseModel):
    """扫描状态响应模型"""
    scan_id: str = Field(..., description="扫描任务ID")
    status: str = Field(..., description="任务状态")
    progress: Optional[float] = Field(None, description="进度百分比")
    start_time: Optional[str] = Field(None, description="开始时间")
    end_time: Optional[str] = Field(None, description="结束时间")
    report_path: Optional[str] = Field(None, description="报告路径")
    error: Optional[str] = Field(None, description="错误信息")


class VulnerabilityCount(BaseModel):
    """漏洞计数模型"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class ScanSummaryResponse(BaseModel):
    """扫描摘要响应模型"""
    scan_id: str
    project_name: str
    scan_date: str
    scan_duration: str
    scanned_files: int
    scanned_lines: int
    vulnerability_count: VulnerabilityCount
    report_url: Optional[str] = None


class FileUploadResponse(BaseModel):
    """文件上传响应模型"""
    upload_id: str
    temp_dir: str
    message: str


class VulnerabilityDetail(BaseModel):
    """漏洞详情模型"""
    id: str
    type: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: Optional[int]
    code_snippet: Optional[str]
    cwe_id: Optional[str]
    confidence: Optional[str]
    recommendation: Optional[str]


class VulnerabilityListResponse(BaseModel):
    """漏洞列表响应模型"""
    scan_id: str
    total: int
    vulnerabilities: List[VulnerabilityDetail]


class RemediationDetail(BaseModel):
    """修复建议详情模型"""
    id: str
    vulnerability_id: str
    title: str
    description: str
    code_before: Optional[str]
    code_after: Optional[str]
    file_path: str
    line_number: Optional[int]
    difficulty: Optional[str]
    priority: Optional[str]


class RemediationListResponse(BaseModel):
    """修复建议列表响应模型"""
    scan_id: str
    total: int
    remediations: List[RemediationDetail]


class ConfigUpdateRequest(BaseModel):
    """配置更新请求模型"""
    project: Optional[Dict[str, Any]] = Field(None, description="项目配置")
    mcp: Optional[Dict[str, Any]] = Field(None, description="MCP配置")
    self_rag: Optional[Dict[str, Any]] = Field(None, description="Self-RAG配置")
    global_config: Optional[Dict[str, Any]] = Field(None, description="全局配置")


class ApiResponse(BaseModel):
    """通用API响应模型"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
