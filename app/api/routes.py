"""
AuditLuma API 路由
定义API端点路由和处理逻辑
"""

import os
import uuid
import zipfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Depends, Query, status
from fastapi.responses import JSONResponse, FileResponse

from loguru import logger

from app.api.models import (
    ScanRequest, ScanResponse, ScanStatusResponse, ScanSummaryResponse,
    FileUploadResponse, VulnerabilityListResponse, RemediationListResponse,
    ApiResponse, VulnerabilityDetail, RemediationDetail, VulnerabilityCount
)
from app.api.utils import get_running_scans, update_scan_status, run_analysis_task
from auditluma.config import Config

# 创建路由器
router = APIRouter(prefix="/api")

@router.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """启动代码扫描分析"""
    target_dir = Path(scan_request.target_dir)
    
    # 验证目录是否存在
    if not target_dir.exists() or not target_dir.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"目标目录不存在: {target_dir}"
        )
    
    # 生成扫描ID
    scan_id = str(uuid.uuid4())
    
    # 设置输出目录
    output_dir = scan_request.output_dir or Config.global_config.report_dir
    output_path = Path(output_dir)
    if not output_path.exists():
        output_path.mkdir(parents=True, exist_ok=True)
    
    # 更新配置
    Config.project.max_batch_size = scan_request.workers or Config.project.max_batch_size
    Config.global_config.report_format = scan_request.report_format or Config.global_config.report_format
    
    # 初始化扫描状态
    running_scans = get_running_scans()
    running_scans[scan_id] = {
        "status": "initializing",
        "start_time": datetime.now().isoformat(),
        "target_dir": str(target_dir),
        "output_dir": str(output_path),
        "progress": 0,
        "report_path": None,
        "error": None
    }
    
    # 在后台运行扫描任务
    background_tasks.add_task(
        run_analysis_task,
        scan_id=scan_id,
        target_dir=str(target_dir),
        output_dir=str(output_path),
        workers=scan_request.workers or Config.project.max_batch_size,
        skip_deps=scan_request.skip_deps,
        skip_remediation=scan_request.skip_remediation
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="initializing",
        message="扫描任务已初始化并在后台运行"
    )

@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """获取扫描任务状态"""
    running_scans = get_running_scans()
    
    if scan_id not in running_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到扫描任务ID: {scan_id}"
        )
    
    scan_info = running_scans[scan_id]
    
    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan_info["status"],
        progress=scan_info.get("progress"),
        start_time=scan_info.get("start_time"),
        end_time=scan_info.get("end_time"),
        report_path=scan_info.get("report_path"),
        error=scan_info.get("error")
    )

@router.get("/scan/{scan_id}/summary", response_model=ScanSummaryResponse)
async def get_scan_summary(scan_id: str):
    """获取扫描任务摘要"""
    running_scans = get_running_scans()
    
    if scan_id not in running_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到扫描任务ID: {scan_id}"
        )
    
    scan_info = running_scans[scan_id]
    
    if scan_info["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"扫描任务尚未完成，当前状态: {scan_info['status']}"
        )
    
    if not scan_info.get("results"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到扫描结果数据"
        )
    
    results = scan_info["results"]
    scan_data = results.get("scan_info", {})
    vulnerabilities = results.get("vulnerabilities", [])
    
    # 统计漏洞
    vuln_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for vuln in vulnerabilities:
        severity = vuln.severity.lower()
        vuln_count[severity] = vuln_count.get(severity, 0) + 1
        vuln_count["total"] += 1
    
    # 构建报告URL
    report_url = None
    if scan_info.get("report_path"):
        report_filename = Path(scan_info["report_path"]).name
        report_url = f"/reports/{report_filename}"
    
    return ScanSummaryResponse(
        scan_id=scan_id,
        project_name=scan_data.get("project_name", "未命名项目"),
        scan_date=scan_data.get("scan_date", ""),
        scan_duration=scan_data.get("scan_duration", ""),
        scanned_files=scan_data.get("scanned_files", 0),
        scanned_lines=scan_data.get("scanned_lines", 0),
        vulnerability_count=VulnerabilityCount(**vuln_count),
        report_url=report_url
    )

@router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """获取扫描报告文件"""
    running_scans = get_running_scans()
    
    if scan_id not in running_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到扫描任务ID: {scan_id}"
        )
    
    scan_info = running_scans[scan_id]
    
    if scan_info["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"扫描任务尚未完成，当前状态: {scan_info['status']}"
        )
    
    if not scan_info.get("report_path"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到报告文件"
        )
    
    report_path = scan_info["report_path"]
    
    if not os.path.exists(report_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"报告文件不存在: {report_path}"
        )
    
    return FileResponse(
        path=report_path,
        filename=Path(report_path).name,
        media_type="application/octet-stream"
    )

@router.get("/scan/{scan_id}/vulnerabilities", response_model=VulnerabilityListResponse)
async def get_vulnerabilities(
    scan_id: str,
    severity: str = Query(None, description="按严重程度过滤 (critical, high, medium, low, info)"),
    limit: int = Query(100, description="返回结果数量限制"),
    offset: int = Query(0, description="分页偏移量")
):
    """获取扫描发现的漏洞列表"""
    running_scans = get_running_scans()
    
    if scan_id not in running_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到扫描任务ID: {scan_id}"
        )
    
    scan_info = running_scans[scan_id]
    
    if scan_info["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"扫描任务尚未完成，当前状态: {scan_info['status']}"
        )
    
    if not scan_info.get("results"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到扫描结果数据"
        )
    
    # 获取漏洞列表
    vulnerabilities = scan_info["results"].get("vulnerabilities", [])
    
    # 根据严重程度过滤
    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.severity.lower() == severity.lower()]
    
    # 转换为API模型
    vuln_details = []
    for vuln in vulnerabilities:
        vuln_details.append(VulnerabilityDetail(
            id=str(vuln.id),
            type=vuln.vulnerability_type,
            severity=vuln.severity,
            title=vuln.title,
            description=vuln.description,
            file_path=vuln.file_path,
            line_number=vuln.line_number,
            code_snippet=vuln.code_snippet,
            cwe_id=vuln.cwe_id,
            confidence=vuln.confidence,
            recommendation=vuln.recommendation
        ))
    
    # 分页
    total = len(vuln_details)
    paginated_vulns = vuln_details[offset:offset + limit]
    
    return VulnerabilityListResponse(
        scan_id=scan_id,
        total=total,
        vulnerabilities=paginated_vulns
    )

@router.get("/scan/{scan_id}/remediations", response_model=RemediationListResponse)
async def get_remediations(
    scan_id: str,
    vulnerability_id: str = Query(None, description="按漏洞ID过滤"),
    limit: int = Query(100, description="返回结果数量限制"),
    offset: int = Query(0, description="分页偏移量")
):
    """获取扫描生成的修复建议列表"""
    running_scans = get_running_scans()
    
    if scan_id not in running_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到扫描任务ID: {scan_id}"
        )
    
    scan_info = running_scans[scan_id]
    
    if scan_info["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"扫描任务尚未完成，当前状态: {scan_info['status']}"
        )
    
    if not scan_info.get("results"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到扫描结果数据"
        )
    
    # 获取修复建议列表
    remediation_data = scan_info["results"].get("remediation_data", {})
    remediations = remediation_data.get("remediations", [])
    
    # 根据漏洞ID过滤
    if vulnerability_id:
        remediations = [r for r in remediations if r.get("vulnerability_id") == vulnerability_id]
    
    # 转换为API模型
    remediation_details = []
    for rem in remediations:
        remediation_details.append(RemediationDetail(
            id=rem.get("id", str(uuid.uuid4())),
            vulnerability_id=rem.get("vulnerability_id", ""),
            title=rem.get("title", ""),
            description=rem.get("description", ""),
            code_before=rem.get("code_before"),
            code_after=rem.get("code_after"),
            file_path=rem.get("file_path", ""),
            line_number=rem.get("line_number"),
            difficulty=rem.get("difficulty"),
            priority=rem.get("priority")
        ))
    
    # 分页
    total = len(remediation_details)
    paginated_rems = remediation_details[offset:offset + limit]
    
    return RemediationListResponse(
        scan_id=scan_id,
        total=total,
        remediations=paginated_rems
    )

@router.post("/upload", response_model=FileUploadResponse)
async def upload_project(file: UploadFile = File(...)):
    """上传项目文件进行扫描"""
    # 生成临时目录ID
    upload_id = str(uuid.uuid4())
    temp_dir = Path(Config.global_config.temp_dir) / upload_id
    
    # 创建临时目录
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # 保存上传的文件
        zip_path = temp_dir / file.filename
        with open(zip_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # 解压文件（假设是zip文件）
        if zipfile.is_zipfile(zip_path):
            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir(exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # 可以删除原始zip文件以节省空间
            os.remove(zip_path)
            
            return FileUploadResponse(
                upload_id=upload_id,
                temp_dir=str(extract_dir),
                message=f"项目已上传并解压到临时目录: {extract_dir}"
            )
        else:
            # 如果不是zip文件，可能是单个文件
            return FileUploadResponse(
                upload_id=upload_id,
                temp_dir=str(temp_dir),
                message=f"文件已上传到临时目录: {temp_dir}"
            )
            
    except Exception as e:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        logger.error(f"文件上传处理失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"文件处理失败: {str(e)}"
        )

@router.get("/config", response_model=ApiResponse)
async def get_config():
    """获取当前配置信息"""
    config_data = {
        "project": {
            "max_batch_size": Config.project.max_batch_size,
            "ignored_extensions": Config.project.ignored_extensions,
            "ignored_directories": Config.project.ignored_directories,
            "max_file_size": Config.project.max_file_size
        },
        "mcp": {
            "enabled": Config.mcp.enabled
        },
        "self_rag": {
            "enabled": Config.self_rag.enabled
        },
        "global_config": {
            "report_dir": Config.global_config.report_dir,
            "report_format": Config.global_config.report_format,
            "temp_dir": Config.global_config.temp_dir
        }
    }
    
    return ApiResponse(
        success=True,
        message="获取配置成功",
        data=config_data
    )

@router.get("/health")
async def health_check():
    """API健康检查"""
    return {"status": "ok", "version": "1.0.0"}
