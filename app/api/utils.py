"""
AuditLuma API 工具函数
提供API服务所需的工具和辅助函数
"""

import os
import time
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from loguru import logger

import sys
# 确保可以导入项目根目录模块
sys.path.append(str(Path(__file__).parent.parent.parent))

from auditluma.config import Config
from auditluma.orchestrator import AgentOrchestrator
from auditluma.scanner import CodeScanner, DependencyScanner
from auditluma.utils import calculate_project_hash
from auditluma.visualizer.report_generator import ReportGenerator
from auditluma.visualizer.graph_visualizer import GraphVisualizer

# 全局状态存储（在实际生产环境中应使用数据库）
_running_scans = {}

def get_running_scans() -> Dict[str, Dict[str, Any]]:
    """
    获取正在运行的扫描任务状态字典
    
    Returns:
        运行中的扫描任务字典
    """
    global _running_scans
    return _running_scans

def update_scan_status(scan_id: str, updates: Dict[str, Any]) -> None:
    """
    更新扫描任务状态
    
    Args:
        scan_id: 扫描任务ID
        updates: 要更新的状态字段
    """
    global _running_scans
    if scan_id in _running_scans:
        _running_scans[scan_id].update(updates)

async def run_analysis_task(
    scan_id: str,
    target_dir: str,
    output_dir: str,
    workers: int,
    skip_deps: bool = False,
    skip_remediation: bool = False
) -> None:
    """
    运行代码分析的后台任务
    
    Args:
        scan_id: 扫描任务ID
        target_dir: 目标项目目录
        output_dir: 输出目录
        workers: 工作线程数
        skip_deps: 是否跳过依赖分析
        skip_remediation: 是否跳过生成修复建议
    """
    try:
        # 更新扫描状态
        update_scan_status(scan_id, {
            "status": "scanning",
            "progress": 5
        })
        
        logger.info(f"开始扫描 [ID: {scan_id}], 目标目录: {target_dir}")
        
        # 计算项目哈希值
        project_hash = calculate_project_hash(target_dir)
        logger.info(f"项目哈希值: {project_hash}")
        
        # 记录开始时间
        start_time = time.time()
        
        # 初始化代码扫描器
        scanner = CodeScanner(target_dir)
        update_scan_status(scan_id, {"progress": 10})
        
        # 扫描源文件
        logger.info("扫描源文件...")
        source_files = await scanner.scan_async()
        total_files = len(source_files)
        total_lines = sum(file.line_count for file in source_files)
        logger.info(f"扫描了 {total_files} 个文件，共 {total_lines} 行代码")
        update_scan_status(scan_id, {"progress": 30})
        
        # 初始化依赖扫描器和处理依赖关系（如果未跳过）
        dependency_graph = None
        if not skip_deps:
            logger.info("分析依赖关系...")
            dependency_scanner = DependencyScanner(target_dir)
            dependency_scanner.scan()
            dependency_graph = dependency_scanner.get_dependency_graph()
            logger.info(f"找到 {len(dependency_graph['nodes']) if dependency_graph else 0} 个依赖项")
        update_scan_status(scan_id, {"progress": 40})
        
        # 初始化协调器
        orchestrator = AgentOrchestrator(workers=workers)
        await orchestrator.initialize_agents()
        update_scan_status(scan_id, {"progress": 50})
        
        # 提取代码单元
        logger.info("提取代码单元...")
        code_units = await orchestrator.extract_code_units(source_files)
        logger.info(f"提取了 {len(code_units)} 个代码单元")
        update_scan_status(scan_id, {"progress": 60})
        
        # 运行代码结构分析
        logger.info("分析代码结构...")
        code_structure = await orchestrator.run_code_structure_analysis(code_units)
        update_scan_status(scan_id, {"progress": 70})
        
        # 运行安全漏洞分析
        logger.info("分析安全漏洞...")
        vulnerabilities = await orchestrator.run_security_analysis(source_files)
        logger.info(f"发现了 {len(vulnerabilities)} 个潜在安全漏洞")
        update_scan_status(scan_id, {"progress": 80})
        
        # 生成修复建议（如果未跳过）
        remediation_data = {"remediation_count": 0, "remediations": []}
        if not skip_remediation and vulnerabilities:
            logger.info("生成修复建议...")
            remediation_data = await orchestrator.generate_remediations(vulnerabilities)
            logger.info(f"生成了 {remediation_data.get('remediation_count', 0)} 个修复建议")
        update_scan_status(scan_id, {"progress": 90})
        
        # 收集扫描信息
        end_time = time.time()
        scan_duration = end_time - start_time
        
        scan_info = {
            "project_name": Path(target_dir).name,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanned_files": total_files,
            "scanned_lines": total_lines,
            "scan_duration": f"{scan_duration:.2f}秒",
            "project_hash": project_hash
        }
        
        # 汇总分析结果
        analysis_results = {
            "vulnerabilities": vulnerabilities,
            "dependency_graph": dependency_graph,
            "code_structure": code_structure,
            "remediation_data": remediation_data,
            "scan_info": scan_info
        }
        
        # 生成报告
        logger.info("生成报告...")
        report_generator = ReportGenerator()
        report_path = report_generator.generate_report(
            vulnerabilities=vulnerabilities,
            dependency_graph=dependency_graph,
            remediation_data=remediation_data,
            scan_info=scan_info,
            output_dir=output_dir
        )
        logger.info(f"报告已生成：{report_path}")
        
        # 生成依赖关系可视化（如果未跳过依赖分析）
        if not skip_deps and dependency_graph:
            graph_visualizer = GraphVisualizer()
            try:
                interactive_graph_path = graph_visualizer.create_interactive_graph(
                    dependency_graph=dependency_graph,
                    output_file=str(Path(output_dir) / f"dependency_graph_{scan_id}.html")
                )
                logger.info(f"依赖关系图已生成：{interactive_graph_path}")
            except Exception as e:
                logger.error(f"创建交互式依赖图时出错: {e}")
        
        # 更新扫描状态
        update_scan_status(scan_id, {
            "status": "completed",
            "progress": 100,
            "end_time": datetime.now().isoformat(),
            "report_path": report_path,
            "results": analysis_results
        })
        
        logger.info(f"扫描 [ID: {scan_id}] 已完成")
        
    except Exception as e:
        logger.error(f"扫描过程中出错 [ID: {scan_id}]: {e}")
        import traceback
        error_details = traceback.format_exc()
        logger.error(error_details)
        
        # 更新扫描状态为失败
        update_scan_status(scan_id, {
            "status": "failed",
            "end_time": datetime.now().isoformat(),
            "error": str(e)
        })

async def cleanup_old_scans(max_age_hours: int = 24) -> None:
    """
    清理旧的扫描记录和临时文件
    
    Args:
        max_age_hours: 最大保留时间（小时）
    """
    global _running_scans
    current_time = datetime.now()
    
    scans_to_remove = []
    
    for scan_id, scan_info in _running_scans.items():
        # 跳过正在运行的扫描
        if scan_info["status"] in ["initializing", "scanning"]:
            continue
        
        # 检查扫描时间
        if "end_time" in scan_info:
            end_time = datetime.fromisoformat(scan_info["end_time"])
            hours_diff = (current_time - end_time).total_seconds() / 3600
            
            if hours_diff > max_age_hours:
                scans_to_remove.append(scan_id)
    
    # 移除旧扫描
    for scan_id in scans_to_remove:
        del _running_scans[scan_id]
        logger.info(f"已清理旧扫描记录: {scan_id}")

def convert_vulnerability_to_api_format(vuln) -> Dict[str, Any]:
    """
    将内部漏洞对象转换为API响应格式
    
    Args:
        vuln: 内部漏洞对象
        
    Returns:
        API格式的漏洞字典
    """
    return {
        "id": str(vuln.id),
        "type": vuln.vulnerability_type,
        "severity": vuln.severity,
        "title": vuln.title,
        "description": vuln.description,
        "file_path": vuln.file_path,
        "line_number": vuln.line_number,
        "code_snippet": vuln.code_snippet,
        "cwe_id": vuln.cwe_id,
        "confidence": vuln.confidence,
        "recommendation": vuln.recommendation
    }

def convert_remediation_to_api_format(remediation) -> Dict[str, Any]:
    """
    将内部修复建议对象转换为API响应格式
    
    Args:
        remediation: 内部修复建议对象
        
    Returns:
        API格式的修复建议字典
    """
    return {
        "id": remediation.get("id", ""),
        "vulnerability_id": remediation.get("vulnerability_id", ""),
        "title": remediation.get("title", ""),
        "description": remediation.get("description", ""),
        "code_before": remediation.get("code_before", ""),
        "code_after": remediation.get("code_after", ""),
        "file_path": remediation.get("file_path", ""),
        "line_number": remediation.get("line_number", 0),
        "difficulty": remediation.get("difficulty", ""),
        "priority": remediation.get("priority", "")
    }
