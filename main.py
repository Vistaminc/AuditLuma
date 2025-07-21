#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
AuditLuma - 高级代码审计AI系统
应用程序的主入口点
"""

import argparse
import os
import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

from loguru import logger

from auditluma.config import Config, load_config
from auditluma.orchestrator import AgentOrchestrator
from auditluma.scanner import CodeScanner
from auditluma.utils import setup_logging, calculate_project_hash
from auditluma.visualizer.report_generator import ReportGenerator
from auditluma.visualizer.graph_visualizer import GraphVisualizer


def init() -> argparse.Namespace:
    """初始化应用程序并解析命令行参数"""
    # 设置日志记录
    setup_logging()
    
    # 配置文件路径
    current_dir = Path(__file__).parent
    config_path = current_dir / "config" / "config.yaml"
    
    # 加载配置
    if config_path.exists():
        load_config(str(config_path))
        logger.info(f"从 {config_path} 加载了配置")
    else:
        logger.warning("未找到config.yaml，使用默认配置")
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="AuditLuma - 高级代码审计AI系统")
    parser.add_argument("-d", "--directory", type=str, default=Config.get_target_dir(), 
                        help=f"目标项目目录路径（默认：{Config.get_target_dir()}）")
    parser.add_argument("-o", "--output", type=str, default=Config.get_report_dir(),
                        help=f"报告输出目录（默认：{Config.get_report_dir()}）")
    parser.add_argument("-w", "--workers", type=int, default=Config.project.max_batch_size,
                        help=f"并行工作线程数（默认：{Config.project.max_batch_size}）")
    parser.add_argument("-f", "--format", type=str, choices=["html", "pdf", "json"], 
                        default=Config.get_report_format(),
                        help=f"报告格式（默认：{Config.get_report_format()}）")
    parser.add_argument("--no-mcp", action="store_true",
                        help="禁用多智能体协作协议")
    parser.add_argument("--no-self-rag", action="store_true",
                        help="禁用Self-RAG检索")
    parser.add_argument("--no-deps", action="store_true",
                        help="跳过依赖分析")
    parser.add_argument("--no-remediation", action="store_true",
                        help="跳过生成修复建议")
    parser.add_argument("--no-cross-file", action="store_true",
                        help="禁用跨文件漏洞检测")
    parser.add_argument("--enhanced-analysis", action="store_true",
                        help="启用增强的跨文件安全分析（实验性功能）")
    parser.add_argument("--verbose", action="store_true",
                        help="启用详细日志记录")
    
    args = parser.parse_args()
    
    # 从参数更新配置
    Config.project.max_batch_size = args.workers
    Config.mcp.enabled = not args.no_mcp
    Config.self_rag.enabled = not args.no_self_rag
    Config.global_config.report_dir = args.output
    Config.global_config.report_format = args.format
    
    # 如果输出目录不存在，则创建它
    output_dir = Path(args.output)
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"创建了输出目录：{args.output}")
    
    # 记录启动信息
    logger.info(f"在以下目录开始AuditLuma分析：{args.directory}")
    logger.info(f"输出将保存到：{args.output}")
    logger.info(f"报告格式：{args.format}")
    logger.info(f"MCP已启用：{Config.mcp.enabled}")
    logger.info(f"Self-RAG已启用：{Config.self_rag.enabled}")
    logger.info(f"依赖分析已启用：{not args.no_deps}")
    logger.info(f"修复建议已启用：{not args.no_remediation}")
    logger.info(f"跨文件分析已启用：{not args.no_cross_file}")
    if args.enhanced_analysis:
        logger.info("✨ 增强跨文件分析模式已启用（实验性功能）")
    
    return args


async def run_analysis(target_dir: str, output_dir: str, workers: int, 
                     skip_deps: bool = False, skip_remediation: bool = False,
                     skip_cross_file: bool = False, enhanced_analysis: bool = False) -> Dict[str, Any]:
    """运行代码分析过程
    
    Args:
        target_dir: 目标项目目录
        output_dir: 输出目录
        workers: 工作线程数
        skip_deps: 是否跳过依赖分析
        skip_remediation: 是否跳过生成修复建议
        skip_cross_file: 是否跳过跨文件漏洞检测
        enhanced_analysis: 是否启用增强的跨文件分析
        
    Returns:
        包含分析结果的字典
    """
    start_time = time.time()
    
    # 确保目标目录为绝对路径
    target_dir_path = Path(target_dir)
    if not target_dir_path.is_absolute():
        target_dir_path = Path(__file__).parent / target_dir_path
    
    # 确保目标目录存在
    if not target_dir_path.exists():
        logger.warning(f"目标目录不存在: {target_dir_path}，尝试创建")
        try:
            target_dir_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"成功创建目标目录: {target_dir_path}")
        except Exception as e:
            logger.error(f"创建目标目录时出错: {e}")
    
    # 计算项目哈希值用于缓存
    project_hash = calculate_project_hash(str(target_dir_path))
    logger.info(f"项目哈希值：{project_hash}")
    
    # 初始化代码扫描器以收集所有源文件
    scanner = CodeScanner(str(target_dir_path))
    # 使用异步扫描加速文件收集
    logger.info("使用异步方式扫描文件...")
    source_files = await scanner.scan_async()
    
    # 统计文件和代码行数
    total_files = len(source_files)
    total_lines = sum(len(sf.content.splitlines()) for sf in source_files)
    logger.info(f"找到{total_files}个要分析的源文件，共{total_lines}行代码")
    
    # 初始化智能体协调器
    orchestrator = AgentOrchestrator(workers=workers)
    await orchestrator.initialize_agents()
    
    # 运行安全分析
    if skip_cross_file:
        logger.info("开始传统安全漏洞分析（跳过跨文件检测）...")
    elif enhanced_analysis:
        logger.info("开始增强安全漏洞分析（包含AI增强的跨文件检测）...")
    else:
        logger.info("开始全面安全漏洞分析（包含跨文件检测）...")
        
    vulnerabilities = await orchestrator.run_security_analysis(
        source_files, 
        skip_cross_file=skip_cross_file, 
        enhanced_analysis=enhanced_analysis
    )
    logger.info(f"安全分析完成：发现{len(vulnerabilities)}个潜在漏洞")
    
    # 运行代码依赖分析（如果未跳过）
    dependency_graph = None
    code_structure = {}
    if not skip_deps:
        logger.info("开始代码依赖分析...")
        code_units = await orchestrator.extract_code_units(source_files)
        code_structure = await orchestrator.run_code_structure_analysis(code_units)
        dependency_graph = orchestrator.get_dependency_graph()
        logger.info(f"代码结构分析完成：分析了{len(code_units)}个代码单元")
    
    # 生成修复建议（如果未跳过）
    remediation_data = None
    if not skip_remediation and vulnerabilities:
        logger.info("开始生成修复建议...")
        remediation_data = await orchestrator.generate_remediations(vulnerabilities)
        logger.info(f"生成了{remediation_data.get('remediation_count', 0)}个修复建议")
    
    # 收集扫描信息
    end_time = time.time()
    scan_duration = end_time - start_time
    
    scan_info = {
        "project_name": Config.project.name,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanned_files": total_files,
        "scanned_lines": total_lines,
        "scan_duration": f"{scan_duration:.2f}秒",
        "project_hash": project_hash
    }
    
    return {
        "vulnerabilities": vulnerabilities,
        "dependency_graph": dependency_graph,
        "code_structure": code_structure,
        "remediation_data": remediation_data,
        "scan_info": scan_info
    }


def generate_report(analysis_results: Dict[str, Any], report_format: str) -> str:
    """生成审计报告
    
    Args:
        analysis_results: 分析结果
        report_format: 报告格式
        
    Returns:
        生成的报告文件路径
    """
    # 初始化报告生成器
    report_generator = ReportGenerator()
    
    # 生成报告
    report_path = report_generator.generate_report(
        vulnerabilities=analysis_results.get("vulnerabilities", []),
        dependency_graph=analysis_results.get("dependency_graph"),
        remediation_data=analysis_results.get("remediation_data"),
        scan_info=analysis_results.get("scan_info", {})
    )
    
    return report_path


def generate_dependency_visualization(dependency_graph, output_dir: str) -> Optional[str]:
    """生成代码依赖关系可视化
    
    Args:
        dependency_graph: 依赖关系图
        output_dir: 输出目录
        
    Returns:
        生成的可视化文件路径
    """
    if not dependency_graph:
        return None
    
    # 初始化图形可视化器
    graph_visualizer = GraphVisualizer()
    
    # 创建交互式依赖关系图
    interactive_graph_path = None
    try:
        interactive_graph_path = graph_visualizer.create_interactive_graph(
            dependency_graph=dependency_graph,
            output_file=str(Path(output_dir) / "dependency_graph_interactive.html")
        )
    except Exception as e:
        logger.error(f"创建交互式依赖图时出错: {e}")
    
    return interactive_graph_path


def save_analysis_data(analysis_results: Dict[str, Any]) -> str:
    """保存分析数据到history目录
    
    Args:
        analysis_results: 分析结果
        
    Returns:
        保存的数据文件路径
    """
    import json
    from pathlib import Path
    
    # 生成文件名 - 包含项目名称
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 获取项目名称并进行清理
    project_name = analysis_results.get("scan_info", {}).get("project_name", "未知项目")
    # 清理项目名称，移除不适合文件名的字符
    safe_project_name = "".join(c for c in project_name if c.isalnum() or c in "._-").rstrip()
    if not safe_project_name:
        safe_project_name = "未知项目"
    
    data_filename = f"Data_{safe_project_name}_{timestamp}.txt"
    data_path = Path("history") / data_filename
    
    # 确保history目录存在
    data_path.parent.mkdir(exist_ok=True)
    
    # 准备要保存的数据
    save_data = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_info": analysis_results.get("scan_info", {}),
        "vulnerabilities_count": len(analysis_results.get("vulnerabilities", [])),
        "vulnerabilities": [],
        "dependency_info": {
            "has_dependency_graph": analysis_results.get("dependency_graph") is not None,
            "dependency_summary": "依赖关系图已生成" if analysis_results.get("dependency_graph") else "未生成依赖关系图"
        },
        "remediation_info": {
            "has_remediation": analysis_results.get("remediation_data") is not None,
            "remediation_count": analysis_results.get("remediation_data", {}).get("remediation_count", 0) if analysis_results.get("remediation_data") else 0
        }
    }
    
    # 处理漏洞数据（序列化VulnerabilityResult对象）
    for vuln in analysis_results.get("vulnerabilities", []):
        vuln_dict = {
            "id": vuln.id,
            "vulnerability_type": vuln.vulnerability_type,
            "severity": vuln.severity,
            "description": vuln.description,
            "file_path": vuln.file_path,
            "start_line": vuln.start_line,
            "end_line": vuln.end_line,
            "snippet": vuln.snippet,
            "metadata": getattr(vuln, 'metadata', {}),
            "cvss4_score": getattr(vuln, 'cvss4_score', None),
            "cvss4_vector": getattr(vuln, 'cvss4_vector', None),
            "cvss4_severity": getattr(vuln, 'cvss4_severity', None)
        }
        save_data["vulnerabilities"].append(vuln_dict)
    
    # 保存完整的分析结果（用于后续报告生成）
    save_data["full_analysis_results"] = {
        "vulnerabilities_serialized": save_data["vulnerabilities"],  # 已序列化的漏洞数据
        "scan_info": analysis_results.get("scan_info", {}),
        "remediation_data": analysis_results.get("remediation_data"),  # 保存修复建议数据
        "dependency_available": analysis_results.get("dependency_graph") is not None,
        "code_structure": analysis_results.get("code_structure", {})
    }
    
    # 写入文件
    with open(data_path, 'w', encoding='utf-8') as f:
        json.dump(save_data, f, ensure_ascii=False, indent=2)
    
    logger.info(f"分析数据已保存到：{data_path}")
    return str(data_path)


async def main() -> None:
    """主入口点"""
    args = init()
    
    try:
        # 运行分析
        analysis_results = await run_analysis(
            target_dir=args.directory,
            output_dir=args.output,
            workers=args.workers,
            skip_deps=args.no_deps,
            skip_remediation=args.no_remediation,
            skip_cross_file=args.no_cross_file,
            enhanced_analysis=args.enhanced_analysis
        )
        
        # 保存分析数据到history目录
        data_path = save_analysis_data(analysis_results)
        
        # 打印摘要
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        severity_counts = {severity: 0 for severity in Config.output.severity_levels}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity.lower()] += 1
        
        logger.info("分析摘要：")
        for severity, count in severity_counts.items():
            logger.info(f"  {severity.upper()}：{count}")
        
        logger.info(f"分析完成！数据已保存到：{data_path}")
        logger.info("请使用Web界面生成不同格式的报告")
        logger.info("运行命令：python -m auditluma.web.report_server")
    
    except Exception as e:
        logger.error(f"分析过程中出错: {e}")
        import traceback
        logger.error(traceback.format_exc())
        logger.error("AuditLuma分析失败")


if __name__ == "__main__":
    asyncio.run(main())
