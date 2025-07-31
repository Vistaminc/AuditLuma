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
# Import AgentOrchestrator from the orchestrator.py file (not the directory)
import importlib.util
import os
orchestrator_path = os.path.join(os.path.dirname(__file__), 'auditluma', 'orchestrator.py')
spec = importlib.util.spec_from_file_location("auditluma.orchestrator_module", orchestrator_path)
orchestrator_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orchestrator_module)
AgentOrchestrator = orchestrator_module.AgentOrchestrator
from auditluma.orchestrator.compatibility import UnifiedOrchestrator, ArchitectureMode, create_unified_orchestrator
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
    
    # 架构选择参数
    parser.add_argument("--architecture", type=str, choices=["traditional", "hierarchical", "auto"], 
                        default="auto",
                        help="选择RAG架构模式：traditional（传统）、hierarchical（层级）、auto（自动选择，默认）")
    parser.add_argument("--force-traditional", action="store_true",
                        help="强制使用传统RAG架构（等同于 --architecture traditional）")
    parser.add_argument("--force-hierarchical", action="store_true",
                        help="强制使用层级RAG架构（等同于 --architecture hierarchical）")
    parser.add_argument("--enable-performance-comparison", action="store_true",
                        help="启用性能对比模式（同时运行两种架构进行对比）")
    parser.add_argument("--auto-switch-threshold", type=int, default=100,
                        help="自动切换架构的文件数量阈值（默认：100）")
    
    # 传统功能参数
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
    
    # 层级RAG特定参数
    parser.add_argument("--haystack-orchestrator", type=str, choices=["traditional", "ai"], 
                        default=None,
                        help="选择Haystack编排器类型：traditional（传统）或 ai（Haystack-AI，默认）")
    parser.add_argument("--enable-txtai", action="store_true",
                        help="启用txtai知识检索层（层级RAG模式）")
    parser.add_argument("--enable-r2r", action="store_true",
                        help="启用R2R上下文增强层（层级RAG模式）")
    parser.add_argument("--enable-self-rag-validation", action="store_true",
                        help="启用Self-RAG验证层（层级RAG模式）")
    parser.add_argument("--disable-caching", action="store_true",
                        help="禁用层级缓存系统")
    parser.add_argument("--disable-monitoring", action="store_true",
                        help="禁用性能监控")
    
    # 其他参数
    parser.add_argument("--verbose", action="store_true",
                        help="启用详细日志记录")
    parser.add_argument("--dry-run", action="store_true",
                        help="试运行模式（不执行实际分析）")
    parser.add_argument("--config-migrate", action="store_true",
                        help="迁移配置到层级RAG格式")
    parser.add_argument("--show-architecture-info", action="store_true",
                        help="显示当前架构信息并退出")
    
    args = parser.parse_args()
    
    # 处理架构选择参数
    if args.force_traditional:
        args.architecture = "traditional"
    elif args.force_hierarchical:
        args.architecture = "hierarchical"
    
    # 处理配置迁移
    if args.config_migrate:
        # 标记需要迁移，在main函数中处理
        args._needs_migration = True
        return args
    
    # 显示架构信息
    if args.show_architecture_info:
        show_architecture_info()
        return args
    
    # 从参数更新配置
    Config.project.max_batch_size = args.workers
    Config.mcp.enabled = not args.no_mcp
    Config.self_rag.enabled = not args.no_self_rag
    Config.global_config.report_dir = args.output
    Config.global_config.report_format = args.format
    
    # 设置架构相关配置
    Config.architecture_mode = args.architecture
    Config.auto_switch_threshold = args.auto_switch_threshold
    Config.enable_performance_comparison = args.enable_performance_comparison
    
    # 设置Haystack编排器类型
    if args.haystack_orchestrator:
        # 更新层级RAG模型配置中的编排器类型
        if hasattr(Config, 'hierarchical_rag_models') and Config.hierarchical_rag_models:
            Config.hierarchical_rag_models.haystack["orchestrator_type"] = args.haystack_orchestrator
    
    # 如果输出目录不存在，则创建它
    output_dir = Path(args.output)
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"创建了输出目录：{args.output}")
    
    # 记录启动信息
    logger.info(f"🚀 在以下目录开始AuditLuma分析：{args.directory}")
    logger.info(f"📁 输出将保存到：{args.output}")
    logger.info(f"📄 报告格式：{args.format}")
    logger.info(f"🏗️ RAG架构模式：{args.architecture}")
    logger.info(f"⚙️ 工作线程数：{args.workers}")
    logger.info(f"🤖 MCP已启用：{Config.mcp.enabled}")
    logger.info(f"🔍 Self-RAG已启用：{Config.self_rag.enabled}")
    logger.info(f"🔗 依赖分析已启用：{not args.no_deps}")
    logger.info(f"🛠️ 修复建议已启用：{not args.no_remediation}")
    logger.info(f"📊 跨文件分析已启用：{not args.no_cross_file}")
    
    if args.architecture == "hierarchical":
        # 显示Haystack编排器类型
        orchestrator_type = args.haystack_orchestrator or (
            Config.hierarchical_rag_models.haystack.get("orchestrator_type", "ai") 
            if hasattr(Config, 'hierarchical_rag_models') and Config.hierarchical_rag_models 
            else "ai"
        )
        orchestrator_name = "Haystack-AI" if orchestrator_type == "ai" else "传统Haystack"
        logger.info(f"🌟 使用层级RAG架构（{orchestrator_name} + txtai + R2R + Self-RAG）")
    elif args.architecture == "traditional":
        logger.info("🔧 使用传统RAG架构")
    else:
        logger.info("🎯 自动选择架构模式（基于项目规模）")
    
    if args.enhanced_analysis:
        logger.info("✨ 增强跨文件分析模式已启用（实验性功能）")
    
    if args.enable_performance_comparison:
        logger.info("📈 性能对比模式已启用")
    
    if args.dry_run:
        logger.info("🧪 试运行模式已启用")
    
    return args


async def handle_config_migration():
    """处理配置迁移"""
    try:
        from auditluma.migration.config_migrator import migrate_config_async
        
        logger.info("🔄 开始配置迁移...")
        success, migration_result = await migrate_config_async()
        
        if success:
            logger.info("✅ 配置迁移成功")
            logger.info(f"📁 备份文件：{migration_result.get('backup_path', 'N/A')}")
            logger.info(f"🔧 应用了 {len(migration_result.get('changes', []))} 个更改")
            
            if migration_result.get('warnings'):
                logger.warning("⚠️ 迁移警告：")
                for warning in migration_result['warnings']:
                    logger.warning(f"  - {warning}")
        else:
            logger.error("❌ 配置迁移失败")
            for error in migration_result.get('errors', []):
                logger.error(f"  - {error}")
                
    except ImportError:
        logger.error("配置迁移工具不可用")
    except Exception as e:
        logger.error(f"配置迁移过程中出错: {e}")


def show_architecture_info():
    """显示架构信息"""
    logger.info("🏗️ AuditLuma架构信息")
    logger.info("=" * 50)
    
    # 显示可用架构
    logger.info("📋 可用架构模式：")
    logger.info("  • traditional - 传统RAG架构（单层智能体协作）")
    logger.info("  • hierarchical - 层级RAG架构（四层：Haystack + txtai + R2R + Self-RAG）")
    logger.info("  • auto - 自动选择（基于项目规模和复杂度）")
    
    # 显示当前配置
    current_mode = getattr(Config, 'architecture_mode', 'auto')
    logger.info(f"\n🎯 当前配置的架构模式：{current_mode}")
    
    # 显示Haystack编排器选择
    logger.info("\n🚀 Haystack编排器选择：")
    try:
        if hasattr(Config, 'hierarchical_rag_models') and Config.hierarchical_rag_models:
            orchestrator_type = Config.hierarchical_rag_models.get_orchestrator_type()
            orchestrator_name = "Haystack-AI编排器" if orchestrator_type == "ai" else "传统Haystack编排器"
            logger.info(f"  • 当前选择：{orchestrator_name} ({orchestrator_type})")
            logger.info(f"  • 可选类型：traditional（传统）、ai（Haystack-AI，推荐）")
            logger.info(f"  • 切换方式：--haystack-orchestrator [traditional|ai]")
        else:
            logger.info("  • 默认：Haystack-AI编排器 (ai)")
    except Exception as e:
        logger.warning(f"  ⚠️ 无法读取编排器配置: {e}")
    
    # 显示层级RAG组件状态
    logger.info("\n🌟 层级RAG组件状态：")
    try:
        hierarchical_config = getattr(Config, 'hierarchical_rag', {})
        if hierarchical_config:
            logger.info(f"  • Haystack编排层：{'✅ 启用' if hierarchical_config.get('haystack', {}).get('enabled', True) else '❌ 禁用'}")
            logger.info(f"  • txtai知识检索层：{'✅ 启用' if hierarchical_config.get('txtai', {}).get('enabled', True) else '❌ 禁用'}")
            logger.info(f"  • R2R上下文增强层：{'✅ 启用' if hierarchical_config.get('r2r', {}).get('enabled', True) else '❌ 禁用'}")
            logger.info(f"  • Self-RAG验证层：{'✅ 启用' if hierarchical_config.get('self_rag_validation', {}).get('enabled', True) else '❌ 禁用'}")
            logger.info(f"  • 层级缓存系统：{'✅ 启用' if hierarchical_config.get('cache', {}).get('enabled', True) else '❌ 禁用'}")
            logger.info(f"  • 性能监控：{'✅ 启用' if hierarchical_config.get('monitoring', {}).get('enabled', True) else '❌ 禁用'}")
        else:
            logger.info("  ⚠️ 层级RAG配置未找到，请运行 --config-migrate 进行配置迁移")
    except Exception as e:
        logger.warning(f"  ⚠️ 无法读取层级RAG配置: {e}")
    
    # 显示兼容性信息
    logger.info("\n🔄 兼容性信息：")
    logger.info("  • 支持从传统架构无缝切换到层级架构")
    logger.info("  • 支持配置热重载和动态架构切换")
    logger.info("  • 提供A/B测试框架进行性能对比")
    logger.info("  • 完全向后兼容现有API和配置")
    
    logger.info("\n💡 使用建议：")
    logger.info("  • 小项目（<100文件）：推荐使用 traditional 架构")
    logger.info("  • 大项目（≥100文件）：推荐使用 hierarchical 架构")
    logger.info("  • 不确定时：使用 auto 模式让系统自动选择")
    logger.info("  • 编排器选择：推荐使用 ai（Haystack-AI编排器）")
    logger.info("  • 性能对比：使用 --enable-performance-comparison 参数")
    
    logger.info("\n🔧 命令示例：")
    logger.info("  • 使用Haystack-AI编排器：--architecture hierarchical --haystack-orchestrator ai")
    logger.info("  • 使用传统编排器：--architecture hierarchical --haystack-orchestrator traditional")
    logger.info("  • 查看架构信息：--show-architecture-info")
    
    logger.info("=" * 50)


async def run_analysis(target_dir: str, output_dir: str, workers: int, 
                     skip_deps: bool = False, skip_remediation: bool = False,
                     skip_cross_file: bool = False, enhanced_analysis: bool = False,
                     architecture_mode: str = "auto", 
                     enable_performance_comparison: bool = False,
                     dry_run: bool = False) -> Dict[str, Any]:
    """运行代码分析过程
    
    Args:
        target_dir: 目标项目目录
        output_dir: 输出目录
        workers: 工作线程数
        skip_deps: 是否跳过依赖分析
        skip_remediation: 是否跳过生成修复建议
        skip_cross_file: 是否跳过跨文件漏洞检测
        enhanced_analysis: 是否启用增强的跨文件分析
        architecture_mode: RAG架构模式
        enable_performance_comparison: 是否启用性能对比
        dry_run: 是否为试运行模式
        
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
    
    # 如果是试运行模式，直接返回模拟结果
    if dry_run:
        logger.info("🧪 试运行模式：跳过实际分析，返回模拟结果")
        return {
            "vulnerabilities": [],
            "dependency_graph": None,
            "code_structure": {},
            "remediation_data": None,
            "scan_info": {
                "project_name": Config.project.name,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scanned_files": total_files,
                "scanned_lines": total_lines,
                "scan_duration": "0.00秒（试运行）",
                "project_hash": project_hash,
                "architecture_mode": architecture_mode,
                "dry_run": True
            }
        }
    
    # 初始化统一编排器（支持架构切换）
    try:
        orchestrator = create_unified_orchestrator(
            workers=workers,
            architecture_mode=architecture_mode,
            enable_performance_comparison=enable_performance_comparison,
            auto_switch_threshold=getattr(Config, 'auto_switch_threshold', 100),
            compatibility_mode=True
        )
        await orchestrator.initialize_orchestrators()
        logger.info(f"🎯 统一编排器初始化完成，当前架构: {orchestrator.current_mode.value if orchestrator.current_mode else 'unknown'}")
        
    except Exception as e:
        logger.warning(f"统一编排器初始化失败，回退到传统编排器: {e}")
        # 回退到传统编排器
        orchestrator = AgentOrchestrator(workers=workers)
        await orchestrator.initialize_agents()
        logger.info("🔧 使用传统编排器")
    
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
    
    # 获取架构信息
    architecture_info = {}
    if hasattr(orchestrator, 'get_orchestrator_info'):
        try:
            architecture_info = orchestrator.get_orchestrator_info()
        except Exception as e:
            logger.debug(f"获取架构信息失败: {e}")
    
    # 获取性能摘要
    performance_summary = {}
    if hasattr(orchestrator, 'get_performance_summary'):
        try:
            performance_summary = orchestrator.get_performance_summary()
        except Exception as e:
            logger.debug(f"获取性能摘要失败: {e}")
    
    scan_info = {
        "project_name": Config.project.name,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanned_files": total_files,
        "scanned_lines": total_lines,
        "scan_duration": f"{scan_duration:.2f}秒",
        "project_hash": project_hash,
        "architecture_mode": architecture_mode,
        "actual_architecture": orchestrator.current_mode.value if hasattr(orchestrator, 'current_mode') and orchestrator.current_mode else "traditional",
        "architecture_info": architecture_info,
        "performance_summary": performance_summary,
        "enable_performance_comparison": enable_performance_comparison
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
    scan_info = analysis_results.get("scan_info", {})
    save_data = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_info": scan_info,
        "vulnerabilities_count": len(analysis_results.get("vulnerabilities", [])),
        "vulnerabilities": [],
        "dependency_info": {
            "has_dependency_graph": analysis_results.get("dependency_graph") is not None,
            "dependency_summary": "依赖关系图已生成" if analysis_results.get("dependency_graph") else "未生成依赖关系图"
        },
        "remediation_info": {
            "has_remediation": analysis_results.get("remediation_data") is not None,
            "remediation_count": analysis_results.get("remediation_data", {}).get("remediation_count", 0) if analysis_results.get("remediation_data") else 0
        },
        "architecture_info": {
            "requested_mode": scan_info.get("architecture_mode", "unknown"),
            "actual_mode": scan_info.get("actual_architecture", "unknown"),
            "performance_comparison_enabled": scan_info.get("enable_performance_comparison", False),
            "architecture_details": scan_info.get("architecture_info", {}),
            "performance_summary": scan_info.get("performance_summary", {})
        }
    }
    
    # 处理漏洞数据（序列化VulnerabilityResult对象）
    for vuln in analysis_results.get("vulnerabilities", []):
        try:
            # 标准化数据类型确保一致性
            vuln_dict = {
                "id": str(vuln.id) if vuln.id else f"vuln_{len(save_data['vulnerabilities'])}",
                "title": getattr(vuln, 'title', vuln.vulnerability_type or "Unknown Vulnerability"),
                "vulnerability_type": str(vuln.vulnerability_type) if vuln.vulnerability_type else "Unknown",
                "severity": str(vuln.severity.value) if hasattr(vuln.severity, 'value') else str(vuln.severity),
                "description": str(vuln.description) if vuln.description else "",
                "file_path": str(vuln.file_path) if vuln.file_path else "unknown",
                "start_line": int(vuln.start_line) if vuln.start_line else 1,
                "end_line": int(vuln.end_line) if vuln.end_line else 1,
                "snippet": str(vuln.snippet) if vuln.snippet else "",
                "metadata": dict(getattr(vuln, 'metadata', {})),
                "cwe_id": getattr(vuln, 'cwe_id', None),
                "owasp_category": getattr(vuln, 'owasp_category', None),
                "confidence": float(getattr(vuln, 'confidence', 1.0)),
                "recommendation": str(getattr(vuln, 'recommendation', "")),
                "references": list(getattr(vuln, 'references', [])),
                "cvss4_score": float(getattr(vuln, 'cvss4_score')) if getattr(vuln, 'cvss4_score') is not None else None,
                "cvss4_vector": str(getattr(vuln, 'cvss4_vector', "")),
                "cvss4_severity": str(getattr(vuln, 'cvss4_severity', ""))
            }
            save_data["vulnerabilities"].append(vuln_dict)
        except Exception as e:
            logger.error(f"序列化漏洞数据时出错: {e}")
            logger.debug(f"问题漏洞对象: {vuln}")
            # 添加最小化的漏洞信息以保持数据完整性
            fallback_vuln = {
                "id": f"error_vuln_{len(save_data['vulnerabilities'])}",
                "title": "数据序列化错误",
                "vulnerability_type": "Serialization Error",
                "severity": "medium",
                "description": f"漏洞数据序列化失败: {str(e)}",
                "file_path": "unknown",
                "start_line": 1,
                "end_line": 1,
                "snippet": "",
                "metadata": {},
                "cvss4_score": None,
                "cvss4_vector": "",
                "cvss4_severity": ""
            }
            save_data["vulnerabilities"].append(fallback_vuln)
    
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
    
    # 处理配置迁移
    if getattr(args, '_needs_migration', False):
        await handle_config_migration()
        return
    
    # 处理特殊命令
    if args.show_architecture_info:
        return
    
    try:
        # 运行分析
        analysis_results = await run_analysis(
            target_dir=args.directory,
            output_dir=args.output,
            workers=args.workers,
            skip_deps=args.no_deps,
            skip_remediation=args.no_remediation,
            skip_cross_file=args.no_cross_file,
            enhanced_analysis=args.enhanced_analysis,
            architecture_mode=args.architecture,
            enable_performance_comparison=args.enable_performance_comparison,
            dry_run=args.dry_run
        )
        
        # 保存分析数据到history目录
        data_path = save_analysis_data(analysis_results)
        
        # 打印摘要
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        scan_info = analysis_results.get("scan_info", {})
        
        if args.dry_run:
            logger.info("🧪 试运行完成")
            logger.info(f"📁 扫描文件数: {scan_info.get('scanned_files', 0)}")
            logger.info(f"📝 代码行数: {scan_info.get('scanned_lines', 0)}")
            logger.info(f"🏗️ 架构模式: {scan_info.get('architecture_mode', 'unknown')}")
            return
        
        # 统计漏洞严重程度
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'unknown')
            if hasattr(severity, 'lower'):
                severity = severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        logger.info("📊 分析摘要：")
        logger.info(f"  📁 扫描文件: {scan_info.get('scanned_files', 0)}")
        logger.info(f"  📝 代码行数: {scan_info.get('scanned_lines', 0)}")
        logger.info(f"  ⏱️ 分析耗时: {scan_info.get('scan_duration', 'N/A')}")
        logger.info(f"  🏗️ 使用架构: {scan_info.get('actual_architecture', 'unknown')}")
        logger.info(f"  🔍 发现漏洞: {len(vulnerabilities)}")
        
        if severity_counts:
            logger.info("  📈 严重程度分布:")
            for severity, count in severity_counts.items():
                logger.info(f"    {severity.upper()}: {count}")
        
        # 显示性能对比信息（如果启用）
        if args.enable_performance_comparison and scan_info.get('performance_summary'):
            perf_summary = scan_info['performance_summary']
            logger.info("📈 性能对比:")
            for arch, stats in perf_summary.get('performance_stats', {}).items():
                if stats.get('calls', 0) > 0:
                    logger.info(f"  {arch}: 平均耗时 {stats.get('avg_time', 0):.2f}秒")
        
        logger.info(f"✅ 分析完成！数据已保存到：{data_path}")
        logger.info("🌐 请使用Web界面生成不同格式的报告")
        logger.info("🚀 运行命令：python -m auditluma.web.report_server")
    
    except Exception as e:
        logger.error(f"分析过程中出错: {e}")
        import traceback
        logger.error(traceback.format_exc())
        logger.error("AuditLuma分析失败")


if __name__ == "__main__":
    asyncio.run(main())
