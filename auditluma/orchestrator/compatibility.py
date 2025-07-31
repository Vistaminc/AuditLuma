"""
兼容性包装器 - 统一传统RAG和层级RAG架构的接口
提供配置驱动的架构切换机制
"""

import asyncio
from typing import List, Dict, Any, Optional, Union
from enum import Enum
from dataclasses import dataclass
import time

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult


class ArchitectureMode(Enum):
    """架构模式枚举"""
    TRADITIONAL = "traditional"  # 传统RAG架构
    HIERARCHICAL = "hierarchical"  # 层级RAG架构
    AUTO = "auto"  # 自动选择


@dataclass
class ArchitectureConfig:
    """架构配置"""
    mode: ArchitectureMode
    fallback_mode: ArchitectureMode = ArchitectureMode.TRADITIONAL
    auto_switch_threshold: int = 100  # 文件数量阈值，超过则自动切换到层级架构
    enable_performance_comparison: bool = False  # 是否启用性能对比
    compatibility_mode: bool = True  # 是否启用兼容性模式


class UnifiedOrchestrator:
    """统一编排器 - 提供传统RAG和层级RAG的统一接口"""
    
    def __init__(self, workers: int = 10, architecture_config: Optional[ArchitectureConfig] = None):
        """初始化统一编排器
        
        Args:
            workers: 工作线程数
            architecture_config: 架构配置，如果为None则从全局配置读取
        """
        self.workers = workers
        self.architecture_config = architecture_config or self._load_architecture_config()
        
        # 当前使用的架构模式
        self.current_mode = None
        
        # 编排器实例
        self._traditional_orchestrator = None
        self._hierarchical_orchestrator = None
        self._active_orchestrator = None
        
        # 性能统计
        self.performance_stats = {
            "traditional": {"calls": 0, "total_time": 0.0, "avg_time": 0.0},
            "hierarchical": {"calls": 0, "total_time": 0.0, "avg_time": 0.0}
        }
        
        # 兼容性状态
        self.compatibility_mode = self.architecture_config.compatibility_mode
        
        logger.info(f"统一编排器初始化完成，架构模式: {self.architecture_config.mode.value}")
        logger.info(f"兼容性模式: {'启用' if self.compatibility_mode else '禁用'}")
    
    def _load_architecture_config(self) -> ArchitectureConfig:
        """从配置文件加载架构配置"""
        try:
            # 从全局配置读取架构设置
            config_mode = getattr(Config, 'architecture_mode', 'auto')
            
            # 转换字符串到枚举
            if isinstance(config_mode, str):
                try:
                    mode = ArchitectureMode(config_mode.lower())
                except ValueError:
                    logger.warning(f"无效的架构模式配置: {config_mode}，使用默认AUTO模式")
                    mode = ArchitectureMode.AUTO
            else:
                mode = config_mode
            
            # 读取其他配置
            fallback_mode = getattr(Config, 'fallback_architecture_mode', 'traditional')
            try:
                fallback = ArchitectureMode(fallback_mode.lower())
            except ValueError:
                fallback = ArchitectureMode.TRADITIONAL
            
            auto_switch_threshold = getattr(Config, 'auto_switch_threshold', 100)
            enable_performance_comparison = getattr(Config, 'enable_performance_comparison', False)
            compatibility_mode = getattr(Config, 'compatibility_mode', True)
            
            return ArchitectureConfig(
                mode=mode,
                fallback_mode=fallback,
                auto_switch_threshold=auto_switch_threshold,
                enable_performance_comparison=enable_performance_comparison,
                compatibility_mode=compatibility_mode
            )
            
        except Exception as e:
            logger.warning(f"加载架构配置失败: {e}，使用默认配置")
            return ArchitectureConfig(mode=ArchitectureMode.AUTO)
    
    async def initialize_orchestrators(self) -> None:
        """初始化编排器实例"""
        logger.info("初始化编排器实例...")
        
        try:
            # 初始化传统编排器
            if self._should_init_traditional():
                await self._init_traditional_orchestrator()
            
            # 初始化层级编排器
            if self._should_init_hierarchical():
                await self._init_hierarchical_orchestrator()
            
            # 设置活跃编排器
            await self._set_active_orchestrator()
            
            logger.info(f"编排器初始化完成，当前使用: {self.current_mode.value}")
            
        except Exception as e:
            logger.error(f"初始化编排器失败: {e}")
            # 回退到传统架构
            await self._fallback_to_traditional()
    
    def _should_init_traditional(self) -> bool:
        """判断是否需要初始化传统编排器"""
        return (
            self.architecture_config.mode in [ArchitectureMode.TRADITIONAL, ArchitectureMode.AUTO] or
            self.architecture_config.fallback_mode == ArchitectureMode.TRADITIONAL or
            self.architecture_config.enable_performance_comparison
        )
    
    def _should_init_hierarchical(self) -> bool:
        """判断是否需要初始化层级编排器"""
        return (
            self.architecture_config.mode in [ArchitectureMode.HIERARCHICAL, ArchitectureMode.AUTO] or
            self.architecture_config.fallback_mode == ArchitectureMode.HIERARCHICAL or
            self.architecture_config.enable_performance_comparison
        )
    
    async def _init_traditional_orchestrator(self) -> None:
        """初始化传统编排器"""
        try:
            # Import AgentOrchestrator from the orchestrator.py file (not the directory)
            import importlib.util
            import os
            orchestrator_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'orchestrator.py')
            spec = importlib.util.spec_from_file_location("auditluma.orchestrator_module", orchestrator_path)
            orchestrator_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(orchestrator_module)
            AgentOrchestrator = orchestrator_module.AgentOrchestrator
            
            self._traditional_orchestrator = AgentOrchestrator(workers=self.workers)
            await self._traditional_orchestrator.initialize_agents()
            logger.info("传统编排器初始化成功")
        except Exception as e:
            logger.error(f"初始化传统编排器失败: {e}")
            raise
    
    async def _init_hierarchical_orchestrator(self) -> None:
        """初始化层级编排器"""
        try:
            # 获取编排器类型配置
            orchestrator_type = self._get_orchestrator_type()
            
            if orchestrator_type == "ai":
                # 使用Haystack-AI编排器
                try:
                    from auditluma.orchestrator.haystack_ai_orchestrator import HaystackAIOrchestrator
                    self._hierarchical_orchestrator = HaystackAIOrchestrator(workers=self.workers)
                    logger.info("Haystack-AI编排器初始化成功")
                except ImportError as e:
                    logger.warning(f"Haystack-AI编排器不可用: {e}，回退到传统编排器")
                    from auditluma.orchestrator.haystack_orchestrator import HaystackOrchestrator
                    self._hierarchical_orchestrator = HaystackOrchestrator(workers=self.workers)
                    logger.info("传统Haystack编排器初始化成功（回退）")
            else:
                # 使用传统编排器
                from auditluma.orchestrator.haystack_orchestrator import HaystackOrchestrator
                self._hierarchical_orchestrator = HaystackOrchestrator(workers=self.workers)
                logger.info("传统Haystack编排器初始化成功")
                
        except Exception as e:
            logger.error(f"初始化层级编排器失败: {e}")
            raise
    
    def _get_orchestrator_type(self) -> str:
        """获取编排器类型"""
        try:
            from auditluma.config import Config
            if hasattr(Config, 'hierarchical_rag_models') and Config.hierarchical_rag_models:
                return Config.hierarchical_rag_models.get_orchestrator_type()
            return "ai"  # 默认使用Haystack-AI
        except Exception as e:
            logger.warning(f"获取编排器类型失败: {e}，使用默认值")
            return "ai"
    
    async def _set_active_orchestrator(self) -> None:
        """设置活跃的编排器"""
        if self.architecture_config.mode == ArchitectureMode.TRADITIONAL:
            if self._traditional_orchestrator:
                self._active_orchestrator = self._traditional_orchestrator
                self.current_mode = ArchitectureMode.TRADITIONAL
            else:
                raise RuntimeError("传统编排器未初始化")
                
        elif self.architecture_config.mode == ArchitectureMode.HIERARCHICAL:
            if self._hierarchical_orchestrator:
                self._active_orchestrator = self._hierarchical_orchestrator
                self.current_mode = ArchitectureMode.HIERARCHICAL
            else:
                raise RuntimeError("层级编排器未初始化")
                
        elif self.architecture_config.mode == ArchitectureMode.AUTO:
            # AUTO模式默认使用层级架构，如果不可用则回退到传统架构
            if self._hierarchical_orchestrator:
                self._active_orchestrator = self._hierarchical_orchestrator
                self.current_mode = ArchitectureMode.HIERARCHICAL
            elif self._traditional_orchestrator:
                self._active_orchestrator = self._traditional_orchestrator
                self.current_mode = ArchitectureMode.TRADITIONAL
            else:
                raise RuntimeError("没有可用的编排器")
    
    async def _fallback_to_traditional(self) -> None:
        """回退到传统架构"""
        logger.warning("回退到传统架构")
        try:
            if not self._traditional_orchestrator:
                await self._init_traditional_orchestrator()
            
            self._active_orchestrator = self._traditional_orchestrator
            self.current_mode = ArchitectureMode.TRADITIONAL
            
        except Exception as e:
            logger.error(f"回退到传统架构失败: {e}")
            raise RuntimeError("无法初始化任何编排器")
    
    async def switch_architecture(self, target_mode: ArchitectureMode) -> bool:
        """动态切换架构模式
        
        Args:
            target_mode: 目标架构模式
            
        Returns:
            切换是否成功
        """
        if target_mode == self.current_mode:
            logger.info(f"已经在使用 {target_mode.value} 架构")
            return True
        
        logger.info(f"切换架构模式: {self.current_mode.value} -> {target_mode.value}")
        
        try:
            if target_mode == ArchitectureMode.TRADITIONAL:
                if not self._traditional_orchestrator:
                    await self._init_traditional_orchestrator()
                self._active_orchestrator = self._traditional_orchestrator
                
            elif target_mode == ArchitectureMode.HIERARCHICAL:
                if not self._hierarchical_orchestrator:
                    await self._init_hierarchical_orchestrator()
                self._active_orchestrator = self._hierarchical_orchestrator
                
            else:
                logger.error(f"不支持切换到 {target_mode.value} 模式")
                return False
            
            self.current_mode = target_mode
            logger.info(f"架构切换成功: {target_mode.value}")
            return True
            
        except Exception as e:
            logger.error(f"架构切换失败: {e}")
            return False
    
    def _should_auto_switch(self, source_files: List[SourceFile]) -> Optional[ArchitectureMode]:
        """判断是否应该自动切换架构
        
        Args:
            source_files: 源文件列表
            
        Returns:
            建议的架构模式，None表示不需要切换
        """
        if self.architecture_config.mode != ArchitectureMode.AUTO:
            return None
        
        file_count = len(source_files)
        threshold = self.architecture_config.auto_switch_threshold
        
        # 根据文件数量决定架构
        if file_count >= threshold:
            # 大项目使用层级架构
            if self.current_mode != ArchitectureMode.HIERARCHICAL:
                logger.info(f"文件数量 {file_count} >= {threshold}，建议切换到层级架构")
                return ArchitectureMode.HIERARCHICAL
        else:
            # 小项目使用传统架构
            if self.current_mode != ArchitectureMode.TRADITIONAL:
                logger.info(f"文件数量 {file_count} < {threshold}，建议切换到传统架构")
                return ArchitectureMode.TRADITIONAL
        
        return None
    
    # ==================== 统一接口方法 ====================
    
    async def initialize_agents(self) -> None:
        """初始化智能体 - 统一接口"""
        if not self._active_orchestrator:
            await self.initialize_orchestrators()
        
        # 调用活跃编排器的初始化方法
        if hasattr(self._active_orchestrator, 'initialize_agents'):
            await self._active_orchestrator.initialize_agents()
        else:
            logger.info(f"{self.current_mode.value} 编排器不需要显式初始化智能体")
    
    async def extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """提取代码单元 - 统一接口"""
        if not self._active_orchestrator:
            await self.initialize_orchestrators()
        
        # 检查是否需要自动切换架构
        suggested_mode = self._should_auto_switch(source_files)
        if suggested_mode:
            await self.switch_architecture(suggested_mode)
        
        return await self._active_orchestrator.extract_code_units(source_files)
    
    async def run_security_analysis(self, source_files: List[SourceFile], 
                                   skip_cross_file: bool = False, 
                                   enhanced_analysis: bool = False) -> List[VulnerabilityResult]:
        """运行安全分析 - 统一接口"""
        if not self._active_orchestrator:
            await self.initialize_orchestrators()
        
        # 检查是否需要自动切换架构
        suggested_mode = self._should_auto_switch(source_files)
        if suggested_mode:
            await self.switch_architecture(suggested_mode)
        
        start_time = time.time()
        
        try:
            # 调用活跃编排器的安全分析方法
            if self.current_mode == ArchitectureMode.HIERARCHICAL:
                # 层级架构使用orchestrate_audit方法
                audit_result = await self._active_orchestrator.orchestrate_audit(source_files)
                vulnerabilities = audit_result.vulnerabilities
            else:
                # 传统架构使用run_security_analysis方法
                vulnerabilities = await self._active_orchestrator.run_security_analysis(
                    source_files, skip_cross_file, enhanced_analysis
                )
            
            # 更新性能统计
            execution_time = time.time() - start_time
            self._update_performance_stats(self.current_mode.value, execution_time)
            
            logger.info(f"安全分析完成 ({self.current_mode.value})，发现 {len(vulnerabilities)} 个漏洞，耗时 {execution_time:.2f}秒")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"安全分析失败 ({self.current_mode.value}): {e}")
            
            # 如果当前不是回退模式，尝试回退
            if self.current_mode != self.architecture_config.fallback_mode:
                logger.info(f"尝试回退到 {self.architecture_config.fallback_mode.value} 架构")
                if await self.switch_architecture(self.architecture_config.fallback_mode):
                    return await self.run_security_analysis(source_files, skip_cross_file, enhanced_analysis)
            
            raise
    
    async def run_code_structure_analysis(self, code_units: List[CodeUnit]) -> Dict[str, Any]:
        """运行代码结构分析 - 统一接口"""
        if not self._active_orchestrator:
            await self.initialize_orchestrators()
        
        return await self._active_orchestrator.run_code_structure_analysis(code_units)
    
    async def generate_remediations(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """生成修复建议 - 统一接口"""
        if not self._active_orchestrator:
            await self.initialize_orchestrators()
        
        return await self._active_orchestrator.generate_remediations(vulnerabilities)
    
    async def run_analysis(self, source_files: List[SourceFile]) -> List[VulnerabilityResult]:
        """运行分析 - 统一接口"""
        return await self.run_security_analysis(source_files)
    
    async def generate_summary(self, vulnerabilities: List[VulnerabilityResult], 
                             assessment: Dict[str, Any] = None) -> str:
        """生成摘要 - 统一接口"""
        if not self._active_orchestrator:
            await self.initialize_orchestrators()
        
        # 添加架构信息到摘要
        base_summary = await self._active_orchestrator.generate_summary(vulnerabilities, assessment)
        
        # 添加统一编排器的信息
        architecture_info = f"\n\n🏗️ 架构信息:\n  - 当前架构: {self.current_mode.value}\n  - 兼容性模式: {'启用' if self.compatibility_mode else '禁用'}"
        
        # 添加性能对比信息（如果启用）
        if self.architecture_config.enable_performance_comparison:
            perf_info = self._get_performance_comparison()
            if perf_info:
                architecture_info += f"\n  - 性能对比: {perf_info}"
        
        return base_summary + architecture_info
    
    # ==================== 性能监控和对比 ====================
    
    def _update_performance_stats(self, mode: str, execution_time: float) -> None:
        """更新性能统计"""
        if mode in self.performance_stats:
            stats = self.performance_stats[mode]
            stats["calls"] += 1
            stats["total_time"] += execution_time
            stats["avg_time"] = stats["total_time"] / stats["calls"]
    
    def _get_performance_comparison(self) -> Optional[str]:
        """获取性能对比信息"""
        traditional_stats = self.performance_stats["traditional"]
        hierarchical_stats = self.performance_stats["hierarchical"]
        
        if traditional_stats["calls"] == 0 or hierarchical_stats["calls"] == 0:
            return None
        
        traditional_avg = traditional_stats["avg_time"]
        hierarchical_avg = hierarchical_stats["avg_time"]
        
        if traditional_avg > hierarchical_avg:
            improvement = ((traditional_avg - hierarchical_avg) / traditional_avg) * 100
            return f"层级架构比传统架构快 {improvement:.1f}%"
        else:
            degradation = ((hierarchical_avg - traditional_avg) / traditional_avg) * 100
            return f"层级架构比传统架构慢 {degradation:.1f}%"
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """获取性能摘要"""
        return {
            "current_mode": self.current_mode.value if self.current_mode else None,
            "performance_stats": self.performance_stats.copy(),
            "architecture_config": {
                "mode": self.architecture_config.mode.value,
                "fallback_mode": self.architecture_config.fallback_mode.value,
                "auto_switch_threshold": self.architecture_config.auto_switch_threshold,
                "enable_performance_comparison": self.architecture_config.enable_performance_comparison,
                "compatibility_mode": self.architecture_config.compatibility_mode
            }
        }
    
    # ==================== 兼容性方法 ====================
    
    @property
    def agents(self) -> Dict[str, Any]:
        """获取智能体字典 - 兼容性属性"""
        if self._active_orchestrator and hasattr(self._active_orchestrator, 'agents'):
            return self._active_orchestrator.agents
        return {}
    
    @property
    def code_units(self) -> List[CodeUnit]:
        """获取代码单元列表 - 兼容性属性"""
        if self._active_orchestrator and hasattr(self._active_orchestrator, 'code_units'):
            return self._active_orchestrator.code_units
        return []
    
    def get_dependency_graph(self):
        """获取代码依赖关系图
        
        Returns:
            依赖关系图对象
        """
        if self._active_orchestrator and hasattr(self._active_orchestrator, 'dependency_graph'):
            return self._active_orchestrator.dependency_graph
        elif self._active_orchestrator and hasattr(self._active_orchestrator, 'get_dependency_graph'):
            return self._active_orchestrator.get_dependency_graph()
        else:
            logger.warning("当前编排器不支持依赖关系图功能")
            return None

    def get_orchestrator_info(self) -> Dict[str, Any]:
        """获取编排器信息"""
        return {
            "unified_orchestrator": {
                "current_mode": self.current_mode.value if self.current_mode else None,
                "architecture_config": {
                    "mode": self.architecture_config.mode.value,
                    "fallback_mode": self.architecture_config.fallback_mode.value,
                    "auto_switch_threshold": self.architecture_config.auto_switch_threshold,
                    "enable_performance_comparison": self.architecture_config.enable_performance_comparison,
                    "compatibility_mode": self.architecture_config.compatibility_mode
                },
                "traditional_available": self._traditional_orchestrator is not None,
                "hierarchical_available": self._hierarchical_orchestrator is not None,
                "active_orchestrator": type(self._active_orchestrator).__name__ if self._active_orchestrator else None
            },
            "performance_stats": self.performance_stats
        }


# ==================== 工厂函数 ====================

def create_unified_orchestrator(workers: int = 10, 
                               architecture_mode: Optional[str] = None,
                               **kwargs) -> UnifiedOrchestrator:
    """创建统一编排器的工厂函数
    
    Args:
        workers: 工作线程数
        architecture_mode: 架构模式 ('traditional', 'hierarchical', 'auto')
        **kwargs: 其他配置参数
        
    Returns:
        统一编排器实例
    """
    # 构建架构配置
    if architecture_mode:
        try:
            mode = ArchitectureMode(architecture_mode.lower())
        except ValueError:
            logger.warning(f"无效的架构模式: {architecture_mode}，使用AUTO模式")
            mode = ArchitectureMode.AUTO
    else:
        mode = ArchitectureMode.AUTO
    
    architecture_config = ArchitectureConfig(
        mode=mode,
        fallback_mode=ArchitectureMode(kwargs.get('fallback_mode', 'traditional')),
        auto_switch_threshold=kwargs.get('auto_switch_threshold', 100),
        enable_performance_comparison=kwargs.get('enable_performance_comparison', False),
        compatibility_mode=kwargs.get('compatibility_mode', True)
    )
    
    return UnifiedOrchestrator(workers=workers, architecture_config=architecture_config)


# ==================== 配置驱动的架构选择 ====================

async def get_orchestrator_for_config() -> UnifiedOrchestrator:
    """根据配置创建合适的编排器
    
    Returns:
        配置好的统一编排器实例
    """
    # 从配置文件读取设置
    workers = getattr(Config, 'workers', 10)
    architecture_mode = getattr(Config, 'architecture_mode', 'auto')
    
    # 创建统一编排器
    orchestrator = create_unified_orchestrator(
        workers=workers,
        architecture_mode=architecture_mode,
        fallback_mode=getattr(Config, 'fallback_architecture_mode', 'traditional'),
        auto_switch_threshold=getattr(Config, 'auto_switch_threshold', 100),
        enable_performance_comparison=getattr(Config, 'enable_performance_comparison', False),
        compatibility_mode=getattr(Config, 'compatibility_mode', True)
    )
    
    # 初始化编排器
    await orchestrator.initialize_orchestrators()
    
    return orchestrator