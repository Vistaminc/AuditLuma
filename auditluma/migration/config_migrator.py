"""
配置迁移工具

从传统配置迁移到层级RAG配置的工具
支持自动迁移、验证、回滚和兼容性检查
"""

import yaml
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import shutil
import asyncio
from enum import Enum

from loguru import logger

try:
    from auditluma.config import Config, HierarchicalRAGConfig
except ImportError:
    logger.warning("无法导入HierarchicalRAGConfig，使用基础配置验证")
    HierarchicalRAGConfig = None


class MigrationType(Enum):
    """迁移类型"""
    TRADITIONAL_TO_HIERARCHICAL = "traditional_to_hierarchical"
    HIERARCHICAL_TO_TRADITIONAL = "hierarchical_to_traditional"
    UPGRADE_HIERARCHICAL = "upgrade_hierarchical"
    COMPATIBILITY_UPDATE = "compatibility_update"


class MigrationStatus(Enum):
    """迁移状态"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    ROLLBACK = "rollback"


class ConfigMigrator:
    """增强的配置迁移器 - 支持层级RAG架构迁移"""
    
    def __init__(self, backup_dir: Optional[str] = None):
        self.migration_history: List[Dict[str, Any]] = []
        self.backup_dir = Path(backup_dir or "./config/backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # 迁移规则和映射
        self.migration_rules = self._load_migration_rules()
        self.validation_rules = self._load_validation_rules()
        
        # 迁移统计
        self.migration_stats = {
            "total_migrations": 0,
            "successful_migrations": 0,
            "failed_migrations": 0,
            "rollbacks": 0
        }
        
        logger.info(f"配置迁移器初始化完成，备份目录: {self.backup_dir}")
    
    def _load_migration_rules(self) -> Dict[str, Any]:
        """加载迁移规则"""
        return {
            "traditional_to_hierarchical": {
                "required_sections": ["hierarchical_rag"],
                "optional_sections": ["compatibility", "migration"],
                "deprecated_sections": [],
                "field_mappings": {
                    "self_rag.enabled": "hierarchical_rag.self_rag_validation.enabled",
                    "self_rag.vector_store": "hierarchical_rag.txtai.vector_store",
                    "self_rag.embedding_model": "hierarchical_rag.txtai.embedding_model",
                    "self_rag.retrieval_k": "hierarchical_rag.txtai.retrieval_k",
                    "self_rag.relevance_threshold": "hierarchical_rag.txtai.similarity_threshold",
                    "project.max_batch_size": "hierarchical_rag.haystack.max_workers",
                    "mcp.enabled": "hierarchical_rag.backward_compatibility",
                    "workers": "hierarchical_rag.haystack.max_workers"
                }
            },
            "hierarchical_to_traditional": {
                "required_sections": ["self_rag", "project"],
                "field_mappings": {
                    "hierarchical_rag.self_rag_validation.enabled": "self_rag.enabled",
                    "hierarchical_rag.txtai.vector_store": "self_rag.vector_store",
                    "hierarchical_rag.txtai.embedding_model": "self_rag.embedding_model",
                    "hierarchical_rag.txtai.retrieval_k": "self_rag.retrieval_k",
                    "hierarchical_rag.txtai.similarity_threshold": "self_rag.relevance_threshold",
                    "hierarchical_rag.haystack.max_workers": "project.max_batch_size"
                }
            }
        }
    
    def _load_validation_rules(self) -> Dict[str, Any]:
        """加载验证规则"""
        return {
            "hierarchical_rag": {
                "required_fields": [
                    "enabled", "architecture_mode", "haystack", "txtai", 
                    "r2r", "self_rag_validation", "cache", "monitoring"
                ],
                "field_types": {
                    "enabled": bool,
                    "architecture_mode": str,
                    "backward_compatibility": bool,
                    "migration_enabled": bool,
                    "ab_testing_enabled": bool,
                    "fallback_to_traditional": bool
                },
                "valid_values": {
                    "architecture_mode": ["traditional", "hierarchical", "auto"],
                    "haystack.enabled": [True, False],
                    "txtai.enabled": [True, False],
                    "r2r.enabled": [True, False],
                    "self_rag_validation.enabled": [True, False]
                }
            }
        }
    
    async def migrate_to_hierarchical_rag(self, config_path: str = "./config/config.yaml", 
                                        force: bool = False, 
                                        dry_run: bool = False) -> Tuple[bool, Dict[str, Any]]:
        """
        将传统配置迁移到层级RAG配置
        
        Args:
            config_path: 配置文件路径
            force: 是否强制迁移（即使已存在层级RAG配置）
            dry_run: 是否只进行试运行（不实际修改文件）
            
        Returns:
            (迁移是否成功, 迁移详情)
        """
        migration_result = {
            "status": MigrationStatus.FAILED,
            "migration_type": MigrationType.TRADITIONAL_TO_HIERARCHICAL,
            "backup_path": None,
            "changes": [],
            "warnings": [],
            "errors": [],
            "validation_results": {}
        }
        
        try:
            self.migration_stats["total_migrations"] += 1
            
            # 1. 预检查
            precheck_result = await self._precheck_migration(config_path, force)
            if not precheck_result["can_migrate"]:
                migration_result["errors"].extend(precheck_result["errors"])
                return False, migration_result
            
            migration_result["warnings"].extend(precheck_result["warnings"])
            
            # 2. 备份原配置（除非是试运行）
            if not dry_run:
                backup_path = self._backup_config(config_path)
                migration_result["backup_path"] = backup_path
                logger.info(f"配置已备份到: {backup_path}")
            
            # 3. 加载现有配置
            with open(config_path, 'r', encoding='utf-8') as file:
                config_data = yaml.safe_load(file) or {}
            
            # 4. 执行迁移
            migrated_config, migration_changes = await self._perform_enhanced_migration(
                config_data, MigrationType.TRADITIONAL_TO_HIERARCHICAL
            )
            migration_result["changes"] = migration_changes
            
            # 5. 验证迁移后的配置
            validation_results = await self._validate_migrated_config(migrated_config)
            migration_result["validation_results"] = validation_results
            
            if validation_results["has_errors"]:
                migration_result["errors"].extend(validation_results["errors"])
                migration_result["status"] = MigrationStatus.FAILED
                logger.error(f"迁移后配置验证失败: {validation_results['errors']}")
                return False, migration_result
            
            if validation_results["has_warnings"]:
                migration_result["warnings"].extend(validation_results["warnings"])
            
            # 6. 保存迁移后的配置（除非是试运行）
            if not dry_run:
                await self._save_config(config_path, migrated_config)
                
                # 7. 记录迁移历史
                await self._record_enhanced_migration(
                    config_path, migration_result["backup_path"], migration_result
                )
            
            migration_result["status"] = MigrationStatus.SUCCESS
            self.migration_stats["successful_migrations"] += 1
            
            logger.info(f"配置迁移{'试运行' if dry_run else ''}完成")
            return True, migration_result
            
        except Exception as e:
            migration_result["errors"].append(f"迁移过程异常: {str(e)}")
            migration_result["status"] = MigrationStatus.FAILED
            self.migration_stats["failed_migrations"] += 1
            logger.error(f"配置迁移失败: {e}")
            return False, migration_result
    
    async def _precheck_migration(self, config_path: str, force: bool) -> Dict[str, Any]:
        """迁移前检查"""
        result = {
            "can_migrate": True,
            "errors": [],
            "warnings": []
        }
        
        try:
            # 检查文件是否存在
            if not Path(config_path).exists():
                result["can_migrate"] = False
                result["errors"].append(f"配置文件不存在: {config_path}")
                return result
            
            # 加载配置
            with open(config_path, 'r', encoding='utf-8') as file:
                config_data = yaml.safe_load(file) or {}
            
            # 检查是否已经是层级RAG配置
            if "hierarchical_rag" in config_data and not force:
                result["can_migrate"] = False
                result["errors"].append("配置已包含层级RAG设置，使用 --force 强制迁移")
                return result
            
            # 检查配置完整性
            if not config_data:
                result["warnings"].append("配置文件为空，将创建默认层级RAG配置")
            
            # 检查潜在的配置冲突
            conflicts = self._check_config_conflicts(config_data)
            if conflicts:
                result["warnings"].extend([f"配置冲突: {conflict}" for conflict in conflicts])
            
            # 检查依赖项
            missing_deps = self._check_dependencies()
            if missing_deps:
                result["warnings"].extend([f"缺少依赖: {dep}" for dep in missing_deps])
            
        except Exception as e:
            result["can_migrate"] = False
            result["errors"].append(f"预检查失败: {str(e)}")
        
        return result
    
    def _check_config_conflicts(self, config_data: Dict[str, Any]) -> List[str]:
        """检查配置冲突"""
        conflicts = []
        
        # 检查Self-RAG配置冲突
        if "self_rag" in config_data:
            self_rag_config = config_data["self_rag"]
            if self_rag_config.get("enabled") is False:
                conflicts.append("Self-RAG已禁用，可能影响层级RAG功能")
        
        # 检查MCP配置冲突
        if "mcp" in config_data:
            mcp_config = config_data["mcp"]
            if mcp_config.get("enabled") is False:
                conflicts.append("MCP已禁用，可能影响智能体协作")
        
        return conflicts
    
    def _check_dependencies(self) -> List[str]:
        """检查依赖项"""
        missing_deps = []
        
        try:
            # 检查必要的模块
            import txtai
        except ImportError:
            missing_deps.append("txtai")
        
        try:
            import haystack
        except ImportError:
            missing_deps.append("haystack")
        
        return missing_deps
    
    async def _perform_enhanced_migration(self, config_data: Dict[str, Any], 
                                        migration_type: MigrationType) -> Tuple[Dict[str, Any], List[str]]:
        """执行增强的配置迁移"""
        changes = []
        migrated_config = config_data.copy()
        
        if migration_type == MigrationType.TRADITIONAL_TO_HIERARCHICAL:
            # 创建层级RAG配置
            hierarchical_config, config_changes = self._create_hierarchical_config(config_data)
            migrated_config["hierarchical_rag"] = hierarchical_config
            changes.extend(config_changes)
            
            # 应用字段映射
            mapping_changes = self._apply_field_mappings(
                config_data, migrated_config, 
                self.migration_rules["traditional_to_hierarchical"]["field_mappings"]
            )
            changes.extend(mapping_changes)
            
            # 添加兼容性配置
            compatibility_changes = self._add_compatibility_config(migrated_config)
            changes.extend(compatibility_changes)
            
        elif migration_type == MigrationType.HIERARCHICAL_TO_TRADITIONAL:
            # 反向迁移逻辑
            traditional_changes = self._migrate_to_traditional(migrated_config)
            changes.extend(traditional_changes)
        
        return migrated_config, changes
    
    def migrate_to_hierarchical_rag_sync(self, config_path: str = "./config/config.yaml") -> bool:
        """同步版本的迁移方法（兼容性）"""
        try:
            # 1. 备份原配置
            backup_path = self._backup_config(config_path)
            logger.info(f"配置已备份到: {backup_path}")
            
            # 2. 加载现有配置
            with open(config_path, 'r', encoding='utf-8') as file:
                config_data = yaml.safe_load(file) or {}
            
            # 3. 检查是否已经是层级RAG配置
            if "hierarchical_rag" in config_data:
                logger.info("配置已经包含层级RAG设置")
                return True
            
            # 4. 执行迁移
            migrated_config = self._perform_migration(config_data)
            
            # 5. 验证迁移后的配置
            validation_errors = self._validate_migrated_config_sync(migrated_config)
            if validation_errors:
                logger.error(f"迁移后配置验证失败: {validation_errors}")
                return False
            
            # 6. 保存迁移后的配置
            with open(config_path, 'w', encoding='utf-8') as file:
                yaml.dump(migrated_config, file, default_flow_style=False, 
                         allow_unicode=True, indent=2)
            
            # 7. 记录迁移历史
            self._record_migration(config_path, backup_path)
            
            logger.info("配置迁移完成")
            return True
            
        except Exception as e:
            logger.error(f"配置迁移失败: {e}")
            return False
    
    def _validate_migrated_config_sync(self, config_data: Dict[str, Any]) -> List[str]:
        """验证迁移后的配置（同步版本）"""
        errors = []
        
        try:
            # 尝试创建HierarchicalRAGConfig实例来验证
            if "hierarchical_rag" in config_data:
                if HierarchicalRAGConfig:
                    hierarchical_config = HierarchicalRAGConfig(**config_data["hierarchical_rag"])
                    if hasattr(hierarchical_config, 'validate_configuration'):
                        validation_errors = hierarchical_config.validate_configuration()
                        errors.extend(validation_errors)
                else:
                    # 基本验证
                    hierarchical_config = config_data["hierarchical_rag"]
                    required_sections = ["haystack", "txtai", "r2r", "self_rag_validation"]
                    for section in required_sections:
                        if section not in hierarchical_config:
                            errors.append(f"缺少必需配置节: {section}")
        except Exception as e:
            errors.append(f"层级RAG配置格式错误: {e}")
        
        return errors
    
    def _create_hierarchical_config(self, existing_config: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """创建层级RAG配置"""
        changes = []
        
        # 基础层级RAG配置
        hierarchical_config = {
            "enabled": False,  # 默认关闭，需要用户手动启用
            "architecture_mode": "auto",  # 自动选择架构
            "haystack": {
                "enabled": True,
                "max_workers": self._get_optimal_workers(existing_config),
                "task_timeout": 300,
                "retry_attempts": 3,
                "retry_delay": 1.0,
                "enable_parallel_execution": True,
                "load_balancing": True,
                "performance_monitoring": True,
                "task_scheduling_strategy": "hybrid"
            },
            "txtai": {
                "enabled": True,
                "cve_database_url": "https://cve.circl.lu/api",
                "cve_cache_ttl": 3600,
                "best_practices_sources": ["owasp", "sans", "nist"],
                "historical_cases_limit": 100,
                "similarity_threshold": 0.8,
                "retrieval_timeout": 30,
                "enable_incremental_update": True,
                "knowledge_cache_size": 1000,
                "vector_store": existing_config.get("self_rag", {}).get("vector_store", "default"),
                "embedding_model": existing_config.get("self_rag", {}).get("embedding_model", "sentence-transformers/all-MiniLM-L6-v2"),
                "retrieval_k": existing_config.get("self_rag", {}).get("retrieval_k", 5)
            },
            "r2r": {
                "enabled": True,
                "max_call_depth": 10,
                "enable_cross_file_analysis": True,
                "enable_data_flow_analysis": True,
                "enable_taint_analysis": True,
                "context_window_size": 500,
                "semantic_similarity_threshold": 0.7,
                "impact_assessment_enabled": True,
                "context_expansion_enabled": True,
                "call_graph_cache_enabled": True,
                "dataflow_cache_enabled": True
            },
            "self_rag_validation": {
                "enabled": existing_config.get("self_rag", {}).get("enabled", True),
                "cross_validation_enabled": True,
                "confidence_threshold": 0.7,
                "false_positive_filter_enabled": True,
                "quality_assessment_enabled": True,
                "validation_timeout": 60,
                "min_consensus_score": 0.6,
                "explanation_required": True,
                "multi_model_validation": False
            },
            "cache": {
                "enabled": True,
                "l1_cache_size": "256MB",
                "l2_cache_size": "2GB",
                "distributed_cache_enabled": False,
                "redis_url": "redis://localhost:6379",
                "cache_ttl": 3600,
                "cache_compression": True,
                "cache_encryption": False
            },
            "monitoring": {
                "enabled": True,
                "performance_tracking": True,
                "quality_tracking": True,
                "health_check_interval": 60,
                "metrics_retention_days": 30,
                "alert_thresholds": {
                    "processing_time": 300.0,
                    "error_rate": 0.1,
                    "confidence_score": 0.5,
                    "memory_usage": 0.8,
                    "cpu_usage": 0.9
                },
                "log_level": "INFO",
                "enable_detailed_logging": False
            },
            "security": {
                "enabled": True,
                "data_encryption": False,
                "access_control": False,
                "audit_logging": True,
                "rate_limiting": True,
                "max_requests_per_minute": 100,
                "api_key_required": False,
                "secure_headers": True,
                "input_validation": True,
                "output_sanitization": True
            },
            "backward_compatibility": True,
            "migration_enabled": True,
            "ab_testing_enabled": False,
            "fallback_to_traditional": True,
            "auto_switch_threshold": 100,
            "enable_performance_comparison": False
        }
        
        changes.append("创建了完整的层级RAG配置")
        changes.append(f"设置工作线程数为: {hierarchical_config['haystack']['max_workers']}")
        
        if existing_config.get("self_rag", {}).get("enabled"):
            changes.append("从现有Self-RAG配置迁移了相关设置")
        
        return hierarchical_config, changes
    
    def _get_optimal_workers(self, existing_config: Dict[str, Any]) -> int:
        """获取最优工作线程数"""
        # 从现有配置获取
        if "project" in existing_config:
            batch_size = existing_config["project"].get("max_batch_size", 10)
            return min(batch_size, 20)  # 限制最大值
        
        # 从全局配置获取
        try:
            return getattr(Config, 'workers', 10)
        except:
            return 10
    
    def _apply_field_mappings(self, source_config: Dict[str, Any], 
                            target_config: Dict[str, Any], 
                            mappings: Dict[str, str]) -> List[str]:
        """应用字段映射"""
        changes = []
        
        for source_path, target_path in mappings.items():
            source_value = self._get_nested_value(source_config, source_path)
            if source_value is not None:
                self._set_nested_value(target_config, target_path, source_value)
                changes.append(f"映射字段: {source_path} -> {target_path} = {source_value}")
        
        return changes
    
    def _get_nested_value(self, config: Dict[str, Any], path: str) -> Any:
        """获取嵌套配置值"""
        keys = path.split('.')
        value = config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return None
    
    def _set_nested_value(self, config: Dict[str, Any], path: str, value: Any) -> None:
        """设置嵌套配置值"""
        keys = path.split('.')
        current = config
        
        # 创建嵌套结构
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # 设置最终值
        current[keys[-1]] = value
    
    def _add_compatibility_config(self, config: Dict[str, Any]) -> List[str]:
        """添加兼容性配置"""
        changes = []
        
        # 添加兼容性部分
        if "compatibility" not in config:
            config["compatibility"] = {
                "enable_legacy_api": True,
                "legacy_orchestrator_fallback": True,
                "maintain_existing_interfaces": True,
                "gradual_migration_mode": True
            }
            changes.append("添加了兼容性配置")
        
        # 添加迁移部分
        if "migration" not in config:
            config["migration"] = {
                "auto_backup": True,
                "backup_retention_days": 30,
                "enable_rollback": True,
                "migration_validation": True,
                "dry_run_support": True
            }
            changes.append("添加了迁移配置")
        
        return changes
    
    def _migrate_to_traditional(self, config: Dict[str, Any]) -> List[str]:
        """迁移到传统配置"""
        changes = []
        
        if "hierarchical_rag" in config:
            hierarchical_config = config["hierarchical_rag"]
            
            # 迁移Self-RAG设置
            if "self_rag" not in config:
                config["self_rag"] = {}
            
            self_rag_validation = hierarchical_config.get("self_rag_validation", {})
            config["self_rag"]["enabled"] = self_rag_validation.get("enabled", True)
            
            txtai_config = hierarchical_config.get("txtai", {})
            config["self_rag"]["vector_store"] = txtai_config.get("vector_store", "default")
            config["self_rag"]["embedding_model"] = txtai_config.get("embedding_model", "sentence-transformers/all-MiniLM-L6-v2")
            config["self_rag"]["retrieval_k"] = txtai_config.get("retrieval_k", 5)
            config["self_rag"]["relevance_threshold"] = txtai_config.get("similarity_threshold", 0.8)
            
            changes.append("迁移了Self-RAG配置")
            
            # 迁移项目设置
            if "project" not in config:
                config["project"] = {}
            
            haystack_config = hierarchical_config.get("haystack", {})
            config["project"]["max_batch_size"] = haystack_config.get("max_workers", 10)
            
            changes.append("迁移了项目配置")
            
            # 移除层级RAG配置
            del config["hierarchical_rag"]
            changes.append("移除了层级RAG配置")
        
        return changes
    
    async def _save_config(self, config_path: str, config_data: Dict[str, Any]) -> None:
        """保存配置文件"""
        with open(config_path, 'w', encoding='utf-8') as file:
            yaml.dump(config_data, file, default_flow_style=False, 
                     allow_unicode=True, indent=2, sort_keys=False)
    
    def _backup_config(self, config_path: str) -> str:
        """备份配置文件"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"config_backup_{timestamp}.yaml"
        backup_path = self.backup_dir / backup_filename
        
        shutil.copy2(config_path, backup_path)
        return str(backup_path)
    
    def _perform_migration(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行配置迁移"""
        # 创建层级RAG配置
        hierarchical_rag_config = {
            "enabled": False,  # 默认关闭，需要用户手动启用
            "architecture_mode": "traditional",  # 保持传统模式
            "haystack": {
                "enabled": True,
                "max_workers": 10,
                "task_timeout": 300,
                "retry_attempts": 3,
                "retry_delay": 1.0,
                "enable_parallel_execution": True,
                "load_balancing": True,
                "performance_monitoring": True
            },
            "txtai": {
                "enabled": True,
                "cve_database_url": "https://cve.circl.lu/api",
                "cve_cache_ttl": 3600,
                "best_practices_sources": ["owasp", "sans", "nist"],
                "historical_cases_limit": 100,
                "similarity_threshold": 0.8,
                "retrieval_timeout": 30,
                "enable_incremental_update": True,
                "knowledge_cache_size": 1000
            },
            "r2r": {
                "enabled": True,
                "max_call_depth": 10,
                "enable_cross_file_analysis": True,
                "enable_data_flow_analysis": True,
                "enable_taint_analysis": True,
                "context_window_size": 500,
                "semantic_similarity_threshold": 0.7,
                "impact_assessment_enabled": True,
                "context_expansion_enabled": True
            },
            "self_rag_validation": {
                "enabled": True,
                "cross_validation_enabled": True,
                "confidence_threshold": 0.7,
                "false_positive_filter_enabled": True,
                "quality_assessment_enabled": True,
                "validation_timeout": 60,
                "min_consensus_score": 0.6,
                "explanation_required": True
            },
            "cache": {
                "enabled": True,
                "l1_cache_size": "256MB",
                "l2_cache_size": "2GB",
                "distributed_cache_enabled": False,
                "redis_url": "redis://localhost:6379",
                "cache_ttl": 3600,
                "cache_compression": True
            },
            "monitoring": {
                "enabled": True,
                "performance_tracking": True,
                "quality_tracking": True,
                "health_check_interval": 60,
                "metrics_retention_days": 30,
                "alert_thresholds": {
                    "processing_time": 300.0,
                    "error_rate": 0.1,
                    "confidence_score": 0.5
                },
                "log_level": "INFO"
            },
            "security": {
                "enabled": True,
                "data_encryption": False,
                "access_control": False,
                "audit_logging": True,
                "rate_limiting": True,
                "max_requests_per_minute": 100,
                "api_key_required": False,
                "secure_headers": True
            },
            "backward_compatibility": True,
            "migration_enabled": True,
            "ab_testing_enabled": False,
            "fallback_to_traditional": True
        }
        
        # 从现有Self-RAG配置迁移相关设置
        if "self_rag" in config_data:
            self_rag_config = config_data["self_rag"]
            
            # 迁移txtai相关设置
            if "vector_store" in self_rag_config:
                hierarchical_rag_config["txtai"]["vector_store"] = self_rag_config["vector_store"]
            
            if "embedding_model" in self_rag_config:
                hierarchical_rag_config["txtai"]["embedding_model"] = self_rag_config["embedding_model"]
            
            if "retrieval_k" in self_rag_config:
                hierarchical_rag_config["txtai"]["retrieval_k"] = self_rag_config["retrieval_k"]
            
            if "relevance_threshold" in self_rag_config:
                hierarchical_rag_config["txtai"]["similarity_threshold"] = self_rag_config["relevance_threshold"]
            
            # 迁移Self-RAG验证设置
            if "enabled" in self_rag_config:
                hierarchical_rag_config["self_rag_validation"]["enabled"] = self_rag_config["enabled"]
        
        # 从项目配置迁移相关设置
        if "project" in config_data:
            project_config = config_data["project"]
            
            if "max_batch_size" in project_config:
                hierarchical_rag_config["haystack"]["max_workers"] = min(
                    project_config["max_batch_size"], 20
                )
        
        # 添加层级RAG配置到原配置中
        migrated_config = config_data.copy()
        migrated_config["hierarchical_rag"] = hierarchical_rag_config
        
        return migrated_config
    
    async def _validate_migrated_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """验证迁移后的配置"""
        validation_result = {
            "has_errors": False,
            "has_warnings": False,
            "errors": [],
            "warnings": [],
            "validation_details": {}
        }
        
        try:
            # 验证层级RAG配置
            if "hierarchical_rag" in config_data:
                hierarchical_validation = self._validate_hierarchical_config(
                    config_data["hierarchical_rag"]
                )
                validation_result["validation_details"]["hierarchical_rag"] = hierarchical_validation
                
                if hierarchical_validation["errors"]:
                    validation_result["has_errors"] = True
                    validation_result["errors"].extend(hierarchical_validation["errors"])
                
                if hierarchical_validation["warnings"]:
                    validation_result["has_warnings"] = True
                    validation_result["warnings"].extend(hierarchical_validation["warnings"])
            
            # 验证配置完整性
            completeness_validation = self._validate_config_completeness(config_data)
            validation_result["validation_details"]["completeness"] = completeness_validation
            
            if completeness_validation["missing_required"]:
                validation_result["has_errors"] = True
                validation_result["errors"].extend([
                    f"缺少必需配置: {field}" for field in completeness_validation["missing_required"]
                ])
            
            # 验证配置一致性
            consistency_validation = self._validate_config_consistency(config_data)
            validation_result["validation_details"]["consistency"] = consistency_validation
            
            if consistency_validation["inconsistencies"]:
                validation_result["has_warnings"] = True
                validation_result["warnings"].extend([
                    f"配置不一致: {issue}" for issue in consistency_validation["inconsistencies"]
                ])
            
            # 尝试使用HierarchicalRAGConfig验证（如果可用）
            if HierarchicalRAGConfig and "hierarchical_rag" in config_data:
                try:
                    hierarchical_config = HierarchicalRAGConfig(**config_data["hierarchical_rag"])
                    if hasattr(hierarchical_config, 'validate_configuration'):
                        config_errors = hierarchical_config.validate_configuration()
                        if config_errors:
                            validation_result["has_errors"] = True
                            validation_result["errors"].extend(config_errors)
                except Exception as e:
                    validation_result["has_warnings"] = True
                    validation_result["warnings"].append(f"HierarchicalRAGConfig验证警告: {e}")
            
        except Exception as e:
            validation_result["has_errors"] = True
            validation_result["errors"].append(f"配置验证异常: {str(e)}")
        
        return validation_result
    
    def _validate_hierarchical_config(self, hierarchical_config: Dict[str, Any]) -> Dict[str, Any]:
        """验证层级RAG配置"""
        result = {
            "errors": [],
            "warnings": [],
            "validated_sections": []
        }
        
        # 验证必需字段
        required_sections = ["haystack", "txtai", "r2r", "self_rag_validation", "cache", "monitoring"]
        for section in required_sections:
            if section not in hierarchical_config:
                result["errors"].append(f"缺少必需配置节: {section}")
            else:
                result["validated_sections"].append(section)
        
        # 验证字段类型和值
        validation_rules = self.validation_rules.get("hierarchical_rag", {})
        
        for field, expected_type in validation_rules.get("field_types", {}).items():
            value = self._get_nested_value(hierarchical_config, field)
            if value is not None and not isinstance(value, expected_type):
                result["errors"].append(f"字段类型错误: {field} 应为 {expected_type.__name__}")
        
        for field, valid_values in validation_rules.get("valid_values", {}).items():
            value = self._get_nested_value(hierarchical_config, field)
            if value is not None and value not in valid_values:
                result["errors"].append(f"字段值无效: {field} = {value}, 有效值: {valid_values}")
        
        # 验证数值范围
        self._validate_numeric_ranges(hierarchical_config, result)
        
        return result
    
    def _validate_numeric_ranges(self, config: Dict[str, Any], result: Dict[str, Any]) -> None:
        """验证数值范围"""
        numeric_validations = {
            "haystack.max_workers": (1, 100),
            "haystack.task_timeout": (10, 3600),
            "haystack.retry_attempts": (0, 10),
            "txtai.cve_cache_ttl": (60, 86400),
            "txtai.similarity_threshold": (0.0, 1.0),
            "r2r.max_call_depth": (1, 50),
            "r2r.context_window_size": (100, 2000),
            "self_rag_validation.confidence_threshold": (0.0, 1.0),
            "cache.cache_ttl": (60, 86400),
            "monitoring.health_check_interval": (10, 3600)
        }
        
        for field, (min_val, max_val) in numeric_validations.items():
            value = self._get_nested_value(config, field)
            if value is not None:
                try:
                    num_value = float(value)
                    if not (min_val <= num_value <= max_val):
                        result["warnings"].append(
                            f"数值超出建议范围: {field} = {value}, 建议范围: [{min_val}, {max_val}]"
                        )
                except (ValueError, TypeError):
                    result["errors"].append(f"数值字段格式错误: {field} = {value}")
    
    def _validate_config_completeness(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """验证配置完整性"""
        result = {
            "missing_required": [],
            "missing_optional": [],
            "extra_fields": []
        }
        
        # 检查必需的顶级配置
        required_top_level = ["hierarchical_rag"]
        for field in required_top_level:
            if field not in config_data:
                result["missing_required"].append(field)
        
        # 检查可选的顶级配置
        optional_top_level = ["compatibility", "migration"]
        for field in optional_top_level:
            if field not in config_data:
                result["missing_optional"].append(field)
        
        return result
    
    def _validate_config_consistency(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """验证配置一致性"""
        result = {
            "inconsistencies": [],
            "recommendations": []
        }
        
        if "hierarchical_rag" in config_data:
            hierarchical_config = config_data["hierarchical_rag"]
            
            # 检查架构模式一致性
            architecture_mode = hierarchical_config.get("architecture_mode", "auto")
            if architecture_mode == "traditional" and hierarchical_config.get("enabled", False):
                result["inconsistencies"].append(
                    "架构模式为traditional但层级RAG已启用"
                )
            
            # 检查缓存配置一致性
            cache_config = hierarchical_config.get("cache", {})
            if cache_config.get("distributed_cache_enabled") and not cache_config.get("redis_url"):
                result["inconsistencies"].append(
                    "启用了分布式缓存但未配置Redis URL"
                )
            
            # 检查监控配置一致性
            monitoring_config = hierarchical_config.get("monitoring", {})
            if monitoring_config.get("enabled") and not monitoring_config.get("performance_tracking"):
                result["recommendations"].append(
                    "建议启用性能跟踪以获得更好的监控效果"
                )
        
        return result
    
    async def _record_enhanced_migration(self, config_path: str, backup_path: str, 
                                       migration_result: Dict[str, Any]) -> None:
        """记录增强的迁移历史"""
        migration_record = {
            "timestamp": datetime.now().isoformat(),
            "config_path": config_path,
            "backup_path": backup_path,
            "migration_type": migration_result["migration_type"].value,
            "status": migration_result["status"].value,
            "changes_count": len(migration_result["changes"]),
            "warnings_count": len(migration_result["warnings"]),
            "errors_count": len(migration_result["errors"]),
            "changes": migration_result["changes"],
            "warnings": migration_result["warnings"],
            "errors": migration_result["errors"],
            "validation_results": migration_result["validation_results"],
            "migration_stats": self.migration_stats.copy()
        }
        
        self.migration_history.append(migration_record)
        
        # 保存迁移历史到文件
        history_file = self.backup_dir / "migration_history.json"
        try:
            if history_file.exists():
                with open(history_file, 'r', encoding='utf-8') as file:
                    existing_history = json.load(file)
            else:
                existing_history = []
            
            existing_history.append(migration_record)
            
            with open(history_file, 'w', encoding='utf-8') as file:
                json.dump(existing_history, file, indent=2, ensure_ascii=False)
            
            logger.info(f"迁移历史已记录到: {history_file}")
                
        except Exception as e:
            logger.warning(f"无法保存迁移历史: {e}")
    
    def _record_migration(self, config_path: str, backup_path: str):
        """记录迁移历史（兼容性方法）"""
        migration_record = {
            "timestamp": datetime.now().isoformat(),
            "config_path": config_path,
            "backup_path": backup_path,
            "migration_type": "traditional_to_hierarchical_rag",
            "success": True
        }
        
        self.migration_history.append(migration_record)
        
        # 保存迁移历史到文件
        history_file = self.backup_dir / "migration_history.json"
        try:
            if history_file.exists():
                with open(history_file, 'r', encoding='utf-8') as file:
                    existing_history = json.load(file)
            else:
                existing_history = []
            
            existing_history.append(migration_record)
            
            with open(history_file, 'w', encoding='utf-8') as file:
                json.dump(existing_history, file, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.warning(f"无法保存迁移历史: {e}")
    
    async def rollback_migration(self, backup_path: str, config_path: str = "./config/config.yaml", 
                               verify_rollback: bool = True) -> Tuple[bool, Dict[str, Any]]:
        """
        回滚配置迁移
        
        Args:
            backup_path: 备份文件路径
            config_path: 目标配置文件路径
            verify_rollback: 是否验证回滚后的配置
            
        Returns:
            (回滚是否成功, 回滚详情)
        """
        rollback_result = {
            "status": MigrationStatus.FAILED,
            "backup_path": backup_path,
            "rollback_backup_path": None,
            "errors": [],
            "warnings": [],
            "validation_results": {}
        }
        
        try:
            self.migration_stats["rollbacks"] += 1
            
            # 检查备份文件是否存在
            if not Path(backup_path).exists():
                rollback_result["errors"].append(f"备份文件不存在: {backup_path}")
                return False, rollback_result
            
            # 验证备份文件
            backup_validation = await self._validate_backup_file(backup_path)
            if backup_validation["has_errors"]:
                rollback_result["errors"].extend(backup_validation["errors"])
                return False, rollback_result
            
            if backup_validation["has_warnings"]:
                rollback_result["warnings"].extend(backup_validation["warnings"])
            
            # 备份当前配置（以防回滚失败）
            current_backup = self._backup_config(config_path)
            rollback_result["rollback_backup_path"] = current_backup
            logger.info(f"当前配置已备份到: {current_backup}")
            
            # 恢复备份
            shutil.copy2(backup_path, config_path)
            
            # 验证回滚后的配置（如果启用）
            if verify_rollback:
                with open(config_path, 'r', encoding='utf-8') as file:
                    restored_config = yaml.safe_load(file) or {}
                
                validation_results = await self._validate_restored_config(restored_config)
                rollback_result["validation_results"] = validation_results
                
                if validation_results["has_errors"]:
                    rollback_result["errors"].extend(validation_results["errors"])
                    rollback_result["status"] = MigrationStatus.PARTIAL
                    logger.warning("回滚完成但配置验证发现问题")
                else:
                    rollback_result["status"] = MigrationStatus.ROLLBACK
            else:
                rollback_result["status"] = MigrationStatus.ROLLBACK
            
            # 记录回滚历史
            await self._record_rollback(config_path, backup_path, rollback_result)
            
            logger.info(f"配置已从 {backup_path} 回滚")
            return True, rollback_result
            
        except Exception as e:
            rollback_result["errors"].append(f"回滚过程异常: {str(e)}")
            logger.error(f"配置回滚失败: {e}")
            return False, rollback_result
    
    async def _validate_backup_file(self, backup_path: str) -> Dict[str, Any]:
        """验证备份文件"""
        result = {
            "has_errors": False,
            "has_warnings": False,
            "errors": [],
            "warnings": []
        }
        
        try:
            with open(backup_path, 'r', encoding='utf-8') as file:
                backup_config = yaml.safe_load(file)
            
            if not backup_config:
                result["has_errors"] = True
                result["errors"].append("备份文件为空或格式错误")
                return result
            
            # 检查备份文件的基本结构
            if not isinstance(backup_config, dict):
                result["has_errors"] = True
                result["errors"].append("备份文件格式不正确")
            
        except yaml.YAMLError as e:
            result["has_errors"] = True
            result["errors"].append(f"备份文件YAML格式错误: {e}")
        except Exception as e:
            result["has_errors"] = True
            result["errors"].append(f"读取备份文件失败: {e}")
        
        return result
    
    async def _validate_restored_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """验证恢复后的配置"""
        # 使用基本的配置验证
        result = {
            "has_errors": False,
            "has_warnings": False,
            "errors": [],
            "warnings": []
        }
        
        try:
            # 检查配置基本结构
            if not isinstance(config_data, dict):
                result["has_errors"] = True
                result["errors"].append("配置格式不正确")
                return result
            
            # 检查是否包含层级RAG配置
            if "hierarchical_rag" in config_data:
                result["warnings"].append("恢复的配置仍包含层级RAG设置")
            
            # 检查传统配置的完整性
            if "self_rag" not in config_data:
                result["warnings"].append("缺少Self-RAG配置")
            
            if "project" not in config_data:
                result["warnings"].append("缺少项目配置")
            
        except Exception as e:
            result["has_errors"] = True
            result["errors"].append(f"配置验证异常: {str(e)}")
        
        return result
    
    async def _record_rollback(self, config_path: str, backup_path: str, 
                             rollback_result: Dict[str, Any]) -> None:
        """记录回滚历史"""
        rollback_record = {
            "timestamp": datetime.now().isoformat(),
            "action": "rollback",
            "config_path": config_path,
            "backup_path": backup_path,
            "rollback_backup_path": rollback_result["rollback_backup_path"],
            "status": rollback_result["status"].value,
            "errors_count": len(rollback_result["errors"]),
            "warnings_count": len(rollback_result["warnings"]),
            "errors": rollback_result["errors"],
            "warnings": rollback_result["warnings"],
            "validation_results": rollback_result["validation_results"]
        }
        
        # 保存到迁移历史
        history_file = self.backup_dir / "migration_history.json"
        try:
            if history_file.exists():
                with open(history_file, 'r', encoding='utf-8') as file:
                    existing_history = json.load(file)
            else:
                existing_history = []
            
            existing_history.append(rollback_record)
            
            with open(history_file, 'w', encoding='utf-8') as file:
                json.dump(existing_history, file, indent=2, ensure_ascii=False)
            
            logger.info(f"回滚历史已记录到: {history_file}")
                
        except Exception as e:
            logger.warning(f"无法保存回滚历史: {e}")
    
    # 兼容性方法
    def rollback_migration_sync(self, backup_path: str, config_path: str = "./config/config.yaml") -> bool:
        """同步回滚方法（兼容性）"""
        try:
            if not Path(backup_path).exists():
                logger.error(f"备份文件不存在: {backup_path}")
                return False
            
            # 备份当前配置（以防回滚失败）
            current_backup = self._backup_config(config_path)
            logger.info(f"当前配置已备份到: {current_backup}")
            
            # 恢复备份
            shutil.copy2(backup_path, config_path)
            
            logger.info(f"配置已从 {backup_path} 回滚")
            return True
            
        except Exception as e:
            logger.error(f"配置回滚失败: {e}")
            return False
    
    def get_migration_history(self) -> List[Dict[str, Any]]:
        """获取迁移历史"""
        history_file = self.backup_dir / "migration_history.json"
        
        try:
            if history_file.exists():
                with open(history_file, 'r', encoding='utf-8') as file:
                    return json.load(file)
        except Exception as e:
            logger.warning(f"无法读取迁移历史: {e}")
        
        return []
    
    def check_compatibility(self, config_path: str = "./config/config.yaml") -> Dict[str, Any]:
        """
        检查配置兼容性
        
        Args:
            config_path: 配置文件路径
            
        Returns:
            兼容性检查结果
        """
        result = {
            "compatible": True,
            "issues": [],
            "recommendations": []
        }
        
        try:
            with open(config_path, 'r', encoding='utf-8') as file:
                config_data = yaml.safe_load(file) or {}
            
            # 检查是否已有层级RAG配置
            if "hierarchical_rag" not in config_data:
                result["issues"].append("缺少层级RAG配置")
                result["recommendations"].append("运行配置迁移工具")
            
            # 检查Self-RAG配置兼容性
            if "self_rag" in config_data:
                self_rag_config = config_data["self_rag"]
                if not self_rag_config.get("enabled", True):
                    result["issues"].append("Self-RAG已禁用，可能影响层级RAG功能")
                    result["recommendations"].append("考虑启用Self-RAG或调整层级RAG配置")
            
            # 检查项目配置
            if "project" in config_data:
                project_config = config_data["project"]
                if project_config.get("max_batch_size", 20) > 50:
                    result["issues"].append("批处理大小过大，可能影响性能")
                    result["recommendations"].append("考虑减少max_batch_size")
            
            if result["issues"]:
                result["compatible"] = False
            
        except Exception as e:
            result["compatible"] = False
            result["issues"].append(f"配置文件读取错误: {e}")
        
        return result


class ConfigHotReloader:
    """配置热重载器"""
    
    def __init__(self, config_path: str = "./config/config.yaml"):
        self.config_path = config_path
        self.last_modified = 0
        self.callbacks: List[callable] = []
    
    def add_callback(self, callback: callable):
        """添加配置变更回调"""
        self.callbacks.append(callback)
    
    def check_for_changes(self) -> bool:
        """检查配置文件是否有变更"""
        try:
            current_modified = Path(self.config_path).stat().st_mtime
            if current_modified > self.last_modified:
                self.last_modified = current_modified
                return True
        except Exception as e:
            logger.warning(f"检查配置文件变更失败: {e}")
        
        return False
    
    def reload_config(self):
        """重新加载配置"""
        try:
            from auditluma.config import load_config
            load_config(self.config_path)
            
            # 执行回调
            for callback in self.callbacks:
                try:
                    callback()
                except Exception as e:
                    logger.error(f"配置重载回调执行失败: {e}")
            
            logger.info("配置已重新加载")
            
        except Exception as e:
            logger.error(f"配置重载失败: {e}")
    
    def start_watching(self, interval: int = 5):
        """开始监听配置文件变更"""
        import time
        import threading
        
        def watch_loop():
            while True:
                if self.check_for_changes():
                    self.reload_config()
                time.sleep(interval)
        
        watch_thread = threading.Thread(target=watch_loop, daemon=True)
        watch_thread.start()
        logger.info(f"开始监听配置文件变更: {self.config_path}")


    async def migrate_from_hierarchical_to_traditional(self, config_path: str = "./config/config.yaml",
                                                     dry_run: bool = False) -> Tuple[bool, Dict[str, Any]]:
        """从层级RAG配置迁移回传统配置"""
        migration_result = {
            "status": MigrationStatus.FAILED,
            "migration_type": MigrationType.HIERARCHICAL_TO_TRADITIONAL,
            "backup_path": None,
            "changes": [],
            "warnings": [],
            "errors": [],
            "validation_results": {}
        }
        
        try:
            # 检查是否存在层级RAG配置
            with open(config_path, 'r', encoding='utf-8') as file:
                config_data = yaml.safe_load(file) or {}
            
            if "hierarchical_rag" not in config_data:
                migration_result["errors"].append("配置中不存在层级RAG设置")
                return False, migration_result
            
            # 备份当前配置
            if not dry_run:
                backup_path = self._backup_config(config_path)
                migration_result["backup_path"] = backup_path
                logger.info(f"配置已备份到: {backup_path}")
            
            # 执行反向迁移
            migrated_config, migration_changes = await self._perform_enhanced_migration(
                config_data, MigrationType.HIERARCHICAL_TO_TRADITIONAL
            )
            migration_result["changes"] = migration_changes
            
            # 验证迁移后的配置
            validation_results = await self._validate_traditional_config(migrated_config)
            migration_result["validation_results"] = validation_results
            
            if validation_results["has_errors"]:
                migration_result["errors"].extend(validation_results["errors"])
                return False, migration_result
            
            # 保存配置
            if not dry_run:
                await self._save_config(config_path, migrated_config)
                await self._record_enhanced_migration(
                    config_path, migration_result["backup_path"], migration_result
                )
            
            migration_result["status"] = MigrationStatus.SUCCESS
            logger.info(f"反向迁移{'试运行' if dry_run else ''}完成")
            return True, migration_result
            
        except Exception as e:
            migration_result["errors"].append(f"反向迁移异常: {str(e)}")
            logger.error(f"反向迁移失败: {e}")
            return False, migration_result
    
    async def _validate_traditional_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """验证传统配置"""
        result = {
            "has_errors": False,
            "has_warnings": False,
            "errors": [],
            "warnings": []
        }
        
        # 检查必需的传统配置节
        required_sections = ["self_rag", "project"]
        for section in required_sections:
            if section not in config_data:
                result["has_warnings"] = True
                result["warnings"].append(f"缺少传统配置节: {section}")
        
        # 检查Self-RAG配置
        if "self_rag" in config_data:
            self_rag_config = config_data["self_rag"]
            if not isinstance(self_rag_config.get("enabled"), bool):
                result["has_errors"] = True
                result["errors"].append("self_rag.enabled 必须是布尔值")
        
        return result
    
    def get_migration_statistics(self) -> Dict[str, Any]:
        """获取迁移统计信息"""
        return {
            "migration_stats": self.migration_stats.copy(),
            "success_rate": (
                self.migration_stats["successful_migrations"] / 
                max(self.migration_stats["total_migrations"], 1)
            ) * 100,
            "total_history_entries": len(self.migration_history),
            "backup_directory": str(self.backup_dir),
            "available_backups": len(list(self.backup_dir.glob("config_backup_*.yaml")))
        }
    
    def cleanup_old_backups(self, retention_days: int = 30) -> int:
        """清理旧备份文件"""
        cutoff_time = datetime.now().timestamp() - (retention_days * 24 * 3600)
        cleaned_count = 0
        
        try:
            for backup_file in self.backup_dir.glob("config_backup_*.yaml"):
                if backup_file.stat().st_mtime < cutoff_time:
                    backup_file.unlink()
                    cleaned_count += 1
                    logger.debug(f"删除旧备份: {backup_file}")
            
            logger.info(f"清理了 {cleaned_count} 个旧备份文件")
            
        except Exception as e:
            logger.error(f"清理备份文件失败: {e}")
        
        return cleaned_count


# ==================== 便捷函数 ====================

async def migrate_config_async(config_path: str = "./config/config.yaml", 
                              force: bool = False, 
                              dry_run: bool = False) -> Tuple[bool, Dict[str, Any]]:
    """异步迁移配置到层级RAG"""
    migrator = ConfigMigrator()
    return await migrator.migrate_to_hierarchical_rag(config_path, force, dry_run)


def migrate_config(config_path: str = "./config/config.yaml") -> bool:
    """迁移配置到层级RAG（同步版本，兼容性）"""
    migrator = ConfigMigrator()
    # 使用原有的同步方法
    return migrator.migrate_to_hierarchical_rag_sync(config_path)


async def rollback_config_async(backup_path: str, 
                               config_path: str = "./config/config.yaml",
                               verify_rollback: bool = True) -> Tuple[bool, Dict[str, Any]]:
    """异步回滚配置"""
    migrator = ConfigMigrator()
    return await migrator.rollback_migration(backup_path, config_path, verify_rollback)


def rollback_config(backup_path: str, config_path: str = "./config/config.yaml") -> bool:
    """回滚配置（同步版本，兼容性）"""
    migrator = ConfigMigrator()
    return migrator.rollback_migration_sync(backup_path, config_path)


def check_config_compatibility(config_path: str = "./config/config.yaml") -> Dict[str, Any]:
    """检查配置兼容性"""
    migrator = ConfigMigrator()
    return migrator.check_compatibility(config_path)


async def migrate_to_traditional_async(config_path: str = "./config/config.yaml",
                                     dry_run: bool = False) -> Tuple[bool, Dict[str, Any]]:
    """异步迁移回传统配置"""
    migrator = ConfigMigrator()
    return await migrator.migrate_from_hierarchical_to_traditional(config_path, dry_run)


def get_migration_info(backup_dir: Optional[str] = None) -> Dict[str, Any]:
    """获取迁移信息"""
    migrator = ConfigMigrator(backup_dir)
    return {
        "statistics": migrator.get_migration_statistics(),
        "history": migrator.get_migration_history(),
        "backup_directory": str(migrator.backup_dir)
    }


if __name__ == "__main__":
    # 命令行工具
    import argparse
    
    parser = argparse.ArgumentParser(description="配置迁移工具")
    parser.add_argument("action", choices=["migrate", "rollback", "check"], 
                       help="执行的操作")
    parser.add_argument("--config", default="./config/config.yaml", 
                       help="配置文件路径")
    parser.add_argument("--backup", help="备份文件路径（用于回滚）")
    
    args = parser.parse_args()
    
    if args.action == "migrate":
        success = migrate_config(args.config)
        print("迁移成功" if success else "迁移失败")
    
    elif args.action == "rollback":
        if not args.backup:
            print("回滚操作需要指定备份文件路径")
        else:
            success = rollback_config(args.backup, args.config)
            print("回滚成功" if success else "回滚失败")
    
    elif args.action == "check":
        result = check_config_compatibility(args.config)
        print(f"兼容性: {'通过' if result['compatible'] else '失败'}")
        if result["issues"]:
            print("问题:")
            for issue in result["issues"]:
                print(f"  - {issue}")
        if result["recommendations"]:
            print("建议:")
            for rec in result["recommendations"]:
                print(f"  - {rec}")