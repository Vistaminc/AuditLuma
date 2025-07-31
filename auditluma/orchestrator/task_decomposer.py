"""
任务分解器 - 层级RAG架构任务分解组件
负责将代码审计任务分解为具体的子任务
"""

import uuid
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from pathlib import Path

from loguru import logger

from auditluma.models.code import SourceFile, CodeUnit


class TaskType(Enum):
    """审计任务类型"""
    SYNTAX_CHECK = "syntax_check"
    LOGIC_ANALYSIS = "logic_analysis"
    SECURITY_SCAN = "security_scan"
    DEPENDENCY_ANALYSIS = "dependency_analysis"


class TaskPriority(Enum):
    """任务优先级"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class TaskDependency:
    """任务依赖关系"""
    task_id: str
    dependency_type: str  # "requires", "blocks", "enhances"
    description: str = ""


@dataclass
class AuditTask:
    """审计任务定义"""
    id: str
    task_type: TaskType
    priority: TaskPriority
    source_files: List[SourceFile]
    code_units: List[CodeUnit]
    dependencies: List[TaskDependency] = field(default_factory=list)
    estimated_duration: float = 0.0  # 预估执行时间（秒）
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """任务创建后的初始化"""
        if not self.estimated_duration:
            self.estimated_duration = self._estimate_duration()
    
    def _estimate_duration(self) -> float:
        """估算任务执行时间"""
        base_time = {
            TaskType.SYNTAX_CHECK: 0.5,
            TaskType.LOGIC_ANALYSIS: 2.0,
            TaskType.SECURITY_SCAN: 3.0,
            TaskType.DEPENDENCY_ANALYSIS: 1.5
        }
        
        # 基础时间
        duration = base_time.get(self.task_type, 1.0)
        
        # 根据代码单元数量调整
        unit_count = len(self.code_units)
        if unit_count > 10:
            duration *= 1.5
        elif unit_count > 50:
            duration *= 2.0
        
        # 根据文件复杂度调整
        total_lines = sum(len(f.content.splitlines()) for f in self.source_files)
        if total_lines > 1000:
            duration *= 1.3
        
        return duration
    
    def add_dependency(self, task_id: str, dependency_type: str, description: str = ""):
        """添加任务依赖"""
        dependency = TaskDependency(task_id, dependency_type, description)
        self.dependencies.append(dependency)
    
    def has_dependency_on(self, task_id: str) -> bool:
        """检查是否依赖特定任务"""
        return any(dep.task_id == task_id for dep in self.dependencies)


@dataclass
class TaskCollection:
    """任务集合"""
    tasks: List[AuditTask] = field(default_factory=list)
    dependency_graph: Dict[str, List[str]] = field(default_factory=dict)
    
    def add_task(self, task: AuditTask):
        """添加任务"""
        self.tasks.append(task)
        self.dependency_graph[task.id] = [dep.task_id for dep in task.dependencies]
    
    def get_task_by_id(self, task_id: str) -> Optional[AuditTask]:
        """根据ID获取任务"""
        return next((task for task in self.tasks if task.id == task_id), None)
    
    def get_tasks_by_type(self, task_type: TaskType) -> List[AuditTask]:
        """根据类型获取任务"""
        return [task for task in self.tasks if task.task_type == task_type]
    
    def get_ready_tasks(self, completed_tasks: Set[str]) -> List[AuditTask]:
        """获取可以执行的任务（依赖已满足）"""
        ready_tasks = []
        
        for task in self.tasks:
            if task.id in completed_tasks:
                continue
            
            # 检查所有依赖是否已完成
            dependencies_met = all(
                dep.task_id in completed_tasks 
                for dep in task.dependencies
            )
            
            if dependencies_met:
                ready_tasks.append(task)
        
        # 按优先级排序
        ready_tasks.sort(key=lambda t: t.priority.value)
        return ready_tasks
    
    def get_execution_order(self) -> List[List[AuditTask]]:
        """获取任务执行顺序（分层）"""
        completed = set()
        execution_layers = []
        
        while len(completed) < len(self.tasks):
            current_layer = self.get_ready_tasks(completed)
            
            if not current_layer:
                # 检测循环依赖
                remaining_tasks = [t for t in self.tasks if t.id not in completed]
                logger.warning(f"检测到可能的循环依赖，剩余任务: {[t.id for t in remaining_tasks]}")
                # 强制添加剩余任务
                current_layer = remaining_tasks
            
            execution_layers.append(current_layer)
            completed.update(task.id for task in current_layer)
        
        return execution_layers
    
    def __len__(self) -> int:
        return len(self.tasks)


class TaskDecomposer:
    """任务分解器 - 将代码审计分解为具体任务"""
    
    def __init__(self):
        """初始化任务分解器"""
        self.task_strategies = {
            "file_based": self._decompose_by_files,
            "unit_based": self._decompose_by_units,
            "risk_based": self._decompose_by_risk,
            "hybrid": self._decompose_hybrid
        }
        
        # 任务分解配置
        self.config = {
            "max_files_per_task": 10,
            "max_units_per_task": 20,
            "enable_dependency_analysis": True,
            "enable_parallel_optimization": True,
            "default_strategy": "hybrid"
        }
        
        logger.info("任务分解器初始化完成")
    
    async def decompose_audit_tasks(self, source_files: List[SourceFile], 
                                  strategy: str = None) -> TaskCollection:
        """分解审计任务 - 主要接口方法"""
        if not source_files:
            logger.warning("没有源文件需要分解")
            return TaskCollection()
        
        strategy = strategy or self.config["default_strategy"]
        logger.info(f"开始任务分解，文件数: {len(source_files)}, 策略: {strategy}")
        
        try:
            # 提取代码单元
            code_units = await self._extract_code_units(source_files)
            logger.info(f"提取代码单元完成，单元数: {len(code_units)}")
            
            # 选择分解策略
            decompose_func = self.task_strategies.get(strategy, self._decompose_hybrid)
            
            # 执行任务分解
            task_collection = await decompose_func(source_files, code_units)
            
            # 建立任务依赖关系
            await self._establish_task_dependencies(task_collection)
            
            # 优化任务分配
            if self.config["enable_parallel_optimization"]:
                await self._optimize_task_parallelism(task_collection)
            
            logger.info(f"任务分解完成，生成任务数: {len(task_collection)}")
            self._log_task_summary(task_collection)
            
            return task_collection
            
        except Exception as e:
            logger.error(f"任务分解失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return TaskCollection()
    
    async def _extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """提取代码单元"""
        try:
            from auditluma.parsers.code_parser import CodeParser
            
            code_units = []
            parser = CodeParser()
            
            for source_file in source_files:
                try:
                    file_units = await parser.parse_file_async(source_file)
                    code_units.extend(file_units)
                except Exception as e:
                    logger.warning(f"解析文件失败: {source_file.path}, {e}")
            
            return code_units
            
        except ImportError:
            logger.warning("代码解析器不可用，使用简化的代码单元提取")
            return self._simple_extract_code_units(source_files)
    
    def _simple_extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """简化的代码单元提取"""
        code_units = []
        
        for source_file in source_files:
            # 创建一个简单的代码单元代表整个文件
            unit = CodeUnit(
                id=f"file_{hashlib.md5(str(source_file.path).encode()).hexdigest()[:8]}",
                name=source_file.path.name,
                type="file",
                content=source_file.content,
                source_file=source_file,
                start_line=1,
                end_line=len(source_file.content.splitlines())
            )
            code_units.append(unit)
        
        return code_units
    
    async def _decompose_by_files(self, source_files: List[SourceFile], 
                                code_units: List[CodeUnit]) -> TaskCollection:
        """按文件分解任务"""
        task_collection = TaskCollection()
        
        # 按文件分组
        file_groups = self._group_files_by_characteristics(source_files)
        
        for group_name, group_files in file_groups.items():
            group_units = [unit for unit in code_units if unit.source_file in group_files]
            
            # 为每个组创建不同类型的任务
            task_configs = [
                (TaskType.SYNTAX_CHECK, TaskPriority.HIGH),
                (TaskType.LOGIC_ANALYSIS, TaskPriority.MEDIUM),
                (TaskType.SECURITY_SCAN, TaskPriority.CRITICAL),
                (TaskType.DEPENDENCY_ANALYSIS, TaskPriority.MEDIUM)
            ]
            
            for task_type, priority in task_configs:
                task = AuditTask(
                    id=f"{task_type.value}_{group_name}_{uuid.uuid4().hex[:8]}",
                    task_type=task_type,
                    priority=priority,
                    source_files=group_files,
                    code_units=group_units,
                    metadata={
                        "group_name": group_name,
                        "file_count": len(group_files),
                        "unit_count": len(group_units),
                        "decomposition_strategy": "file_based"
                    }
                )
                task_collection.add_task(task)
        
        return task_collection
    
    async def _decompose_by_units(self, source_files: List[SourceFile], 
                                code_units: List[CodeUnit]) -> TaskCollection:
        """按代码单元分解任务"""
        task_collection = TaskCollection()
        
        # 按代码单元类型分组
        unit_groups = self._group_units_by_type(code_units)
        
        for unit_type, units in unit_groups.items():
            # 将大组拆分为小批次
            batch_size = self.config["max_units_per_task"]
            unit_batches = [units[i:i + batch_size] for i in range(0, len(units), batch_size)]
            
            for batch_idx, unit_batch in enumerate(unit_batches):
                batch_files = list(set(unit.source_file for unit in unit_batch))
                
                # 为每个批次创建任务
                task_configs = [
                    (TaskType.SYNTAX_CHECK, TaskPriority.HIGH),
                    (TaskType.LOGIC_ANALYSIS, TaskPriority.MEDIUM),
                    (TaskType.SECURITY_SCAN, TaskPriority.CRITICAL)
                ]
                
                for task_type, priority in task_configs:
                    task = AuditTask(
                        id=f"{task_type.value}_{unit_type}_batch{batch_idx}_{uuid.uuid4().hex[:8]}",
                        task_type=task_type,
                        priority=priority,
                        source_files=batch_files,
                        code_units=unit_batch,
                        metadata={
                            "unit_type": unit_type,
                            "batch_index": batch_idx,
                            "unit_count": len(unit_batch),
                            "decomposition_strategy": "unit_based"
                        }
                    )
                    task_collection.add_task(task)
        
        return task_collection
    
    async def _decompose_by_risk(self, source_files: List[SourceFile], 
                               code_units: List[CodeUnit]) -> TaskCollection:
        """按风险级别分解任务"""
        task_collection = TaskCollection()
        
        # 评估文件风险级别
        risk_groups = self._assess_file_risks(source_files, code_units)
        
        for risk_level, risk_files in risk_groups.items():
            risk_units = [unit for unit in code_units if unit.source_file in risk_files]
            
            # 根据风险级别确定任务优先级和类型
            if risk_level == "critical":
                task_configs = [
                    (TaskType.SECURITY_SCAN, TaskPriority.CRITICAL),
                    (TaskType.LOGIC_ANALYSIS, TaskPriority.HIGH),
                    (TaskType.DEPENDENCY_ANALYSIS, TaskPriority.HIGH),
                    (TaskType.SYNTAX_CHECK, TaskPriority.MEDIUM)
                ]
            elif risk_level == "high":
                task_configs = [
                    (TaskType.SECURITY_SCAN, TaskPriority.HIGH),
                    (TaskType.LOGIC_ANALYSIS, TaskPriority.MEDIUM),
                    (TaskType.DEPENDENCY_ANALYSIS, TaskPriority.MEDIUM),
                    (TaskType.SYNTAX_CHECK, TaskPriority.LOW)
                ]
            else:  # medium, low
                task_configs = [
                    (TaskType.SYNTAX_CHECK, TaskPriority.MEDIUM),
                    (TaskType.LOGIC_ANALYSIS, TaskPriority.LOW),
                    (TaskType.SECURITY_SCAN, TaskPriority.MEDIUM)
                ]
            
            for task_type, priority in task_configs:
                task = AuditTask(
                    id=f"{task_type.value}_{risk_level}_{uuid.uuid4().hex[:8]}",
                    task_type=task_type,
                    priority=priority,
                    source_files=risk_files,
                    code_units=risk_units,
                    metadata={
                        "risk_level": risk_level,
                        "file_count": len(risk_files),
                        "unit_count": len(risk_units),
                        "decomposition_strategy": "risk_based"
                    }
                )
                task_collection.add_task(task)
        
        return task_collection
    
    async def _decompose_hybrid(self, source_files: List[SourceFile], 
                              code_units: List[CodeUnit]) -> TaskCollection:
        """混合分解策略"""
        task_collection = TaskCollection()
        
        # 1. 首先按风险评估进行初步分组
        risk_groups = self._assess_file_risks(source_files, code_units)
        
        # 2. 对每个风险组进一步细分
        for risk_level, risk_files in risk_groups.items():
            risk_units = [unit for unit in code_units if unit.source_file in risk_files]
            
            # 按文件特征进一步分组
            file_groups = self._group_files_by_characteristics(risk_files)
            
            for group_name, group_files in file_groups.items():
                group_units = [unit for unit in risk_units if unit.source_file in group_files]
                
                if not group_units:
                    continue
                
                # 根据风险级别和组特征确定任务配置
                task_configs = self._get_task_configs_for_group(risk_level, group_name)
                
                # 如果组太大，进一步拆分
                if len(group_files) > self.config["max_files_per_task"]:
                    file_batches = self._split_files_into_batches(group_files, group_units)
                    
                    for batch_idx, (batch_files, batch_units) in enumerate(file_batches):
                        for task_type, priority in task_configs:
                            task = AuditTask(
                                id=f"{task_type.value}_{risk_level}_{group_name}_batch{batch_idx}_{uuid.uuid4().hex[:8]}",
                                task_type=task_type,
                                priority=priority,
                                source_files=batch_files,
                                code_units=batch_units,
                                metadata={
                                    "risk_level": risk_level,
                                    "group_name": group_name,
                                    "batch_index": batch_idx,
                                    "file_count": len(batch_files),
                                    "unit_count": len(batch_units),
                                    "decomposition_strategy": "hybrid"
                                }
                            )
                            task_collection.add_task(task)
                else:
                    # 直接创建任务
                    for task_type, priority in task_configs:
                        task = AuditTask(
                            id=f"{task_type.value}_{risk_level}_{group_name}_{uuid.uuid4().hex[:8]}",
                            task_type=task_type,
                            priority=priority,
                            source_files=group_files,
                            code_units=group_units,
                            metadata={
                                "risk_level": risk_level,
                                "group_name": group_name,
                                "file_count": len(group_files),
                                "unit_count": len(group_units),
                                "decomposition_strategy": "hybrid"
                            }
                        )
                        task_collection.add_task(task)
        
        return task_collection
    
    def _group_files_by_characteristics(self, source_files: List[SourceFile]) -> Dict[str, List[SourceFile]]:
        """按特征分组文件"""
        groups = {
            "high_risk": [],      # 高风险文件
            "medium_risk": [],    # 中风险文件
            "low_risk": [],       # 低风险文件
            "config": [],         # 配置文件
            "test": [],           # 测试文件
            "library": []         # 库文件
        }
        
        for source_file in source_files:
            file_path_lower = str(source_file.path).lower()
            content_lower = source_file.content.lower()
            
            # 分类逻辑
            if any(keyword in file_path_lower for keyword in ['test', 'spec', '__test__']):
                groups["test"].append(source_file)
            elif any(keyword in file_path_lower for keyword in ['config', 'setting', 'env']):
                groups["config"].append(source_file)
            elif any(keyword in file_path_lower for keyword in ['lib', 'vendor', 'node_modules']):
                groups["library"].append(source_file)
            elif any(keyword in content_lower for keyword in ['sql', 'database', 'network', 'http', 'api', 'auth']):
                groups["high_risk"].append(source_file)
            elif any(keyword in content_lower for keyword in ['function', 'class', 'method', 'import']):
                groups["medium_risk"].append(source_file)
            else:
                groups["low_risk"].append(source_file)
        
        # 移除空组
        return {k: v for k, v in groups.items() if v}
    
    def _group_units_by_type(self, code_units: List[CodeUnit]) -> Dict[str, List[CodeUnit]]:
        """按类型分组代码单元"""
        groups = {}
        
        for unit in code_units:
            unit_type = getattr(unit, 'type', 'unknown')
            if unit_type not in groups:
                groups[unit_type] = []
            groups[unit_type].append(unit)
        
        return groups
    
    def _assess_file_risks(self, source_files: List[SourceFile], 
                          code_units: List[CodeUnit]) -> Dict[str, List[SourceFile]]:
        """评估文件风险级别"""
        risk_groups = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for source_file in source_files:
            risk_score = self._calculate_file_risk_score(source_file, code_units)
            
            if risk_score >= 8:
                risk_groups["critical"].append(source_file)
            elif risk_score >= 6:
                risk_groups["high"].append(source_file)
            elif risk_score >= 3:
                risk_groups["medium"].append(source_file)
            else:
                risk_groups["low"].append(source_file)
        
        return {k: v for k, v in risk_groups.items() if v}
    
    def _calculate_file_risk_score(self, source_file: SourceFile, 
                                 code_units: List[CodeUnit]) -> int:
        """计算文件风险评分"""
        score = 0
        content_lower = source_file.content.lower()
        file_path_lower = str(source_file.path).lower()
        
        # 高风险关键词
        high_risk_keywords = [
            'sql', 'database', 'query', 'exec', 'eval',
            'system', 'shell', 'command', 'network', 'socket',
            'auth', 'password', 'token', 'session', 'cookie'
        ]
        
        for keyword in high_risk_keywords:
            if keyword in content_lower:
                score += 2
        
        # 中风险关键词
        medium_risk_keywords = [
            'input', 'output', 'file', 'read', 'write',
            'http', 'api', 'request', 'response'
        ]
        
        for keyword in medium_risk_keywords:
            if keyword in content_lower:
                score += 1
        
        # 文件类型风险
        if any(ext in file_path_lower for ext in ['.py', '.js', '.php', '.java']):
            score += 1
        
        # 文件大小风险
        lines = len(source_file.content.splitlines())
        if lines > 500:
            score += 2
        elif lines > 200:
            score += 1
        
        # 代码单元复杂度
        file_units = [unit for unit in code_units if unit.source_file == source_file]
        if len(file_units) > 20:
            score += 2
        elif len(file_units) > 10:
            score += 1
        
        return min(score, 10)  # 最大评分10
    
    def _get_task_configs_for_group(self, risk_level: str, 
                                  group_name: str) -> List[tuple]:
        """获取组的任务配置"""
        base_configs = {
            "critical": [
                (TaskType.SECURITY_SCAN, TaskPriority.CRITICAL),
                (TaskType.LOGIC_ANALYSIS, TaskPriority.HIGH),
                (TaskType.DEPENDENCY_ANALYSIS, TaskPriority.HIGH),
                (TaskType.SYNTAX_CHECK, TaskPriority.MEDIUM)
            ],
            "high": [
                (TaskType.SECURITY_SCAN, TaskPriority.HIGH),
                (TaskType.LOGIC_ANALYSIS, TaskPriority.MEDIUM),
                (TaskType.DEPENDENCY_ANALYSIS, TaskPriority.MEDIUM),
                (TaskType.SYNTAX_CHECK, TaskPriority.LOW)
            ],
            "medium": [
                (TaskType.SECURITY_SCAN, TaskPriority.MEDIUM),
                (TaskType.LOGIC_ANALYSIS, TaskPriority.LOW),
                (TaskType.SYNTAX_CHECK, TaskPriority.MEDIUM)
            ],
            "low": [
                (TaskType.SYNTAX_CHECK, TaskPriority.MEDIUM),
                (TaskType.LOGIC_ANALYSIS, TaskPriority.LOW)
            ]
        }
        
        configs = base_configs.get(risk_level, base_configs["medium"])
        
        # 根据组特征调整
        if group_name == "test":
            # 测试文件主要检查语法和逻辑
            configs = [
                (TaskType.SYNTAX_CHECK, TaskPriority.HIGH),
                (TaskType.LOGIC_ANALYSIS, TaskPriority.MEDIUM)
            ]
        elif group_name == "config":
            # 配置文件主要检查安全配置
            configs = [
                (TaskType.SECURITY_SCAN, TaskPriority.HIGH),
                (TaskType.SYNTAX_CHECK, TaskPriority.MEDIUM)
            ]
        
        return configs
    
    def _split_files_into_batches(self, files: List[SourceFile], 
                                units: List[CodeUnit]) -> List[tuple]:
        """将文件拆分为批次"""
        batch_size = self.config["max_files_per_task"]
        batches = []
        
        for i in range(0, len(files), batch_size):
            batch_files = files[i:i + batch_size]
            batch_units = [unit for unit in units if unit.source_file in batch_files]
            batches.append((batch_files, batch_units))
        
        return batches
    
    async def _establish_task_dependencies(self, task_collection: TaskCollection):
        """建立任务依赖关系"""
        if not self.config["enable_dependency_analysis"]:
            return
        
        tasks_by_type = {}
        for task in task_collection.tasks:
            task_type = task.task_type
            if task_type not in tasks_by_type:
                tasks_by_type[task_type] = []
            tasks_by_type[task_type].append(task)
        
        # 建立类型间依赖关系
        dependency_rules = [
            (TaskType.SYNTAX_CHECK, TaskType.LOGIC_ANALYSIS, "requires"),
            (TaskType.LOGIC_ANALYSIS, TaskType.SECURITY_SCAN, "enhances"),
            (TaskType.DEPENDENCY_ANALYSIS, TaskType.SECURITY_SCAN, "enhances")
        ]
        
        for prerequisite_type, dependent_type, dep_type in dependency_rules:
            prerequisite_tasks = tasks_by_type.get(prerequisite_type, [])
            dependent_tasks = tasks_by_type.get(dependent_type, [])
            
            for dependent_task in dependent_tasks:
                # 找到相关的前置任务
                related_prerequisites = self._find_related_tasks(
                    dependent_task, prerequisite_tasks
                )
                
                for prereq_task in related_prerequisites:
                    dependent_task.add_dependency(
                        prereq_task.id, 
                        dep_type,
                        f"{dependent_type.value} depends on {prerequisite_type.value}"
                    )
    
    def _find_related_tasks(self, target_task: AuditTask, 
                          candidate_tasks: List[AuditTask]) -> List[AuditTask]:
        """找到相关的任务"""
        related_tasks = []
        
        # 使用文件路径而不是SourceFile对象来创建集合
        target_files = set(getattr(f, 'path', str(f)) for f in target_task.source_files)
        
        for candidate in candidate_tasks:
            candidate_files = set(getattr(f, 'path', str(f)) for f in candidate.source_files)
            
            # 如果有文件重叠，认为是相关任务
            if target_files & candidate_files:
                related_tasks.append(candidate)
        
        return related_tasks
    
    async def _optimize_task_parallelism(self, task_collection: TaskCollection):
        """优化任务并行性"""
        # 分析任务执行时间和依赖关系，优化并行度
        execution_layers = task_collection.get_execution_order()
        
        for layer_idx, layer_tasks in enumerate(execution_layers):
            if len(layer_tasks) > 1:
                # 按预估执行时间排序，长任务优先
                layer_tasks.sort(key=lambda t: t.estimated_duration, reverse=True)
                
                # 更新任务优先级以优化并行执行
                for task_idx, task in enumerate(layer_tasks):
                    if task.estimated_duration > 5.0:  # 长任务
                        if task.priority.value > TaskPriority.HIGH.value:
                            task.priority = TaskPriority.HIGH
                    
                    # 添加并行优化元数据
                    task.metadata.update({
                        "execution_layer": layer_idx,
                        "layer_position": task_idx,
                        "parallel_optimized": True
                    })
    
    def _log_task_summary(self, task_collection: TaskCollection):
        """记录任务摘要"""
        type_counts = {}
        priority_counts = {}
        total_estimated_time = 0.0
        
        for task in task_collection.tasks:
            # 统计任务类型
            task_type = task.task_type.value
            type_counts[task_type] = type_counts.get(task_type, 0) + 1
            
            # 统计优先级
            priority = task.priority.name
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
            
            # 累计预估时间
            total_estimated_time += task.estimated_duration
        
        logger.info("任务分解摘要:")
        logger.info(f"  总任务数: {len(task_collection)}")
        logger.info(f"  预估总时间: {total_estimated_time:.2f}秒")
        logger.info(f"  任务类型分布: {type_counts}")
        logger.info(f"  优先级分布: {priority_counts}")
        
        # 记录执行顺序
        execution_layers = task_collection.get_execution_order()
        logger.info(f"  执行层数: {len(execution_layers)}")
        for layer_idx, layer_tasks in enumerate(execution_layers):
            logger.info(f"    第{layer_idx + 1}层: {len(layer_tasks)}个任务")