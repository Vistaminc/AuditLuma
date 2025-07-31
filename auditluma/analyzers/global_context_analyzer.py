"""
全局上下文分析器 - 构建项目级别的代码关系图和上下文信息
"""

import ast
import hashlib
import networkx as nx
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from loguru import logger

from auditluma.models.code import SourceFile, CodeUnit, FileType
from auditluma.parsers.code_parser import extract_code_units
from auditluma.rag.enhanced_self_rag import enhanced_self_rag as self_rag


class AnalysisLevel(Enum):
    """分析层次枚举"""
    SYNTAX = "syntax"           # 语法级别
    SEMANTIC = "semantic"       # 语义级别  
    DATAFLOW = "dataflow"       # 数据流级别
    CONTROL_FLOW = "control_flow"  # 控制流级别
    GLOBAL = "global"           # 全局级别


@dataclass
class CodeEntity:
    """代码实体"""
    name: str
    type: str  # function, class, variable, etc.
    file_path: str
    start_line: int
    end_line: int
    ast_node: Optional[ast.AST] = None
    dependencies: Set[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = set()


@dataclass
class DataFlowEdge:
    """数据流边"""
    source: CodeEntity
    target: CodeEntity
    flow_type: str  # assignment, parameter, return, etc.
    confidence: float = 1.0


@dataclass
class CrossFileFlow:
    """跨文件数据流"""
    source_file: str
    source_func: str
    target_file: str
    target_func: str
    flow_type: str  # "call", "import", "data"
    risk_level: str  # "high", "medium", "low"


class GlobalContextAnalyzer:
    """全局上下文分析器 - 构建项目级别的代码关系图"""
    
    def __init__(self):
        self.call_graph = nx.DiGraph()
        self.data_flow_graph = nx.DiGraph()
        self.file_dependency_graph = nx.DiGraph()
        self.entities: Dict[str, CodeEntity] = {}
        self.cross_file_flows: List[CrossFileFlow] = []
        self.import_graph = nx.DiGraph()
        self.file_functions: Dict[str, List[str]] = {}
        
    async def build_global_context(self, source_files: List[SourceFile]) -> Dict[str, Any]:
        """构建全局上下文
        
        Args:
            source_files: 源文件列表
            
        Returns:
            全局上下文信息字典
        """
        logger.info("🔍 开始构建全局上下文...")
        
        # Self-RAG增强：检索相关的代码分析知识
        self.use_self_rag = False
        try:
            if hasattr(self_rag, 'retrieve') and hasattr(self_rag, 'embedder') and hasattr(self_rag, 'vector_store'):
                self.use_self_rag = True
                logger.debug("🤖 全局上下文分析器启用Self-RAG增强")
        except Exception as e:
            logger.debug(f"Self-RAG初始化检查失败: {e}")
        
        # 1. 解析所有文件，构建实体图
        await self._parse_all_files(source_files)
        
        # 2. 构建调用图
        self._build_call_graph()
        
        # 3. 构建数据流图
        self._build_dataflow_graph()
        
        # 4. 分析跨文件依赖
        self._analyze_cross_file_dependencies()
        
        # 5. 分析跨文件数据流
        self._analyze_cross_file_flows()
        
        # 6. 计算统计信息
        stats = self._calculate_statistics()
        
        logger.info(f"✅ 全局上下文构建完成")
        logger.info(f"   - 代码实体: {len(self.entities)}")
        logger.info(f"   - 调用关系: {self.call_graph.number_of_edges()}")
        logger.info(f"   - 数据流: {self.data_flow_graph.number_of_edges()}")
        logger.info(f"   - 跨文件流: {len(self.cross_file_flows)}")
        
        return {
            "entities": self.entities,
            "call_graph": self.call_graph,
            "data_flow_graph": self.data_flow_graph,
            "file_dependencies": self.file_dependency_graph,
            "cross_file_flows": self.cross_file_flows,
            "import_graph": self.import_graph,
            "statistics": stats
        }
    
    async def _parse_all_files(self, source_files: List[SourceFile]):
        """解析所有代码文件，提取实体信息"""
        logger.info(f"解析 {len(source_files)} 个源文件...")
        
        for source_file in source_files:
            try:
                # 提取代码单元
                code_units = await extract_code_units(source_file)
                
                # 处理每个代码单元
                for unit in code_units:
                    entity = self._code_unit_to_entity(unit)
                    self.entities[entity.name] = entity
                    
                    # 记录文件中的函数
                    if entity.type == "function":
                        if entity.file_path not in self.file_functions:
                            self.file_functions[entity.file_path] = []
                        self.file_functions[entity.file_path].append(entity.name)
                
                # 分析文件级别的导入关系
                if source_file.file_type == FileType.PYTHON:
                    self._analyze_python_imports(source_file)
                
            except Exception as e:
                logger.error(f"解析文件 {source_file.path} 时出错: {e}")
    
    def _code_unit_to_entity(self, unit: CodeUnit) -> CodeEntity:
        """将CodeUnit转换为CodeEntity"""
        # 构建唯一的实体名称
        entity_name = f"{unit.source_file.path}::{unit.name}"
        
        # 尝试解析AST节点（如果是Python代码）
        ast_node = None
        if unit.source_file.file_type == FileType.PYTHON:
            try:
                ast_node = ast.parse(unit.content)
            except Exception:
                # 如果无法解析整个内容，尝试解析为表达式
                try:
                    ast_node = ast.parse(unit.content, mode='exec')
                except Exception:
                    pass
        
        return CodeEntity(
            name=entity_name,
            type=unit.type,
            file_path=str(unit.source_file.path),
            start_line=unit.start_line,
            end_line=unit.end_line,
            ast_node=ast_node
        )
    
    def _analyze_python_imports(self, source_file: SourceFile):
        """分析Python文件的导入关系"""
        try:
            tree = ast.parse(source_file.content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.import_graph.add_edge(
                            str(source_file.path), 
                            alias.name,
                            import_type="direct"
                        )
                        
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self.import_graph.add_edge(
                            str(source_file.path),
                            node.module,
                            import_type="from"
                        )
                        
        except Exception as e:
            logger.debug(f"分析导入关系时出错 {source_file.path}: {e}")
    
    def _build_call_graph(self):
        """构建函数调用图"""
        logger.debug("构建调用图...")
        
        for entity_name, entity in self.entities.items():
            if entity.type == "function":
                # 尝试从原始代码文件分析调用关系
                try:
                    with open(entity.file_path, 'r', encoding='utf-8') as f:
                        file_content = f.read()
                    
                    # 解析整个文件的AST
                    file_tree = ast.parse(file_content)
                    
                    # 找到当前函数的定义
                    for node in ast.walk(file_tree):
                        if isinstance(node, ast.FunctionDef) and node.name == entity.name.split("::")[-1]:
                            # 分析这个函数内的调用
                            for call_node in ast.walk(node):
                                if isinstance(call_node, ast.Call):
                                    called_function = self._resolve_function_call(call_node, entity.file_path)
                                    if called_function and called_function in self.entities:
                                        self.call_graph.add_edge(
                                            entity_name, 
                                            called_function,
                                            call_type="function_call",
                                            line_number=getattr(call_node, 'lineno', 0)
                                        )
                                        logger.debug(f"添加调用关系: {entity_name} -> {called_function}")
                            break
                            
                except Exception as e:
                    logger.debug(f"分析文件调用关系失败 {entity.file_path}: {e}")
                    # 回退到AST节点方法
                    if entity.ast_node:
                        for node in ast.walk(entity.ast_node):
                            if isinstance(node, ast.Call):
                                called_function = self._resolve_function_call(node, entity.file_path)
                                if called_function and called_function in self.entities:
                                    self.call_graph.add_edge(
                                        entity_name, 
                                        called_function,
                                        call_type="function_call",
                                        line_number=getattr(node, 'lineno', 0)
                                    )
    
    def _build_dataflow_graph(self):
        """构建数据流图"""
        logger.debug("构建数据流图...")
        
        for entity_name, entity in self.entities.items():
            if entity.type == "function" and entity.ast_node:
                # 分析数据流
                dataflow_edges = self._analyze_function_dataflow(entity)
                for edge in dataflow_edges:
                    self.data_flow_graph.add_edge(
                        edge.source.name, 
                        edge.target.name,
                        flow_type=edge.flow_type,
                        confidence=edge.confidence
                    )
    
    def _analyze_cross_file_dependencies(self):
        """分析跨文件依赖关系"""
        logger.debug("分析跨文件依赖...")
        
        # 基于导入图构建文件依赖关系
        for source_file, target_module in self.import_graph.edges():
            # 尝试将模块名映射到实际文件
            target_file = self._resolve_module_to_file(target_module)
            if target_file:
                self.file_dependency_graph.add_edge(source_file, target_file)
    
    def _analyze_cross_file_flows(self):
        """分析跨文件数据流"""
        logger.debug("分析跨文件数据流...")
        
        # 基于调用图和文件依赖构建跨文件流
        for source_entity, target_entity in self.call_graph.edges():
            source_file = self.entities[source_entity].file_path
            target_file = self.entities[target_entity].file_path
            
            if source_file != target_file:
                # 这是一个跨文件调用
                flow = CrossFileFlow(
                    source_file=source_file,
                    source_func=self.entities[source_entity].name.split("::")[-1],
                    target_file=target_file,
                    target_func=self.entities[target_entity].name.split("::")[-1],
                    flow_type="function_call",
                    risk_level=self._assess_flow_risk_level(source_entity, target_entity)
                )
                self.cross_file_flows.append(flow)
    
    def _resolve_function_call(self, call_node: ast.Call, current_file: str) -> Optional[str]:
        """解析函数调用，返回目标函数的实体名称"""
        if isinstance(call_node.func, ast.Name):
            # 本地函数调用
            func_name = call_node.func.id
            
            # 首先检查同文件内的函数
            local_name = f"{current_file}::{func_name}"
            if local_name in self.entities:
                return local_name
            
            # 检查是否是导入的函数 - 查找所有文件中的同名函数
            for entity_name in self.entities:
                if entity_name.endswith(f"::{func_name}") and entity_name != local_name:
                    # 检查是否有导入关系
                    imported_module = entity_name.split("::")[0]
                    module_basename = Path(imported_module).stem
                    
                    # 检查导入图中是否有这个模块的导入
                    for source, target in self.import_graph.edges():
                        if source == current_file and (target == module_basename or target == imported_module):
                            return entity_name
                            
        elif isinstance(call_node.func, ast.Attribute):
            # 方法调用或模块函数调用
            if isinstance(call_node.func.value, ast.Name):
                module_name = call_node.func.value.id
                func_name = call_node.func.attr
                
                # 查找匹配的函数
                for entity_name in self.entities:
                    if entity_name.endswith(f"::{func_name}"):
                        entity_file = entity_name.split("::")[0]
                        entity_module = Path(entity_file).stem
                        
                        # 检查模块名是否匹配
                        if entity_module == module_name:
                            return entity_name
                        
                        # 检查导入关系
                        for source, target in self.import_graph.edges():
                            if source == current_file and target == module_name:
                                # 进一步检查文件名匹配
                                if entity_module == module_name or entity_file.endswith(f"{module_name}.py"):
                                    return entity_name
                        
        return None
    
    def _analyze_function_dataflow(self, entity: CodeEntity) -> List[DataFlowEdge]:
        """分析函数内数据流"""
        edges = []
        # 简化版本 - 实际需要更精细的数据流分析
        # 这里可以扩展实现更复杂的数据流追踪
        return edges
    
    def _resolve_module_to_file(self, module_name: str) -> Optional[str]:
        """将模块名解析为文件路径"""
        # 简化实现 - 可以扩展支持更复杂的模块解析
        for file_path in self.file_functions.keys():
            if module_name in file_path or file_path.endswith(f"{module_name}.py"):
                return file_path
        return None
    
    def _assess_flow_risk_level(self, source_entity: str, target_entity: str) -> str:
        """评估流的风险级别"""
        source = self.entities[source_entity]
        target = self.entities[target_entity]
        
        # 基于简单规则评估风险
        risk_keywords = ['auth', 'login', 'password', 'token', 'admin', 'delete', 'execute', 'sql']
        
        source_content = source.name.lower()
        target_content = target.name.lower()
        
        if any(keyword in target_content for keyword in risk_keywords):
            return "high"
        elif any(keyword in source_content for keyword in risk_keywords):
            return "medium"
        else:
            return "low"
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """计算统计信息"""
        return {
            "total_entities": len(self.entities),
            "total_files": len(set(entity.file_path for entity in self.entities.values())),
            "entity_types": {
                entity_type: len([e for e in self.entities.values() if e.type == entity_type])
                for entity_type in set(entity.type for entity in self.entities.values())
            },
            "call_relationships": self.call_graph.number_of_edges(),
            "data_flow_relationships": self.data_flow_graph.number_of_edges(),
            "file_dependencies": self.file_dependency_graph.number_of_edges(),
            "cross_file_flows": len(self.cross_file_flows),
            "import_relationships": self.import_graph.number_of_edges()
        }
    
    def get_entity_context(self, entity_name: str) -> Dict[str, Any]:
        """获取特定实体的上下文信息"""
        if entity_name not in self.entities:
            return {}
        
        entity = self.entities[entity_name]
        
        # 获取依赖和被依赖关系
        dependencies = list(self.call_graph.successors(entity_name))
        dependents = list(self.call_graph.predecessors(entity_name))
        
        # 获取相关的跨文件流
        related_flows = [
            flow for flow in self.cross_file_flows
            if entity.file_path in [flow.source_file, flow.target_file]
        ]
        
        return {
            "entity": entity,
            "dependencies": dependencies,
            "dependents": dependents,
            "related_flows": related_flows,
            "file_imports": list(self.import_graph.successors(entity.file_path)),
            "file_imported_by": list(self.import_graph.predecessors(entity.file_path))
        }
    
    def find_data_flow_paths(self, source_pattern: str, target_pattern: str) -> List[List[str]]:
        """查找从源到目标的数据流路径"""
        paths = []
        
        # 查找匹配模式的实体
        source_entities = [
            name for name, entity in self.entities.items()
            if source_pattern.lower() in entity.name.lower()
        ]
        
        target_entities = [
            name for name, entity in self.entities.items()
            if target_pattern.lower() in entity.name.lower()
        ]
        
        # 查找路径
        for source in source_entities:
            for target in target_entities:
                try:
                    if nx.has_path(self.call_graph, source, target):
                        path = nx.shortest_path(self.call_graph, source, target)
                        paths.append(path)
                except nx.NetworkXNoPath:
                    continue
        
        return paths 