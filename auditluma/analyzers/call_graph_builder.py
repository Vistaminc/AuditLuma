"""
调用图构建器 - 构建代码的函数调用关系图
支持多语言的函数调用关系解析和跨文件调用关系构建
"""

import ast
import re
import networkx as nx
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict

from loguru import logger

from auditluma.models.code import SourceFile, CodeUnit


@dataclass
class CallRelation:
    """调用关系"""
    caller: str
    callee: str
    call_type: str  # "direct", "indirect", "dynamic", "recursive"
    confidence: float
    line_number: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FunctionSignature:
    """函数签名"""
    name: str
    parameters: List[str]
    return_type: Optional[str]
    visibility: str  # "public", "private", "protected"
    is_static: bool = False
    is_async: bool = False


@dataclass
class CallGraphNode:
    """调用图节点"""
    function_name: str
    signature: FunctionSignature
    code_unit: CodeUnit
    incoming_calls: Set[str] = field(default_factory=set)
    outgoing_calls: Set[str] = field(default_factory=set)
    complexity_score: float = 0.0


class LanguageParser:
    """语言解析器基类"""
    
    def __init__(self, language: str):
        self.language = language
        self.function_patterns = self._init_function_patterns()
        self.call_patterns = self._init_call_patterns()
    
    def _init_function_patterns(self) -> List[str]:
        """初始化函数定义模式"""
        return []
    
    def _init_call_patterns(self) -> List[str]:
        """初始化函数调用模式"""
        return []
    
    def extract_functions(self, source_file: SourceFile) -> List[CallGraphNode]:
        """提取函数定义"""
        raise NotImplementedError
    
    def extract_calls(self, source_file: SourceFile, functions: Dict[str, CallGraphNode]) -> List[CallRelation]:
        """提取函数调用"""
        raise NotImplementedError


class PythonParser(LanguageParser):
    """Python语言解析器"""
    
    def __init__(self):
        super().__init__("python")
    
    def _init_function_patterns(self) -> List[str]:
        return [
            r'def\s+(\w+)\s*\([^)]*\):',
            r'async\s+def\s+(\w+)\s*\([^)]*\):',
            r'class\s+(\w+).*:',
        ]
    
    def _init_call_patterns(self) -> List[str]:
        return [
            r'(\w+)\s*\(',
            r'(\w+)\.(\w+)\s*\(',
            r'self\.(\w+)\s*\(',
            r'super\(\)\.(\w+)\s*\(',
        ]
    
    def extract_functions(self, source_file: SourceFile) -> List[CallGraphNode]:
        """提取Python函数定义"""
        nodes = []
        
        try:
            tree = ast.parse(source_file.content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_node = self._create_function_node(node, source_file)
                    if func_node:
                        nodes.append(func_node)
                elif isinstance(node, ast.ClassDef):
                    # 处理类中的方法
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            method_node = self._create_method_node(item, node.name, source_file)
                            if method_node:
                                nodes.append(method_node)
        
        except SyntaxError as e:
            logger.warning(f"Python语法错误: {source_file.path}, {e}")
        except Exception as e:
            logger.warning(f"解析Python文件失败: {source_file.path}, {e}")
        
        return nodes
    
    def _create_function_node(self, node: ast.FunctionDef, source_file: SourceFile) -> Optional[CallGraphNode]:
        """创建函数节点"""
        try:
            # 提取参数
            parameters = [arg.arg for arg in node.args.args]
            
            # 创建函数签名
            signature = FunctionSignature(
                name=node.name,
                parameters=parameters,
                return_type=self._extract_return_type(node),
                visibility="public",  # Python默认为public
                is_static=False,
                is_async=isinstance(node, ast.AsyncFunctionDef)
            )
            
            # 创建代码单元
            code_unit = CodeUnit(
                id=f"{source_file.path}::{node.name}",
                name=node.name,
                type="function",
                content=ast.get_source_segment(source_file.content, node) or "",
                start_line=node.lineno,
                end_line=getattr(node, 'end_lineno', node.lineno),
                source_file=source_file
            )
            
            return CallGraphNode(
                function_name=f"{source_file.path}::{node.name}",
                signature=signature,
                code_unit=code_unit,
                complexity_score=self._calculate_complexity(node)
            )
            
        except Exception as e:
            logger.warning(f"创建函数节点失败: {node.name}, {e}")
            return None
    
    def _create_method_node(self, node: ast.FunctionDef, class_name: str, source_file: SourceFile) -> Optional[CallGraphNode]:
        """创建方法节点"""
        try:
            # 提取参数（排除self）
            parameters = [arg.arg for arg in node.args.args[1:]]  # 排除self
            
            # 判断是否为静态方法
            is_static = any(
                isinstance(decorator, ast.Name) and decorator.id == 'staticmethod'
                for decorator in node.decorator_list
            )
            
            # 创建方法签名
            signature = FunctionSignature(
                name=node.name,
                parameters=parameters,
                return_type=self._extract_return_type(node),
                visibility=self._get_method_visibility(node.name),
                is_static=is_static,
                is_async=isinstance(node, ast.AsyncFunctionDef)
            )
            
            # 创建代码单元
            method_name = f"{class_name}.{node.name}"
            code_unit = CodeUnit(
                id=f"{source_file.path}::{method_name}",
                name=method_name,
                type="method",
                content=ast.get_source_segment(source_file.content, node) or "",
                start_line=node.lineno,
                end_line=getattr(node, 'end_lineno', node.lineno),
                source_file=source_file
            )
            
            return CallGraphNode(
                function_name=f"{source_file.path}::{method_name}",
                signature=signature,
                code_unit=code_unit,
                complexity_score=self._calculate_complexity(node)
            )
            
        except Exception as e:
            logger.warning(f"创建方法节点失败: {class_name}.{node.name}, {e}")
            return None
    
    def _extract_return_type(self, node: ast.FunctionDef) -> Optional[str]:
        """提取返回类型"""
        if node.returns:
            if isinstance(node.returns, ast.Name):
                return node.returns.id
            elif isinstance(node.returns, ast.Constant):
                return str(node.returns.value)
        return None
    
    def _get_method_visibility(self, method_name: str) -> str:
        """获取方法可见性"""
        if method_name.startswith('__') and method_name.endswith('__'):
            return "special"
        elif method_name.startswith('__'):
            return "private"
        elif method_name.startswith('_'):
            return "protected"
        else:
            return "public"
    
    def _calculate_complexity(self, node: ast.FunctionDef) -> float:
        """计算函数复杂度"""
        complexity = 1  # 基础复杂度
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, (ast.Try, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.Lambda):
                complexity += 1
        
        return float(complexity)
    
    def extract_calls(self, source_file: SourceFile, functions: Dict[str, CallGraphNode]) -> List[CallRelation]:
        """提取Python函数调用"""
        calls = []
        
        try:
            tree = ast.parse(source_file.content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_relation = self._analyze_call(node, source_file, functions)
                    if call_relation:
                        calls.append(call_relation)
        
        except Exception as e:
            logger.warning(f"提取函数调用失败: {source_file.path}, {e}")
        
        return calls
    
    def _analyze_call(self, node: ast.Call, source_file: SourceFile, functions: Dict[str, CallGraphNode]) -> Optional[CallRelation]:
        """分析函数调用"""
        try:
            # 获取被调用的函数名
            callee = self._get_callee_name(node.func)
            if not callee:
                return None
            
            # 查找调用者
            caller = self._find_caller_function(node.lineno, functions, source_file)
            if not caller:
                return None
            
            # 确定调用类型
            call_type = self._determine_call_type(node.func)
            
            # 计算置信度
            confidence = self._calculate_call_confidence(node.func, callee)
            
            return CallRelation(
                caller=caller,
                callee=self._resolve_callee_name(callee, source_file, functions),
                call_type=call_type,
                confidence=confidence,
                line_number=node.lineno,
                metadata={
                    "args_count": len(node.args),
                    "has_kwargs": len(node.keywords) > 0
                }
            )
            
        except Exception as e:
            logger.debug(f"分析函数调用失败: {e}")
            return None
    
    def _get_callee_name(self, func_node: ast.expr) -> Optional[str]:
        """获取被调用函数名"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
            else:
                return func_node.attr
        return None
    
    def _find_caller_function(self, line_number: int, functions: Dict[str, CallGraphNode], source_file: SourceFile) -> Optional[str]:
        """查找调用者函数"""
        for func_name, func_node in functions.items():
            if (func_node.code_unit.source_file == source_file and
                func_node.code_unit.start_line <= line_number <= func_node.code_unit.end_line):
                return func_name
        return None
    
    def _determine_call_type(self, func_node: ast.expr) -> str:
        """确定调用类型"""
        if isinstance(func_node, ast.Name):
            return "direct"
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name) and func_node.value.id == "self":
                return "method"
            else:
                return "indirect"
        else:
            return "dynamic"
    
    def _calculate_call_confidence(self, func_node: ast.expr, callee: str) -> float:
        """计算调用置信度"""
        if isinstance(func_node, ast.Name):
            return 0.9  # 直接调用，高置信度
        elif isinstance(func_node, ast.Attribute):
            return 0.8  # 属性调用，中高置信度
        else:
            return 0.6  # 动态调用，中等置信度
    
    def _resolve_callee_name(self, callee: str, source_file: SourceFile, functions: Dict[str, CallGraphNode]) -> str:
        """解析被调用函数的完整名称"""
        # 如果已经是完整名称
        if "::" in callee:
            return callee
        
        # 在同一文件中查找
        same_file_name = f"{source_file.path}::{callee}"
        if same_file_name in functions:
            return same_file_name
        
        # 在所有文件中查找
        for func_name in functions:
            if func_name.endswith(f"::{callee}"):
                return func_name
        
        # 返回原名（可能是外部函数）
        return callee


class JavaScriptParser(LanguageParser):
    """JavaScript/TypeScript语言解析器"""
    
    def __init__(self):
        super().__init__("javascript")
    
    def _init_function_patterns(self) -> List[str]:
        return [
            r'function\s+(\w+)\s*\(',
            r'(\w+)\s*:\s*function\s*\(',
            r'(\w+)\s*=\s*function\s*\(',
            r'(\w+)\s*=\s*\([^)]*\)\s*=>\s*{',
            r'async\s+function\s+(\w+)\s*\(',
        ]
    
    def _init_call_patterns(self) -> List[str]:
        return [
            r'(\w+)\s*\(',
            r'(\w+)\.(\w+)\s*\(',
            r'this\.(\w+)\s*\(',
            r'await\s+(\w+)\s*\(',
        ]
    
    def extract_functions(self, source_file: SourceFile) -> List[CallGraphNode]:
        """提取JavaScript函数定义"""
        nodes = []
        content = source_file.content
        
        for pattern in self.function_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                func_name = match.group(1)
                if func_name:
                    node = self._create_js_function_node(func_name, match, source_file)
                    if node:
                        nodes.append(node)
        
        return nodes
    
    def _create_js_function_node(self, func_name: str, match: re.Match, source_file: SourceFile) -> Optional[CallGraphNode]:
        """创建JavaScript函数节点"""
        try:
            # 计算行号
            start_pos = match.start()
            lines_before = source_file.content[:start_pos].count('\n')
            start_line = lines_before + 1
            
            # 提取函数体
            function_body = self._extract_js_function_body(source_file.content, start_pos)
            
            # 创建函数签名
            signature = FunctionSignature(
                name=func_name,
                parameters=self._extract_js_parameters(match.group(0)),
                return_type=None,  # JavaScript动态类型
                visibility="public",
                is_static=False,
                is_async="async" in match.group(0)
            )
            
            # 创建代码单元
            code_unit = CodeUnit(
                id=f"{source_file.path}::{func_name}",
                name=func_name,
                type="function",
                content=function_body,
                start_line=start_line,
                end_line=start_line + function_body.count('\n'),
                source_file=source_file
            )
            
            return CallGraphNode(
                function_name=f"{source_file.path}::{func_name}",
                signature=signature,
                code_unit=code_unit,
                complexity_score=self._calculate_js_complexity(function_body)
            )
            
        except Exception as e:
            logger.warning(f"创建JavaScript函数节点失败: {func_name}, {e}")
            return None
    
    def _extract_js_function_body(self, content: str, start_pos: int, max_lines: int = 100) -> str:
        """提取JavaScript函数体"""
        lines = content[start_pos:].split('\n')
        
        brace_count = 0
        function_lines = []
        
        for i, line in enumerate(lines):
            if i >= max_lines:
                break
                
            function_lines.append(line)
            brace_count += line.count('{') - line.count('}')
            
            if brace_count == 0 and i > 0 and '{' in lines[0]:
                break
        
        return '\n'.join(function_lines)
    
    def _extract_js_parameters(self, func_declaration: str) -> List[str]:
        """提取JavaScript函数参数"""
        # 简单的参数提取
        param_match = re.search(r'\(([^)]*)\)', func_declaration)
        if param_match:
            params_str = param_match.group(1).strip()
            if params_str:
                return [p.strip() for p in params_str.split(',')]
        return []
    
    def _calculate_js_complexity(self, function_body: str) -> float:
        """计算JavaScript函数复杂度"""
        complexity = 1
        
        # 控制结构
        complexity += len(re.findall(r'\b(if|while|for|switch)\b', function_body))
        complexity += len(re.findall(r'\bcatch\b', function_body))
        complexity += len(re.findall(r'\?\s*.*\s*:', function_body))  # 三元操作符
        
        return float(complexity)
    
    def extract_calls(self, source_file: SourceFile, functions: Dict[str, CallGraphNode]) -> List[CallRelation]:
        """提取JavaScript函数调用"""
        calls = []
        content = source_file.content
        
        for pattern in self.call_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                call_relation = self._analyze_js_call(match, source_file, functions)
                if call_relation:
                    calls.append(call_relation)
        
        return calls
    
    def _analyze_js_call(self, match: re.Match, source_file: SourceFile, functions: Dict[str, CallGraphNode]) -> Optional[CallRelation]:
        """分析JavaScript函数调用"""
        try:
            # 获取被调用函数名
            if match.lastindex == 1:
                callee = match.group(1)
                call_type = "direct"
            elif match.lastindex == 2:
                callee = f"{match.group(1)}.{match.group(2)}"
                call_type = "method"
            else:
                return None
            
            # 计算行号
            start_pos = match.start()
            lines_before = source_file.content[:start_pos].count('\n')
            line_number = lines_before + 1
            
            # 查找调用者
            caller = self._find_js_caller_function(line_number, functions, source_file)
            if not caller:
                return None
            
            return CallRelation(
                caller=caller,
                callee=self._resolve_callee_name(callee, source_file, functions),
                call_type=call_type,
                confidence=0.8,
                line_number=line_number,
                metadata={}
            )
            
        except Exception as e:
            logger.debug(f"分析JavaScript函数调用失败: {e}")
            return None
    
    def _find_js_caller_function(self, line_number: int, functions: Dict[str, CallGraphNode], source_file: SourceFile) -> Optional[str]:
        """查找JavaScript调用者函数"""
        for func_name, func_node in functions.items():
            if (func_node.code_unit.source_file == source_file and
                func_node.code_unit.start_line <= line_number <= func_node.code_unit.end_line):
                return func_name
        return None
    
    def _resolve_callee_name(self, callee: str, source_file: SourceFile, functions: Dict[str, CallGraphNode]) -> str:
        """解析被调用函数的完整名称"""
        # 如果已经是完整名称
        if "::" in callee:
            return callee
        
        # 在同一文件中查找
        same_file_name = f"{source_file.path}::{callee}"
        if same_file_name in functions:
            return same_file_name
        
        # 在所有文件中查找
        for func_name in functions:
            if func_name.endswith(f"::{callee}"):
                return func_name
        
        return callee


class CallGraphBuilder:
    """调用图构建器 - 主要组件"""
    
    def __init__(self):
        """初始化调用图构建器"""
        self.parsers = {
            "python": PythonParser(),
            "javascript": JavaScriptParser(),
            "typescript": JavaScriptParser(),  # TypeScript使用JavaScript解析器
        }
        self.call_graph = nx.DiGraph()
        self.functions = {}  # function_name -> CallGraphNode
        
        logger.info("调用图构建器初始化完成")
    
    async def build_call_graph(self, source_files: List[SourceFile]) -> nx.DiGraph:
        """构建调用图"""
        logger.info(f"开始构建调用图，文件数: {len(source_files)}")
        
        # 清理之前的数据
        self.call_graph.clear()
        self.functions.clear()
        
        # 第一阶段：提取所有函数定义
        await self._extract_all_functions(source_files)
        
        # 第二阶段：分析函数调用关系
        await self._analyze_all_calls(source_files)
        
        # 第三阶段：构建图结构
        self._build_graph_structure()
        
        # 第四阶段：优化和验证
        self._optimize_graph()
        
        logger.info(f"调用图构建完成，节点数: {self.call_graph.number_of_nodes()}, 边数: {self.call_graph.number_of_edges()}")
        return self.call_graph
    
    async def _extract_all_functions(self, source_files: List[SourceFile]):
        """提取所有函数定义"""
        logger.debug("开始提取函数定义")
        
        for source_file in source_files:
            try:
                parser = self._get_parser(source_file.file_type)
                if parser:
                    nodes = parser.extract_functions(source_file)
                    for node in nodes:
                        self.functions[node.function_name] = node
                else:
                    logger.warning(f"不支持的文件类型: {source_file.file_type}")
                    
            except Exception as e:
                logger.warning(f"提取函数定义失败: {source_file.path}, {e}")
        
        logger.debug(f"函数定义提取完成，共 {len(self.functions)} 个函数")
    
    async def _analyze_all_calls(self, source_files: List[SourceFile]):
        """分析所有函数调用"""
        logger.debug("开始分析函数调用")
        
        all_calls = []
        
        for source_file in source_files:
            try:
                parser = self._get_parser(source_file.file_type)
                if parser:
                    calls = parser.extract_calls(source_file, self.functions)
                    all_calls.extend(calls)
                    
            except Exception as e:
                logger.warning(f"分析函数调用失败: {source_file.path}, {e}")
        
        # 处理调用关系
        for call in all_calls:
            self._add_call_relation(call)
        
        logger.debug(f"函数调用分析完成，共 {len(all_calls)} 个调用关系")
    
    def _get_parser(self, file_type: str) -> Optional[LanguageParser]:
        """获取语言解析器"""
        return self.parsers.get(file_type.lower())
    
    def _add_call_relation(self, call: CallRelation):
        """添加调用关系"""
        # 更新函数节点的调用关系
        if call.caller in self.functions:
            self.functions[call.caller].outgoing_calls.add(call.callee)
        
        if call.callee in self.functions:
            self.functions[call.callee].incoming_calls.add(call.caller)
        
        # 添加到图中
        self.call_graph.add_edge(call.caller, call.callee, relation=call)
    
    def _build_graph_structure(self):
        """构建图结构"""
        logger.debug("构建图结构")
        
        # 添加所有函数节点
        for func_name, func_node in self.functions.items():
            self.call_graph.add_node(func_name, 
                                   function_node=func_node,
                                   code_unit=func_node.code_unit,
                                   complexity=func_node.complexity_score)
    
    def _optimize_graph(self):
        """优化调用图"""
        logger.debug("优化调用图")
        
        # 移除自环（递归调用标记为特殊类型）
        self_loops = list(nx.selfloop_edges(self.call_graph))
        for caller, callee in self_loops:
            edge_data = self.call_graph.get_edge_data(caller, callee)
            if edge_data and 'relation' in edge_data:
                edge_data['relation'].call_type = "recursive"
        
        # 计算图的统计信息
        self._calculate_graph_metrics()
    
    def _calculate_graph_metrics(self):
        """计算图的度量指标"""
        # 计算每个节点的度中心性
        in_degree_centrality = nx.in_degree_centrality(self.call_graph)
        out_degree_centrality = nx.out_degree_centrality(self.call_graph)
        
        # 更新节点属性
        for node in self.call_graph.nodes():
            self.call_graph.nodes[node]['in_degree_centrality'] = in_degree_centrality.get(node, 0)
            self.call_graph.nodes[node]['out_degree_centrality'] = out_degree_centrality.get(node, 0)
    
    def get_function_dependencies(self, function_name: str, max_depth: int = 3) -> Dict[str, Any]:
        """获取函数依赖关系"""
        if function_name not in self.call_graph:
            return {}
        
        # 获取前驱（调用者）
        predecessors = self._get_predecessors_with_depth(function_name, max_depth)
        
        # 获取后继（被调用者）
        successors = self._get_successors_with_depth(function_name, max_depth)
        
        return {
            "function": function_name,
            "callers": predecessors,
            "callees": successors,
            "direct_callers": list(self.call_graph.predecessors(function_name)),
            "direct_callees": list(self.call_graph.successors(function_name))
        }
    
    def _get_predecessors_with_depth(self, node: str, max_depth: int) -> Dict[int, List[str]]:
        """获取指定深度的前驱节点"""
        predecessors = defaultdict(list)
        visited = set()
        queue = [(node, 0)]
        
        while queue:
            current, depth = queue.pop(0)
            if depth >= max_depth or current in visited:
                continue
                
            visited.add(current)
            
            for predecessor in self.call_graph.predecessors(current):
                if predecessor not in visited:
                    predecessors[depth + 1].append(predecessor)
                    queue.append((predecessor, depth + 1))
        
        return dict(predecessors)
    
    def _get_successors_with_depth(self, node: str, max_depth: int) -> Dict[int, List[str]]:
        """获取指定深度的后继节点"""
        successors = defaultdict(list)
        visited = set()
        queue = [(node, 0)]
        
        while queue:
            current, depth = queue.pop(0)
            if depth >= max_depth or current in visited:
                continue
                
            visited.add(current)
            
            for successor in self.call_graph.successors(current):
                if successor not in visited:
                    successors[depth + 1].append(successor)
                    queue.append((successor, depth + 1))
        
        return dict(successors)
    
    def find_call_paths(self, source: str, target: str, max_paths: int = 5) -> List[List[str]]:
        """查找调用路径"""
        if source not in self.call_graph or target not in self.call_graph:
            return []
        
        try:
            # 使用NetworkX查找所有简单路径
            paths = list(nx.all_simple_paths(self.call_graph, source, target, cutoff=5))
            return paths[:max_paths]
        except nx.NetworkXNoPath:
            return []
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """获取图统计信息"""
        if not self.call_graph.nodes():
            return {}
        
        return {
            "total_functions": self.call_graph.number_of_nodes(),
            "total_calls": self.call_graph.number_of_edges(),
            "average_in_degree": sum(dict(self.call_graph.in_degree()).values()) / self.call_graph.number_of_nodes(),
            "average_out_degree": sum(dict(self.call_graph.out_degree()).values()) / self.call_graph.number_of_nodes(),
            "is_connected": nx.is_weakly_connected(self.call_graph),
            "number_of_components": nx.number_weakly_connected_components(self.call_graph),
            "has_cycles": not nx.is_directed_acyclic_graph(self.call_graph)
        }
    
    def export_graph(self, format: str = "gexf") -> str:
        """导出调用图"""
        if format.lower() == "gexf":
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gexf', delete=False) as f:
                nx.write_gexf(self.call_graph, f.name)
                return f.name
        elif format.lower() == "dot":
            return nx.nx_agraph.to_agraph(self.call_graph).to_string()
        else:
            raise ValueError(f"不支持的导出格式: {format}")