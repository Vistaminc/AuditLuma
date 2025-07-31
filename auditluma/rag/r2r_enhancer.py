"""
R2R代码上下文增强层 - 层级RAG架构第三层
负责深度代码理解与关系分析
"""

import asyncio
import networkx as nx
import time
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import ast
import re
from pathlib import Path

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult


@dataclass
class CallRelation:
    """调用关系"""
    caller: str
    callee: str
    call_type: str  # "direct", "indirect", "dynamic"
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlow:
    """数据流信息"""
    source: str
    sink: str
    flow_path: List[str]
    data_type: str
    taint_level: str  # "high", "medium", "low"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImpactScope:
    """影响范围"""
    affected_functions: Set[str]
    affected_files: Set[str]
    propagation_depth: int
    risk_level: str  # "critical", "high", "medium", "low"
    propagation_paths: List[List[str]]


@dataclass
class EnhancedContext:
    """增强的代码上下文"""
    call_chain: List[CallRelation]
    data_flow: List[DataFlow]
    impact_scope: ImpactScope
    semantic_context: Dict[str, Any]
    context_completeness: float  # 0.0 - 1.0


class CallGraphBuilder:
    """调用图构建器"""
    
    def __init__(self):
        self.call_graph = nx.DiGraph()
        self.function_definitions = {}  # function_name -> CodeUnit
        self.call_patterns = self._init_call_patterns()
    
    def _init_call_patterns(self) -> Dict[str, List[str]]:
        """初始化调用模式"""
        return {
            "python": [
                r'(\w+)\s*\(',  # 函数调用
                r'(\w+)\.(\w+)\s*\(',  # 方法调用
                r'(\w+)\.\w+\.\w+\s*\(',  # 链式调用
            ],
            "javascript": [
                r'(\w+)\s*\(',
                r'(\w+)\.(\w+)\s*\(',
                r'await\s+(\w+)\s*\(',
            ],
            "java": [
                r'(\w+)\s*\(',
                r'(\w+)\.(\w+)\s*\(',
                r'this\.(\w+)\s*\(',
            ]
        }
    
    async def build_call_graph(self, source_files: List[SourceFile]) -> nx.DiGraph:
        """构建调用图"""
        logger.info(f"开始构建调用图，文件数: {len(source_files)}")
        
        # 1. 提取所有函数定义
        await self._extract_function_definitions(source_files)
        
        # 2. 分析函数调用关系
        await self._analyze_function_calls(source_files)
        
        # 3. 构建图结构
        self._build_graph_structure()
        
        logger.info(f"调用图构建完成，节点数: {self.call_graph.number_of_nodes()}, 边数: {self.call_graph.number_of_edges()}")
        return self.call_graph
    
    async def _extract_function_definitions(self, source_files: List[SourceFile]):
        """提取函数定义"""
        for source_file in source_files:
            try:
                # 根据文件类型选择解析方法
                if source_file.file_type == "python":
                    await self._extract_python_functions(source_file)
                elif source_file.file_type in ["javascript", "typescript"]:
                    await self._extract_js_functions(source_file)
                elif source_file.file_type == "java":
                    await self._extract_java_functions(source_file)
                else:
                    await self._extract_generic_functions(source_file)
                    
            except Exception as e:
                logger.warning(f"提取函数定义失败: {source_file.path}, {e}")
    
    async def _extract_python_functions(self, source_file: SourceFile):
        """提取Python函数定义"""
        try:
            tree = ast.parse(source_file.content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_name = f"{source_file.path}::{node.name}"
                    
                    # 创建代码单元
                    code_unit = CodeUnit(
                        id=func_name,
                        name=node.name,
                        type="function",
                        content=ast.get_source_segment(source_file.content, node) or "",
                        start_line=node.lineno,
                        end_line=getattr(node, 'end_lineno', node.lineno),
                        source_file=source_file
                    )
                    
                    self.function_definitions[func_name] = code_unit
                    
        except SyntaxError as e:
            logger.warning(f"Python语法错误: {source_file.path}, {e}")
        except Exception as e:
            logger.warning(f"解析Python文件失败: {source_file.path}, {e}")
    
    async def _extract_js_functions(self, source_file: SourceFile):
        """提取JavaScript/TypeScript函数定义"""
        content = source_file.content
        
        # 使用正则表达式提取函数定义
        patterns = [
            r'function\s+(\w+)\s*\(',  # function declaration
            r'(\w+)\s*:\s*function\s*\(',  # object method
            r'(\w+)\s*=\s*function\s*\(',  # function expression
            r'(\w+)\s*=\s*\([^)]*\)\s*=>\s*{',  # arrow function
            r'async\s+function\s+(\w+)\s*\(',  # async function
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                func_name = match.group(1)
                full_name = f"{source_file.path}::{func_name}"
                
                # 估算函数位置
                start_pos = match.start()
                lines_before = content[:start_pos].count('\n')
                start_line = lines_before + 1
                
                code_unit = CodeUnit(
                    id=full_name,
                    name=func_name,
                    type="function",
                    content=self._extract_function_body(content, match.start()),
                    start_line=start_line,
                    end_line=start_line + 10,  # 估算
                    source_file=source_file
                )
                
                self.function_definitions[full_name] = code_unit
    
    async def _extract_java_functions(self, source_file: SourceFile):
        """提取Java方法定义"""
        content = source_file.content
        
        # Java方法模式
        method_pattern = r'(public|private|protected)?\s*(static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*{'
        
        matches = re.finditer(method_pattern, content, re.MULTILINE)
        for match in matches:
            method_name = match.group(3)
            full_name = f"{source_file.path}::{method_name}"
            
            start_pos = match.start()
            lines_before = content[:start_pos].count('\n')
            start_line = lines_before + 1
            
            code_unit = CodeUnit(
                id=full_name,
                name=method_name,
                type="method",
                content=self._extract_function_body(content, match.start()),
                start_line=start_line,
                end_line=start_line + 15,  # 估算
                source_file=source_file
            )
            
            self.function_definitions[full_name] = code_unit
    
    async def _extract_generic_functions(self, source_file: SourceFile):
        """通用函数提取"""
        content = source_file.content
        
        # 通用函数模式
        patterns = [
            r'(\w+)\s*\([^)]*\)\s*{',  # 基本函数模式
            r'def\s+(\w+)\s*\(',  # Python def
            r'function\s+(\w+)\s*\(',  # JavaScript function
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                func_name = match.group(1)
                if func_name in ['if', 'for', 'while', 'switch']:  # 排除关键字
                    continue
                    
                full_name = f"{source_file.path}::{func_name}"
                
                start_pos = match.start()
                lines_before = content[:start_pos].count('\n')
                start_line = lines_before + 1
                
                code_unit = CodeUnit(
                    id=full_name,
                    name=func_name,
                    type="function",
                    content=self._extract_function_body(content, match.start()),
                    start_line=start_line,
                    end_line=start_line + 10,
                    source_file=source_file
                )
                
                self.function_definitions[full_name] = code_unit
    
    def _extract_function_body(self, content: str, start_pos: int, max_lines: int = 50) -> str:
        """提取函数体"""
        lines = content[start_pos:].split('\n')
        
        # 简单的大括号匹配
        brace_count = 0
        function_lines = []
        
        for i, line in enumerate(lines):
            if i >= max_lines:
                break
                
            function_lines.append(line)
            brace_count += line.count('{') - line.count('}')
            
            if brace_count == 0 and i > 0:
                break
        
        return '\n'.join(function_lines)
    
    async def _analyze_function_calls(self, source_files: List[SourceFile]):
        """分析函数调用关系"""
        for source_file in source_files:
            try:
                file_type = source_file.file_type
                if file_type in self.call_patterns:
                    patterns = self.call_patterns[file_type]
                else:
                    patterns = self.call_patterns.get("python", [])  # 默认使用Python模式
                
                await self._find_function_calls(source_file, patterns)
                
            except Exception as e:
                logger.warning(f"分析函数调用失败: {source_file.path}, {e}")
    
    async def _find_function_calls(self, source_file: SourceFile, patterns: List[str]):
        """查找函数调用"""
        content = source_file.content
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                try:
                    # 提取调用者和被调用者
                    if match.lastindex == 1:  # 简单函数调用
                        callee = match.group(1)
                        caller = self._find_containing_function(source_file, match.start())
                    elif match.lastindex == 2:  # 方法调用
                        obj = match.group(1)
                        method = match.group(2)
                        callee = f"{obj}.{method}"
                        caller = self._find_containing_function(source_file, match.start())
                    else:
                        continue
                    
                    if caller and callee:
                        self._add_call_relation(caller, callee, "direct", 0.9)
                        
                except Exception as e:
                    logger.debug(f"处理函数调用匹配失败: {e}")
    
    def _find_containing_function(self, source_file: SourceFile, position: int) -> Optional[str]:
        """查找包含指定位置的函数"""
        lines_before = source_file.content[:position].count('\n')
        line_number = lines_before + 1
        
        # 查找包含该行的函数
        for func_name, code_unit in self.function_definitions.items():
            if (code_unit.source_file == source_file and 
                code_unit.start_line <= line_number <= code_unit.end_line):
                return func_name
        
        return None
    
    def _add_call_relation(self, caller: str, callee: str, call_type: str, confidence: float):
        """添加调用关系"""
        # 解析完整的被调用者名称
        full_callee = self._resolve_function_name(callee, caller)
        
        if full_callee in self.function_definitions:
            relation = CallRelation(
                caller=caller,
                callee=full_callee,
                call_type=call_type,
                confidence=confidence
            )
            
            # 添加到图中
            self.call_graph.add_edge(caller, full_callee, relation=relation)
    
    def _resolve_function_name(self, callee: str, caller: str) -> str:
        """解析函数全名"""
        # 如果已经是全名，直接返回
        if "::" in callee:
            return callee
        
        # 尝试在同一文件中查找
        caller_file = caller.split("::")[0] if "::" in caller else ""
        potential_name = f"{caller_file}::{callee}"
        
        if potential_name in self.function_definitions:
            return potential_name
        
        # 在所有文件中查找
        for func_name in self.function_definitions:
            if func_name.endswith(f"::{callee}"):
                return func_name
        
        return callee  # 返回原名
    
    def _build_graph_structure(self):
        """构建图结构"""
        # 添加所有函数节点
        for func_name, code_unit in self.function_definitions.items():
            self.call_graph.add_node(func_name, code_unit=code_unit)


class DataFlowAnalyzer:
    """数据流分析器"""
    
    def __init__(self):
        self.taint_sources = self._init_taint_sources()
        self.taint_sinks = self._init_taint_sinks()
        self.sanitizers = self._init_sanitizers()
    
    def _init_taint_sources(self) -> Set[str]:
        """初始化污点源"""
        return {
            # 用户输入
            "input", "raw_input", "sys.argv", "request.form", "request.args",
            "request.json", "request.data", "request.files",
            # 网络输入
            "socket.recv", "urllib.request", "requests.get", "requests.post",
            # 文件输入
            "open", "file.read", "os.environ"
        }
    
    def _init_taint_sinks(self) -> Set[str]:
        """初始化污点汇聚点"""
        return {
            # SQL执行
            "execute", "query", "cursor.execute", "db.query",
            # 命令执行
            "os.system", "subprocess.call", "subprocess.run", "eval", "exec",
            # 文件操作
            "open", "file.write", "os.remove", "shutil.rmtree",
            # 网络输出
            "response.write", "print", "render_template"
        }
    
    def _init_sanitizers(self) -> Set[str]:
        """初始化净化函数"""
        return {
            "escape", "quote", "sanitize", "validate", "filter",
            "html.escape", "urllib.parse.quote", "re.escape"
        }
    
    async def analyze_data_flow(self, call_graph: nx.DiGraph, 
                              vulnerability: VulnerabilityResult) -> List[DataFlow]:
        """分析数据流"""
        logger.debug(f"开始数据流分析: {vulnerability.id}")
        
        data_flows = []
        
        # 查找漏洞相关的函数
        vuln_function = self._find_vulnerability_function(call_graph, vulnerability)
        if not vuln_function:
            return data_flows
        
        # 从污点源开始追踪
        for source in self.taint_sources:
            if source in vulnerability.snippet.lower():
                flows = await self._trace_taint_flow(call_graph, source, vuln_function)
                data_flows.extend(flows)
        
        return data_flows
    
    def _find_vulnerability_function(self, call_graph: nx.DiGraph, 
                                   vulnerability: VulnerabilityResult) -> Optional[str]:
        """查找漏洞所在的函数"""
        for node in call_graph.nodes():
            code_unit = call_graph.nodes[node].get('code_unit')
            if (code_unit and 
                str(code_unit.source_file.path) == vulnerability.file_path and
                code_unit.start_line <= vulnerability.start_line <= code_unit.end_line):
                return node
        return None
    
    async def _trace_taint_flow(self, call_graph: nx.DiGraph, 
                              source: str, target: str) -> List[DataFlow]:
        """追踪污点流"""
        flows = []
        
        try:
            # 使用BFS查找从源到目标的路径
            if call_graph.has_node(target):
                # 查找所有可能的路径
                paths = self._find_taint_paths(call_graph, source, target)
                
                for path in paths:
                    # 检查路径中是否有净化函数
                    taint_level = self._calculate_taint_level(path)
                    
                    flow = DataFlow(
                        source=source,
                        sink=target,
                        flow_path=path,
                        data_type="user_input",
                        taint_level=taint_level,
                        metadata={"path_length": len(path)}
                    )
                    flows.append(flow)
        
        except Exception as e:
            logger.warning(f"追踪污点流失败: {e}")
        
        return flows
    
    def _find_taint_paths(self, call_graph: nx.DiGraph, 
                         source: str, target: str, max_depth: int = 5) -> List[List[str]]:
        """查找污点传播路径"""
        paths = []
        
        # 使用DFS查找路径
        def dfs(current: str, path: List[str], depth: int):
            if depth > max_depth:
                return
            
            if current == target:
                paths.append(path + [current])
                return
            
            if current in call_graph:
                for successor in call_graph.successors(current):
                    if successor not in path:  # 避免循环
                        dfs(successor, path + [current], depth + 1)
        
        # 从包含源的函数开始搜索
        for node in call_graph.nodes():
            code_unit = call_graph.nodes[node].get('code_unit')
            if code_unit and source in code_unit.content.lower():
                dfs(node, [], 0)
        
        return paths
    
    def _calculate_taint_level(self, path: List[str]) -> str:
        """计算污点级别"""
        # 检查路径中是否有净化函数
        for node in path:
            if any(sanitizer in node.lower() for sanitizer in self.sanitizers):
                return "low"
        
        # 根据路径长度判断
        if len(path) <= 2:
            return "high"
        elif len(path) <= 4:
            return "medium"
        else:
            return "low"


class ImpactAnalyzer:
    """影响面分析器"""
    
    def __init__(self):
        self.risk_weights = {
            "critical_functions": 3.0,
            "public_apis": 2.5,
            "data_handlers": 2.0,
            "utility_functions": 1.0
        }
    
    async def analyze_impact_scope(self, call_graph: nx.DiGraph,
                                 vulnerability: VulnerabilityResult) -> ImpactScope:
        """分析影响范围"""
        logger.debug(f"开始影响面分析: {vulnerability.id}")
        
        # 查找漏洞函数
        vuln_function = self._find_vulnerability_function(call_graph, vulnerability)
        if not vuln_function:
            return ImpactScope(
                affected_functions=set(),
                affected_files=set(),
                propagation_depth=0,
                risk_level="low",
                propagation_paths=[]
            )
        
        # 分析影响范围
        affected_functions = self._find_affected_functions(call_graph, vuln_function)
        affected_files = self._extract_affected_files(call_graph, affected_functions)
        propagation_paths = self._find_propagation_paths(call_graph, vuln_function)
        propagation_depth = max(len(path) for path in propagation_paths) if propagation_paths else 0
        risk_level = self._calculate_risk_level(affected_functions, propagation_depth)
        
        return ImpactScope(
            affected_functions=affected_functions,
            affected_files=affected_files,
            propagation_depth=propagation_depth,
            risk_level=risk_level,
            propagation_paths=propagation_paths
        )
    
    def _find_vulnerability_function(self, call_graph: nx.DiGraph,
                                   vulnerability: VulnerabilityResult) -> Optional[str]:
        """查找漏洞函数"""
        for node in call_graph.nodes():
            code_unit = call_graph.nodes[node].get('code_unit')
            if (code_unit and 
                str(code_unit.source_file.path) == vulnerability.file_path and
                code_unit.start_line <= vulnerability.start_line <= code_unit.end_line):
                return node
        return None
    
    def _find_affected_functions(self, call_graph: nx.DiGraph, 
                               vuln_function: str, max_depth: int = 5) -> Set[str]:
        """查找受影响的函数"""
        affected = set()
        
        # 向前传播（调用者）
        predecessors = self._get_predecessors_bfs(call_graph, vuln_function, max_depth)
        affected.update(predecessors)
        
        # 向后传播（被调用者）
        successors = self._get_successors_bfs(call_graph, vuln_function, max_depth)
        affected.update(successors)
        
        affected.add(vuln_function)
        return affected
    
    def _get_predecessors_bfs(self, call_graph: nx.DiGraph, 
                            start: str, max_depth: int) -> Set[str]:
        """BFS获取前驱节点"""
        visited = set()
        queue = deque([(start, 0)])
        
        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth or node in visited:
                continue
                
            visited.add(node)
            
            for predecessor in call_graph.predecessors(node):
                if predecessor not in visited:
                    queue.append((predecessor, depth + 1))
        
        visited.discard(start)
        return visited
    
    def _get_successors_bfs(self, call_graph: nx.DiGraph, 
                          start: str, max_depth: int) -> Set[str]:
        """BFS获取后继节点"""
        visited = set()
        queue = deque([(start, 0)])
        
        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth or node in visited:
                continue
                
            visited.add(node)
            
            for successor in call_graph.successors(node):
                if successor not in visited:
                    queue.append((successor, depth + 1))
        
        visited.discard(start)
        return visited
    
    def _extract_affected_files(self, call_graph: nx.DiGraph, 
                              affected_functions: Set[str]) -> Set[str]:
        """提取受影响的文件"""
        affected_files = set()
        
        for func_name in affected_functions:
            if "::" in func_name:
                file_path = func_name.split("::")[0]
                affected_files.add(file_path)
        
        return affected_files
    
    def _find_propagation_paths(self, call_graph: nx.DiGraph, 
                              vuln_function: str, max_paths: int = 10) -> List[List[str]]:
        """查找传播路径"""
        paths = []
        
        # 查找从漏洞函数开始的路径
        def dfs(current: str, path: List[str], depth: int):
            if depth > 5 or len(paths) >= max_paths:
                return
            
            path = path + [current]
            
            # 如果没有后继节点，这是一条完整路径
            successors = list(call_graph.successors(current))
            if not successors:
                paths.append(path)
                return
            
            for successor in successors:
                if successor not in path:  # 避免循环
                    dfs(successor, path, depth + 1)
        
        dfs(vuln_function, [], 0)
        return paths
    
    def _calculate_risk_level(self, affected_functions: Set[str], 
                            propagation_depth: int) -> str:
        """计算风险级别"""
        # 基础风险分数
        base_score = len(affected_functions) * 0.1 + propagation_depth * 0.2
        
        # 根据函数类型调整权重
        weighted_score = base_score
        for func_name in affected_functions:
            if self._is_critical_function(func_name):
                weighted_score += self.risk_weights["critical_functions"]
            elif self._is_public_api(func_name):
                weighted_score += self.risk_weights["public_apis"]
            elif self._is_data_handler(func_name):
                weighted_score += self.risk_weights["data_handlers"]
        
        # 确定风险级别
        if weighted_score >= 8.0:
            return "critical"
        elif weighted_score >= 5.0:
            return "high"
        elif weighted_score >= 2.0:
            return "medium"
        else:
            return "low"
    
    def _is_critical_function(self, func_name: str) -> bool:
        """判断是否为关键函数"""
        critical_keywords = ["auth", "login", "password", "admin", "root", "exec", "eval"]
        return any(keyword in func_name.lower() for keyword in critical_keywords)
    
    def _is_public_api(self, func_name: str) -> bool:
        """判断是否为公共API"""
        api_keywords = ["api", "endpoint", "route", "handler", "controller"]
        return any(keyword in func_name.lower() for keyword in api_keywords)
    
    def _is_data_handler(self, func_name: str) -> bool:
        """判断是否为数据处理函数"""
        data_keywords = ["process", "parse", "validate", "sanitize", "transform"]
        return any(keyword in func_name.lower() for keyword in data_keywords)


class ContextExpander:
    """上下文扩展器"""
    
    def __init__(self):
        self.semantic_analyzers = {
            "variable_usage": self._analyze_variable_usage,
            "control_flow": self._analyze_control_flow,
            "error_handling": self._analyze_error_handling,
            "security_patterns": self._analyze_security_patterns
        }
    
    async def expand_semantic_context(self, vulnerability: VulnerabilityResult,
                                    global_context: Dict[str, Any]) -> Dict[str, Any]:
        """扩展语义上下文"""
        semantic_context = {}
        
        # 并行执行各种语义分析
        tasks = []
        for analyzer_name, analyzer_func in self.semantic_analyzers.items():
            task = asyncio.create_task(
                analyzer_func(vulnerability, global_context),
                name=analyzer_name
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 收集结果
        for i, (analyzer_name, result) in enumerate(zip(self.semantic_analyzers.keys(), results)):
            if isinstance(result, Exception):
                logger.warning(f"语义分析失败 {analyzer_name}: {result}")
                semantic_context[analyzer_name] = {}
            else:
                semantic_context[analyzer_name] = result
        
        return semantic_context
    
    async def _analyze_variable_usage(self, vulnerability: VulnerabilityResult,
                                    global_context: Dict[str, Any]) -> Dict[str, Any]:
        """分析变量使用"""
        # 提取代码片段中的变量
        variables = self._extract_variables(vulnerability.snippet)
        
        # 分析变量的定义和使用
        usage_analysis = {}
        for var in variables:
            usage_analysis[var] = {
                "defined": self._is_variable_defined(var, vulnerability.snippet),
                "used": self._count_variable_usage(var, vulnerability.snippet),
                "type": self._infer_variable_type(var, vulnerability.snippet)
            }
        
        return {"variables": usage_analysis}
    
    async def _analyze_control_flow(self, vulnerability: VulnerabilityResult,
                                  global_context: Dict[str, Any]) -> Dict[str, Any]:
        """分析控制流"""
        snippet = vulnerability.snippet
        
        control_structures = {
            "conditionals": len(re.findall(r'\b(if|elif|else)\b', snippet)),
            "loops": len(re.findall(r'\b(for|while)\b', snippet)),
            "try_catch": len(re.findall(r'\b(try|except|catch|finally)\b', snippet)),
            "returns": len(re.findall(r'\breturn\b', snippet))
        }
        
        return {"control_flow": control_structures}
    
    async def _analyze_error_handling(self, vulnerability: VulnerabilityResult,
                                    global_context: Dict[str, Any]) -> Dict[str, Any]:
        """分析错误处理"""
        snippet = vulnerability.snippet
        
        error_handling = {
            "has_try_catch": bool(re.search(r'\b(try|except|catch)\b', snippet)),
            "has_error_logging": bool(re.search(r'\b(log|print|console)\b.*error', snippet, re.IGNORECASE)),
            "has_validation": bool(re.search(r'\b(validate|check|verify)\b', snippet, re.IGNORECASE)),
            "error_propagation": bool(re.search(r'\b(raise|throw)\b', snippet))
        }
        
        return {"error_handling": error_handling}
    
    async def _analyze_security_patterns(self, vulnerability: VulnerabilityResult,
                                       global_context: Dict[str, Any]) -> Dict[str, Any]:
        """分析安全模式"""
        snippet = vulnerability.snippet.lower()
        
        security_patterns = {
            "input_validation": bool(re.search(r'\b(validate|sanitize|escape|filter)\b', snippet)),
            "authentication": bool(re.search(r'\b(auth|login|password|token)\b', snippet)),
            "authorization": bool(re.search(r'\b(permission|role|access|allow|deny)\b', snippet)),
            "encryption": bool(re.search(r'\b(encrypt|decrypt|hash|crypto)\b', snippet)),
            "sql_injection_protection": bool(re.search(r'\b(prepare|bind|param)\b', snippet)),
            "xss_protection": bool(re.search(r'\b(escape|encode|sanitize)\b.*html', snippet))
        }
        
        return {"security_patterns": security_patterns}
    
    def _extract_variables(self, code: str) -> List[str]:
        """提取代码中的变量"""
        # 使用正则表达式提取变量名
        variables = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', code)
        
        # 过滤关键字
        keywords = {'if', 'else', 'for', 'while', 'def', 'class', 'import', 'return', 'try', 'except'}
        variables = [var for var in variables if var not in keywords]
        
        return list(set(variables))  # 去重
    
    def _is_variable_defined(self, var: str, code: str) -> bool:
        """检查变量是否被定义"""
        patterns = [
            rf'\b{var}\s*=',  # 赋值
            rf'\bdef\s+{var}\s*\(',  # 函数定义
            rf'\bclass\s+{var}\b',  # 类定义
            rf'\bfor\s+{var}\b',  # for循环变量
        ]
        
        return any(re.search(pattern, code) for pattern in patterns)
    
    def _count_variable_usage(self, var: str, code: str) -> int:
        """计算变量使用次数"""
        return len(re.findall(rf'\b{var}\b', code))
    
    def _infer_variable_type(self, var: str, code: str) -> str:
        """推断变量类型"""
        # 简单的类型推断
        if re.search(rf'{var}\s*=\s*\d+', code):
            return "integer"
        elif re.search(rf'{var}\s*=\s*["\']', code):
            return "string"
        elif re.search(rf'{var}\s*=\s*\[', code):
            return "list"
        elif re.search(rf'{var}\s*=\s*\{{', code):
            return "dict"
        else:
            return "unknown"


class R2REnhancer:
    """R2R代码上下文增强器 - 层级RAG架构第三层核心组件"""
    
    def __init__(self):
        """初始化R2R增强器"""
        # 获取R2R层的模型配置
        self.r2r_models = Config.get_r2r_models()
        self.context_model = self.r2r_models.get("context_model", "gpt-3.5-turbo@openai")
        self.enhancement_model = self.r2r_models.get("enhancement_model", "gpt-3.5-turbo@openai")
        
        logger.info(f"R2R增强器使用模型 - 上下文: {self.context_model}, 增强: {self.enhancement_model}")
        
        self.call_graph_builder = CallGraphBuilder()
        self.dataflow_analyzer = DataFlowAnalyzer()
        self.impact_analyzer = ImpactAnalyzer()
        self.context_expander = ContextExpander()
        
        # 缓存
        self.global_context_cache = {}
        
        logger.info("R2R上下文增强器初始化完成")
    
    def get_context_model(self) -> str:
        """获取上下文分析模型"""
        return self.context_model
    
    def get_enhancement_model(self) -> str:
        """获取增强模型"""
        return self.enhancement_model
    
    async def _call_context_model(self, prompt: str, **kwargs) -> str:
        """调用上下文分析模型"""
        start_time = time.time()
        
        try:
            from auditluma.utils import init_llm_client
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            
            logger.info(f"🔗 R2R增强层 - 调用上下文分析模型: {self.context_model}")
            logger.debug(f"上下文分析提示长度: {len(prompt)} 字符")
            
            # 使用配置的上下文模型
            llm_client = init_llm_client(self.context_model)
            response = await llm_client.generate_async(prompt, **kwargs)
            
            execution_time = time.time() - start_time
            
            # 记录模型使用
            model_usage_logger.log_model_usage(
                layer="r2r",
                component="R2REnhancer",
                model_name=self.context_model,
                operation="context_analysis",
                input_size=len(prompt),
                output_size=len(response),
                execution_time=execution_time,
                success=True
            )
            
            logger.info(f"✅ R2R增强层 - 上下文模型 {self.context_model} 调用成功，响应长度: {len(response)} 字符")
            return response
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # 记录失败的模型使用
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            model_usage_logger.log_model_usage(
                layer="r2r",
                component="R2REnhancer",
                model_name=self.context_model,
                operation="context_analysis",
                input_size=len(prompt),
                output_size=0,
                execution_time=execution_time,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"❌ R2R增强层 - 调用上下文模型 {self.context_model} 失败: {e}")
            return ""
    
    async def _call_enhancement_model(self, prompt: str, **kwargs) -> str:
        """调用增强模型"""
        start_time = time.time()
        
        try:
            from auditluma.utils import init_llm_client
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            
            logger.info(f"🔗 R2R增强层 - 调用增强模型: {self.enhancement_model}")
            logger.debug(f"增强提示长度: {len(prompt)} 字符")
            
            # 使用配置的增强模型
            llm_client = init_llm_client(self.enhancement_model)
            response = await llm_client.generate_async(prompt, **kwargs)
            
            execution_time = time.time() - start_time
            
            # 记录模型使用
            model_usage_logger.log_model_usage(
                layer="r2r",
                component="R2REnhancer",
                model_name=self.enhancement_model,
                operation="enhancement",
                input_size=len(prompt),
                output_size=len(response),
                execution_time=execution_time,
                success=True
            )
            
            logger.info(f"✅ R2R增强层 - 增强模型 {self.enhancement_model} 调用成功，响应长度: {len(response)} 字符")
            return response
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # 记录失败的模型使用
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            model_usage_logger.log_model_usage(
                layer="r2r",
                component="R2REnhancer",
                model_name=self.enhancement_model,
                operation="enhancement",
                input_size=len(prompt),
                output_size=0,
                execution_time=execution_time,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"❌ R2R增强层 - 调用增强模型 {self.enhancement_model} 失败: {e}")
            return ""
    
    async def build_global_context(self, source_files: List[SourceFile]) -> Dict[str, Any]:
        """构建全局上下文"""
        logger.info(f"开始构建全局上下文，文件数: {len(source_files)}")
        
        # 检查缓存
        cache_key = self._generate_cache_key(source_files)
        if cache_key in self.global_context_cache:
            logger.info("使用缓存的全局上下文")
            return self.global_context_cache[cache_key]
        
        # 构建调用图
        call_graph = await self.call_graph_builder.build_call_graph(source_files)
        
        # 构建全局上下文
        global_context = {
            "call_graph": call_graph,
            "source_files": source_files,
            "function_definitions": self.call_graph_builder.function_definitions,
            "file_count": len(source_files),
            "function_count": len(self.call_graph_builder.function_definitions),
            "call_relationships": call_graph.number_of_edges()
        }
        
        # 缓存结果
        self.global_context_cache[cache_key] = global_context
        
        logger.info(f"全局上下文构建完成，函数数: {global_context['function_count']}, 调用关系: {global_context['call_relationships']}")
        return global_context
    
    async def enhance_context(self, vulnerability: VulnerabilityResult,
                            global_context: Dict[str, Any]) -> EnhancedContext:
        """增强代码上下文 - 主要接口方法"""
        logger.debug(f"开始增强上下文: {vulnerability.id}")
        
        call_graph = global_context.get("call_graph")
        if not call_graph:
            logger.warning("全局上下文中缺少调用图")
            return self._create_empty_context()
        
        try:
            # 并行执行各种分析
            tasks = [
                self._trace_call_dependencies(vulnerability, call_graph),
                self.dataflow_analyzer.analyze_data_flow(call_graph, vulnerability),
                self.impact_analyzer.analyze_impact_scope(call_graph, vulnerability),
                self.context_expander.expand_semantic_context(vulnerability, global_context)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 处理结果
            call_chain = results[0] if not isinstance(results[0], Exception) else []
            data_flow = results[1] if not isinstance(results[1], Exception) else []
            impact_scope = results[2] if not isinstance(results[2], Exception) else ImpactScope(
                affected_functions=set(), affected_files=set(), propagation_depth=0, 
                risk_level="low", propagation_paths=[]
            )
            semantic_context = results[3] if not isinstance(results[3], Exception) else {}
            
            # 计算上下文完整性
            context_completeness = self._calculate_context_completeness(
                call_chain, data_flow, impact_scope, semantic_context
            )
            
            enhanced_context = EnhancedContext(
                call_chain=call_chain,
                data_flow=data_flow,
                impact_scope=impact_scope,
                semantic_context=semantic_context,
                context_completeness=context_completeness
            )
            
            logger.debug(f"上下文增强完成: {vulnerability.id}, 完整性: {context_completeness:.2f}")
            return enhanced_context
            
        except Exception as e:
            logger.error(f"上下文增强失败: {vulnerability.id}, {e}")
            return self._create_empty_context()
    
    async def _trace_call_dependencies(self, vulnerability: VulnerabilityResult,
                                     call_graph: nx.DiGraph) -> List[CallRelation]:
        """追踪调用依赖关系"""
        call_relations = []
        
        # 查找漏洞所在的函数
        vuln_function = self._find_vulnerability_function(call_graph, vulnerability)
        if not vuln_function:
            return call_relations
        
        # 获取调用关系
        for predecessor in call_graph.predecessors(vuln_function):
            edge_data = call_graph.get_edge_data(predecessor, vuln_function)
            if edge_data and 'relation' in edge_data:
                call_relations.append(edge_data['relation'])
        
        for successor in call_graph.successors(vuln_function):
            edge_data = call_graph.get_edge_data(vuln_function, successor)
            if edge_data and 'relation' in edge_data:
                call_relations.append(edge_data['relation'])
        
        return call_relations
    
    def _find_vulnerability_function(self, call_graph: nx.DiGraph,
                                   vulnerability: VulnerabilityResult) -> Optional[str]:
        """查找漏洞所在的函数"""
        for node in call_graph.nodes():
            code_unit = call_graph.nodes[node].get('code_unit')
            if (code_unit and 
                str(code_unit.source_file.path) == vulnerability.file_path and
                code_unit.start_line <= vulnerability.start_line <= code_unit.end_line):
                return node
        return None
        
        # 添加数据流信息
        if enhanced_context.data_flow:
            flow_info = f"\n数据流分析: 检测到 {len(enhanced_context.data_flow)} 个数据流路径"
            high_risk_flows = [f for f in enhanced_context.data_flow if f.taint_level == "high"]
            if high_risk_flows:
                flow_info += f"，其中 {len(high_risk_flows)} 个为高风险路径"
            enhanced_description += flow_info
        
        # 添加影响面信息
        impact_info = f"\n影响面分析: 影响 {len(enhanced_context.impact_scope.affected_functions)} 个函数，" \
                     f"{len(enhanced_context.impact_scope.affected_files)} 个文件，" \
                     f"传播深度 {enhanced_context.impact_scope.propagation_depth}，" \
                     f"风险级别 {enhanced_context.impact_scope.risk_level}"
        enhanced_description += impact_info
        
        vulnerability.description = enhanced_description
        
        # 更新元数据
        if not hasattr(vulnerability, 'metadata'):
            vulnerability.metadata = {}
        
        vulnerability.metadata.update({
            "r2r_enhanced": True,
            "context_completeness": enhanced_context.context_completeness,
            "call_chain_length": len(enhanced_context.call_chain),
            "data_flow_count": len(enhanced_context.data_flow),
            "impact_scope": {
                "affected_functions": len(enhanced_context.impact_scope.affected_functions),
                "affected_files": len(enhanced_context.impact_scope.affected_files),
                "risk_level": enhanced_context.impact_scope.risk_level
            },
            "semantic_analysis": enhanced_context.semantic_context
        })
        
        return vulnerability
    
    async def _trace_call_dependencies(self, vulnerability: VulnerabilityResult,
                                     call_graph: nx.DiGraph) -> List[CallRelation]:
        """追踪调用依赖关系"""
        call_relations = []
        
        # 查找漏洞函数
        vuln_function = self._find_vulnerability_function(call_graph, vulnerability)
        if not vuln_function:
            return call_relations
        
        # 获取直接调用关系
        for predecessor in call_graph.predecessors(vuln_function):
            edge_data = call_graph.get_edge_data(predecessor, vuln_function)
            if edge_data and 'relation' in edge_data:
                call_relations.append(edge_data['relation'])
        
        for successor in call_graph.successors(vuln_function):
            edge_data = call_graph.get_edge_data(vuln_function, successor)
            if edge_data and 'relation' in edge_data:
                call_relations.append(edge_data['relation'])
        
        return call_relations
    
    def _find_vulnerability_function(self, call_graph: nx.DiGraph,
                                   vulnerability: VulnerabilityResult) -> Optional[str]:
        """查找漏洞所在的函数"""
        for node in call_graph.nodes():
            code_unit = call_graph.nodes[node].get('code_unit')
            if (code_unit and 
                str(code_unit.source_file.path) == vulnerability.file_path and
                code_unit.start_line <= vulnerability.start_line <= code_unit.end_line):
                return node
        return None
    
    def _calculate_context_completeness(self, call_chain: List[CallRelation],
                                      data_flow: List[DataFlow],
                                      impact_scope: ImpactScope,
                                      semantic_context: Dict[str, Any]) -> float:
        """计算上下文完整性"""
        completeness_factors = []
        
        # 调用链完整性
        if call_chain:
            call_completeness = min(1.0, len(call_chain) / 5.0)  # 假设5个调用关系为完整
            completeness_factors.append(call_completeness)
        
        # 数据流完整性
        if data_flow:
            flow_completeness = min(1.0, len(data_flow) / 3.0)  # 假设3个数据流为完整
            completeness_factors.append(flow_completeness)
        
        # 影响面完整性
        if impact_scope.affected_functions:
            impact_completeness = min(1.0, len(impact_scope.affected_functions) / 10.0)
            completeness_factors.append(impact_completeness)
        
        # 语义分析完整性
        semantic_completeness = len(semantic_context) / 4.0  # 4个分析器
        completeness_factors.append(semantic_completeness)
        
        # 计算平均完整性
        if completeness_factors:
            return sum(completeness_factors) / len(completeness_factors)
        else:
            return 0.0
    
    def _create_empty_context(self) -> EnhancedContext:
        """创建空的增强上下文"""
        return EnhancedContext(
            call_chain=[],
            data_flow=[],
            impact_scope=ImpactScope(
                affected_functions=set(),
                affected_files=set(),
                propagation_depth=0,
                risk_level="low",
                propagation_paths=[]
            ),
            semantic_context={},
            context_completeness=0.0
        )
    
    def _generate_cache_key(self, source_files: List[SourceFile]) -> str:
        """生成缓存键"""
        import hashlib
        
        # 使用文件路径和修改时间生成缓存键
        file_info = []
        for source_file in source_files:
            file_info.append(f"{source_file.path}:{len(source_file.content)}")
        
        cache_content = "|".join(sorted(file_info))
        return hashlib.md5(cache_content.encode()).hexdigest()
    
    def clear_cache(self):
        """清理缓存"""
        self.global_context_cache.clear()
        logger.info("R2R缓存已清理")