"""
增强数据流分析器 - 扩展现有DataFlowAnalyzer支持污点分析
实现变量追踪和数据传播路径分析，构建数据流图和可视化
"""

import ast
import re
import networkx as nx
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

from loguru import logger

from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult
from .dataflow_analyzer import DataFlowAnalyzer, TaintLevel, TaintSource, TaintSink, DataFlowPath


class TaintPropagationType(Enum):
    """污点传播类型"""
    DIRECT = "direct"           # 直接传播
    INDIRECT = "indirect"       # 间接传播
    CONDITIONAL = "conditional" # 条件传播
    LOOP = "loop"              # 循环传播
    RETURN = "return"          # 返回值传播
    PARAMETER = "parameter"    # 参数传播


@dataclass
class VariableState:
    """变量状态"""
    name: str
    taint_level: TaintLevel
    source_line: int
    data_type: Optional[str] = None
    value_range: Optional[Tuple[Any, Any]] = None
    dependencies: Set[str] = field(default_factory=set)
    propagation_history: List[str] = field(default_factory=list)


@dataclass
class TaintPropagationStep:
    """污点传播步骤"""
    from_var: str
    to_var: str
    propagation_type: TaintPropagationType
    line_number: int
    confidence: float
    sanitization_applied: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlowGraph:
    """数据流图"""
    nodes: Dict[str, VariableState]
    edges: List[TaintPropagationStep]
    entry_points: Set[str]
    exit_points: Set[str]
    critical_paths: List[List[str]]


@dataclass
class EnhancedDataFlowPath:
    """增强的数据流路径"""
    source: TaintSource
    sink: TaintSink
    path: List[str]
    variable_states: Dict[str, VariableState]
    propagation_steps: List[TaintPropagationStep]
    taint_level: TaintLevel
    sanitization_points: List[str]
    risk_score: float
    vulnerability_types: Set[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class VariableTracker:
    """变量追踪器"""
    
    def __init__(self):
        self.variable_states: Dict[str, VariableState] = {}
        self.variable_aliases: Dict[str, Set[str]] = defaultdict(set)
        self.scope_stack: List[str] = []
    
    def track_variable_assignment(self, var_name: str, value_expr: ast.expr, 
                                line_number: int, scope: str) -> VariableState:
        """追踪变量赋值"""
        full_name = f"{scope}::{var_name}"
        
        # 分析赋值表达式
        taint_level = self._analyze_expression_taint(value_expr)
        data_type = self._infer_data_type(value_expr)
        dependencies = self._extract_dependencies(value_expr)
        
        # 创建或更新变量状态
        var_state = VariableState(
            name=full_name,
            taint_level=taint_level,
            source_line=line_number,
            data_type=data_type,
            dependencies=dependencies,
            propagation_history=[full_name]
        )
        
        self.variable_states[full_name] = var_state
        
        # 处理别名
        if isinstance(value_expr, ast.Name):
            source_var = f"{scope}::{value_expr.id}"
            self.variable_aliases[full_name].add(source_var)
            self.variable_aliases[source_var].add(full_name)
        
        return var_state
    
    def track_variable_usage(self, var_name: str, scope: str, line_number: int) -> Optional[VariableState]:
        """追踪变量使用"""
        full_name = f"{scope}::{var_name}"
        
        # 查找变量状态
        if full_name in self.variable_states:
            return self.variable_states[full_name]
        
        # 查找别名
        for alias_set in self.variable_aliases.values():
            if full_name in alias_set:
                for alias in alias_set:
                    if alias in self.variable_states:
                        return self.variable_states[alias]
        
        return None
    
    def _analyze_expression_taint(self, expr: ast.expr) -> TaintLevel:
        """分析表达式的污点级别"""
        if isinstance(expr, ast.Name):
            # 变量引用
            var_state = self.variable_states.get(expr.id)
            return var_state.taint_level if var_state else TaintLevel.SAFE
        
        elif isinstance(expr, ast.Call):
            # 函数调用
            if isinstance(expr.func, ast.Name):
                func_name = expr.func.id
                if self._is_taint_source(func_name):
                    return TaintLevel.TAINTED
                elif self._is_sanitizer(func_name):
                    return TaintLevel.SANITIZED
        
        elif isinstance(expr, ast.BinOp):
            # 二元操作
            left_taint = self._analyze_expression_taint(expr.left)
            right_taint = self._analyze_expression_taint(expr.right)
            return max(left_taint, right_taint, key=lambda x: x.value)
        
        return TaintLevel.SAFE
    
    def _infer_data_type(self, expr: ast.expr) -> Optional[str]:
        """推断数据类型"""
        if isinstance(expr, ast.Constant):
            return type(expr.value).__name__
        elif isinstance(expr, ast.List):
            return "list"
        elif isinstance(expr, ast.Dict):
            return "dict"
        elif isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Name):
                # 基于函数名推断
                func_name = expr.func.id
                if func_name in ['str', 'int', 'float', 'bool']:
                    return func_name
        return None
    
    def _extract_dependencies(self, expr: ast.expr) -> Set[str]:
        """提取表达式依赖的变量"""
        dependencies = set()
        
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                dependencies.add(node.id)
        
        return dependencies
    
    def _is_taint_source(self, func_name: str) -> bool:
        """判断是否为污点源"""
        taint_sources = {
            'input', 'raw_input', 'sys.argv', 'request', 'form',
            'args', 'json', 'params', 'cookies', 'headers',
            'open', 'read', 'readline', 'readlines'
        }
        return func_name.lower() in taint_sources
    
    def _is_sanitizer(self, func_name: str) -> bool:
        """判断是否为净化函数"""
        sanitizers = {
            'escape', 'quote', 'sanitize', 'validate', 'filter',
            'html_escape', 'url_quote', 'sql_escape'
        }
        return func_name.lower() in sanitizers


class TaintPropagationAnalyzer:
    """污点传播分析器"""
    
    def __init__(self):
        self.propagation_rules = self._init_propagation_rules()
        self.sanitization_rules = self._init_sanitization_rules()
    
    def _init_propagation_rules(self) -> Dict[str, TaintPropagationType]:
        """初始化传播规则"""
        return {
            'assignment': TaintPropagationType.DIRECT,
            'parameter_passing': TaintPropagationType.PARAMETER,
            'return_value': TaintPropagationType.RETURN,
            'string_concatenation': TaintPropagationType.DIRECT,
            'list_append': TaintPropagationType.DIRECT,
            'dict_update': TaintPropagationType.DIRECT,
            'conditional_assignment': TaintPropagationType.CONDITIONAL,
            'loop_iteration': TaintPropagationType.LOOP,
        }
    
    def _init_sanitization_rules(self) -> Dict[str, float]:
        """初始化净化规则"""
        return {
            'html.escape': 0.9,
            'urllib.parse.quote': 0.8,
            'bleach.clean': 0.95,
            'validate_input': 0.7,
            'sanitize_sql': 0.9,
            'escape_shell': 0.8,
        }
    
    def analyze_propagation(self, source_file: SourceFile, 
                          variable_tracker: VariableTracker) -> List[TaintPropagationStep]:
        """分析污点传播"""
        propagation_steps = []
        
        try:
            tree = ast.parse(source_file.content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    steps = self._analyze_assignment(node, variable_tracker)
                    propagation_steps.extend(steps)
                elif isinstance(node, ast.Call):
                    step = self._analyze_function_call(node, variable_tracker)
                    if step:
                        propagation_steps.append(step)
        
        except Exception as e:
            logger.warning(f"污点传播分析失败: {source_file.path}, {e}")
        
        return propagation_steps
    
    def _analyze_assignment(self, node: ast.Assign, 
                          variable_tracker: VariableTracker) -> List[TaintPropagationStep]:
        """分析赋值语句的污点传播"""
        steps = []
        
        # 获取赋值目标
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_var = target.id
                
                # 分析赋值源
                source_vars = self._extract_source_variables(node.value)
                
                for source_var in source_vars:
                    step = TaintPropagationStep(
                        from_var=source_var,
                        to_var=target_var,
                        propagation_type=TaintPropagationType.DIRECT,
                        line_number=node.lineno,
                        confidence=0.9
                    )
                    steps.append(step)
        
        return steps
    
    def _analyze_function_call(self, node: ast.Call, 
                             variable_tracker: VariableTracker) -> Optional[TaintPropagationStep]:
        """分析函数调用的污点传播"""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            # 检查是否为净化函数
            if func_name in self.sanitization_rules:
                # 处理净化
                if node.args:
                    source_vars = self._extract_source_variables(node.args[0])
                    if source_vars:
                        return TaintPropagationStep(
                            from_var=source_vars[0],
                            to_var=f"sanitized_{func_name}",
                            propagation_type=TaintPropagationType.DIRECT,
                            line_number=node.lineno,
                            confidence=self.sanitization_rules[func_name],
                            sanitization_applied=True,
                            metadata={'sanitizer': func_name}
                        )
        
        return None
    
    def _extract_source_variables(self, expr: ast.expr) -> List[str]:
        """提取表达式中的源变量"""
        variables = []
        
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                variables.append(node.id)
        
        return variables


class DataFlowGraphBuilder:
    """数据流图构建器"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.variable_nodes = {}
        self.propagation_edges = []
    
    def build_graph(self, variable_states: Dict[str, VariableState],
                   propagation_steps: List[TaintPropagationStep]) -> DataFlowGraph:
        """构建数据流图"""
        # 添加变量节点
        for var_name, var_state in variable_states.items():
            self.graph.add_node(var_name, 
                              taint_level=var_state.taint_level,
                              data_type=var_state.data_type,
                              source_line=var_state.source_line)
            self.variable_nodes[var_name] = var_state
        
        # 添加传播边
        for step in propagation_steps:
            if step.from_var in self.graph and step.to_var in self.graph:
                self.graph.add_edge(step.from_var, step.to_var,
                                  propagation_type=step.propagation_type,
                                  confidence=step.confidence,
                                  line_number=step.line_number,
                                  sanitization=step.sanitization_applied)
                self.propagation_edges.append(step)
        
        # 识别入口和出口点
        entry_points = {node for node in self.graph.nodes() 
                       if self.graph.in_degree(node) == 0}
        exit_points = {node for node in self.graph.nodes() 
                      if self.graph.out_degree(node) == 0}
        
        # 查找关键路径
        critical_paths = self._find_critical_paths(entry_points, exit_points)
        
        return DataFlowGraph(
            nodes=self.variable_nodes,
            edges=self.propagation_edges,
            entry_points=entry_points,
            exit_points=exit_points,
            critical_paths=critical_paths
        )
    
    def _find_critical_paths(self, entry_points: Set[str], 
                           exit_points: Set[str]) -> List[List[str]]:
        """查找关键路径"""
        critical_paths = []
        
        for entry in entry_points:
            for exit in exit_points:
                try:
                    if nx.has_path(self.graph, entry, exit):
                        paths = list(nx.all_simple_paths(self.graph, entry, exit, cutoff=10))
                        critical_paths.extend(paths[:3])  # 限制路径数量
                except nx.NetworkXError:
                    continue
        
        return critical_paths
    
    def visualize_graph(self, output_path: str = "dataflow_graph.png"):
        """可视化数据流图"""
        try:
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches
            
            plt.figure(figsize=(12, 8))
            
            # 设置布局
            pos = nx.spring_layout(self.graph, k=1, iterations=50)
            
            # 根据污点级别设置节点颜色
            node_colors = []
            for node in self.graph.nodes():
                taint_level = self.graph.nodes[node].get('taint_level', TaintLevel.SAFE)
                if taint_level == TaintLevel.DANGEROUS:
                    node_colors.append('red')
                elif taint_level == TaintLevel.TAINTED:
                    node_colors.append('orange')
                elif taint_level == TaintLevel.SANITIZED:
                    node_colors.append('yellow')
                else:
                    node_colors.append('green')
            
            # 绘制节点
            nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors, 
                                 node_size=500, alpha=0.8)
            
            # 绘制边
            nx.draw_networkx_edges(self.graph, pos, alpha=0.6, arrows=True)
            
            # 绘制标签
            nx.draw_networkx_labels(self.graph, pos, font_size=8)
            
            # 添加图例
            legend_elements = [
                mpatches.Patch(color='red', label='Dangerous'),
                mpatches.Patch(color='orange', label='Tainted'),
                mpatches.Patch(color='yellow', label='Sanitized'),
                mpatches.Patch(color='green', label='Safe')
            ]
            plt.legend(handles=legend_elements, loc='upper right')
            
            plt.title("Data Flow Graph")
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"数据流图已保存到: {output_path}")
            
        except ImportError:
            logger.warning("matplotlib未安装，无法生成可视化图表")
        except Exception as e:
            logger.error(f"生成数据流图失败: {e}")


class EnhancedDataFlowAnalyzer(DataFlowAnalyzer):
    """增强数据流分析器 - 扩展基础DataFlowAnalyzer"""
    
    def __init__(self, global_context: Dict[str, Any]):
        super().__init__(global_context)
        
        # 增强组件
        self.variable_tracker = VariableTracker()
        self.propagation_analyzer = TaintPropagationAnalyzer()
        self.graph_builder = DataFlowGraphBuilder()
        
        # 增强配置
        self.enable_variable_tracking = True
        self.enable_graph_visualization = True
        self.max_path_length = 15
        self.confidence_threshold = 0.5
        
        logger.info("增强数据流分析器初始化完成")
    
    def analyze_enhanced_data_flows(self, source_files: List[SourceFile], 
                                  vulnerability: Optional[VulnerabilityResult] = None) -> List[EnhancedDataFlowPath]:
        """分析增强的数据流"""
        logger.info("🔍 开始增强数据流分析...")
        
        enhanced_paths = []
        
        # 第一阶段：变量追踪
        if self.enable_variable_tracking:
            self._track_variables_in_files(source_files)
        
        # 第二阶段：污点传播分析
        all_propagation_steps = []
        for source_file in source_files:
            steps = self.propagation_analyzer.analyze_propagation(source_file, self.variable_tracker)
            all_propagation_steps.extend(steps)
        
        # 第三阶段：构建数据流图
        data_flow_graph = self.graph_builder.build_graph(
            self.variable_tracker.variable_states, 
            all_propagation_steps
        )
        
        # 第四阶段：分析增强路径
        for source in self.taint_sources:
            for sink in self.taint_sinks:
                enhanced_path = self._analyze_enhanced_path(
                    source, sink, data_flow_graph, vulnerability
                )
                if enhanced_path and enhanced_path.risk_score > self.confidence_threshold:
                    enhanced_paths.append(enhanced_path)
        
        # 第五阶段：可视化（如果启用）
        if self.enable_graph_visualization:
            self.graph_builder.visualize_graph()
        
        # 按风险评分排序
        enhanced_paths.sort(key=lambda x: x.risk_score, reverse=True)
        
        logger.info(f"✅ 增强数据流分析完成，发现 {len(enhanced_paths)} 条增强路径")
        
        return enhanced_paths
    
    def _track_variables_in_files(self, source_files: List[SourceFile]):
        """在文件中追踪变量"""
        logger.debug("开始变量追踪...")
        
        for source_file in source_files:
            try:
                tree = ast.parse(source_file.content)
                
                # 遍历AST节点
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign):
                        self._track_assignment(node, source_file.path)
                    elif isinstance(node, ast.FunctionDef):
                        self._track_function_parameters(node, source_file.path)
            
            except Exception as e:
                logger.warning(f"变量追踪失败: {source_file.path}, {e}")
        
        logger.debug(f"变量追踪完成，共追踪 {len(self.variable_tracker.variable_states)} 个变量")
    
    def _track_assignment(self, node: ast.Assign, file_path: str):
        """追踪赋值语句"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.variable_tracker.track_variable_assignment(
                    target.id, node.value, node.lineno, file_path
                )
    
    def _track_function_parameters(self, node: ast.FunctionDef, file_path: str):
        """追踪函数参数"""
        scope = f"{file_path}::{node.name}"
        
        for arg in node.args.args:
            # 假设参数可能是污点源
            var_state = VariableState(
                name=f"{scope}::{arg.arg}",
                taint_level=TaintLevel.TAINTED,  # 保守假设
                source_line=node.lineno,
                data_type="parameter"
            )
            self.variable_tracker.variable_states[var_state.name] = var_state
    
    def _analyze_enhanced_path(self, source: TaintSource, sink: TaintSink,
                             data_flow_graph: DataFlowGraph,
                             vulnerability: Optional[VulnerabilityResult]) -> Optional[EnhancedDataFlowPath]:
        """分析增强路径"""
        # 查找从源到汇的路径
        paths = self._find_enhanced_paths(source.entity_name, sink.entity_name, data_flow_graph)
        
        if not paths:
            return None
        
        # 选择最佳路径（最短且风险最高）
        best_path = min(paths, key=len)
        
        # 分析路径上的变量状态
        path_variable_states = {}
        for var_name in best_path:
            if var_name in data_flow_graph.nodes:
                path_variable_states[var_name] = data_flow_graph.nodes[var_name]
        
        # 提取传播步骤
        path_propagation_steps = []
        for i in range(len(best_path) - 1):
            from_var = best_path[i]
            to_var = best_path[i + 1]
            
            for step in data_flow_graph.edges:
                if step.from_var == from_var and step.to_var == to_var:
                    path_propagation_steps.append(step)
                    break
        
        # 计算污点级别和风险评分
        taint_level, risk_score = self._calculate_path_risk(
            best_path, path_propagation_steps, vulnerability
        )
        
        # 识别净化点
        sanitization_points = [
            step.to_var for step in path_propagation_steps 
            if step.sanitization_applied
        ]
        
        # 识别漏洞类型
        vulnerability_types = self._identify_vulnerability_types(source, sink, best_path)
        
        return EnhancedDataFlowPath(
            source=source,
            sink=sink,
            path=best_path,
            variable_states=path_variable_states,
            propagation_steps=path_propagation_steps,
            taint_level=taint_level,
            sanitization_points=sanitization_points,
            risk_score=risk_score,
            vulnerability_types=vulnerability_types,
            metadata={
                'path_length': len(best_path),
                'propagation_steps': len(path_propagation_steps),
                'has_sanitization': len(sanitization_points) > 0
            }
        )
    
    def _find_enhanced_paths(self, source: str, sink: str, 
                           data_flow_graph: DataFlowGraph) -> List[List[str]]:
        """查找增强路径"""
        paths = []
        
        # 在数据流图中查找路径
        graph = self.graph_builder.graph
        
        try:
            if nx.has_path(graph, source, sink):
                all_paths = list(nx.all_simple_paths(
                    graph, source, sink, cutoff=self.max_path_length
                ))
                paths.extend(all_paths[:5])  # 限制路径数量
        except nx.NetworkXError:
            pass
        
        # 如果没有直接路径，尝试通过关键路径
        if not paths:
            for critical_path in data_flow_graph.critical_paths:
                if source in critical_path and sink in critical_path:
                    source_idx = critical_path.index(source)
                    sink_idx = critical_path.index(sink)
                    if source_idx < sink_idx:
                        paths.append(critical_path[source_idx:sink_idx + 1])
        
        return paths
    
    def _calculate_path_risk(self, path: List[str], 
                           propagation_steps: List[TaintPropagationStep],
                           vulnerability: Optional[VulnerabilityResult]) -> Tuple[TaintLevel, float]:
        """计算路径风险"""
        base_risk = 0.5
        
        # 路径长度影响
        length_factor = min(1.0, len(path) / 10.0)
        base_risk += length_factor * 0.2
        
        # 传播类型影响
        for step in propagation_steps:
            if step.propagation_type == TaintPropagationType.DIRECT:
                base_risk += 0.1
            elif step.propagation_type == TaintPropagationType.PARAMETER:
                base_risk += 0.15
            elif step.propagation_type == TaintPropagationType.RETURN:
                base_risk += 0.12
        
        # 净化影响
        sanitization_count = sum(1 for step in propagation_steps if step.sanitization_applied)
        if sanitization_count > 0:
            base_risk *= (1.0 - sanitization_count * 0.2)
        
        # 漏洞上下文影响
        if vulnerability:
            if vulnerability.severity in ['high', 'critical']:
                base_risk += 0.2
            elif vulnerability.severity == 'medium':
                base_risk += 0.1
        
        # 确定污点级别
        if base_risk >= 0.8:
            taint_level = TaintLevel.DANGEROUS
        elif base_risk >= 0.6:
            taint_level = TaintLevel.TAINTED
        elif sanitization_count > 0:
            taint_level = TaintLevel.SANITIZED
        else:
            taint_level = TaintLevel.SAFE
        
        return taint_level, min(1.0, base_risk)
    
    def _identify_vulnerability_types(self, source: TaintSource, sink: TaintSink, 
                                    path: List[str]) -> Set[str]:
        """识别漏洞类型"""
        vulnerability_types = set()
        
        # 基于源和汇的组合判断
        if source.source_type == "user_input":
            if sink.sink_type == "sql_query":
                vulnerability_types.add("SQL Injection")
            elif sink.sink_type == "command_exec":
                vulnerability_types.add("Command Injection")
            elif sink.sink_type == "template_render":
                vulnerability_types.add("XSS")
            elif sink.sink_type == "file_write":
                vulnerability_types.add("Path Traversal")
        
        elif source.source_type == "file_input":
            if sink.sink_type == "command_exec":
                vulnerability_types.add("Code Injection")
            elif sink.sink_type == "response_output":
                vulnerability_types.add("Information Disclosure")
        
        elif source.source_type == "network_input":
            if sink.sink_type == "file_write":
                vulnerability_types.add("Remote File Write")
            elif sink.sink_type == "command_exec":
                vulnerability_types.add("Remote Code Execution")
        
        # 如果没有识别出特定类型，添加通用类型
        if not vulnerability_types:
            vulnerability_types.add("Data Flow Vulnerability")
        
        return vulnerability_types
    
    def generate_flow_report(self, enhanced_paths: List[EnhancedDataFlowPath]) -> Dict[str, Any]:
        """生成数据流报告"""
        if not enhanced_paths:
            return {"status": "no_flows_found"}
        
        # 统计信息
        total_paths = len(enhanced_paths)
        high_risk_paths = len([p for p in enhanced_paths if p.risk_score >= 0.8])
        medium_risk_paths = len([p for p in enhanced_paths if 0.5 <= p.risk_score < 0.8])
        
        # 漏洞类型统计
        vulnerability_type_counts = defaultdict(int)
        for path in enhanced_paths:
            for vuln_type in path.vulnerability_types:
                vulnerability_type_counts[vuln_type] += 1
        
        # 净化覆盖率
        paths_with_sanitization = len([p for p in enhanced_paths if p.sanitization_points])
        sanitization_coverage = paths_with_sanitization / total_paths if total_paths > 0 else 0
        
        return {
            "status": "analysis_complete",
            "summary": {
                "total_paths": total_paths,
                "high_risk_paths": high_risk_paths,
                "medium_risk_paths": medium_risk_paths,
                "sanitization_coverage": sanitization_coverage
            },
            "vulnerability_types": dict(vulnerability_type_counts),
            "top_risk_paths": [
                {
                    "source": path.source.entity_name,
                    "sink": path.sink.entity_name,
                    "risk_score": path.risk_score,
                    "path_length": len(path.path),
                    "vulnerability_types": list(path.vulnerability_types)
                }
                for path in enhanced_paths[:5]
            ],
            "recommendations": self._generate_recommendations(enhanced_paths)
        }
    
    def _generate_recommendations(self, enhanced_paths: List[EnhancedDataFlowPath]) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        # 基于分析结果生成建议
        high_risk_count = len([p for p in enhanced_paths if p.risk_score >= 0.8])
        if high_risk_count > 0:
            recommendations.append(f"发现 {high_risk_count} 条高风险数据流路径，建议优先修复")
        
        # 净化建议
        unsanitized_paths = [p for p in enhanced_paths if not p.sanitization_points]
        if unsanitized_paths:
            recommendations.append(f"有 {len(unsanitized_paths)} 条路径缺少数据净化，建议添加输入验证和输出编码")
        
        # 漏洞类型建议
        vulnerability_types = set()
        for path in enhanced_paths:
            vulnerability_types.update(path.vulnerability_types)
        
        if "SQL Injection" in vulnerability_types:
            recommendations.append("检测到SQL注入风险，建议使用参数化查询")
        
        if "XSS" in vulnerability_types:
            recommendations.append("检测到XSS风险，建议对输出进行HTML编码")
        
        if "Command Injection" in vulnerability_types:
            recommendations.append("检测到命令注入风险，建议避免直接执行用户输入")
        
        return recommendations