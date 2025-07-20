"""
数据流分析器 - 追踪数据在函数间的流动路径和污点分析
"""

import ast
import networkx as nx
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from loguru import logger

from auditluma.models.code import SourceFile, CodeUnit
from .global_context_analyzer import CodeEntity


class TaintLevel(Enum):
    """污点级别"""
    SAFE = "safe"           # 安全的
    SANITIZED = "sanitized" # 已消毒的
    TAINTED = "tainted"     # 有污点的
    DANGEROUS = "dangerous" # 危险的


@dataclass
class TaintSource:
    """污点源"""
    entity_name: str
    source_type: str  # "user_input", "file_input", "network_input", etc.
    confidence: float = 1.0


@dataclass
class TaintSink:
    """污点汇点"""
    entity_name: str
    sink_type: str  # "sql_query", "command_exec", "file_write", etc.
    danger_level: str = "high"


@dataclass
class DataFlowPath:
    """数据流路径"""
    source: TaintSource
    sink: TaintSink
    path: List[str]
    taint_level: TaintLevel
    sanitization_points: List[str]
    risk_score: float


class DataFlowAnalyzer:
    """数据流分析器 - 追踪数据流动和污点传播"""
    
    def __init__(self, global_context: Dict[str, Any]):
        self.global_context = global_context
        self.call_graph = global_context["call_graph"]
        self.entities = global_context["entities"]
        
        # 污点分析相关
        self.taint_sources: List[TaintSource] = []
        self.taint_sinks: List[TaintSink] = []
        self.taint_propagation_graph = nx.DiGraph()
        
        # 数据流路径缓存
        self.analyzed_paths: Dict[Tuple[str, str], DataFlowPath] = {}
        
        # 初始化污点源和汇点
        self._initialize_taint_analysis()
    
    def _initialize_taint_analysis(self):
        """初始化污点分析 - 识别污点源和汇点"""
        logger.debug("初始化污点分析...")
        
        # 定义污点源模式
        source_patterns = {
            'user_input': [
                r'request\.',
                r'input\s*\(',
                r'raw_input\s*\(',
                r'sys\.argv',
                r'os\.environ',
                r'form\.',
                r'args\.',
                r'json\.',
                r'params\.',
                r'cookies\.',
                r'headers\.'
            ],
            'file_input': [
                r'open\s*\(',
                r'read\s*\(',
                r'readline\s*\(',
                r'readlines\s*\(',
                r'file\s*\(',
                r'csv\.reader',
                r'json\.load'
            ],
            'network_input': [
                r'requests\.',
                r'urllib\.',
                r'socket\.',
                r'http\.',
                r'ftp\.',
                r'urlopen'
            ]
        }
        
        # 定义汇点模式
        sink_patterns = {
            'sql_query': [
                r'execute\s*\(',
                r'query\s*\(',
                r'cursor\.',
                r'SELECT\s+.*FROM',
                r'INSERT\s+INTO',
                r'UPDATE\s+.*SET',
                r'DELETE\s+FROM'
            ],
            'command_exec': [
                r'os\.system\s*\(',
                r'subprocess\.',
                r'eval\s*\(',
                r'exec\s*\(',
                r'shell=True',
                r'popen\s*\('
            ],
            'file_write': [
                r'write\s*\(',
                r'writelines\s*\(',
                r'open\s*\(.*["\']w',
                r'open\s*\(.*["\']a'
            ],
            'template_render': [
                r'render\s*\(',
                r'template\.',
                r'jinja',
                r'{% .*%}',
                r'{{ .*}}'
            ],
            'response_output': [
                r'response\.',
                r'HttpResponse',
                r'return.*render',
                r'print\s*\(',
                r'write\s*\('
            ]
        }
        
        # 识别污点源
        for source_type, patterns in source_patterns.items():
            entities = self._find_entities_with_patterns(patterns)
            for entity_name in entities:
                source = TaintSource(
                    entity_name=entity_name,
                    source_type=source_type,
                    confidence=0.9
                )
                self.taint_sources.append(source)
        
        # 识别汇点
        for sink_type, patterns in sink_patterns.items():
            entities = self._find_entities_with_patterns(patterns)
            for entity_name in entities:
                danger_level = "high" if sink_type in ['sql_query', 'command_exec'] else "medium"
                sink = TaintSink(
                    entity_name=entity_name,
                    sink_type=sink_type,
                    danger_level=danger_level
                )
                self.taint_sinks.append(sink)
        
        logger.debug(f"识别了 {len(self.taint_sources)} 个污点源和 {len(self.taint_sinks)} 个汇点")
    
    def analyze_data_flows(self) -> List[DataFlowPath]:
        """分析数据流路径"""
        logger.info("🔍 开始数据流分析...")
        
        dangerous_paths = []
        
        # 分析每个污点源到汇点的路径
        for source in self.taint_sources:
            for sink in self.taint_sinks:
                path_key = (source.entity_name, sink.entity_name)
                
                # 检查缓存
                if path_key in self.analyzed_paths:
                    dangerous_paths.append(self.analyzed_paths[path_key])
                    continue
                
                # 查找路径
                paths = self._find_all_paths(source.entity_name, sink.entity_name)
                
                for path in paths:
                    # 分析路径的污点传播
                    flow_path = self._analyze_path_taint_propagation(source, sink, path)
                    
                    if flow_path and flow_path.risk_score > 0.3:
                        dangerous_paths.append(flow_path)
                        self.analyzed_paths[path_key] = flow_path
        
        # 按风险评分排序
        dangerous_paths.sort(key=lambda x: x.risk_score, reverse=True)
        
        logger.info(f"✅ 数据流分析完成，发现 {len(dangerous_paths)} 条危险路径")
        
        return dangerous_paths
    
    def _find_entities_with_patterns(self, patterns: List[str]) -> List[str]:
        """查找包含特定模式的实体"""
        import re
        matching_entities = []
        
        for entity_name, entity in self.entities.items():
            if entity.ast_node:
                try:
                    # 尝试获取代码字符串
                    import astor
                    code_str = astor.to_source(entity.ast_node)
                except ImportError:
                    code_str = str(entity.ast_node)
                
                for pattern in patterns:
                    if re.search(pattern, code_str, re.IGNORECASE):
                        matching_entities.append(entity_name)
                        break
        
        return matching_entities
    
    def _find_all_paths(self, source: str, sink: str, max_length: int = 10) -> List[List[str]]:
        """查找从源到汇点的所有路径"""
        try:
            # 使用调用图查找路径
            if nx.has_path(self.call_graph, source, sink):
                all_paths = list(nx.all_simple_paths(
                    self.call_graph, source, sink, cutoff=max_length
                ))
                return all_paths[:5]  # 限制路径数量
        except nx.NetworkXError:
            pass
        
        return []
    
    def _analyze_path_taint_propagation(self, source: TaintSource, sink: TaintSink, path: List[str]) -> Optional[DataFlowPath]:
        """分析路径上的污点传播"""
        if len(path) < 2:
            return None
        
        # 初始污点级别基于源类型
        current_taint = TaintLevel.TAINTED
        if source.source_type == "user_input":
            current_taint = TaintLevel.DANGEROUS
        
        sanitization_points = []
        
        # 分析路径上每个节点的污点传播
        for i, node in enumerate(path[1:-1], 1):  # 跳过源和汇点
            node_effect = self._analyze_node_taint_effect(node)
            
            if node_effect == "sanitize":
                current_taint = TaintLevel.SANITIZED
                sanitization_points.append(node)
            elif node_effect == "propagate":
                # 污点继续传播
                pass
            elif node_effect == "amplify":
                if current_taint == TaintLevel.TAINTED:
                    current_taint = TaintLevel.DANGEROUS
        
        # 计算风险评分
        risk_score = self._calculate_risk_score(source, sink, current_taint, path)
        
        return DataFlowPath(
            source=source,
            sink=sink,
            path=path,
            taint_level=current_taint,
            sanitization_points=sanitization_points,
            risk_score=risk_score
        )
    
    def _analyze_node_taint_effect(self, node: str) -> str:
        """分析节点对污点的影响"""
        if node not in self.entities:
            return "propagate"
        
        entity = self.entities[node]
        
        if entity.ast_node:
            try:
                import astor
                code_str = astor.to_source(entity.ast_node).lower()
            except ImportError:
                code_str = str(entity.ast_node).lower()
            
            # 检查是否有消毒操作
            sanitization_keywords = [
                'escape', 'sanitize', 'clean', 'validate', 'filter',
                'quote', 'encode', 'htmlentities', 'htmlspecialchars',
                'strip_tags', 'bleach', 'purify'
            ]
            
            for keyword in sanitization_keywords:
                if keyword in code_str:
                    return "sanitize"
            
            # 检查是否有放大风险的操作
            amplify_keywords = [
                'eval', 'exec', 'compile', 'format', 'template'
            ]
            
            for keyword in amplify_keywords:
                if keyword in code_str:
                    return "amplify"
        
        return "propagate"
    
    def _calculate_risk_score(self, source: TaintSource, sink: TaintSink, 
                            taint_level: TaintLevel, path: List[str]) -> float:
        """计算风险评分"""
        base_score = 0.0
        
        # 基于污点源类型的基础分数
        source_scores = {
            'user_input': 0.8,
            'file_input': 0.6,
            'network_input': 0.7
        }
        base_score += source_scores.get(source.source_type, 0.5)
        
        # 基于汇点类型的分数
        sink_scores = {
            'sql_query': 0.9,
            'command_exec': 1.0,
            'file_write': 0.6,
            'template_render': 0.7,
            'response_output': 0.5
        }
        base_score += sink_scores.get(sink.sink_type, 0.3)
        
        # 基于污点级别的调整
        taint_multipliers = {
            TaintLevel.SAFE: 0.0,
            TaintLevel.SANITIZED: 0.2,
            TaintLevel.TAINTED: 0.7,
            TaintLevel.DANGEROUS: 1.0
        }
        base_score *= taint_multipliers[taint_level]
        
        # 基于路径长度的调整（路径越短风险越高）
        path_factor = max(0.3, 1.0 - (len(path) - 2) * 0.1)
        base_score *= path_factor
        
        # 基于源的可信度
        base_score *= source.confidence
        
        return min(1.0, base_score)
    
    def get_critical_data_flows(self, min_risk_score: float = 0.7) -> List[DataFlowPath]:
        """获取高风险数据流"""
        all_flows = self.analyze_data_flows()
        return [flow for flow in all_flows if flow.risk_score >= min_risk_score]
    
    def get_sanitization_coverage(self) -> Dict[str, Any]:
        """获取消毒覆盖率统计"""
        all_flows = self.analyze_data_flows()
        
        total_flows = len(all_flows)
        sanitized_flows = len([f for f in all_flows if f.taint_level == TaintLevel.SANITIZED])
        
        coverage_by_source = {}
        for source_type in ['user_input', 'file_input', 'network_input']:
            type_flows = [f for f in all_flows if f.source.source_type == source_type]
            type_sanitized = [f for f in type_flows if f.taint_level == TaintLevel.SANITIZED]
            
            coverage_by_source[source_type] = {
                'total': len(type_flows),
                'sanitized': len(type_sanitized),
                'coverage_rate': len(type_sanitized) / len(type_flows) if type_flows else 0
            }
        
        return {
            'overall_coverage': sanitized_flows / total_flows if total_flows else 0,
            'total_flows': total_flows,
            'sanitized_flows': sanitized_flows,
            'coverage_by_source': coverage_by_source
        }
    
    def visualize_data_flow(self, flow_path: DataFlowPath) -> Dict[str, Any]:
        """可视化数据流路径"""
        nodes = []
        edges = []
        
        # 创建节点
        for i, node in enumerate(flow_path.path):
            node_type = "source" if i == 0 else "sink" if i == len(flow_path.path) - 1 else "intermediate"
            is_sanitization = node in flow_path.sanitization_points
            
            nodes.append({
                'id': node,
                'label': node.split("::")[-1] if "::" in node else node,
                'type': node_type,
                'sanitization': is_sanitization,
                'entity': self.entities.get(node, {})
            })
        
        # 创建边
        for i in range(len(flow_path.path) - 1):
            edges.append({
                'source': flow_path.path[i],
                'target': flow_path.path[i + 1],
                'type': 'data_flow'
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'flow_info': {
                'source_type': flow_path.source.source_type,
                'sink_type': flow_path.sink.sink_type,
                'taint_level': flow_path.taint_level.value,
                'risk_score': flow_path.risk_score,
                'sanitization_points': len(flow_path.sanitization_points)
            }
        } 