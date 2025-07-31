"""
语义上下文扩展器 - R2R上下文增强层组件
实现动态上下文窗口扩展算法和语义关联性评估
"""

import asyncio
import re
import ast
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
import math

from loguru import logger

from auditluma.models.code import VulnerabilityResult, SourceFile, CodeUnit
from auditluma.models.hierarchical_rag import SemanticContext


@dataclass
class ContextWindow:
    """上下文窗口"""
    center_line: int
    start_line: int
    end_line: int
    content: str
    relevance_score: float
    expansion_reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def size(self) -> int:
        """窗口大小（行数）"""
        return self.end_line - self.start_line + 1
    
    def overlaps_with(self, other: 'ContextWindow') -> bool:
        """检查是否与另一个窗口重叠"""
        return not (self.end_line < other.start_line or self.start_line > other.end_line)
    
    def merge_with(self, other: 'ContextWindow') -> 'ContextWindow':
        """与另一个窗口合并"""
        new_start = min(self.start_line, other.start_line)
        new_end = max(self.end_line, other.end_line)
        new_relevance = max(self.relevance_score, other.relevance_score)
        
        # 保留重要窗口类型的标识
        important_reasons = ["original_context", "function_boundary"]
        
        if self.expansion_reason in important_reasons:
            new_reason = self.expansion_reason
        elif other.expansion_reason in important_reasons:
            new_reason = other.expansion_reason
        else:
            new_reason = f"{self.expansion_reason}+{other.expansion_reason}"
        
        return ContextWindow(
            center_line=(new_start + new_end) // 2,
            start_line=new_start,
            end_line=new_end,
            content=f"{self.content}\n{other.content}",
            relevance_score=new_relevance,
            expansion_reason=new_reason
        )


@dataclass
class SemanticRelation:
    """语义关系"""
    source_entity: str
    target_entity: str
    relation_type: str
    strength: float
    context: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExpandedContext:
    """扩展后的上下文"""
    original_context: str
    expanded_content: str
    context_windows: List[ContextWindow]
    semantic_relations: List[SemanticRelation]
    completeness_score: float
    expansion_metadata: Dict[str, Any] = field(default_factory=dict)


class ContextExpander:
    """语义上下文扩展器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化上下文扩展器"""
        self.config = config or {}
        self.max_window_size = self.config.get('max_window_size', 50)
        self.min_relevance_threshold = self.config.get('min_relevance_threshold', 0.2)
        self.expansion_strategies = self.config.get('expansion_strategies', [
            'variable_tracking',
            'function_boundary', 
            'control_flow',
            'data_dependency',
            'semantic_similarity'
        ])
        
        # 语义分析模式
        self.semantic_patterns = self._init_semantic_patterns()
        
        logger.info(f"语义上下文扩展器初始化完成，最大窗口大小: {self.max_window_size}")
    
    def _init_semantic_patterns(self) -> Dict[str, List[str]]:
        """初始化语义模式"""
        return {
            'variable_assignment': [
                r'(\w+)\s*=\s*(.+)',
                r'(\w+)\s*:\s*\w+\s*=\s*(.+)',  # 类型注解赋值
            ],
            'function_call': [
                r'(\w+)\s*\(',
                r'(\w+)\.(\w+)\s*\(',
                r'await\s+(\w+)\s*\(',
            ],
            'control_flow': [
                r'\b(if|elif|else|for|while|try|except|finally|with)\b',
                r'\breturn\s+(.+)',
                r'\byield\s+(.+)',
            ],
            'data_dependency': [
                r'(\w+)\s*\[\s*(\w+)\s*\]',  # 数组/字典访问
                r'(\w+)\.(\w+)',  # 属性访问
                r'(\w+)\s*\+=\s*(.+)',  # 累加操作
            ],
            'security_patterns': [
                r'\b(validate|sanitize|escape|filter|authenticate|authorize)\b',
                r'\b(sql|query|execute|cursor)\b',
                r'\b(password|token|secret|key)\b',
            ]
        }
    
    async def expand_context(self, vulnerability: VulnerabilityResult, 
                           source_file: SourceFile) -> ExpandedContext:
        """扩展代码上下文"""
        logger.debug(f"开始扩展上下文: {vulnerability.id}")
        
        try:
            # 获取原始上下文
            original_context = self._get_original_context(vulnerability, source_file)
            
            # 创建初始窗口
            original_window = self._create_original_window(vulnerability, source_file)
            context_windows = [original_window]
            
            # 应用扩展策略
            for strategy in self.expansion_strategies:
                try:
                    new_windows = await self._apply_expansion_strategy(
                        strategy, vulnerability, source_file, context_windows
                    )
                    context_windows.extend(new_windows)
                except Exception as e:
                    logger.warning(f"扩展策略 {strategy} 失败: {e}")
            
            # 去重和合并窗口
            context_windows = self._deduplicate_windows(context_windows)
            
            # 分析语义关系
            semantic_relations = await self._analyze_semantic_relations(
                vulnerability, source_file, context_windows
            )
            
            # 生成扩展内容
            expanded_content = self._generate_expanded_content(context_windows)
            
            # 计算完整性评分
            completeness_score = self._calculate_completeness_score(
                context_windows, semantic_relations
            )
            
            expanded_context = ExpandedContext(
                original_context=original_context,
                expanded_content=expanded_content,
                context_windows=context_windows,
                semantic_relations=semantic_relations,
                completeness_score=completeness_score,
                expansion_metadata={
                    'total_windows': len(context_windows),
                    'total_relations': len(semantic_relations),
                    'strategies_used': self.expansion_strategies
                }
            )
            
            logger.debug(f"上下文扩展完成，窗口数: {len(context_windows)}, 关系数: {len(semantic_relations)}")
            return expanded_context
            
        except Exception as e:
            logger.error(f"上下文扩展失败: {e}")
            return self._create_fallback_context(vulnerability, source_file)
    
    def _get_original_context(self, vulnerability: VulnerabilityResult, 
                            source_file: SourceFile) -> str:
        """获取原始上下文"""
        if vulnerability.snippet:
            return vulnerability.snippet
        
        # 从源文件中提取上下文
        lines = source_file.content.split('\n')
        start_line = max(0, vulnerability.start_line - 3)
        end_line = min(len(lines), vulnerability.end_line + 3)
        
        return '\n'.join(lines[start_line:end_line])
    
    def _create_original_window(self, vulnerability: VulnerabilityResult,
                              source_file: SourceFile) -> ContextWindow:
        """创建原始上下文窗口"""
        lines = source_file.content.split('\n')
        
        # 扩展到周围几行
        context_size = 5
        start_line = max(0, vulnerability.start_line - context_size - 1)  # 调整索引
        end_line = min(len(lines) - 1, vulnerability.end_line + context_size - 1)  # 调整索引
        
        content = '\n'.join(lines[start_line:end_line + 1])
        
        return ContextWindow(
            center_line=vulnerability.start_line - 1,  # 调整为0基索引
            start_line=start_line,
            end_line=end_line,
            content=content,
            relevance_score=1.0,
            expansion_reason="original_context"
        )
    
    async def _apply_expansion_strategy(self, strategy: str, 
                                      vulnerability: VulnerabilityResult,
                                      source_file: SourceFile,
                                      existing_windows: List[ContextWindow]) -> List[ContextWindow]:
        """应用扩展策略"""
        if strategy == 'variable_tracking':
            return await self._expand_by_variable_tracking(vulnerability, source_file)
        elif strategy == 'function_boundary':
            return await self._expand_by_function_boundary(vulnerability, source_file)
        elif strategy == 'control_flow':
            return await self._expand_by_control_flow(vulnerability, source_file)
        elif strategy == 'data_dependency':
            return await self._expand_by_data_dependency(vulnerability, source_file)
        elif strategy == 'semantic_similarity':
            return await self._expand_by_semantic_similarity(vulnerability, source_file)
        else:
            logger.warning(f"未知的扩展策略: {strategy}")
            return []
    
    async def _expand_by_variable_tracking(self, vulnerability: VulnerabilityResult,
                                         source_file: SourceFile) -> List[ContextWindow]:
        """基于变量追踪扩展上下文"""
        windows = []
        
        # 提取漏洞代码中的变量
        variables = self._extract_variables_from_snippet(vulnerability.snippet)
        
        lines = source_file.content.split('\n')
        
        for var in variables:
            # 查找变量的定义和使用
            for i, line in enumerate(lines):
                if var in line and i != vulnerability.start_line:
                    # 检查是否是真正的变量使用
                    if self._is_variable_usage(var, line):
                        window = self._create_context_window_around_line(
                            i, lines, f"variable_tracking_{var}", 0.7
                        )
                        if window:
                            windows.append(window)
        
        return windows[:5]  # 限制数量
    
    async def _expand_by_function_boundary(self, vulnerability: VulnerabilityResult,
                                         source_file: SourceFile) -> List[ContextWindow]:
        """基于函数边界扩展上下文"""
        windows = []
        lines = source_file.content.split('\n')
        
        # 查找包含漏洞的函数
        func_start, func_end = self._find_function_boundaries(vulnerability.start_line, lines)
        
        if func_start is not None and func_end is not None:
            content = '\n'.join(lines[func_start:func_end + 1])
            window = ContextWindow(
                center_line=(func_start + func_end) // 2,
                start_line=func_start,
                end_line=func_end,
                content=content,
                relevance_score=0.9,
                expansion_reason="function_boundary"
            )
            windows.append(window)
        else:
            # 如果找不到函数边界，创建一个较大的上下文窗口
            context_size = 10
            start_line = max(0, vulnerability.start_line - context_size - 1)
            end_line = min(len(lines) - 1, vulnerability.start_line + context_size - 1)
            
            content = '\n'.join(lines[start_line:end_line + 1])
            window = ContextWindow(
                center_line=vulnerability.start_line - 1,
                start_line=start_line,
                end_line=end_line,
                content=content,
                relevance_score=0.8,
                expansion_reason="function_boundary"
            )
            windows.append(window)
        
        return windows
    
    async def _expand_by_control_flow(self, vulnerability: VulnerabilityResult,
                                    source_file: SourceFile) -> List[ContextWindow]:
        """基于控制流扩展上下文"""
        windows = []
        lines = source_file.content.split('\n')
        
        # 查找控制流语句
        control_flow_patterns = [
            r'\s*(if|elif|else|for|while|try|except|finally|with)\b',
            r'\s*return\b',
            r'\s*break\b',
            r'\s*continue\b'
        ]
        
        for i, line in enumerate(lines):
            for pattern in control_flow_patterns:
                if re.search(pattern, line):
                    # 检查是否在漏洞附近
                    distance = abs(i - vulnerability.start_line)
                    if distance <= 10 and distance > 0:
                        window = self._create_context_window_around_line(
                            i, lines, "control_flow", 0.6
                        )
                        if window:
                            windows.append(window)
                    break
        
        return windows[:3]  # 限制数量
    
    async def _expand_by_data_dependency(self, vulnerability: VulnerabilityResult,
                                       source_file: SourceFile) -> List[ContextWindow]:
        """基于数据依赖扩展上下文"""
        windows = []
        lines = source_file.content.split('\n')
        
        # 提取漏洞代码中的变量
        variables = self._extract_variables_from_snippet(vulnerability.snippet)
        
        # 查找数据依赖关系
        for i, line in enumerate(lines):
            for var in variables:
                # 查找赋值语句
                if re.search(rf'\b{var}\s*=', line) and i != vulnerability.start_line:
                    window = self._create_context_window_around_line(
                        i, lines, f"data_dependency_assignment", 0.8
                    )
                    if window:
                        windows.append(window)
                
                # 查找函数调用中的变量使用
                if re.search(rf'\w+\([^)]*\b{var}\b[^)]*\)', line) and i != vulnerability.start_line:
                    window = self._create_context_window_around_line(
                        i, lines, f"data_dependency_call", 0.7
                    )
                    if window:
                        windows.append(window)
        
        return windows[:4]  # 限制数量
    
    async def _expand_by_semantic_similarity(self, vulnerability: VulnerabilityResult,
                                           source_file: SourceFile) -> List[ContextWindow]:
        """基于语义相似性扩展上下文"""
        windows = []
        lines = source_file.content.split('\n')
        
        # 提取漏洞代码的关键词
        vuln_keywords = self._extract_keywords_from_snippet(vulnerability.snippet)
        
        for i, line in enumerate(lines):
            if i == vulnerability.start_line:
                continue
            
            # 提取当前行的关键词
            line_keywords = self._extract_keywords_from_snippet(line)
            
            # 计算相似度
            similarity = self._calculate_keyword_similarity(vuln_keywords, line_keywords)
            
            if similarity >= self.min_relevance_threshold:
                window = self._create_context_window_around_line(
                    i, lines, "semantic_similarity", similarity
                )
                if window:
                    windows.append(window)
        
        # 按相似度排序并限制数量
        windows.sort(key=lambda w: w.relevance_score, reverse=True)
        return windows[:5]
    
    def _extract_variables_from_snippet(self, snippet: str) -> Set[str]:
        """从代码片段中提取变量"""
        variables = set()
        
        # 使用正则表达式提取标识符
        identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', snippet)
        
        # 过滤掉Python关键字和常见函数
        python_keywords = {
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def', 'del',
            'elif', 'else', 'except', 'exec', 'finally', 'for', 'from', 'global',
            'if', 'import', 'in', 'is', 'lambda', 'not', 'or', 'pass', 'print',
            'raise', 'return', 'try', 'while', 'with', 'yield', 'True', 'False', 'None'
        }
        
        for identifier in identifiers:
            if identifier not in python_keywords and len(identifier) > 1:
                variables.add(identifier)
        
        return variables
    
    def _extract_keywords_from_snippet(self, snippet: str) -> Set[str]:
        """从代码片段中提取关键词"""
        keywords = set()
        
        # 提取标识符
        identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', snippet.lower())
        keywords.update(identifiers)
        
        # 提取字符串字面量中的关键词
        strings = re.findall(r'["\']([^"\']*)["\']', snippet)
        for string in strings:
            string_words = re.findall(r'\b[a-zA-Z]+\b', string.lower())
            keywords.update(string_words)
        
        # 提取注释中的关键词
        comments = re.findall(r'#\s*(.+)', snippet)
        for comment in comments:
            comment_words = re.findall(r'\b[a-zA-Z]+\b', comment.lower())
            keywords.update(comment_words)
        
        return keywords
    
    def _calculate_keyword_similarity(self, keywords1: Set[str], keywords2: Set[str]) -> float:
        """计算关键词相似度"""
        if not keywords1 or not keywords2:
            return 0.0
        
        intersection = keywords1.intersection(keywords2)
        union = keywords1.union(keywords2)
        
        # Jaccard相似度
        jaccard = len(intersection) / len(union) if union else 0.0
        
        # 考虑关键词的重要性权重
        important_keywords = {
            'password', 'user', 'auth', 'login', 'query', 'sql', 'database',
            'input', 'output', 'validate', 'sanitize', 'escape', 'security'
        }
        
        important_intersection = intersection.intersection(important_keywords)
        importance_bonus = len(important_intersection) * 0.1
        
        return min(1.0, jaccard + importance_bonus)
    
    def _is_variable_usage(self, variable: str, line: str) -> bool:
        """检查是否是真正的变量使用"""
        # 简单的启发式检查
        patterns = [
            rf'\b{variable}\s*=',  # 赋值
            rf'\b{variable}\s*\[',  # 数组访问
            rf'\b{variable}\s*\.',  # 属性访问
            rf'\({variable}\)',     # 函数参数
            rf'\b{variable}\b',     # 一般使用
        ]
        
        return any(re.search(pattern, line) for pattern in patterns)
    
    def _find_function_boundaries(self, line_number: int, lines: List[str]) -> Tuple[Optional[int], Optional[int]]:
        """查找函数边界"""
        start_line = None
        end_line = None
        
        # 调整为0基索引
        search_line = line_number - 1 if line_number > 0 else 0
        
        # 向上查找函数定义
        for i in range(search_line, -1, -1):
            if i < len(lines) and re.match(r'\s*def\s+\w+\s*\(', lines[i]):
                start_line = i
                break
        
        if start_line is not None:
            # 向下查找函数结束
            indent_level = len(lines[start_line]) - len(lines[start_line].lstrip())
            
            for i in range(start_line + 1, len(lines)):
                line = lines[i]
                if line.strip():  # 非空行
                    current_indent = len(line) - len(line.lstrip())
                    if current_indent <= indent_level and not line.strip().startswith('#'):
                        end_line = i - 1
                        break
            
            if end_line is None:
                end_line = len(lines) - 1
        
        return start_line, end_line
    
    def _create_context_window_around_line(self, center_line: int, lines: List[str],
                                         reason: str, relevance: float) -> Optional[ContextWindow]:
        """在指定行周围创建上下文窗口"""
        if center_line < 0 or center_line >= len(lines):
            return None
        
        window_size = 3  # 上下各3行
        start_line = max(0, center_line - window_size)
        end_line = min(len(lines) - 1, center_line + window_size)
        
        content = '\n'.join(lines[start_line:end_line + 1])
        
        return ContextWindow(
            center_line=center_line,
            start_line=start_line,
            end_line=end_line,
            content=content,
            relevance_score=relevance,
            expansion_reason=reason
        )
    
    def _deduplicate_windows(self, windows: List[ContextWindow]) -> List[ContextWindow]:
        """去重和合并重叠的窗口"""
        if not windows:
            return []
        
        # 分离重要窗口和普通窗口
        important_reasons = ["original_context", "function_boundary"]
        important_windows = [w for w in windows if w.expansion_reason in important_reasons]
        other_windows = [w for w in windows if w.expansion_reason not in important_reasons]
        
        # 对普通窗口进行去重合并
        if other_windows:
            sorted_windows = sorted(other_windows, key=lambda w: w.start_line)
            
            merged_windows = []
            current_window = sorted_windows[0]
            
            for next_window in sorted_windows[1:]:
                if current_window.overlaps_with(next_window):
                    # 合并重叠的窗口
                    current_window = current_window.merge_with(next_window)
                else:
                    merged_windows.append(current_window)
                    current_window = next_window
            
            merged_windows.append(current_window)
            
            # 过滤低相关性的窗口
            filtered_other_windows = [w for w in merged_windows 
                                    if w.relevance_score >= self.min_relevance_threshold]
        else:
            filtered_other_windows = []
        
        # 合并重要窗口和过滤后的普通窗口
        all_windows = important_windows + filtered_other_windows
        
        # 按起始行排序返回
        return sorted(all_windows, key=lambda w: w.start_line)
    
    async def _analyze_semantic_relations(self, vulnerability: VulnerabilityResult,
                                        source_file: SourceFile,
                                        context_windows: List[ContextWindow]) -> List[SemanticRelation]:
        """分析语义关系"""
        relations = []
        
        # 提取所有窗口中的实体
        all_entities = set()
        for window in context_windows:
            entities = self._extract_variables_from_snippet(window.content)
            all_entities.update(entities)
        
        # 分析实体间的关系
        for window in context_windows:
            window_relations = self._extract_relations_from_window(window, all_entities)
            relations.extend(window_relations)
        
        # 去重和过滤
        unique_relations = self._deduplicate_relations(relations)
        
        return unique_relations[:20]  # 限制数量
    
    def _extract_relations_from_window(self, window: ContextWindow, 
                                     all_entities: Set[str]) -> List[SemanticRelation]:
        """从窗口中提取关系"""
        relations = []
        
        for pattern_type, patterns in self.semantic_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, window.content, re.MULTILINE)
                for match in matches:
                    relation = self._create_relation_from_match(
                        match, pattern_type, window, all_entities
                    )
                    if relation:
                        relations.append(relation)
        
        return relations
    
    def _create_relation_from_match(self, match, pattern_type: str, 
                                  window: ContextWindow, all_entities: Set[str]) -> Optional[SemanticRelation]:
        """从正则匹配创建关系"""
        try:
            if pattern_type == 'variable_assignment' and match.lastindex >= 2:
                source = match.group(1).strip()
                target = match.group(2).strip()
                
                if source in all_entities:
                    return SemanticRelation(
                        source_entity=source,
                        target_entity=target,
                        relation_type="variable_assignment",
                        strength=0.8,
                        context=match.group(0)
                    )
            
            elif pattern_type == 'function_call' and match.lastindex >= 1:
                func_name = match.group(1).strip()
                
                if func_name in all_entities:
                    return SemanticRelation(
                        source_entity="caller",
                        target_entity=func_name,
                        relation_type="function_call",
                        strength=0.7,
                        context=match.group(0)
                    )
            
            elif pattern_type == 'data_dependency' and match.lastindex >= 2:
                source = match.group(1).strip()
                target = match.group(2).strip()
                
                if source in all_entities and target in all_entities:
                    return SemanticRelation(
                        source_entity=source,
                        target_entity=target,
                        relation_type="data_dependency",
                        strength=0.6,
                        context=match.group(0)
                    )
        
        except Exception as e:
            logger.debug(f"创建关系失败: {e}")
        
        return None
    
    def _deduplicate_relations(self, relations: List[SemanticRelation]) -> List[SemanticRelation]:
        """去重关系"""
        seen = set()
        unique_relations = []
        
        for relation in relations:
            key = (relation.source_entity, relation.target_entity, relation.relation_type)
            if key not in seen:
                seen.add(key)
                unique_relations.append(relation)
        
        return unique_relations
    
    def _generate_expanded_content(self, context_windows: List[ContextWindow]) -> str:
        """生成扩展内容"""
        if not context_windows:
            return ""
        
        # 按行号排序窗口
        sorted_windows = sorted(context_windows, key=lambda w: w.start_line)
        
        # 合并内容，避免重复
        content_parts = []
        last_end_line = -1
        
        for window in sorted_windows:
            if window.start_line > last_end_line:
                content_parts.append(f"\n# --- {window.expansion_reason} ---\n")
                content_parts.append(window.content)
                last_end_line = window.end_line
        
        return '\n'.join(content_parts)
    
    def _calculate_completeness_score(self, context_windows: List[ContextWindow],
                                    semantic_relations: List[SemanticRelation]) -> float:
        """计算完整性评分"""
        base_score = 0.3  # 基础分数
        
        # 窗口数量贡献
        window_score = min(0.4, len(context_windows) * 0.05)
        
        # 关系数量贡献
        relation_score = min(0.2, len(semantic_relations) * 0.02)
        
        # 窗口质量贡献
        if context_windows:
            avg_relevance = sum(w.relevance_score for w in context_windows) / len(context_windows)
            quality_score = avg_relevance * 0.1
        else:
            quality_score = 0.0
        
        total_score = base_score + window_score + relation_score + quality_score
        return min(1.0, total_score)
    
    def _create_fallback_context(self, vulnerability: VulnerabilityResult,
                                source_file: SourceFile) -> ExpandedContext:
        """创建回退上下文"""
        logger.warning("使用回退上下文")
        
        original_context = self._get_original_context(vulnerability, source_file)
        fallback_window = self._create_original_window(vulnerability, source_file)
        
        return ExpandedContext(
            original_context=original_context,
            expanded_content=original_context,
            context_windows=[fallback_window],
            semantic_relations=[],
            completeness_score=0.3,
            expansion_metadata={'fallback': True}
        )
    
    def create_semantic_context(self, expanded_context: ExpandedContext) -> SemanticContext:
        """创建语义上下文对象"""
        # 提取相关代码块
        related_code_blocks = [window.content for window in expanded_context.context_windows]
        
        # 计算语义相似度分数
        semantic_similarity_scores = {}
        for window in expanded_context.context_windows:
            semantic_similarity_scores[f"window_{window.center_line}"] = window.relevance_score
        
        return SemanticContext(
            related_code_blocks=related_code_blocks,
            semantic_similarity_scores=semantic_similarity_scores,
            context_window_size=len(expanded_context.expanded_content),
            expanded_context=expanded_context.expanded_content
        )
    
    async def expand_dynamic_context(self, vulnerability: VulnerabilityResult,
                                   source_file: SourceFile,
                                   global_context: Dict[str, Any]) -> SemanticContext:
        """动态扩展上下文（主要接口方法）"""
        logger.info(f"开始动态上下文扩展: {vulnerability.id}")
        
        try:
            # 扩展上下文
            expanded_context = await self.expand_context(vulnerability, source_file)
            
            # 创建语义上下文对象
            semantic_context = self.create_semantic_context(expanded_context)
            
            logger.info(f"动态上下文扩展完成，相关代码块数: {len(semantic_context.related_code_blocks)}")
            return semantic_context
            
        except Exception as e:
            logger.error(f"动态上下文扩展失败: {e}")
            # 返回基础语义上下文
            return SemanticContext(
                related_code_blocks=[vulnerability.snippet or ""],
                semantic_similarity_scores={"original": 1.0},
                context_window_size=len(vulnerability.snippet or ""),
                expanded_context=vulnerability.snippet or ""
            )