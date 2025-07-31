"""
假阳性过滤器 - Self-RAG验证层组件

本模块实现了基于历史模式的假阳性检测算法，用于减少误报。
包括：
- 基于历史模式的假阳性检测
- 自适应学习和过滤规则更新
- 多维度假阳性分析
- 动态阈值调整
"""

import asyncio
import re
import json
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import time
from datetime import datetime, timedelta
import hashlib
import statistics

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import VulnerabilityResult
from auditluma.models.hierarchical_rag import EnhancedContext, VulnerabilityKnowledge


class FilterReason(str, Enum):
    """过滤原因枚举"""
    TEST_FILE = "test_file"
    EXAMPLE_CODE = "example_code"
    COMMENT_CODE = "comment_code"
    DOCUMENTATION = "documentation"
    PLACEHOLDER_CONTENT = "placeholder_content"
    LOW_IMPACT = "low_impact"
    PROTECTED_CONTEXT = "protected_context"
    HISTORICAL_PATTERN = "historical_pattern"
    CONFIDENCE_THRESHOLD = "confidence_threshold"
    SEMANTIC_MISMATCH = "semantic_mismatch"


@dataclass
class FalsePositivePattern:
    """假阳性模式"""
    pattern_id: str
    vulnerability_type: str
    code_pattern: str
    description: str
    confidence: float
    created_at: datetime
    usage_count: int = 0
    success_rate: float = 0.0  # 过滤成功率
    last_used: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        try:
            return {
                'pattern_id': str(self.pattern_id) if self.pattern_id else '',
                'vulnerability_type': str(self.vulnerability_type) if self.vulnerability_type else '',
                'code_pattern': str(self.code_pattern) if self.code_pattern else '',
                'description': str(self.description) if self.description else '',
                'confidence': float(self.confidence) if self.confidence is not None else 0.0,
                'created_at': self.created_at.isoformat() if self.created_at else datetime.now().isoformat(),
                'usage_count': int(self.usage_count) if self.usage_count is not None else 0,
                'success_rate': float(self.success_rate) if self.success_rate is not None else 0.0,
                'last_used': self.last_used.isoformat() if self.last_used else None,
                'metadata': dict(self.metadata) if self.metadata else {}
            }
        except Exception as e:
            logger.error(f"序列化模式失败: {e}")
            # 返回最小化的安全字典
            return {
                'pattern_id': str(getattr(self, 'pattern_id', 'unknown')),
                'vulnerability_type': str(getattr(self, 'vulnerability_type', 'unknown')),
                'code_pattern': str(getattr(self, 'code_pattern', '')),
                'description': str(getattr(self, 'description', '')),
                'confidence': 0.0,
                'created_at': datetime.now().isoformat(),
                'usage_count': 0,
                'success_rate': 0.0,
                'last_used': None,
                'metadata': {},
                'serialization_error': str(e)
            }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FalsePositivePattern':
        """从字典反序列化"""
        return cls(
            pattern_id=data['pattern_id'],
            vulnerability_type=data['vulnerability_type'],
            code_pattern=data['code_pattern'],
            description=data['description'],
            confidence=data['confidence'],
            created_at=datetime.fromisoformat(data['created_at']),
            usage_count=data.get('usage_count', 0),
            success_rate=data.get('success_rate', 0.0),
            last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None,
            metadata=data.get('metadata', {})
        )


@dataclass
class FilterResult:
    """过滤结果"""
    is_false_positive: bool
    filter_reason: Optional[FilterReason]
    confidence: float
    explanation: str
    matched_patterns: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'is_false_positive': self.is_false_positive,
            'filter_reason': self.filter_reason.value if self.filter_reason else None,
            'confidence': self.confidence,
            'explanation': self.explanation,
            'matched_patterns': self.matched_patterns,
            'evidence': self.evidence
        }


class RuleBasedFilter:
    """基于规则的假阳性过滤器"""
    
    def __init__(self):
        """初始化规则过滤器"""
        self.rules = self._initialize_rules()
        self.rule_stats = {rule_name: {'applied': 0, 'filtered': 0} for rule_name in self.rules.keys()}
    
    def _initialize_rules(self) -> Dict[str, Dict[str, Any]]:
        """初始化过滤规则"""
        return {
            'test_file_rule': {
                'patterns': [
                    r'test[s]?[/\\]',
                    r'[/\\]test[s]?[/\\]',
                    r'\.test\.',
                    r'_test\.',
                    r'spec[s]?[/\\]',
                    r'[/\\]spec[s]?[/\\]',
                    r'\.spec\.',
                    r'_spec\.',
                    r'mock[s]?[/\\]',
                    r'fixture[s]?[/\\]'
                ],
                'confidence': 0.9,
                'reason': FilterReason.TEST_FILE
            },
            'example_code_rule': {
                'patterns': [
                    r'example[s]?[/\\]',
                    r'[/\\]example[s]?[/\\]',
                    r'demo[s]?[/\\]',
                    r'[/\\]demo[s]?[/\\]',
                    r'sample[s]?[/\\]',
                    r'tutorial[s]?[/\\]',
                    r'playground[/\\]',
                    r'\.example\.',
                    r'_example\.',
                    r'\.demo\.',
                    r'_demo\.'
                ],
                'confidence': 0.85,
                'reason': FilterReason.EXAMPLE_CODE
            },
            'comment_rule': {
                'patterns': [
                    r'^\s*//.*',
                    r'^\s*#.*',
                    r'^\s*/\*.*\*/',
                    r'^\s*<!--.*-->',
                    r'^\s*\*.*',
                    r'^\s*""".*"""',
                    r"^\s*'''.*'''"
                ],
                'confidence': 0.95,
                'reason': FilterReason.COMMENT_CODE
            },
            'documentation_rule': {
                'patterns': [
                    r'doc[s]?[/\\]',
                    r'[/\\]doc[s]?[/\\]',
                    r'readme',
                    r'\.md$',
                    r'\.rst$',
                    r'\.txt$',
                    r'changelog',
                    r'license'
                ],
                'confidence': 0.8,
                'reason': FilterReason.DOCUMENTATION
            },
            'placeholder_rule': {
                'patterns': [
                    r'<placeholder>',
                    r'\{\{.*\}\}',
                    r'\$\{.*\}',
                    r'example\.com',
                    r'localhost',
                    r'127\.0\.0\.1',
                    r'TODO',
                    r'FIXME',
                    r'XXX'
                ],
                'confidence': 0.75,
                'reason': FilterReason.PLACEHOLDER_CONTENT
            }
        }
    
    def apply_rules(self, vulnerability: VulnerabilityResult) -> Optional[FilterResult]:
        """应用规则过滤"""
        file_path = vulnerability.file_path.lower()
        snippet = vulnerability.snippet
        
        for rule_name, rule_config in self.rules.items():
            self.rule_stats[rule_name]['applied'] += 1
            
            patterns = rule_config['patterns']
            confidence = rule_config['confidence']
            reason = rule_config['reason']
            
            matched_patterns = []
            
            # 检查文件路径模式
            for pattern in patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    matched_patterns.append(pattern)
                elif re.search(pattern, snippet, re.IGNORECASE | re.MULTILINE):
                    matched_patterns.append(pattern)
            
            if matched_patterns:
                self.rule_stats[rule_name]['filtered'] += 1
                
                return FilterResult(
                    is_false_positive=True,
                    filter_reason=reason,
                    confidence=confidence,
                    explanation=f"匹配规则 {rule_name}: {', '.join(matched_patterns[:3])}",
                    matched_patterns=matched_patterns,
                    evidence={
                        'rule_name': rule_name,
                        'matched_count': len(matched_patterns),
                        'file_path': file_path
                    }
                )
        
        return None
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """获取规则统计信息"""
        stats = {}
        for rule_name, rule_stat in self.rule_stats.items():
            applied = rule_stat['applied']
            filtered = rule_stat['filtered']
            stats[rule_name] = {
                'applied': applied,
                'filtered': filtered,
                'filter_rate': filtered / applied if applied > 0 else 0.0
            }
        
        return stats


class ContextBasedFilter:
    """基于上下文的假阳性过滤器"""
    
    def __init__(self):
        """初始化上下文过滤器"""
        self.impact_threshold = 0.3  # 影响分数阈值
        self.protection_indicators = [
            'validate', 'sanitize', 'escape', 'filter', 'check', 'verify',
            'authenticate', 'authorize', 'permission', 'csrf', 'xss_clean',
            'sql_escape', 'prepared_statement', 'parameterized_query'
        ]
    
    def apply_context_filter(self, 
                           vulnerability: VulnerabilityResult,
                           enhanced_context: Optional[EnhancedContext]) -> Optional[FilterResult]:
        """应用上下文过滤"""
        if not enhanced_context:
            return None
        
        evidence = {}
        
        # 1. 检查影响范围
        impact_result = self._check_impact_scope(enhanced_context.impact_scope, evidence)
        if impact_result:
            return impact_result
        
        # 2. 检查保护措施
        protection_result = self._check_protection_measures(
            vulnerability, enhanced_context, evidence
        )
        if protection_result:
            return protection_result
        
        # 3. 检查语义一致性
        semantic_result = self._check_semantic_consistency(
            vulnerability, enhanced_context, evidence
        )
        if semantic_result:
            return semantic_result
        
        return None
    
    def _check_impact_scope(self, impact_scope, evidence: Dict[str, Any]) -> Optional[FilterResult]:
        """检查影响范围"""
        if not impact_scope:
            return None
        
        impact_score = impact_scope.impact_score
        affected_functions = len(impact_scope.affected_functions)
        affected_files = len(impact_scope.affected_files)
        
        evidence.update({
            'impact_score': impact_score,
            'affected_functions': affected_functions,
            'affected_files': affected_files
        })
        
        # 如果影响范围很小且风险级别低，可能是假阳性
        if (impact_score < self.impact_threshold and 
            affected_functions <= 1 and 
            impact_scope.criticality_level == "low"):
            
            return FilterResult(
                is_false_positive=True,
                filter_reason=FilterReason.LOW_IMPACT,
                confidence=0.7,
                explanation=f"影响范围极小: 影响分数{impact_score:.2f}, 影响函数{affected_functions}个",
                evidence=evidence
            )
        
        return None
    
    def _check_protection_measures(self, 
                                 vulnerability: VulnerabilityResult,
                                 enhanced_context: EnhancedContext,
                                 evidence: Dict[str, Any]) -> Optional[FilterResult]:
        """检查保护措施"""
        # 检查代码片段中的保护措施
        snippet_lower = vulnerability.snippet.lower()
        protection_count = sum(
            1 for indicator in self.protection_indicators 
            if indicator in snippet_lower
        )
        
        # 检查相关代码块中的保护措施
        related_protection_count = 0
        if enhanced_context.semantic_context.related_code_blocks:
            for block in enhanced_context.semantic_context.related_code_blocks:
                block_lower = block.lower()
                related_protection_count += sum(
                    1 for indicator in self.protection_indicators 
                    if indicator in block_lower
                )
        
        total_protection = protection_count + related_protection_count
        evidence.update({
            'snippet_protection_count': protection_count,
            'related_protection_count': related_protection_count,
            'total_protection_measures': total_protection
        })
        
        # 如果检测到多种保护措施，可能是假阳性
        if total_protection >= 3:
            return FilterResult(
                is_false_positive=True,
                filter_reason=FilterReason.PROTECTED_CONTEXT,
                confidence=0.6 + min(0.3, total_protection * 0.1),
                explanation=f"检测到{total_protection}种安全保护措施",
                evidence=evidence
            )
        
        return None
    
    def _check_semantic_consistency(self, 
                                  vulnerability: VulnerabilityResult,
                                  enhanced_context: EnhancedContext,
                                  evidence: Dict[str, Any]) -> Optional[FilterResult]:
        """检查语义一致性"""
        semantic_context = enhanced_context.semantic_context
        
        if not semantic_context.semantic_similarity_scores:
            return None
        
        # 计算平均语义相似度
        avg_similarity = sum(semantic_context.semantic_similarity_scores.values()) / len(semantic_context.semantic_similarity_scores)
        
        # 检查上下文窗口大小
        context_window_size = semantic_context.context_window_size
        
        evidence.update({
            'avg_semantic_similarity': avg_similarity,
            'context_window_size': context_window_size,
            'similarity_scores_count': len(semantic_context.semantic_similarity_scores)
        })
        
        # 如果语义相似度很低，可能是假阳性
        if avg_similarity < 0.3 and context_window_size > 0:
            return FilterResult(
                is_false_positive=True,
                filter_reason=FilterReason.SEMANTIC_MISMATCH,
                confidence=0.5 + (0.3 - avg_similarity),
                explanation=f"语义相似度过低: {avg_similarity:.2f}",
                evidence=evidence
            )
        
        return None


class PatternLearningFilter:
    """基于模式学习的假阳性过滤器"""
    
    def __init__(self):
        """初始化模式学习过滤器"""
        self.patterns: List[FalsePositivePattern] = []
        self.pattern_index: Dict[str, List[FalsePositivePattern]] = {}
        self.learning_threshold = 0.6  # 学习阈值
        self.pattern_expiry_days = 90  # 模式过期天数
        
        # 加载预定义模式
        self._load_predefined_patterns()
    
    def _load_predefined_patterns(self):
        """加载预定义的假阳性模式"""
        predefined_patterns = [
            FalsePositivePattern(
                pattern_id="test_sql_1",
                vulnerability_type="sql injection",
                code_pattern=r"test.*sql.*query",
                description="测试代码中的SQL查询",
                confidence=0.8,
                created_at=datetime.now(),
                metadata={'source': 'predefined', 'category': 'test'}
            ),
            FalsePositivePattern(
                pattern_id="example_xss_1",
                vulnerability_type="xss",
                code_pattern=r"example.*script.*tag",
                description="示例代码中的脚本标签",
                confidence=0.7,
                created_at=datetime.now(),
                metadata={'source': 'predefined', 'category': 'example'}
            ),
            FalsePositivePattern(
                pattern_id="comment_cmd_1",
                vulnerability_type="command injection",
                code_pattern=r"//.*system.*call",
                description="注释中的系统调用",
                confidence=0.9,
                created_at=datetime.now(),
                metadata={'source': 'predefined', 'category': 'comment'}
            ),
            FalsePositivePattern(
                pattern_id="doc_path_1",
                vulnerability_type="path traversal",
                code_pattern=r"documentation.*\.\./",
                description="文档中的路径遍历示例",
                confidence=0.75,
                created_at=datetime.now(),
                metadata={'source': 'predefined', 'category': 'documentation'}
            )
        ]
        
        for pattern in predefined_patterns:
            self.add_pattern(pattern)
    
    def add_pattern(self, pattern: FalsePositivePattern):
        """添加假阳性模式"""
        self.patterns.append(pattern)
        
        # 更新索引
        vuln_type = pattern.vulnerability_type.lower()
        if vuln_type not in self.pattern_index:
            self.pattern_index[vuln_type] = []
        self.pattern_index[vuln_type].append(pattern)
        
        logger.debug(f"添加假阳性模式: {pattern.pattern_id}")
    
    def match_patterns(self, vulnerability: VulnerabilityResult) -> Optional[FilterResult]:
        """匹配假阳性模式"""
        vuln_type = vulnerability.vulnerability_type.lower()
        
        # 获取相关模式
        relevant_patterns = []
        for pattern_type in self.pattern_index:
            if pattern_type in vuln_type or any(word in vuln_type for word in pattern_type.split()):
                relevant_patterns.extend(self.pattern_index[pattern_type])
        
        if not relevant_patterns:
            return None
        
        # 检查模式匹配
        best_match = None
        best_confidence = 0.0
        matched_patterns = []
        
        for pattern in relevant_patterns:
            if self._is_pattern_expired(pattern):
                continue
            
            match_confidence = self._calculate_pattern_match(vulnerability, pattern)
            if match_confidence > self.learning_threshold:
                matched_patterns.append(pattern.pattern_id)
                
                if match_confidence > best_confidence:
                    best_confidence = match_confidence
                    best_match = pattern
        
        if best_match:
            # 更新模式使用统计
            best_match.usage_count += 1
            best_match.last_used = datetime.now()
            
            return FilterResult(
                is_false_positive=True,
                filter_reason=FilterReason.HISTORICAL_PATTERN,
                confidence=best_confidence,
                explanation=f"匹配历史模式: {best_match.description}",
                matched_patterns=matched_patterns,
                evidence={
                    'matched_pattern_id': best_match.pattern_id,
                    'pattern_confidence': best_match.confidence,
                    'match_confidence': best_confidence,
                    'pattern_usage_count': best_match.usage_count
                }
            )
        
        return None
    
    def _calculate_pattern_match(self, 
                               vulnerability: VulnerabilityResult,
                               pattern: FalsePositivePattern) -> float:
        """计算模式匹配度"""
        try:
            # 检查代码模式匹配
            code_match = bool(re.search(pattern.code_pattern, vulnerability.snippet, re.IGNORECASE))
            if not code_match:
                code_match = bool(re.search(pattern.code_pattern, vulnerability.file_path, re.IGNORECASE))
            
            if not code_match:
                return 0.0
            
            # 基础匹配分数
            match_score = pattern.confidence
            
            # 考虑模式的成功率
            if pattern.usage_count > 0:
                success_rate_bonus = pattern.success_rate * 0.2
                match_score += success_rate_bonus
            
            # 考虑模式的新鲜度
            days_since_created = (datetime.now() - pattern.created_at).days
            if days_since_created < 30:
                freshness_bonus = 0.1
                match_score += freshness_bonus
            
            return min(1.0, match_score)
            
        except re.error as e:
            logger.warning(f"无效的正则表达式模式: {pattern.code_pattern}, {e}")
            return 0.0
    
    def _is_pattern_expired(self, pattern: FalsePositivePattern) -> bool:
        """检查模式是否过期"""
        days_since_created = (datetime.now() - pattern.created_at).days
        return days_since_created > self.pattern_expiry_days
    
    async def learn_from_feedback(self, 
                                vulnerability: VulnerabilityResult,
                                is_false_positive: bool,
                                feedback: str,
                                confidence: float = 0.6):
        """从反馈中学习新模式"""
        if not is_false_positive:
            return
        
        # 生成新的模式ID
        pattern_id = f"learned_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(vulnerability.id) % 10000}"
        
        # 提取代码模式
        code_pattern = self._extract_code_pattern(vulnerability.snippet)
        
        # 创建新模式
        new_pattern = FalsePositivePattern(
            pattern_id=pattern_id,
            vulnerability_type=vulnerability.vulnerability_type,
            code_pattern=code_pattern,
            description=f"从反馈学习: {feedback}",
            confidence=confidence,
            created_at=datetime.now(),
            metadata={
                'source': 'learned',
                'feedback': feedback,
                'original_vulnerability_id': vulnerability.id,
                'file_path': vulnerability.file_path
            }
        )
        
        self.add_pattern(new_pattern)
        logger.info(f"学习新的假阳性模式: {pattern_id}")
    
    def _extract_code_pattern(self, code_snippet: str) -> str:
        """从代码片段提取模式"""
        # 简化的模式提取逻辑
        pattern = code_snippet
        
        # 替换字符串字面量
        pattern = re.sub(r'"[^"]*"', '".*?"', pattern)
        pattern = re.sub(r"'[^']*'", "'.*?'", pattern)
        
        # 替换数字
        pattern = re.sub(r'\b\d+\b', r'\\d+', pattern)
        
        # 替换变量名（保留关键字）
        keywords = {'if', 'else', 'for', 'while', 'def', 'class', 'return', 'import', 'function', 'var', 'let', 'const'}
        words = re.findall(r'\b\w+\b', pattern)
        for word in set(words):
            if word.lower() not in keywords and not word.isupper():
                pattern = re.sub(rf'\b{re.escape(word)}\b', r'\\w+', pattern)
        
        # 转义特殊字符
        special_chars = r'()[]{}+*?^$|.'
        for char in special_chars:
            if char in pattern and not pattern.count('\\' + char):
                pattern = pattern.replace(char, '\\' + char)
        
        # 限制长度
        if len(pattern) > 200:
            pattern = pattern[:200] + '.*'
        
        return pattern
    
    def update_pattern_success_rate(self, pattern_id: str, success: bool):
        """更新模式成功率"""
        for pattern in self.patterns:
            if pattern.pattern_id == pattern_id:
                # 使用移动平均更新成功率
                if pattern.usage_count == 1:
                    pattern.success_rate = 1.0 if success else 0.0
                else:
                    alpha = 0.1  # 学习率
                    new_rate = 1.0 if success else 0.0
                    pattern.success_rate = (1 - alpha) * pattern.success_rate + alpha * new_rate
                break
    
    def cleanup_expired_patterns(self):
        """清理过期模式"""
        before_count = len(self.patterns)
        
        # 移除过期模式
        self.patterns = [p for p in self.patterns if not self._is_pattern_expired(p)]
        
        # 重建索引
        self.pattern_index.clear()
        for pattern in self.patterns:
            vuln_type = pattern.vulnerability_type.lower()
            if vuln_type not in self.pattern_index:
                self.pattern_index[vuln_type] = []
            self.pattern_index[vuln_type].append(pattern)
        
        after_count = len(self.patterns)
        if before_count != after_count:
            logger.info(f"清理过期模式: {before_count - after_count}个")
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """获取模式统计信息"""
        try:
            total_patterns = len(self.patterns) if self.patterns else 0
            active_patterns = len([p for p in self.patterns if p.usage_count > 0]) if self.patterns else 0
            
            # 按类型分布
            type_distribution = {}
            if self.patterns:
                for pattern in self.patterns:
                    try:
                        vuln_type = pattern.vulnerability_type or 'unknown'
                        type_distribution[vuln_type] = type_distribution.get(vuln_type, 0) + 1
                    except Exception as e:
                        logger.warning(f"处理模式类型分布时出错: {e}")
            
            # 按来源分布
            source_distribution = {}
            if self.patterns:
                for pattern in self.patterns:
                    try:
                        source = pattern.metadata.get('source', 'unknown') if pattern.metadata else 'unknown'
                        source_distribution[source] = source_distribution.get(source, 0) + 1
                    except Exception as e:
                        logger.warning(f"处理模式来源分布时出错: {e}")
            
            # 最常用模式
            most_used_pattern = None
            most_used_pattern_id = None
            if self.patterns:
                try:
                    most_used_pattern = max(self.patterns, key=lambda p: p.usage_count, default=None)
                    most_used_pattern_id = most_used_pattern.pattern_id if most_used_pattern else None
                except Exception as e:
                    logger.warning(f"获取最常用模式时出错: {e}")
            
            # 计算平均成功率
            average_success_rate = 0.0
            if self.patterns and total_patterns > 0:
                try:
                    success_rates = [p.success_rate for p in self.patterns if hasattr(p, 'success_rate') and p.success_rate is not None]
                    average_success_rate = sum(success_rates) / len(success_rates) if success_rates else 0.0
                except Exception as e:
                    logger.warning(f"计算平均成功率时出错: {e}")
            
            return {
                'total_patterns': total_patterns,
                'active_patterns': active_patterns,
                'type_distribution': type_distribution,
                'source_distribution': source_distribution,
                'most_used_pattern': most_used_pattern_id,
                'average_success_rate': average_success_rate
            }
            
        except Exception as e:
            logger.error(f"获取模式统计信息失败: {e}")
            return {
                'total_patterns': 0,
                'active_patterns': 0,
                'type_distribution': {},
                'source_distribution': {},
                'most_used_pattern': None,
                'average_success_rate': 0.0,
                'error': str(e)
            }


class FalsePositiveFilter:
    """假阳性过滤器 - 综合多种过滤策略"""
    
    def __init__(self):
        """初始化假阳性过滤器"""
        # 初始化子过滤器
        self.rule_based_filter = RuleBasedFilter()
        self.context_based_filter = ContextBasedFilter()
        self.pattern_learning_filter = PatternLearningFilter()
        
        # 配置参数
        hierarchical_config = getattr(Config, 'hierarchical_rag', None)
        
        # 使用默认配置值
        self.confidence_threshold = 0.7
        self.enable_learning = True
        self.max_concurrent_filters = 5
        
        # 如果有层级RAG配置，尝试获取假阳性过滤配置
        if hierarchical_config and hasattr(hierarchical_config, 'self_rag_validation'):
            # 这里可以扩展为从配置中读取过滤配置
            # 目前使用默认配置
            pass
        
        # 性能统计
        self.stats = {
            'total_checks': 0,
            'false_positives_detected': 0,
            'filter_breakdown': {
                'rule_based': 0,
                'context_based': 0,
                'pattern_learning': 0
            },
            'average_processing_time': 0.0,
            'learning_events': 0
        }
        
        logger.info(f"假阳性过滤器初始化完成")
        logger.info(f"置信度阈值: {self.confidence_threshold}, 学习功能: {'启用' if self.enable_learning else '禁用'}")
    
    async def check_false_positive(self, 
                                 vulnerability: VulnerabilityResult,
                                 enhanced_context: Optional[EnhancedContext] = None,
                                 knowledge: Optional[VulnerabilityKnowledge] = None) -> FilterResult:
        """检查是否为假阳性"""
        start_time = time.time()
        
        try:
            logger.debug(f"检查假阳性: {vulnerability.id}")
            
            # 并行执行多种过滤策略
            filter_tasks = [
                self._apply_rule_based_filter(vulnerability),
                self._apply_context_based_filter(vulnerability, enhanced_context),
                self._apply_pattern_learning_filter(vulnerability)
            ]
            
            # 使用信号量限制并发
            semaphore = asyncio.Semaphore(self.max_concurrent_filters)
            
            async def bounded_filter(task):
                async with semaphore:
                    return await task
            
            results = await asyncio.gather(
                *[bounded_filter(task) for task in filter_tasks],
                return_exceptions=True
            )
            
            # 处理结果
            filter_results = []
            for i, result in enumerate(results):
                if isinstance(result, FilterResult):
                    filter_results.append(result)
                elif result is not None and not isinstance(result, Exception):
                    logger.warning(f"过滤器 {i} 返回了意外结果: {result}")
                elif isinstance(result, Exception):
                    logger.error(f"过滤器 {i} 执行异常: {result}")
            
            # 综合判断
            final_result = self._combine_filter_results(filter_results, vulnerability.id)
            
            # 更新统计信息
            processing_time = time.time() - start_time
            self._update_stats(final_result, processing_time)
            
            logger.debug(f"假阳性检查完成: {vulnerability.id}, 结果: {final_result.is_false_positive}")
            
            return final_result
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"假阳性检查失败: {vulnerability.id}, {e}")
            
            # 返回默认结果（不过滤）
            return FilterResult(
                is_false_positive=False,
                filter_reason=None,
                confidence=0.0,
                explanation=f"过滤检查失败: {str(e)}",
                evidence={'error': str(e), 'processing_time': processing_time}
            )
    
    async def _apply_rule_based_filter(self, vulnerability: VulnerabilityResult) -> Optional[FilterResult]:
        """应用基于规则的过滤"""
        return self.rule_based_filter.apply_rules(vulnerability)
    
    async def _apply_context_based_filter(self, 
                                        vulnerability: VulnerabilityResult,
                                        enhanced_context: Optional[EnhancedContext]) -> Optional[FilterResult]:
        """应用基于上下文的过滤"""
        return self.context_based_filter.apply_context_filter(vulnerability, enhanced_context)
    
    async def _apply_pattern_learning_filter(self, vulnerability: VulnerabilityResult) -> Optional[FilterResult]:
        """应用基于模式学习的过滤"""
        return self.pattern_learning_filter.match_patterns(vulnerability)
    
    def _combine_filter_results(self, 
                              filter_results: List[FilterResult],
                              vulnerability_id: str) -> FilterResult:
        """综合多个过滤结果"""
        if not filter_results:
            return FilterResult(
                is_false_positive=False,
                filter_reason=None,
                confidence=0.0,
                explanation="没有过滤器检测到假阳性",
                evidence={'filters_applied': 0}
            )
        
        # 找到置信度最高的假阳性结果
        positive_results = [r for r in filter_results if r.is_false_positive]
        
        if not positive_results:
            return FilterResult(
                is_false_positive=False,
                filter_reason=None,
                confidence=0.0,
                explanation=f"所有过滤器({len(filter_results)})均未检测到假阳性",
                evidence={
                    'filters_applied': len(filter_results),
                    'positive_filters': 0
                }
            )
        
        # 选择置信度最高的结果
        best_result = max(positive_results, key=lambda r: r.confidence)
        
        # 如果置信度低于阈值，不过滤
        if best_result.confidence < self.confidence_threshold:
            return FilterResult(
                is_false_positive=False,
                filter_reason=None,
                confidence=best_result.confidence,
                explanation=f"最高置信度({best_result.confidence:.2f})低于阈值({self.confidence_threshold})",
                evidence={
                    'best_filter_reason': best_result.filter_reason.value if best_result.filter_reason else None,
                    'best_confidence': best_result.confidence,
                    'threshold': self.confidence_threshold,
                    'positive_filters': len(positive_results)
                }
            )
        
        # 综合多个结果的信息
        all_reasons = [r.filter_reason for r in positive_results if r.filter_reason]
        all_patterns = []
        for r in positive_results:
            all_patterns.extend(r.matched_patterns)
        
        combined_explanation = f"检测到假阳性(置信度: {best_result.confidence:.2f}): {best_result.explanation}"
        if len(positive_results) > 1:
            combined_explanation += f" (共{len(positive_results)}个过滤器检测到)"
        
        return FilterResult(
            is_false_positive=True,
            filter_reason=best_result.filter_reason,
            confidence=best_result.confidence,
            explanation=combined_explanation,
            matched_patterns=list(set(all_patterns)),
            evidence={
                'primary_filter': best_result.filter_reason.value if best_result.filter_reason else None,
                'all_filter_reasons': [r.value for r in all_reasons],
                'positive_filters': len(positive_results),
                'total_filters': len(filter_results),
                'confidence_scores': [r.confidence for r in positive_results]
            }
        )
    
    def _update_stats(self, result: FilterResult, processing_time: float):
        """更新统计信息"""
        self.stats['total_checks'] += 1
        
        if result.is_false_positive:
            self.stats['false_positives_detected'] += 1
            
            # 更新过滤器分类统计
            if result.filter_reason:
                if result.filter_reason in [FilterReason.TEST_FILE, FilterReason.EXAMPLE_CODE, 
                                          FilterReason.COMMENT_CODE, FilterReason.DOCUMENTATION, 
                                          FilterReason.PLACEHOLDER_CONTENT]:
                    self.stats['filter_breakdown']['rule_based'] += 1
                elif result.filter_reason in [FilterReason.LOW_IMPACT, FilterReason.PROTECTED_CONTEXT, 
                                            FilterReason.SEMANTIC_MISMATCH]:
                    self.stats['filter_breakdown']['context_based'] += 1
                elif result.filter_reason == FilterReason.HISTORICAL_PATTERN:
                    self.stats['filter_breakdown']['pattern_learning'] += 1
        
        # 更新平均处理时间
        total_checks = self.stats['total_checks']
        current_avg = self.stats['average_processing_time']
        self.stats['average_processing_time'] = (
            (current_avg * (total_checks - 1) + processing_time) / total_checks
        )
    
    async def learn_from_feedback(self, 
                                vulnerability: VulnerabilityResult,
                                is_false_positive: bool,
                                feedback: str,
                                confidence: float = 0.6):
        """从反馈中学习"""
        if not self.enable_learning:
            logger.debug("学习功能已禁用")
            return
        
        try:
            logger.info(f"接收假阳性反馈: {vulnerability.id}, 是否假阳性: {is_false_positive}")
            
            if is_false_positive:
                await self.pattern_learning_filter.learn_from_feedback(
                    vulnerability, is_false_positive, feedback, confidence
                )
                
                self.stats['learning_events'] += 1
                logger.info(f"学习事件完成: {vulnerability.id}")
            
        except Exception as e:
            logger.error(f"学习过程失败: {vulnerability.id}, {e}")
    
    async def batch_check_false_positives(self, 
                                        vulnerabilities: List[VulnerabilityResult],
                                        enhanced_contexts: Optional[List[EnhancedContext]] = None,
                                        knowledge_list: Optional[List[VulnerabilityKnowledge]] = None,
                                        max_concurrency: int = 10) -> List[FilterResult]:
        """批量检查假阳性"""
        logger.info(f"开始批量假阳性检查，漏洞数: {len(vulnerabilities)}")
        
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def check_single(i, vulnerability):
            async with semaphore:
                enhanced_context = enhanced_contexts[i] if enhanced_contexts else None
                knowledge = knowledge_list[i] if knowledge_list else None
                return await self.check_false_positive(vulnerability, enhanced_context, knowledge)
        
        # 并发检查
        tasks = [check_single(i, vuln) for i, vuln in enumerate(vulnerabilities)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量假阳性检查异常: {vulnerabilities[i].id}, {result}")
                final_results.append(FilterResult(
                    is_false_positive=False,
                    filter_reason=None,
                    confidence=0.0,
                    explanation=f"检查异常: {str(result)}",
                    evidence={'batch_error': str(result)}
                ))
            else:
                final_results.append(result)
        
        # 统计结果
        false_positive_count = sum(1 for r in final_results if r.is_false_positive)
        logger.info(f"批量假阳性检查完成，检测到假阳性: {false_positive_count}/{len(vulnerabilities)}")
        
        return final_results
    
    def get_filter_statistics(self) -> Dict[str, Any]:
        """获取过滤器统计信息"""
        base_stats = self.stats.copy()
        
        # 添加子过滤器统计
        base_stats['rule_based_stats'] = self.rule_based_filter.get_rule_statistics()
        base_stats['pattern_learning_stats'] = self.pattern_learning_filter.get_pattern_statistics()
        
        # 计算过滤率
        if base_stats['total_checks'] > 0:
            base_stats['false_positive_rate'] = (
                base_stats['false_positives_detected'] / base_stats['total_checks']
            )
        else:
            base_stats['false_positive_rate'] = 0.0
        
        return base_stats
    
    def update_configuration(self, new_config: Dict[str, Any]):
        """更新配置"""
        if 'confidence_threshold' in new_config:
            self.confidence_threshold = new_config['confidence_threshold']
            logger.info(f"更新置信度阈值: {self.confidence_threshold}")
        
        if 'enable_learning' in new_config:
            self.enable_learning = new_config['enable_learning']
            logger.info(f"学习功能: {'启用' if self.enable_learning else '禁用'}")
        
        if 'max_concurrent_filters' in new_config:
            self.max_concurrent_filters = new_config['max_concurrent_filters']
            logger.info(f"最大并发过滤器数: {self.max_concurrent_filters}")
    
    def cleanup_resources(self):
        """清理资源"""
        logger.info("开始清理假阳性过滤器资源")
        
        # 清理过期模式
        self.pattern_learning_filter.cleanup_expired_patterns()
        
        logger.info("假阳性过滤器资源清理完成")
    
    def export_patterns(self, file_path: str):
        """导出学习到的模式"""
        try:
            if not self.pattern_learning_filter.patterns:
                logger.info("没有模式需要导出")
                return
            
            patterns_data = []
            for pattern in self.pattern_learning_filter.patterns:
                try:
                    pattern_dict = pattern.to_dict()
                    patterns_data.append(pattern_dict)
                except Exception as e:
                    logger.warning(f"序列化模式失败: {pattern.pattern_id if hasattr(pattern, 'pattern_id') else 'unknown'}, {e}")
            
            if not patterns_data:
                logger.warning("没有成功序列化的模式数据")
                return
            
            # 确保目录存在
            import os
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(patterns_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"成功导出 {len(patterns_data)} 个模式到 {file_path}")
            
        except Exception as e:
            logger.error(f"导出模式失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def import_patterns(self, file_path: str):
        """导入模式"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                patterns_data = json.load(f)
            
            imported_count = 0
            for pattern_data in patterns_data:
                try:
                    pattern = FalsePositivePattern.from_dict(pattern_data)
                    self.pattern_learning_filter.add_pattern(pattern)
                    imported_count += 1
                except Exception as e:
                    logger.warning(f"导入模式失败: {pattern_data.get('pattern_id', 'unknown')}, {e}")
            
            logger.info(f"成功导入 {imported_count}/{len(patterns_data)} 个模式")
            
        except Exception as e:
            logger.error(f"导入模式失败: {e}")