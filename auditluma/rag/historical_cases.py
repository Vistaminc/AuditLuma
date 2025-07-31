"""
历史案例检索系统 - 实现相似代码模式的检索和评分算法

本模块提供历史案例检索功能，包括：
- 相似代码模式的检索和评分算法
- 历史案例的学习和更新机制
- 案例数据库管理
- 相似性计算和排序
"""

import asyncio
import json
import aiofiles
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import os
import difflib
import re
from collections import defaultdict
import pickle
import numpy as np

from loguru import logger

from auditluma.models.hierarchical_rag import HistoricalCase
from auditluma.models.code import VulnerabilityResult


@dataclass
class CaseFeatures:
    """案例特征"""
    tokens: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    complexity_score: float = 0.0
    language_features: Dict[str, Any] = field(default_factory=dict)
    
    def to_vector(self) -> List[float]:
        """转换为特征向量"""
        # 简化的特征向量化
        vector = []
        
        # 添加复杂度分数
        vector.append(self.complexity_score)
        
        # 添加token数量
        vector.append(len(self.tokens))
        
        # 添加关键词数量
        vector.append(len(self.keywords))
        
        # 添加模式数量
        vector.append(len(self.patterns))
        
        # 添加语言特征
        vector.append(len(self.language_features))
        
        return vector


class CodeSimilarityCalculator:
    """代码相似性计算器"""
    
    def __init__(self):
        """初始化相似性计算器"""
        self.weights = {
            "token_similarity": 0.3,
            "structure_similarity": 0.25,
            "semantic_similarity": 0.25,
            "pattern_similarity": 0.2
        }
    
    def calculate_similarity(self, code1: str, code2: str, 
                           language: str = "general") -> float:
        """计算两段代码的相似性"""
        try:
            # 标准化代码
            normalized_code1 = self._normalize_code(code1, language)
            normalized_code2 = self._normalize_code(code2, language)
            
            # 计算各种相似性
            token_sim = self._calculate_token_similarity(normalized_code1, normalized_code2)
            structure_sim = self._calculate_structure_similarity(normalized_code1, normalized_code2)
            semantic_sim = self._calculate_semantic_similarity(normalized_code1, normalized_code2)
            pattern_sim = self._calculate_pattern_similarity(normalized_code1, normalized_code2)
            
            # 加权平均
            total_similarity = (
                token_sim * self.weights["token_similarity"] +
                structure_sim * self.weights["structure_similarity"] +
                semantic_sim * self.weights["semantic_similarity"] +
                pattern_sim * self.weights["pattern_similarity"]
            )
            
            return min(max(total_similarity, 0.0), 1.0)
            
        except Exception as e:
            logger.warning(f"相似性计算失败: {e}")
            return 0.0
    
    def _normalize_code(self, code: str, language: str) -> str:
        """标准化代码"""
        # 移除注释
        code = self._remove_comments(code, language)
        
        # 标准化空白字符
        code = re.sub(r'\s+', ' ', code.strip())
        
        # 移除字符串字面量
        code = re.sub(r'["\'].*?["\']', '""', code)
        
        # 移除数字字面量
        code = re.sub(r'\b\d+\b', '0', code)
        
        return code
    
    def _remove_comments(self, code: str, language: str) -> str:
        """移除注释"""
        if language.lower() in ["python", "bash", "shell"]:
            # Python风格注释
            code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        elif language.lower() in ["java", "javascript", "c", "cpp", "csharp", "php"]:
            # C风格注释
            code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        elif language.lower() == "sql":
            # SQL注释
            code = re.sub(r'--.*$', '', code, flags=re.MULTILINE)
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        return code
    
    def _calculate_token_similarity(self, code1: str, code2: str) -> float:
        """计算token相似性"""
        tokens1 = set(re.findall(r'\w+', code1.lower()))
        tokens2 = set(re.findall(r'\w+', code2.lower()))
        
        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)
        
        return len(intersection) / len(union)
    
    def _calculate_structure_similarity(self, code1: str, code2: str) -> float:
        """计算结构相似性"""
        # 提取结构特征（括号、分号等）
        structure1 = re.sub(r'\w+', 'X', code1)
        structure2 = re.sub(r'\w+', 'X', code2)
        
        # 使用序列匹配
        matcher = difflib.SequenceMatcher(None, structure1, structure2)
        return matcher.ratio()
    
    def _calculate_semantic_similarity(self, code1: str, code2: str) -> float:
        """计算语义相似性"""
        # 提取关键词
        keywords1 = self._extract_keywords(code1)
        keywords2 = self._extract_keywords(code2)
        
        if not keywords1 and not keywords2:
            return 1.0
        if not keywords1 or not keywords2:
            return 0.0
        
        # 计算关键词相似性
        common_keywords = set(keywords1).intersection(set(keywords2))
        total_keywords = set(keywords1).union(set(keywords2))
        
        return len(common_keywords) / len(total_keywords)
    
    def _calculate_pattern_similarity(self, code1: str, code2: str) -> float:
        """计算模式相似性"""
        patterns1 = self._extract_patterns(code1)
        patterns2 = self._extract_patterns(code2)
        
        if not patterns1 and not patterns2:
            return 1.0
        if not patterns1 or not patterns2:
            return 0.0
        
        # 计算模式匹配度
        common_patterns = set(patterns1).intersection(set(patterns2))
        total_patterns = set(patterns1).union(set(patterns2))
        
        return len(common_patterns) / len(total_patterns)
    
    def _extract_keywords(self, code: str) -> List[str]:
        """提取代码关键词"""
        # 常见的编程关键词
        programming_keywords = {
            "if", "else", "for", "while", "function", "class", "return",
            "try", "catch", "throw", "import", "from", "def", "var",
            "let", "const", "public", "private", "protected", "static"
        }
        
        # 安全相关关键词
        security_keywords = {
            "password", "token", "auth", "login", "session", "cookie",
            "encrypt", "decrypt", "hash", "sql", "query", "execute",
            "eval", "exec", "system", "shell", "file", "path"
        }
        
        words = re.findall(r'\w+', code.lower())
        keywords = []
        
        for word in words:
            if word in programming_keywords or word in security_keywords:
                keywords.append(word)
        
        return keywords
    
    def _extract_patterns(self, code: str) -> List[str]:
        """提取代码模式"""
        patterns = []
        
        # 函数调用模式
        func_calls = re.findall(r'\w+\s*\(', code)
        patterns.extend([call.strip() for call in func_calls])
        
        # 赋值模式
        assignments = re.findall(r'\w+\s*=', code)
        patterns.extend([assign.strip() for assign in assignments])
        
        # 条件模式
        conditions = re.findall(r'if\s*\(.*?\)', code)
        patterns.extend(conditions)
        
        # 循环模式
        loops = re.findall(r'(for|while)\s*\(.*?\)', code)
        patterns.extend([loop[0] for loop in loops])
        
        return patterns


class HistoricalCasesIndex:
    """历史案例索引 - 核心检索系统"""
    
    def __init__(self):
        """初始化历史案例索引"""
        self.cases: List[HistoricalCase] = []
        self.case_features: Dict[str, CaseFeatures] = {}
        self.similarity_calculator = CodeSimilarityCalculator()
        
        # 数据目录
        self.data_dir = Path("./data/historical_cases")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # 索引文件
        self.index_file = self.data_dir / "cases_index.json"
        self.features_file = self.data_dir / "case_features.pkl"
        
        # 缓存
        self.similarity_cache: Dict[str, float] = {}
        self.max_cache_size = 10000
        
        # 性能指标
        self.metrics = {
            "cases_indexed": 0,
            "queries_processed": 0,
            "cache_hits": 0,
            "similarity_calculations": 0,
            "last_update": None
        }
        
        # 初始化标志
        self._initialized = False
        self._initialization_lock = asyncio.Lock() if self._has_running_loop() else None
        
        # 尝试同步初始化，如果失败则延迟到第一次使用时
        try:
            if self._has_running_loop():
                asyncio.create_task(self._initialize_index())
            else:
                # 没有事件循环时，延迟初始化
                logger.info("没有运行的事件循环，将在首次使用时初始化历史案例索引")
        except Exception as e:
            logger.warning(f"异步初始化失败，将在首次使用时初始化: {e}")
        
        logger.info("历史案例索引初始化完成")
    
    def _has_running_loop(self) -> bool:
        """检查是否有运行的事件循环"""
        try:
            asyncio.get_running_loop()
            return True
        except RuntimeError:
            return False
    
    async def _ensure_initialized(self):
        """确保索引已初始化"""
        if self._initialized:
            return
        
        if self._initialization_lock is None:
            self._initialization_lock = asyncio.Lock()
        
        async with self._initialization_lock:
            if not self._initialized:
                await self._initialize_index()
    
    async def _initialize_index(self):
        """初始化索引"""
        try:
            # 加载现有案例
            await self._load_cases()
            
            # 加载特征
            await self._load_features()
            
            # 如果没有案例，创建一些示例案例
            if not self.cases:
                await self._create_sample_cases()
            
            self.metrics["cases_indexed"] = len(self.cases)
            self.metrics["last_update"] = datetime.now()
            
            logger.info(f"加载了 {len(self.cases)} 个历史案例")
            self._initialized = True
            
        except Exception as e:
            logger.error(f"索引初始化失败: {e}")
            self._initialized = False
    
    async def _load_cases(self):
        """加载历史案例"""
        try:
            if self.index_file.exists():
                async with aiofiles.open(self.index_file, 'r', encoding='utf-8') as f:
                    data = json.loads(await f.read())
                
                self.cases = []
                for case_data in data.get("cases", []):
                    case = HistoricalCase.from_dict(case_data)
                    self.cases.append(case)
                
                logger.info(f"从索引文件加载了 {len(self.cases)} 个案例")
            
        except Exception as e:
            logger.error(f"加载案例失败: {e}")
    
    async def _load_features(self):
        """加载案例特征"""
        try:
            if self.features_file.exists():
                with open(self.features_file, 'rb') as f:
                    self.case_features = pickle.load(f)
                
                logger.info(f"加载了 {len(self.case_features)} 个案例特征")
            
        except Exception as e:
            logger.error(f"加载特征失败: {e}")
    
    async def _create_sample_cases(self):
        """创建示例案例"""
        sample_cases = [
            HistoricalCase(
                id="sample_001",
                title="SQL注入漏洞修复案例",
                description="在用户登录功能中发现SQL注入漏洞",
                code_pattern="""SELECT * FROM users WHERE username = '" + user_input + "' AND password = '" + pass_input + "'""",
                vulnerability_type="sql injection",
                solution="使用参数化查询：SELECT * FROM users WHERE username = ? AND password = ?",
                similarity_score=1.0,
                case_date=datetime.now() - timedelta(days=30),
                source_project="sample_project_1",
                references=["https://example.com/case1"]
            ),
            HistoricalCase(
                id="sample_002",
                title="XSS漏洞修复案例",
                description="在评论功能中发现存储型XSS漏洞",
                code_pattern="document.getElementById('comments').innerHTML = userComment;",
                vulnerability_type="xss",
                solution="使用textContent或HTML编码：document.getElementById('comments').textContent = userComment;",
                similarity_score=1.0,
                case_date=datetime.now() - timedelta(days=20),
                source_project="sample_project_2",
                references=["https://example.com/case2"]
            ),
            HistoricalCase(
                id="sample_003",
                title="命令注入漏洞修复案例",
                description="在文件处理功能中发现命令注入漏洞",
                code_pattern="""os.system('convert ' + filename + ' output.jpg')""",
                vulnerability_type="command injection",
                solution="""使用subprocess.run with shell=False：subprocess.run(['convert', filename, 'output.jpg'])""",
                similarity_score=1.0,
                case_date=datetime.now() - timedelta(days=10),
                source_project="sample_project_3",
                references=["https://example.com/case3"]
            )
        ]
        
        for case in sample_cases:
            await self.add_case(case)
    
    async def search_similar_cases(self, code_pattern: str, 
                                 vulnerability_type: str,
                                 similarity_threshold: float = 0.3,
                                 max_results: int = 10) -> List[HistoricalCase]:
        """搜索相似的历史案例"""
        await self._ensure_initialized()
        try:
            self.metrics["queries_processed"] += 1
            
            # 过滤相关案例
            relevant_cases = [
                case for case in self.cases
                if case.vulnerability_type.lower() == vulnerability_type.lower()
            ]
            
            # 如果没有完全匹配的类型，使用模糊匹配
            if not relevant_cases:
                relevant_cases = [
                    case for case in self.cases
                    if vulnerability_type.lower() in case.vulnerability_type.lower() or
                       case.vulnerability_type.lower() in vulnerability_type.lower()
                ]
            
            # 计算相似性
            case_similarities = []
            for case in relevant_cases:
                similarity = await self._calculate_case_similarity(code_pattern, case)
                if similarity >= similarity_threshold:
                    # 更新案例的相似性分数
                    case.similarity_score = similarity
                    case_similarities.append((case, similarity))
            
            # 按相似性排序
            case_similarities.sort(key=lambda x: x[1], reverse=True)
            
            # 返回结果
            result_cases = [case for case, _ in case_similarities[:max_results]]
            
            logger.debug(f"找到 {len(result_cases)} 个相似案例")
            return result_cases
            
        except Exception as e:
            logger.error(f"相似案例搜索失败: {e}")
            return []
    
    async def _calculate_case_similarity(self, code_pattern: str, case: HistoricalCase) -> float:
        """计算与案例的相似性"""
        try:
            # 检查缓存
            cache_key = hashlib.md5(f"{code_pattern}_{case.id}".encode()).hexdigest()
            if cache_key in self.similarity_cache:
                self.metrics["cache_hits"] += 1
                return self.similarity_cache[cache_key]
            
            # 计算相似性
            similarity = self.similarity_calculator.calculate_similarity(
                code_pattern, case.code_pattern
            )
            
            # 缓存结果
            if len(self.similarity_cache) < self.max_cache_size:
                self.similarity_cache[cache_key] = similarity
            
            self.metrics["similarity_calculations"] += 1
            return similarity
            
        except Exception as e:
            logger.warning(f"相似性计算失败: {e}")
            return 0.0
    
    async def add_case(self, case: HistoricalCase):
        """添加新案例"""
        await self._ensure_initialized()
        try:
            # 检查是否已存在
            existing_ids = {c.id for c in self.cases}
            if case.id in existing_ids:
                logger.warning(f"案例ID已存在: {case.id}")
                return
            
            # 添加案例
            self.cases.append(case)
            
            # 提取特征
            features = await self._extract_case_features(case)
            self.case_features[case.id] = features
            
            # 保存到文件
            await self._save_cases()
            await self._save_features()
            
            self.metrics["cases_indexed"] = len(self.cases)
            logger.info(f"添加历史案例: {case.id}")
            
        except Exception as e:
            logger.error(f"添加案例失败: {e}")
            raise
    
    async def add_case_from_vulnerability(self, vulnerability: VulnerabilityResult,
                                        solution: str,
                                        lessons_learned: List[str]):
        """从漏洞结果创建历史案例"""
        await self._ensure_initialized()
        try:
            case = HistoricalCase(
                id=f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(vulnerability.snippet) % 10000:04d}",
                title=f"{vulnerability.vulnerability_type} - {vulnerability.file_path}",
                description=vulnerability.description,
                code_pattern=vulnerability.snippet,
                vulnerability_type=vulnerability.vulnerability_type,
                solution=solution,
                similarity_score=1.0,
                case_date=datetime.now(),
                source_project=getattr(vulnerability, 'project_name', 'unknown'),
                references=getattr(vulnerability, 'references', [])
            )
            
            await self.add_case(case)
            return case
            
        except Exception as e:
            logger.error(f"从漏洞创建案例失败: {e}")
            raise
    
    async def _extract_case_features(self, case: HistoricalCase) -> CaseFeatures:
        """提取案例特征"""
        try:
            # 提取tokens
            tokens = re.findall(r'\w+', case.code_pattern.lower())
            
            # 提取关键词
            keywords = self.similarity_calculator._extract_keywords(case.code_pattern)
            
            # 提取模式
            patterns = self.similarity_calculator._extract_patterns(case.code_pattern)
            
            # 计算复杂度
            complexity_score = self._calculate_complexity(case.code_pattern)
            
            # 语言特征
            language_features = {
                "has_sql": "sql" in case.code_pattern.lower(),
                "has_html": any(tag in case.code_pattern.lower() for tag in ["<", ">", "html", "script"]),
                "has_system_calls": any(call in case.code_pattern.lower() for call in ["system", "exec", "shell"]),
                "has_file_ops": any(op in case.code_pattern.lower() for op in ["file", "open", "read", "write"]),
                "line_count": len(case.code_pattern.split('\n'))
            }
            
            return CaseFeatures(
                tokens=tokens,
                keywords=keywords,
                patterns=patterns,
                complexity_score=complexity_score,
                language_features=language_features
            )
            
        except Exception as e:
            logger.warning(f"特征提取失败: {e}")
            return CaseFeatures()
    
    def _calculate_complexity(self, code: str) -> float:
        """计算代码复杂度"""
        try:
            # 简单的复杂度计算
            complexity = 0.0
            
            # 行数
            lines = len(code.split('\n'))
            complexity += lines * 0.1
            
            # 控制结构
            control_structures = len(re.findall(r'\b(if|for|while|switch|try)\b', code, re.IGNORECASE))
            complexity += control_structures * 0.5
            
            # 函数调用
            function_calls = len(re.findall(r'\w+\s*\(', code))
            complexity += function_calls * 0.2
            
            # 嵌套层次
            max_nesting = self._calculate_nesting_depth(code)
            complexity += max_nesting * 0.3
            
            return min(complexity, 10.0)  # 限制最大复杂度
            
        except Exception as e:
            logger.warning(f"复杂度计算失败: {e}")
            return 1.0
    
    def _calculate_nesting_depth(self, code: str) -> int:
        """计算嵌套深度"""
        try:
            depth = 0
            max_depth = 0
            
            for char in code:
                if char in '{([':
                    depth += 1
                    max_depth = max(max_depth, depth)
                elif char in '})]':
                    depth = max(0, depth - 1)
            
            return max_depth
            
        except Exception as e:
            logger.warning(f"嵌套深度计算失败: {e}")
            return 1
    
    async def _save_cases(self):
        """保存案例到文件"""
        try:
            data = {
                "cases": [case.to_dict() for case in self.cases],
                "metadata": {
                    "total_cases": len(self.cases),
                    "last_updated": datetime.now().isoformat()
                }
            }
            
            async with aiofiles.open(self.index_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            
        except Exception as e:
            logger.error(f"保存案例失败: {e}")
    
    async def _save_features(self):
        """保存特征到文件"""
        try:
            with open(self.features_file, 'wb') as f:
                pickle.dump(self.case_features, f)
            
        except Exception as e:
            logger.error(f"保存特征失败: {e}")
    
    async def update_case_learning(self, case_id: str, feedback: Dict[str, Any]):
        """更新案例学习信息"""
        await self._ensure_initialized()
        try:
            # 找到案例
            case = None
            for c in self.cases:
                if c.id == case_id:
                    case = c
                    break
            
            if not case:
                logger.warning(f"案例不存在: {case_id}")
                return
            
            # 更新学习信息
            if "effectiveness" in feedback:
                # 根据反馈调整相似性权重
                effectiveness = feedback["effectiveness"]
                if effectiveness > 0.8:
                    case.similarity_score *= 1.1
                elif effectiveness < 0.3:
                    case.similarity_score *= 0.9
            
            # 保存更新
            await self._save_cases()
            
            logger.info(f"更新案例学习信息: {case_id}")
            
        except Exception as e:
            logger.error(f"更新案例学习失败: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        return self.metrics.copy()
    
    def get_case_statistics(self) -> Dict[str, Any]:
        """获取案例统计信息"""
        stats = {
            "total_cases": len(self.cases),
            "by_vulnerability_type": defaultdict(int),
            "by_source_project": defaultdict(int),
            "average_similarity": 0.0,
            "date_range": {
                "earliest": None,
                "latest": None
            }
        }
        
        if self.cases:
            # 按漏洞类型统计
            for case in self.cases:
                stats["by_vulnerability_type"][case.vulnerability_type] += 1
                stats["by_source_project"][case.source_project] += 1
            
            # 平均相似性
            avg_similarity = sum(case.similarity_score for case in self.cases) / len(self.cases)
            stats["average_similarity"] = avg_similarity
            
            # 日期范围
            dates = [case.case_date for case in self.cases]
            stats["date_range"]["earliest"] = min(dates).isoformat()
            stats["date_range"]["latest"] = max(dates).isoformat()
        
        return dict(stats)
    
    async def cleanup_old_cases(self, days_threshold: int = 365):
        """清理旧案例"""
        await self._ensure_initialized()
        try:
            cutoff_date = datetime.now() - timedelta(days=days_threshold)
            
            old_cases = [case for case in self.cases if case.case_date < cutoff_date]
            
            if old_cases:
                # 移除旧案例
                self.cases = [case for case in self.cases if case.case_date >= cutoff_date]
                
                # 移除对应的特征
                for case in old_cases:
                    self.case_features.pop(case.id, None)
                
                # 保存更新
                await self._save_cases()
                await self._save_features()
                
                logger.info(f"清理了 {len(old_cases)} 个旧案例")
            
        except Exception as e:
            logger.error(f"清理旧案例失败: {e}")