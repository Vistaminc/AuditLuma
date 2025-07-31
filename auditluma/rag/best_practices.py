"""
最佳实践匹配系统 - 实现OWASP、SANS、NIST等标准的集成

本模块提供最佳实践匹配功能，包括：
- OWASP、SANS、NIST等标准的集成
- 代码模式与最佳实践的匹配算法
- 最佳实践数据库管理
- 动态规则更新和扩展
"""

import asyncio
import json
import aiohttp
import aiofiles
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import os
import re
import difflib
from enum import Enum

from loguru import logger

from auditluma.models.hierarchical_rag import BestPractice


class StandardSource(str, Enum):
    """标准来源"""
    OWASP = "owasp"
    SANS = "sans"
    NIST = "nist"
    CWE = "cwe"
    CUSTOM = "custom"


@dataclass
class PracticeRule:
    """实践规则"""
    id: str
    pattern: str  # 代码模式正则表达式
    language: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    recommendation: str
    source: StandardSource
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0
    
    def __hash__(self):
        """使对象可哈希，基于ID"""
        return hash(self.id)
    
    def __eq__(self, other):
        """定义相等性比较"""
        if not isinstance(other, PracticeRule):
            return False
        return self.id == other.id
    
    def matches(self, code: str, language: str) -> Tuple[bool, float]:
        """检查代码是否匹配此规则"""
        if self.language != "general" and self.language != language.lower():
            return False, 0.0
        
        try:
            # 使用正则表达式匹配
            if re.search(self.pattern, code, re.IGNORECASE | re.MULTILINE):
                # 计算匹配置信度
                confidence = self.confidence
                
                # 根据匹配的复杂度调整置信度
                if len(self.pattern) > 50:  # 复杂模式
                    confidence *= 1.1
                
                # 根据语言特异性调整
                if self.language != "general":
                    confidence *= 1.2
                
                return True, min(confidence, 1.0)
            
            return False, 0.0
            
        except re.error as e:
            logger.warning(f"正则表达式错误 {self.id}: {e}")
            return False, 0.0


class BestPracticesIndex:
    """最佳实践索引 - 核心匹配系统"""
    
    def __init__(self):
        """初始化最佳实践索引"""
        self.rules: Dict[str, PracticeRule] = {}
        self.rules_by_language: Dict[str, List[PracticeRule]] = {}
        self.rules_by_vuln_type: Dict[str, List[PracticeRule]] = {}
        
        # 数据目录
        self.data_dir = Path("./data/best_practices")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # 缓存
        self.cache_dir = Path("./data/best_practices_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # 性能指标
        self.metrics = {
            "rules_loaded": 0,
            "matches_found": 0,
            "queries_processed": 0,
            "last_update": None
        }
        
        # 初始化规则（同步方式，避免阻塞）
        self._initialize_rules_sync()
        
        logger.info("最佳实践索引初始化完成")
    
    async def _initialize_rules(self):
        """初始化规则集"""
        try:
            # 加载内置规则
            await self._load_builtin_rules()
            
            # 加载OWASP规则
            await self._load_owasp_rules()
            
            # 加载SANS规则
            await self._load_sans_rules()
            
            # 加载NIST规则
            await self._load_nist_rules()
            
            # 加载自定义规则
            await self._load_custom_rules()
            
            # 构建索引
            self._build_indexes()
            
            self.metrics["rules_loaded"] = len(self.rules)
            self.metrics["last_update"] = datetime.now()
            
            logger.info(f"加载了 {len(self.rules)} 条最佳实践规则")
            
        except Exception as e:
            logger.error(f"规则初始化失败: {e}")
    
    def _initialize_rules_sync(self):
        """同步版本的规则初始化"""
        try:
            # 直接加载内置规则（同步方式）
            self._load_builtin_rules_sync()
            
            # 构建索引
            self._build_indexes()
            
            self.metrics["rules_loaded"] = len(self.rules)
            self.metrics["last_update"] = datetime.now()
            
            logger.info(f"同步加载了 {len(self.rules)} 条最佳实践规则")
            
        except Exception as e:
            logger.error(f"同步规则初始化失败: {e}")
    
    def _load_builtin_rules_sync(self):
        """同步加载内置规则"""
        builtin_rules = [
            # SQL注入规则
            PracticeRule(
                id="sql_injection_001",
                pattern=r"(SELECT|INSERT|UPDATE|DELETE).*\+.*['\"]",
                language="general",
                vulnerability_type="sql injection",
                severity="HIGH",
                title="SQL注入 - 字符串拼接",
                description="检测到使用字符串拼接构建SQL查询，可能导致SQL注入",
                recommendation="使用参数化查询或预编译语句",
                source=StandardSource.CUSTOM,
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                tags=["sql", "injection", "database"],
                confidence=0.9
            ),
            # XSS规则
            PracticeRule(
                id="xss_001",
                pattern=r"innerHTML\s*=\s*[^;]*\+",
                language="javascript",
                vulnerability_type="xss",
                severity="HIGH",
                title="XSS - innerHTML动态内容",
                description="检测到使用innerHTML插入动态内容，可能导致XSS",
                recommendation="使用textContent或进行HTML转义",
                source=StandardSource.CUSTOM,
                references=["https://owasp.org/www-community/attacks/xss/"],
                tags=["xss", "javascript", "dom"],
                confidence=0.8
            ),
            # 更多内置规则...
        ]
        
        for rule in builtin_rules:
            self.rules[rule.id] = rule
    
    async def _load_builtin_rules(self):
        """加载内置规则"""
        builtin_rules = [
            # SQL注入规则
            PracticeRule(
                id="sql_injection_001",
                pattern=r"(SELECT|INSERT|UPDATE|DELETE).*\+.*['\"]",
                language="general",
                vulnerability_type="sql injection",
                severity="HIGH",
                title="SQL注入 - 字符串拼接",
                description="检测到使用字符串拼接构建SQL查询，可能导致SQL注入",
                recommendation="使用参数化查询或预编译语句",
                source=StandardSource.CUSTOM,
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                tags=["sql", "injection", "database"],
                confidence=0.9
            ),
            
            # XSS规则
            PracticeRule(
                id="xss_001",
                pattern=r"innerHTML\s*=\s*[^;]*\+",
                language="javascript",
                vulnerability_type="xss",
                severity="MEDIUM",
                title="XSS - innerHTML动态内容",
                description="检测到使用innerHTML动态插入内容，可能导致XSS",
                recommendation="使用textContent或进行HTML编码",
                source=StandardSource.CUSTOM,
                references=["https://owasp.org/www-community/attacks/xss/"],
                tags=["xss", "javascript", "dom"],
                confidence=0.8
            ),
            
            # 命令注入规则
            PracticeRule(
                id="command_injection_001",
                pattern=r"(system|exec|shell_exec|passthru)\s*\([^)]*\$",
                language="php",
                vulnerability_type="command injection",
                severity="HIGH",
                title="命令注入 - 动态命令执行",
                description="检测到使用用户输入执行系统命令，可能导致命令注入",
                recommendation="避免使用系统命令执行函数，或严格验证输入",
                source=StandardSource.CUSTOM,
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
                tags=["command", "injection", "php"],
                confidence=0.95
            ),
            
            # 路径遍历规则
            PracticeRule(
                id="path_traversal_001",
                pattern=r"(file_get_contents|fopen|include|require)\s*\([^)]*\.\./",
                language="php",
                vulnerability_type="path traversal",
                severity="HIGH",
                title="路径遍历 - 相对路径访问",
                description="检测到使用相对路径访问文件，可能导致路径遍历",
                recommendation="验证和规范化文件路径，使用白名单限制访问",
                source=StandardSource.CUSTOM,
                references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                tags=["path", "traversal", "file"],
                confidence=0.9
            ),
            
            # 缓冲区溢出规则
            PracticeRule(
                id="buffer_overflow_001",
                pattern=r"(strcpy|strcat|sprintf|gets)\s*\(",
                language="c",
                vulnerability_type="buffer overflow",
                severity="HIGH",
                title="缓冲区溢出 - 不安全函数",
                description="检测到使用不安全的字符串函数，可能导致缓冲区溢出",
                recommendation="使用安全的字符串函数如strncpy, strncat, snprintf",
                source=StandardSource.CUSTOM,
                references=["https://cwe.mitre.org/data/definitions/120.html"],
                tags=["buffer", "overflow", "c"],
                confidence=0.95
            )
        ]
        
        for rule in builtin_rules:
            self.rules[rule.id] = rule
    
    async def _load_owasp_rules(self):
        """加载OWASP规则"""
        try:
            # OWASP Top 10 相关规则
            owasp_rules = [
                # A01:2021 – Broken Access Control
                PracticeRule(
                    id="owasp_a01_001",
                    pattern=r"if\s*\(\s*\$_SESSION\[['\"]\w+['\"]\]\s*==\s*['\"]admin['\"]",
                    language="php",
                    vulnerability_type="broken access control",
                    severity="HIGH",
                    title="OWASP A01 - 硬编码权限检查",
                    description="检测到硬编码的权限检查，可能导致访问控制绕过",
                    recommendation="实施基于角色的访问控制(RBAC)和最小权限原则",
                    source=StandardSource.OWASP,
                    references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    tags=["access-control", "authorization", "owasp-top10"],
                    confidence=0.8
                ),
                
                # A02:2021 – Cryptographic Failures
                PracticeRule(
                    id="owasp_a02_001",
                    pattern=r"(md5|sha1)\s*\([^)]*password",
                    language="general",
                    vulnerability_type="cryptographic failures",
                    severity="MEDIUM",
                    title="OWASP A02 - 弱密码哈希",
                    description="检测到使用弱哈希算法处理密码",
                    recommendation="使用bcrypt、scrypt或Argon2等强密码哈希算法",
                    source=StandardSource.OWASP,
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                    tags=["crypto", "password", "hash", "owasp-top10"],
                    confidence=0.9
                ),
                
                # A03:2021 – Injection
                PracticeRule(
                    id="owasp_a03_001",
                    pattern=r"query\s*=\s*['\"].*\$.*['\"]",
                    language="general",
                    vulnerability_type="injection",
                    severity="HIGH",
                    title="OWASP A03 - SQL注入风险",
                    description="检测到动态构建SQL查询，存在注入风险",
                    recommendation="使用参数化查询、存储过程或ORM",
                    source=StandardSource.OWASP,
                    references=["https://owasp.org/Top10/A03_2021-Injection/"],
                    tags=["injection", "sql", "owasp-top10"],
                    confidence=0.85
                ),
                
                # A07:2021 – Identification and Authentication Failures
                PracticeRule(
                    id="owasp_a07_001",
                    pattern=r"password\s*=\s*['\"][^'\"]{1,7}['\"]",
                    language="general",
                    vulnerability_type="authentication failures",
                    severity="MEDIUM",
                    title="OWASP A07 - 弱密码策略",
                    description="检测到可能的弱密码或硬编码密码",
                    recommendation="实施强密码策略和多因素认证",
                    source=StandardSource.OWASP,
                    references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
                    tags=["authentication", "password", "owasp-top10"],
                    confidence=0.7
                )
            ]
            
            for rule in owasp_rules:
                self.rules[rule.id] = rule
            
        except Exception as e:
            logger.error(f"OWASP规则加载失败: {e}")
    
    async def _load_sans_rules(self):
        """加载SANS规则"""
        try:
            # SANS Top 25 相关规则
            sans_rules = [
                # CWE-79: Cross-site Scripting
                PracticeRule(
                    id="sans_cwe79_001",
                    pattern=r"document\.write\s*\([^)]*\+",
                    language="javascript",
                    vulnerability_type="xss",
                    severity="HIGH",
                    title="SANS CWE-79 - document.write XSS",
                    description="检测到使用document.write动态输出内容，可能导致XSS",
                    recommendation="使用安全的DOM操作方法和内容编码",
                    source=StandardSource.SANS,
                    references=["https://cwe.mitre.org/data/definitions/79.html"],
                    tags=["xss", "javascript", "sans-top25"],
                    confidence=0.85
                ),
                
                # CWE-89: SQL Injection
                PracticeRule(
                    id="sans_cwe89_001",
                    pattern=r"(mysqli_query|mysql_query)\s*\([^)]*\.[^)]*\$",
                    language="php",
                    vulnerability_type="sql injection",
                    severity="HIGH",
                    title="SANS CWE-89 - MySQL查询注入",
                    description="检测到动态构建MySQL查询，存在SQL注入风险",
                    recommendation="使用预编译语句或参数化查询",
                    source=StandardSource.SANS,
                    references=["https://cwe.mitre.org/data/definitions/89.html"],
                    tags=["sql", "injection", "mysql", "sans-top25"],
                    confidence=0.9
                ),
                
                # CWE-78: Command Injection
                PracticeRule(
                    id="sans_cwe78_001",
                    pattern=r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+",
                    language="java",
                    vulnerability_type="command injection",
                    severity="HIGH",
                    title="SANS CWE-78 - Java命令执行",
                    description="检测到动态构建系统命令，可能导致命令注入",
                    recommendation="避免执行系统命令，或使用ProcessBuilder进行安全调用",
                    source=StandardSource.SANS,
                    references=["https://cwe.mitre.org/data/definitions/78.html"],
                    tags=["command", "injection", "java", "sans-top25"],
                    confidence=0.9
                )
            ]
            
            for rule in sans_rules:
                self.rules[rule.id] = rule
            
        except Exception as e:
            logger.error(f"SANS规则加载失败: {e}")
    
    async def _load_nist_rules(self):
        """加载NIST规则"""
        try:
            # NIST安全控制相关规则
            nist_rules = [
                # 访问控制
                PracticeRule(
                    id="nist_ac_001",
                    pattern=r"chmod\s+777",
                    language="general",
                    vulnerability_type="access control",
                    severity="HIGH",
                    title="NIST AC - 过度权限设置",
                    description="检测到设置过度的文件权限(777)",
                    recommendation="遵循最小权限原则，设置适当的文件权限",
                    source=StandardSource.NIST,
                    references=["https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-6"],
                    tags=["access-control", "permissions", "nist"],
                    confidence=0.95
                ),
                
                # 系统和通信保护
                PracticeRule(
                    id="nist_sc_001",
                    pattern=r"http://[^/]*password",
                    language="general",
                    vulnerability_type="insecure communication",
                    severity="MEDIUM",
                    title="NIST SC - 不安全的通信",
                    description="检测到通过HTTP传输敏感信息",
                    recommendation="使用HTTPS加密传输敏感数据",
                    source=StandardSource.NIST,
                    references=["https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-8"],
                    tags=["communication", "encryption", "nist"],
                    confidence=0.8
                )
            ]
            
            for rule in nist_rules:
                self.rules[rule.id] = rule
            
        except Exception as e:
            logger.error(f"NIST规则加载失败: {e}")
    
    async def _load_custom_rules(self):
        """加载自定义规则"""
        try:
            custom_rules_file = self.data_dir / "custom_rules.json"
            
            if custom_rules_file.exists():
                async with aiofiles.open(custom_rules_file, 'r', encoding='utf-8') as f:
                    data = json.loads(await f.read())
                
                for rule_data in data.get("rules", []):
                    rule = PracticeRule(
                        id=rule_data["id"],
                        pattern=rule_data["pattern"],
                        language=rule_data["language"],
                        vulnerability_type=rule_data["vulnerability_type"],
                        severity=rule_data["severity"],
                        title=rule_data["title"],
                        description=rule_data["description"],
                        recommendation=rule_data["recommendation"],
                        source=StandardSource.CUSTOM,
                        references=rule_data.get("references", []),
                        tags=rule_data.get("tags", []),
                        confidence=rule_data.get("confidence", 1.0)
                    )
                    self.rules[rule.id] = rule
                
                logger.info(f"加载了 {len(data.get('rules', []))} 条自定义规则")
            
        except Exception as e:
            logger.error(f"自定义规则加载失败: {e}")
    
    def _build_indexes(self):
        """构建索引以提高查询性能"""
        self.rules_by_language.clear()
        self.rules_by_vuln_type.clear()
        
        for rule in self.rules.values():
            # 按语言索引
            if rule.language not in self.rules_by_language:
                self.rules_by_language[rule.language] = []
            self.rules_by_language[rule.language].append(rule)
            
            # 按漏洞类型索引
            if rule.vulnerability_type not in self.rules_by_vuln_type:
                self.rules_by_vuln_type[rule.vulnerability_type] = []
            self.rules_by_vuln_type[rule.vulnerability_type].append(rule)
    
    async def match_best_practices(self, code_pattern: str, 
                                 language: str, 
                                 vulnerability_type: Optional[str] = None) -> List[BestPractice]:
        """匹配最佳实践"""
        try:
            self.metrics["queries_processed"] += 1
            
            # 获取候选规则
            candidate_rules = self._get_candidate_rules(language, vulnerability_type)
            
            # 匹配规则
            matched_practices = []
            for rule in candidate_rules:
                matches, confidence = rule.matches(code_pattern, language)
                if matches:
                    practice = BestPractice(
                        id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        category=rule.vulnerability_type,
                        language=rule.language,
                        source=rule.source.value,
                        code_pattern=rule.pattern,
                        recommendation=rule.recommendation,
                        references=rule.references,
                        tags=rule.tags
                    )
                    matched_practices.append((practice, confidence))
            
            # 按置信度排序
            matched_practices.sort(key=lambda x: x[1], reverse=True)
            
            # 返回最佳实践对象
            result = [practice for practice, _ in matched_practices]
            
            self.metrics["matches_found"] += len(result)
            
            return result
            
        except Exception as e:
            logger.error(f"最佳实践匹配失败: {e}")
            return []
    
    def _get_candidate_rules(self, language: str, 
                           vulnerability_type: Optional[str] = None) -> List[PracticeRule]:
        """获取候选规则"""
        candidates = set()
        
        # 按语言筛选
        if language in self.rules_by_language:
            candidates.update(self.rules_by_language[language])
        
        # 添加通用规则
        if "general" in self.rules_by_language:
            candidates.update(self.rules_by_language["general"])
        
        # 按漏洞类型筛选
        if vulnerability_type and vulnerability_type in self.rules_by_vuln_type:
            vuln_rules = set(self.rules_by_vuln_type[vulnerability_type])
            candidates = candidates.intersection(vuln_rules) if candidates else vuln_rules
        
        return list(candidates)
    
    async def get_practices_by_vulnerability_type(self, vulnerability_type: str) -> List[BestPractice]:
        """根据漏洞类型获取最佳实践"""
        try:
            if vulnerability_type not in self.rules_by_vuln_type:
                return []
            
            practices = []
            for rule in self.rules_by_vuln_type[vulnerability_type]:
                practice = BestPractice(
                    id=rule.id,
                    title=rule.title,
                    description=rule.description,
                    category=rule.vulnerability_type,
                    language=rule.language,
                    source=rule.source.value,
                    code_pattern=rule.pattern,
                    recommendation=rule.recommendation,
                    references=rule.references,
                    tags=rule.tags
                )
                practices.append(practice)
            
            return practices
            
        except Exception as e:
            logger.error(f"按漏洞类型获取实践失败: {e}")
            return []
    
    async def get_practices_by_source(self, source: StandardSource) -> List[BestPractice]:
        """根据标准来源获取最佳实践"""
        try:
            practices = []
            for rule in self.rules.values():
                if rule.source == source:
                    practice = BestPractice(
                        id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        category=rule.vulnerability_type,
                        language=rule.language,
                        source=rule.source.value,
                        code_pattern=rule.pattern,
                        recommendation=rule.recommendation,
                        references=rule.references,
                        tags=rule.tags
                    )
                    practices.append(practice)
            
            return practices
            
        except Exception as e:
            logger.error(f"按来源获取实践失败: {e}")
            return []
    
    async def add_custom_rule(self, rule: PracticeRule):
        """添加自定义规则"""
        try:
            # 检查ID是否已存在
            existing_ids = set(self.rules.keys())
            if rule.id in existing_ids:
                raise ValueError(f"规则ID已存在: {rule.id}")
            
            # 添加规则
            self.rules[rule.id] = rule
            
            # 重建索引
            self._build_indexes()
            
            # 保存到文件
            await self._save_custom_rules()
            
            logger.info(f"添加自定义规则: {rule.id}")
            
        except Exception as e:
            logger.error(f"添加自定义规则失败: {e}")
            raise
    
    async def _save_custom_rules(self):
        """保存自定义规则到文件"""
        try:
            custom_rules = [r for r in self.rules.values() if r.source == StandardSource.CUSTOM]
            
            data = {
                "rules": [
                    {
                        "id": rule.id,
                        "pattern": rule.pattern,
                        "language": rule.language,
                        "vulnerability_type": rule.vulnerability_type,
                        "severity": rule.severity,
                        "title": rule.title,
                        "description": rule.description,
                        "recommendation": rule.recommendation,
                        "references": rule.references,
                        "tags": rule.tags,
                        "confidence": rule.confidence
                    }
                    for rule in custom_rules
                ]
            }
            
            custom_rules_file = self.data_dir / "custom_rules.json"
            async with aiofiles.open(custom_rules_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            
        except Exception as e:
            logger.error(f"保存自定义规则失败: {e}")
    
    async def update_rules_from_source(self, source: StandardSource):
        """从指定来源更新规则"""
        try:
            logger.info(f"开始更新 {source.value} 规则")
            
            if source == StandardSource.OWASP:
                await self._update_owasp_rules()
            elif source == StandardSource.SANS:
                await self._update_sans_rules()
            elif source == StandardSource.NIST:
                await self._update_nist_rules()
            
            # 重建索引
            self._build_indexes()
            
            self.metrics["last_update"] = datetime.now()
            logger.info(f"{source.value} 规则更新完成")
            
        except Exception as e:
            logger.error(f"更新 {source.value} 规则失败: {e}")
    
    async def _update_owasp_rules(self):
        """更新OWASP规则（从网络获取最新信息）"""
        # 这里可以实现从OWASP官网获取最新规则的逻辑
        # 目前使用静态规则
        pass
    
    async def _update_sans_rules(self):
        """更新SANS规则"""
        # 这里可以实现从SANS获取最新规则的逻辑
        pass
    
    async def _update_nist_rules(self):
        """更新NIST规则"""
        # 这里可以实现从NIST获取最新规则的逻辑
        pass
    
    def get_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        return self.metrics.copy()
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """获取规则统计信息"""
        stats = {
            "total_rules": len(self.rules),
            "by_source": {},
            "by_language": {},
            "by_vulnerability_type": {},
            "by_severity": {}
        }
        
        for rule in self.rules.values():
            # 按来源统计
            source = rule.source.value
            stats["by_source"][source] = stats["by_source"].get(source, 0) + 1
            
            # 按语言统计
            lang = rule.language
            stats["by_language"][lang] = stats["by_language"].get(lang, 0) + 1
            
            # 按漏洞类型统计
            vuln_type = rule.vulnerability_type
            stats["by_vulnerability_type"][vuln_type] = stats["by_vulnerability_type"].get(vuln_type, 0) + 1
            
            # 按严重性统计
            severity = rule.severity
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
        
        return stats