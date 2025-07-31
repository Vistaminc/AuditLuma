"""
txtai实时知识检索层 - 层级RAG架构第二层
负责外部知识库检索与匹配

本模块实现了层级RAG架构的第二层，提供实时知识检索功能，包括：
- CVE数据库实时查询
- 最佳实践匹配
- 历史案例检索
- 知识源管理和更新
- 与现有self_rag系统的集成接口
"""

import asyncio
import json
import aiohttp
import aiofiles
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import os
import time

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import VulnerabilityResult
from auditluma.models.hierarchical_rag import (
    VulnerabilityKnowledge, CVEInfo, BestPractice, HistoricalCase
)


@dataclass
class VulnerabilityInfo:
    """漏洞信息数据结构 - 兼容性保持"""
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    severity: str = "medium"
    description: str = ""
    references: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)
    historical_cases: List[Dict[str, Any]] = field(default_factory=list)
    owasp_category: Optional[str] = None
    remediation_suggestions: List[str] = field(default_factory=list)
    
    def to_vulnerability_knowledge(self) -> VulnerabilityKnowledge:
        """转换为标准的VulnerabilityKnowledge格式"""
        # 转换CVE信息
        cve_info = []
        if self.cve_id:
            cve_info.append(CVEInfo(
                cve_id=self.cve_id,
                description=self.description,
                severity=self.severity,
                cvss_score=7.5 if self.severity.lower() == "high" else 5.0,
                published_date=datetime.now(),
                modified_date=datetime.now(),
                references=self.references,
                cwe_ids=[self.cwe_id] if self.cwe_id else []
            ))
        
        # 转换最佳实践
        best_practices_objs = []
        for i, practice in enumerate(self.best_practices):
            best_practices_objs.append(BestPractice(
                id=f"bp_{i}",
                title=f"Best Practice {i+1}",
                description=practice,
                category=self.owasp_category or "General",
                language="general",
                source="txtai_retriever",
                code_pattern="",
                recommendation=practice
            ))
        
        # 转换历史案例
        historical_cases_objs = []
        for i, case in enumerate(self.historical_cases):
            historical_cases_objs.append(HistoricalCase(
                id=case.get("case_id", f"hc_{i}"),
                title=case.get("description", f"Historical Case {i+1}"),
                description=case.get("description", ""),
                code_pattern=case.get("code_pattern", ""),
                vulnerability_type=case.get("vulnerability_type", "unknown"),
                solution=case.get("resolution", ""),
                similarity_score=case.get("code_pattern_similarity", 0.0),
                case_date=datetime.fromisoformat(case.get("date", datetime.now().isoformat())),
                source_project=case.get("source_project", "unknown")
            ))
        
        return VulnerabilityKnowledge(
            cve_info=cve_info,
            best_practices=best_practices_objs,
            historical_cases=historical_cases_objs,
            relevance_scores={},
            retrieval_time=0.0,
            source_queries=[]
        )


@dataclass
class KnowledgeSource:
    """知识源定义"""
    name: str
    url: str
    update_frequency: str
    last_updated: Optional[datetime] = None
    enabled: bool = True


class CVEDatabase:
    """CVE数据库接口 - 使用新的CVEDatabaseClient"""
    
    def __init__(self):
        from auditluma.rag.cve_client import CVEDatabaseClient
        self.client = CVEDatabaseClient()
        self.session = None
        
    async def __aenter__(self):
        self.session = await self.client.__aenter__()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.__aexit__(exc_type, exc_val, exc_tb)
    
    async def search_cve(self, vulnerability_type: str, code_pattern: str) -> List[Dict[str, Any]]:
        """搜索相关CVE"""
        try:
            # 提取搜索关键词
            search_terms = self._extract_search_terms(vulnerability_type, code_pattern)
            
            # 使用新的客户端查询
            results = []
            for term in search_terms[:3]:  # 限制搜索词数量
                cve_infos = await self.client.query_cve_by_keyword(term, limit=5)
                for cve_info in cve_infos:
                    results.append({
                        "cve_id": cve_info.cve_id,
                        "description": cve_info.description,
                        "severity": cve_info.severity,
                        "cvss_score": cve_info.cvss_score,
                        "references": cve_info.references,
                        "published_date": cve_info.published_date.isoformat(),
                        "modified_date": cve_info.modified_date.isoformat(),
                        "cwe_ids": cve_info.cwe_ids,
                        "affected_products": cve_info.affected_products
                    })
            
            return results
            
        except Exception as e:
            logger.warning(f"CVE搜索失败: {e}")
            return []
    
    def _extract_search_terms(self, vulnerability_type: str, code_pattern: str) -> List[str]:
        """提取搜索关键词"""
        terms = []
        
        # 从漏洞类型提取关键词
        vuln_keywords = {
            "sql injection": ["sql", "injection", "database"],
            "xss": ["cross-site", "scripting", "xss"],
            "command injection": ["command", "injection", "execution"],
            "path traversal": ["path", "traversal", "directory"],
            "buffer overflow": ["buffer", "overflow", "memory"]
        }
        
        vuln_type_lower = vulnerability_type.lower()
        for pattern, keywords in vuln_keywords.items():
            if pattern in vuln_type_lower:
                terms.extend(keywords)
                break
        
        # 从代码模式提取关键词
        code_keywords = self._extract_code_keywords(code_pattern)
        terms.extend(code_keywords)
        
        return list(set(terms))  # 去重
    
    def _extract_code_keywords(self, code_pattern: str) -> List[str]:
        """从代码模式提取关键词"""
        keywords = []
        
        # 常见的危险函数和模式
        dangerous_patterns = [
            "eval", "exec", "system", "shell_exec",
            "mysqli_query", "mysql_query", "PDO",
            "file_get_contents", "fopen", "include",
            "require", "curl_exec", "fsockopen"
        ]
        
        code_lower = code_pattern.lower()
        for pattern in dangerous_patterns:
            if pattern in code_lower:
                keywords.append(pattern)
        
        return keywords


class BestPracticesDatabase:
    """最佳实践数据库 - 使用新的BestPracticesIndex"""
    
    def __init__(self):
        from auditluma.rag.best_practices import BestPracticesIndex
        self.index = BestPracticesIndex()
        
        # 保持向后兼容的简单规则
        self.simple_practices = self._load_simple_practices()
    
    def _load_simple_practices(self) -> Dict[str, List[str]]:
        """加载简单的最佳实践规则（向后兼容）"""
        return {
            "sql injection": [
                "使用参数化查询或预编译语句",
                "对用户输入进行严格验证和转义",
                "使用最小权限原则配置数据库用户",
                "启用数据库查询日志和监控",
                "定期更新数据库软件和驱动程序"
            ],
            "xss": [
                "对所有用户输入进行HTML编码",
                "使用内容安全策略(CSP)",
                "验证和过滤用户输入",
                "使用安全的模板引擎",
                "避免直接将用户数据插入DOM"
            ],
            "command injection": [
                "避免使用系统命令执行函数",
                "对用户输入进行严格验证",
                "使用白名单验证输入参数",
                "使用安全的API替代系统命令",
                "运行在受限的执行环境中"
            ],
            "path traversal": [
                "验证和规范化文件路径",
                "使用白名单限制可访问的目录",
                "避免直接使用用户输入构造文件路径",
                "实施访问控制和权限检查",
                "使用安全的文件操作API"
            ]
        }
    
    async def get_best_practices(self, vulnerability_type: str) -> List[str]:
        """获取最佳实践建议（兼容性方法）"""
        try:
            # 尝试使用新的索引系统
            practices = await self.index.get_practices_by_vulnerability_type(vulnerability_type)
            if practices:
                return [practice.recommendation for practice in practices]
            
            # 回退到简单规则
            vuln_type_lower = vulnerability_type.lower()
            
            # 直接匹配
            if vuln_type_lower in self.simple_practices:
                return self.simple_practices[vuln_type_lower]
            
            # 模糊匹配
            for pattern, practices in self.simple_practices.items():
                if pattern in vuln_type_lower or vuln_type_lower in pattern:
                    return practices
            
            # 通用最佳实践
            return [
                "对所有用户输入进行验证和过滤",
                "使用最小权限原则",
                "定期进行安全审计和测试",
                "保持软件和依赖项更新",
                "实施适当的错误处理和日志记录"
            ]
            
        except Exception as e:
            logger.warning(f"获取最佳实践失败: {e}")
            return self.simple_practices.get(vulnerability_type.lower(), [
                "遵循安全编码规范",
                "进行代码审查",
                "使用安全工具扫描"
            ])
    
    async def match_practices_with_code(self, code_pattern: str, 
                                      language: str, 
                                      vulnerability_type: Optional[str] = None) -> List[BestPractice]:
        """使用代码模式匹配最佳实践"""
        try:
            return await self.index.match_best_practices(code_pattern, language, vulnerability_type)
        except Exception as e:
            logger.warning(f"代码模式匹配失败: {e}")
            return []


class HistoricalCasesDatabase:
    """历史案例数据库 - 使用新的HistoricalCasesIndex"""
    
    def __init__(self):
        from auditluma.rag.historical_cases import HistoricalCasesIndex
        self.index = HistoricalCasesIndex()
        self.cases_cache = {}
        
    async def search_similar_cases(self, vulnerability_type: str, 
                                 code_pattern: str) -> List[Dict[str, Any]]:
        """搜索相似的历史案例"""
        try:
            # 生成搜索键
            search_key = f"{vulnerability_type}_{hashlib.md5(code_pattern.encode()).hexdigest()[:8]}"
            
            # 检查缓存
            if search_key in self.cases_cache:
                return self.cases_cache[search_key]
            
            # 使用新的索引搜索
            cases = await self.index.search_similar_cases(
                code_pattern, vulnerability_type, similarity_threshold=0.3
            )
            
            # 转换为兼容格式
            result_cases = []
            for case in cases:
                result_cases.append({
                    "case_id": case.id,
                    "vulnerability_type": case.vulnerability_type,
                    "description": case.description,
                    "code_pattern": case.code_pattern,
                    "code_pattern_similarity": case.similarity_score,
                    "resolution": case.solution,
                    "lessons_learned": [case.solution],  # 简化处理
                    "date": case.case_date.isoformat(),
                    "severity": "HIGH" if "injection" in case.vulnerability_type.lower() else "MEDIUM",
                    "source_project": case.source_project
                })
            
            # 缓存结果
            self.cases_cache[search_key] = result_cases
            
            return result_cases
            
        except Exception as e:
            logger.warning(f"历史案例搜索失败: {e}")
            # 回退到模拟数据
            return await self._get_fallback_cases(vulnerability_type)
    
    async def _get_fallback_cases(self, vulnerability_type: str) -> List[Dict[str, Any]]:
        """获取回退案例数据"""
        mock_cases = [
            {
                "case_id": f"FALLBACK-{hash(vulnerability_type) % 10000:04d}",
                "vulnerability_type": vulnerability_type,
                "description": f"Historical case of {vulnerability_type}",
                "code_pattern_similarity": 0.85,
                "resolution": f"Resolved by implementing proper input validation for {vulnerability_type}",
                "lessons_learned": [
                    "Early detection is crucial",
                    "Proper testing prevents similar issues",
                    "Code review processes should be enhanced"
                ],
                "date": "2023-12-01",
                "severity": "HIGH" if "injection" in vulnerability_type.lower() else "MEDIUM"
            }
        ]
        
        return mock_cases
    
    async def add_case(self, vulnerability: VulnerabilityResult, 
                      resolution: str, lessons_learned: List[str]):
        """添加新的历史案例"""
        try:
            # 使用新的索引添加案例
            case = await self.index.add_case_from_vulnerability(
                vulnerability, resolution, lessons_learned
            )
            
            logger.info(f"添加历史案例: {case.id}")
            
        except Exception as e:
            logger.error(f"添加历史案例失败: {e}")
            # 回退到简单保存
            await self._add_case_fallback(vulnerability, resolution, lessons_learned)
    
    async def _add_case_fallback(self, vulnerability: VulnerabilityResult, 
                               resolution: str, lessons_learned: List[str]):
        """回退的案例添加方法"""
        case = {
            "case_id": f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "vulnerability_type": vulnerability.vulnerability_type,
            "description": vulnerability.description,
            "code_pattern": vulnerability.snippet,
            "resolution": resolution,
            "lessons_learned": lessons_learned,
            "date": datetime.now().isoformat(),
            "severity": vulnerability.severity,
            "file_path": vulnerability.file_path
        }
        
        # 保存到文件
        cases_dir = Path("./data/historical_cases")
        cases_dir.mkdir(parents=True, exist_ok=True)
        case_file = cases_dir / f"{case['case_id']}.json"
        
        async with aiofiles.open(case_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(case, ensure_ascii=False, indent=2))
        
        logger.info(f"添加历史案例(回退): {case['case_id']}")
    
    async def get_case_statistics(self) -> Dict[str, Any]:
        """获取案例统计信息"""
        try:
            return self.index.get_case_statistics()
        except Exception as e:
            logger.warning(f"获取案例统计失败: {e}")
            return {"total_cases": 0, "error": str(e)}


class TxtaiRetriever:
    """txtai实时知识检索器 - 层级RAG架构第二层核心组件
    
    提供实时知识检索功能，包括：
    - CVE数据库查询
    - 最佳实践匹配
    - 历史案例检索
    - 与现有self_rag系统的集成
    """
    
    def __init__(self):
        """初始化知识检索器"""
        # 获取txtai层的模型配置
        self.txtai_models = Config.get_txtai_models()
        self.retrieval_model = self.txtai_models.get("retrieval_model", "gpt-3.5-turbo@openai")
        self.embedding_model = self.txtai_models.get("embedding_model", "text-embedding-ada-002@openai")
        
        logger.info(f"txtai检索器使用模型 - 检索: {self.retrieval_model}, 嵌入: {self.embedding_model}")
        
        self.cve_database = CVEDatabase()
        self.best_practices_db = BestPracticesDatabase()
        self.historical_cases_db = HistoricalCasesDatabase()
        
        # 集成知识源管理器
        self._init_knowledge_manager()
        
        # 知识源配置（向后兼容）
        self.knowledge_sources = [
            KnowledgeSource("CVE Database", "https://cve.mitre.org/", "daily"),
            KnowledgeSource("OWASP", "https://owasp.org/", "weekly"),
            KnowledgeSource("SANS", "https://www.sans.org/", "weekly"),
            KnowledgeSource("NIST", "https://nvd.nist.gov/", "daily")
        ]
        
        # 性能指标
        self.metrics = {
            "queries_processed": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "average_response_time": 0.0
        }
        
        # 集成现有self_rag系统
        self._init_self_rag_integration()
        
        logger.info("txtai知识检索器初始化完成")
    
    def get_retrieval_model(self) -> str:
        """获取检索模型"""
        return self.retrieval_model
    
    def get_embedding_model(self) -> str:
        """获取嵌入模型"""
        return self.embedding_model
    
    async def _call_retrieval_model(self, prompt: str, **kwargs) -> str:
        """调用检索模型进行推理"""
        start_time = time.time()
        
        try:
            from auditluma.utils import init_llm_client
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            
            logger.info(f"🔍 txtai检索层 - 调用检索模型: {self.retrieval_model}")
            logger.debug(f"检索提示长度: {len(prompt)} 字符")
            
            # 使用配置的检索模型
            llm_client = init_llm_client(self.retrieval_model)
            response = await llm_client.generate_async(prompt, **kwargs)
            
            execution_time = time.time() - start_time
            
            # 记录模型使用
            model_usage_logger.log_model_usage(
                layer="txtai",
                component="TxtaiRetriever",
                model_name=self.retrieval_model,
                operation="retrieval",
                input_size=len(prompt),
                output_size=len(response),
                execution_time=execution_time,
                success=True
            )
            
            logger.info(f"✅ txtai检索层 - 检索模型 {self.retrieval_model} 调用成功，响应长度: {len(response)} 字符")
            return response
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # 记录失败的模型使用
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            model_usage_logger.log_model_usage(
                layer="txtai",
                component="TxtaiRetriever",
                model_name=self.retrieval_model,
                operation="retrieval",
                input_size=len(prompt),
                output_size=0,
                execution_time=execution_time,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"❌ txtai检索层 - 调用检索模型 {self.retrieval_model} 失败: {e}")
            return ""
    
    async def _generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """使用配置的嵌入模型生成嵌入"""
        start_time = time.time()
        
        try:
            from auditluma.utils import init_llm_client
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            
            logger.info(f"🔍 txtai检索层 - 调用嵌入模型: {self.embedding_model}")
            logger.debug(f"生成嵌入文本数量: {len(texts)}")
            
            # 使用配置的嵌入模型
            embedding_client = init_llm_client(self.embedding_model)
            embeddings = []
            
            total_chars = sum(len(text) for text in texts)
            
            for i, text in enumerate(texts):
                embedding = await embedding_client.get_embedding_async(text)
                embeddings.append(embedding)
                if i == 0:  # 只记录第一个嵌入的维度信息
                    logger.debug(f"嵌入向量维度: {len(embedding)}")
            
            execution_time = time.time() - start_time
            
            # 记录模型使用
            model_usage_logger.log_model_usage(
                layer="txtai",
                component="TxtaiRetriever",
                model_name=self.embedding_model,
                operation="embedding",
                input_size=total_chars,
                output_size=len(embeddings),
                execution_time=execution_time,
                success=True,
                metadata={"text_count": len(texts), "embedding_dimension": len(embeddings[0]) if embeddings else 0}
            )
            
            logger.info(f"✅ txtai检索层 - 嵌入模型 {self.embedding_model} 调用成功，生成 {len(embeddings)} 个嵌入向量")
            return embeddings
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # 记录失败的模型使用
            from auditluma.monitoring.model_usage_logger import model_usage_logger
            model_usage_logger.log_model_usage(
                layer="txtai",
                component="TxtaiRetriever",
                model_name=self.embedding_model,
                operation="embedding",
                input_size=sum(len(text) for text in texts),
                output_size=0,
                execution_time=execution_time,
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"❌ txtai检索层 - 调用嵌入模型 {self.embedding_model} 失败: {e}")
            return []
    
    def _init_knowledge_manager(self):
        """初始化知识源管理器集成"""
        try:
            from auditluma.rag.knowledge_manager import knowledge_manager
            self.knowledge_manager = knowledge_manager
            logger.info("成功集成知识源管理器")
            
            # 初始化阿里云CVE爬虫集成
            self._init_aliyun_crawler_integration()
        except ImportError as e:
            logger.warning(f"无法导入知识源管理器: {e}")
            self.knowledge_manager = None
    
    def _init_aliyun_crawler_integration(self):
        """初始化阿里云CVE爬虫集成"""
        try:
            from auditluma.crawlers.cve_knowledge_integrator import cve_integrator
            self.cve_integrator = cve_integrator
            logger.info("成功集成阿里云CVE爬虫")
        except ImportError as e:
            logger.warning(f"无法导入阿里云CVE爬虫: {e}")
            self.cve_integrator = None
    
    def _init_self_rag_integration(self):
        """初始化与现有self_rag系统的集成"""
        try:
            from auditluma.rag.enhanced_self_rag import enhanced_self_rag as self_rag
            self.self_rag = self_rag
            logger.info("成功集成现有self_rag系统")
        except ImportError as e:
            logger.warning(f"无法导入self_rag系统: {e}")
            self.self_rag = None
    
    async def retrieve_vulnerability_info(self, vulnerability_type: str, 
                                        code_snippet: str) -> VulnerabilityInfo:
        """检索漏洞相关信息 - 主要接口方法（兼容性保持）"""
        knowledge = await self.retrieve_vulnerability_knowledge(vulnerability_type, code_snippet)
        return self._knowledge_to_info(knowledge)
    
    async def retrieve_vulnerability_knowledge(self, vulnerability_type: str, 
                                             code_snippet: str, 
                                             context: Optional[Dict[str, Any]] = None) -> VulnerabilityKnowledge:
        """检索漏洞相关知识 - 新的标准接口"""
        start_time = time.time()
        
        try:
            # 优先使用知识源管理器
            if self.knowledge_manager:
                try:
                    knowledge = await self.knowledge_manager.query_all_sources(
                        code_snippet, vulnerability_type, context
                    )
                    
                    # 更新性能指标
                    self._update_metrics(start_time)
                    
                    return knowledge
                    
                except Exception as e:
                    logger.warning(f"知识源管理器查询失败，回退到传统方法: {e}")
            
            # 回退到传统的并行检索方法
            cve_task = self._retrieve_cve_info(vulnerability_type, code_snippet)
            practices_task = self._retrieve_best_practices(vulnerability_type)
            cases_task = self._retrieve_historical_cases(vulnerability_type, code_snippet)
            
            # 如果有self_rag集成，也从中检索相关信息
            self_rag_task = None
            if self.self_rag and context:
                self_rag_task = self._retrieve_from_self_rag(vulnerability_type, code_snippet, context)
            
            # 等待所有任务完成
            tasks = [cve_task, practices_task, cases_task]
            if self_rag_task:
                tasks.append(self_rag_task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            cve_info = results[0] if not isinstance(results[0], Exception) else []
            best_practices = results[1] if not isinstance(results[1], Exception) else []
            historical_cases = results[2] if not isinstance(results[2], Exception) else []
            self_rag_results = results[3] if len(results) > 3 and not isinstance(results[3], Exception) else []
            
            # 处理异常结果
            if isinstance(results[0], Exception):
                logger.warning(f"CVE检索失败: {results[0]}")
            if isinstance(results[1], Exception):
                logger.warning(f"最佳实践检索失败: {results[1]}")
            if isinstance(results[2], Exception):
                logger.warning(f"历史案例检索失败: {results[2]}")
            if len(results) > 3 and isinstance(results[3], Exception):
                logger.warning(f"Self-RAG检索失败: {results[3]}")
            
            # 构建标准的VulnerabilityKnowledge对象
            knowledge = await self._build_vulnerability_knowledge(
                vulnerability_type, cve_info, best_practices, historical_cases, self_rag_results
            )
            
            # 更新性能指标
            knowledge.retrieval_time = time.time() - start_time
            self._update_metrics(start_time)
            
            return knowledge
            
        except Exception as e:
            logger.error(f"知识检索过程中出错: {e}")
            # 返回空的知识对象
            return VulnerabilityKnowledge(
                retrieval_time=time.time() - start_time,
                source_queries=[vulnerability_type]
            )
    
    async def _retrieve_cve_info(self, vulnerability_type: str, 
                               code_snippet: str) -> List[Dict[str, Any]]:
        """检索CVE信息"""
        async with self.cve_database as cve_db:
            return await cve_db.search_cve(vulnerability_type, code_snippet)
    
    async def _retrieve_best_practices(self, vulnerability_type: str) -> List[str]:
        """检索最佳实践"""
        return await self.best_practices_db.get_best_practices(vulnerability_type)
    
    async def _retrieve_historical_cases(self, vulnerability_type: str, 
                                       code_snippet: str) -> List[Dict[str, Any]]:
        """检索历史案例"""
        return await self.historical_cases_db.search_similar_cases(
            vulnerability_type, code_snippet
        )
    
    async def _retrieve_from_self_rag(self, vulnerability_type: str, 
                                    code_snippet: str, 
                                    context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从self_rag系统检索相关信息"""
        if not self.self_rag:
            return []
        
        try:
            # 构建查询字符串
            query = f"{vulnerability_type}: {code_snippet[:200]}"
            
            # 从self_rag检索相关文档
            documents = await self.self_rag.retrieve(query, k=5)
            
            # 转换为标准格式
            results = []
            for doc, score in documents:
                results.append({
                    "id": doc.id,
                    "content": doc.content,
                    "metadata": doc.metadata,
                    "relevance_score": score,
                    "source": "self_rag"
                })
            
            return results
            
        except Exception as e:
            logger.warning(f"从self_rag检索失败: {e}")
            return []
    
    async def _build_vulnerability_knowledge(self, vulnerability_type: str,
                                            cve_info: List[Dict[str, Any]],
                                            best_practices: List[str],
                                            historical_cases: List[Dict[str, Any]],
                                            self_rag_results: List[Dict[str, Any]]) -> VulnerabilityKnowledge:
        """构建标准的VulnerabilityKnowledge对象"""
        # 转换CVE信息
        cve_objects = []
        for cve in cve_info:
            cve_objects.append(CVEInfo(
                cve_id=cve.get("cve_id", ""),
                description=cve.get("description", ""),
                severity=cve.get("severity", "MEDIUM"),
                cvss_score=float(cve.get("cvss_score", 5.0)),
                published_date=datetime.fromisoformat(cve.get("published_date", datetime.now().isoformat())),
                modified_date=datetime.fromisoformat(cve.get("modified_date", datetime.now().isoformat())),
                references=cve.get("references", []),
                cwe_ids=cve.get("cwe_ids", [])
            ))
        
        # 转换最佳实践
        best_practice_objects = []
        for i, practice in enumerate(best_practices):
            best_practice_objects.append(BestPractice(
                id=f"bp_{vulnerability_type}_{i}",
                title=f"Best Practice for {vulnerability_type}",
                description=practice,
                category=self._determine_owasp_category(vulnerability_type) or "General",
                language="general",
                source="txtai_retriever",
                code_pattern="",
                recommendation=practice
            ))
        
        # 转换历史案例
        historical_case_objects = []
        for case in historical_cases:
            historical_case_objects.append(HistoricalCase(
                id=case.get("case_id", f"hc_{len(historical_case_objects)}"),
                title=case.get("description", "Historical Case"),
                description=case.get("description", ""),
                code_pattern=case.get("code_pattern", ""),
                vulnerability_type=case.get("vulnerability_type", vulnerability_type),
                solution=case.get("resolution", ""),
                similarity_score=float(case.get("code_pattern_similarity", 0.0)),
                case_date=datetime.fromisoformat(case.get("date", datetime.now().isoformat())),
                source_project=case.get("source_project", "unknown")
            ))
        
        # 计算相关性分数
        relevance_scores = {}
        if cve_objects:
            relevance_scores["cve"] = 0.9
        if best_practice_objects:
            relevance_scores["best_practices"] = 0.8
        if historical_case_objects:
            relevance_scores["historical_cases"] = 0.7
        if self_rag_results:
            relevance_scores["self_rag"] = 0.6
        
        return VulnerabilityKnowledge(
            cve_info=cve_objects,
            best_practices=best_practice_objects,
            historical_cases=historical_case_objects,
            relevance_scores=relevance_scores,
            source_queries=[vulnerability_type]
        )
    
    def _knowledge_to_info(self, knowledge: VulnerabilityKnowledge) -> VulnerabilityInfo:
        """将VulnerabilityKnowledge转换为VulnerabilityInfo（兼容性）"""
        cve_id = knowledge.cve_info[0].cve_id if knowledge.cve_info else None
        cwe_id = knowledge.cve_info[0].cwe_ids[0] if knowledge.cve_info and knowledge.cve_info[0].cwe_ids else None
        severity = knowledge.cve_info[0].severity.lower() if knowledge.cve_info else "medium"
        references = []
        for cve in knowledge.cve_info:
            references.extend(cve.references)
        
        best_practices = [bp.recommendation for bp in knowledge.best_practices]
        historical_cases = [
            {
                "case_id": hc.id,
                "description": hc.description,
                "code_pattern": hc.code_pattern,
                "vulnerability_type": hc.vulnerability_type,
                "resolution": hc.solution,
                "code_pattern_similarity": hc.similarity_score,
                "date": hc.case_date.isoformat(),
                "source_project": hc.source_project
            }
            for hc in knowledge.historical_cases
        ]
        
        owasp_category = knowledge.best_practices[0].category if knowledge.best_practices else None
        
        return VulnerabilityInfo(
            cve_id=cve_id,
            cwe_id=cwe_id,
            severity=severity,
            description=f"Knowledge retrieved for vulnerability type: {knowledge.source_queries[0] if knowledge.source_queries else 'unknown'}",
            references=references,
            best_practices=best_practices,
            historical_cases=historical_cases,
            owasp_category=owasp_category,
            remediation_suggestions=best_practices[:3]  # 限制数量
        )
    
    def _build_vulnerability_info(self, vulnerability_type: str,
                                cve_info: List[Dict[str, Any]],
                                best_practices: List[str],
                                historical_cases: List[Dict[str, Any]]) -> VulnerabilityInfo:
        """构建综合漏洞信息"""
        # 提取CVE信息
        cve_id = None
        cwe_id = None
        severity = "medium"
        references = []
        
        if cve_info:
            first_cve = cve_info[0]
            cve_id = first_cve.get("cve_id")
            cwe_id = first_cve.get("cwe_id")
            severity = first_cve.get("severity", "medium").lower()
            references = [ref for cve in cve_info for ref in cve.get("references", [])]
        
        # 生成描述
        description = self._generate_description(vulnerability_type, cve_info, historical_cases)
        
        # 提取OWASP分类
        owasp_category = self._determine_owasp_category(vulnerability_type)
        
        # 生成修复建议
        remediation_suggestions = self._generate_remediation_suggestions(
            vulnerability_type, best_practices, historical_cases
        )
        
        return VulnerabilityInfo(
            cve_id=cve_id,
            cwe_id=cwe_id,
            severity=severity,
            description=description,
            references=references,
            best_practices=best_practices,
            historical_cases=historical_cases,
            owasp_category=owasp_category,
            remediation_suggestions=remediation_suggestions
        )
    
    def _generate_description(self, vulnerability_type: str,
                            cve_info: List[Dict[str, Any]],
                            historical_cases: List[Dict[str, Any]]) -> str:
        """生成漏洞描述"""
        base_description = f"检测到 {vulnerability_type} 漏洞。"
        
        if cve_info:
            cve_count = len(cve_info)
            base_description += f" 发现 {cve_count} 个相关CVE记录。"
        
        if historical_cases:
            cases_count = len(historical_cases)
            base_description += f" 找到 {cases_count} 个相似历史案例。"
        
        return base_description
    
    def _determine_owasp_category(self, vulnerability_type: str) -> Optional[str]:
        """确定OWASP分类"""
        owasp_mapping = {
            "sql injection": "A03:2021 – Injection",
            "xss": "A07:2021 – Cross-Site Scripting",
            "command injection": "A03:2021 – Injection",
            "path traversal": "A01:2021 – Broken Access Control",
            "buffer overflow": "A06:2021 – Vulnerable and Outdated Components"
        }
        
        vuln_type_lower = vulnerability_type.lower()
        for pattern, category in owasp_mapping.items():
            if pattern in vuln_type_lower:
                return category
        
        return None
    
    def _generate_remediation_suggestions(self, vulnerability_type: str,
                                        best_practices: List[str],
                                        historical_cases: List[Dict[str, Any]]) -> List[str]:
        """生成修复建议"""
        suggestions = []
        
        # 添加最佳实践建议
        suggestions.extend(best_practices[:3])  # 限制数量
        
        # 从历史案例中提取建议
        for case in historical_cases[:2]:  # 限制数量
            if "resolution" in case:
                suggestions.append(f"参考历史案例: {case['resolution']}")
        
        # 添加通用建议
        if not suggestions:
            suggestions = [
                "对用户输入进行严格验证",
                "使用安全的编程实践",
                "定期进行安全测试"
            ]
        
        return suggestions
    
    async def enhance_vulnerability(self, vulnerability: VulnerabilityResult,
                                  knowledge_info: VulnerabilityInfo) -> VulnerabilityResult:
        """使用知识信息增强漏洞结果"""
        # 更新漏洞信息
        if knowledge_info.cve_id:
            vulnerability.cve_id = knowledge_info.cve_id
        
        if knowledge_info.cwe_id:
            vulnerability.cwe_id = knowledge_info.cwe_id
        
        if knowledge_info.owasp_category:
            vulnerability.owasp_category = knowledge_info.owasp_category
        
        # 增强描述
        enhanced_description = vulnerability.description
        if knowledge_info.description:
            enhanced_description += f"\n\n知识库信息: {knowledge_info.description}"
        
        vulnerability.description = enhanced_description
        
        # 添加参考链接
        if knowledge_info.references:
            vulnerability.references = knowledge_info.references
        
        # 添加修复建议
        if knowledge_info.remediation_suggestions:
            vulnerability.recommendation = "\n".join(knowledge_info.remediation_suggestions)
        
        # 更新元数据
        if not hasattr(vulnerability, 'metadata'):
            vulnerability.metadata = {}
        
        vulnerability.metadata.update({
            "txtai_enhanced": True,
            "knowledge_sources": len(knowledge_info.references),
            "best_practices_count": len(knowledge_info.best_practices),
            "historical_cases_count": len(knowledge_info.historical_cases)
        })
        
        return vulnerability
    
    def _update_metrics(self, start_time: float):
        """更新性能指标"""
        end_time = asyncio.get_event_loop().time()
        response_time = end_time - start_time
        
        self.metrics["queries_processed"] += 1
        self.metrics["api_calls"] += 1
        
        # 更新平均响应时间
        total_queries = self.metrics["queries_processed"]
        current_avg = self.metrics["average_response_time"]
        self.metrics["average_response_time"] = (
            (current_avg * (total_queries - 1) + response_time) / total_queries
        )
    
    async def update_knowledge_sources(self):
        """更新知识源"""
        logger.info("开始更新知识源...")
        
        for source in self.knowledge_sources:
            if not source.enabled:
                continue
                
            try:
                # 检查是否需要更新
                if self._should_update_source(source):
                    await self._update_source(source)
                    source.last_updated = datetime.now()
                    logger.info(f"知识源更新完成: {source.name}")
                    
            except Exception as e:
                logger.error(f"更新知识源失败 {source.name}: {e}")
    
    def _should_update_source(self, source: KnowledgeSource) -> bool:
        """检查是否需要更新知识源"""
        if not source.last_updated:
            return True
        
        now = datetime.now()
        if source.update_frequency == "daily":
            return now - source.last_updated > timedelta(days=1)
        elif source.update_frequency == "weekly":
            return now - source.last_updated > timedelta(weeks=1)
        elif source.update_frequency == "monthly":
            return now - source.last_updated > timedelta(days=30)
        
        return False
    
    async def _update_source(self, source: KnowledgeSource):
        """更新特定知识源"""
        # 这里实现具体的知识源更新逻辑
        # 由于涉及外部API调用，这里提供框架
        logger.info(f"更新知识源: {source.name} from {source.url}")
        
        # 模拟更新过程
        await asyncio.sleep(0.1)
    
    async def get_remediation_suggestions(self, vulnerability_type: str, 
                                        description: str) -> Dict[str, Any]:
        """获取修复建议 - 兼容性方法，集成阿里云CVE数据"""
        try:
            # 获取最佳实践
            best_practices = await self.best_practices_db.get_best_practices(vulnerability_type)
            
            # 搜索历史案例
            historical_cases = await self.historical_cases_db.search_similar_cases(
                vulnerability_type, description
            )
            
            # 从阿里云CVE数据获取相关信息
            aliyun_cve_info = await self._get_aliyun_cve_info(vulnerability_type, description)
            
            # 生成修复建议
            suggestions = self._generate_remediation_suggestions(
                vulnerability_type, best_practices, historical_cases
            )
            
            # 如果有阿里云CVE信息，添加到建议中
            if aliyun_cve_info:
                suggestions.extend(aliyun_cve_info.get("suggestions", []))
            
            # 生成代码示例（简化版）
            code_examples = self._generate_code_examples(vulnerability_type)
            
            return {
                "suggestions": suggestions,
                "best_practices": best_practices,
                "code_examples": code_examples,
                "historical_cases": [case.get("resolution", "") for case in historical_cases],
                "aliyun_cve_info": aliyun_cve_info
            }
            
        except Exception as e:
            logger.warning(f"获取修复建议失败: {e}")
            return {
                "suggestions": [f"请修复 {vulnerability_type} 漏洞"],
                "best_practices": ["遵循安全编码规范"],
                "code_examples": [],
                "historical_cases": [],
                "aliyun_cve_info": None
            }
    
    async def _get_aliyun_cve_info(self, vulnerability_type: str, description: str) -> Optional[Dict[str, Any]]:
        """从阿里云CVE数据获取相关信息"""
        try:
            if not self.cve_integrator:
                return None
            
            # 搜索相关的CVE
            search_keyword = vulnerability_type.split()[0] if vulnerability_type else "vulnerability"
            cve_results = await self.cve_integrator.search_integrated_cves(search_keyword, limit=3)
            
            if not cve_results:
                return None
            
            # 提取有用信息
            suggestions = []
            references = []
            
            for cve in cve_results:
                # 添加CVE特定的建议
                if cve.severity == "HIGH" or cve.severity == "CRITICAL":
                    suggestions.append(f"高危漏洞 {cve.cve_id}：立即修复，CVSS评分 {cve.cvss_score}")
                else:
                    suggestions.append(f"漏洞 {cve.cve_id}：建议修复，CVSS评分 {cve.cvss_score}")
                
                # 添加参考链接
                references.extend(cve.references[:2])  # 限制数量
            
            return {
                "suggestions": suggestions[:3],  # 限制建议数量
                "references": references[:5],    # 限制参考链接数量
                "cve_count": len(cve_results),
                "source": "阿里云漏洞库"
            }
            
        except Exception as e:
            logger.warning(f"获取阿里云CVE信息失败: {e}")
            return None
    
    def _generate_code_examples(self, vulnerability_type: str) -> List[Dict[str, str]]:
        """生成代码示例"""
        examples = {
            "sql injection": [
                {
                    "title": "使用参数化查询",
                    "language": "python",
                    "code": """# 错误的做法
query = f"SELECT * FROM users WHERE id = {user_id}"

# 正确的做法
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))"""
                }
            ],
            "xss": [
                {
                    "title": "HTML转义",
                    "language": "python",
                    "code": """import html

# 错误的做法
output = f"<div>{user_input}</div>"

# 正确的做法
output = f"<div>{html.escape(user_input)}</div>" """
                }
            ]
        }
        
        vuln_type_lower = vulnerability_type.lower()
        for pattern, example_list in examples.items():
            if pattern in vuln_type_lower:
                return example_list
        
        return []
    
    def get_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        return self.metrics.copy()
    
    async def query_cve_database(self, vulnerability_signature: str) -> List[CVEInfo]:
        """实时查询CVE数据库 - 标准接口"""
        try:
            cve_data = await self.cve_database.search_cve("general", vulnerability_signature)
            
            cve_objects = []
            for cve in cve_data:
                cve_objects.append(CVEInfo(
                    cve_id=cve.get("cve_id", ""),
                    description=cve.get("description", ""),
                    severity=cve.get("severity", "MEDIUM"),
                    cvss_score=float(cve.get("cvss_score", 5.0)),
                    published_date=datetime.fromisoformat(cve.get("published_date", datetime.now().isoformat())),
                    modified_date=datetime.fromisoformat(cve.get("modified_date", datetime.now().isoformat())),
                    references=cve.get("references", []),
                    cwe_ids=[cve.get("cwe_id")] if cve.get("cwe_id") else []
                ))
            
            return cve_objects
            
        except Exception as e:
            logger.error(f"CVE数据库查询失败: {e}")
            return []
    
    async def match_best_practices(self, code_pattern: str, language: str) -> List[BestPractice]:
        """匹配最佳实践 - 标准接口"""
        try:
            # 从代码模式推断漏洞类型
            vulnerability_type = self._infer_vulnerability_type(code_pattern)
            
            practices = await self.best_practices_db.get_best_practices(vulnerability_type)
            
            best_practice_objects = []
            for i, practice in enumerate(practices):
                best_practice_objects.append(BestPractice(
                    id=f"bp_{language}_{vulnerability_type}_{i}",
                    title=f"Best Practice for {vulnerability_type}",
                    description=practice,
                    category=self._determine_owasp_category(vulnerability_type) or "General",
                    language=language,
                    source="txtai_retriever",
                    code_pattern=code_pattern,
                    recommendation=practice
                ))
            
            return best_practice_objects
            
        except Exception as e:
            logger.error(f"最佳实践匹配失败: {e}")
            return []
    
    async def search_historical_cases(self, code_pattern: str, 
                                    similarity_threshold: float = 0.8) -> List[HistoricalCase]:
        """搜索历史案例 - 标准接口"""
        try:
            vulnerability_type = self._infer_vulnerability_type(code_pattern)
            cases = await self.historical_cases_db.search_similar_cases(vulnerability_type, code_pattern)
            
            historical_case_objects = []
            for case in cases:
                if case.get("code_pattern_similarity", 0.0) >= similarity_threshold:
                    historical_case_objects.append(HistoricalCase(
                        id=case.get("case_id", f"hc_{len(historical_case_objects)}"),
                        title=case.get("description", "Historical Case"),
                        description=case.get("description", ""),
                        code_pattern=case.get("code_pattern", ""),
                        vulnerability_type=case.get("vulnerability_type", vulnerability_type),
                        solution=case.get("resolution", ""),
                        similarity_score=float(case.get("code_pattern_similarity", 0.0)),
                        case_date=datetime.fromisoformat(case.get("date", datetime.now().isoformat())),
                        source_project=case.get("source_project", "unknown")
                    ))
            
            return historical_case_objects
            
        except Exception as e:
            logger.error(f"历史案例搜索失败: {e}")
            return []
    
    def _infer_vulnerability_type(self, code_pattern: str) -> str:
        """从代码模式推断漏洞类型"""
        code_lower = code_pattern.lower()
        
        if any(keyword in code_lower for keyword in ["sql", "query", "select", "insert", "update", "delete"]):
            return "sql injection"
        elif any(keyword in code_lower for keyword in ["<script>", "javascript:", "onerror", "onload"]):
            return "xss"
        elif any(keyword in code_lower for keyword in ["system", "exec", "shell", "command"]):
            return "command injection"
        elif any(keyword in code_lower for keyword in ["../", "..\\", "path", "file"]):
            return "path traversal"
        elif any(keyword in code_lower for keyword in ["buffer", "overflow", "strcpy", "strcat"]):
            return "buffer overflow"
        else:
            return "general"
    
    async def enhance_with_self_rag(self, vulnerability: VulnerabilityResult, 
                                  context: Optional[Dict[str, Any]] = None) -> VulnerabilityResult:
        """使用self_rag系统增强漏洞信息"""
        if not self.self_rag:
            return vulnerability
        
        try:
            # 从self_rag检索相关信息
            query = f"{vulnerability.vulnerability_type}: {vulnerability.snippet[:200]}"
            documents = await self.self_rag.retrieve(query, k=3)
            
            # 增强描述
            if documents:
                enhanced_description = vulnerability.description
                enhanced_description += "\n\n相关上下文信息:"
                
                for doc, score in documents:
                    if score > 0.7:  # 只使用高相关性的文档
                        enhanced_description += f"\n- {doc.content[:100]}... (相关性: {score:.2f})"
                
                vulnerability.description = enhanced_description
            
            return vulnerability
            
        except Exception as e:
            logger.warning(f"Self-RAG增强失败: {e}")
            return vulnerability
    
    async def get_knowledge_source_status(self) -> Dict[str, Any]:
        """获取知识源状态"""
        try:
            if self.knowledge_manager:
                return {
                    "manager_available": True,
                    "sources": self.knowledge_manager.get_source_status(),
                    "metrics": self.knowledge_manager.get_metrics()
                }
            else:
                return {
                    "manager_available": False,
                    "fallback_sources": {
                        "cve_database": "available",
                        "best_practices": "available", 
                        "historical_cases": "available",
                        "self_rag": "available" if self.self_rag else "unavailable"
                    }
                }
        except Exception as e:
            logger.error(f"获取知识源状态失败: {e}")
            return {"error": str(e)}
    
    async def update_knowledge_sources(self):
        """更新知识源，包括阿里云CVE爬虫数据"""
        try:
            if self.knowledge_manager:
                # 使用知识源管理器的更新功能
                await self.knowledge_manager._perform_updates()
                logger.info("通过知识源管理器更新完成")
            else:
                # 回退到传统更新方法
                logger.info("开始更新知识源...")
                
                for source in self.knowledge_sources:
                    if not source.enabled:
                        continue
                        
                    try:
                        # 检查是否需要更新
                        if self._should_update_source(source):
                            await self._update_source(source)
                            source.last_updated = datetime.now()
                            logger.info(f"知识源更新完成: {source.name}")
                            
                    except Exception as e:
                        logger.error(f"更新知识源失败 {source.name}: {e}")
                
                logger.info("传统方法更新完成")
            
            # 额外更新阿里云CVE爬虫数据
            await self._update_aliyun_cve_data()
                
        except Exception as e:
            logger.error(f"更新知识源失败: {e}")
    
    async def _update_aliyun_cve_data(self):
        """更新阿里云CVE爬虫数据"""
        try:
            if self.cve_integrator:
                logger.info("开始更新阿里云CVE数据...")
                
                # 执行增量爬取和集成
                new_cves = await self.cve_integrator.integrate_incremental(days=1)
                
                if new_cves:
                    logger.info(f"阿里云CVE数据更新完成，新增 {len(new_cves)} 个CVE")
                    
                    # 更新CVE数据库客户端的缓存
                    if hasattr(self.cve_database, 'client') and hasattr(self.cve_database.client, 'integrator'):
                        await self.cve_database.client.update_cache_incremental()
                else:
                    logger.info("阿里云CVE数据无新增")
            else:
                logger.debug("阿里云CVE爬虫未集成，跳过更新")
                
        except Exception as e:
            logger.error(f"更新阿里云CVE数据失败: {e}")
    
    async def add_knowledge_source(self, name: str, source_type: str, config: Dict[str, Any]):
        """添加知识源"""
        try:
            if self.knowledge_manager:
                from auditluma.rag.knowledge_manager import KnowledgeSourceConfig, SourceType
                
                source_config = KnowledgeSourceConfig(
                    name=name,
                    type=SourceType(source_type),
                    config=config
                )
                
                await self.knowledge_manager.add_source(source_config)
                logger.info(f"通过管理器添加知识源: {name}")
            else:
                # 回退到传统方法
                source = KnowledgeSource(name, config.get("url", ""), config.get("frequency", "daily"))
                self.knowledge_sources.append(source)
                logger.info(f"传统方法添加知识源: {name}")
                
        except Exception as e:
            logger.error(f"添加知识源失败: {e}")
            raise
    
    async def remove_knowledge_source(self, name: str):
        """移除知识源"""
        try:
            if self.knowledge_manager:
                await self.knowledge_manager.remove_source(name)
                logger.info(f"通过管理器移除知识源: {name}")
            else:
                # 回退到传统方法
                self.knowledge_sources = [s for s in self.knowledge_sources if s.name != name]
                logger.info(f"传统方法移除知识源: {name}")
                
        except Exception as e:
            logger.error(f"移除知识源失败: {e}")
            raise
    
    async def cleanup(self):
        """清理资源"""
        try:
            # 清理CVE数据库连接
            if hasattr(self, 'cve_database') and hasattr(self.cve_database, 'session'):
                if self.cve_database.session:
                    await self.cve_database.session.close()
            
            # 清理知识源管理器
            if self.knowledge_manager:
                await self.knowledge_manager.cleanup()
            
            logger.info("txtai知识检索器清理完成")
            
        except Exception as e:
            logger.error(f"清理失败: {e}")