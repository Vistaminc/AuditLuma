"""
知识源管理器 - 实现多知识源的统一查询和结果合并

本模块提供知识源管理功能，包括：
- 多知识源的统一查询和结果合并
- 知识源的定时更新和健康检查
- 知识源配置管理
- 查询结果的智能合并和去重
"""

import asyncio
import json
import aiofiles
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import os
from enum import Enum
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import threading

from loguru import logger

from auditluma.models.hierarchical_rag import (
    VulnerabilityKnowledge, CVEInfo, BestPractice, HistoricalCase
)
from auditluma.rag.cve_client import CVEDatabaseClient
from auditluma.crawlers.cve_knowledge_integrator import CVEKnowledgeIntegrator
from auditluma.rag.best_practices import BestPracticesIndex
from auditluma.rag.historical_cases import HistoricalCasesIndex


class SourceType(str, Enum):
    """知识源类型"""
    CVE_DATABASE = "cve_database"
    BEST_PRACTICES = "best_practices"
    HISTORICAL_CASES = "historical_cases"
    SELF_RAG = "self_rag"
    EXTERNAL_API = "external_api"


class SourceStatus(str, Enum):
    """知识源状态"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DISABLED = "disabled"


@dataclass
class KnowledgeSourceConfig:
    """知识源配置"""
    name: str
    type: SourceType
    enabled: bool = True
    priority: int = 1  # 优先级，数字越小优先级越高
    timeout: int = 30  # 查询超时时间（秒）
    retry_count: int = 3  # 重试次数
    cache_ttl: int = 3600  # 缓存TTL（秒）
    health_check_interval: int = 300  # 健康检查间隔（秒）
    update_interval: int = 86400  # 更新间隔（秒）
    config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'name': self.name,
            'type': self.type.value,
            'enabled': self.enabled,
            'priority': self.priority,
            'timeout': self.timeout,
            'retry_count': self.retry_count,
            'cache_ttl': self.cache_ttl,
            'health_check_interval': self.health_check_interval,
            'update_interval': self.update_interval,
            'config': self.config
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KnowledgeSourceConfig':
        """从字典反序列化"""
        return cls(
            name=data['name'],
            type=SourceType(data['type']),
            enabled=data.get('enabled', True),
            priority=data.get('priority', 1),
            timeout=data.get('timeout', 30),
            retry_count=data.get('retry_count', 3),
            cache_ttl=data.get('cache_ttl', 3600),
            health_check_interval=data.get('health_check_interval', 300),
            update_interval=data.get('update_interval', 86400),
            config=data.get('config', {})
        )


@dataclass
class SourceHealthStatus:
    """知识源健康状态"""
    source_name: str
    status: SourceStatus
    last_check: datetime
    response_time: float
    error_message: Optional[str] = None
    success_rate: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'source_name': self.source_name,
            'status': self.status.value,
            'last_check': self.last_check.isoformat(),
            'response_time': self.response_time,
            'error_message': self.error_message,
            'success_rate': self.success_rate,
            'metadata': self.metadata
        }


@dataclass
class QueryResult:
    """查询结果"""
    source_name: str
    source_type: SourceType
    success: bool
    response_time: float
    data: Any = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class KnowledgeSourceManager:
    """知识源管理器 - 核心管理系统"""
    
    def __init__(self):
        """初始化知识源管理器"""
        self.sources: Dict[str, KnowledgeSourceConfig] = {}
        self.source_instances: Dict[str, Any] = {}
        self.health_status: Dict[str, SourceHealthStatus] = {}
        
        # 数据目录
        self.data_dir = Path("./data/knowledge_sources")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # 配置文件
        self.config_file = self.data_dir / "sources_config.json"
        
        # 缓存
        self.query_cache: Dict[str, Tuple[datetime, Any]] = {}
        self.max_cache_size = 1000
        
        # 性能指标
        self.metrics = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "cache_hits": 0,
            "average_response_time": 0.0,
            "last_health_check": None
        }
        
        # 健康检查任务
        self.health_check_task = None
        self.update_task = None
        
        # 线程池
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # 初始化
        asyncio.create_task(self._initialize())
        
        logger.info("知识源管理器初始化完成")
    
    async def _initialize(self):
        """初始化管理器"""
        try:
            # 加载配置
            await self._load_config()
            
            # 如果没有配置，创建默认配置
            if not self.sources:
                await self._create_default_config()
            
            # 初始化知识源实例
            await self._initialize_sources()
            
            # 启动健康检查
            await self._start_health_check()
            
            # 启动更新任务
            await self._start_update_task()
            
            logger.info(f"初始化了 {len(self.sources)} 个知识源")
            
        except Exception as e:
            logger.error(f"知识源管理器初始化失败: {e}")
    
    async def _load_config(self):
        """加载配置"""
        try:
            if self.config_file.exists():
                async with aiofiles.open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.loads(await f.read())
                
                self.sources = {}
                for source_data in data.get("sources", []):
                    config = KnowledgeSourceConfig.from_dict(source_data)
                    self.sources[config.name] = config
                
                logger.info(f"加载了 {len(self.sources)} 个知识源配置")
            
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
    
    async def _create_default_config(self):
        """创建默认配置"""
        default_sources = [
            KnowledgeSourceConfig(
                name="cve_database",
                type=SourceType.CVE_DATABASE,
                priority=1,
                timeout=30,
                config={"rate_limit": 50}
            ),
            KnowledgeSourceConfig(
                name="best_practices",
                type=SourceType.BEST_PRACTICES,
                priority=2,
                timeout=10,
                config={"include_owasp": True, "include_sans": True, "include_nist": True}
            ),
            KnowledgeSourceConfig(
                name="historical_cases",
                type=SourceType.HISTORICAL_CASES,
                priority=3,
                timeout=15,
                config={"similarity_threshold": 0.3}
            ),
            KnowledgeSourceConfig(
                name="self_rag",
                type=SourceType.SELF_RAG,
                priority=4,
                timeout=20,
                config={"max_results": 5}
            )
        ]
        
        for source in default_sources:
            self.sources[source.name] = source
        
        await self._save_config()
    
    async def _initialize_sources(self):
        """初始化知识源实例"""
        for name, config in self.sources.items():
            try:
                if config.type == SourceType.CVE_DATABASE:
                    # 集成阿里云CVE爬虫
                    cve_client = CVEDatabaseClient()
                    cve_integrator = CVEKnowledgeIntegrator()
                    # 将爬虫集成器附加到CVE客户端
                    cve_client.integrator = cve_integrator
                    self.source_instances[name] = cve_client
                elif config.type == SourceType.BEST_PRACTICES:
                    self.source_instances[name] = BestPracticesIndex()
                elif config.type == SourceType.HISTORICAL_CASES:
                    self.source_instances[name] = HistoricalCasesIndex()
                elif config.type == SourceType.SELF_RAG:
                    try:
                        from auditluma.rag.enhanced_self_rag import enhanced_self_rag as self_rag
                        self.source_instances[name] = self_rag
                    except ImportError:
                        logger.warning(f"无法导入self_rag，跳过源: {name}")
                        config.enabled = False
                
                logger.info(f"初始化知识源: {name}")
                
            except Exception as e:
                logger.error(f"初始化知识源失败 {name}: {e}")
                config.enabled = False
    
    async def query_all_sources(self, query: str, 
                              vulnerability_type: Optional[str] = None,
                              context: Optional[Dict[str, Any]] = None) -> VulnerabilityKnowledge:
        """查询所有知识源"""
        try:
            self.metrics["total_queries"] += 1
            start_time = asyncio.get_event_loop().time()
            
            # 检查缓存
            cache_key = self._generate_cache_key(query, vulnerability_type, context)
            cached_result = self._get_from_cache(cache_key)
            if cached_result:
                self.metrics["cache_hits"] += 1
                return cached_result
            
            # 获取启用的源
            enabled_sources = [
                (name, config) for name, config in self.sources.items()
                if config.enabled and name in self.source_instances
            ]
            
            # 按优先级排序
            enabled_sources.sort(key=lambda x: x[1].priority)
            
            # 并行查询所有源
            query_tasks = []
            for name, config in enabled_sources:
                task = self._query_source(name, config, query, vulnerability_type, context)
                query_tasks.append(task)
            
            # 等待所有查询完成
            query_results = await asyncio.gather(*query_tasks, return_exceptions=True)
            
            # 处理结果
            successful_results = []
            failed_count = 0
            
            for i, result in enumerate(query_results):
                if isinstance(result, Exception):
                    logger.warning(f"查询源失败 {enabled_sources[i][0]}: {result}")
                    failed_count += 1
                elif isinstance(result, QueryResult) and result.success:
                    successful_results.append(result)
                else:
                    failed_count += 1
            
            # 合并结果
            merged_knowledge = await self._merge_query_results(successful_results)
            
            # 更新指标
            self.metrics["successful_queries"] += len(successful_results)
            self.metrics["failed_queries"] += failed_count
            
            end_time = asyncio.get_event_loop().time()
            response_time = end_time - start_time
            
            # 更新平均响应时间
            total_queries = self.metrics["total_queries"]
            current_avg = self.metrics["average_response_time"]
            self.metrics["average_response_time"] = (
                (current_avg * (total_queries - 1) + response_time) / total_queries
            )
            
            # 设置检索时间
            merged_knowledge.retrieval_time = response_time
            merged_knowledge.source_queries = [query]
            
            # 缓存结果
            self._save_to_cache(cache_key, merged_knowledge)
            
            return merged_knowledge
            
        except Exception as e:
            logger.error(f"查询所有源失败: {e}")
            self.metrics["failed_queries"] += 1
            return VulnerabilityKnowledge()
    
    async def _query_source(self, name: str, config: KnowledgeSourceConfig,
                          query: str, vulnerability_type: Optional[str],
                          context: Optional[Dict[str, Any]]) -> QueryResult:
        """查询单个知识源"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            source_instance = self.source_instances[name]
            
            # 根据源类型调用不同的查询方法
            if config.type == SourceType.CVE_DATABASE:
                async with source_instance:
                    data = await asyncio.wait_for(
                        source_instance.query_cve_by_keyword(query, limit=10),
                        timeout=config.timeout
                    )
            
            elif config.type == SourceType.BEST_PRACTICES:
                if vulnerability_type:
                    data = await asyncio.wait_for(
                        source_instance.get_practices_by_vulnerability_type(vulnerability_type),
                        timeout=config.timeout
                    )
                else:
                    data = await asyncio.wait_for(
                        source_instance.match_best_practices(query, "general"),
                        timeout=config.timeout
                    )
            
            elif config.type == SourceType.HISTORICAL_CASES:
                if vulnerability_type:
                    data = await asyncio.wait_for(
                        source_instance.search_similar_cases(
                            query, vulnerability_type,
                            similarity_threshold=config.config.get("similarity_threshold", 0.3)
                        ),
                        timeout=config.timeout
                    )
                else:
                    data = []
            
            elif config.type == SourceType.SELF_RAG:
                if hasattr(source_instance, 'retrieve'):
                    documents = await asyncio.wait_for(
                        source_instance.retrieve(query, k=config.config.get("max_results", 5)),
                        timeout=config.timeout
                    )
                    data = documents
                else:
                    data = []
            
            else:
                data = []
            
            end_time = asyncio.get_event_loop().time()
            response_time = end_time - start_time
            
            return QueryResult(
                source_name=name,
                source_type=config.type,
                success=True,
                response_time=response_time,
                data=data
            )
            
        except asyncio.TimeoutError:
            end_time = asyncio.get_event_loop().time()
            response_time = end_time - start_time
            
            return QueryResult(
                source_name=name,
                source_type=config.type,
                success=False,
                response_time=response_time,
                error_message="查询超时"
            )
            
        except Exception as e:
            end_time = asyncio.get_event_loop().time()
            response_time = end_time - start_time
            
            return QueryResult(
                source_name=name,
                source_type=config.type,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _merge_query_results(self, results: List[QueryResult]) -> VulnerabilityKnowledge:
        """合并查询结果"""
        try:
            merged_knowledge = VulnerabilityKnowledge()
            relevance_scores = {}
            
            for result in results:
                if not result.data:
                    continue
                
                # 根据源类型处理数据
                if result.source_type == SourceType.CVE_DATABASE:
                    if isinstance(result.data, list):
                        merged_knowledge.cve_info.extend(result.data)
                        relevance_scores[f"cve_{result.source_name}"] = 0.9
                
                elif result.source_type == SourceType.BEST_PRACTICES:
                    if isinstance(result.data, list):
                        merged_knowledge.best_practices.extend(result.data)
                        relevance_scores[f"practices_{result.source_name}"] = 0.8
                
                elif result.source_type == SourceType.HISTORICAL_CASES:
                    if isinstance(result.data, list):
                        merged_knowledge.historical_cases.extend(result.data)
                        relevance_scores[f"cases_{result.source_name}"] = 0.7
                
                elif result.source_type == SourceType.SELF_RAG:
                    # Self-RAG结果需要特殊处理
                    relevance_scores[f"self_rag_{result.source_name}"] = 0.6
            
            # 去重和排序
            merged_knowledge = await self._deduplicate_and_sort(merged_knowledge)
            
            # 设置相关性分数
            merged_knowledge.relevance_scores = relevance_scores
            
            return merged_knowledge
            
        except Exception as e:
            logger.error(f"合并查询结果失败: {e}")
            return VulnerabilityKnowledge()
    
    async def _deduplicate_and_sort(self, knowledge: VulnerabilityKnowledge) -> VulnerabilityKnowledge:
        """去重和排序"""
        try:
            # CVE去重
            seen_cve_ids = set()
            unique_cves = []
            for cve in knowledge.cve_info:
                if cve.cve_id not in seen_cve_ids:
                    seen_cve_ids.add(cve.cve_id)
                    unique_cves.append(cve)
            
            # 按发布日期排序
            unique_cves.sort(key=lambda x: x.published_date, reverse=True)
            knowledge.cve_info = unique_cves
            
            # 最佳实践去重
            seen_practice_ids = set()
            unique_practices = []
            for practice in knowledge.best_practices:
                if practice.id not in seen_practice_ids:
                    seen_practice_ids.add(practice.id)
                    unique_practices.append(practice)
            
            # 按来源和类别排序
            unique_practices.sort(key=lambda x: (x.source, x.category))
            knowledge.best_practices = unique_practices
            
            # 历史案例去重
            seen_case_ids = set()
            unique_cases = []
            for case in knowledge.historical_cases:
                if case.id not in seen_case_ids:
                    seen_case_ids.add(case.id)
                    unique_cases.append(case)
            
            # 按相似性分数排序
            unique_cases.sort(key=lambda x: x.similarity_score, reverse=True)
            knowledge.historical_cases = unique_cases
            
            return knowledge
            
        except Exception as e:
            logger.error(f"去重和排序失败: {e}")
            return knowledge
    
    def _generate_cache_key(self, query: str, 
                          vulnerability_type: Optional[str],
                          context: Optional[Dict[str, Any]]) -> str:
        """生成缓存键"""
        key_parts = [query]
        if vulnerability_type:
            key_parts.append(vulnerability_type)
        if context:
            key_parts.append(json.dumps(context, sort_keys=True))
        
        key_string = "_".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_from_cache(self, cache_key: str) -> Optional[VulnerabilityKnowledge]:
        """从缓存获取结果"""
        if cache_key in self.query_cache:
            timestamp, data = self.query_cache[cache_key]
            
            # 检查是否过期
            if datetime.now() - timestamp < timedelta(seconds=3600):  # 1小时缓存
                return data
            else:
                del self.query_cache[cache_key]
        
        return None
    
    def _save_to_cache(self, cache_key: str, data: VulnerabilityKnowledge):
        """保存到缓存"""
        # 检查缓存大小
        if len(self.query_cache) >= self.max_cache_size:
            # 删除最旧的条目
            oldest_key = min(self.query_cache.keys(), 
                           key=lambda k: self.query_cache[k][0])
            del self.query_cache[oldest_key]
        
        self.query_cache[cache_key] = (datetime.now(), data)
    
    async def _start_health_check(self):
        """启动健康检查任务"""
        async def health_check_loop():
            while True:
                try:
                    await self._perform_health_check()
                    await asyncio.sleep(300)  # 5分钟检查一次
                except Exception as e:
                    logger.error(f"健康检查失败: {e}")
                    await asyncio.sleep(60)  # 出错后1分钟重试
        
        self.health_check_task = asyncio.create_task(health_check_loop())
    
    async def _perform_health_check(self):
        """执行健康检查"""
        try:
            self.metrics["last_health_check"] = datetime.now()
            
            for name, config in self.sources.items():
                if not config.enabled or name not in self.source_instances:
                    continue
                
                start_time = asyncio.get_event_loop().time()
                
                try:
                    # 执行简单的健康检查查询
                    await self._query_source(name, config, "test", None, None)
                    
                    end_time = asyncio.get_event_loop().time()
                    response_time = end_time - start_time
                    
                    # 更新健康状态
                    self.health_status[name] = SourceHealthStatus(
                        source_name=name,
                        status=SourceStatus.HEALTHY,
                        last_check=datetime.now(),
                        response_time=response_time
                    )
                    
                except Exception as e:
                    self.health_status[name] = SourceHealthStatus(
                        source_name=name,
                        status=SourceStatus.UNHEALTHY,
                        last_check=datetime.now(),
                        response_time=0.0,
                        error_message=str(e)
                    )
            
            logger.debug("健康检查完成")
            
        except Exception as e:
            logger.error(f"健康检查执行失败: {e}")
    
    async def _start_update_task(self):
        """启动更新任务"""
        async def update_loop():
            while True:
                try:
                    await self._perform_updates()
                    await asyncio.sleep(86400)  # 24小时更新一次
                except Exception as e:
                    logger.error(f"更新任务失败: {e}")
                    await asyncio.sleep(3600)  # 出错后1小时重试
        
        self.update_task = asyncio.create_task(update_loop())
    
    async def _perform_updates(self):
        """执行更新，包括阿里云CVE爬虫数据"""
        try:
            logger.info("开始更新知识源")
            
            for name, config in self.sources.items():
                if not config.enabled or name not in self.source_instances:
                    continue
                
                try:
                    source_instance = self.source_instances[name]
                    
                    # 根据源类型执行更新
                    if config.type == SourceType.CVE_DATABASE:
                        # 更新CVE数据库，包括爬虫数据
                        if hasattr(source_instance, 'update_cache_incremental'):
                            await source_instance.update_cache_incremental()
                        
                        # 如果有集成的爬虫，也执行爬虫更新
                        if hasattr(source_instance, 'integrator') and source_instance.integrator:
                            try:
                                logger.info("执行阿里云CVE爬虫增量更新...")
                                new_cves = await source_instance.integrator.integrate_incremental(days=1)
                                logger.info(f"阿里云CVE爬虫更新完成，新增 {len(new_cves)} 个CVE")
                            except Exception as e:
                                logger.warning(f"阿里云CVE爬虫更新失败: {e}")
                    
                    elif config.type == SourceType.BEST_PRACTICES:
                        if hasattr(source_instance, 'update_rules_from_source'):
                            from auditluma.rag.best_practices import StandardSource
                            await source_instance.update_rules_from_source(StandardSource.OWASP)
                    
                    logger.info(f"更新知识源完成: {name}")
                    
                except Exception as e:
                    logger.error(f"更新知识源失败 {name}: {e}")
            
            logger.info("知识源更新完成")
            
        except Exception as e:
            logger.error(f"执行更新失败: {e}")
    
    async def add_source(self, config: KnowledgeSourceConfig):
        """添加知识源"""
        try:
            if config.name in self.sources:
                raise ValueError(f"知识源已存在: {config.name}")
            
            self.sources[config.name] = config
            
            # 初始化源实例
            await self._initialize_sources()
            
            # 保存配置
            await self._save_config()
            
            logger.info(f"添加知识源: {config.name}")
            
        except Exception as e:
            logger.error(f"添加知识源失败: {e}")
            raise
    
    async def remove_source(self, name: str):
        """移除知识源"""
        try:
            if name not in self.sources:
                raise ValueError(f"知识源不存在: {name}")
            
            # 移除配置和实例
            del self.sources[name]
            if name in self.source_instances:
                del self.source_instances[name]
            if name in self.health_status:
                del self.health_status[name]
            
            # 保存配置
            await self._save_config()
            
            logger.info(f"移除知识源: {name}")
            
        except Exception as e:
            logger.error(f"移除知识源失败: {e}")
            raise
    
    async def update_source_config(self, name: str, config: KnowledgeSourceConfig):
        """更新知识源配置"""
        try:
            if name not in self.sources:
                raise ValueError(f"知识源不存在: {name}")
            
            self.sources[name] = config
            
            # 重新初始化源实例
            await self._initialize_sources()
            
            # 保存配置
            await self._save_config()
            
            logger.info(f"更新知识源配置: {name}")
            
        except Exception as e:
            logger.error(f"更新知识源配置失败: {e}")
            raise
    
    async def _save_config(self):
        """保存配置"""
        try:
            data = {
                "sources": [config.to_dict() for config in self.sources.values()],
                "metadata": {
                    "total_sources": len(self.sources),
                    "last_updated": datetime.now().isoformat()
                }
            }
            
            async with aiofiles.open(self.config_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
    
    def get_source_status(self) -> Dict[str, SourceHealthStatus]:
        """获取所有源的健康状态"""
        return {name: status for name, status in self.health_status.items()}
    
    def get_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        return self.metrics.copy()
    
    def get_source_configs(self) -> Dict[str, KnowledgeSourceConfig]:
        """获取所有源配置"""
        return self.sources.copy()
    
    async def cleanup(self):
        """清理资源"""
        try:
            # 取消任务
            if self.health_check_task:
                self.health_check_task.cancel()
            if self.update_task:
                self.update_task.cancel()
            
            # 关闭线程池
            self.executor.shutdown(wait=True)
            
            # 清理源实例
            for name, instance in self.source_instances.items():
                if hasattr(instance, 'cleanup'):
                    await instance.cleanup()
            
            logger.info("知识源管理器清理完成")
            
        except Exception as e:
            logger.error(f"清理失败: {e}")


# 全局知识源管理器实例
knowledge_manager = KnowledgeSourceManager()