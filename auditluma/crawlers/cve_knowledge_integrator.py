"""
CVE知识库集成器 - 将爬取的CVE数据集成到知识库系统

本模块提供CVE数据与知识库的集成功能，包括：
- 爬取数据的自动导入
- 与现有CVE客户端的集成
- 数据去重和更新机制
- 定时爬取和更新任务
"""

import asyncio
import json
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from pathlib import Path
import os

from loguru import logger

from auditluma.models.hierarchical_rag import CVEInfo
from auditluma.crawlers.aliyun_cve_crawler import AliyunCVECrawler, CrawlConfig
from auditluma.rag.cve_client import CVEDatabaseClient


class CVEKnowledgeIntegrator:
    """CVE知识库集成器"""
    
    def __init__(self):
        """初始化集成器"""
        self.crawler_config = CrawlConfig()
        self.data_dir = Path("./data/integrated_cve")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # 集成状态
        self.last_crawl_time: Optional[datetime] = None
        self.integrated_cves: Set[str] = set()
        
        # 性能指标
        self.metrics = {
            "total_crawled": 0,
            "total_integrated": 0,
            "duplicates_skipped": 0,
            "errors": 0,
            "last_update": None
        }
        
        logger.info("CVE知识库集成器初始化完成")
    
    async def integrate_from_crawler(self, max_pages: int = 5) -> List[CVEInfo]:
        """从爬虫集成CVE数据"""
        try:
            logger.info(f"开始从阿里云爬取CVE数据，最大页数: {max_pages}")
            
            # 使用爬虫获取数据
            async with AliyunCVECrawler(self.crawler_config) as crawler:
                cve_infos = await crawler.crawl_all(max_pages=max_pages)
            
            self.metrics["total_crawled"] = len(cve_infos)
            
            # 集成到知识库
            integrated_cves = await self._integrate_cve_data(cve_infos)
            
            self.metrics["total_integrated"] = len(integrated_cves)
            self.metrics["last_update"] = datetime.now()
            self.last_crawl_time = datetime.now()
            
            logger.info(f"集成完成，爬取: {len(cve_infos)}, 集成: {len(integrated_cves)}")
            
            return integrated_cves
            
        except Exception as e:
            logger.error(f"从爬虫集成CVE数据失败: {e}")
            self.metrics["errors"] += 1
            raise
    
    async def integrate_incremental(self, days: int = 1) -> List[CVEInfo]:
        """增量集成CVE数据"""
        try:
            since_date = datetime.now() - timedelta(days=days)
            logger.info(f"开始增量集成CVE数据，起始日期: {since_date.strftime('%Y-%m-%d')}")
            
            # 使用爬虫获取增量数据
            async with AliyunCVECrawler(self.crawler_config) as crawler:
                cve_infos = await crawler.crawl_incremental(since_date)
            
            if not cve_infos:
                logger.info("没有新的CVE数据需要集成")
                return []
            
            self.metrics["total_crawled"] += len(cve_infos)
            
            # 集成到知识库
            integrated_cves = await self._integrate_cve_data(cve_infos)
            
            self.metrics["total_integrated"] += len(integrated_cves)
            self.metrics["last_update"] = datetime.now()
            self.last_crawl_time = datetime.now()
            
            logger.info(f"增量集成完成，新增: {len(integrated_cves)}")
            
            return integrated_cves
            
        except Exception as e:
            logger.error(f"增量集成CVE数据失败: {e}")
            self.metrics["errors"] += 1
            raise
    
    async def _integrate_cve_data(self, cve_infos: List[CVEInfo]) -> List[CVEInfo]:
        """集成CVE数据到知识库"""
        try:
            # 去重处理
            unique_cves = await self._deduplicate_cves(cve_infos)
            
            # 保存到本地知识库
            await self._save_to_knowledge_base(unique_cves)
            
            # 更新集成状态
            for cve in unique_cves:
                self.integrated_cves.add(cve.cve_id)
            
            return unique_cves
            
        except Exception as e:
            logger.error(f"集成CVE数据失败: {e}")
            raise
    
    async def _deduplicate_cves(self, cve_infos: List[CVEInfo]) -> List[CVEInfo]:
        """去重CVE数据"""
        try:
            # 加载已存在的CVE ID
            existing_cves = await self._load_existing_cve_ids()
            
            unique_cves = []
            duplicates = 0
            
            for cve in cve_infos:
                if cve.cve_id not in existing_cves and cve.cve_id not in self.integrated_cves:
                    unique_cves.append(cve)
                    existing_cves.add(cve.cve_id)
                else:
                    duplicates += 1
            
            self.metrics["duplicates_skipped"] = duplicates
            
            logger.info(f"去重完成，唯一CVE: {len(unique_cves)}, 重复跳过: {duplicates}")
            
            return unique_cves
            
        except Exception as e:
            logger.error(f"CVE去重失败: {e}")
            return cve_infos  # 出错时返回原始数据
    
    async def _load_existing_cve_ids(self) -> Set[str]:
        """加载已存在的CVE ID"""
        try:
            existing_cves = set()
            
            # 从本地文件加载
            for json_file in self.data_dir.glob("integrated_cves_*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for cve_data in data.get("cves", []):
                            existing_cves.add(cve_data.get("cve_id", ""))
                except Exception as e:
                    logger.warning(f"加载CVE文件失败 {json_file}: {e}")
            
            logger.debug(f"加载了 {len(existing_cves)} 个已存在的CVE ID")
            return existing_cves
            
        except Exception as e:
            logger.error(f"加载已存在CVE ID失败: {e}")
            return set()
    
    async def _save_to_knowledge_base(self, cve_infos: List[CVEInfo]):
        """保存CVE数据到知识库"""
        try:
            if not cve_infos:
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 保存为JSON格式
            json_file = self.data_dir / f"integrated_cves_{timestamp}.json"
            data = {
                "timestamp": timestamp,
                "count": len(cve_infos),
                "cves": [cve.to_dict() for cve in cve_infos]
            }
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            # 更新索引文件
            await self._update_index_file(cve_infos)
            
            logger.info(f"CVE数据已保存到知识库: {json_file}")
            
        except Exception as e:
            logger.error(f"保存CVE数据到知识库失败: {e}")
            raise
    
    async def _update_index_file(self, cve_infos: List[CVEInfo]):
        """更新CVE索引文件"""
        try:
            index_file = self.data_dir / "cve_index.json"
            
            # 加载现有索引
            index_data = {"cves": [], "last_updated": None, "total_count": 0}
            if index_file.exists():
                with open(index_file, 'r', encoding='utf-8') as f:
                    index_data = json.load(f)
            
            # 添加新的CVE索引
            for cve in cve_infos:
                index_entry = {
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "published_date": cve.published_date.isoformat(),
                    "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description
                }
                index_data["cves"].append(index_entry)
            
            # 更新元数据
            index_data["last_updated"] = datetime.now().isoformat()
            index_data["total_count"] = len(index_data["cves"])
            
            # 保存索引
            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, ensure_ascii=False, indent=2)
            
            logger.debug(f"CVE索引已更新，总计: {index_data['total_count']}")
            
        except Exception as e:
            logger.error(f"更新CVE索引失败: {e}")
    
    async def integrate_with_cve_client(self, cve_infos: List[CVEInfo]):
        """与CVE客户端集成"""
        try:
            logger.info(f"开始与CVE客户端集成 {len(cve_infos)} 个CVE")
            
            # 这里可以将CVE数据推送到CVE客户端的缓存中
            # 或者更新CVE客户端的本地数据库
            
            # 示例：保存为CVE客户端可以读取的格式
            client_data_dir = Path("./data/cve_cache")
            client_data_dir.mkdir(parents=True, exist_ok=True)
            
            for cve in cve_infos:
                # 为每个CVE创建缓存文件
                cache_key = f"aliyun_{cve.cve_id.lower()}"
                cache_file = client_data_dir / f"{cache_key}.json"
                
                cache_data = [cve.to_dict()]
                
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"CVE客户端集成完成")
            
        except Exception as e:
            logger.error(f"CVE客户端集成失败: {e}")
    
    async def setup_scheduled_crawling(self, interval_hours: int = 24):
        """设置定时爬取任务"""
        try:
            logger.info(f"设置定时爬取任务，间隔: {interval_hours} 小时")
            
            async def scheduled_task():
                while True:
                    try:
                        logger.info("开始定时爬取任务")
                        
                        # 执行增量爬取
                        cve_infos = await self.integrate_incremental(days=1)
                        
                        if cve_infos:
                            # 与CVE客户端集成
                            await self.integrate_with_cve_client(cve_infos)
                            
                            logger.info(f"定时爬取完成，新增 {len(cve_infos)} 个CVE")
                        else:
                            logger.info("定时爬取完成，没有新数据")
                        
                        # 等待下次执行
                        await asyncio.sleep(interval_hours * 3600)
                        
                    except Exception as e:
                        logger.error(f"定时爬取任务失败: {e}")
                        # 出错后等待较短时间再重试
                        await asyncio.sleep(3600)  # 1小时后重试
            
            # 启动后台任务
            asyncio.create_task(scheduled_task())
            
            logger.info("定时爬取任务已启动")
            
        except Exception as e:
            logger.error(f"设置定时爬取任务失败: {e}")
    
    async def search_integrated_cves(self, keyword: str, limit: int = 10) -> List[CVEInfo]:
        """搜索已集成的CVE数据"""
        try:
            results = []
            
            # 搜索所有集成的CVE文件
            for json_file in self.data_dir.glob("integrated_cves_*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        for cve_data in data.get("cves", []):
                            # 简单的关键词匹配
                            if (keyword.lower() in cve_data.get("cve_id", "").lower() or
                                keyword.lower() in cve_data.get("description", "").lower()):
                                
                                cve_info = CVEInfo.from_dict(cve_data)
                                results.append(cve_info)
                                
                                if len(results) >= limit:
                                    break
                    
                    if len(results) >= limit:
                        break
                        
                except Exception as e:
                    logger.warning(f"搜索CVE文件失败 {json_file}: {e}")
            
            logger.info(f"搜索完成，找到 {len(results)} 个匹配的CVE")
            return results
            
        except Exception as e:
            logger.error(f"搜索集成CVE失败: {e}")
            return []
    
    def get_integration_stats(self) -> Dict[str, Any]:
        """获取集成统计信息"""
        stats = self.metrics.copy()
        stats.update({
            "last_crawl_time": self.last_crawl_time.isoformat() if self.last_crawl_time else None,
            "integrated_cves_count": len(self.integrated_cves),
            "data_directory": str(self.data_dir)
        })
        return stats
    
    async def cleanup_old_data(self, days_to_keep: int = 30):
        """清理旧数据"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            cleaned_files = 0
            for json_file in self.data_dir.glob("integrated_cves_*.json"):
                try:
                    # 从文件名提取时间戳
                    filename = json_file.stem
                    timestamp_str = filename.split("_")[-2] + "_" + filename.split("_")[-1]
                    file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    
                    if file_date < cutoff_date:
                        json_file.unlink()
                        cleaned_files += 1
                        
                except Exception as e:
                    logger.warning(f"清理文件失败 {json_file}: {e}")
            
            logger.info(f"清理完成，删除了 {cleaned_files} 个旧文件")
            
        except Exception as e:
            logger.error(f"清理旧数据失败: {e}")


# 全局集成器实例
cve_integrator = CVEKnowledgeIntegrator()


# 便捷函数
async def integrate_aliyun_cves(max_pages: int = 5) -> List[CVEInfo]:
    """便捷的CVE集成函数"""
    return await cve_integrator.integrate_from_crawler(max_pages)


async def integrate_aliyun_cves_incremental(days: int = 1) -> List[CVEInfo]:
    """便捷的增量CVE集成函数"""
    return await cve_integrator.integrate_incremental(days)


# 命令行接口
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE知识库集成器")
    parser.add_argument("--pages", type=int, default=5, help="爬取页数")
    parser.add_argument("--incremental", action="store_true", help="增量集成")
    parser.add_argument("--days", type=int, default=1, help="增量集成天数")
    parser.add_argument("--search", type=str, help="搜索关键词")
    parser.add_argument("--cleanup", action="store_true", help="清理旧数据")
    parser.add_argument("--stats", action="store_true", help="显示统计信息")
    
    args = parser.parse_args()
    
    async def main():
        if args.stats:
            stats = cve_integrator.get_integration_stats()
            print("集成统计信息:")
            for key, value in stats.items():
                print(f"  {key}: {value}")
        
        elif args.search:
            results = await cve_integrator.search_integrated_cves(args.search)
            print(f"搜索结果 ({len(results)} 个):")
            for cve in results:
                print(f"  {cve.cve_id}: {cve.description[:100]}...")
        
        elif args.cleanup:
            await cve_integrator.cleanup_old_data()
            print("清理完成")
        
        elif args.incremental:
            cve_infos = await integrate_aliyun_cves_incremental(args.days)
            print(f"增量集成完成，新增 {len(cve_infos)} 个CVE")
        
        else:
            cve_infos = await integrate_aliyun_cves(args.pages)
            print(f"集成完成，获得 {len(cve_infos)} 个CVE")
    
    asyncio.run(main())