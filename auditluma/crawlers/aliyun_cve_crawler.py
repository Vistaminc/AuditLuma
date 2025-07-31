"""
阿里云漏洞库爬虫 - 爬取CVE数据

本模块提供阿里云漏洞库的数据爬取功能，包括：
- CVE列表页面的批量爬取
- CVE详情页面的详细信息提取
- 数据清洗和标准化处理
- 增量更新和去重机制
- 与知识库的集成
"""

import asyncio
import json
import aiofiles
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import os
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
import random

from loguru import logger
from playwright.async_api import async_playwright, Browser, Page, BrowserContext

from auditluma.models.hierarchical_rag import CVEInfo


@dataclass
class CrawlConfig:
    """爬虫配置"""
    base_url: str = "https://avd.aliyun.com"
    list_url: str = "https://avd.aliyun.com/nvd/list"
    detail_url_template: str = "https://avd.aliyun.com/detail?id={}"
    
    # 爬取配置
    max_pages: int = 100  # 最大爬取页数
    page_size: int = 30   # 每页条目数
    delay_range: tuple = (1, 3)  # 请求间隔范围（秒）
    timeout: int = 30     # 页面加载超时
    
    # 浏览器配置
    headless: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # 数据存储
    data_dir: str = "./data/aliyun_cve"
    cache_ttl: int = 86400  # 缓存TTL（秒）


@dataclass
class CVEListItem:
    """CVE列表项"""
    cve_id: str
    title: str
    cwe_type: str
    disclosure_date: str
    cvss_score: str
    detail_url: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'title': self.title,
            'cwe_type': self.cwe_type,
            'disclosure_date': self.disclosure_date,
            'cvss_score': self.cvss_score,
            'detail_url': self.detail_url
        }


@dataclass
class CVEDetail:
    """CVE详细信息"""
    cve_id: str
    title: str
    description: str
    solution: str
    references: List[str] = field(default_factory=list)
    cvss_score: str = ""
    cvss_vector: str = ""
    cwe_info: List[Dict[str, str]] = field(default_factory=list)
    disclosure_date: str = ""
    patch_status: str = ""
    exploit_status: str = ""
    aliyun_products: List[str] = field(default_factory=list)
    
    def to_cve_info(self) -> CVEInfo:
        """转换为标准CVEInfo格式"""
        try:
            # 解析CVSS分数，处理'N/A'和其他无效值
            cvss_score = 5.0  # 默认值
            if self.cvss_score and self.cvss_score.strip():
                cvss_str = self.cvss_score.strip()
                # 检查是否为'N/A'或其他无效值
                if cvss_str.upper() not in ['N/A', 'NA', 'NULL', 'NONE', '', '-']:
                    try:
                        cvss_score = float(cvss_str)
                        # 确保CVSS分数在有效范围内 (0.0-10.0)
                        cvss_score = max(0.0, min(10.0, cvss_score))
                    except (ValueError, TypeError):
                        logger.warning(f"无法解析CVSS分数 '{cvss_str}' for {self.cve_id}，使用默认值5.0")
                        cvss_score = 5.0
                else:
                    logger.debug(f"CVE {self.cve_id} CVSS分数为 '{cvss_str}'，使用默认值5.0")

            # 确定严重性等级
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # 解析日期
            try:
                published_date = datetime.strptime(self.disclosure_date, "%Y-%m-%d")
            except:
                published_date = datetime.now()
            
            # 提取CWE ID
            cwe_ids = []
            for cwe in self.cwe_info:
                if 'id' in cwe and cwe['id'].startswith('CWE-'):
                    cwe_ids.append(cwe['id'])
            
            return CVEInfo(
                cve_id=self.cve_id,
                description=self.description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=published_date,
                modified_date=published_date,  # 使用披露日期作为修改日期
                references=self.references,
                affected_products=self.aliyun_products,
                cwe_ids=cwe_ids
            )
            
        except Exception as e:
            logger.error(f"转换CVE信息失败 {self.cve_id}: {e}")
            # 返回基本信息
            return CVEInfo(
                cve_id=self.cve_id,
                description=self.description or f"CVE {self.cve_id} vulnerability",
                severity="MEDIUM",
                cvss_score=5.0,
                published_date=datetime.now(),
                modified_date=datetime.now(),
                references=self.references
            )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'title': self.title,
            'description': self.description,
            'solution': self.solution,
            'references': self.references,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cwe_info': self.cwe_info,
            'disclosure_date': self.disclosure_date,
            'patch_status': self.patch_status,
            'exploit_status': self.exploit_status,
            'aliyun_products': self.aliyun_products
        }


class AliyunCVECrawler:
    """阿里云CVE爬虫"""
    
    def __init__(self, config: Optional[CrawlConfig] = None):
        """初始化爬虫"""
        self.config = config or CrawlConfig()
        
        # 创建数据目录
        self.data_dir = Path(self.config.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # 缓存和状态
        self.crawled_cves: Set[str] = set()
        self.failed_cves: Set[str] = set()
        
        # 性能指标
        self.metrics = {
            "pages_crawled": 0,
            "cves_found": 0,
            "cves_detailed": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None
        }
        
        # 浏览器实例
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        
        logger.info("阿里云CVE爬虫初始化完成")
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self._init_browser()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self._cleanup_browser()
    
    async def _init_browser(self):
        """初始化浏览器"""
        try:
            playwright = await async_playwright().start()
            
            self.browser = await playwright.chromium.launch(
                headless=self.config.headless,
                args=[
                    '--no-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor'
                ]
            )
            
            self.context = await self.browser.new_context(
                user_agent=self.config.user_agent,
                viewport={'width': 1920, 'height': 1080},
                extra_http_headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
            )
            
            logger.info("浏览器初始化完成")
            
        except Exception as e:
            logger.error(f"浏览器初始化失败: {e}")
            raise
    
    async def _cleanup_browser(self):
        """清理浏览器资源"""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            logger.info("浏览器资源清理完成")
        except Exception as e:
            logger.error(f"浏览器清理失败: {e}")
    
    async def crawl_all(self, start_page: int = 1, max_pages: Optional[int] = None) -> List[CVEInfo]:
        """爬取所有CVE数据"""
        try:
            self.metrics["start_time"] = datetime.now()
            max_pages = max_pages or self.config.max_pages
            
            logger.info(f"开始爬取阿里云CVE数据，起始页: {start_page}, 最大页数: {max_pages}")
            
            # 第一步：爬取CVE列表
            cve_list = await self._crawl_cve_list(start_page, max_pages)
            self.metrics["cves_found"] = len(cve_list)
            
            logger.info(f"找到 {len(cve_list)} 个CVE条目")
            
            # 第二步：爬取CVE详情
            cve_details = await self._crawl_cve_details(cve_list)
            self.metrics["cves_detailed"] = len(cve_details)
            
            # 第三步：转换为标准格式
            cve_infos = []
            for detail in cve_details:
                try:
                    cve_info = detail.to_cve_info()
                    cve_infos.append(cve_info)
                except Exception as e:
                    logger.error(f"转换CVE信息失败 {detail.cve_id}: {e}")
                    self.metrics["errors"] += 1
            
            # 保存结果
            await self._save_results(cve_details, cve_infos)
            
            self.metrics["end_time"] = datetime.now()
            duration = (self.metrics["end_time"] - self.metrics["start_time"]).total_seconds()
            
            logger.info(f"爬取完成，耗时: {duration:.2f}秒，成功: {len(cve_infos)}，失败: {self.metrics['errors']}")
            
            return cve_infos
            
        except Exception as e:
            logger.error(f"爬取过程失败: {e}")
            self.metrics["errors"] += 1
            raise
    
    async def _crawl_cve_list(self, start_page: int, max_pages: int) -> List[CVEListItem]:
        """爬取CVE列表"""
        cve_list = []
        
        for page_num in range(start_page, start_page + max_pages):
            try:
                logger.info(f"爬取第 {page_num} 页")
                
                page_cves = await self._crawl_list_page(page_num)
                if not page_cves:
                    logger.info(f"第 {page_num} 页没有数据，停止爬取")
                    break
                
                cve_list.extend(page_cves)
                self.metrics["pages_crawled"] += 1
                
                # 随机延迟
                delay = random.uniform(*self.config.delay_range)
                await asyncio.sleep(delay)
                
            except Exception as e:
                logger.error(f"爬取第 {page_num} 页失败: {e}")
                self.metrics["errors"] += 1
                continue
        
        return cve_list
    
    async def _crawl_list_page(self, page_num: int) -> List[CVEListItem]:
        """爬取单个列表页面"""
        page = await self.context.new_page()
        
        try:
            # 构建URL
            url = f"{self.config.list_url}?page={page_num}"
            
            # 访问页面
            await page.goto(url, timeout=self.config.timeout * 1000)
            await page.wait_for_load_state('networkidle')
            
            # 等待表格加载
            await page.wait_for_selector('table tbody tr', timeout=10000)
            
            # 提取CVE数据
            cve_items = []
            rows = await page.query_selector_all('table tbody tr')
            
            for row in rows:
                try:
                    # 提取各列数据
                    cells = await row.query_selector_all('td')
                    if len(cells) >= 5:
                        # CVE编号
                        cve_link = await cells[0].query_selector('a')
                        if cve_link:
                            cve_id = await cve_link.text_content()
                            detail_url = await cve_link.get_attribute('href')
                            if detail_url:
                                detail_url = urljoin(self.config.base_url, detail_url)
                        else:
                            continue
                        
                        # 漏洞名称
                        title = await cells[1].text_content()
                        
                        # 漏洞类型
                        cwe_type = await cells[2].text_content()
                        
                        # 披露时间
                        disclosure_date = await cells[3].text_content()
                        
                        # CVSS评分
                        cvss_score = await cells[4].text_content()
                        
                        cve_item = CVEListItem(
                            cve_id=cve_id.strip(),
                            title=title.strip(),
                            cwe_type=cwe_type.strip(),
                            disclosure_date=disclosure_date.strip(),
                            cvss_score=cvss_score.strip(),
                            detail_url=detail_url
                        )
                        
                        cve_items.append(cve_item)
                        
                except Exception as e:
                    logger.warning(f"解析CVE行失败: {e}")
                    continue
            
            logger.debug(f"第 {page_num} 页提取到 {len(cve_items)} 个CVE")
            return cve_items
            
        except Exception as e:
            logger.error(f"爬取列表页面失败 {page_num}: {e}")
            raise
        finally:
            await page.close()
    
    async def _crawl_cve_details(self, cve_list: List[CVEListItem]) -> List[CVEDetail]:
        """爬取CVE详情"""
        cve_details = []
        
        # 限制并发数
        semaphore = asyncio.Semaphore(5)
        
        async def crawl_single_detail(cve_item: CVEListItem) -> Optional[CVEDetail]:
            async with semaphore:
                try:
                    detail = await self._crawl_detail_page(cve_item)
                    if detail:
                        self.crawled_cves.add(cve_item.cve_id)
                        return detail
                    else:
                        self.failed_cves.add(cve_item.cve_id)
                        return None
                except Exception as e:
                    logger.error(f"爬取CVE详情失败 {cve_item.cve_id}: {e}")
                    self.failed_cves.add(cve_item.cve_id)
                    return None
        
        # 并发爬取详情
        tasks = [crawl_single_detail(cve_item) for cve_item in cve_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 收集成功的结果
        for result in results:
            if isinstance(result, CVEDetail):
                cve_details.append(result)
            elif isinstance(result, Exception):
                logger.error(f"CVE详情爬取异常: {result}")
                self.metrics["errors"] += 1
        
        return cve_details
    
    async def _crawl_detail_page(self, cve_item: CVEListItem) -> Optional[CVEDetail]:
        """爬取单个CVE详情页面"""
        page = await self.context.new_page()
        
        try:
            # 访问详情页面
            await page.goto(cve_item.detail_url, timeout=self.config.timeout * 1000)
            await page.wait_for_load_state('networkidle')
            
            # 等待内容加载
            await page.wait_for_selector('h5', timeout=10000)
            
            # 提取标题
            title_element = await page.query_selector('h5')
            title = await title_element.text_content() if title_element else cve_item.title
            
            # 提取基本信息
            cve_id = cve_item.cve_id
            disclosure_date = cve_item.disclosure_date
            
            # 提取利用情况和补丁情况
            exploit_status = ""
            patch_status = ""
            
            info_sections = await page.query_selector_all('div.info-section div')
            for section in info_sections:
                text = await section.text_content()
                if "利用情况" in text:
                    exploit_status = text.replace("利用情况", "").strip()
                elif "补丁情况" in text:
                    patch_status = text.replace("补丁情况", "").strip()
            
            # 提取漏洞描述
            description = ""
            desc_element = await page.query_selector('h6:has-text("漏洞描述") + div')
            if desc_element:
                description = await desc_element.text_content()
            
            # 提取解决建议
            solution = ""
            solution_element = await page.query_selector('h6:has-text("解决建议") + div')
            if solution_element:
                solution = await solution_element.text_content()
            
            # 提取参考链接
            references = []
            ref_links = await page.query_selector_all('table a[href]')
            for link in ref_links:
                href = await link.get_attribute('href')
                if href and href.startswith('http'):
                    references.append(href)
            
            # 提取CVSS信息
            cvss_score = cve_item.cvss_score
            cvss_vector = ""
            
            cvss_element = await page.query_selector('div:has-text("CVSS:3.1/")')
            if cvss_element:
                cvss_text = await cvss_element.text_content()
                cvss_match = re.search(r'CVSS:3\.1/[A-Z:/]+', cvss_text)
                if cvss_match:
                    cvss_vector = cvss_match.group()
            
            # 提取CWE信息
            cwe_info = []
            cwe_rows = await page.query_selector_all('table tbody tr')
            for row in cwe_rows:
                cells = await row.query_selector_all('td')
                if len(cells) >= 2:
                    cwe_id = await cells[0].text_content()
                    cwe_desc = await cells[1].text_content()
                    if cwe_id and cwe_id.startswith('CWE-'):
                        cwe_info.append({
                            'id': cwe_id.strip(),
                            'description': cwe_desc.strip()
                        })
            
            # 提取阿里云产品覆盖情况
            aliyun_products = []
            product_buttons = await page.query_selector_all('button:has-text("云安全中心"), button:has-text("WAF"), button:has-text("云防火墙"), button:has-text("RASP")')
            for button in product_buttons:
                product_name = await button.text_content()
                if product_name:
                    aliyun_products.append(product_name.strip())
            
            # 创建CVE详情对象
            cve_detail = CVEDetail(
                cve_id=cve_id,
                title=title.strip() if title else "",
                description=description.strip() if description else "",
                solution=solution.strip() if solution else "",
                references=references,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_info=cwe_info,
                disclosure_date=disclosure_date,
                patch_status=patch_status,
                exploit_status=exploit_status,
                aliyun_products=aliyun_products
            )
            
            # 随机延迟
            delay = random.uniform(*self.config.delay_range)
            await asyncio.sleep(delay)
            
            return cve_detail
            
        except Exception as e:
            logger.error(f"爬取CVE详情页面失败 {cve_item.cve_id}: {e}")
            raise
        finally:
            await page.close()
    
    async def _save_results(self, cve_details: List[CVEDetail], cve_infos: List[CVEInfo]):
        """保存爬取结果"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 保存原始详情数据
            details_file = self.data_dir / f"cve_details_{timestamp}.json"
            details_data = {
                "timestamp": timestamp,
                "count": len(cve_details),
                "details": [detail.to_dict() for detail in cve_details]
            }
            
            async with aiofiles.open(details_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(details_data, ensure_ascii=False, indent=2))
            
            # 保存标准格式数据
            infos_file = self.data_dir / f"cve_infos_{timestamp}.json"
            infos_data = {
                "timestamp": timestamp,
                "count": len(cve_infos),
                "infos": [info.to_dict() for info in cve_infos]
            }
            
            async with aiofiles.open(infos_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(infos_data, ensure_ascii=False, indent=2))
            
            # 保存爬取统计
            stats_file = self.data_dir / f"crawl_stats_{timestamp}.json"
            stats_data = {
                "timestamp": timestamp,
                "metrics": self.metrics,
                "crawled_cves": list(self.crawled_cves),
                "failed_cves": list(self.failed_cves)
            }
            
            async with aiofiles.open(stats_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(stats_data, ensure_ascii=False, indent=2))
            
            logger.info(f"结果已保存到: {self.data_dir}")
            
        except Exception as e:
            logger.error(f"保存结果失败: {e}")
    
    async def crawl_incremental(self, since_date: Optional[datetime] = None) -> List[CVEInfo]:
        """增量爬取（爬取指定日期之后的CVE）"""
        try:
            if not since_date:
                since_date = datetime.now() - timedelta(days=7)  # 默认爬取最近7天
            
            logger.info(f"开始增量爬取，起始日期: {since_date.strftime('%Y-%m-%d')}")
            
            # 爬取第一页检查最新数据
            cve_list = await self._crawl_list_page(1)
            
            # 过滤出需要爬取的CVE
            new_cves = []
            for cve_item in cve_list:
                try:
                    cve_date = datetime.strptime(cve_item.disclosure_date, "%Y-%m-%d")
                    if cve_date >= since_date:
                        new_cves.append(cve_item)
                except:
                    # 日期解析失败，保守起见包含在内
                    new_cves.append(cve_item)
            
            if not new_cves:
                logger.info("没有新的CVE数据")
                return []
            
            logger.info(f"找到 {len(new_cves)} 个新CVE")
            
            # 爬取详情
            cve_details = await self._crawl_cve_details(new_cves)
            
            # 转换为标准格式
            cve_infos = []
            for detail in cve_details:
                try:
                    cve_info = detail.to_cve_info()
                    cve_infos.append(cve_info)
                except Exception as e:
                    logger.error(f"转换CVE信息失败 {detail.cve_id}: {e}")
            
            # 保存结果
            await self._save_results(cve_details, cve_infos)
            
            logger.info(f"增量爬取完成，获得 {len(cve_infos)} 个新CVE")
            return cve_infos
            
        except Exception as e:
            logger.error(f"增量爬取失败: {e}")
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """获取爬取指标"""
        return self.metrics.copy()


# 便捷函数
async def crawl_aliyun_cves(max_pages: int = 10, 
                           start_page: int = 1,
                           headless: bool = True) -> List[CVEInfo]:
    """便捷的CVE爬取函数"""
    config = CrawlConfig(
        max_pages=max_pages,
        headless=headless
    )
    
    async with AliyunCVECrawler(config) as crawler:
        return await crawler.crawl_all(start_page, max_pages)


async def crawl_aliyun_cves_incremental(days: int = 7) -> List[CVEInfo]:
    """便捷的增量CVE爬取函数"""
    config = CrawlConfig()
    since_date = datetime.now() - timedelta(days=days)
    
    async with AliyunCVECrawler(config) as crawler:
        return await crawler.crawl_incremental(since_date)


# 命令行接口
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="阿里云CVE爬虫")
    parser.add_argument("--pages", type=int, default=5, help="爬取页数")
    parser.add_argument("--start-page", type=int, default=1, help="起始页")
    parser.add_argument("--incremental", action="store_true", help="增量爬取")
    parser.add_argument("--days", type=int, default=7, help="增量爬取天数")
    parser.add_argument("--headless", action="store_true", default=True, help="无头模式")
    
    args = parser.parse_args()
    
    async def main():
        if args.incremental:
            cve_infos = await crawl_aliyun_cves_incremental(args.days)
        else:
            cve_infos = await crawl_aliyun_cves(args.pages, args.start_page, args.headless)
        
        print(f"爬取完成，获得 {len(cve_infos)} 个CVE")
        
        # 显示前几个结果
        for i, cve in enumerate(cve_infos[:3]):
            print(f"\n{i+1}. {cve.cve_id}")
            print(f"   描述: {cve.description[:100]}...")
            print(f"   严重性: {cve.severity}")
            print(f"   CVSS: {cve.cvss_score}")
    
    asyncio.run(main())