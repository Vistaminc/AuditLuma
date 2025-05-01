"""
报告生成器 - 负责生成HTML/PDF格式的审计报告
"""

import os
import json
import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import base64
import io

from loguru import logger
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # 使用非交互式后端
import numpy as np

from auditluma.config import Config
from auditluma.models.code import VulnerabilityResult, SeverityLevel


class ReportGenerator:
    """AuditLuma报告生成器"""
    
    def __init__(self):
        """初始化报告生成器"""
        self.templates_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(self.templates_dir)))
        
        # 确保输出目录存在
        self.output_dir = Path(Config.get_report_dir())
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 报告格式
        self.report_format = Config.get_report_format().lower()
        if self.report_format not in ["html", "pdf", "json"]:
            logger.warning(f"不支持的报告格式: {self.report_format}，将使用HTML格式")
            self.report_format = "html"
    
    def generate_report(self, 
                      vulnerabilities: List[VulnerabilityResult], 
                      dependency_graph: Any = None,
                      remediation_data: Optional[Dict[str, Any]] = None,
                      scan_info: Optional[Dict[str, Any]] = None) -> str:
        """生成安全审计报告
        
        Args:
            vulnerabilities: 发现的漏洞列表
            dependency_graph: 代码依赖关系图(可选)
            remediation_data: 修复建议数据(可选)
            scan_info: 扫描信息(可选)
            
        Returns:
            生成的报告文件路径
        """
        # 如果没有提供扫描信息，创建默认信息
        if not scan_info:
            scan_info = {
                "project_name": Config.project.name,
                "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scanned_files": 0,
                "scanned_lines": 0,
                "scan_duration": "unknown"
            }
        
        # 按严重程度分组漏洞
        vulns_by_severity = self._group_by_severity(vulnerabilities)
        
        # 准备图表数据
        charts_data = self._prepare_charts_data(vulnerabilities)
        
        # 生成报告内容
        if self.report_format == "html":
            return self._generate_html_report(
                vulnerabilities, 
                vulns_by_severity,
                dependency_graph,
                remediation_data,
                scan_info,
                charts_data
            )
        elif self.report_format == "pdf":
            return self._generate_pdf_report(
                vulnerabilities, 
                vulns_by_severity,
                dependency_graph,
                remediation_data,
                scan_info,
                charts_data
            )
        else:  # json
            return self._generate_json_report(
                vulnerabilities, 
                scan_info,
                remediation_data
            )
    
    def _group_by_severity(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, List[VulnerabilityResult]]:
        """按严重程度分组漏洞"""
        result = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            if severity in result:
                result[severity].append(vuln)
            else:
                result["info"].append(vuln)
        
        return result
    
    def _prepare_charts_data(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """准备图表数据"""
        # 按严重程度统计
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # 按漏洞类型统计
        vuln_type_counts = {}
        
        # 按文件统计
        file_counts = {}
        
        for vuln in vulnerabilities:
            # 统计严重程度
            severity = vuln.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["info"] += 1
            
            # 统计漏洞类型
            vuln_type = vuln.vulnerability_type
            if vuln_type not in vuln_type_counts:
                vuln_type_counts[vuln_type] = 0
            vuln_type_counts[vuln_type] += 1
            
            # 统计文件
            file_path = vuln.file_path
            if file_path not in file_counts:
                file_counts[file_path] = 0
            file_counts[file_path] += 1
        
        # 生成图表
        charts = {
            "severity_chart": self._generate_severity_chart(severity_counts),
            "vuln_type_chart": self._generate_vuln_type_chart(vuln_type_counts),
            "file_chart": self._generate_file_chart(file_counts)
        }
        
        return {
            "severity_counts": severity_counts,
            "vuln_type_counts": vuln_type_counts,
            "file_counts": file_counts,
            "charts": charts
        }
    
    def _generate_severity_chart(self, severity_counts: Dict[str, int]) -> str:
        """生成严重程度分布图表"""
        try:
            # 确保图表清晰
            plt.figure(figsize=(8, 6))
            
            # 设置颜色映射
            colors = {
                "critical": "#FF0000",  # 红色
                "high": "#FF7F00",      # 橙色
                "medium": "#FFFF00",    # 黄色
                "low": "#00FF00",       # 绿色
                "info": "#0000FF"       # 蓝色
            }
            
            # 准备数据
            labels = list(severity_counts.keys())
            values = list(severity_counts.values())
            chart_colors = [colors[label] for label in labels]
            
            # 生成饼图
            plt.pie(values, labels=labels, colors=chart_colors, autopct='%1.1f%%', shadow=True, startangle=90)
            plt.axis('equal')  # 确保饼图是圆形的
            plt.title('漏洞严重程度分布')
            
            # 将图表转换为base64编码的字符串
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            plt.close()
            
            # 转换为可嵌入HTML的数据URL
            image_data = base64.b64encode(buffer.read()).decode('utf-8')
            return f"data:image/png;base64,{image_data}"
            
        except Exception as e:
            logger.error(f"生成严重程度图表时出错: {e}")
            return ""
    
    def _generate_vuln_type_chart(self, vuln_type_counts: Dict[str, int]) -> str:
        """生成漏洞类型分布图表"""
        try:
            # 限制显示的漏洞类型数量，防止图表过于复杂
            max_types = 10
            if len(vuln_type_counts) > max_types:
                # 按数量排序，取前N个最常见的类型
                sorted_types = sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)
                top_types = dict(sorted_types[:max_types-1])
                # 将其余类型合并为"其他"
                other_count = sum(count for _, count in sorted_types[max_types-1:])
                top_types["其他"] = other_count
                vuln_type_counts = top_types
            
            plt.figure(figsize=(10, 6))
            
            # 准备数据
            labels = list(vuln_type_counts.keys())
            values = list(vuln_type_counts.values())
            
            # 生成条形图
            bars = plt.bar(labels, values, color='skyblue')
            
            # 添加数值标签
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height}',
                        ha='center', va='bottom')
            
            plt.title('漏洞类型分布')
            plt.xlabel('漏洞类型')
            plt.ylabel('数量')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            
            # 将图表转换为base64编码的字符串
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            plt.close()
            
            # 转换为可嵌入HTML的数据URL
            image_data = base64.b64encode(buffer.read()).decode('utf-8')
            return f"data:image/png;base64,{image_data}"
            
        except Exception as e:
            logger.error(f"生成漏洞类型图表时出错: {e}")
            return ""
    
    def _generate_file_chart(self, file_counts: Dict[str, int]) -> str:
        """生成文件漏洞分布图表"""
        try:
            # 限制显示的文件数量
            max_files = 10
            if len(file_counts) > max_files:
                # 按数量排序，取前N个最多漏洞的文件
                sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
                top_files = dict(sorted_files[:max_files-1])
                # 将其余文件合并为"其他"
                other_count = sum(count for _, count in sorted_files[max_files-1:])
                top_files["其他文件"] = other_count
                file_counts = top_files
            
            plt.figure(figsize=(10, 6))
            
            # 准备数据
            # 使用文件名而不是完整路径
            labels = [Path(path).name for path in file_counts.keys()]
            values = list(file_counts.values())
            
            # 生成水平条形图
            bars = plt.barh(labels, values, color='lightgreen')
            
            # 添加数值标签
            for bar in bars:
                width = bar.get_width()
                plt.text(width, bar.get_y() + bar.get_height()/2.,
                        f'{width}',
                        ha='left', va='center')
            
            plt.title('文件漏洞分布')
            plt.xlabel('漏洞数量')
            plt.ylabel('文件名')
            plt.tight_layout()
            
            # 将图表转换为base64编码的字符串
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            plt.close()
            
            # 转换为可嵌入HTML的数据URL
            image_data = base64.b64encode(buffer.read()).decode('utf-8')
            return f"data:image/png;base64,{image_data}"
            
        except Exception as e:
            logger.error(f"生成文件图表时出错: {e}")
            return ""
    
    def _generate_html_report(self, 
                      vulnerabilities: List[VulnerabilityResult],
                      vulns_by_severity: Dict[str, List[VulnerabilityResult]],
                      dependency_graph: Any,
                      remediation_data: Optional[Dict[str, Any]],
                      scan_info: Dict[str, Any],
                      charts_data: Dict[str, Any]) -> str:
        """生成HTML格式的报告"""
        try:
            # 加载HTML模板
            template = self.env.get_template("report_template.html")
            
            # 生成依赖关系图数据(如果提供)
            dependency_data = ""
            if dependency_graph:
                try:
                    dependency_data = self._prepare_dependency_data(dependency_graph)
                except Exception as e:
                    logger.error(f"准备依赖关系图数据时出错: {e}")
                    dependency_data = ""
            
            # 统计数据
            stats = {
                "high_count": len(vulns_by_severity.get("high", [])),
                "medium_count": len(vulns_by_severity.get("medium", [])),
                "low_count": len(vulns_by_severity.get("low", [])),
                "file_count": scan_info.get("scanned_files", 0),
                "total_count": len(vulnerabilities)
            }
            
            # 准备漏洞类型数据
            vuln_types = []
            vuln_type_counts = []
            for vuln_type, count in charts_data.get("vuln_type_counts", {}).items():
                vuln_types.append(vuln_type)
                vuln_type_counts.append(count)
            
            # 准备复杂度数据 (假设有这些数据)
            complexity_labels = ["低", "中", "高", "非常高"]
            complexity_counts = [20, 15, 10, 5]  # 示例数据，实际应从分析中获取
            
            # 准备常见漏洞类型数据 (取前5种最常见的漏洞类型)
            common_vuln_types = []
            common_vuln_counts = []
            if vuln_types:
                # 按数量排序
                sorted_data = sorted(zip(vuln_types, vuln_type_counts), 
                                   key=lambda x: x[1], reverse=True)[:5]
                common_vuln_types = [item[0] for item in sorted_data]
                common_vuln_counts = [item[1] for item in sorted_data]
            
            # 创建时间线数据
            timeline_events = []
            scan_date = scan_info.get("scan_date", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            timeline_events.append({
                "date": scan_date,
                "event": "完成安全扫描",
                "description": f"发现 {len(vulnerabilities)} 个安全问题"
            })
            
            # 准备每日漏洞趋势数据 (这里使用模拟数据，实际中可以从历史记录获取)
            today = datetime.datetime.now()
            daily_data = []
            
            # 创建过去7天的日期标签
            for i in range(6, -1, -1):
                day = today - datetime.timedelta(days=i)
                daily_data.append({
                    "date": day.strftime("%Y-%m-%d"),
                    "label": "今天" if i == 0 else f"{i}天前",
                    # 模拟数据
                    "high": 0 if i != 0 else stats["high_count"],
                    "medium": 0 if i != 0 else stats["medium_count"],
                    "low": 0 if i != 0 else stats["low_count"]
                })
            
            # 准备报告数据
            report_data = {
                "project_name": scan_info.get("project_name", "未知项目"),
                "scan_date": scan_info.get("scan_date", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "scan_info": scan_info,
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities_by_severity": vulns_by_severity,
                "charts": charts_data.get("charts", {}),
                "dependency_data": dependency_data,
                "remediations": remediation_data.get("remediations", []) if remediation_data else [],
                "stats": stats,
                "vuln_types": json.dumps(vuln_types),
                "vuln_type_counts": json.dumps(vuln_type_counts),
                "complexity_labels": json.dumps(complexity_labels),
                "complexity_counts": json.dumps(complexity_counts),
                "common_vuln_types": json.dumps(common_vuln_types),
                "common_vuln_counts": json.dumps(common_vuln_counts),
                "timeline_events": timeline_events,
                "daily_data": daily_data,
                "daily_labels": json.dumps([day["label"] for day in daily_data])
            }
            
            # 渲染HTML
            html_content = template.render(**report_data)
            
            # 生成报告文件名
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"{Config.project.name}_security_report_{timestamp}.html"
            report_path = self.output_dir / report_filename
            
            # 写入文件
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            logger.info(f"HTML报告已生成: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"生成HTML报告时出错: {e}")
            # 创建一个简单的错误报告
            error_report_path = self.output_dir / f"error_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(error_report_path, "w", encoding="utf-8") as f:
                f.write(f"<html><body><h1>报告生成错误</h1><p>{str(e)}</p></body></html>")
            return str(error_report_path)
    
    def _generate_pdf_report(self, 
                          vulnerabilities: List[VulnerabilityResult],
                          vulns_by_severity: Dict[str, List[VulnerabilityResult]],
                          dependency_graph: Any,
                          remediation_data: Optional[Dict[str, Any]],
                          scan_info: Dict[str, Any],
                          charts_data: Dict[str, Any]) -> str:
        """生成PDF格式的报告"""
        try:
            # 首先生成HTML报告
            html_report_path = self._generate_html_report(
                vulnerabilities,
                vulns_by_severity,
                dependency_graph,
                remediation_data,
                scan_info,
                charts_data
            )
            
            # 生成PDF文件名
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"{Config.project.name}_security_report_{timestamp}.pdf"
            pdf_path = self.output_dir / pdf_filename
            
            # 使用weasyprint将HTML转换为PDF
            try:
                from weasyprint import HTML
                HTML(html_report_path).write_pdf(pdf_path)
                logger.info(f"PDF报告已生成: {pdf_path}")
                return str(pdf_path)
            except ImportError:
                logger.warning("WeasyPrint未安装，无法生成PDF报告，返回HTML报告")
                return html_report_path
                
        except Exception as e:
            logger.error(f"生成PDF报告时出错: {e}")
            # 返回HTML报告作为备选
            return self._generate_html_report(
                vulnerabilities,
                vulns_by_severity,
                dependency_graph,
                remediation_data,
                scan_info,
                charts_data
            )
    
    def _generate_json_report(self, 
                           vulnerabilities: List[VulnerabilityResult],
                           scan_info: Dict[str, Any],
                           remediation_data: Optional[Dict[str, Any]]) -> str:
        """生成JSON格式的报告"""
        try:
            # 准备JSON数据
            report_data = {
                "project_name": scan_info.get("project_name", "未知项目"),
                "scan_date": scan_info.get("scan_date", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "scan_info": scan_info,
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities": [vuln.dict() for vuln in vulnerabilities],
                "remediations": remediation_data.get("remediations", []) if remediation_data else []
            }
            
            # 生成报告文件名
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"{Config.project.name}_security_report_{timestamp}.json"
            report_path = self.output_dir / report_filename
            
            # 写入文件
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
                
            logger.info(f"JSON报告已生成: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"生成JSON报告时出错: {e}")
            # 创建一个简单的错误报告
            error_report_path = self.output_dir / f"error_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(error_report_path, "w", encoding="utf-8") as f:
                json.dump({"error": str(e)}, f, ensure_ascii=False, indent=2)
            return str(error_report_path)
    
    def _prepare_dependency_data(self, dependency_graph) -> str:
        """准备依赖关系图的ECharts数据"""
        try:
            import networkx as nx
            
            # 构建ECharts所需数据结构
            nodes = []
            links = []
            
            # 获取节点属性
            node_types = nx.get_node_attributes(dependency_graph, 'type')
            node_names = nx.get_node_attributes(dependency_graph, 'name')
            
            # 定义不同类型节点的样式
            type_config = {
                'function': {'color': '#2a86db', 'symbol': 'circle'},
                'class': {'color': '#52b788', 'symbol': 'rect'},
                'module': {'color': '#ffbe0b', 'symbol': 'triangle'},
                'unknown': {'color': '#6c757d', 'symbol': 'diamond'}
            }
            
            # 创建节点数据
            for node_id in dependency_graph.nodes():
                node_type = node_types.get(node_id, 'unknown')
                node_name = node_names.get(node_id, str(node_id))
                
                config = type_config.get(node_type, type_config['unknown'])
                
                nodes.append({
                    'id': str(node_id),
                    'name': node_name,
                    'symbolSize': 30,
                    'itemStyle': {'color': config['color']},
                    'symbol': config['symbol'],
                    'category': node_type
                })
            
            # 创建边数据
            for source, target in dependency_graph.edges():
                links.append({
                    'source': str(source),
                    'target': str(target)
                })
            
            # 创建类别数据
            categories = [
                {'name': 'function'},
                {'name': 'class'},
                {'name': 'module'},
                {'name': 'unknown'}
            ]
            
            # 构建完整的ECharts选项
            option = {
                'title': {'text': '代码依赖关系图'},
                'tooltip': {},
                'legend': {
                    'data': [cat['name'] for cat in categories]
                },
                'animationDurationUpdate': 1500,
                'animationEasingUpdate': 'quinticInOut',
                'series': [{
                    'type': 'graph',
                    'layout': 'force',
                    'data': nodes,
                    'links': links,
                    'categories': categories,
                    'roam': True,
                    'label': {
                        'show': True,
                        'position': 'right',
                        'formatter': '{b}'
                    },
                    'force': {
                        'repulsion': 100
                    }
                }]
            }
            
            # 转换为JSON字符串
            return json.dumps(option)
            
        except Exception as e:
            logger.error(f"准备依赖关系图数据时出错: {e}")
            return ""
