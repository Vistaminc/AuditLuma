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
            
            # 生成依赖关系图(如果提供)
            dependency_graph_img = ""
            if dependency_graph:
                dependency_graph_img = self._render_dependency_graph(dependency_graph)
            
            # 准备报告数据
            report_data = {
                "project_name": scan_info.get("project_name", "未知项目"),
                "scan_date": scan_info.get("scan_date", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "scan_info": scan_info,
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities_by_severity": vulns_by_severity,
                "charts": charts_data.get("charts", {}),
                "dependency_graph": dependency_graph_img,
                "remediations": remediation_data.get("remediations", []) if remediation_data else []
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
    
    def _render_dependency_graph(self, dependency_graph) -> str:
        """渲染依赖关系图"""
        try:
            import networkx as nx
            
            plt.figure(figsize=(12, 10))
            
            # 创建节点位置
            pos = nx.spring_layout(dependency_graph)
            
            # 获取节点类型
            node_types = nx.get_node_attributes(dependency_graph, 'type')
            
            # 按类型设置节点颜色
            node_colors = []
            for node in dependency_graph.nodes():
                node_type = node_types.get(node, 'unknown')
                if node_type == 'function':
                    node_colors.append('skyblue')
                elif node_type == 'class':
                    node_colors.append('lightgreen')
                elif node_type == 'module':
                    node_colors.append('orange')
                else:
                    node_colors.append('gray')
            
            # 获取节点标签(使用名称而不是ID)
            node_labels = nx.get_node_attributes(dependency_graph, 'name')
            
            # 绘制节点
            nx.draw_networkx_nodes(dependency_graph, pos, 
                                  node_size=700, 
                                  node_color=node_colors, 
                                  alpha=0.8)
            
            # 绘制边
            nx.draw_networkx_edges(dependency_graph, pos, 
                                  arrowsize=15, 
                                  arrowstyle='->', 
                                  width=1.5, 
                                  alpha=0.6)
            
            # 绘制标签
            nx.draw_networkx_labels(dependency_graph, pos, 
                                   labels=node_labels, 
                                   font_size=10)
            
            plt.title('代码依赖关系图')
            plt.axis('off')  # 关闭坐标轴
            
            # 调整布局
            plt.tight_layout()
            
            # 转换为base64编码的图像
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=150)
            buffer.seek(0)
            plt.close()
            
            # 转换为可嵌入HTML的数据URL
            image_data = base64.b64encode(buffer.read()).decode('utf-8')
            return f"data:image/png;base64,{image_data}"
            
        except Exception as e:
            logger.error(f"渲染依赖关系图时出错: {e}")
            return ""
