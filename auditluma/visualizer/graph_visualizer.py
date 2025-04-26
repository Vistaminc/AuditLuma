"""
图形可视化器 - 负责生成代码依赖关系图
"""

import os
import json
import tempfile
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import base64
import io

from loguru import logger
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # 使用非交互式后端
import networkx as nx

from auditluma.config import Config


class GraphVisualizer:
    """AuditLuma图形可视化器 - 负责可视化代码依赖关系和热点图"""
    
    def __init__(self):
        """初始化图形可视化器"""
        self.output_dir = Path(Config.get_report_dir())
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def visualize_dependency_graph(self, dependency_graph: nx.DiGraph, 
                                file_path: Optional[str] = None) -> str:
        """可视化代码依赖关系图
        
        Args:
            dependency_graph: 代码依赖关系图
            file_path: 输出文件路径(可选)
            
        Returns:
            生成的图形文件路径或base64编码的图像数据
        """
        try:
            if not dependency_graph or dependency_graph.number_of_nodes() == 0:
                logger.warning("依赖图为空，无法生成可视化")
                return ""
            
            # 设置图形大小
            plt.figure(figsize=(12, 10))
            
            # 创建节点位置 - 使用force-directed布局
            pos = nx.spring_layout(dependency_graph, k=0.3, iterations=50)
            
            # 根据节点类型划分颜色
            node_types = nx.get_node_attributes(dependency_graph, 'type')
            node_colors = []
            node_sizes = []
            
            # 节点类型颜色映射
            color_map = {
                'function': 'skyblue',
                'class': 'lightgreen',
                'module': 'orange',
                'method': 'pink',
                'variable': 'yellow',
                'external': 'gray'
            }
            
            # 节点类型大小映射
            size_map = {
                'function': 700,
                'class': 900,
                'module': 1100,
                'method': 600,
                'variable': 500,
                'external': 400
            }
            
            # 应用颜色和大小映射
            for node in dependency_graph.nodes():
                node_type = node_types.get(node, 'unknown')
                node_colors.append(color_map.get(node_type, 'gray'))
                node_sizes.append(size_map.get(node_type, 600))
            
            # 获取节点标签(使用名称而不是ID)
            node_labels = nx.get_node_attributes(dependency_graph, 'name')
            if not node_labels:
                # 如果没有名称属性，使用节点ID作为标签
                node_labels = {node: str(node) for node in dependency_graph.nodes()}
            
            # 获取边类型
            edge_types = nx.get_edge_attributes(dependency_graph, 'type')
            edge_colors = []
            
            # 边类型颜色映射
            edge_color_map = {
                'import': 'blue',
                'call': 'red',
                'inherit': 'green',
                'use': 'purple',
                'unknown': 'gray'
            }
            
            # 应用边颜色
            for edge in dependency_graph.edges():
                edge_type = edge_types.get(edge, 'unknown')
                edge_colors.append(edge_color_map.get(edge_type, 'gray'))
            
            # 绘制节点
            nx.draw_networkx_nodes(dependency_graph, pos, 
                                 node_size=node_sizes, 
                                 node_color=node_colors, 
                                 alpha=0.8)
            
            # 绘制边
            nx.draw_networkx_edges(dependency_graph, pos, 
                                 arrowsize=15, 
                                 arrowstyle='->', 
                                 width=1.5, 
                                 alpha=0.6,
                                 edge_color=edge_colors)
            
            # 绘制标签 - 可能需要截断过长的标签
            truncated_labels = {k: (v[:15] + '...' if len(v) > 15 else v) 
                               for k, v in node_labels.items()}
            nx.draw_networkx_labels(dependency_graph, pos, 
                                  labels=truncated_labels, 
                                  font_size=10,
                                  font_family='sans-serif')
            
            plt.title('代码依赖关系图')
            plt.axis('off')  # 关闭坐标轴
            
            # 添加图例
            legend_elements = [
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['function'], 
                          label='函数', markersize=10),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['class'], 
                          label='类', markersize=10),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['module'], 
                          label='模块', markersize=10),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['method'], 
                          label='方法', markersize=10),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['external'], 
                          label='外部依赖', markersize=10)
            ]
            
            plt.legend(handles=legend_elements, loc='upper right')
            
            # 调整布局
            plt.tight_layout()
            
            # 如果提供了文件路径，保存到文件
            if file_path:
                plt.savefig(file_path, format='png', dpi=150)
                plt.close()
                logger.info(f"依赖图已保存到: {file_path}")
                return file_path
            else:
                # 转换为base64编码
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png', dpi=150)
                buffer.seek(0)
                plt.close()
                
                # 转换为base64编码的字符串
                image_data = base64.b64encode(buffer.read()).decode('utf-8')
                return f"data:image/png;base64,{image_data}"
                
        except Exception as e:
            logger.error(f"可视化依赖图时出错: {e}")
            return ""
    
    def create_interactive_graph(self, dependency_graph: nx.DiGraph, 
                              output_file: Optional[str] = None) -> str:
        """创建交互式依赖关系图
        
        Args:
            dependency_graph: 代码依赖关系图
            output_file: 输出HTML文件路径(可选)
            
        Returns:
            生成的HTML文件路径
        """
        try:
            # 检查是否有pyvis库
            try:
                from pyvis.network import Network
            except ImportError:
                logger.warning("未安装pyvis库，无法创建交互式图表")
                # 回退到静态图表
                if not output_file:
                    output_file = str(self.output_dir / "dependency_graph.png")
                return self.visualize_dependency_graph(dependency_graph, output_file)
            
            # 创建交互式网络图
            net = Network(height="750px", width="100%", directed=True, notebook=False)
            
            # 获取节点属性
            node_types = nx.get_node_attributes(dependency_graph, 'type')
            node_names = nx.get_node_attributes(dependency_graph, 'name')
            node_files = nx.get_node_attributes(dependency_graph, 'file_path')
            
            # 节点类型颜色映射
            color_map = {
                'function': '#00BFFF',  # 深天蓝
                'class': '#90EE90',     # 淡绿色
                'module': '#FFA500',    # 橙色
                'method': '#FFC0CB',    # 粉色
                'variable': '#FFFF00',  # 黄色
                'external': '#C0C0C0'   # 灰色
            }
            
            # 添加节点
            for node_id in dependency_graph.nodes():
                node_type = node_types.get(node_id, 'unknown')
                node_name = node_names.get(node_id, str(node_id))
                node_file = node_files.get(node_id, "")
                
                # 构建节点标题(悬停时显示)
                title = f"ID: {node_id}<br>Type: {node_type}<br>File: {node_file}"
                
                # 添加到网络图
                net.add_node(
                    node_id, 
                    label=node_name, 
                    title=title,
                    color=color_map.get(node_type, '#C0C0C0')
                )
            
            # 获取边属性
            edge_types = nx.get_edge_attributes(dependency_graph, 'type')
            edge_descs = nx.get_edge_attributes(dependency_graph, 'description')
            
            # 边类型颜色映射
            edge_color_map = {
                'import': '#0000FF',   # 蓝色
                'call': '#FF0000',     # 红色
                'inherit': '#008000',  # 绿色
                'use': '#800080',      # 紫色
                'unknown': '#A9A9A9'   # 深灰色
            }
            
            # 添加边
            for source, target in dependency_graph.edges():
                edge_type = edge_types.get((source, target), 'unknown')
                edge_desc = edge_descs.get((source, target), "")
                
                # 添加到网络图
                net.add_edge(
                    source, 
                    target, 
                    title=f"Type: {edge_type}<br>Desc: {edge_desc}",
                    color=edge_color_map.get(edge_type, '#A9A9A9')
                )
            
            # 配置交互选项
            net.toggle_physics(True)
            net.show_buttons()
            
            # 生成输出文件路径
            if not output_file:
                output_file = str(self.output_dir / "interactive_dependency_graph.html")
            
            # 保存为HTML文件
            net.save_graph(output_file)
            logger.info(f"交互式依赖图已保存到: {output_file}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"创建交互式依赖图时出错: {e}")
            
            # 回退到静态图表
            if not output_file:
                output_file = str(self.output_dir / "dependency_graph.png")
            return self.visualize_dependency_graph(dependency_graph, output_file)
    
    def create_vulnerability_heatmap(self, vulnerabilities: List[Any], 
                                  file_paths: List[str],
                                  output_file: Optional[str] = None) -> str:
        """创建漏洞热点图
        
        Args:
            vulnerabilities: 漏洞列表
            file_paths: 文件路径列表
            output_file: 输出文件路径(可选)
            
        Returns:
            生成的热点图文件路径或base64编码的图像数据
        """
        try:
            # 如果没有漏洞或文件，返回空
            if not vulnerabilities or not file_paths:
                logger.warning("没有漏洞或文件，无法创建热点图")
                return ""
            
            # 按文件和严重程度统计漏洞数量
            severity_levels = ["critical", "high", "medium", "low", "info"]
            
            # 初始化统计
            # 使用文件名(而不是完整路径)作为标签
            file_names = [Path(path).name for path in file_paths]
            stats = {file: {sev: 0 for sev in severity_levels} for file in file_names}
            
            # 文件路径到文件名的映射
            path_to_name = {path: Path(path).name for path in file_paths}
            
            # 统计每个文件中各严重程度的漏洞数量
            for vuln in vulnerabilities:
                file_path = vuln.file_path
                file_name = path_to_name.get(file_path)
                if not file_name:
                    continue
                    
                severity = vuln.severity.lower()
                if severity not in severity_levels:
                    severity = "info"  # 默认为info级别
                
                if file_name in stats:
                    stats[file_name][severity] += 1
            
            # 转换为热点图数据
            files = []
            criticals = []
            highs = []
            mediums = []
            lows = []
            infos = []
            
            # 获取排名前15的文件(按漏洞总数)
            files_with_scores = []
            for file, severities in stats.items():
                total = sum(severities.values())
                # 使用加权分数:critical*5 + high*4 + medium*3 + low*2 + info*1
                weighted = (severities["critical"] * 5 + 
                           severities["high"] * 4 + 
                           severities["medium"] * 3 + 
                           severities["low"] * 2 + 
                           severities["info"])
                files_with_scores.append((file, total, weighted))
            
            # 按加权分数排序
            files_with_scores.sort(key=lambda x: x[2], reverse=True)
            
            # 只取前15个文件
            top_files = [f[0] for f in files_with_scores[:15]]
            
            # 准备绘图数据
            for file in top_files:
                files.append(file)
                criticals.append(stats[file]["critical"])
                highs.append(stats[file]["high"])
                mediums.append(stats[file]["medium"])
                lows.append(stats[file]["low"])
                infos.append(stats[file]["info"])
            
            # 创建叠加条形图
            plt.figure(figsize=(12, 8))
            
            # 设置底部位置
            bottoms = [0] * len(files)
            
            # 创建条形
            p1 = plt.barh(files, criticals, left=bottoms, color='red', label='严重')
            
            # 更新底部位置
            bottoms = [a + b for a, b in zip(bottoms, criticals)]
            p2 = plt.barh(files, highs, left=bottoms, color='orange', label='高')
            
            bottoms = [a + b for a, b in zip(bottoms, highs)]
            p3 = plt.barh(files, mediums, left=bottoms, color='yellow', label='中')
            
            bottoms = [a + b for a, b in zip(bottoms, mediums)]
            p4 = plt.barh(files, lows, left=bottoms, color='green', label='低')
            
            bottoms = [a + b for a, b in zip(bottoms, lows)]
            p5 = plt.barh(files, infos, left=bottoms, color='blue', label='信息')
            
            # 添加标题和标签
            plt.title('文件漏洞热点图')
            plt.xlabel('漏洞数量')
            plt.ylabel('文件名')
            
            # 添加图例
            plt.legend()
            
            # 调整布局
            plt.tight_layout()
            
            # 如果提供了文件路径，保存到文件
            if output_file:
                plt.savefig(output_file, format='png', dpi=150)
                plt.close()
                logger.info(f"漏洞热点图已保存到: {output_file}")
                return output_file
            else:
                # 转换为base64编码
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png', dpi=150)
                buffer.seek(0)
                plt.close()
                
                # 转换为base64编码的字符串
                image_data = base64.b64encode(buffer.read()).decode('utf-8')
                return f"data:image/png;base64,{image_data}"
                
        except Exception as e:
            logger.error(f"创建漏洞热点图时出错: {e}")
            return ""
