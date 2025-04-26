"""
代码分析智能体 - 专门负责分析代码结构和依赖关系
"""

import os
import re
import asyncio
from typing import List, Dict, Any, Optional, Tuple, Union, Set
import uuid
import json
import networkx as nx
from pathlib import Path

from loguru import logger

from auditluma.config import Config
from auditluma.agents.base import BaseAgent
from auditluma.mcp.protocol import MessageType, MessagePriority
from auditluma.models.code import SourceFile, CodeUnit
from auditluma.rag.self_rag import self_rag


class CodeAnalyzerAgent(BaseAgent):
    """代码分析智能体 - 负责分析代码结构和依赖关系"""
    
    def __init__(self, agent_id: Optional[str] = None):
        """初始化代码分析智能体"""
        super().__init__(agent_id, agent_type="code_analyzer")
        self.description = "分析代码结构和依赖关系"
        
        # 初始化LLM客户端
        from auditluma.utils import init_llm_client
        self.llm_client = init_llm_client()
        
        # 依赖关系图
        self.dependency_graph = nx.DiGraph()
        
        # 代码结构缓存
        self.code_structure_cache = {}
        
        # 特定消息处理器
        self.register_handler(MessageType.QUERY, self._handle_code_query)
    
    async def execute_task(self, task_type: str, task_data: Any) -> Any:
        """执行任务 - 实现基类的抽象方法"""
        if task_type == "analyze_code_structure":
            return await self._analyze_code_structure(task_data)
        elif task_type == "analyze_code_structure_group":
            return await self._analyze_code_structure_group(task_data)
        elif task_type == "analyze_dependencies":
            return await self._analyze_dependencies(task_data)
        elif task_type == "get_call_path":
            return await self._get_call_path(task_data)
        else:
            raise ValueError(f"不支持的任务类型: {task_type}")
    
    async def _handle_code_query(self, message: Any) -> None:
        """处理代码相关查询"""
        query = message.content.get("query")
        code_unit_id = message.content.get("code_unit_id")
        
        if not query:
            await self.send_error(
                receiver=message.sender,
                content={"error": "缺少查询参数"},
                reply_to=message.message_id
            )
            return
        
        # 如果提供了代码单元ID，分析该代码单元
        if code_unit_id and code_unit_id in self.code_structure_cache:
            code_info = self.code_structure_cache[code_unit_id]
            await self.send_response(
                receiver=message.sender,
                content={"code_info": code_info},
                reply_to=message.message_id
            )
        else:
            # 尝试检索相关代码信息
            context_docs = await self.retrieve_context(query)
            await self.send_response(
                receiver=message.sender,
                content={"context": [doc.content for doc in context_docs]},
                reply_to=message.message_id
            )
    
    async def _analyze_code_structure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """分析代码结构，构建依赖关系图"""
        code_units = data.get("code_units", [])
        if not code_units:
            logger.warning("没有提供代码单元进行分析")
            return {}
        
        logger.info(f"开始分析 {len(code_units)} 个代码单元的结构")
        
        # 清空之前的图
        self.dependency_graph = nx.DiGraph()
        self.code_structure_cache = {}
        
        # 首先添加所有节点到图中
        for unit in code_units:
            self.dependency_graph.add_node(
                unit.id,
                name=unit.name,
                type=unit.type,
                file_path=str(unit.source_file.path),
                start_line=unit.start_line,
                end_line=unit.end_line
            )
            
            # 缓存代码单元信息
            self.code_structure_cache[unit.id] = {
                "id": unit.id,
                "name": unit.name,
                "type": unit.type,
                "file_path": str(unit.source_file.path),
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "parent_id": unit.parent_id,
                "dependencies": [],
                "dependents": [],
                "complexity": 0,
                "metrics": {}
            }
        
        # 分析代码单元间的依赖关系
        results = await self._analyze_code_dependencies(code_units)
        
        # 更新依赖关系图和缓存
        for source_id, target_id, attributes in results:
            # 添加边到图中
            self.dependency_graph.add_edge(
                source_id, 
                target_id,
                **attributes
            )
            
            # 更新缓存
            if source_id in self.code_structure_cache:
                self.code_structure_cache[source_id]["dependencies"].append({
                    "id": target_id,
                    "type": attributes.get("type", "unknown"),
                    "description": attributes.get("description", "")
                })
            
            if target_id in self.code_structure_cache:
                self.code_structure_cache[target_id]["dependents"].append({
                    "id": source_id,
                    "type": attributes.get("type", "unknown"),
                    "description": attributes.get("description", "")
                })
        
        # 计算每个单元的复杂度
        for unit in code_units:
            complexity = await self._calculate_complexity(unit)
            if unit.id in self.code_structure_cache:
                self.code_structure_cache[unit.id]["complexity"] = complexity
                
                # 添加额外度量
                self.code_structure_cache[unit.id]["metrics"] = {
                    "lines_of_code": unit.end_line - unit.start_line + 1,
                    "cyclomatic_complexity": complexity,
                    "dependency_count": len(self.code_structure_cache[unit.id]["dependencies"]),
                    "dependent_count": len(self.code_structure_cache[unit.id]["dependents"])
                }
        
        logger.info(f"代码结构分析完成，发现 {self.dependency_graph.number_of_edges()} 个依赖关系")
        
        # 返回分析结果
        return self.code_structure_cache
    
    async def _analyze_code_dependencies(self, code_units: List[CodeUnit]) -> List[Tuple[str, str, Dict[str, Any]]]:
        """分析代码单元之间的依赖关系"""
        dependencies = []
        tasks = []
        semaphore = asyncio.Semaphore(10)  # 限制并发
        
        async def analyze_unit_dependencies(unit):
            async with semaphore:
                try:
                    # 获取上下文
                    context_docs = await self.retrieve_context(unit.content)
                    context_text = "\n\n".join([doc.content for doc in context_docs])
                    
                    # 准备提示
                    prompt = self._prepare_dependency_prompt(unit, context_text)
                    
                    # 调用LLM分析依赖，确保使用聊天模型而不是嵌入模型
                    provider_config = Config.get_llm_provider_config(Config.agent.default_provider)
                    chat_model = provider_config.model  # 使用配置中的聊天模型
                    
                    response = await self.llm_client.chat.completions.create(
                        model=chat_model,
                        messages=[
                            {"role": "system", "content": prompt["system"]},
                            {"role": "user", "content": prompt["user"]}
                        ],
                        temperature=0.1
                    )
                    
                    # 解析结果
                    analysis_text = response.choices[0].message.content
                    return self._parse_dependency_analysis(analysis_text, unit)
                    
                except Exception as e:
                    logger.error(f"分析代码单元依赖关系时出错: {unit.name}, {e}")
                    return []
        
        # 为每个代码单元创建任务
        for unit in code_units:
            task = asyncio.create_task(analyze_unit_dependencies(unit))
            tasks.append(task)
        
        # 等待所有任务完成
        results = await asyncio.gather(*tasks)
        
        # 合并所有依赖关系
        for deps in results:
            dependencies.extend(deps)
        
        return dependencies
    
    def _prepare_dependency_prompt(self, unit: CodeUnit, context_text: str) -> Dict[str, str]:
        """准备用于依赖分析的提示"""
        system_prompt = """
你是一个代码依赖分析专家。请分析提供的代码单元，并识别其中的依赖关系。
请关注以下类型的依赖：
1. 导入/引用 - 代码单元导入或引用的外部模块、包或文件
2. 调用 - 代码单元调用的函数、方法或API
3. 继承 - 类继承关系
4. 使用 - 代码单元使用的变量、常量或数据结构

请使用以下格式输出分析结果：
<依赖分析>
[依赖1]
- 源: 当前代码单元的名称或ID
- 目标: 被依赖对象的名称
- 类型: 依赖类型（导入、调用、继承、使用）
- 描述: 简要描述依赖关系
- 位置: 依赖出现的行号

[依赖2]
...
</依赖分析>

如果没有发现依赖关系，请回复：
<依赖分析>
未发现依赖关系。
</依赖分析>

请基于代码事实进行分析，避免过度解读或假设。
"""
        
        user_prompt = f"""
以下是需要分析的代码单元信息：

文件路径: {unit.source_file.path}
单元名称: {unit.name}
单元类型: {unit.type}
行范围: {unit.start_line}-{unit.end_line}
代码语言: {unit.source_file.file_type}

代码内容:
```
{unit.content}
```
"""
        
        # 如果有上下文，添加到提示中
        if context_text:
            user_prompt += f"""
相关上下文信息:
```
{context_text[:2000]}  # 限制上下文长度
```
"""
        
        return {
            "system": system_prompt,
            "user": user_prompt
        }
    
    def _parse_dependency_analysis(self, analysis_text: str, unit: CodeUnit) -> List[Tuple[str, str, Dict[str, Any]]]:
        """解析LLM返回的依赖分析结果"""
        dependencies = []
        
        # 提取<依赖分析>标签之间的内容
        import re
        analysis_pattern = r"<依赖分析>(.*?)</依赖分析>"
        matches = re.search(analysis_pattern, analysis_text, re.DOTALL)
        
        if not matches:
            logger.warning(f"无法从LLM响应中提取依赖分析结果: {unit.name}")
            return dependencies
        
        analysis_content = matches.group(1).strip()
        
        # 检查是否未发现依赖关系
        if "未发现依赖关系" in analysis_content:
            return dependencies
        
        # 提取各个依赖项
        dependency_pattern = r"\[依赖\d+\](.*?)(?=\[依赖\d+\]|\Z)"
        dependency_matches = re.finditer(dependency_pattern, analysis_content, re.DOTALL)
        
        # 用于存储已处理的依赖，避免重复
        processed_deps = set()
        
        for match in dependency_matches:
            dep_text = match.group(1).strip()
            
            # 解析依赖属性
            source = self._extract_property(dep_text, "源") or unit.name
            target = self._extract_property(dep_text, "目标")
            dep_type = self._extract_property(dep_text, "类型")
            description = self._extract_property(dep_text, "描述")
            location = self._extract_property(dep_text, "位置")
            
            if not target:
                continue
                
            # 查找目标单元ID
            target_id = self._find_target_unit_id(target, unit.source_file.path)
            if not target_id:
                # 如果找不到目标ID，创建一个外部依赖节点
                target_id = f"external_{hashlib.md5(target.encode()).hexdigest()[:12]}"
                self.dependency_graph.add_node(
                    target_id,
                    name=target,
                    type="external",
                    file_path="external",
                    start_line=0,
                    end_line=0
                )
            
            # 创建一个唯一标识符，避免重复依赖
            dep_key = f"{unit.id}:{target_id}:{dep_type}"
            if dep_key in processed_deps:
                continue
                
            processed_deps.add(dep_key)
            
            # 解析行号
            line_number = None
            if location:
                try:
                    line_number = int(re.search(r'\d+', location).group())
                except (AttributeError, ValueError):
                    pass
            
            # 添加依赖关系
            dep_attrs = {
                "type": dep_type or "unknown",
                "description": description or f"{unit.name} 依赖 {target}",
                "line_number": line_number
            }
            
            dependencies.append((unit.id, target_id, dep_attrs))
        
        return dependencies
    
    def _extract_property(self, text: str, property_name: str) -> Optional[str]:
        """从文本中提取属性值"""
        import re
        pattern = rf"- {property_name}: ?(.*?)(?=\n- |\n\n|\Z)"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None
    
    def _find_target_unit_id(self, target_name: str, source_file_path: str) -> Optional[str]:
        """查找目标单元的ID"""
        # 先在依赖图中查找完全匹配的节点
        for node_id, attrs in self.dependency_graph.nodes(data=True):
            if attrs.get("name") == target_name:
                return node_id
        
        # 如果没有完全匹配，尝试查找部分匹配
        # 优先考虑同一文件中的单元
        best_match = None
        best_score = 0
        
        for node_id, attrs in self.dependency_graph.nodes(data=True):
            name = attrs.get("name", "")
            file_path = attrs.get("file_path", "")
            
            # 计算匹配分数
            score = 0
            if target_name in name:
                score += 5
            elif name in target_name:
                score += 3
                
            # 同一文件加分
            if file_path == source_file_path:
                score += 2
                
            if score > best_score:
                best_score = score
                best_match = node_id
        
        # 只有当分数足够高时才返回匹配结果
        if best_score >= 5:
            return best_match
            
        return None
    
    async def _calculate_complexity(self, unit: CodeUnit) -> int:
        """计算代码单元的复杂度
        
        简单估算代码复杂度，主要基于代码行数和条件分支数量
        
        Args:
            unit: 代码单元
            
        Returns:
            复杂度评分
        """
        try:
            # 基础复杂度从代码行数开始
            complexity = unit.end_line - unit.start_line + 1
            
            # 计算分支语句数量（if, for, while等）
            branch_patterns = [
                r'\bif\b', r'\belse\b', r'\belif\b', r'\bfor\b', r'\bwhile\b', 
                r'\btry\b', r'\bexcept\b', r'\bcatch\b', r'\bswitch\b', r'\bcase\b'
            ]
            
            for pattern in branch_patterns:
                matches = re.findall(pattern, unit.content)
                complexity += len(matches) * 2  # 每个分支增加2点复杂度
            
            # 计算函数/方法调用
            function_calls = re.findall(r'\w+\(', unit.content)
            complexity += len(function_calls)
            
            # 最低复杂度为1
            return max(1, complexity)
        except Exception as e:
            logger.warning(f"计算代码复杂度时出错: {e}")
            return 1  # 出错时返回最低复杂度
    
    async def _analyze_code_structure_group(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """分析特定类型组的代码结构，用于并发处理
        
        Args:
            data: 包含代码单元组和单元类型的数据
            
        Returns:
            该组的代码结构分析结果
        """
        code_units = data.get("code_units", [])
        unit_type = data.get("unit_type", "unknown")
        
        if not code_units:
            logger.warning(f"没有提供代码单元进行分析，类型: {unit_type}")
            return {}
        
        logger.info(f"开始分析 {len(code_units)} 个类型为 {unit_type} 的代码单元")
        
        # 分析结果存储
        group_results = {}
        
        # 首先添加所有节点到图中
        for unit in code_units:
            self.dependency_graph.add_node(
                unit.id,
                name=unit.name,
                type=unit.type,
                file_path=str(unit.source_file.path),
                start_line=unit.start_line,
                end_line=unit.end_line
            )
            
            # 缓存代码单元信息
            unit_info = {
                "id": unit.id,
                "name": unit.name,
                "type": unit.type,
                "file_path": str(unit.source_file.path),
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "parent_id": unit.parent_id,
                "dependencies": [],
                "dependents": [],
                "complexity": 0,
                "metrics": {}
            }
            
            self.code_structure_cache[unit.id] = unit_info
            group_results[unit.id] = unit_info
        
        # 分析代码单元间的依赖关系
        dependencies = await self._analyze_code_dependencies(code_units)
        
        # 更新依赖关系图和缓存
        for source_id, target_id, attributes in dependencies:
            # 添加边到图中
            self.dependency_graph.add_edge(
                source_id, 
                target_id,
                **attributes
            )
            
            # 更新缓存和结果
            if source_id in self.code_structure_cache:
                self.code_structure_cache[source_id]["dependencies"].append({
                    "id": target_id,
                    "type": attributes.get("type", "unknown"),
                    "description": attributes.get("description", "")
                })
                
                if source_id in group_results:
                    group_results[source_id]["dependencies"].append({
                        "id": target_id,
                        "type": attributes.get("type", "unknown"),
                        "description": attributes.get("description", "")
                    })
            
            if target_id in self.code_structure_cache:
                self.code_structure_cache[target_id]["dependents"].append({
                    "id": source_id,
                    "type": attributes.get("type", "unknown"),
                    "description": attributes.get("description", "")
                })
                
                if target_id in group_results:
                    group_results[target_id]["dependents"].append({
                        "id": source_id,
                        "type": attributes.get("type", "unknown"),
                        "description": attributes.get("description", "")
                    })
        
        # 计算每个单元的复杂度
        for unit in code_units:
            complexity = await self._calculate_complexity(unit)
            
            if unit.id in self.code_structure_cache:
                self.code_structure_cache[unit.id]["complexity"] = complexity
                
                # 添加额外度量
                metrics = {
                    "lines_of_code": unit.end_line - unit.start_line + 1,
                    "cyclomatic_complexity": complexity,
                    "dependency_count": len(self.code_structure_cache[unit.id]["dependencies"]),
                    "dependent_count": len(self.code_structure_cache[unit.id]["dependents"])
                }
                
                self.code_structure_cache[unit.id]["metrics"] = metrics
                
                if unit.id in group_results:
                    group_results[unit.id]["complexity"] = complexity
                    group_results[unit.id]["metrics"] = metrics
        
        logger.info(f"完成 {len(code_units)} 个类型为 {unit_type} 的代码单元分析")
        return group_results
