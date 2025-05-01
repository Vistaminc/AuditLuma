"""
智能体协调器 - 管理和协调多个智能体的工作流程
"""

import asyncio
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
import time

from loguru import logger

from auditluma.config import Config
from auditluma.mcp.protocol import agent_coordinator, MessageType
from auditluma.agents.base import BaseAgent
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult
from auditluma.rag.self_rag import self_rag


class AgentOrchestrator:
    """管理和协调多个智能体的协调器"""
    
    def __init__(self, workers: int = 10):
        """初始化协调器"""
        self.workers = workers
        self.agents = {}  # 存储已初始化的智能体
        self.code_units = []  # 解析的代码单元
        self.task_queue = asyncio.Queue()
        self.result_queue = asyncio.Queue()
        self.dependency_graph = None  # 代码依赖关系图
    
    async def initialize_agents(self) -> None:
        """初始化所有需要的智能体"""
        # 检查是否启用MCP
        if not Config.mcp.enabled:
            logger.warning("MCP已禁用，使用简化的单智能体模式")
            # 仅初始化必须的智能体
            await self._init_security_analyst()
            return
        
        # 根据配置初始化所有智能体
        agent_configs = sorted(Config.mcp.agents, key=lambda x: x.priority)
        
        for agent_config in agent_configs:
            await self._init_agent(agent_config.name, agent_config.type)
        
        logger.info(f"已初始化 {len(self.agents)} 个智能体")
    
    async def _init_agent(self, name: str, agent_type: str) -> BaseAgent:
        """初始化特定类型的智能体"""
        agent = None
        agent_id = f"{name}_{uuid.uuid4().hex[:6]}"
        
        # 查找该名称智能体的MCP配置
        agent_config = next((a for a in Config.mcp.agents if a.name == name), None)
        model_spec = None
        
        # 如果找到配置并指定了模型，使用指定的模型
        if agent_config and agent_config.model:
            model_spec = agent_config.model
            logger.info(f"使用MCP配置中指定的模型 '{model_spec}' 初始化智能体: {name}")
        
        if agent_type == "analyzer":
            from auditluma.agents.code_analyzer import CodeAnalyzerAgent
            agent = CodeAnalyzerAgent(agent_id, model_spec)
        elif agent_type == "analyst":
            from auditluma.agents.security_analyst import SecurityAnalystAgent
            agent = SecurityAnalystAgent(agent_id, model_spec)
        elif agent_type == "generator":
            from auditluma.agents.remediation import RemediationAgent
            agent = RemediationAgent(agent_id, model_spec)
        elif agent_type == "coordinator":
            from auditluma.agents.orchestrator import OrchestratorAgent
            agent = OrchestratorAgent(agent_id, model_spec)
        else:
            logger.warning(f"未知的智能体类型: {agent_type}")
            return None
        
        if agent:
            await agent.start()
            self.agents[agent_id] = agent
            logger.info(f"初始化了智能体: {name} (ID: {agent_id}, 类型: {agent_type})")
        
        return agent
    
    async def _init_security_analyst(self) -> None:
        """初始化安全分析智能体（简化模式）"""
        try:
            from auditluma.agents.security_analyst import SecurityAnalystAgent
            agent_id = f"security_analyst_{uuid.uuid4().hex[:6]}"
            agent = SecurityAnalystAgent(agent_id)
            await agent.start()
            self.agents[agent_id] = agent
            logger.info(f"初始化了安全分析智能体: {agent_id}")
        except Exception as e:
            logger.error(f"初始化安全分析智能体时出错: {e}")
            raise
    
    async def extract_code_units(self, source_files: List[SourceFile]) -> List[CodeUnit]:
        """从源文件中提取代码单元
        
        Args:
            source_files: 源文件列表
            
        Returns:
            代码单元列表
        """
        # 清空之前的代码单元
        self.code_units = []
        
        # 提取代码单元
        await self._extract_code_units(source_files)
        
        return self.code_units
    
    async def run_code_structure_analysis(self, code_units: List[CodeUnit]) -> Dict[str, Any]:
        """运行代码结构分析
        
        Args:
            code_units: 代码单元列表
            
        Returns:
            代码结构分析结果
        """
        logger.info(f"开始代码结构分析，分析 {len(code_units)} 个代码单元")
        
        # 查找代码分析智能体
        code_analyzer = next((a for a in self.agents.values() if a.agent_type == "code_analyzer"), None)
        
        if not code_analyzer:
            logger.warning("未找到代码分析智能体，尝试初始化")
            code_analyzer = await self._init_agent("code_analyzer", "analyzer")
            
        if not code_analyzer:
            logger.error("无法初始化代码分析智能体")
            return {}
        
        try:
            # 使用并行处理分析代码结构
            tasks = []
            semaphore = asyncio.Semaphore(self.workers)
            all_structure_results = {}
            
            # 根据代码单元类型进行分组
            units_by_type = {}
            for unit in code_units:
                unit_type = unit.type
                if unit_type not in units_by_type:
                    units_by_type[unit_type] = []
                units_by_type[unit_type].append(unit)
            
            # 定义并发处理函数
            async def analyze_unit_group(unit_type, units):
                async with semaphore:
                    try:
                        group_task_data = {"code_units": units, "unit_type": unit_type}
                        group_result = await code_analyzer.execute_task("analyze_code_structure_group", group_task_data)
                        return group_result
                    except Exception as e:
                        logger.error(f"分析代码单元组 {unit_type} 时出错: {e}")
                        return {}
            
            # 为每个类型组创建任务
            for unit_type, units in units_by_type.items():
                logger.debug(f"为 {unit_type} 类型创建分析任务，包含 {len(units)} 个单元")
                task = asyncio.create_task(analyze_unit_group(unit_type, units))
                tasks.append(task)
            
            # 等待所有任务完成
            group_results = await asyncio.gather(*tasks)
            
            # 合并所有结果
            for result in group_results:
                if result:
                    all_structure_results.update(result)
            
            # 保存依赖图供后续使用
            if hasattr(code_analyzer, "dependency_graph"):
                self.dependency_graph = code_analyzer.dependency_graph
                
            logger.info(f"代码结构分析完成，处理了 {len(all_structure_results)} 个代码单元")
            return all_structure_results
            
        except Exception as e:
            logger.error(f"代码结构分析时出错: {e}")
            return {}
    
    async def run_security_analysis(self, source_files: List[SourceFile]) -> List[VulnerabilityResult]:
        """运行安全漏洞分析
        
        Args:
            source_files: 源文件列表
            
        Returns:
            漏洞结果列表
        """
        logger.info(f"开始安全漏洞分析，分析 {len(source_files)} 个源文件")
        
        # 初始化智能体（如果尚未初始化）
        if not self.agents:
            await self.initialize_agents()
        
        # 如果启用了Self-RAG，准备知识库
        if Config.self_rag.enabled:
            logger.info("初始化Self-RAG知识库...")
            await self._batch_add_to_knowledge_base(source_files, batch_size=self.workers)
        
        # 提取代码单元（如果尚未提取）
        if not self.code_units:
            await self._extract_code_units(source_files)
            logger.info(f"从 {len(source_files)} 个文件中提取了 {len(self.code_units)} 个代码单元")
        
        # 在简化模式下使用安全分析智能体
        if not Config.mcp.enabled:
            return await self._run_simplified_analysis()
        
        # 查找安全分析智能体
        security_agent = next((a for a in self.agents.values() if a.agent_type == "security_analyst"), None)
        
        if not security_agent:
            logger.warning("未找到安全分析智能体，尝试初始化")
            security_agent = await self._init_agent("security_analyst", "analyst")
            
        if not security_agent:
            logger.error("无法初始化安全分析智能体")
            return []
        
        # 运行安全分析
        results = []
        tasks = []
        semaphore = asyncio.Semaphore(self.workers)
        
        async def analyze_unit(unit):
            async with semaphore:
                try:
                    task_data = {"code_unit": unit}
                    vulnerabilities = await security_agent.execute_task("analyze_code_security", task_data)
                    return vulnerabilities
                except Exception as e:
                    logger.error(f"分析代码单元时出错: {unit.name}, {e}")
                    return []
        
        # 为每个代码单元创建分析任务
        for unit in self.code_units:
            task = asyncio.create_task(analyze_unit(unit))
            tasks.append(task)
        
        # 等待所有任务完成
        unit_results = await asyncio.gather(*tasks)
        
        # 收集所有结果
        for vulns in unit_results:
            if vulns:
                results.extend(vulns)
        
        logger.info(f"安全分析完成，发现 {len(results)} 个漏洞")
        return results
    
    async def generate_remediations(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """为检测到的漏洞生成修复建议
        
        Args:
            vulnerabilities: 漏洞结果列表
            
        Returns:
            修复建议数据
        """
        if not vulnerabilities:
            logger.info("没有漏洞需要生成修复建议")
            return {
                "summary": "未发现需要修复的漏洞",
                "remediation_count": 0,
                "remediations": []
            }
        
        logger.info(f"开始为 {len(vulnerabilities)} 个漏洞生成修复建议")
        
        # 查找修复建议智能体
        remediation_agent = next((a for a in self.agents.values() if a.agent_type == "generator"), None)
        
        if not remediation_agent:
            logger.warning("未找到修复建议智能体，尝试初始化")
            remediation_agent = await self._init_agent("remediation", "generator")
            
        if not remediation_agent:
            logger.error("无法初始化修复建议智能体")
            return {
                "summary": "无法生成修复建议：修复建议智能体初始化失败",
                "remediation_count": 0,
                "remediations": []
            }
        
        try:
            # 按漏洞类型分组，以便相似的漏洞可以共享通用修复建议
            vuln_by_type = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.vulnerability_type
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                vuln_by_type[vuln_type].append(vuln)
            
            # 创建分析任务
            all_remediations = []
            tasks = []
            semaphore = asyncio.Semaphore(self.workers)  # 控制并发数
            
            # 将修复建议生成分解为并发任务
            async def process_vulnerability(vuln):
                async with semaphore:
                    try:
                        # 对单个漏洞执行修复建议生成
                        task_data = {"vulnerabilities": [vuln]}
                        result = await remediation_agent.execute_task("generate_remediation", task_data)
                        if result and "remediations" in result and len(result["remediations"]) > 0:
                            return result["remediations"][0]
                        return None
                    except Exception as e:
                        logger.error(f"生成漏洞 {vuln.id} 的修复建议时出错: {e}")
                        return None
            
            # 创建并发任务
            for vuln in vulnerabilities:
                task = asyncio.create_task(process_vulnerability(vuln))
                tasks.append(task)
            
            # 并发执行所有修复建议生成任务
            remediation_results = await asyncio.gather(*tasks)
            
            # 收集有效的修复建议
            for remediation in remediation_results:
                if remediation:
                    all_remediations.append(remediation)
            
            logger.info(f"修复建议生成完成，生成了 {len(all_remediations)} 个建议")
            
            return {
                "summary": f"生成了 {len(all_remediations)} 个漏洞修复建议",
                "remediation_count": len(all_remediations),
                "remediations": all_remediations
            }
            
        except Exception as e:
            logger.error(f"生成修复建议时出错: {e}")
            return {
                "summary": f"生成修复建议时出错: {str(e)}",
                "remediation_count": 0,
                "remediations": []
            }
    
    def get_dependency_graph(self):
        """获取代码依赖关系图
        
        Returns:
            依赖关系图对象
        """
        return self.dependency_graph
    
    async def run_analysis(self, source_files: List[SourceFile]) -> List[VulnerabilityResult]:
        """运行代码分析流程"""
        start_time = time.time()
        logger.info(f"开始分析 {len(source_files)} 个源文件")
        
        # 初始化智能体
        await self.initialize_agents()
        
        # 如果启用了Self-RAG，准备知识库
        if Config.self_rag.enabled:
            logger.info("初始化Self-RAG知识库...")
            for file in source_files:
                await self._add_to_knowledge_base(file)
        
        # 提取代码单元
        await self._extract_code_units(source_files)
        logger.info(f"从 {len(source_files)} 个文件中提取了 {len(self.code_units)} 个代码单元")
        
        # 在简化模式下使用安全分析智能体
        if not Config.mcp.enabled:
            return await self._run_simplified_analysis()
        
        # 使用MCP运行完整的多智能体分析
        return await self._run_mcp_analysis()
    
    async def _add_to_knowledge_base(self, file: SourceFile) -> None:
        """将源文件添加到Self-RAG知识库"""
        try:
            # 添加超时控制，防止长时间阻塞
            async def add_with_timeout():
                return await self_rag.add_source_file(file)
            
            # 设置超时为30秒
            try:
                await asyncio.wait_for(add_with_timeout(), timeout=30.0)
                logger.info(f"成功将文件 {file.path.name} 添加到知识库")
            except asyncio.TimeoutError:
                logger.warning(f"将文件 {file.path.name} 添加到知识库超时，将跳过嵌入但继续分析")
                # 记录文件但跳过嵌入处理
                self_rag.register_file_without_embedding(file)
        except Exception as e:
            logger.error(f"将文件添加到知识库时出错: {e}")
            # 出错时也注册文件，以确保分析可以继续
            try:
                self_rag.register_file_without_embedding(file)
            except:
                pass
    
    async def _batch_add_to_knowledge_base(self, files: List[SourceFile], batch_size: int = 5) -> None:
        """批量将源文件添加到Self-RAG知识库
        
        Args:
            files: 要添加的源文件列表
            batch_size: 每批处理的文件数量
        """
        logger.info(f"批量添加 {len(files)} 个文件到知识库，批次大小: {batch_size}")
        
        # 过滤掉已处理的文件
        files_to_process = [f for f in files if f.id not in self_rag.processed_files]
        if len(files_to_process) < len(files):
            logger.info(f"跳过 {len(files) - len(files_to_process)} 个已处理的文件")
        
        # 如果没有需要处理的文件，直接返回
        if not files_to_process:
            logger.info("没有新文件需要添加到知识库")
            return
            
        # 将文件分成批次
        batches = [files_to_process[i:i+batch_size] for i in range(0, len(files_to_process), batch_size)]
        logger.info(f"将 {len(files_to_process)} 个文件分成 {len(batches)} 个批次处理")
        
        # 批量处理文件
        for i, batch in enumerate(batches):
            logger.info(f"处理批次 {i+1}/{len(batches)}, 包含 {len(batch)} 个文件")
            
            # 创建并发任务
            tasks = []
            for file in batch:
                task = asyncio.create_task(self._add_to_knowledge_base(file))
                tasks.append(task)
            
            # 等待当前批次完成
            await asyncio.gather(*tasks)
            
        logger.info(f"完成批量添加 {len(files_to_process)} 个文件到知识库")
    
    async def _extract_code_units(self, source_files: List[SourceFile]) -> None:
        """从源文件中提取代码单元"""
        tasks = []
        semaphore = asyncio.Semaphore(self.workers)
        
        async def extract_units(file):
            async with semaphore:
                try:
                    from auditluma.parsers.code_parser import extract_code_units
                    units = await extract_code_units(file)
                    return units
                except Exception as e:
                    logger.error(f"从文件提取代码单元时出错: {file.path}, {e}")
                    return []
        
        # 为每个文件创建任务
        for file in source_files:
            task = asyncio.create_task(extract_units(file))
            tasks.append(task)
        
        # 等待所有任务完成
        results = await asyncio.gather(*tasks)
        
        # 收集所有代码单元
        all_units = []
        for units in results:
            if units:
                all_units.extend(units)
                self.code_units.extend(units)
                
        # 如果启用了Self-RAG，批量添加代码单元到知识库
        if Config.self_rag.enabled and all_units:
            logger.info(f"将提取的代码单元添加到知识库...")
            await self_rag.add_batch_code_units(all_units, max_concurrency=self.workers)
    
    async def _run_simplified_analysis(self) -> List[VulnerabilityResult]:
        """运行简化的单智能体分析流程"""
        security_agent = next((a for a in self.agents.values() if a.agent_type == "security_analyst"), None)
        
        if not security_agent:
            logger.error("未找到安全分析智能体")
            return []
        
        results = []
        tasks = []
        semaphore = asyncio.Semaphore(self.workers)
        
        async def analyze_unit(unit):
            async with semaphore:
                try:
                    task_data = {"code_unit": unit}
                    vulnerabilities = await security_agent.execute_task("analyze_code_security", task_data)
                    return vulnerabilities
                except Exception as e:
                    logger.error(f"分析代码单元时出错: {unit.name}, {e}")
                    return []
        
        # 为每个代码单元创建分析任务
        for unit in self.code_units:
            task = asyncio.create_task(analyze_unit(unit))
            tasks.append(task)
        
        # 等待所有任务完成
        unit_results = await asyncio.gather(*tasks)
        
        # 收集所有结果
        for vulns in unit_results:
            if vulns:
                results.extend(vulns)
        
        logger.info(f"简化分析完成，发现 {len(results)} 个漏洞")
        
        # 关闭所有智能体
        for agent in self.agents.values():
            await agent.stop()
        
        return results
    
    async def _run_mcp_analysis(self) -> List[VulnerabilityResult]:
        """运行完整的多智能体协作分析流程"""
        # 为了简化实现，我们将直接调用每个智能体，而不是使用消息总线
        # 在实际的MCP实现中，应该使用消息总线和任务系统
        
        # 1. 代码结构分析
        structure_results = await self.run_code_structure_analysis(self.code_units)
        
        # 2. 安全漏洞分析
        vulnerability_results = await self.run_security_analysis(self.code_units)
        
        # 3. 修复建议生成
        remediation_results = await self.generate_remediations(vulnerability_results)
        
        # 4. 漏洞评估
        assessment_results = await self._run_vulnerability_assessment(
            vulnerability_results, structure_results, remediation_results
        )
        
        # 关闭所有智能体
        for agent in self.agents.values():
            await agent.stop()
        
        # 添加评估信息到漏洞结果
        for vuln in vulnerability_results:
            vuln.metadata = vuln.metadata or {}
            vuln.metadata["assessment"] = assessment_results
        
        return vulnerability_results
    
    async def _run_code_structure_analysis(self) -> Dict[str, Any]:
        """运行代码结构分析"""
        analyzer_agent = next((a for a in self.agents.values() if a.agent_type == "analyzer"), None)
        
        if not analyzer_agent:
            logger.warning("未找到代码分析智能体，跳过结构分析")
            return {}
        
        try:
            result = await analyzer_agent.execute_task("analyze_code_structure", {"code_units": self.code_units})
            logger.info("代码结构分析完成")
            return result
        except Exception as e:
            logger.error(f"代码结构分析出错: {e}")
            return {}
    
    async def _run_security_analysis(self, structure_results: Dict[str, Any]) -> List[VulnerabilityResult]:
        """运行安全漏洞分析"""
        security_agent = next((a for a in self.agents.values() if a.agent_type == "analyst"), None)
        
        if not security_agent:
            logger.error("未找到安全分析智能体")
            return []
        
        results = []
        tasks = []
        semaphore = asyncio.Semaphore(self.workers)
        
        async def analyze_unit(unit):
            async with semaphore:
                try:
                    task_data = {
                        "code_unit": unit,
                        "structure_context": structure_results.get(unit.id, {})
                    }
                    vulnerabilities = await security_agent.execute_task("analyze_code_security", task_data)
                    return vulnerabilities
                except Exception as e:
                    logger.error(f"分析代码单元时出错: {unit.name}, {e}")
                    return []
        
        # 为每个代码单元创建分析任务
        for unit in self.code_units:
            task = asyncio.create_task(analyze_unit(unit))
            tasks.append(task)
        
        # 等待所有任务完成
        unit_results = await asyncio.gather(*tasks)
        
        # 收集所有结果
        for vulns in unit_results:
            if vulns:
                results.extend(vulns)
        
        logger.info(f"安全分析完成，发现 {len(results)} 个漏洞")
        return results
    
    async def _run_remediation_analysis(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """运行修复建议生成"""
        remediation_agent = next((a for a in self.agents.values() if a.agent_type == "generator"), None)
        
        if not remediation_agent:
            logger.warning("未找到修复建议智能体，跳过修复建议生成")
            return {}
        
        try:
            result = await remediation_agent.execute_task("generate_remediation", {"vulnerabilities": vulnerabilities})
            logger.info("修复建议生成完成")
            return result
        except Exception as e:
            logger.error(f"生成修复建议时出错: {e}")
            return {}
    
    async def _run_vulnerability_assessment(self, 
                                         vulnerabilities: List[VulnerabilityResult],
                                         structure_results: Dict[str, Any],
                                         remediation_results: Dict[str, Any]) -> Dict[str, Any]:
        """运行漏洞评估"""
        security_agent = next((a for a in self.agents.values() if a.agent_type == "analyst"), None)
        
        if not security_agent:
            logger.warning("未找到安全分析智能体，跳过漏洞评估")
            return {}
        
        try:
            task_data = {
                "vulnerabilities": vulnerabilities,
                "code_structure": structure_results,
                "remediation": remediation_results
            }
            result = await security_agent.execute_task("vulnerability_assessment", task_data)
            logger.info("漏洞评估完成")
            return result
        except Exception as e:
            logger.error(f"进行漏洞评估时出错: {e}")
            return {}
    
    async def generate_summary(self, vulnerabilities: List[VulnerabilityResult], assessment: Dict[str, Any]) -> str:
        """生成安全分析结果摘要
        
        Args:
            vulnerabilities: 检测到的漏洞列表
            assessment: 漏洞评估结果
            
        Returns:
            生成的摘要文本
        """
        # 使用协调器智能体生成摘要
        coordinator_agent = next((a for a in self.agents.values() if a.agent_type == "coordinator"), None)
        
        if not coordinator_agent:
            logger.warning("未找到编排智能体，无法生成摘要")
            return "无法生成摘要，未找到编排智能体。"
        
        try:
            # 获取严重程度统计
            severity_counts = {}
            for severity in SeverityLevel:
                severity_counts[severity.name.lower()] = 0
            
            for vuln in vulnerabilities:
                severity = vuln.severity.name.lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # 获取漏洞类型统计
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.vulnerability_type
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            # 按漏洞数量排序
            sorted_vuln_types = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)
            
            # 调用LLM API生成摘要
            system_prompt = """
你是一个安全报告总结专家。请根据提供的扫描结果，生成一个简明扼要的执行摘要。
摘要应该清晰地传达以下内容：
1. 安全扫描的总体结果概述
2. 按严重程度分类的主要发现
3. 最关键的漏洞类型及其潜在影响
4. 总体风险评估

请使用专业、清晰的语言，避免技术术语或行话。摘要应该是非技术人员也能理解的。
限制在400字以内。
"""

            user_prompt = f"""
扫描结果统计：
漏洞总数: {len(vulnerabilities)}

严重程度分布:
- 严重: {severity_counts.get('critical', 0)}
- 高危: {severity_counts.get('high', 0)}
- 中危: {severity_counts.get('medium', 0)}
- 低危: {severity_counts.get('low', 0)}
- 信息: {severity_counts.get('info', 0)}

最常见漏洞类型:
{
    '\\n'.join([f"- {vuln_type}: {count}件" for vuln_type, count in sorted_vuln_types[:5]])
}

风险评分: {assessment.get('risk_score', 0)}/100

根据以上信息，生成安全分析执行摘要。
"""
            
            response = await coordinator_agent.llm_client.chat.completions.create(
                model=coordinator_agent.model_spec,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1
            )
            
            summary = response.choices[0].message.content
            logger.info("生成了安全分析结果摘要")
            return summary
            
        except Exception as e:
            logger.error(f"生成摘要时出错: {e}")
            return f"生成摘要时出错: {str(e)}"
