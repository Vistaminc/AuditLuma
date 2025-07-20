"""
安全分析智能体 - 专门负责代码安全漏洞分析
"""

import os
import json
from typing import Dict, List, Any, Optional, Tuple, Union
import asyncio

from loguru import logger

from auditluma.config import Config
from auditluma.agents.base import BaseAgent
from auditluma.mcp.protocol import MessageType, MessagePriority
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult, SeverityLevel, FileType
from auditluma.rag.self_rag import self_rag


class SecurityAnalystAgent(BaseAgent):
    """安全分析智能体 - 负责识别代码中的安全漏洞"""
    
    def __init__(self, agent_id: Optional[str] = None, model_spec: Optional[str] = None):
        """初始化安全分析智能体"""
        super().__init__(agent_id, agent_type="security_analyst", model_spec=model_spec)
        self.description = "识别代码中的安全漏洞和风险"
        
        # 初始化LLM客户端，使用特定任务的默认模型
        from auditluma.utils import init_llm_client
        # 使用指定模型或任务默认模型，格式为"model@provider"
        self.model_spec = model_spec or Config.default_models.security_audit
        # 解析模型名称，只保存实际的模型名称部分
        self.model_name, _ = Config.parse_model_spec(self.model_spec)
        # 初始化LLM客户端
        self.llm_client = init_llm_client(self.model_spec)
        logger.info(f"安全分析智能体使用模型: {self.model_name}")
        
        # 加载安全知识库
        self.security_knowledge = self._load_security_knowledge()
        
        # 特定消息处理器
        self.register_handler(MessageType.QUERY, self._handle_security_query)
    
    def _load_security_knowledge(self) -> Dict[str, Any]:
        """加载安全知识库"""
        # 这里可以加载CWE、OWASP等安全风险知识库
        # 简单实现，实际应用中可以从文件或数据库加载
        return {
            "cwe": {
                "CWE-79": {
                    "name": "跨站脚本",
                    "description": "跨站点脚本(XSS)漏洞发生在应用程序接受来自用户的数据，并且在没有适当验证或编码的情况下将其发送到Web浏览器时。",
                    "mitigation": "使用上下文相关的输出编码，例如HTML实体编码、JavaScript编码等。"
                },
                "CWE-89": {
                    "name": "SQL注入",
                    "description": "当软件构造的SQL命令包含来自外部源的未验证输入时，可能导致SQL注入漏洞。",
                    "mitigation": "使用参数化查询或预处理语句，避免动态构建SQL语句。"
                },
                "CWE-20": {
                    "name": "输入验证不当",
                    "description": "当软件未正确验证输入时，攻击者可以构造特殊输入绕过预期的安全限制。",
                    "mitigation": "实施输入验证，确保只接受符合规范的输入数据。"
                },
                "CWE-200": {
                    "name": "信息泄露",
                    "description": "应用程序不小心向用户泄露敏感信息，如系统数据、环境数据或私人用户数据。",
                    "mitigation": "审查错误处理机制，确保不会泄露敏感信息。"
                },
                "CWE-287": {
                    "name": "身份验证不当",
                    "description": "当软件未正确验证用户身份就授予访问权限时，可能导致未授权访问。",
                    "mitigation": "使用强大的身份验证机制，如多因素认证。"
                }
            },
            "owasp": {
                "A01:2021": {
                    "name": "失效的访问控制",
                    "description": "控制谁可以访问什么或做什么的限制未得到适当执行。",
                    "mitigation": "实施适当的访问控制机制，拒绝默认访问权限。"
                },
                "A02:2021": {
                    "name": "加密机制失效",
                    "description": "加密机制失效或缺乏，导致敏感数据暴露。",
                    "mitigation": "确保所有敏感数据都已加密，使用强大的加密算法。"
                },
                "A03:2021": {
                    "name": "注入",
                    "description": "用户提供的数据被解释为命令或查询的一部分。",
                    "mitigation": "使用参数化查询，验证和清理用户输入。"
                },
                "A04:2021": {
                    "name": "不安全设计",
                    "description": "缺乏威胁建模和安全设计原则。",
                    "mitigation": "采用安全设计原则和模式，进行威胁建模。"
                },
                "A05:2021": {
                    "name": "安全配置错误",
                    "description": "系统配置不当，如默认账户、未使用的页面、未受保护的文件等。",
                    "mitigation": "实施安全基线配置，删除未使用的功能和框架。"
                }
            }
        }
    
    async def execute_task(self, task_type: str, task_data: Any) -> Any:
        """执行任务 - 实现基类的抽象方法"""
        if task_type == "analyze_code_security":
            return await self._analyze_code_security(task_data)
        elif task_type == "analyze_code_security_with_context":
            return await self._analyze_code_security_with_context(task_data)
        elif task_type == "vulnerability_assessment":
            return await self._vulnerability_assessment(task_data)
        elif task_type == "analyze_cross_file_security":
            return await self._analyze_cross_file_security(task_data)
        else:
            raise ValueError(f"不支持的任务类型: {task_type}")
    
    async def _handle_security_query(self, message: Any) -> None:
        """处理安全相关查询"""
        query = message.content.get("query")
        code = message.content.get("code")
        
        if not query:
            await self.send_error(
                receiver=message.sender,
                content={"error": "缺少查询参数"},
                reply_to=message.message_id
            )
            return
        
        # 检索相关安全知识
        context = await self._retrieve_security_knowledge(query)
        
        # 如果提供了代码，分析代码安全问题
        if code:
            analysis = await self._quick_security_analysis(code, context)
            await self.send_response(
                receiver=message.sender,
                content={"analysis": analysis, "context": context},
                reply_to=message.message_id
            )
        else:
            # 仅返回安全知识
            await self.send_response(
                receiver=message.sender,
                content={"context": context},
                reply_to=message.message_id
            )
    
    async def _analyze_code_security(self, data: Dict[str, Any]) -> List[VulnerabilityResult]:
        """分析代码安全问题"""
        code_unit = data.get("code_unit")
        if not code_unit:
            raise ValueError("缺少代码单元数据")
        
        # 获取相关上下文
        context_docs = await self.retrieve_context(code_unit.content)
        context_text = "\n\n".join([doc.content for doc in context_docs])
        
        # 准备提示
        prompt = self._prepare_security_prompt(code_unit, context_text)
        
        # 调用LLM进行安全分析，使用特定任务的默认模型
        logger.debug(f"发送安全分析提示到LLM，代码单元: {code_unit.id}")
        
        try:
            response = await self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user", "content": prompt["user"]}
                ],
                temperature=0.1
            )
            
            analysis_text = response.choices[0].message.content
            logger.debug(f"收到LLM安全分析响应")
            
            # 解析结果
            vulnerabilities = self._parse_security_analysis(analysis_text, code_unit)
            
            return vulnerabilities
        
        except Exception as e:
            logger.error(f"安全分析LLM调用出错: {e}")
            raise
    
    async def _analyze_code_security_with_context(self, data: Dict[str, Any]) -> List[VulnerabilityResult]:
        """带全局上下文的代码安全分析"""
        code_unit = data.get("code_unit")
        global_context = data.get("global_context", {})
        enhanced_context = data.get("enhanced_context", "")
        dependency_info = data.get("dependency_info", {})
        
        if not code_unit:
            raise ValueError("缺少代码单元数据")
        
        # 获取Self-RAG上下文
        context_docs = await self.retrieve_context(code_unit.content)
        context_text = "\n\n".join([doc.content for doc in context_docs])
        
        # 合并所有上下文信息
        full_context = self._merge_contexts(context_text, enhanced_context, dependency_info, global_context)
        
        # 准备增强的安全分析提示
        prompt = self._prepare_enhanced_security_prompt(code_unit, full_context)
        
        try:
            response = await self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user", "content": prompt["user"]}
                ],
                temperature=0.1
            )
            
            analysis_text = response.choices[0].message.content
            vulnerabilities = self._parse_security_analysis(analysis_text, code_unit)
            
            # 为每个漏洞添加上下文信息
            for vuln in vulnerabilities:
                vuln.metadata = vuln.metadata or {}
                vuln.metadata["global_context_analysis"] = True
                vuln.metadata["dependency_info"] = dependency_info
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"增强安全分析出错: {e}")
            return []
    
    async def _analyze_cross_file_security(self, data: Dict[str, Any]) -> List[VulnerabilityResult]:
        """跨文件安全分析"""
        source_files = data.get("source_files", [])
        global_context = data.get("global_context", {})
        
        if not source_files:
            logger.warning("没有提供源文件进行跨文件分析")
            return []
        
        # 导入分析器
        try:
            from auditluma.analyzers.global_context_analyzer import GlobalContextAnalyzer
            from auditluma.analyzers.cross_file_analyzer import CrossFileAnalyzer
            from auditluma.analyzers.dataflow_analyzer import DataFlowAnalyzer
        except ImportError as e:
            logger.error(f"无法导入分析器模块: {e}")
            return []
        
        # 构建全局上下文（如果未提供）
        if not global_context:
            logger.info("构建全局上下文...")
            context_analyzer = GlobalContextAnalyzer()
            global_context = await context_analyzer.build_global_context(source_files)
        
        # 跨文件漏洞检测
        cross_file_analyzer = CrossFileAnalyzer(global_context)
        cross_file_vulns = cross_file_analyzer.detect_cross_file_vulnerabilities()
        
        # 数据流分析
        dataflow_analyzer = DataFlowAnalyzer(global_context)
        dangerous_flows = dataflow_analyzer.get_critical_data_flows(min_risk_score=0.6)
        
        # 转换为标准漏洞结果
        vulnerability_results = cross_file_analyzer.convert_to_vulnerability_results(cross_file_vulns)
        
        # 添加数据流漏洞
        flow_vulns = self._convert_dataflow_to_vulnerabilities(dangerous_flows)
        vulnerability_results.extend(flow_vulns)
        
        logger.info(f"跨文件安全分析完成，发现 {len(vulnerability_results)} 个跨文件漏洞")
        
        return vulnerability_results
    
    async def _vulnerability_assessment(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """对整体代码库进行漏洞评估"""
        vulnerabilities = data.get("vulnerabilities", [])
        code_structure = data.get("code_structure", {})
        
        if not vulnerabilities:
            return {
                "summary": "未发现漏洞",
                "risk_score": 0,
                "recommendations": ["代码安全性良好，保持现有的安全实践。"]
            }
        
        # 分类漏洞
        by_severity = {}
        for severity in SeverityLevel:
            by_severity[severity] = []
        
        for vuln in vulnerabilities:
            by_severity[vuln.severity].append(vuln)
        
        # 计算风险评分 (0-100)
        weights = {
            SeverityLevel.CRITICAL: 10,
            SeverityLevel.HIGH: 5,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0.1
        }
        
        total_vulns = len(vulnerabilities)
        weighted_score = 0
        
        for severity, vulns in by_severity.items():
            weighted_score += len(vulns) * weights[severity]
        
        # 归一化分数(0-100)
        risk_score = min(100, weighted_score * 2)
        
        # 生成对应的建议
        recommendations = await self._generate_recommendations(vulnerabilities, code_structure)
        
        return {
            "summary": f"发现{total_vulns}个潜在漏洞",
            "risk_score": risk_score,
            "severity_breakdown": {severity: len(vulns) for severity, vulns in by_severity.items()},
            "recommendations": recommendations
        }
    
    async def _retrieve_security_knowledge(self, query: str) -> Dict[str, Any]:
        """检索与查询相关的安全知识"""
        # 从安全知识库检索
        relevant_cwe = {}
        relevant_owasp = {}
        
        # 简单文本匹配 (实际实现可以用更高级的检索算法)
        query = query.lower()
        for cwe_id, info in self.security_knowledge["cwe"].items():
            if query in info["name"].lower() or query in info["description"].lower():
                relevant_cwe[cwe_id] = info
        
        for owasp_id, info in self.security_knowledge["owasp"].items():
            if query in info["name"].lower() or query in info["description"].lower():
                relevant_owasp[owasp_id] = info
        
        # 如果启用了Self-RAG，也从那里获取
        if Config.self_rag.enabled:
            docs = await self.retrieve_context(f"security vulnerability {query}")
            context_text = "\n".join([doc.content for doc in docs])
        else:
            context_text = ""
        
        return {
            "cwe": relevant_cwe,
            "owasp": relevant_owasp,
            "additional_context": context_text
        }
    
    async def _quick_security_analysis(self, code: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """对单个代码片段进行快速安全分析"""
        # 准备提示
        system_prompt = """
你是一位安全分析专家，请对提供的代码进行安全漏洞分析。
请仔细检查可能存在的安全问题并提供详细分析：
1. 识别潜在的安全漏洞
2. 确定每个漏洞的严重程度(严重/高/中/低/信息)
3. 提供改进建议

请以安全专家的眼光分析代码，提供具体、实用的建议。
"""

        user_prompt = f"""
请分析以下代码片段的安全问题：

```
{code}
```
"""
        
        try:
            # 使用特定任务的默认模型
            response = await self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1
            )
            
            analysis = response.choices[0].message.content
            
            # 提取安全问题
            issues = self._extract_security_issues(analysis)
            
            return {
                "issues": issues,
                "raw_analysis": analysis
            }
            
        except Exception as e:
            logger.error(f"快速安全分析出错: {e}")
            return {
                "issues": [],
                "raw_analysis": f"分析失败: {str(e)}",
                "error": str(e)
            }
    
    def _prepare_security_prompt(self, code_unit: CodeUnit, context_text: str) -> Dict[str, str]:
        """准备安全分析提示"""
        system_prompt = """
你是一个专业的代码安全审计专家。请分析提供的代码，识别潜在的安全漏洞和风险。请使用以下格式输出结果：

<安全审计结果>
[漏洞1]
- 类型: [漏洞类型, 例如SQL注入、XSS、CSRF等]
- CWE: [对应的CWE编号，如果适用]
- OWASP: [对应的OWASP Top 10分类，如果适用]
- 严重性: [critical/high/medium/low/info]
- 位置: [代码行号]
- 描述: [详细描述漏洞及其风险]
- 代码片段:
```
[相关代码片段]
```
- 修复建议: [如何修复这个漏洞]

[漏洞2]
...
</安全审计结果>

如果没有发现漏洞，请回复:
<安全审计结果>
未发现安全漏洞。
</安全审计结果>

评估代码时，请考虑:
1. 代码的上下文和使用场景
2. 输入验证缺陷
3. 认证和授权问题
4. 数据保护和隐私问题
5. 会话管理缺陷
6. 安全配置错误
7. 加密问题
8. 业务逻辑缺陷
9. 错误处理问题
10. 第三方组件的已知漏洞

请基于代码事实进行分析，避免过度解读或假设。如果无法确定，请说明需要更多上下文信息。
"""
        
        user_prompt = f"""
以下是需要审计的代码单元信息：

文件路径: {code_unit.source_file.path}
单元名称: {code_unit.name}
单元类型: {code_unit.type}
行范围: {code_unit.start_line}-{code_unit.end_line}
代码语言: {code_unit.source_file.file_type}

代码内容:
```
{code_unit.content}
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
    
    def _prepare_enhanced_security_prompt(self, code_unit: CodeUnit, context: str) -> Dict[str, str]:
        """准备增强的安全分析提示 - 包含全局上下文"""
        system_prompt = """
你是一个高级代码安全审计专家。你现在不仅看到目标代码，还看到了全局上下文信息，包括：
- 跨文件的调用关系
- 模块依赖关系  
- 数据流路径
- 相关函数的上下文

请特别关注：
1. **跨文件数据流安全**：分析数据如何在不同文件间流动
2. **调用链安全**：检查完整的函数调用链中的安全问题
3. **模块间接口安全**：分析模块边界的安全问题
4. **全局状态安全**：考虑全局变量和共享状态的影响

在分析时，请明确指出：
- 是否是跨文件/跨模块的安全问题
- 涉及的完整数据流路径
- 需要在哪些位置添加安全检查

输出格式与之前相同，但请在描述中包含跨文件分析的结果。

<安全审计结果>
[漏洞1]
- 类型: [漏洞类型，标明是否为跨文件漏洞]
- CWE: [对应的CWE编号]
- OWASP: [对应的OWASP Top 10分类]
- 严重性: [critical/high/medium/low/info]
- 位置: [代码行号]
- 跨文件路径: [如果是跨文件漏洞，显示数据流路径]
- 描述: [详细描述漏洞及其风险，包含全局上下文分析]
- 代码片段:
```
[相关代码片段]
```
- 修复建议: [如何修复这个漏洞，包含跨文件修复建议]

[漏洞2]
...
</安全审计结果>

如果没有发现漏洞，请回复:
<安全审计结果>
未发现安全漏洞。
</安全审计结果>
"""
        
        user_prompt = f"""
以下是需要审计的代码单元信息：

文件路径: {code_unit.source_file.path}
单元名称: {code_unit.name}
单元类型: {code_unit.type}
行范围: {code_unit.start_line}-{code_unit.end_line}
代码语言: {code_unit.source_file.file_type}

代码内容:
```
{code_unit.content}
```

全局上下文信息:
{context}

请基于完整的全局上下文进行安全分析，特别关注跨文件的安全问题。
"""
        
        return {
            "system": system_prompt,
            "user": user_prompt
        }
    
    def _merge_contexts(self, context_text: str, enhanced_context: str, 
                       dependency_info: Dict, global_context: Dict) -> str:
        """合并多种上下文信息"""
        context_parts = []
        
        # 1. Self-RAG上下文
        if context_text:
            context_parts.append(f"### Self-RAG检索上下文:\n{context_text[:1500]}")
        
        # 2. 增强上下文
        if enhanced_context:
            context_parts.append(f"### 文件级上下文:\n{enhanced_context}")
        
        # 3. 依赖信息
        if dependency_info:
            deps = []
            for dep in dependency_info.get('dependencies', []):
                deps.append(f"- 调用: {dep.get('name', 'unknown')} ({dep.get('type', 'unknown')})")
            for dep in dependency_info.get('dependents', []):
                deps.append(f"- 被调用: {dep.get('name', 'unknown')} ({dep.get('type', 'unknown')})")
            
            if deps:
                context_parts.append(f"### 依赖关系:\n" + "\n".join(deps))
        
        # 4. 全局上下文统计
        if global_context:
            stats = global_context.get('statistics', {})
            if stats:
                context_parts.append(f"""### 全局项目信息:
- 总代码实体: {stats.get('total_entities', 0)}
- 总文件数: {stats.get('total_files', 0)} 
- 调用关系: {stats.get('call_relationships', 0)}
- 跨文件流: {stats.get('cross_file_flows', 0)}""")
        
        return "\n\n".join(context_parts)
    
    def _convert_dataflow_to_vulnerabilities(self, dangerous_flows) -> List[VulnerabilityResult]:
        """将危险数据流转换为漏洞结果"""
        vulnerability_results = []
        
        for flow in dangerous_flows:
            # 创建虚拟的源文件和代码单元
            from auditluma.models.code import SourceFile, CodeUnit
            import uuid
            from pathlib import Path
            
            # 获取源文件路径
            source_entity = flow.source.entity_name
            source_file_path = source_entity.split("::")[0] if "::" in source_entity else "unknown"
            
            source_file = SourceFile(
                path=Path(source_file_path),
                relative_path=source_file_path,
                name=Path(source_file_path).name,
                extension=Path(source_file_path).suffix,
                file_type=FileType.from_extension(Path(source_file_path).suffix),
                size=0,
                content="# Data flow vulnerability",
                modified_time=0
            )
            
            dummy_unit = CodeUnit(
                id=f"dataflow_{uuid.uuid4().hex[:8]}",
                name="data_flow_vulnerability",
                type="data_flow",
                source_file=source_file,
                start_line=1,
                end_line=1,
                content="# Data flow vulnerability detected",
                parent_id=None
            )
            
            # 根据风险评分确定严重程度
            if flow.risk_score >= 0.8:
                severity = SeverityLevel.CRITICAL
            elif flow.risk_score >= 0.6:
                severity = SeverityLevel.HIGH
            elif flow.risk_score >= 0.4:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW
            
            # 构建描述
            description = f"危险数据流：{flow.source.source_type} -> {flow.sink.sink_type}"
            if len(flow.path) > 2:
                description += f"，通过 {len(flow.path)-2} 个中间节点"
            description += f"。污点级别：{flow.taint_level.value}，风险评分：{flow.risk_score:.2f}"
            
            vuln_result = VulnerabilityResult(
                id=str(uuid.uuid4()),
                title=f"Data Flow Vulnerability: {flow.source.source_type} -> {flow.sink.sink_type}",
                description=description,
                code_unit=dummy_unit,
                file_path=source_file_path,
                start_line=1,
                end_line=1,
                vulnerability_type="Data Flow Vulnerability",
                severity=severity,
                cwe_id=self._get_dataflow_cwe_id(flow.sink.sink_type),
                owasp_category="A03:2021",  # Injection
                confidence=flow.risk_score,
                snippet="# Data flow vulnerability",
                recommendation=self._get_dataflow_recommendation(flow),
                metadata={
                    "data_flow": True,
                    "source_type": flow.source.source_type,
                    "sink_type": flow.sink.sink_type,
                    "flow_path": flow.path,
                    "taint_level": flow.taint_level.value,
                    "sanitization_points": flow.sanitization_points,
                    "risk_score": flow.risk_score
                }
            )
            
            vulnerability_results.append(vuln_result)
        
        return vulnerability_results
    
    def _get_dataflow_cwe_id(self, sink_type: str) -> Optional[str]:
        """根据汇点类型获取CWE ID"""
        cwe_mapping = {
            "sql_query": "CWE-89",
            "command_exec": "CWE-78", 
            "file_write": "CWE-22",
            "template_render": "CWE-79",
            "response_output": "CWE-79"
        }
        return cwe_mapping.get(sink_type, "CWE-20")
    
    def _get_dataflow_recommendation(self, flow) -> str:
        """根据数据流生成修复建议"""
        recommendations = {
            "sql_query": "使用参数化查询或预处理语句，避免直接拼接用户输入到SQL语句中",
            "command_exec": "验证和转义用户输入，使用白名单验证，避免直接执行用户提供的命令",
            "file_write": "验证文件路径，限制可访问的目录范围，使用安全的文件操作API",
            "template_render": "对输出进行HTML编码，使用安全的模板引擎",
            "response_output": "对用户输入进行输出编码，防止XSS攻击"
        }
        
        base_rec = recommendations.get(flow.sink.sink_type, "对用户输入进行验证和转义")
        
        if not flow.sanitization_points:
            return f"{base_rec}。当前数据流路径中没有发现消毒处理。"
        else:
            return f"{base_rec}。已在 {', '.join(flow.sanitization_points)} 处发现部分消毒处理，请检查是否充分。"
    
    def _parse_security_analysis(self, analysis_text: str, code_unit: CodeUnit) -> List[VulnerabilityResult]:
        """解析LLM返回的安全分析结果"""
        vulnerabilities = []
        
        # 首先尝试标准格式
        import re
        result_pattern = r"<安全审计结果>(.*?)</安全审计结果>"
        matches = re.search(result_pattern, analysis_text, re.DOTALL)
        
        # 如果没有找到标准格式，尝试其他可能的格式
        if not matches:
            # 尝试其他可能的结果部分格式
            alternative_patterns = [
                r"安全审计结果[\s\n:]*([\s\S]*?)(?=\n\n|\Z)",  # 中文标题
                r"Security Analysis Results?[\s\n:]*([\s\S]*?)(?=\n\n|\Z)",  # 英文标题
                r"\n*([\s\S]*?漏洞[\s\S]*?)(?=\n\n|\Z)",  # 包含“漏洞”关键词的部分
                r"\n*([\s\S]*?vulnerability[\s\S]*?)(?=\n\n|\Z)",  # 包含“vulnerability”关键词的部分
                r"\n*([\s\S]*?finding[\s\S]*?)(?=\n\n|\Z)"  # 包含“finding”关键词的部分
            ]
            
            for pattern in alternative_patterns:
                alt_match = re.search(pattern, analysis_text, re.IGNORECASE | re.DOTALL)
                if alt_match:
                    logger.info(f"使用替代格式解析安全审计结果: {pattern}")
                    result_text = alt_match.group(1).strip()
                    break
            else:
                # 如果所有替代格式都未找到匹配，使用整个文本
                logger.warning(f"无法使用标准模式提取安全审计结果，尝试处理全部文本")
                result_text = analysis_text.strip()
        else:
            # 使用标准格式提取的内容
            result_text = matches.group(1).strip()
        
        # 检查是否未发现漏洞
        if "未发现安全漏洞" in result_text:
            return vulnerabilities
        
        # 尝试各种可能的漏洞项格式
        # 首先尝试标准的标签格式
        vulnerability_pattern = r"\[漏洞\d+\](.*?)(?=\[漏洞\d+\]|\Z)"
        vulnerability_matches = list(re.finditer(vulnerability_pattern, result_text, re.DOTALL))
        
        # 如果没有找到标准格式的漏洞项，尝试其他可能的格式
        if not vulnerability_matches:
            # 尝试其他常见的漏洞项格式
            alternative_patterns = [
                r"\d+\.\s+[^\n]+(\n\s+[^\n]+)*",                # 序号列表格式: 1. xxx\n   xxx
                r"- [^\n]+(\n\s+[^\n]+)*",                      # 项目符号列表: - xxx\n   xxx
                r"\*\*漏洞\s*\d*\*\*[^*]+(\n[^*]+)*",      # 加粗标题: **漏洞**xxx
                r"Vulnerability\s*\d*[:]?[^\n]+(\n\s+[^\n]+)*", # 英文漏洞: Vulnerability: xxx
                r"Finding\s*\d*[:]?[^\n]+(\n\s+[^\n]+)*"       # 英文发现: Finding: xxx
            ]
            
            for pattern in alternative_patterns:
                alt_matches = list(re.finditer(pattern, result_text, re.DOTALL))
                if alt_matches:
                    logger.info(f"使用替代格式匹配漏洞项: {pattern}")
                    vulnerability_matches = alt_matches
                    break
            
            # 如果还是没找到，尝试按段落分割
            if not vulnerability_matches:
                # 按段落分割文本，每个段落作为一个漏洞项
                paragraphs = re.split(r"\n\s*\n", result_text)
                # 过滤出可能是漏洞的段落（至少需要包含“漏洞”、“危险”或英文对应词汇）
                vuln_keywords = ["漏洞", "危险", "vulnerability", "risk", "cwe", "owasp", "severity"]
                filtered_paragraphs = [p for p in paragraphs if any(keyword.lower() in p.lower() for keyword in vuln_keywords)]
                
                # 创建模拟的匹配对象
                vulnerability_matches = [type('obj', (object,), {'group': lambda self, x=0: p}) for p in filtered_paragraphs if p.strip()]
                if vulnerability_matches:
                    logger.info(f"使用段落分割提取漏洞项: 找到 {len(vulnerability_matches)} 项")
        
        # 如果所有方法都失败但有关键词显示存在漏洞，创建一个通用漏洞
        vuln_indicators = ["漏洞", "vulnerability", "cwe-", "owasp", "injection", "xss", "csrf"]
        if not vulnerability_matches and any(indicator.lower() in result_text.lower() for indicator in vuln_indicators):
            # 创建一个单一的模拟匹配对象
            dummy_match = type('obj', (object,), {'group': lambda self, x=0: result_text})
            vulnerability_matches = [dummy_match]
            logger.warning(f"未能识别标准漏洞格式，但发现漏洞关键词，尝试提取单一漏洞")
        
        # 如果没有找到任何漏洞，返回空列表
        if not vulnerability_matches:
            logger.info(f"未找到任何漏洞项: {code_unit.name}")
            return vulnerabilities
        
        import uuid
        
        for match in vulnerability_matches:
            vuln_text = match.group(1).strip()
            
            # 解析漏洞属性
            vuln_type = self._extract_property(vuln_text, "类型")
            cwe_id = self._extract_property(vuln_text, "CWE")
            owasp_category = self._extract_property(vuln_text, "OWASP")
            severity_str = self._extract_property(vuln_text, "严重性")
            location_str = self._extract_property(vuln_text, "位置")
            description = self._extract_property(vuln_text, "描述")
            code_snippet = self._extract_code_snippet(vuln_text)
            recommendation = self._extract_property(vuln_text, "修复建议")
            
            # 解析行号
            start_line = code_unit.start_line
            end_line = code_unit.end_line
            if location_str:
                try:
                    line_numbers = [int(n.strip()) for n in location_str.split("-")]
                    if len(line_numbers) > 0:
                        start_line = line_numbers[0]
                        if len(line_numbers) > 1:
                            end_line = line_numbers[1]
                        else:
                            end_line = start_line
                except ValueError:
                    pass
            
            # 确定严重性级别
            severity = SeverityLevel.MEDIUM  # 默认值
            if severity_str:
                severity_str = severity_str.lower()
                if "critical" in severity_str:
                    severity = SeverityLevel.CRITICAL
                elif "high" in severity_str:
                    severity = SeverityLevel.HIGH
                elif "medium" in severity_str:
                    severity = SeverityLevel.MEDIUM
                elif "low" in severity_str:
                    severity = SeverityLevel.LOW
                elif "info" in severity_str:
                    severity = SeverityLevel.INFO
            
            # 创建漏洞对象
            vulnerability = VulnerabilityResult(
                id=str(uuid.uuid4()),
                title=vuln_type or "未知漏洞",
                description=description or "无描述",
                code_unit=code_unit,
                file_path=str(code_unit.source_file.path),
                start_line=start_line,
                end_line=end_line,
                vulnerability_type=vuln_type or "未知",
                severity=severity,
                cwe_id=cwe_id,
                owasp_category=owasp_category,
                confidence=0.8,  # 默认置信度
                snippet=code_snippet or "",
                recommendation=recommendation or "无修复建议"
            )
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _extract_property(self, text: str, property_name: str) -> Optional[str]:
        """从文本中提取属性值，支持多种格式"""
        import re
        
        # 尝试多种可能的属性格式
        patterns = [
            # 标准列表格式
            rf"- {property_name}: ?(.*?)(?=\n- |\n\n|\Z)",
            # 标准字典格式
            rf'"{property_name}":\s*"(.*?)"(?=,|\n|\Z)',
            # 带引号的键值对
            rf"{property_name}:\s*['\"]([^'\"]*)['\"](?=,|\n|\Z)",
            # 英文冒号格式
            rf"{property_name}:\s*(.*?)(?=\n\w+:|\n\n|\Z)",
            # 中文冒号格式
            rf"{property_name}：\s*(.*?)(?=\n\w+[：:]|\n\n|\Z)",
            # 简单字段名后跟内容
            rf"{property_name}\s*[：:，,]?\s*(.*?)(?=\n\w+[：:，,]?\s+|\n\n|\Z)",
            # 字段名后面的内容
            rf"(?:\n|^)\s*{property_name}\b[^\n]*?(\S[^\n]*)(?=\n|\Z)"
        ]
        
        # 尝试所有模式匹配
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                result = match.group(1).strip()
                # 如果结果过长，可能是错误匹配，跳过
                if len(result) > 100:
                    continue
                return result
        
        # 尝试特殊属性的匹配
        if property_name.lower() in ["cwe", "owasp"]:
            # 尝试找到CWE或OWASP编号
            specific_patterns = [
                rf"(?:CWE|cwe)[-:\s]*(\d+)",  # CWE-123 or CWE: 123
                rf"(?:OWASP|owasp)[-:\s]*([A-Z0-9]{{2,3}}(?::\d+)?)",  # OWASP A1:2021 or OWASP-A1
            ]
            
            for pattern in specific_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match and property_name.lower() == "cwe" and "cwe" in pattern.lower():
                    return f"CWE-{match.group(1)}"
                elif match and property_name.lower() == "owasp" and "owasp" in pattern.lower():
                    return f"OWASP-{match.group(1)}"
                    
        # 如果是位置属性，尝试提取行号
        if property_name.lower() in ["位置", "location", "line"]:
            # 尝试找到行号信息
            line_patterns = [
                r"(?:line|lines|\u884c)\s*(\d+)(?:\s*-\s*(\d+))?",  # line 10 or lines 10-20
                r"L(\d+)(?:-L?(\d+))?",  # L10 or L10-L20 or L10-20
            ]
            
            for pattern in line_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    if match.group(2):  # 有范围
                        return f"{match.group(1)}-{match.group(2)}"
                    else:  # 单行
                        return match.group(1)
        
        # 如果是严重性属性，尝试提取严重级别
        if property_name.lower() in ["严重性", "severity"]:
            severity_keywords = [
                (r"\b(?:critical|\u4e25重|\u6781高)\b", "CRITICAL"),
                (r"\b(?:high|\u9ad8)\b", "HIGH"),
                (r"\b(?:medium|\u4e2d|\u4e2d等)\b", "MEDIUM"),
                (r"\b(?:low|\u4f4e)\b", "LOW"),
                (r"\b(?:info|information|\u4fe1息)\b", "INFO")
            ]
            
            for pattern, level in severity_keywords:
                if re.search(pattern, text, re.IGNORECASE):
                    return level
            
        return None
    
    def _extract_code_snippet(self, text: str) -> Optional[str]:
        """从文本中提取代码片段，支持多种格式"""
        import re
        
        # 尝试不同的代码片段格式
        code_patterns = [
            # Markdown 代码块格式
            r"```(?:\w+)?\n(.*?)```",
            # 代码标签格式
            r"<code>(.*?)</code>",
            # 代码引用格式（单行）
            r"`([^`\n]+)`",
            # 自定义标签格式
            r"<代码\s*\d*>(.*?)</代码>",
            # 缩进代码块
            r"(?:\n\s{4,}[^\n]+){2,}",
            # 可能的代码关键词开头
            r"(?:\n|^)(?:def|class|function|import|var|let|const|public|private|#include)\s+[^\n]+(?:\n\s+[^\n]+){1,}"
        ]
        
        for pattern in code_patterns:
            matches = re.finditer(pattern, text, re.DOTALL)
            for match in matches:
                snippet = match.group(1) if "(" in pattern else match.group(0)
                
                # 清理片段
                snippet = snippet.strip()
                
                # 去除缩进代码块的空格前缀
                if pattern.endswith("{2,}"):
                    lines = snippet.split('\n')
                    if lines:
                        # 找出最小缩进量
                        min_indent = min(len(line) - len(line.lstrip()) for line in lines if line.strip())
                        # 去除统一的缩进
                        snippet = '\n'.join(line[min_indent:] if line.strip() else line for line in lines)
                
                # 验证这是否真的是代码
                code_indicators = [
                    "=", "(", ")", "{", "}", "[", "]", ";", ":", "+", "-", "*", "/", "%",
                    "def ", "class ", "function ", "import ", "from ", "var ", "let ", "const ",
                    "public ", "private ", "protected ", "#include ", "return ", "if ", "for ", "while "
                ]
                
                if any(indicator in snippet for indicator in code_indicators) and len(snippet) > 10:
                    return snippet
        
        # 如果没有找到代码片段，尝试找到“代码”或“code”相关的段落
        code_section_patterns = [
            r"漏洞代码\s*[:：]?\s*([^\n]+(?:\n\s+[^\n]+){0,5})",
            r"vulnerable\s+code\s*:?\s*([^\n]+(?:\n\s+[^\n]+){0,5})",
            r"code\s+sample\s*:?\s*([^\n]+(?:\n\s+[^\n]+){0,5})"
        ]
        
        for pattern in code_section_patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def _extract_security_issues(self, analysis: str) -> List[Dict[str, Any]]:
        """从分析文本中提取安全问题"""
        issues = []
        
        # 简单实现 - 在实际应用中可以使用更复杂的提取逻辑
        import re
        
        # 尝试识别漏洞类型和描述
        vulnerability_patterns = [
            (r"SQL\s+注入", "SQL注入"),
            (r"XSS|跨站脚本", "跨站脚本(XSS)"),
            (r"CSRF|跨站请求伪造", "跨站请求伪造(CSRF)"),
            (r"命令\s*注入", "命令注入"),
            (r"路径遍历|目录遍历|path\s+traversal", "路径遍历"),
            (r"未验证的\s*重定向|open\s+redirect", "未验证的重定向"),
            (r"不安全的\s*反序列化", "不安全的反序列化"),
            (r"XML\s+注入|XXE", "XML注入/XXE"),
            (r"SSRF|服务器端请求伪造", "服务器端请求伪造(SSRF)"),
            (r"硬编码\s*(密码|凭证|secret|API\s+key)", "硬编码凭证"),
            (r"敏感\s*信息\s*泄露", "敏感信息泄露"),
            (r"缺少\s*输入\s*验证", "缺少输入验证"),
            (r"缺少\s*认证|认证\s*不当", "认证不当"),
            (r"缺少\s*授权|授权\s*不当", "授权不当"),
            (r"(不安全|弱)\s*加密", "加密不当")
        ]
        
        for pattern, issue_type in vulnerability_patterns:
            try:
                if re.search(pattern, analysis, re.IGNORECASE):
                    # 尝试提取相关描述
                    try:
                        # 包裹模式在捕获组中
                        context_pattern = rf"({pattern}.{{0,200}})"
                        context_match = re.search(context_pattern, analysis, re.IGNORECASE | re.DOTALL)
                        
                        # 确保匹配存在且有捕获组
                        if context_match and len(context_match.groups()) > 0:
                            description = context_match.group(1)
                        else:
                            # 如果没有捕获组，直接使用匹配的整个文本
                            original_match = re.search(pattern, analysis, re.IGNORECASE | re.DOTALL)
                            if original_match:
                                # 提取匹配文本及其前后一些上下文
                                match_start = max(0, original_match.start() - 50)
                                match_end = min(len(analysis), original_match.end() + 150)
                                description = analysis[match_start:match_end].strip()
                            else:
                                description = "未提供详细描述"
                    except Exception as e:
                        logger.warning(f"提取漏洞描述时出错: {e}")
                        description = f"检测到 {issue_type} 漏洞"
            except Exception as e:
                logger.warning(f"匹配漏洞模式时出错: {pattern}, {e}")
                continue
                
                issues.append({
                    "type": issue_type,
                    "description": description
                })
        
        return issues
    
    async def _generate_recommendations(self, vulnerabilities: List[VulnerabilityResult], 
                                     code_structure: Dict[str, Any]) -> List[str]:
        """生成安全建议"""
        # 根据漏洞类型生成建议
        recommendations = []
        
        # 按类型分组漏洞
        vuln_types = {}
        for vuln in vulnerabilities:
            if vuln.vulnerability_type not in vuln_types:
                vuln_types[vuln.vulnerability_type] = []
            vuln_types[vuln.vulnerability_type].append(vuln)
        
        # 为每种主要漏洞类型生成建议
        for vuln_type, vulns in vuln_types.items():
            if not vulns:
                continue
                
            # 找出严重级别最高的漏洞
            most_severe = max(vulns, key=lambda v: list(SeverityLevel).index(v.severity))
            
            # 根据漏洞类型和严重程度生成建议
            if "注入" in vuln_type.lower() or "injection" in vuln_type.lower():
                recommendations.append(f"实施参数化查询和输入验证，以防止{vuln_type}漏洞")
            elif "xss" in vuln_type.lower() or "跨站脚本" in vuln_type.lower():
                recommendations.append("实施上下文感知的输出编码，使用现代框架的XSS保护功能")
            elif "认证" in vuln_type.lower() or "auth" in vuln_type.lower():
                recommendations.append("增强认证机制，考虑实施多因素认证和安全的会话管理")
            elif "授权" in vuln_type.lower() or "授权" in vuln_type.lower():
                recommendations.append("实施细粒度的访问控制，遵循最小权限原则")
            elif "加密" in vuln_type.lower() or "crypt" in vuln_type.lower():
                recommendations.append("使用现代、标准的加密算法和库，避免自行实现加密逻辑")
            elif "信息泄露" in vuln_type.lower() or "disclosure" in vuln_type.lower():
                recommendations.append("审查错误处理机制，确保不会泄露敏感信息，启用安全的HTTP响应头")
            else:
                recommendations.append(f"修复{vuln_type}漏洞，优先处理严重程度为{most_severe.severity}的问题")
        
        # 添加一般性安全建议
        recommendations.append("实施安全编码实践，遵循OWASP安全编码指南")
        recommendations.append("进行定期的安全培训，提高开发团队的安全意识")
        recommendations.append("考虑使用自动化安全扫描工具，集成到CI/CD流程中")
        
        return recommendations
