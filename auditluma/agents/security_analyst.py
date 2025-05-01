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
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult, SeverityLevel
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
        elif task_type == "vulnerability_assessment":
            return await self._vulnerability_assessment(task_data)
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
    
    def _parse_security_analysis(self, analysis_text: str, code_unit: CodeUnit) -> List[VulnerabilityResult]:
        """解析LLM返回的安全分析结果"""
        vulnerabilities = []
        
        # 提取<安全审计结果>标签之间的内容
        import re
        result_pattern = r"<安全审计结果>(.*?)</安全审计结果>"
        matches = re.search(result_pattern, analysis_text, re.DOTALL)
        
        if not matches:
            logger.warning("无法从LLM响应中提取安全审计结果")
            return vulnerabilities
        
        result_text = matches.group(1).strip()
        
        # 检查是否未发现漏洞
        if "未发现安全漏洞" in result_text:
            return vulnerabilities
        
        # 提取各个漏洞
        vulnerability_pattern = r"\[漏洞\d+\](.*?)(?=\[漏洞\d+\]|\Z)"
        vulnerability_matches = re.finditer(vulnerability_pattern, result_text, re.DOTALL)
        
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
        """从文本中提取属性值"""
        import re
        pattern = rf"- {property_name}: ?(.*?)(?=\n- |\n\n|\Z)"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None
    
    def _extract_code_snippet(self, text: str) -> Optional[str]:
        """从文本中提取代码片段"""
        import re
        pattern = r"```(?:\w+)?\n(.*?)```"
        match = re.search(pattern, text, re.DOTALL)
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
            if re.search(pattern, analysis, re.IGNORECASE):
                # 尝试提取相关描述
                context_pattern = rf"({pattern}.{{0,200}})"
                context_match = re.search(context_pattern, analysis, re.IGNORECASE | re.DOTALL)
                description = context_match.group(1) if context_match else "未提供详细描述"
                
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
