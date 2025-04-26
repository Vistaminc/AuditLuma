"""
修复建议智能体 - 专门负责生成漏洞修复建议
"""

import os
import re
import asyncio
from typing import List, Dict, Any, Optional, Tuple, Union
import json
from pathlib import Path

from loguru import logger

from auditluma.config import Config
from auditluma.agents.base import BaseAgent
from auditluma.mcp.protocol import MessageType, MessagePriority
from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult, SeverityLevel
from auditluma.rag.self_rag import self_rag
from auditluma.utils import init_llm_client


class RemediationAgent(BaseAgent):
    """修复建议智能体 - 负责生成漏洞修复建议"""
    
    def __init__(self, agent_id: Optional[str] = None):
        """初始化修复建议智能体"""
        super().__init__(agent_id, agent_type="generator")
        self.description = "提供代码修复建议和安全最佳实践"
        
        # 初始化LLM客户端
        self.llm_client = init_llm_client()
        
        # 加载修复模板
        self.remediation_templates = self._load_remediation_templates()
        
        # 特定消息处理器
        self.register_handler(MessageType.QUERY, self._handle_remediation_query)
    
    def _load_remediation_templates(self) -> Dict[str, Any]:
        """加载修复建议模板"""
        # 这里实际应用中可以从文件加载，此处使用内置模板
        return {
            "sql_injection": {
                "pattern": r"SQL注入|SQLi|sql injection",
                "description": "SQL注入是一种安全漏洞，攻击者可以在SQL查询中注入恶意代码。",
                "template": """
修复SQL注入漏洞的最佳方法是使用参数化查询（预处理语句）:

1. **使用参数化查询**:
   ```{{language}}
   // 错误示例
   query = "SELECT * FROM users WHERE username = '" + username + "'";
   
   // 正确示例
   query = "SELECT * FROM users WHERE username = ?";
   statement = connection.prepareStatement(query);
   statement.setString(1, username);
   ```

2. **使用ORM框架**:
   ORM框架通常提供内置的参数化查询功能。

3. **输入验证**:
   实施严格的输入验证，拒绝包含特殊字符的输入。

4. **最小权限原则**:
   确保数据库用户只有执行必要操作的最小权限。
"""
            },
            "xss": {
                "pattern": r"XSS|跨站脚本|cross-site scripting",
                "description": "跨站脚本(XSS)是一种漏洞，攻击者可以向网页注入恶意脚本。",
                "template": """
修复XSS漏洞的最佳方法是实施正确的输出编码和内容安全策略:

1. **输出编码**:
   ```{{language}}
   // 错误示例
   element.innerHTML = userInput;
   
   // 正确示例 - 使用安全的API或库进行HTML编码
   element.textContent = userInput; // 或
   element.innerText = userInput;
   ```

2. **使用框架的XSS保护**:
   许多现代框架(React, Vue等)默认提供XSS保护。

3. **内容安全策略(CSP)**:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'
   ```

4. **验证输入数据**:
   在服务器和客户端双重验证所有用户输入。
"""
            },
            "file_inclusion": {
                "pattern": r"文件包含|路径遍历|目录遍历|path traversal|LFI|RFI",
                "description": "文件包含漏洞允许攻击者访问或包含未经授权的文件。",
                "template": """
修复文件包含漏洞的最佳方法:

1. **路径规范化和验证**:
   ```{{language}}
   // 错误示例
   file = request.getParameter("file");
   include(file);
   
   // 正确示例
   file = request.getParameter("file");
   if (!isAllowedFile(file)) {
     throw new SecurityException("不允许访问该文件");
   }
   include(safePathJoin(BASE_DIR, file));
   ```

2. **白名单验证**:
   使用预定义的安全文件列表，只允许包含这些文件。

3. **禁止使用../等路径操作符**:
   过滤或规范化包含`../`的路径。

4. **使用安全的文件API**:
   使用不允许目录遍历的API。
"""
            },
            "injection": {
                "pattern": r"注入|injection",
                "description": "注入漏洞允许攻击者将恶意代码注入应用程序执行。",
                "template": """
修复通用注入漏洞的最佳方法:

1. **参数化和类型强制**:
   ```{{language}}
   // 错误示例
   exec("command " + userInput);
   
   // 正确示例 - 使用参数化或安全API
   safeCommand.execute(new String[]{"command", userParameter});
   ```

2. **输入验证**:
   使用白名单验证用户输入，只接受预期格式的数据。

3. **最小权限**:
   以最小所需权限运行代码，限制执行环境。

4. **使用安全库**:
   使用经过验证的安全库处理风险操作。
"""
            },
            "authentication": {
                "pattern": r"认证|authentication|auth",
                "description": "认证漏洞可能导致未经授权的访问。",
                "template": """
修复认证漏洞的最佳方法:

1. **实施强密码策略**:
   ```{{language}}
   // 示例密码强度验证
   if (!password.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$")) {
     throw new ValidationException("密码不符合安全要求");
   }
   ```

2. **多因素认证(MFA)**:
   实施MFA以增加额外的安全层。

3. **安全存储凭证**:
   使用强哈希算法(如bcrypt)存储密码。

4. **限制登录尝试**:
   实施登录尝试限制以防止暴力攻击。

5. **使用HTTPS**:
   所有认证通信必须通过HTTPS进行。
"""
            },
            "authorization": {
                "pattern": r"授权|authorization",
                "description": "授权漏洞可能导致用户访问未经授权的资源。",
                "template": """
修复授权漏洞的最佳方法:

1. **实施细粒度访问控制**:
   ```{{language}}
   // 错误示例
   if (user.isLoggedIn()) {
     // 允许所有操作
   }
   
   // 正确示例
   if (accessControl.hasPermission(user, resource, action)) {
     // 允许特定操作
   }
   ```

2. **基于角色的访问控制(RBAC)**:
   实施RBAC以便根据用户角色授予适当权限。

3. **最小权限原则**:
   仅授予执行任务所需的最低权限。

4. **验证所有请求**:
   在每个API端点上验证授权，不仅仅在UI层。
"""
            },
            "cryptographic": {
                "pattern": r"加密|密码|crypto|cryptographic",
                "description": "加密漏洞可能导致敏感数据泄露。",
                "template": """
修复加密相关漏洞的最佳方法:

1. **使用标准加密库**:
   ```{{language}}
   // 错误示例 - 使用过时算法
   MD5Hash(password);
   
   // 正确示例 - 使用现代算法
   BCrypt.hashpw(password, BCrypt.gensalt(12));
   ```

2. **避免自实现加密算法**:
   使用经过验证的加密库，而不是自己实现。

3. **安全密钥管理**:
   使用密钥管理服务，避免硬编码密钥。

4. **使用适当的加密强度**:
   使用足够长的密钥和适当的加密模式。
"""
            },
            "information_disclosure": {
                "pattern": r"信息泄露|information disclosure|敏感信息",
                "description": "信息泄露漏洞可能导致敏感数据被未授权访问。",
                "template": """
修复信息泄露漏洞的最佳方法:

1. **审查错误处理**:
   ```{{language}}
   // 错误示例
   catch (Exception e) {
     response.write(e.toString());
   }
   
   // 正确示例
   catch (Exception e) {
     logger.error("Error: ", e);
     response.write("发生错误，请联系管理员");
   }
   ```

2. **配置安全标头**:
   实施合适的HTTP安全标头:
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - Strict-Transport-Security: max-age=31536000

3. **最小化暴露面**:
   默认情况下，仅返回完成任务所需的最少信息。

4. **移除敏感数据**:
   从日志文件、错误消息和响应中移除敏感数据。
"""
            }
        }
    
    async def execute_task(self, task_type: str, task_data: Any) -> Any:
        """执行任务 - 实现基类的抽象方法"""
        if task_type == "generate_remediation":
            return await self._generate_remediation(task_data)
        else:
            raise ValueError(f"不支持的任务类型: {task_type}")
    
    async def _handle_remediation_query(self, message: Any) -> None:
        """处理修复相关查询"""
        vulnerability_type = message.content.get("vulnerability_type")
        code = message.content.get("code")
        
        if not vulnerability_type:
            await self.send_error(
                receiver=message.sender,
                content={"error": "缺少漏洞类型参数"},
                reply_to=message.message_id
            )
            return
        
        # 获取漏洞类型的修复建议
        remediation = self._get_remediation_template(vulnerability_type)
        
        # 如果提供了代码，生成具体的修复建议
        if code:
            specific_remediation = await self._generate_specific_remediation(vulnerability_type, code)
            await self.send_response(
                receiver=message.sender,
                content={
                    "general_advice": remediation,
                    "specific_remediation": specific_remediation
                },
                reply_to=message.message_id
            )
        else:
            # 只返回通用修复建议
            await self.send_response(
                receiver=message.sender,
                content={"general_advice": remediation},
                reply_to=message.message_id
            )
    
    async def _generate_remediation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """为检测到的漏洞生成修复建议"""
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return {
                "summary": "未发现需要修复的漏洞",
                "remediation_count": 0,
                "remediations": []
            }
        
        # 按漏洞类型分组
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # 生成修复建议
        all_remediations = []
        for vuln_type, vulns in vuln_by_type.items():
            # 获取该类型的通用修复建议
            general_advice = self._get_remediation_template(vuln_type)
            
            # 为每个漏洞实例生成具体的修复建议
            for vuln in vulns:
                remediation = {
                    "vulnerability_id": vuln.id,
                    "vulnerability_type": vuln_type,
                    "severity": vuln.severity,
                    "file_path": vuln.file_path,
                    "line_range": f"{vuln.start_line}-{vuln.end_line}",
                    "general_advice": general_advice,
                    "specific_remediation": await self._generate_specific_remediation_for_vuln(vuln)
                }
                all_remediations.append(remediation)
        
        logger.info(f"为 {len(vulnerabilities)} 个漏洞生成了 {len(all_remediations)} 个修复建议")
        
        return {
            "summary": f"生成了 {len(all_remediations)} 个漏洞修复建议",
            "remediation_count": len(all_remediations),
            "remediations": all_remediations
        }
    
    def _get_remediation_template(self, vulnerability_type: str) -> Dict[str, Any]:
        """获取特定漏洞类型的修复建议模板"""
        # 尝试匹配漏洞类型
        for template_key, template in self.remediation_templates.items():
            pattern = template["pattern"]
            if re.search(pattern, vulnerability_type, re.IGNORECASE):
                return {
                    "title": template_key,
                    "description": template["description"],
                    "advice": template["template"]
                }
        
        # 如果没有匹配的模板，返回通用建议
        return {
            "title": "安全漏洞",
            "description": "为防止安全漏洞，请遵循安全编码最佳实践。",
            "advice": """
一般安全最佳实践:

1. **输入验证**:
   验证所有来自用户的输入数据。

2. **输出编码**:
   对输出到用户界面的数据进行适当的编码。

3. **使用安全库**:
   尽可能使用经过验证的安全库和框架。

4. **最小权限原则**:
   以完成任务所需的最小权限运行应用程序。

5. **安全默认设置**:
   确保应用默认配置是安全的。
"""
        }
    
    async def _generate_specific_remediation(self, vulnerability_type: str, code: str) -> str:
        """为特定代码和漏洞类型生成具体的修复建议"""
        # 准备系统提示
        system_prompt = """
你是安全代码修复专家。请分析提供的有漏洞代码，并提供具体的修复建议。
请确保你的修复建议:
1. 针对特定代码给出具体的修复方案
2. 提供修复后的代码示例
3. 解释修复的原理和安全考虑
4. 关注安全最佳实践和常见的防护模式

你的回答应保持简洁和针对性，专注于解决具体的安全问题。
"""
        
        # 准备用户提示
        user_prompt = f"""
以下代码存在 {vulnerability_type} 类型的安全漏洞:

```
{code}
```

请提供具体的修复方案和修复后的代码示例。
"""
        
        try:
            # 调用LLM生成修复建议
            response = await self.llm_client.chat.completions.create(
                model=Config.default_models.remediation,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"生成修复建议时出错: {e}")
            return "无法生成具体的修复建议。请参考通用最佳实践。"
    
    async def _generate_specific_remediation_for_vuln(self, vulnerability: VulnerabilityResult) -> str:
        """为特定漏洞实例生成具体的修复建议"""
        # 获取漏洞相关的代码片段
        code_snippet = vulnerability.snippet
        if not code_snippet and hasattr(vulnerability, "code_unit"):
            code_unit = vulnerability.code_unit
            if code_unit:
                # 提取相关代码行
                lines = code_unit.content.splitlines()
                start = max(0, vulnerability.start_line - code_unit.start_line)
                end = min(len(lines), vulnerability.end_line - code_unit.start_line + 1)
                code_snippet = "\n".join(lines[start:end])
        
        if not code_snippet:
            return "无法获取漏洞代码片段，无法生成具体的修复建议。"
        
        # 准备系统提示
        system_prompt = """
你是安全代码修复专家。请分析提供的有漏洞代码，并提供具体的修复建议。
请确保你的修复建议:
1. 针对特定代码给出具体的修复方案
2. 提供修复后的代码示例，标明修改的部分
3. 解释修复的原理和安全考虑
4. 关注安全最佳实践和常见的防护模式

你的回答应保持简洁和针对性，专注于解决具体的安全问题。
"""
        
        # 准备用户提示
        user_prompt = f"""
以下代码存在 {vulnerability.vulnerability_type} 类型的安全漏洞:

```
{code_snippet}
```

漏洞描述: {vulnerability.description}

请提供具体的修复方案和修复后的代码示例。
"""
        
        try:
            # 调用LLM生成修复建议
            response = await self.llm_client.chat.completions.create(
                model=Config.default_models.remediation,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2
            )
            
            remediation_text = response.choices[0].message.content
            
            # 添加安全说明
            remediation_text += f"\n\n**注意**: 此修复仅针对所识别的漏洞。请确保全面审查代码以识别可能存在的其他安全问题。"
            
            return remediation_text
            
        except Exception as e:
            logger.error(f"生成修复建议时出错: {vulnerability.id}, {e}")
            return "无法生成具体的修复建议。请参考通用最佳实践。"
