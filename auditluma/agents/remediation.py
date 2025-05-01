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
    
    def __init__(self, agent_id: Optional[str] = None, model_spec: Optional[str] = None):
        """初始化修复建议智能体"""
        super().__init__(agent_id, agent_type="generator", model_spec=model_spec)
        self.description = "提供代码修复建议和安全最佳实践"
        
        # 初始化LLM客户端，使用特定任务的默认模型
        # 使用指定模型或任务默认模型，格式为"model@provider"
        self.model_spec = model_spec or Config.default_models.remediation
        # 解析模型名称，只保存实际的模型名称部分
        self.model_name, _ = Config.parse_model_spec(self.model_spec)
        # 初始化LLM客户端
        self.llm_client = init_llm_client(self.model_spec)
        logger.info(f"修复建议智能体使用模型: {self.model_name}")
        
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
        
        # 处理并发调用的单个漏洞情况
        if len(vulnerabilities) == 1:
            vuln = vulnerabilities[0]
            vuln_type = vuln.vulnerability_type
            
            # 获取该类型的通用修复建议
            general_advice = self._get_remediation_template(vuln_type)
            
            # 生成具体修复建议
            specific_remediation = await self._generate_specific_remediation_for_vuln(vuln)
            
            remediation = {
                "vulnerability_id": vuln.id,
                "vulnerability_type": vuln_type,
                "severity": vuln.severity,
                "file_path": vuln.file_path,
                "line_range": f"{vuln.start_line}-{vuln.end_line}",
                "general_advice": general_advice,
                "specific_remediation": specific_remediation
            }
            all_remediations.append(remediation)
        else:
            # 批量处理多个漏洞（通常由orchestrator直接处理）
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
        """为特定类型的漏洞生成具体修复建议"""
        language = detect_language(code)
        
        # 构建提示
        system_prompt = """
你是一位经验丰富的安全修复专家。请为提供的漏洞代码生成具体修复建议。
你的建议应该:
1. 清晰解释问题的根源
2. 提供改进代码的具体步骤
3. 包含修复后的代码示例
4. 说明修复如何解决安全问题

请保持简洁明了，直接提供有用的修复建议。
"""

        user_prompt = f"""
以下是包含 {vulnerability_type} 漏洞的代码:

```{language}
{code}
```

请提供具体修复建议，包括修复后的代码示例。
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
            
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"生成修复建议时出错: {e}")
            return f"生成修复建议时出错: {str(e)}"
    
    async def _generate_specific_remediation_for_vuln(self, vulnerability: VulnerabilityResult) -> str:
        """为具体的漏洞生成修复建议"""
        if not vulnerability or not vulnerability.snippet:
            return "无法生成修复建议：缺少漏洞代码片段"
        
        # 获取漏洞类型
        vuln_type = vulnerability.vulnerability_type
        
        # 获取代码上下文
        try:
            context_docs = await self.retrieve_context(vulnerability.snippet)
            context_text = "\n\n".join([doc.content for doc in context_docs[:3]])  # 限制上下文大小
            
            system_prompt = """
你是一位精通代码安全的修复专家。请为提供的漏洞代码生成详细的修复方案。
你的修复方案应该:
1. 清晰解释漏洞原理
2. 提供具体的代码修复步骤
3. 包含修复后的代码示例
4. 遵循安全最佳实践

请直接提供最佳的修复方案，不需要解释不同的选项。确保你的修复方案与代码语言和上下文一致。
"""

            user_prompt = f"""
以下是存在漏洞的代码片段:
文件: {vulnerability.file_path}
位置: {vulnerability.start_line}-{vulnerability.end_line}
漏洞类型: {vuln_type}
描述: {vulnerability.description}

```
{vulnerability.snippet}
```

相关上下文:
```
{context_text}
```

请提供详细的修复建议，包括修复后的代码。
"""
            
            # 使用特定任务默认模型
            response = await self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"生成漏洞修复建议出错: {e}")
            return f"无法为此漏洞生成修复建议: {str(e)}"

            return f"无法为此漏洞生成修复建议: {str(e)}"

