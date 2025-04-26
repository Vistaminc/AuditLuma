"""
LLM客户端模拟模块 - 提供用于测试的模拟LLM实现
"""

import json
import asyncio
from typing import Dict, List, Any, Optional
from loguru import logger


class MockResponse:
    """模拟的LLM响应对象"""
    
    def __init__(self, content: str):
        self.content = content
        
    def json(self):
        try:
            return json.loads(self.content)
        except:
            return {"error": "Invalid JSON"}


class MockChoice:
    """模拟的LLM选择对象"""
    
    def __init__(self, content: str):
        self.message = MockMessage(content)
        self.finish_reason = "stop"
        self.index = 0


class MockMessage:
    """模拟的LLM消息对象"""
    
    def __init__(self, content: str):
        self.content = content
        self.role = "assistant"


class MockCompletion:
    """模拟的LLM完成对象"""
    
    def __init__(self, content: str):
        self.choices = [MockChoice(content)]
        self.created = 0
        self.id = "mock-completion-id"
        self.model = "mock-model"
        self.object = "chat.completion"
        self.usage = {"completion_tokens": 100, "prompt_tokens": 50, "total_tokens": 150}


class MockChatModule:
    """模拟的聊天模块"""
    
    def __init__(self):
        self.completions = MockCompletionsModule()


class MockCompletionsModule:
    """模拟的完成模块"""
    
    async def create(self, model: str, messages: List[Dict[str, str]], **kwargs) -> MockCompletion:
        """模拟创建完成"""
        # 记录调用
        logger.info(f"[模拟] LLM调用 - 模型: {model}, 参数: {kwargs}")
        
        # 获取系统和用户消息
        system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_msg = next((m["content"] for m in messages if m["role"] == "user"), "")
        
        # 根据消息类型生成模拟响应
        if "安全分析" in system_msg or "漏洞" in system_msg:
            # 安全分析模拟响应
            return MockCompletion(generate_security_analysis_response(user_msg))
        elif "依赖关系" in system_msg:
            # 依赖分析模拟响应
            return MockCompletion(generate_dependency_analysis_response(user_msg))
        elif "修复建议" in system_msg or "remediation" in system_msg.lower():
            # 修复建议模拟响应
            return MockCompletion(generate_remediation_response(user_msg))
        else:
            # 通用模拟响应
            return MockCompletion(generate_generic_response(system_msg, user_msg))


class MockEmbeddingsModule:
    """模拟的嵌入模块"""
    
    async def create(self, model: str, input: List[str], **kwargs) -> Dict[str, Any]:
        """模拟创建嵌入"""
        # 为每个输入文本生成随机嵌入向量（每个维度值在-1到1之间）
        import random
        
        embeddings = []
        for _ in input:
            # 创建1536维的随机向量（与OpenAI的嵌入模型维度一致）
            embedding = [random.uniform(-1, 1) for _ in range(1536)]
            # 归一化向量
            magnitude = sum(x*x for x in embedding) ** 0.5
            embedding = [x/magnitude for x in embedding]
            embeddings.append(embedding)
        
        return {
            "data": [{"embedding": emb, "index": i} for i, emb in enumerate(embeddings)],
            "model": model,
            "object": "list",
            "usage": {"prompt_tokens": len(input) * 100, "total_tokens": len(input) * 100}
        }


class MockLLMClient:
    """模拟的LLM客户端类
    
    用于在无法连接真实API时提供基本功能
    """
    
    def __init__(self):
        """初始化模拟LLM客户端"""
        self.chat = MockChatModule()
        self.embeddings = MockEmbeddingsModule()


def generate_security_analysis_response(code: str) -> str:
    """生成安全分析的模拟响应"""
    # 检查代码中的常见漏洞关键词
    vulnerabilities = []
    
    if "exec(" in code or "eval(" in code:
        vulnerabilities.append({
            "name": "代码注入",
            "description": "使用了危险的代码执行函数",
            "severity": "high",
            "location": "模拟位置",
            "remediation": "避免使用exec()和eval()函数处理不可信数据"
        })
    
    if "password" in code.lower() and ("=" in code or ":" in code):
        vulnerabilities.append({
            "name": "硬编码密码",
            "description": "代码中包含硬编码的密码",
            "severity": "medium",
            "location": "模拟位置",
            "remediation": "使用环境变量或安全的配置管理系统存储敏感信息"
        })
    
    # 构建响应
    if vulnerabilities:
        response = "我在代码中发现了以下安全漏洞：\n\n"
        for i, vuln in enumerate(vulnerabilities, 1):
            response += f"{i}. **{vuln['name']}** ({vuln['severity'].upper()})\n"
            response += f"   描述: {vuln['description']}\n"
            response += f"   位置: {vuln['location']}\n"
            response += f"   修复建议: {vuln['remediation']}\n\n"
    else:
        response = "我没有在代码中发现明显的安全漏洞。代码实现了基本功能，没有使用不安全的函数或明显的安全问题。"
    
    return response


def generate_dependency_analysis_response(code: str) -> str:
    """生成依赖分析的模拟响应"""
    # 提取代码中可能的导入和函数调用
    imports = []
    if "import " in code:
        imports = ["模拟导入项"]
    
    function_calls = []
    if "(" in code and ")" in code:
        function_calls = ["模拟函数调用"]
    
    # 构建响应
    response = "## 依赖分析\n\n"
    response += "该代码单元有以下依赖关系：\n\n"
    
    if imports:
        response += "### 导入依赖\n"
        for imp in imports:
            response += f"- {imp}\n"
    
    if function_calls:
        response += "\n### 函数调用\n"
        for func in function_calls:
            response += f"- {func}\n"
    
    if not imports and not function_calls:
        response += "没有发现明显的依赖关系。\n"
    
    return response


def generate_remediation_response(code: str) -> str:
    """生成修复建议的模拟响应"""
    return """## 修复建议

为了解决代码中的安全问题，建议进行以下修改：

1. **输入验证**：在处理用户输入前添加适当的验证和清理
2. **使用参数化查询**：避免直接拼接SQL语句，使用参数化查询防止SQL注入
3. **加密敏感数据**：使用安全的加密算法存储敏感数据
4. **实施访问控制**：确保用户只能访问其有权限的资源

修复后的代码示例：

```python
# 这是一个安全的代码示例
def process_user_input(user_input):
    # 输入验证
    if not is_valid_input(user_input):
        raise ValueError("无效输入")
    
    # 使用安全的API
    result = secure_api_call(user_input)
    return result
```
"""


def generate_generic_response(system_msg: str, user_msg: str) -> str:
    """生成通用的模拟响应"""
    return f"""作为AI助手，我已收到您的请求。

由于系统当前处于模拟模式，无法提供真实的LLM分析。这是一个模拟响应，仅供测试使用。

在真实环境中，系统会对您的请求进行详细分析并提供专业建议。

如需获取真实分析，请禁用模拟模式并确保LLM API连接正常。
"""
