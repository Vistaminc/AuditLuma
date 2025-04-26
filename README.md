# AuditLuma - 高级代码审计AI系统

AuditLuma是一个智能代码审计系统，它利用多个AI代理和先进的技术，包括多代理合作协议（MCP）和Self-RAG（检索增强生成），为代码库提供全面的安全分析。

## 特性

- **多代理架构**：针对不同审计任务的专门代理
- **MCP（多代理合作协议）**：增强代理之间的协调
- **Self-RAG技术**：提高上下文理解和知识检索
- **综合安全分析**：检测漏洞并提出修复建议
- **可视化**：生成依赖关系图和安全报告
- **多LLM厂商支持**：支持OpenAI、DeepSeek、MoonShot、通义千问等多家厂商
- **自动厂商检测**：根据模型名称自动识别并配置正确的厂商API

## 安装

```bash
pip install -r requirements.txt
```

### 可选依赖

**FAISS向量检索库**

默认情况下，AuditLuma会使用一个简单的内置向量存储实现。如果需要处理大型代码库，建议安装FAISS以提高性能：

```bash
# CPU版本
pip install faiss-cpu

# GPU版本(支持CUDA)
pip install faiss-gpu
```

安装FAISS后，系统将自动检测并使用它进行向量存储和检索，显著提高分析大型项目时的性能。

## 使用

```bash
python main.py -d ./goalfile -o ./reports
```

支持的命令行参数:
- `-d, --directory`：目标项目目录（默认：./goalfile）
- `-o, --output`：报告输出目录（默认：./reports）
- `-w, --workers`：并行工作线程数
- `-f, --format`：报告格式（html、pdf或json）
- `--no-mcp`：禁用多智能体协作协议
- `--no-self-rag`：禁用Self-RAG检索
- `--no-deps`：跳过依赖分析
- `--no-remediation`：跳过生成修复建议

## 配置

通过编辑`config/config.yaml`文件配置系统。主要配置项包括：

### LLM配置
```yaml
llm:
  provider: "openai"  # 支持: openai, deepseek, moonshot, qwen, baichuan, zhipu, azure
  base_url: "https://api.openai.com/v1"
  api_key: ""  # API密钥
  model: "gpt-4-turbo-preview"  # 默认模型
```

### 多厂商支持
AuditLuma支持多家LLM厂商，并能根据模型名称自动检测厂商：
- 以`gpt-`开头的模型识别为OpenAI
- 以`deepseek-`开头的模型识别为DeepSeek
- 以`moonshot-`开头的模型识别为硅基流动
- 以`qwen-`开头的模型识别为通义千问
- 以`glm-`或`chatglm`开头的模型识别为智谱AI

## 支持语言

AuditLuma支持分析以下编程语言：

### 主要语言（包括排名前10）
- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Java (.java)
- C# (.cs)
- C++ (.cpp, .cc, .hpp)
- C (.c, .h)
- Go (.go)
- Ruby (.rb)
- PHP (.php)
- Lua (.lua)

### 其他支持的语言
- Rust (.rs)
- Swift (.swift)
- Kotlin (.kt)
- Scala (.scala)
- Dart (.dart)
- Bash (.sh, .bash)
- PowerShell (.ps1, .psm1)

### 标记和配置语言
- HTML (.html, .htm)
- CSS (.css)
- JSON (.json)
- XML (.xml)
- YAML (.yml, .yaml)
- SQL (.sql)

## 架构

AuditLuma使用多代理架构，包含以下组件：

1. **Agent Orchestrator**：协调工作流中的所有代理
2. **代码分析代理**：分析代码结构并提取依赖关系
3. **安全分析代理**：识别安全漏洞
4. **修复建议代理**：生成针对性漏洞修复方案
5. **可视化组件**：生成直观的报告和依赖关系图

## 报告格式

AuditLuma支持以下报告格式：
- **HTML报告**：包含漏洞详情、统计图表和交互式可视化
- **PDF报告**：适合打印和分享的格式
- **JSON报告**：适合进一步处理和集成的机器可读格式

## 贡献

欢迎贡献代码和建议！请提交问题和PR。

## 许可证

MIT
