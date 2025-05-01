# AuditLuma - 高级代码审计AI系统 🔍

<div align="center">

![Version](https://img.shields.io/badge/version-1.1.5-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8+-yellow)

</div>

AuditLuma是一个智能代码审计系统，它利用多个AI代理和先进的技术，包括多代理合作协议（MCP）和Self-RAG（检索增强生成），为代码库提供全面的安全分析。

## ✨ 特性

- 🤖 **多代理架构** - 针对不同审计任务的专门代理
- 🔄 **MCP（多代理合作协议）** - 增强代理之间的协调与合作
- 🔍 **Self-RAG技术** - 提高上下文理解和知识检索能力
- 🛡️ **综合安全分析** - 全面检测漏洞并提出有效修复建议
- 📊 **可视化功能** - 生成依赖关系图和详细安全报告
- 🌐 **多LLM厂商支持** - 支持OpenAI、DeepSeek、MoonShot、通义千问等多家厂商
- 🔄 **自动厂商检测** - 根据模型名称自动识别并配置正确的厂商API
- ⚡ **异步并行处理** - 使用异步并发技术提高性能，加快分析速度

## 📋 目录

- [安装](#-安装)
- [使用](#-使用)
- [配置](#-配置)
- [支持语言](#-支持语言)
- [架构](#-架构)
- [报告格式](#-报告格式)
- [贡献](#-贡献)
- [许可证](#-许可证)

## 🚀 安装

克隆仓库并安装依赖：

```bash
git clone https://github.com/yourusername/AuditLuma.git
cd AuditLuma
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

## 🛠 使用

基本用法：

```bash
python main.py -d ./goalfile -o ./reports
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-d, --directory` | 目标项目目录 | `./goalfile` |
| `-o, --output` | 报告输出目录 | `./reports` |
| `-w, --workers` | 并行工作线程数 | 配置中的max_batch_size |
| `-f, --format` | 报告格式(html/pdf/json) | 配置中的report_format |
| `--no-mcp` | 禁用多智能体协作协议 | 默认启用 |
| `--no-self-rag` | 禁用Self-RAG检索 | 默认启用 |
| `--no-deps` | 跳过依赖分析 | 默认不跳过 |
| `--no-remediation` | 跳过生成修复建议 | 默认不跳过 |
| `--verbose` | 启用详细日志记录 | 默认禁用 |

## ⚙️ 配置

通过编辑`config/config.yaml`文件配置系统。主要配置项包括：

### 模型规范格式

AuditLuma支持使用统一的模型规范格式 `model@provider` 来指定模型和提供商：

```
deepseek-chat@deepseek  # 指定使用DeepSeek提供商的deepseek-chat模型
gpt-4-turbo@openai      # 指定使用OpenAI提供商的gpt-4-turbo模型
qwen-turbo@qwen         # 指定使用通义千问提供商的qwen-turbo模型
```

如果不指定提供商（不使用@符号），系统将自动根据模型名称推断提供商。

### 配置文件示例

```yaml
# 默认模型配置
default_models:
  code_analysis: "deepseek-chat@deepseek"   # 代码分析模型
  security_audit: "gpt-4-turbo@openai"      # 安全审计模型
  remediation: "deepseek-chat@deepseek"     # 修复建议模型
  summarization: "qwen-turbo@qwen"          # 报告总结模型

# Self-RAG配置
self_rag:
  enabled: true
  embedding_model: "text-embedding-3-small@openai"  # 嵌入模型

# 多智能体配置
mcp:
  enabled: true
  agents:
    - name: "orchestrator"
      type: "coordinator"
      model: "deepseek-chat@deepseek"  # 编排智能体使用的模型
    - name: "security_analyst"
      type: "analyst"
      model: "gpt-4-turbo@openai"      # 安全分析智能体使用的模型
```

### 多厂商支持

AuditLuma支持多家LLM厂商，并能根据模型名称自动检测厂商：

| 模型前缀 | 厂商 |
|---------|------|
| `gpt-` | OpenAI |
| `deepseek-` | DeepSeek |
| `moonshot-` | 硅基流动 |
| `qwen-` | 通义千问 |
| `glm-`或`chatglm` | 智谱AI |
| `baichuan` | 百川 |

## 💻 支持语言

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

## 🏛 架构

AuditLuma使用多代理架构，包含以下组件：

![Architecture](https://via.placeholder.com/800x400?text=AuditLuma+Architecture)

1. **Agent Orchestrator** - 协调工作流中的所有代理
2. **代码分析代理** - 分析代码结构并提取依赖关系
3. **安全分析代理** - 识别安全漏洞
4. **修复建议代理** - 生成针对性漏洞修复方案
5. **可视化组件** - 生成直观的报告和依赖关系图

## 📊 报告格式

AuditLuma支持以下报告格式：

- 📋 **HTML报告** - 包含漏洞详情、统计图表和交互式可视化
- 📄 **PDF报告** - 适合打印和分享的格式
- 🔄 **JSON报告** - 适合进一步处理和集成的机器可读格式

## 💬 贡献

欢迎贡献代码和建议！请遵循以下步骤：

1. Fork 仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 📞 交流方式
-QQ：1047736593

## 支持与赞赏

如果您觉得AuditLuma对您有帮助，欢迎通过以下方式支持我们：

- 您的赞助将用于帮助我们持续改进和完善 AuditLuma！

<div style="display: flex; justify-content: space-between; max-width: 600px; margin: 0 auto;">
  <div style="flex: 1; margin-right: 20px;">
    <img src="https://github.com/Vistaminc/Miniluma/blob/main/ui/web/static/img/zanshang/wechat.jpg"/>
  </div>
  <div style="flex: 1;">
    <img src="https://github.com/Vistaminc/Miniluma/blob/main/ui/web/static/img/zanshang/zfb.jpg"/>
  </div>
</div>

## 📜 许可证

MIT

---

<div align="center">
  <sub>Built with ❤️ by AuditLuma Team</sub>
</div>
