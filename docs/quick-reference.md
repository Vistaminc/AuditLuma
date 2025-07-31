# 快速参考手册

## 常用命令

### 基础使用

```bash
# 快速开始（自动选择架构）
python main.py --architecture auto -d ./your-project

# 使用层级RAG架构（推荐）
python main.py --architecture hierarchical -d ./your-project

# 使用传统RAG架构
python main.py --architecture traditional -d ./your-project

# 查看架构信息
python main.py --show-architecture-info

# 配置迁移
python main.py --config-migrate
```

### 编排器选择

```bash
# 使用Haystack-AI编排器（推荐）
python main.py --architecture hierarchical --haystack-orchestrator ai

# 使用传统编排器
python main.py --architecture hierarchical --haystack-orchestrator traditional
```

### 层级RAG组件

```bash
# 启用所有层级RAG组件
python main.py --architecture hierarchical \
  --enable-txtai \
  --enable-r2r \
  --enable-self-rag-validation

# 启用性能对比模式
python main.py --enable-performance-comparison
```

### 调试和监控

```bash
# 启用详细日志
python main.py --verbose -d ./your-project

# 试运行模式
python main.py --dry-run -d ./your-project

# 运行诊断工具
python -m auditluma.diagnostics run-all
```

## 配置速查

### 层级RAG基础配置

```yaml
hierarchical_rag_models:
  enabled: true
  
  haystack:
    orchestrator_type: "ai"  # ai | traditional
    default_model: "gpt-4@openai"
    
  txtai:
    retrieval_model: "gpt-3.5-turbo@openai"
    embedding_model: "text-embedding-ada-002@openai"
    
  r2r:
    context_model: "gpt-3.5-turbo@openai"
    enhancement_model: "gpt-4@openai"
    
  self_rag_validation:
    validation_model: "gpt-4@openai"
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
```

### 性能优化配置

```yaml
# 缓存配置
cache:
  enabled: true
  type: "redis"
  cache_strategy:
    max_size: "1GB"
    default_ttl: 3600

# 并行处理
project:
  max_batch_size: 20
  max_file_size: 1000000

# 监控配置
monitoring:
  enabled: true
  performance:
    track_response_time: true
    track_accuracy: true
```

### 模型提供商配置

```yaml
providers:
  openai:
    api_key: "your-openai-key"
    base_url: "https://api.openai.com/v1"
    max_tokens: 8000
    temperature: 0.1
    
  deepseek:
    api_key: "your-deepseek-key"
    base_url: "https://api.deepseek.com/v1"
    max_tokens: 8000
    temperature: 0.1
```

## 环境变量

```bash
# API密钥
export OPENAI_API_KEY="your-openai-key"
export DEEPSEEK_API_KEY="your-deepseek-key"
export QWEN_API_KEY="your-qwen-key"

# 架构设置
export AUDITLUMA_ARCHITECTURE="hierarchical"
export AUDITLUMA_ORCHESTRATOR="ai"

# 缓存设置
export AUDITLUMA_CACHE_TYPE="redis"
export AUDITLUMA_REDIS_URL="redis://localhost:6379"
```

## 故障排除速查

### 配置问题

```bash
# 验证配置文件
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"

# 配置验证工具
python -m auditluma.config validate

# 配置迁移
python main.py --config-migrate
```

### 连接问题

```bash
# 测试API连接
python -c "
import openai
openai.api_key = 'your-key'
print(openai.Model.list())
"

# 检查网络连接
curl -I https://api.openai.com/v1/models
```

### 性能问题

```bash
# 减少并行度
python main.py --workers 2

# 启用缓存
python main.py --enable-caching

# 使用轻量级模型
# 在配置文件中设置 gpt-3.5-turbo
```

## 架构选择指南

| 项目规模 | 推荐架构 | 编排器 | 命令示例 |
|---------|---------|--------|----------|
| <100文件 | traditional | - | `--architecture traditional` |
| 100-1000文件 | hierarchical | ai | `--architecture hierarchical --haystack-orchestrator ai` |
| >1000文件 | hierarchical | ai | `--architecture hierarchical --enable-txtai --enable-r2r --enable-self-rag-validation` |
| 自动选择 | auto | - | `--architecture auto` |

## 模型选择指南

| 任务类型 | 推荐模型 | 说明 |
|---------|---------|------|
| 安全扫描 | gpt-4@openai | 最高精度 |
| 语法检查 | gpt-3.5-turbo@openai | 快速高效 |
| 逻辑分析 | deepseek-chat@deepseek | 平衡性能 |
| 依赖分析 | qwen-turbo@qwen | 成本优化 |
| 交叉验证 | 多模型组合 | 提高可靠性 |

## 报告格式

| 格式 | 用途 | 命令参数 |
|------|------|----------|
| HTML | 交互式查看 | `--format html` |
| JSON | 程序处理 | `--format json` |
| PDF | 打印分享 | `--format pdf` |

## 集成示例

### GitHub Actions

```yaml
- name: Run AuditLuma
  run: |
    python main.py --architecture auto --format json -d . -o ./reports
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Docker

```dockerfile
FROM python:3.8
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "main.py", "--architecture", "hierarchical"]
```

### Jenkins

```groovy
stage('Security Audit') {
    steps {
        sh 'python main.py --architecture hierarchical -d ${WORKSPACE} -o ./reports'
    }
}
```

## 性能基准

| 架构模式 | 小项目(<100文件) | 中项目(100-1000文件) | 大项目(>1000文件) |
|---------|-----------------|-------------------|------------------|
| traditional | ~2分钟 | ~15分钟 | ~60分钟 |
| hierarchical | ~3分钟 | ~10分钟 | ~30分钟 |
| hierarchical+全组件 | ~5分钟 | ~12分钟 | ~25分钟 |

*注：实际性能取决于硬件配置、网络状况和模型响应速度*

## 常见错误代码

| 错误代码 | 含义 | 解决方案 |
|---------|------|----------|
| CONFIG_001 | 配置文件语法错误 | 检查YAML语法 |
| API_001 | API密钥无效 | 检查API密钥设置 |
| NETWORK_001 | 网络连接超时 | 检查网络连接 |
| MEMORY_001 | 内存不足 | 减少批处理大小 |
| CACHE_001 | 缓存连接失败 | 检查Redis服务 |

## 联系支持

- **GitHub Issues**: 报告bug和功能请求
- **文档**: 查看完整文档
- **QQ群**: 1047736593
- **邮箱**: support@auditluma.com

## 版本信息

- **当前版本**: 2.0.0
- **最低Python版本**: 3.8+
- **推荐Python版本**: 3.9+
- **支持操作系统**: Windows, macOS, Linux