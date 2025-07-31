# 配置参考指南

## 概述

本文档提供AuditLuma的完整配置参考，包括所有配置选项、参数说明和最佳实践建议。AuditLuma支持传统RAG架构和层级RAG架构两种模式，本指南将详细介绍两种架构的配置方法。

## 📁 配置文件结构

```
config/
├── config.yaml                    # 主配置文件
├── config.yaml.example           # 配置示例文件
├── hierarchical_rag_config.yaml  # 层级RAG专用配置
└── enhanced_self_rag_config.yaml # 增强Self-RAG配置
```

## 🔧 主配置文件 (config.yaml)

### 全局设置

```yaml
# 全局设置
global:
  # 是否显示代理思考过程
  show_thinking: false
  
  # 默认语言
  language: "zh-CN"
  
  # 目标项目目录
  target_dir: "./goalfile"
  
  # 报告输出目录
  report_dir: "./reports"
  
  # 报告格式：html, pdf, json
  report_format: "html"
  
  # 默认架构模式：traditional, hierarchical, auto
  default_architecture: "hierarchical"
  
  # 自动切换阈值（文件数量）
  auto_switch_threshold: 100
  
  # 是否启用性能对比
  enable_performance_comparison: false
```

#### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `show_thinking` | boolean | `false` | 是否在输出中显示AI的思考过程 |
| `language` | string | `"zh-CN"` | 系统默认语言，支持zh-CN、en-US等 |
| `target_dir` | string | `"./goalfile"` | 默认的代码分析目标目录 |
| `report_dir` | string | `"./reports"` | 分析报告的输出目录 |
| `report_format` | string | `"html"` | 报告格式，可选html、pdf、json |
| `default_architecture` | string | `"hierarchical"` | 默认架构模式 |
| `auto_switch_threshold` | integer | `100` | 自动切换架构的文件数量阈值 |
| `enable_performance_comparison` | boolean | `false` | 是否启用架构性能对比 |

### LLM提供商配置

#### OpenAI配置

```yaml
# OpenAI 配置
openai:
  model: "gpt-4-turbo-preview"
  api_key: "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  base_url: "https://api.openai.com/v1"  # 可选，用于代理或中转
  max_tokens: 8000
  temperature: 0.1
  timeout: 60
  max_retries: 3
```

#### DeepSeek配置

```yaml
# DeepSeek 配置
deepseek:
  model: "deepseek-chat"
  api_key: "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  base_url: "https://api.deepseek.com/v1"
  max_tokens: 8000
  temperature: 0.1
  timeout: 60
  max_retries: 3
```

#### 通义千问配置

```yaml
# 通义千问配置
qwen:
  model: "qwen-max"
  api_key: "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  base_url: "https://dashscope.aliyuncs.com/api/v1"
  max_tokens: 8000
  temperature: 0.1
  timeout: 60
  max_retries: 3
```

#### Ollama配置

```yaml
# Ollama 配置
ollama:
  model: "deepseek-r1:1.5b"
  api_key: ""  # Ollama本地部署不需要API key
  base_url: "http://localhost:11434/api"
  max_tokens: 8000
  temperature: 0.1
  timeout: 120
  max_retries: 2
```

#### 嵌入模型配置

```yaml
# Ollama嵌入模型配置
ollama_emd:
  model: "mxbai-embed-large:latest"
  api_key: ""
  base_url: "http://localhost:11434/api/embeddings"
  max_tokens: 8000
  temperature: 0.1
```

### 代理设置

```yaml
# 代理设置
agent:
  # 默认使用的LLM提供商
  default_provider: "openai"
  
  # 系统提示词
  system_prompt: "你是一个专业的代码安全审计助手，将帮助用户分析代码中的安全漏洞"
  
  # 记忆容量
  memory_limit: 10
  
  # 最大重试次数
  max_retries: 3
  
  # 超时时间（秒）
  timeout: 300
```

### 项目配置

```yaml
# 项目配置
project:
  name: "AuditLuma项目"
  
  # 处理的最大文件大小（字节）
  max_file_size: 1000000
  
  # 并行处理的最大文件数
  max_batch_size: 20
  
  # 忽略的文件扩展名
  ignored_extensions: 
    - ".jpg"
    - ".png"
    - ".gif"
    - ".mp3"
    - ".mp4"
    - ".zip"
    - ".tar"
    - ".gz"
  
  # 忽略的目录
  ignored_directories: 
    - "node_modules"
    - "__pycache__"
    - ".git"
    - "dist"
    - "build"
    - "venv"
    - "env"
```

### 传统Self-RAG配置

```yaml
# 传统Self-RAG系统配置
self_rag:
  enabled: true
  
  # 向量存储类型：faiss, simple
  vector_store: "faiss"
  
  # 嵌入模型
  embedding_model: "text-embedding-ada-002@openai"
  
  # 文档分块大小
  chunk_size: 1000
  
  # 分块重叠大小
  chunk_overlap: 200
  
  # 最大文档数量
  max_documents: 10000
  
  # 检索返回的文档数量
  retrieval_k: 5
  
  # 相关性阈值
  relevance_threshold: 0.75
```

## 🏗️ 层级RAG架构配置

### 主配置

```yaml
# 层级RAG架构模型配置
hierarchical_rag_models:
  # 是否启用层级RAG架构
  enabled: true
  
  # 全局配置
  global_config:
    # 最大并行任务数
    max_parallel_tasks: 10
    
    # 全局超时时间（秒）
    global_timeout: 600
    
    # 是否启用调试模式
    debug_mode: false
    
    # 日志级别：DEBUG, INFO, WARNING, ERROR
    log_level: "INFO"
```

### Haystack编排层配置

```yaml
hierarchical_rag_models:
  haystack:
    # 编排器类型：traditional, ai
    orchestrator_type: "ai"
    
    # 默认模型（支持 model@provider 格式）
    default_model: "gpt-4@openai"
    
    # 任务特定模型配置
    task_models:
      security_scan: "gpt-4@openai"
      syntax_check: "deepseek-chat@deepseek"
      logic_analysis: "qwen-turbo@qwen"
      dependency_analysis: "gpt-3.5-turbo@openai"
      code_review: "claude-3@anthropic"
      vulnerability_assessment: "gpt-4@openai"
    
    # 编排器配置
    orchestrator_config:
      # 最大并行任务数
      max_parallel_tasks: 8
      
      # 任务超时时间（秒）
      task_timeout: 300
      
      # 重试次数
      retry_attempts: 3
      
      # 结果整合策略：weighted, majority, confidence
      integration_strategy: "weighted"
      
      # 是否启用智能负载均衡
      enable_load_balancing: true
```

### txtai知识检索层配置

```yaml
hierarchical_rag_models:
  txtai:
    # 检索模型
    retrieval_model: "gpt-3.5-turbo@openai"
    
    # 嵌入模型
    embedding_model: "text-embedding-ada-002@openai"
    
    # 索引配置
    index_config:
      # 向量维度
      dimensions: 1536
      
      # 相似性度量：cosine, euclidean, dot
      metric: "cosine"
      
      # 是否启用量化
      quantize: true
      
      # 批处理大小
      batch_size: 100
      
      # 索引类型：flat, hnsw, ivf
      index_type: "hnsw"
    
    # 检索配置
    retrieval_config:
      # 检索数量
      top_k: 10
      
      # 相似性阈值
      similarity_threshold: 0.7
      
      # 是否启用重排序
      enable_reranking: true
      
      # 重排序模型
      reranking_model: "cross-encoder/ms-marco-MiniLM-L-6-v2"
```

### R2R上下文增强层配置

```yaml
hierarchical_rag_models:
  r2r:
    # 上下文分析模型
    context_model: "gpt-3.5-turbo@openai"
    
    # 增强模型
    enhancement_model: "gpt-4@openai"
    
    # 上下文配置
    context_config:
      # 最大上下文长度
      max_context_length: 8000
      
      # 扩展策略：fixed, adaptive, dynamic
      expansion_strategy: "adaptive"
      
      # 相关性阈值
      relevance_threshold: 0.7
      
      # 最大扩展次数
      max_expansions: 5
      
      # 上下文窗口大小
      context_window_size: 2000
    
    # 增强配置
    enhancement_config:
      # 是否启用语义增强
      enable_semantic_enhancement: true
      
      # 是否启用结构化增强
      enable_structural_enhancement: true
      
      # 增强强度：low, medium, high
      enhancement_strength: "medium"
```

### Self-RAG验证层配置

```yaml
hierarchical_rag_models:
  self_rag_validation:
    # 主验证模型
    validation_model: "gpt-4@openai"
    
    # 交叉验证模型列表
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
      - "claude-3@anthropic"
      - "qwen-max@qwen"
    
    # 验证配置
    validation_config:
      # 最小置信度阈值
      min_confidence: 0.7
      
      # 共识阈值（多模型一致性）
      consensus_threshold: 0.6
      
      # 最大验证迭代次数
      max_iterations: 3
      
      # 是否启用假阳性过滤
      enable_false_positive_filter: true
      
      # 假阳性过滤阈值
      false_positive_threshold: 0.8
    
    # 交叉验证配置
    cross_validation_config:
      # 验证策略：majority, weighted, consensus
      validation_strategy: "weighted"
      
      # 模型权重（与cross_validation_models对应）
      model_weights:
        - 0.4  # gpt-4
        - 0.3  # deepseek-chat
        - 0.2  # claude-3
        - 0.1  # qwen-max
      
      # 是否启用动态权重调整
      enable_dynamic_weighting: true
```

## 🗄️ 缓存配置

```yaml
# 层级缓存配置
hierarchical_cache:
  enabled: true
  
  # 缓存类型：memory, redis, file
  cache_type: "memory"
  
  # 缓存层配置
  cache_layers:
    - name: "haystack"
      enabled: true
      ttl: 3600  # 过期时间（秒）
      max_size: 1000  # 最大条目数
    
    - name: "txtai"
      enabled: true
      ttl: 7200
      max_size: 2000
    
    - name: "r2r"
      enabled: true
      ttl: 1800
      max_size: 500
    
    - name: "self_rag"
      enabled: true
      ttl: 3600
      max_size: 1000
  
  # Redis配置（当cache_type为redis时）
  redis_config:
    host: "localhost"
    port: 6379
    db: 0
    password: ""
    max_connections: 10
  
  # 文件缓存配置（当cache_type为file时）
  file_cache_config:
    cache_dir: "./cache"
    max_file_size: 10485760  # 10MB
    cleanup_interval: 3600   # 清理间隔（秒）
```

## 📊 监控配置

```yaml
# 层级监控配置
hierarchical_monitoring:
  enabled: true
  
  # 监控指标
  metrics:
    - "performance"      # 性能指标
    - "accuracy"         # 准确性指标
    - "resource_usage"   # 资源使用指标
    - "error_rate"       # 错误率指标
  
  # 导出格式：prometheus, json, csv
  export_format: "prometheus"
  
  # 监控配置
  monitoring_config:
    # 采样间隔（秒）
    sampling_interval: 60
    
    # 数据保留时间（秒）
    retention_period: 86400  # 24小时
    
    # 是否启用实时监控
    enable_realtime: true
    
    # 告警阈值
    alert_thresholds:
      error_rate: 0.05      # 错误率超过5%告警
      response_time: 30     # 响应时间超过30秒告警
      memory_usage: 0.8     # 内存使用率超过80%告警
  
  # Prometheus配置
  prometheus_config:
    port: 8000
    path: "/metrics"
    enable_auth: false
```

## 🔧 工具配置

```yaml
# 工具设置
tools:
  # 启用的工具列表
  enabled: 
    - "code_analyzer"
    - "security_scanner"
    - "dependency_analyzer"
    - "vulnerability_detector"
    - "compliance_checker"
  
  # 工具特定配置
  code_analyzer:
    # 分析深度：shallow, medium, deep
    analysis_depth: "medium"
    
    # 是否启用语法分析
    enable_syntax_analysis: true
    
    # 是否启用语义分析
    enable_semantic_analysis: true
  
  security_scanner:
    # 扫描规则集：basic, standard, comprehensive
    rule_set: "comprehensive"
    
    # 严重性级别：low, medium, high, critical
    min_severity: "medium"
    
    # 是否启用自定义规则
    enable_custom_rules: true
  
  dependency_analyzer:
    # 是否分析间接依赖
    analyze_transitive: true
    
    # 依赖深度限制
    max_depth: 5
    
    # 是否检查已知漏洞
    check_vulnerabilities: true
```

## 🌐 多智能体协作协议 (MCP)

```yaml
# 多智能体协作协议
mcp:
  enabled: true
  
  # 代理配置
  agents:
    - name: "orchestrator"
      description: "协调所有智能体和工作流程"
      type: "coordinator"
      priority: 1
      config:
        max_concurrent_tasks: 10
        timeout: 300
    
    - name: "code_parser"
      description: "分析代码结构并提取依赖关系"
      type: "analyzer"
      priority: 2
      config:
        supported_languages: ["python", "javascript", "java", "go"]
        max_file_size: 1048576  # 1MB
    
    - name: "security_analyst"
      description: "识别安全漏洞"
      type: "analyst"
      priority: 3
      config:
        vulnerability_databases: ["cve", "owasp", "cwe"]
        confidence_threshold: 0.7
    
    - name: "remediation"
      description: "提供代码修复建议和最佳实践"
      type: "generator"
      priority: 5
      config:
        suggestion_types: ["fix", "improvement", "best_practice"]
        max_suggestions: 10
  
  # 协作配置
  collaboration_config:
    # 通信协议：http, grpc, websocket
    protocol: "http"
    
    # 消息格式：json, protobuf
    message_format: "json"
    
    # 是否启用加密
    enable_encryption: false
    
    # 超时配置
    timeouts:
      connection: 30
      request: 120
      response: 300
```

## 🎨 UI设置

```yaml
# UI设置
ui:
  # 主题颜色：blue, green, red, purple
  theme: "blue"
  
  # 是否在终端中使用彩色输出
  use_colors: true
  
  # 详细程度：quiet, normal, verbose
  verbosity: "normal"
  
  # 报告配置
  report_config:
    # 是否包含详细信息
    include_details: true
    
    # 是否生成图表
    generate_charts: true
    
    # 图表类型：bar, pie, line, scatter
    chart_types: ["bar", "pie"]
    
    # 是否启用交互式报告
    enable_interactive: true
```

## 🗃️ 漏洞数据库配置

```yaml
# 漏洞数据库
vulnerability_db:
  # 数据源
  sources:
    - "OWASP Top 10"
    - "CWE Top 25"
    - "SANS Top 25"
    - "CVE Database"
  
  # 更新频率：daily, weekly, monthly
  update_frequency: "weekly"
  
  # 本地存储路径
  local_storage: "./data/vulnerability_db"
  
  # 数据库配置
  db_config:
    # 数据库类型：sqlite, postgresql, mysql
    type: "sqlite"
    
    # 连接配置
    connection:
      host: "localhost"
      port: 5432
      database: "auditluma"
      username: "auditluma"
      password: "password"
```

## 📤 输出配置

```yaml
# 输出配置
output:
  # 支持的格式
  formats: ["html", "json", "markdown", "pdf"]
  
  # 是否启用可视化
  visualization: true
  
  # 图形格式：d3, plotly, matplotlib
  graph_format: "d3"
  
  # 最大结果数量
  max_results: 100
  
  # 严重性级别
  severity_levels: ["critical", "high", "medium", "low", "info"]
  
  # 报告模板
  templates:
    html: "./templates/report.html"
    pdf: "./templates/report_pdf.html"
    json: "./templates/report.json"
```

## 🎯 默认模型配置

```yaml
# 默认模型配置
default_models:
  # 代码分析模型
  code_analysis: "gpt-4@openai"
  
  # 安全审计模型
  security_audit: "gpt-4@openai"
  
  # 修复建议模型
  remediation: "gpt-3.5-turbo@openai"
  
  # 摘要生成模型
  summarization: "gpt-3.5-turbo@openai"
  
  # 嵌入模型
  embedding: "text-embedding-ada-002@openai"
```

## 🔄 配置迁移

### 自动迁移

```bash
# 运行配置迁移工具
python main.py --config-migrate
```

### 手动迁移步骤

1. **备份现有配置**
   ```bash
   cp config/config.yaml config/config.yaml.backup
   ```

2. **更新配置结构**
   - 添加`hierarchical_rag_models`部分
   - 更新模型规范格式
   - 配置新的缓存和监控选项

3. **验证配置**
   ```bash
   python main.py --show-architecture-info
   ```

## 🔍 配置验证

### 验证命令

```bash
# 验证配置文件语法
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"

# 验证架构配置
python main.py --show-architecture-info

# 测试配置
python main.py --dry-run
```

### 常见配置错误

1. **YAML语法错误**
   - 检查缩进是否正确
   - 确保字符串正确引用
   - 验证列表和字典格式

2. **模型规范错误**
   - 确保使用正确的`model@provider`格式
   - 验证提供商名称拼写
   - 检查模型名称是否存在

3. **路径配置错误**
   - 确保目录路径存在
   - 检查文件权限
   - 验证相对路径正确性

## 📚 配置示例

### 小型项目配置

```yaml
# 适用于小型项目的轻量级配置
global:
  default_architecture: "traditional"
  
agent:
  default_provider: "deepseek"
  
project:
  max_batch_size: 5
  
self_rag:
  enabled: true
  chunk_size: 500
  retrieval_k: 3
```

### 大型项目配置

```yaml
# 适用于大型项目的完整配置
global:
  default_architecture: "hierarchical"
  
hierarchical_rag_models:
  enabled: true
  haystack:
    orchestrator_type: "ai"
    orchestrator_config:
      max_parallel_tasks: 20
  
hierarchical_cache:
  enabled: true
  cache_type: "redis"
  
hierarchical_monitoring:
  enabled: true
  export_format: "prometheus"
```

### 高安全性配置

```yaml
# 适用于高安全性要求的配置
hierarchical_rag_models:
  self_rag_validation:
    validation_config:
      min_confidence: 0.9
      consensus_threshold: 0.8
      enable_false_positive_filter: true
    
    cross_validation_models:
      - "gpt-4@openai"
      - "claude-3@anthropic"
      - "deepseek-chat@deepseek"

tools:
  security_scanner:
    rule_set: "comprehensive"
    min_severity: "low"
```

## 🛠️ 环境变量配置

AuditLuma支持通过环境变量覆盖配置文件设置：

```bash
# API密钥
export OPENAI_API_KEY="sk-xxxxxxxx"
export DEEPSEEK_API_KEY="sk-xxxxxxxx"
export QWEN_API_KEY="sk-xxxxxxxx"

# 基础URL
export OPENAI_BASE_URL="https://api.openai.com/v1"
export DEEPSEEK_BASE_URL="https://api.deepseek.com/v1"

# 架构设置
export AUDITLUMA_ARCHITECTURE="hierarchical"
export AUDITLUMA_ORCHESTRATOR="ai"

# 缓存设置
export AUDITLUMA_CACHE_ENABLED="true"
export AUDITLUMA_CACHE_TYPE="redis"
export REDIS_URL="redis://localhost:6379"

# 监控设置
export AUDITLUMA_MONITORING_ENABLED="true"
export PROMETHEUS_PORT="8000"
```

## 📋 配置检查清单

在部署前，请确保以下配置项已正确设置：

- [ ] API密钥已配置且有效
- [ ] 模型规范格式正确
- [ ] 目录路径存在且有权限
- [ ] 架构模式适合项目规模
- [ ] 缓存配置符合环境要求
- [ ] 监控配置满足运维需求
- [ ] 安全配置符合合规要求

## 🔗 相关文档

- [层级RAG架构指南](./hierarchical-rag-guide.md) - 详细的架构说明
- [故障排除指南](./troubleshooting.md) - 配置问题解决方案
- [最佳实践](./best-practices.md) - 配置优化建议
- [架构设计](./architecture-design.md) - 系统设计理念

---

*本配置参考持续更新中，如有疑问请参考相关文档或联系技术支持。*

### 性能监控

```yaml
monitoring:
  # 全局监控设置
  enabled: true
  log_level: "INFO"
  metrics_enabled: true
  performance_tracking: true
  
  # 监控间隔
  intervals:
    metrics_collection: 30  # 秒
    health_check: 60  # 秒
    performance_report: 300  # 秒
  
  # 性能阈值
  thresholds:
    max_response_time: 30  # 秒
    max_memory_usage: "2GB"
    min_accuracy: 0.85
    max_error_rate: 0.05
    min_cache_hit_rate: 0.7
  
  # 分层监控配置
  layers:
    haystack:
      enabled: true
      metrics:
        - "task_completion_time"
        - "model_call_count"
        - "error_rate"
        - "resource_usage"
      alerts:
        - "high_error_rate"
        - "slow_response"
    
    txtai:
      enabled: true
      metrics:
        - "retrieval_time"
        - "embedding_time"
        - "index_size"
        - "query_accuracy"
      alerts:
        - "index_corruption"
        - "low_accuracy"
    
    r2r:
      enabled: true
      metrics:
        - "context_expansion_time"
        - "enhancement_quality"
        - "cross_file_coverage"
      alerts:
        - "context_overflow"
        - "low_quality"
    
    self_rag:
      enabled: true
      metrics:
        - "validation_time"
        - "consensus_rate"
        - "false_positive_rate"
      alerts:
        - "low_consensus"
        - "high_false_positive"
  
  # 日志配置
  logging:
    # 日志级别配置
    levels:
      root: "INFO"
      haystack: "INFO"
      txtai: "DEBUG"
      r2r: "INFO"
      self_rag: "WARNING"
    
    # 日志输出配置
    handlers:
      - type: "console"
        level: "INFO"
        format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
      
      - type: "file"
        level: "DEBUG"
        filename: "./logs/hierarchical_rag.log"
        max_size: "100MB"
        backup_count: 5
        rotation: "time"
        interval: "midnight"
      
      - type: "json"
        level: "INFO"
        filename: "./logs/metrics.jsonl"
        fields:
          - "timestamp"
          - "level"
          - "layer"
          - "metric"
          - "value"
  
  # 指标导出
  exporters:
    # Prometheus导出
    prometheus:
      enabled: false
      port: 8000
      path: "/metrics"
    
    # InfluxDB导出
    influxdb:
      enabled: false
      url: "http://localhost:8086"
      database: "auditluma"
      username: ""
      password: ""
  
  # 告警配置
  alerting:
    enabled: true
    
    # 告警规则
    rules:
      - name: "high_error_rate"
        condition: "error_rate > 0.1"
        duration: "5m"
        severity: "critical"
        
      - name: "slow_response"
        condition: "avg_response_time > 60"
        duration: "2m"
        severity: "warning"
        
      - name: "low_cache_hit_rate"
        condition: "cache_hit_rate < 0.5"
        duration: "10m"
        severity: "info"
    
    # 通知配置
    notifications:
      - type: "email"
        enabled: false
        smtp_server: "smtp.example.com"
        smtp_port: 587
        username: "alerts@example.com"
        password: "password"
        recipients:
          - "admin@example.com"
      
      - type: "webhook"
        enabled: false
        url: "https://hooks.slack.com/services/xxx/yyy/zzz"
        method: "POST"
        headers:
          Content-Type: "application/json"
```

### 健康检查配置

```yaml
health_check:
  enabled: true
  interval: 60  # 秒
  timeout: 10  # 秒
  
  # 检查项目
  checks:
    - name: "database_connection"
      type: "database"
      config:
        connection_string: "sqlite:///./data/auditluma.db"
    
    - name: "model_availability"
      type: "model"
      config:
        models:
          - "gpt-4@openai"
          - "deepseek-chat@deepseek"
    
    - name: "cache_status"
      type: "cache"
      config:
        cache_layers:
          - "haystack"
          - "txtai"
          - "r2r"
          - "self_rag"
    
    - name: "disk_space"
      type: "system"
      config:
        min_free_space: "1GB"
        paths:
          - "./cache"
          - "./logs"
          - "./reports"
  
  # 健康状态定义
  status_definitions:
    healthy: "所有检查通过"
    degraded: "部分检查失败，但核心功能可用"
    unhealthy: "关键检查失败，系统不可用"
```

## 安全配置

### API密钥管理

```yaml
security:
  # API密钥加密
  api_key_encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_derivation: "PBKDF2"
    iterations: 100000
  
  # 密钥轮换
  key_rotation:
    enabled: false
    interval: "30d"  # 30天
    backup_count: 3
  
  # 访问控制
  access_control:
    enabled: false
    whitelist_ips:
      - "127.0.0.1"
      - "192.168.1.0/24"
    
    rate_limiting:
      enabled: true
      requests_per_minute: 100
      burst_size: 20
  
  # 审计日志
  audit_logging:
    enabled: true
    log_file: "./logs/audit.log"
    log_level: "INFO"
    include_request_body: false
    include_response_body: false
```

### 数据保护

```yaml
data_protection:
  # 敏感数据脱敏
  data_masking:
    enabled: true
    patterns:
      - type: "api_key"
        pattern: "sk-[a-zA-Z0-9]{48}"
        replacement: "sk-****"
      
      - type: "email"
        pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
        replacement: "***@***.***"
      
      - type: "ip_address"
        pattern: "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
        replacement: "***.***.***.***"
  
  # 数据加密
  encryption:
    enabled: false
    algorithm: "AES-256-CBC"
    key_file: "./keys/data_encryption.key"
  
  # 数据保留
  retention:
    logs: "30d"
    cache: "7d"
    reports: "90d"
    metrics: "365d"
```

## 环境变量

AuditLuma支持通过环境变量覆盖配置文件中的设置：

### 基础环境变量

```bash
# 全局设置
export AUDITLUMA_DEBUG=true
export AUDITLUMA_LOG_LEVEL=DEBUG
export AUDITLUMA_TARGET_DIR=./my-project
export AUDITLUMA_REPORT_DIR=./my-reports

# 架构设置
export AUDITLUMA_ARCHITECTURE=hierarchical
export AUDITLUMA_ORCHESTRATOR_TYPE=ai

# API密钥
export OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export QWEN_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# 缓存设置
export AUDITLUMA_CACHE_ENABLED=true
export AUDITLUMA_CACHE_DIR=./cache
export AUDITLUMA_CACHE_SIZE=2GB

# 监控设置
export AUDITLUMA_MONITORING_ENABLED=true
export AUDITLUMA_METRICS_ENABLED=true
```

### 高级环境变量

```bash
# 并发设置
export AUDITLUMA_MAX_WORKERS=4
export AUDITLUMA_BATCH_SIZE=10

# 超时设置
export AUDITLUMA_ANALYSIS_TIMEOUT=300
export AUDITLUMA_MODEL_TIMEOUT=60

# 性能设置
export AUDITLUMA_MAX_MEMORY=2GB
export AUDITLUMA_ENABLE_PERFORMANCE_COMPARISON=true

# 安全设置
export AUDITLUMA_ENCRYPT_API_KEYS=true
export AUDITLUMA_ENABLE_AUDIT_LOG=true
```

### 环境变量优先级

环境变量使用以下命名约定：
- 前缀：`AUDITLUMA_`
- 分隔符：`_`（下划线）
- 大小写：全大写

示例映射：
```yaml
# 配置文件
hierarchical_rag_models:
  haystack:
    orchestrator_type: "ai"

# 对应环境变量
AUDITLUMA_HIERARCHICAL_RAG_MODELS_HAYSTACK_ORCHESTRATOR_TYPE=ai
```

## 配置验证

### 配置验证工具

```bash
# 验证配置文件
python -m auditluma.config.validator --config ./config/config.yaml

# 验证特定配置段
python -m auditluma.config.validator --config ./config/config.yaml --section hierarchical_rag_models

# 生成配置模板
python -m auditluma.config.generator --template hierarchical_rag --output ./config/template.yaml
```

### 配置迁移

```bash
# 从传统配置迁移到层级RAG配置
python main.py --config-migrate

# 指定源配置文件
python -m auditluma.migration.config_migrator --source ./config/old_config.yaml --target ./config/new_config.yaml
```

### 配置测试

```python
# Python API测试配置
from auditluma.config import Config, validate_config

# 加载并验证配置
config = Config.load_from_file("./config/config.yaml")
validation_result = validate_config(config)

if validation_result.is_valid:
    print("配置验证通过")
else:
    print(f"配置验证失败: {validation_result.errors}")
```

---

更多详细信息请参考：
- [层级RAG架构指南](./hierarchical-rag-guide.md)
- [故障排除指南](./troubleshooting.md)
- [最佳实践](./best-practices.md)