# 最佳实践指南

## 概述

本指南提供AuditLuma层级RAG架构的最佳实践，帮助您充分发挥系统性能，获得最佳的代码审计效果。

## 架构选择最佳实践

### 1. 根据项目规模选择架构

#### 小型项目（<100文件）
```bash
# 推荐使用传统架构，快速高效
python main.py --architecture traditional -d ./small-project

# 或使用自动选择模式
python main.py --architecture auto -d ./small-project
```

**配置建议**：
```yaml
global:
  default_architecture: "traditional"
  
# 使用轻量级模型
default_models:
  code_analysis: "gpt-3.5-turbo@openai"
  security_audit: "gpt-3.5-turbo@openai"
```

#### 中型项目（100-1000文件）
```bash
# 推荐使用层级RAG架构
python main.py --architecture hierarchical --haystack-orchestrator ai -d ./medium-project
```

**配置建议**：
```yaml
hierarchical_rag_models:
  enabled: true
  haystack:
    orchestrator_type: "ai"
    orchestrator_config:
      max_parallel_tasks: 5
      enable_caching: true
      
cache:
  enabled: true
  type: "redis"
```

#### 大型项目（>1000文件）
```bash
# 使用完整层级RAG架构，启用所有优化
python main.py --architecture hierarchical --haystack-orchestrator ai \
  --enable-txtai --enable-r2r --enable-self-rag-validation \
  -d ./large-project
```

**配置建议**：
```yaml
hierarchical_rag_models:
  enabled: true
  haystack:
    orchestrator_type: "ai"
    orchestrator_config:
      max_parallel_tasks: 10
      enable_caching: true
      
  txtai:
    index_config:
      quantize: true
      normalize: true
      
  self_rag_validation:
    validation_config:
      min_consensus: 3
      confidence_threshold: 0.9
      
cache:
  enabled: true
  type: "redis"
  cache_strategy:
    max_size: "2GB"
```

### 2. 编排器选择策略

#### 开发环境
```yaml
# 推荐使用Haystack-AI编排器，获得最佳性能
hierarchical_rag_models:
  haystack:
    orchestrator_type: "ai"
    fallback_to_traditional: true  # 启用自动回退
```

#### 生产环境
```yaml
# 可选择传统编排器，确保稳定性
hierarchical_rag_models:
  haystack:
    orchestrator_type: "traditional"
    
# 或使用AI编排器但配置更保守的参数
hierarchical_rag_models:
  haystack:
    orchestrator_type: "ai"
    orchestrator_config:
      max_parallel_tasks: 3  # 较保守的并行度
      task_timeout: 180      # 较长的超时时间
      retry_attempts: 5      # 更多重试次数
```

## 模型配置最佳实践

### 1. 模型选择策略

#### 按任务类型选择模型
```yaml
hierarchical_rag_models:
  haystack:
    task_models:
      # 安全扫描使用最强模型，确保检测精度
      security_scan: "gpt-4@openai"
      
      # 语法检查使用快速模型，提高效率
      syntax_check: "gpt-3.5-turbo@openai"
      
      # 逻辑分析使用平衡模型
      logic_analysis: "deepseek-chat@deepseek"
      
      # 依赖分析使用专门优化的模型
      dependency_analysis: "qwen-turbo@qwen"
```

#### 按项目特点选择模型
```yaml
# 对于安全要求极高的项目
hierarchical_rag_models:
  self_rag_validation:
    validation_model: "gpt-4@openai"
    cross_validation_models:
      - "gpt-4@openai"
      - "claude-3@anthropic"
      - "deepseek-chat@deepseek"

# 对于成本敏感的项目
hierarchical_rag_models:
  haystack:
    default_model: "gpt-3.5-turbo@openai"
  txtai:
    retrieval_model: "gpt-3.5-turbo@openai"
```

### 2. 模型参数优化

#### 温度参数设置
```yaml
providers:
  openai:
    temperature: 0.1    # 代码分析需要确定性结果
    
  deepseek:
    temperature: 0.2    # 稍高的温度用于创造性任务
```

#### 令牌限制设置
```yaml
providers:
  openai:
    max_tokens: 4000    # 平衡输出质量和成本
    
  # 对于需要详细输出的任务
  gpt4_detailed:
    model: "gpt-4@openai"
    max_tokens: 8000
```

## 性能优化最佳实践

### 1. 并行处理优化

#### 合理设置并行度
```bash
# 根据系统资源设置并行度
# CPU核心数 * 2 通常是一个好的起点
python main.py --workers 8 -d ./your-project

# 对于I/O密集型任务，可以设置更高的并行度
python main.py --workers 16 -d ./your-project
```

#### 批处理大小优化
```yaml
project:
  max_batch_size: 20    # 根据内存大小调整
  
# 对于内存受限的环境
project:
  max_batch_size: 5
  max_file_size: 500000  # 限制单文件大小
```

### 2. 缓存策略优化

#### 多层缓存配置
```yaml
cache:
  enabled: true
  type: "redis"
  
  # 分层缓存配置
  layer_cache:
    haystack:
      enabled: true
      ttl: 1800         # 30分钟，适合任务编排结果
    txtai:
      enabled: true
      ttl: 3600         # 1小时，适合检索结果
    r2r:
      enabled: true
      ttl: 1800         # 30分钟，适合上下文增强
    self_rag:
      enabled: true
      ttl: 900          # 15分钟，适合验证结果
```

#### 缓存策略选择
```yaml
cache:
  cache_strategy:
    # 对于频繁访问的小文件项目
    eviction_policy: "lfu"  # 最少使用频率
    max_size: "512MB"
    
    # 对于大型项目
    eviction_policy: "lru"  # 最近最少使用
    max_size: "2GB"
```

### 3. 网络和API优化

#### API请求优化
```yaml
providers:
  openai:
    # 连接池配置
    connection_pool_size: 10
    max_connections_per_host: 5
    
    # 重试策略
    retry_config:
      max_retries: 3
      backoff_factor: 2
      retry_on_timeout: true
      
    # 请求限制
    rate_limit:
      requests_per_minute: 60
      tokens_per_minute: 50000
```

#### 多API密钥轮换
```yaml
providers:
  openai:
    api_keys:
      - "key1"
      - "key2"
      - "key3"
    load_balancing: "round_robin"  # 轮询
    # load_balancing: "random"     # 随机
    # load_balancing: "least_used" # 最少使用
```

## 质量保证最佳实践

### 1. 验证层配置

#### 多模型交叉验证
```yaml
hierarchical_rag_models:
  self_rag_validation:
    # 使用不同厂商的模型进行交叉验证
    cross_validation_models:
      - "gpt-4@openai"          # OpenAI
      - "deepseek-chat@deepseek" # DeepSeek
      - "claude-3@anthropic"     # Anthropic
      - "qwen-max@qwen"         # 阿里云
      
    validation_config:
      min_consensus: 3          # 至少3个模型同意
      confidence_threshold: 0.85 # 高置信度阈值
```

#### 假阳性过滤
```yaml
hierarchical_rag_models:
  self_rag_validation:
    validation_config:
      enable_false_positive_filter: true
      false_positive_threshold: 0.3
      
    # 质量评估配置
    quality_config:
      enable_quality_scoring: true
      quality_threshold: 0.8
      enable_uncertainty_estimation: true
```

### 2. 结果验证策略

#### 分级验证
```yaml
# 根据漏洞严重程度采用不同验证策略
hierarchical_rag_models:
  self_rag_validation:
    severity_based_validation:
      critical:
        min_consensus: 4
        confidence_threshold: 0.95
      high:
        min_consensus: 3
        confidence_threshold: 0.9
      medium:
        min_consensus: 2
        confidence_threshold: 0.8
      low:
        min_consensus: 2
        confidence_threshold: 0.7
```

## 监控和运维最佳实践

### 1. 监控配置

#### 关键指标监控
```yaml
monitoring:
  enabled: true
  
  # 性能指标
  performance:
    track_response_time: true
    track_accuracy: true
    track_resource_usage: true
    track_cache_hit_rate: true
    
  # 业务指标
  business_metrics:
    track_vulnerability_detection_rate: true
    track_false_positive_rate: true
    track_analysis_completion_rate: true
```

#### 告警配置
```yaml
monitoring:
  alerts:
    enabled: true
    
    # 性能告警
    thresholds:
      response_time: 30         # 响应时间超过30秒
      error_rate: 0.05          # 错误率超过5%
      memory_usage: 0.8         # 内存使用率超过80%
      cache_hit_rate: 0.3       # 缓存命中率低于30%
      
    # 业务告警
    business_thresholds:
      false_positive_rate: 0.2  # 假阳性率超过20%
      analysis_timeout_rate: 0.1 # 分析超时率超过10%
```

### 2. 日志管理

#### 结构化日志
```yaml
logging:
  format: "json"              # 使用JSON格式便于分析
  level: "INFO"               # 生产环境使用INFO级别
  
  # 日志轮转
  rotation:
    max_size: "100MB"
    backup_count: 10
    
  # 分组件日志
  components:
    haystack: "DEBUG"         # 开发阶段可以设置为DEBUG
    txtai: "INFO"
    r2r: "INFO"
    self_rag: "INFO"
```

### 3. 备份和恢复

#### 配置备份
```bash
#!/bin/bash
# backup-config.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="./backups/config_$DATE"

mkdir -p $BACKUP_DIR
cp -r config/ $BACKUP_DIR/
cp -r .cache/ $BACKUP_DIR/

echo "配置备份完成: $BACKUP_DIR"
```

#### 缓存备份
```bash
#!/bin/bash
# backup-cache.sh

# 备份Redis缓存
redis-cli --rdb ./backups/cache_$(date +%Y%m%d_%H%M%S).rdb

# 备份文件缓存
tar -czf ./backups/file_cache_$(date +%Y%m%d_%H%M%S).tar.gz .cache/
```

## 安全最佳实践

### 1. API密钥管理

#### 环境变量管理
```bash
# 使用环境变量存储敏感信息
export OPENAI_API_KEY="your-openai-key"
export DEEPSEEK_API_KEY="your-deepseek-key"

# 使用密钥管理工具
# 例如：AWS Secrets Manager, Azure Key Vault, HashiCorp Vault
```

#### 密钥轮换
```yaml
# 定期轮换API密钥
providers:
  openai:
    api_keys:
      - key: "current-key"
        expires_at: "2024-12-31"
      - key: "backup-key"
        expires_at: "2025-01-31"
    
    # 自动轮换配置
    auto_rotation:
      enabled: true
      rotation_days: 30
```

### 2. 网络安全

#### HTTPS和代理配置
```yaml
providers:
  openai:
    base_url: "https://api.openai.com/v1"  # 确保使用HTTPS
    verify_ssl: true                        # 验证SSL证书
    
    # 代理配置
    proxy:
      http: "http://proxy.company.com:8080"
      https: "https://proxy.company.com:8080"
```

#### 访问控制
```yaml
# IP白名单
security:
  ip_whitelist:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
    
# API访问限制
security:
  api_access:
    require_authentication: true
    rate_limiting:
      requests_per_hour: 1000
      requests_per_day: 10000
```

## 成本优化最佳实践

### 1. 模型成本优化

#### 智能模型选择
```yaml
# 根据任务复杂度选择合适的模型
hierarchical_rag_models:
  haystack:
    task_models:
      # 简单任务使用便宜的模型
      syntax_check: "gpt-3.5-turbo@openai"
      
      # 复杂任务使用强大的模型
      security_scan: "gpt-4@openai"
      
      # 中等任务使用平衡的模型
      logic_analysis: "deepseek-chat@deepseek"  # 通常更便宜
```

#### 令牌使用优化
```yaml
providers:
  openai:
    # 限制输出长度
    max_tokens: 2000
    
    # 使用更精确的提示词减少不必要的输出
    optimize_prompts: true
    
    # 启用流式输出，可以提前终止
    stream: true
```

### 2. 缓存成本优化

#### 智能缓存策略
```yaml
cache:
  # 根据成本效益设置TTL
  layer_cache:
    haystack:
      ttl: 3600         # 编排结果缓存1小时
      cost_weight: 0.8  # 高成本权重，优先缓存
    txtai:
      ttl: 7200         # 检索结果缓存2小时
      cost_weight: 0.6
    r2r:
      ttl: 1800         # 上下文增强缓存30分钟
      cost_weight: 0.7
```

## 团队协作最佳实践

### 1. 配置管理

#### 环境分离
```
config/
├── config.yaml              # 基础配置
├── environments/
│   ├── development.yaml     # 开发环境配置
│   ├── staging.yaml         # 测试环境配置
│   └── production.yaml      # 生产环境配置
```

#### 版本控制
```bash
# 配置文件版本控制
git add config/config.yaml
git commit -m "feat: 添加层级RAG配置"

# 敏感信息不要提交到版本控制
echo "config/secrets.yaml" >> .gitignore
```

### 2. 文档和培训

#### 团队文档
```markdown
# 团队使用指南

## 开发环境设置
1. 克隆项目
2. 复制配置模板
3. 设置环境变量
4. 运行测试

## 常用命令
- 开发环境分析：`python main.py --architecture auto -d ./project`
- 生产环境分析：`python main.py --architecture hierarchical -d ./project`
- 性能测试：`python main.py --enable-performance-comparison -d ./project`
```

#### 最佳实践检查清单
```markdown
## 部署前检查清单

### 配置检查
- [ ] 配置文件语法正确
- [ ] API密钥已设置
- [ ] 缓存配置正确
- [ ] 监控已启用

### 性能检查
- [ ] 并行度设置合理
- [ ] 缓存命中率 > 50%
- [ ] 平均响应时间 < 30秒
- [ ] 内存使用率 < 80%

### 安全检查
- [ ] 使用HTTPS连接
- [ ] API密钥安全存储
- [ ] 访问控制配置
- [ ] 日志不包含敏感信息
```

## 总结

遵循这些最佳实践可以帮助您：

1. **选择合适的架构**：根据项目规模和需求选择最优配置
2. **优化性能**：通过合理的并行度、缓存和网络配置提升效率
3. **保证质量**：使用多层验证确保结果准确性
4. **控制成本**：通过智能模型选择和缓存策略优化成本
5. **确保安全**：保护API密钥和敏感数据
6. **便于维护**：建立监控、日志和备份机制

建议从基础配置开始，逐步应用这些最佳实践，根据实际使用情况持续优化配置。