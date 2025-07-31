# 故障排除指南

## 概述

本指南提供AuditLuma常见问题的诊断和解决方案，特别针对层级RAG架构的故障排除。

## 快速诊断

### 系统健康检查

```bash
# 检查系统整体状态
python main.py --show-architecture-info

# 运行诊断工具
python -m auditluma.diagnostics run-all

# 检查配置文件
python -m auditluma.config validate
```

### 日志分析

```bash
# 启用详细日志
python main.py --verbose -d ./your-project

# 查看特定组件日志
python main.py --verbose --log-level DEBUG --log-component haystack
```

## 常见问题分类

### 1. 启动和配置问题

#### 问题：配置文件加载失败

**症状**：
```
ERROR: 无法加载配置文件 config/config.yaml
FileNotFoundError: [Errno 2] No such file or directory: 'config/config.yaml'
```

**解决方案**：
```bash
# 检查配置文件是否存在
ls -la config/

# 从示例配置创建配置文件
cp config/config.yaml.example config/config.yaml

# 验证配置文件语法
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"
```

#### 问题：YAML语法错误

**症状**：
```
ERROR: 配置文件语法错误
yaml.scanner.ScannerError: mapping values are not allowed here
```

**解决方案**：
```bash
# 使用YAML验证工具
python -c "
import yaml
try:
    with open('config/config.yaml', 'r') as f:
        yaml.safe_load(f)
    print('配置文件语法正确')
except yaml.YAMLError as e:
    print(f'YAML语法错误: {e}')
"

# 常见语法问题：
# 1. 缩进不一致（使用空格，不要使用Tab）
# 2. 冒号后缺少空格
# 3. 字符串包含特殊字符未加引号
```

#### 问题：环境变量未设置

**症状**：
```
ERROR: API密钥未配置
KeyError: 'OPENAI_API_KEY'
```

**解决方案**：
```bash
# 设置环境变量
export OPENAI_API_KEY="your-api-key"
export DEEPSEEK_API_KEY="your-deepseek-api-key"

# 或在配置文件中直接配置
# config/config.yaml:
providers:
  openai:
    api_key: "your-api-key"
```

### 2. 层级RAG架构问题

#### 问题：Haystack-AI编排器启动失败

**症状**：
```
ERROR: Haystack-AI编排器初始化失败
ConnectionError: 无法连接到模型API
```

**诊断步骤**：
```bash
# 1. 检查网络连接
curl -I https://api.openai.com/v1/models

# 2. 验证API密钥
python -c "
import openai
openai.api_key = 'your-api-key'
try:
    models = openai.Model.list()
    print('API连接正常')
except Exception as e:
    print(f'API连接失败: {e}')
"

# 3. 检查模型配置
python -m auditluma.models test --model "gpt-4@openai"
```

**解决方案**：
```yaml
# 配置自动回退
hierarchical_rag_models:
  haystack:
    orchestrator_type: "ai"
    fallback_to_traditional: true  # 启用自动回退
    
    # 或直接使用传统编排器
    orchestrator_type: "traditional"
```

#### 问题：txtai检索层性能差

**症状**：
```
WARNING: txtai检索响应时间过长 (>30s)
WARNING: 检索结果相关性低 (<0.5)
```

**诊断步骤**：
```bash
# 检查嵌入模型状态
python -c "
from auditluma.rag.txtai_retriever import TxtaiRetriever
retriever = TxtaiRetriever()
print(f'索引大小: {retriever.index_size()}')
print(f'嵌入维度: {retriever.embedding_dimensions}')
"

# 检查索引质量
python -m auditluma.rag.txtai_retriever diagnose
```

**解决方案**：
```yaml
# 优化txtai配置
hierarchical_rag_models:
  txtai:
    index_config:
      dimensions: 1536
      metric: "cosine"
      quantize: true        # 启用量化提高性能
      normalize: true       # 启用归一化提高精度
      
    retrieval_config:
      limit: 5              # 减少检索数量
      threshold: 0.8        # 提高相似度阈值
      rerank: true          # 启用重新排序
```

#### 问题：R2R上下文增强超时

**症状**：
```
ERROR: R2R上下文增强超时
TimeoutError: 上下文扩展操作超过最大时间限制
```

**诊断步骤**：
```bash
# 检查上下文扩展深度
python -c "
from auditluma.config import Config
r2r_config = Config.hierarchical_rag_models.r2r.context_config
print(f'扩展深度: {r2r_config.expansion_depth}')
print(f'最大上下文长度: {r2r_config.max_context_length}')
"
```

**解决方案**：
```yaml
# 优化R2R配置
hierarchical_rag_models:
  r2r:
    context_config:
      max_context_length: 2000  # 减少上下文长度
      expansion_depth: 2        # 减少扩展深度
      relevance_threshold: 0.7  # 提高相关性阈值
      
    # 增加超时时间
    timeout: 60  # 秒
```

#### 问题：Self-RAG验证层假阳性率高

**症状**：
```
WARNING: Self-RAG验证层假阳性率过高 (>20%)
WARNING: 交叉验证共识度低 (<50%)
```

**诊断步骤**：
```bash
# 分析验证结果
python -c "
from auditluma.rag.self_rag_validator import SelfRAGValidator
validator = SelfRAGValidator()
stats = validator.get_validation_stats()
print(f'假阳性率: {stats.false_positive_rate:.2%}')
print(f'共识度: {stats.consensus_rate:.2%}')
"
```

**解决方案**：
```yaml
# 优化验证配置
hierarchical_rag_models:
  self_rag_validation:
    validation_config:
      min_consensus: 3              # 提高最小共识数
      confidence_threshold: 0.9     # 提高置信度阈值
      enable_false_positive_filter: true
      
    # 使用更多样化的模型
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
      - "claude-3@anthropic"
      - "qwen-max@qwen"
```

### 3. 性能问题

#### 问题：分析速度慢

**症状**：
```
INFO: 分析进度缓慢，预计完成时间: 2小时
WARNING: 平均文件处理时间: 45秒
```

**诊断步骤**：
```bash
# 检查系统资源使用
python -c "
import psutil
print(f'CPU使用率: {psutil.cpu_percent()}%')
print(f'内存使用率: {psutil.virtual_memory().percent}%')
print(f'磁盘IO: {psutil.disk_io_counters()}')
"

# 检查并行度设置
python main.py --show-architecture-info | grep -i "工作线程"
```

**解决方案**：
```bash
# 增加并行度
python main.py --workers 8 -d ./your-project

# 启用缓存
python main.py --architecture hierarchical --enable-caching -d ./your-project

# 使用更快的模型
# 在配置文件中设置轻量级模型用于语法检查等简单任务
```

```yaml
# 性能优化配置
hierarchical_rag_models:
  haystack:
    orchestrator_config:
      max_parallel_tasks: 8     # 增加并行任务数
      enable_caching: true      # 启用缓存
      
    task_models:
      syntax_check: "gpt-3.5-turbo@openai"  # 使用更快的模型
      
cache:
  enabled: true
  type: "redis"
  cache_strategy:
    max_size: "2GB"
```

#### 问题：内存使用过高

**症状**：
```
WARNING: 内存使用率过高 (>90%)
ERROR: 内存不足，无法加载更多文件
```

**诊断步骤**：
```bash
# 监控内存使用
python -c "
import psutil
import os
process = psutil.Process(os.getpid())
print(f'进程内存使用: {process.memory_info().rss / 1024 / 1024:.2f} MB')
print(f'系统可用内存: {psutil.virtual_memory().available / 1024 / 1024:.2f} MB')
"
```

**解决方案**：
```yaml
# 内存优化配置
project:
  max_batch_size: 5         # 减少批处理大小
  max_file_size: 500000     # 限制单文件大小

hierarchical_rag_models:
  txtai:
    index_config:
      quantize: true        # 启用量化减少内存使用
      
cache:
  cache_strategy:
    max_size: "512MB"       # 限制缓存大小
    eviction_policy: "lru"  # 使用LRU淘汰策略
```

### 4. 网络和API问题

#### 问题：API请求频率限制

**症状**：
```
ERROR: API请求频率超限
RateLimitError: Rate limit exceeded. Please try again later.
```

**解决方案**：
```yaml
# 配置请求限制
providers:
  openai:
    rate_limit:
      requests_per_minute: 50
      tokens_per_minute: 40000
    retry_config:
      max_retries: 3
      backoff_factor: 2
      
# 使用多个API密钥轮换
providers:
  openai:
    api_keys:
      - "key1"
      - "key2"
      - "key3"
    load_balancing: "round_robin"
```

#### 问题：网络连接不稳定

**症状**：
```
ERROR: 网络连接超时
ConnectionTimeout: Request timed out after 60 seconds
```

**解决方案**：
```yaml
# 网络优化配置
providers:
  openai:
    timeout: 120            # 增加超时时间
    max_retries: 5          # 增加重试次数
    retry_delay: 2          # 重试延迟
    
# 使用代理
providers:
  openai:
    proxy:
      http: "http://proxy.example.com:8080"
      https: "https://proxy.example.com:8080"
```

### 5. 缓存问题

#### 问题：Redis连接失败

**症状**：
```
ERROR: 无法连接到Redis服务器
ConnectionError: Error 111 connecting to localhost:6379. Connection refused.
```

**诊断步骤**：
```bash
# 检查Redis服务状态
redis-cli ping

# 检查Redis配置
redis-cli info server
```

**解决方案**：
```bash
# 启动Redis服务
sudo systemctl start redis

# 或使用Docker启动Redis
docker run -d -p 6379:6379 redis:latest

# 或切换到内存缓存
```

```yaml
# 回退到内存缓存
cache:
  type: "memory"
  cache_strategy:
    max_size: "256MB"
```

#### 问题：缓存命中率低

**症状**：
```
WARNING: 缓存命中率过低 (<30%)
INFO: 大量缓存未命中，性能受影响
```

**诊断步骤**：
```bash
# 检查缓存统计
python -c "
from auditluma.cache.hierarchical_cache import HierarchicalCache
cache = HierarchicalCache()
stats = cache.get_stats()
print(f'命中率: {stats.hit_rate:.2%}')
print(f'缓存大小: {stats.size}')
"
```

**解决方案**：
```yaml
# 优化缓存配置
cache:
  cache_strategy:
    default_ttl: 7200       # 增加过期时间
    max_size: "1GB"         # 增加缓存大小
    
  layer_cache:
    haystack:
      ttl: 3600             # 调整各层缓存时间
    txtai:
      ttl: 7200
```

## 调试工具

### 1. 内置诊断工具

```bash
# 运行完整诊断
python -m auditluma.diagnostics run-all

# 诊断特定组件
python -m auditluma.diagnostics haystack
python -m auditluma.diagnostics txtai
python -m auditluma.diagnostics r2r
python -m auditluma.diagnostics self-rag

# 网络诊断
python -m auditluma.diagnostics network

# 性能诊断
python -m auditluma.diagnostics performance
```

### 2. 日志分析

```bash
# 启用详细日志
export AUDITLUMA_LOG_LEVEL=DEBUG
python main.py --verbose -d ./your-project

# 过滤特定组件日志
python main.py --verbose 2>&1 | grep "haystack"

# 保存日志到文件
python main.py --verbose -d ./your-project > analysis.log 2>&1
```

### 3. 性能分析

```bash
# 启用性能分析
python -m cProfile -o profile.stats main.py -d ./your-project

# 分析性能数据
python -c "
import pstats
p = pstats.Stats('profile.stats')
p.sort_stats('cumulative').print_stats(20)
"

# 内存分析
pip install memory-profiler
python -m memory_profiler main.py -d ./your-project
```

## 监控和告警

### 1. 设置监控

```yaml
# 启用监控
monitoring:
  enabled: true
  metrics:
    enabled: true
    export_format: "prometheus"
    
  alerts:
    enabled: true
    thresholds:
      response_time: 30
      error_rate: 0.05
      memory_usage: 0.8
```

### 2. 健康检查端点

```bash
# 检查系统健康状态
curl http://localhost:8080/health

# 检查各组件状态
curl http://localhost:8080/health/haystack
curl http://localhost:8080/health/txtai
curl http://localhost:8080/health/r2r
curl http://localhost:8080/health/self-rag
```

## 常用修复脚本

### 1. 配置修复脚本

```bash
#!/bin/bash
# fix-config.sh

echo "修复AuditLuma配置..."

# 备份原配置
cp config/config.yaml config/config.yaml.backup

# 验证配置语法
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))" || {
    echo "配置文件语法错误，恢复备份"
    cp config/config.yaml.backup config/config.yaml
    exit 1
}

# 迁移配置到最新格式
python main.py --config-migrate

echo "配置修复完成"
```

### 2. 缓存清理脚本

```bash
#!/bin/bash
# clear-cache.sh

echo "清理AuditLuma缓存..."

# 清理Redis缓存
redis-cli FLUSHDB

# 清理文件缓存
rm -rf .cache/auditluma/*

# 重建索引
python -m auditluma.rag.txtai_retriever rebuild-index

echo "缓存清理完成"
```

### 3. 环境检查脚本

```bash
#!/bin/bash
# check-environment.sh

echo "检查AuditLuma运行环境..."

# 检查Python版本
python --version | grep -E "3\.[8-9]|3\.1[0-9]" || {
    echo "错误: 需要Python 3.8或更高版本"
    exit 1
}

# 检查依赖包
pip check || {
    echo "警告: 依赖包存在冲突"
}

# 检查配置文件
[ -f config/config.yaml ] || {
    echo "错误: 配置文件不存在"
    exit 1
}

# 检查API密钥
[ -n "$OPENAI_API_KEY" ] || {
    echo "警告: OPENAI_API_KEY未设置"
}

echo "环境检查完成"
```

## 获取帮助

### 1. 社区支持

- GitHub Issues: 报告bug和功能请求
- 讨论区: 技术讨论和经验分享
- 文档: 查看最新文档和教程

### 2. 专业支持

- 企业支持: 联系我们获取专业技术支持
- 培训服务: 提供定制化培训和咨询服务
- 定制开发: 根据需求定制功能和集成

### 3. 自助诊断

```bash
# 生成诊断报告
python -m auditluma.diagnostics generate-report

# 收集系统信息
python -m auditluma.diagnostics collect-info

# 导出配置和日志
python -m auditluma.diagnostics export-debug-info
```

## 总结

故障排除的关键是：

1. **系统化诊断**：使用内置工具进行全面检查
2. **日志分析**：启用详细日志，分析错误模式
3. **配置验证**：确保配置文件正确和完整
4. **性能监控**：持续监控系统性能指标
5. **预防性维护**：定期清理缓存，更新配置

遇到问题时，建议按照以下步骤：

1. 查看错误日志，确定问题类型
2. 运行相应的诊断工具
3. 根据诊断结果应用解决方案
4. 验证修复效果
5. 更新监控和告警配置，预防类似问题