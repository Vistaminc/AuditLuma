# 层级RAG架构指南

## 概述

AuditLuma 2.0引入了创新的**层级RAG架构**，这是一个四层智能架构系统，显著提升了代码安全分析的精度和效率。本指南将详细介绍层级RAG架构的设计理念、组件功能和使用方法。

## 🏗️ 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                    层级RAG架构                                │
├─────────────────────────────────────────────────────────────┤
│ 第一层：Haystack编排层                                        │
│ ├─ Haystack-AI编排器（推荐）- 智能任务分解和结果整合           │
│ └─ 传统编排器 - 规则驱动的稳定方案                            │
├─────────────────────────────────────────────────────────────┤
│ 第二层：txtai知识检索层                                       │
│ ├─ 语义检索和相似性匹配                                       │
│ └─ 上下文理解和知识图谱构建                                   │
├─────────────────────────────────────────────────────────────┤
│ 第三层：R2R上下文增强层                                       │
│ ├─ 动态上下文扩展                                            │
│ └─ 关联分析和依赖追踪                                         │
├─────────────────────────────────────────────────────────────┤
│ 第四层：Self-RAG验证层                                        │
│ ├─ 多模型交叉验证                                            │
│ └─ 假阳性过滤和置信度评估                                     │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 第一层：Haystack编排层

### Haystack-AI编排器（推荐）

Haystack-AI编排器是基于人工智能的智能任务编排系统，能够：

- **智能任务分解**：自动将复杂的代码分析任务分解为可并行执行的子任务
- **动态资源分配**：根据任务复杂度和系统负载智能分配计算资源
- **结果智能整合**：使用AI技术整合多个分析结果，提供更准确的综合评估
- **自适应优化**：根据历史分析结果持续优化任务分解策略

#### 配置示例

```yaml
hierarchical_rag_models:
  haystack:
    orchestrator_type: "ai"  # 使用Haystack-AI编排器
    default_model: "gpt-4@openai"
    task_models:
      security_scan: "gpt-4@openai"
      syntax_check: "deepseek-chat@deepseek"
      logic_analysis: "qwen-turbo@qwen"
      dependency_analysis: "gpt-3.5-turbo@openai"
```

#### 使用方法

```bash
# 使用Haystack-AI编排器（默认）
python main.py --architecture hierarchical --haystack-orchestrator ai

# 查看编排器状态
python main.py --show-architecture-info
```

### 传统编排器

传统编排器提供规则驱动的稳定编排方案，适用于：

- **稳定性要求高**的生产环境
- **网络受限**的环境（减少AI API调用）
- **成本敏感**的场景

#### 配置示例

```yaml
hierarchical_rag_models:
  haystack:
    orchestrator_type: "traditional"  # 使用传统编排器
```

#### 使用方法

```bash
# 使用传统编排器
python main.py --architecture hierarchical --haystack-orchestrator traditional
```

### 自动回退机制

系统提供智能回退机制，当Haystack-AI编排器不可用时自动切换到传统编排器：

```python
# 自动回退逻辑示例
try:
    # 尝试使用Haystack-AI编排器
    orchestrator = HaystackAIOrchestrator(config)
    logger.info("✅ 使用Haystack-AI编排器")
except Exception as e:
    # 回退到传统编排器
    orchestrator = HaystackOrchestrator(config)
    logger.warning(f"⚠️ Haystack-AI编排器不可用，回退到传统编排器: {e}")
```

## 🔍 第二层：txtai知识检索层

txtai知识检索层提供强大的语义检索和知识理解能力：

### 核心功能

1. **语义检索**
   - 基于向量相似性的代码片段检索
   - 支持自然语言查询代码功能
   - 智能代码模式匹配

2. **知识图谱构建**
   - 自动构建代码知识图谱
   - 函数调用关系映射
   - 数据流依赖分析

3. **上下文理解**
   - 深度理解代码语义
   - 跨文件上下文关联
   - 业务逻辑推理

### 配置示例

```yaml
hierarchical_rag_models:
  txtai:
    retrieval_model: "gpt-3.5-turbo@openai"
    embedding_model: "text-embedding-ada-002@openai"
    index_config:
      dimensions: 1536
      metric: "cosine"
      quantize: true
```

### 使用方法

```bash
# 启用txtai知识检索层
python main.py --architecture hierarchical --enable-txtai
```

## 🎯 第三层：R2R上下文增强层

R2R（Retrieval-to-Retrieval）上下文增强层提供动态上下文扩展和关联分析：

### 核心功能

1. **动态上下文扩展**
   - 根据分析需求动态扩展上下文范围
   - 智能识别相关代码片段
   - 自适应上下文窗口调整

2. **关联分析**
   - 跨文件依赖关系分析
   - 数据流追踪和污点分析
   - 业务逻辑关联推理

3. **依赖追踪**
   - 函数调用链追踪
   - 变量生命周期分析
   - 模块间依赖映射

### 配置示例

```yaml
hierarchical_rag_models:
  r2r:
    context_model: "gpt-3.5-turbo@openai"
    enhancement_model: "gpt-4@openai"
    context_config:
      max_context_length: 8000
      expansion_strategy: "adaptive"
      relevance_threshold: 0.7
```

### 使用方法

```bash
# 启用R2R上下文增强层
python main.py --architecture hierarchical --enable-r2r
```

## 🛡️ 第四层：Self-RAG验证层

Self-RAG验证层是层级架构的最后一层，提供多模型交叉验证和假阳性过滤：

### 核心功能

1. **多模型交叉验证**
   - 使用多个不同的AI模型进行交叉验证
   - 提高漏洞检测的准确性
   - 减少单一模型的偏见

2. **假阳性过滤**
   - 智能识别和过滤假阳性结果
   - 基于置信度的结果筛选
   - 历史数据学习优化

3. **置信度评估**
   - 为每个检测结果提供置信度评分
   - 支持基于置信度的结果排序
   - 提供详细的验证报告

### 配置示例

```yaml
hierarchical_rag_models:
  self_rag_validation:
    validation_model: "gpt-4@openai"
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
      - "claude-3@anthropic"
    validation_config:
      min_confidence: 0.7
      consensus_threshold: 0.6
      max_iterations: 3
```

### 使用方法

```bash
# 启用Self-RAG验证层
python main.py --architecture hierarchical --enable-self-rag-validation
```

## 🔧 完整配置示例

以下是一个完整的层级RAG架构配置示例：

```yaml
# 层级RAG架构模型配置
hierarchical_rag_models:
  # 启用层级RAG架构
  enabled: true
  
  # Haystack编排层配置
  haystack:
    orchestrator_type: "ai"  # 使用Haystack-AI编排器
    default_model: "gpt-4@openai"
    task_models:
      security_scan: "gpt-4@openai"
      syntax_check: "deepseek-chat@deepseek"
      logic_analysis: "qwen-turbo@qwen"
      dependency_analysis: "gpt-3.5-turbo@openai"
    orchestrator_config:
      max_parallel_tasks: 10
      timeout: 300
      retry_attempts: 3
  
  # txtai知识检索层配置
  txtai:
    retrieval_model: "gpt-3.5-turbo@openai"
    embedding_model: "text-embedding-ada-002@openai"
    index_config:
      dimensions: 1536
      metric: "cosine"
      quantize: true
      batch_size: 100
  
  # R2R上下文增强层配置
  r2r:
    context_model: "gpt-3.5-turbo@openai"
    enhancement_model: "gpt-4@openai"
    context_config:
      max_context_length: 8000
      expansion_strategy: "adaptive"
      relevance_threshold: 0.7
      max_expansions: 5
  
  # Self-RAG验证层配置
  self_rag_validation:
    validation_model: "gpt-4@openai"
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
      - "claude-3@anthropic"
    validation_config:
      min_confidence: 0.7
      consensus_threshold: 0.6
      max_iterations: 3
      enable_false_positive_filter: true

# 缓存配置
hierarchical_cache:
  enabled: true
  cache_layers:
    - "haystack"
    - "txtai"
    - "r2r"
    - "self_rag"
  ttl: 3600  # 缓存过期时间（秒）
  max_size: 1000  # 最大缓存条目数

# 监控配置
hierarchical_monitoring:
  enabled: true
  metrics:
    - "performance"
    - "accuracy"
    - "resource_usage"
  export_format: "prometheus"
```

## 🚀 使用最佳实践

### 1. 架构选择建议

- **小项目（<100文件）**：使用传统架构或自动模式
- **中型项目（100-1000文件）**：推荐使用层级架构
- **大型项目（>1000文件）**：强烈推荐使用层级架构

### 2. 编排器选择建议

- **生产环境**：推荐使用Haystack-AI编排器，配置自动回退
- **开发环境**：可以使用任一编排器进行测试
- **资源受限环境**：使用传统编排器

### 3. 模型配置建议

- **安全扫描**：使用最强的模型（如GPT-4）
- **语法检查**：可以使用较轻量的模型
- **交叉验证**：使用多样化的模型组合

### 4. 性能优化建议

- 启用层级缓存系统
- 合理配置并行任务数量
- 根据项目规模调整上下文长度

## 🔍 监控和调试

### 启用详细日志

```bash
python main.py --architecture hierarchical --verbose
```

### 查看架构信息

```bash
python main.py --show-architecture-info
```

### 性能对比模式

```bash
python main.py --architecture hierarchical --enable-performance-comparison
```

## 🛠️ 故障排除

### 常见问题

1. **Haystack-AI编排器初始化失败**
   - 检查API密钥配置
   - 验证网络连接
   - 查看自动回退日志

2. **txtai检索性能差**
   - 检查嵌入模型配置
   - 调整批处理大小
   - 考虑使用量化索引

3. **Self-RAG验证超时**
   - 增加超时时间配置
   - 减少交叉验证模型数量
   - 调整置信度阈值

### 调试命令

```bash
# 试运行模式（不执行实际分析）
python main.py --architecture hierarchical --dry-run

# 禁用特定层进行调试
python main.py --architecture hierarchical --disable-caching --disable-monitoring
```

## 📈 性能指标

层级RAG架构相比传统架构的性能提升：

- **准确率提升**：30-50%
- **假阳性减少**：40-60%
- **分析速度**：提升20-30%（启用缓存）
- **资源利用率**：提升25-40%

## 🔄 迁移指南

从传统架构迁移到层级RAG架构：

```bash
# 1. 备份现有配置
cp config/config.yaml config/config.yaml.backup

# 2. 运行配置迁移
python main.py --config-migrate

# 3. 验证新配置
python main.py --show-architecture-info

# 4. 测试运行
python main.py --architecture hierarchical --dry-run
```

## 📚 相关文档

- [配置参考](./configuration-reference.md) - 完整的配置选项说明
- [故障排除指南](./troubleshooting.md) - 常见问题和解决方案
- [最佳实践](./best-practices.md) - 使用建议和优化技巧
- [架构设计](./architecture-design.md) - 系统架构和设计理念

---

*本指南持续更新中，如有问题请参考故障排除指南或联系技术支持。*
### Python API使用

```python
from auditluma.models.hierarchical_rag import HierarchicalRAGModel
from auditluma.config import Config

# 初始化层级RAG模型
model = HierarchicalRAGModel(
    orchestrator_type="ai",
    enable_txtai=True,
    enable_r2r=True,
    enable_self_rag_validation=True
)

# 分析代码
results = await model.analyze_code(
    code_path="./your-project",
    analysis_type="security_scan"
)

# 获取分析结果
vulnerabilities = results.get_vulnerabilities()
confidence_scores = results.get_confidence_scores()
```

## 性能优化

### 缓存优化

```yaml
# 启用智能缓存
hierarchical_cache:
  enabled: true
  
  # 缓存策略
  strategy: "lru"  # lru, lfu, ttl
  
  # 分层缓存配置
  layers:
    haystack:
      enabled: true
      ttl: 3600
      max_entries: 1000
    txtai:
      enabled: true
      ttl: 7200
      max_entries: 5000
    r2r:
      enabled: true
      ttl: 1800
      max_entries: 2000
    self_rag:
      enabled: true
      ttl: 900
      max_entries: 500
```

### 并发优化

```yaml
# 并发配置
concurrency:
  # 每层的并发配置
  haystack:
    max_workers: 4
    batch_size: 10
  txtai:
    max_workers: 8
    batch_size: 20
  r2r:
    max_workers: 6
    batch_size: 15
  self_rag:
    max_workers: 2
    batch_size: 5
```

### 模型优化

```yaml
# 模型选择优化
hierarchical_rag_models:
  haystack:
    # 根据任务复杂度选择模型
    task_models:
      simple_syntax: "gpt-3.5-turbo@openai"  # 简单任务用轻量模型
      complex_security: "gpt-4@openai"       # 复杂任务用强力模型
      
  # 模型负载均衡
  load_balancing:
    enabled: true
    strategy: "round_robin"  # round_robin, least_loaded, random
```

## 监控和调试

### 性能监控

```bash
# 启用详细监控
python main.py --architecture hierarchical \
  --verbose \
  --enable-monitoring \
  -d ./your-project
```

监控指标包括：
- **响应时间** - 每层的处理时间
- **内存使用** - 各组件的内存占用
- **缓存命中率** - 缓存效率统计
- **模型调用次数** - API调用统计
- **错误率** - 各层的错误统计

### 调试模式

```bash
# 调试模式
python main.py --architecture hierarchical \
  --verbose \
  --disable-caching \
  --dry-run \
  -d ./your-project
```

调试功能：
- **详细日志** - 每个步骤的详细信息
- **禁用缓存** - 确保获取最新结果
- **试运行模式** - 不执行实际分析，仅验证配置
- **性能分析** - 详细的性能统计

### 日志配置

```yaml
# 日志配置
logging:
  level: "DEBUG"  # DEBUG, INFO, WARNING, ERROR
  
  # 分层日志配置
  layers:
    haystack: "INFO"
    txtai: "DEBUG"
    r2r: "INFO"
    self_rag: "WARNING"
  
  # 输出配置
  handlers:
    - type: "console"
      level: "INFO"
    - type: "file"
      level: "DEBUG"
      filename: "./logs/hierarchical_rag.log"
```

## 故障排除

### 常见问题

1. **编排器初始化失败**
   ```bash
   # 检查配置
   python main.py --show-architecture-info
   
   # 强制使用传统编排器
   python main.py --haystack-orchestrator traditional
   ```

2. **内存不足**
   ```yaml
   # 减少并发数
   concurrency:
     max_workers: 2
     batch_size: 5
   
   # 启用缓存清理
   hierarchical_cache:
     auto_cleanup: true
     max_size: "500MB"
   ```

3. **模型调用失败**
   ```yaml
   # 配置回退模型
   hierarchical_rag_models:
     haystack:
       fallback_models:
         - "gpt-3.5-turbo@openai"
         - "deepseek-chat@deepseek"
   ```

### 性能调优建议

1. **小型项目**（<100文件）
   - 使用传统编排器
   - 减少交叉验证模型数量
   - 启用积极缓存

2. **中型项目**（100-1000文件）
   - 使用Haystack-AI编排器
   - 平衡精度和性能
   - 启用分层缓存

3. **大型项目**（>1000文件）
   - 使用完整层级RAG架构
   - 启用所有优化选项
   - 考虑分布式部署

---

更多详细信息请参考：
- [配置参考](./configuration-reference.md)
- [故障排除指南](./troubleshooting.md)
- [最佳实践](./best-practices.md)