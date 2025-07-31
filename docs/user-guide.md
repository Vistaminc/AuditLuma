# AuditLuma 用户指南

## 概述

欢迎使用AuditLuma 2.0！本指南将帮助您快速上手层级RAG架构的代码安全审计系统，从基础使用到高级配置，让您充分发挥系统的强大功能。

## 快速入门

### 第一次使用

#### 1. 环境准备

```bash
# 检查Python版本（需要3.8+）
python --version

# 克隆项目
git clone https://github.com/Vistaminc/AuditLuma.git
cd AuditLuma

# 安装依赖
pip install -r requirements.txt
```

#### 2. 基础配置

```bash
# 复制配置模板
cp config/config.yaml.example config/config.yaml

# 设置API密钥（选择一个或多个）
export OPENAI_API_KEY="your-openai-api-key"
export DEEPSEEK_API_KEY="your-deepseek-api-key"
export QWEN_API_KEY="your-qwen-api-key"
```

#### 3. 第一次分析

```bash
# 使用默认配置分析项目
python main.py -d ./your-project-path

# 查看生成的报告
open ./reports/index.html
```

### 架构选择指南

#### 自动选择（推荐新手）

```bash
# 让系统根据项目规模自动选择最优架构
python main.py --architecture auto -d ./your-project
```

系统会根据以下规则自动选择：
- **小项目（<100文件）**：传统RAG架构
- **中型项目（100-1000文件）**：层级RAG架构
- **大型项目（>1000文件）**：完整层级RAG架构

#### 手动选择

```bash
# 使用层级RAG架构（推荐）
python main.py --architecture hierarchical -d ./your-project

# 使用传统RAG架构
python main.py --architecture traditional -d ./your-project
```

## 层级RAG架构详解

### 架构概览

AuditLuma 2.0的核心创新是四层RAG架构：

```
用户请求 → 第一层：Haystack编排 → 第二层：txtai检索 → 第三层：R2R增强 → 第四层：Self-RAG验证 → 最终结果
```

### 各层功能详解

#### 第一层：Haystack编排层

**功能**：智能任务分解和执行调度

**两种编排器**：
- **Haystack-AI编排器**（推荐）：基于AI的智能编排
- **传统编排器**：基于规则的稳定编排

**使用方法**：
```bash
# 使用AI编排器（默认）
python main.py --architecture hierarchical --haystack-orchestrator ai

# 使用传统编排器
python main.py --architecture hierarchical --haystack-orchestrator traditional
```

#### 第二层：txtai知识检索层

**功能**：语义检索和知识图谱构建

**启用方法**：
```bash
python main.py --architecture hierarchical --enable-txtai
```

**配置示例**：
```yaml
hierarchical_rag_models:
  txtai:
    retrieval_model: "gpt-3.5-turbo@openai"
    embedding_model: "text-embedding-ada-002@openai"
    retrieval_config:
      limit: 10
      threshold: 0.7
```

#### 第三层：R2R上下文增强层

**功能**：动态上下文扩展和关联分析

**启用方法**：
```bash
python main.py --architecture hierarchical --enable-r2r
```

**配置示例**：
```yaml
hierarchical_rag_models:
  r2r:
    context_model: "gpt-3.5-turbo@openai"
    context_config:
      max_context_length: 4000
      expansion_depth: 3
```

#### 第四层：Self-RAG验证层

**功能**：多模型交叉验证和假阳性过滤

**启用方法**：
```bash
python main.py --architecture hierarchical --enable-self-rag-validation
```

**配置示例**：
```yaml
hierarchical_rag_models:
  self_rag_validation:
    validation_model: "gpt-4@openai"
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
      - "claude-3@anthropic"
```

## 实用场景指南

### 场景1：小型项目快速审计

**适用**：个人项目、小型脚本、原型代码

```bash
# 快速分析，使用传统架构
python main.py --architecture traditional -d ./small-project --workers 2
```

**配置建议**：
```yaml
global:
  default_architecture: "traditional"

default_models:
  code_analysis: "gpt-3.5-turbo@openai"
  security_audit: "gpt-3.5-turbo@openai"
```

### 场景2：企业级项目深度审计

**适用**：大型企业项目、关键业务系统

```bash
# 使用完整层级RAG架构
python main.py --architecture hierarchical \
  --haystack-orchestrator ai \
  --enable-txtai \
  --enable-r2r \
  --enable-self-rag-validation \
  -d ./enterprise-project
```

**配置建议**：
```yaml
hierarchical_rag_models:
  enabled: true
  haystack:
    orchestrator_type: "ai"
    task_models:
      security_scan: "gpt-4@openai"  # 使用最强模型
      
  self_rag_validation:
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
      - "claude-3@anthropic"
    validation_config:
      min_consensus: 3
      confidence_threshold: 0.9
```

### 场景3：持续集成/持续部署(CI/CD)

**适用**：自动化代码审计、DevSecOps流程

```bash
# CI/CD友好的配置
python main.py --architecture auto \
  --format json \
  --no-interactive \
  -d ./ci-project \
  -o ./ci-reports
```

**配置建议**：
```yaml
global:
  auto_switch_threshold: 50  # 较低的阈值，快速切换

cache:
  enabled: true
  type: "redis"  # 使用Redis缓存提高CI性能

monitoring:
  enabled: true
  export_format: "json"
```

### 场景4：安全合规审计

**适用**：金融、医疗等高安全要求行业

```bash
# 最高安全标准配置
python main.py --architecture hierarchical \
  --haystack-orchestrator ai \
  --enable-self-rag-validation \
  --enhanced-analysis \
  -d ./compliance-project
```

**配置建议**：
```yaml
hierarchical_rag_models:
  self_rag_validation:
    validation_config:
      min_consensus: 4  # 更高的共识要求
      confidence_threshold: 0.95
      enable_false_positive_filter: true
      
    cross_validation_models:
      - "gpt-4@openai"
      - "deepseek-chat@deepseek"
      - "claude-3@anthropic"
      - "qwen-max@qwen"
```

## 性能优化指南

### 基础优化

#### 1. 合理设置并行度

```bash
# 根据CPU核心数设置（通常为核心数的2倍）
python main.py --workers 8 -d ./your-project

# 查看系统资源
python -c "import os; print(f'CPU核心数: {os.cpu_count()}')"
```

#### 2. 启用缓存

```yaml
# 配置Redis缓存
cache:
  enabled: true
  type: "redis"
  redis_config:
    host: "localhost"
    port: 6379
  cache_strategy:
    max_size: "1GB"
    default_ttl: 3600
```

#### 3. 模型选择优化

```yaml
# 根据任务复杂度选择模型
hierarchical_rag_models:
  haystack:
    task_models:
      syntax_check: "gpt-3.5-turbo@openai"    # 简单任务用快速模型
      security_scan: "gpt-4@openai"           # 复杂任务用强大模型
      logic_analysis: "deepseek-chat@deepseek" # 平衡性能和成本
```

### 高级优化

#### 1. 分层缓存策略

```yaml
cache:
  layer_cache:
    haystack:
      enabled: true
      ttl: 1800  # 30分钟
    txtai:
      enabled: true
      ttl: 3600  # 1小时
    r2r:
      enabled: true
      ttl: 1800  # 30分钟
    self_rag:
      enabled: true
      ttl: 900   # 15分钟
```

#### 2. 智能批处理

```yaml
project:
  max_batch_size: 20        # 根据内存调整
  max_file_size: 1000000    # 限制单文件大小
  
# 对于内存受限环境
project:
  max_batch_size: 5
  max_file_size: 500000
```

#### 3. 网络优化

```yaml
providers:
  openai:
    timeout: 60
    max_retries: 3
    connection_pool_size: 10
    
    # 使用多个API密钥轮换
    api_keys:
      - "key1"
      - "key2"
      - "key3"
    load_balancing: "round_robin"
```

## 监控和调试

### 启用详细日志

```bash
# 启用详细日志
python main.py --verbose -d ./your-project

# 保存日志到文件
python main.py --verbose -d ./your-project > analysis.log 2>&1
```

### 性能监控

```yaml
monitoring:
  enabled: true
  
  performance:
    track_response_time: true
    track_accuracy: true
    track_resource_usage: true
    track_cache_hit_rate: true
    
  alerts:
    enabled: true
    thresholds:
      response_time: 30
      error_rate: 0.05
      memory_usage: 0.8
```

### 架构信息查看

```bash
# 查看当前架构配置
python main.py --show-architecture-info

# 运行诊断工具
python -m auditluma.diagnostics run-all
```

## 常见使用模式

### 开发阶段

```bash
# 快速迭代，使用自动架构选择
python main.py --architecture auto --verbose -d ./dev-project
```

### 测试阶段

```bash
# 启用性能对比，评估不同架构效果
python main.py --enable-performance-comparison -d ./test-project
```

### 生产部署

```bash
# 使用稳定配置，启用监控
python main.py --architecture hierarchical \
  --haystack-orchestrator traditional \
  --enable-monitoring \
  -d ./prod-project
```

## 报告解读

### HTML报告结构

生成的HTML报告包含以下部分：

1. **执行摘要**：整体安全状况概览
2. **漏洞统计**：按严重程度分类的漏洞数量
3. **详细发现**：每个漏洞的详细信息
4. **修复建议**：针对性的修复方案
5. **依赖关系图**：项目依赖可视化
6. **性能指标**：分析过程的性能数据

### 漏洞严重程度

- **Critical（严重）**：立即需要修复的高风险漏洞
- **High（高）**：应尽快修复的重要漏洞
- **Medium（中）**：建议修复的一般漏洞
- **Low（低）**：可选修复的轻微问题
- **Info（信息）**：代码质量建议

### 置信度解读

- **90%+**：高置信度，建议立即处理
- **70-90%**：中等置信度，建议人工确认
- **50-70%**：低置信度，可能存在假阳性
- **<50%**：很低置信度，需要仔细验证

## 集成指南

### 与IDE集成

#### VS Code集成

1. 安装AuditLuma扩展（如果可用）
2. 配置工作区设置：

```json
{
  "auditluma.configPath": "./config/config.yaml",
  "auditluma.architecture": "hierarchical",
  "auditluma.autoRun": true
}
```

#### IntelliJ IDEA集成

1. 配置外部工具：
   - Program: `python`
   - Arguments: `main.py --architecture hierarchical -d $ProjectFileDir$`
   - Working directory: `$AuditLumaPath$`

### 与CI/CD集成

#### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.8'
    - name: Install AuditLuma
      run: |
        git clone https://github.com/Vistaminc/AuditLuma.git
        cd AuditLuma
        pip install -r requirements.txt
    - name: Run Security Audit
      run: |
        cd AuditLuma
        python main.py --architecture auto --format json -d $GITHUB_WORKSPACE -o ./reports
      env:
        OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    - name: Upload Reports
      uses: actions/upload-artifact@v2
      with:
        name: security-reports
        path: AuditLuma/reports/
```

#### Jenkins集成

```groovy
pipeline {
    agent any
    
    environment {
        OPENAI_API_KEY = credentials('openai-api-key')
    }
    
    stages {
        stage('Security Audit') {
            steps {
                script {
                    sh '''
                        cd /path/to/AuditLuma
                        python main.py --architecture hierarchical \
                          --format json \
                          -d ${WORKSPACE} \
                          -o ./reports
                    '''
                }
            }
        }
        
        stage('Publish Reports') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: 'index.html',
                    reportName: 'Security Audit Report'
                ])
            }
        }
    }
}
```

## 故障排除快速参考

### 常见问题

#### 1. 配置文件错误

```bash
# 验证配置文件
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"

# 使用配置验证工具
python -m auditluma.config validate
```

#### 2. API连接问题

```bash
# 测试API连接
python -c "
import openai
openai.api_key = 'your-api-key'
print(openai.Model.list())
"
```

#### 3. 内存不足

```yaml
# 减少批处理大小
project:
  max_batch_size: 5
  max_file_size: 500000

# 启用量化
hierarchical_rag_models:
  txtai:
    index_config:
      quantize: true
```

#### 4. 性能问题

```bash
# 启用缓存
python main.py --enable-caching -d ./your-project

# 减少并行度
python main.py --workers 2 -d ./your-project
```

### 获取帮助

- **查看帮助**：`python main.py --help`
- **架构信息**：`python main.py --show-architecture-info`
- **运行诊断**：`python -m auditluma.diagnostics run-all`
- **社区支持**：GitHub Issues
- **商业支持**：联系开发团队

## 总结

AuditLuma 2.0的层级RAG架构为代码安全审计提供了强大而灵活的解决方案。通过合理的配置和使用，您可以：

1. **提高检测精度**：四层验证机制显著减少假阳性
2. **优化性能**：智能缓存和并行处理提升分析速度
3. **灵活部署**：支持从小型项目到企业级应用的各种场景
4. **持续改进**：通过监控和反馈不断优化配置

建议从自动架构选择开始，根据实际使用情况逐步调整配置，最终找到最适合您项目的最优配置。