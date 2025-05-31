# AuditLuma API 文档

## 目录
- [概述](#概述)
- [快速开始](#快速开始)
- [认证](#认证)
- [API 端点](#api-端点)
  - [扫描管理](#扫描管理)
  - [漏洞管理](#漏洞管理)
  - [修复建议](#修复建议)
  - [文件上传](#文件上传)
  - [配置管理](#配置管理)
  - [系统状态](#系统状态)
- [数据模型](#数据模型)
- [错误处理](#错误处理)
- [示例](#示例)

## 概述

AuditLuma API 是一个基于 FastAPI 构建的 RESTful 服务，提供了代码审计、安全漏洞检测、依赖分析等功能。通过 API，您可以集成 AuditLuma 的代码审计能力到您的 CI/CD 流程或其他系统中。

## 快速开始

1. 启动 API 服务器：
   ```bash
   python -m app.api.server --host 0.0.0.0 --port 8000
   ```

2. 访问交互式 API 文档：
   - Swagger UI: http://localhost:8000/api/docs
   - ReDoc: http://localhost:8000/api/redoc

3. 使用 API 进行代码审计：
   ```bash
   # 启动扫描
   curl -X POST "http://localhost:8000/api/scan" \
     -H "Content-Type: application/json" \
     -d '{"target_dir": "/path/to/your/code"}'
   
   # 获取扫描状态
   curl "http://localhost:8000/api/scan/{scan_id}/status"
   ```

## 认证

当前版本的 API 不需要认证，但生产环境建议启用认证。

## API 端点

### 扫描管理

#### 启动扫描

```
POST /api/scan
```

启动代码扫描分析任务。

**请求体 (application/json):**

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| target_dir | string | 是 | 目标项目目录路径 |
| output_dir | string | 否 | 报告输出目录（默认使用配置值） |
| workers | integer | 否 | 并行工作线程数 |
| report_format | string | 否 | 报告格式 (html, pdf, json)，默认 "html" |
| skip_deps | boolean | 否 | 是否跳过依赖分析，默认 false |
| skip_remediation | boolean | 否 | 是否跳过生成修复建议，默认 false |

**响应示例 (200 OK):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "initializing",
  "message": "扫描任务已初始化并在后台运行"
}
```

#### 获取扫描状态

```
GET /api/scan/{scan_id}/status
```

获取指定扫描任务的状态。

**路径参数:**
- `scan_id` (string, 必填): 扫描任务ID

**响应示例 (200 OK):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "scanning",
  "progress": 45.5,
  "start_time": "2025-05-31T14:00:00Z",
  "end_time": null,
  "report_path": null,
  "error": null
}
```

#### 获取扫描摘要

```
GET /api/scan/{scan_id}/summary
```

获取扫描结果的摘要信息。

**路径参数:**
- `scan_id` (string, 必填): 扫描任务ID

**响应示例 (200 OK):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_name": "example-project",
  "scan_date": "2025-05-31 14:00:00",
  "scan_duration": "12.34秒",
  "scanned_files": 42,
  "scanned_lines": 1234,
  "vulnerability_count": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 0,
    "total": 11
  },
  "report_url": "/reports/scan_550e8400.html"
}
```

#### 下载扫描报告

```
GET /api/scan/{scan_id}/report
```

下载生成的扫描报告文件。

**路径参数:**
- `scan_id` (string, 必填): 扫描任务ID

**响应:**
- `200 OK`: 返回报告文件内容
- `404 Not Found`: 报告文件不存在

### 漏洞管理

#### 获取漏洞列表

```
GET /api/scan/{scan_id}/vulnerabilities
```

获取扫描发现的漏洞列表。

**查询参数:**
- `severity` (string, 可选): 按严重程度过滤 (critical, high, medium, low, info)
- `limit` (integer, 可选): 返回结果数量限制，默认 100
- `offset` (integer, 可选): 分页偏移量，默认 0

**响应示例 (200 OK):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "total": 11,
  "vulnerabilities": [
    {
      "id": "vuln-123",
      "type": "sql_injection",
      "severity": "high",
      "title": "SQL 注入漏洞",
      "description": "在 user_input 参数中检测到未经验证的用户输入直接拼接到 SQL 查询中。",
      "file_path": "/src/main.py",
      "line_number": 42,
      "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_input}')",
      "cwe_id": "CWE-89",
      "confidence": "high",
      "recommendation": "使用参数化查询或预编译语句来防止 SQL 注入。"
    }
  ]
}
```

### 修复建议

#### 获取修复建议列表

```
GET /api/scan/{scan_id}/remediations
```

获取扫描生成的修复建议列表。

**查询参数:**
- `vulnerability_id` (string, 可选): 按漏洞ID过滤
- `limit` (integer, 可选): 返回结果数量限制，默认 100
- `offset` (integer, 可选): 分页偏移量，默认 0

**响应示例 (200 OK):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "total": 3,
  "remediations": [
    {
      "id": "rem-456",
      "vulnerability_id": "vuln-123",
      "title": "修复 SQL 注入",
      "description": "使用参数化查询替换字符串拼接",
      "code_before": "cursor.execute(f'SELECT * FROM users WHERE id = {user_input}')",
      "code_after": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))",
      "file_path": "/src/main.py",
      "line_number": 42,
      "difficulty": "low",
      "priority": "high"
    }
  ]
}
```

### 文件上传

#### 上传项目文件

```
POST /api/upload
```

上传项目文件（ZIP格式）进行扫描。

**请求体 (multipart/form-data):**
- `file` (file, 必填): 要上传的ZIP文件

**响应示例 (200 OK):**

```json
{
  "upload_id": "upload-789",
  "temp_dir": "/tmp/upload_789",
  "message": "文件上传成功，已解压到临时目录"
}
```

### 配置管理

#### 获取当前配置

```
GET /api/config
```

获取当前系统配置信息。

**响应示例 (200 OK):**

```json
{
  "success": true,
  "message": "配置获取成功",
  "data": {
    "global": {
      "show_thinking": false,
      "language": "zh-CN",
      "target_dir": "./goalfile",
      "report_dir": "./reports",
      "report_format": "html",
      "temp_dir": "./temp"
    },
    "project": {
      "name": "AuditLuma项目",
      "max_file_size": 1000000,
      "max_batch_size": 20
    }
  }
}
```

### 系统状态

#### 健康检查

```
GET /api/health
```

检查API服务是否正常运行。

**响应示例 (200 OK):**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "timestamp": "2025-05-31T14:00:00Z"
}
```

## 数据模型

### 扫描请求 (ScanRequest)

| 字段 | 类型 | 必填 | 描述 |
|------|------|------|------|
| target_dir | string | 是 | 目标项目目录路径 |
| output_dir | string | 否 | 报告输出目录 |
| workers | integer | 否 | 并行工作线程数 |
| report_format | string | 否 | 报告格式 (html, pdf, json) |
| skip_deps | boolean | 否 | 是否跳过依赖分析 |
| skip_remediation | boolean | 否 | 是否跳过生成修复建议 |

### 漏洞详情 (VulnerabilityDetail)

| 字段 | 类型 | 描述 |
|------|------|------|
| id | string | 漏洞ID |
| type | string | 漏洞类型 |
| severity | string | 严重程度 (critical, high, medium, low, info) |
| title | string | 漏洞标题 |
| description | string | 漏洞描述 |
| file_path | string | 文件路径 |
| line_number | integer | 行号 |
| code_snippet | string | 相关代码片段 |
| cwe_id | string | CWE ID |
| confidence | string | 置信度 (high, medium, low) |
| recommendation | string | 修复建议 |

### 修复建议详情 (RemediationDetail)

| 字段 | 类型 | 描述 |
|------|------|------|
| id | string | 修复建议ID |
| vulnerability_id | string | 关联的漏洞ID |
| title | string | 修复建议标题 |
| description | string | 修复建议描述 |
| code_before | string | 修复前代码 |
| code_after | string | 修复后代码 |
| file_path | string | 文件路径 |
| line_number | integer | 行号 |
| difficulty | string | 修复难度 (low, medium, high) |
| priority | string | 修复优先级 (low, medium, high) |

## 错误处理

API 使用标准的 HTTP 状态码表示请求结果：

- `200 OK`: 请求成功
- `400 Bad Request`: 请求参数错误
- `404 Not Found`: 资源不存在
- `422 Unprocessable Entity`: 请求参数验证失败
- `500 Internal Server Error`: 服务器内部错误

错误响应格式：

```json
{
  "detail": "错误描述",
  "error_code": "ERROR_CODE",
  "request_id": "请求ID"
}
```

## 示例

### 完整扫描流程

1. **启动扫描**
   ```bash
   curl -X POST "http://localhost:8000/api/scan" \
     -H "Content-Type: application/json" \
     -d '{
       "target_dir": "/path/to/your/code",
       "report_format": "html"
     }'
   ```

2. **检查扫描状态**
   ```bash
   curl "http://localhost:8000/api/scan/550e8400-e29b-41d4-a716-446655440000/status"
   ```

3. **获取漏洞列表**
   ```bash
   curl "http://localhost:8000/api/scan/550e8400-e29b-41d4-a716-446655440000/vulnerabilities?severity=high"
   ```

4. **下载报告**
   ```bash
   curl -o report.html "http://localhost:8000/api/scan/550e8400-e29b-41d4-a716-446655440000/report"
   ```

### 使用文件上传

```bash
curl -X POST "http://localhost:8000/api/upload" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/your/project.zip"
```

然后使用返回的 `temp_dir` 作为 `target_dir` 启动扫描。

## 注意事项

1. 扫描大型项目可能需要较长时间，建议使用异步方式调用API。
2. 报告生成后，文件会保存在服务器上，请定期清理。
3. 生产环境建议启用认证和HTTPS。
4. 默认配置适用于开发环境，生产环境请根据需求调整。
