# 安装指南

## 系统要求

### 最低要求

- **操作系统**: Windows 10+, macOS 10.14+, Ubuntu 18.04+
- **Python版本**: 3.8+
- **内存**: 4GB RAM
- **存储空间**: 2GB 可用空间
- **网络**: 稳定的互联网连接（用于API调用）

### 推荐配置

- **操作系统**: Windows 11, macOS 12+, Ubuntu 20.04+
- **Python版本**: 3.9+
- **内存**: 8GB+ RAM
- **存储空间**: 5GB+ 可用空间
- **CPU**: 4核心+
- **网络**: 高速互联网连接

## 安装方式

### 方式一：从源码安装（推荐）

#### 1. 克隆仓库

```bash
# 使用HTTPS
git clone https://github.com/Vistaminc/AuditLuma.git

# 或使用SSH
git clone git@github.com:Vistaminc/AuditLuma.git

# 进入项目目录
cd AuditLuma
```

#### 2. 创建虚拟环境（推荐）

```bash
# 使用venv
python -m venv auditluma-env

# 激活虚拟环境
# Windows
auditluma-env\Scripts\activate

# macOS/Linux
source auditluma-env/bin/activate
```

#### 3. 安装依赖

```bash
# 安装基础依赖
pip install -r requirements.txt

# 验证安装
python main.py --help
```

### 方式二：使用Docker

#### 1. 拉取镜像

```bash
# 拉取最新镜像
docker pull auditluma/auditluma:latest

# 或构建本地镜像
git clone https://github.com/Vistaminc/AuditLuma.git
cd AuditLuma
docker build -t auditluma:local .
```

#### 2. 运行容器

```bash
# 基础运行
docker run -v /path/to/your/project:/app/project \
  -v /path/to/reports:/app/reports \
  -e OPENAI_API_KEY=your-api-key \
  auditluma/auditluma:latest \
  --architecture hierarchical -d /app/project -o /app/reports

# 使用docker-compose
cat > docker-compose.yml << EOF
version: '3.8'
services:
  auditluma:
    image: auditluma/auditluma:latest
    volumes:
      - ./your-project:/app/project
      - ./reports:/app/reports
      - ./config:/app/config
    environment:
      - OPENAI_API_KEY=your-api-key
      - DEEPSEEK_API_KEY=your-deepseek-key
    command: ["--architecture", "hierarchical", "-d", "/app/project"]
  
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
EOF

docker-compose up
```

### 方式三：使用pip安装（即将支持）

```bash
# 从PyPI安装（开发中）
pip install auditluma

# 从GitHub安装
pip install git+https://github.com/Vistaminc/AuditLuma.git
```

## 依赖安装详解

### 核心依赖

```bash
# 必需依赖
pip install pyyaml>=6.0
pip install loguru>=0.6.0
pip install aiohttp>=3.8.0
pip install asyncio-throttle>=1.0.0

# AI/ML依赖
pip install openai>=1.0.0
pip install transformers>=4.20.0
pip install torch>=1.12.0
```

### 可选依赖

#### FAISS向量检索（推荐用于大型项目）

```bash
# CPU版本
pip install faiss-cpu

# GPU版本（需要CUDA支持）
pip install faiss-gpu
```

#### Redis缓存（推荐用于生产环境）

```bash
# Redis Python客户端
pip install redis>=4.0.0

# 安装Redis服务器
# Ubuntu/Debian
sudo apt-get install redis-server

# CentOS/RHEL
sudo yum install redis

# macOS
brew install redis

# Windows
# 下载并安装Redis for Windows
```

#### 可视化依赖

```bash
# 图表生成
pip install matplotlib>=3.5.0
pip install plotly>=5.0.0

# PDF报告生成
pip install reportlab>=3.6.0
pip install weasyprint>=56.0
```

#### 开发依赖

```bash
# 测试框架
pip install pytest>=7.0.0
pip install pytest-asyncio>=0.20.0

# 代码质量
pip install black>=22.0.0
pip install flake8>=5.0.0
pip install mypy>=0.990
```

## 配置设置

### 1. 创建配置文件

```bash
# 复制配置模板
cp config/config.yaml.example config/config.yaml

# 编辑配置文件
nano config/config.yaml  # 或使用你喜欢的编辑器
```

### 2. 设置API密钥

#### 方法一：环境变量（推荐）

```bash
# 设置环境变量
export OPENAI_API_KEY="your-openai-api-key"
export DEEPSEEK_API_KEY="your-deepseek-api-key"
export QWEN_API_KEY="your-qwen-api-key"

# 永久设置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export OPENAI_API_KEY="your-openai-api-key"' >> ~/.bashrc
source ~/.bashrc
```

#### 方法二：配置文件

```yaml
# config/config.yaml
providers:
  openai:
    api_key: "your-openai-api-key"
    base_url: "https://api.openai.com/v1"
  
  deepseek:
    api_key: "your-deepseek-api-key"
    base_url: "https://api.deepseek.com/v1"
```

#### 方法三：密钥文件

```bash
# 创建密钥文件
cat > config/secrets.yaml << EOF
openai_api_key: "your-openai-api-key"
deepseek_api_key: "your-deepseek-api-key"
qwen_api_key: "your-qwen-api-key"
EOF

# 设置文件权限
chmod 600 config/secrets.yaml

# 添加到.gitignore
echo "config/secrets.yaml" >> .gitignore
```

### 3. 验证配置

```bash
# 验证配置文件语法
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"

# 验证API连接
python -c "
import openai
import os
openai.api_key = os.getenv('OPENAI_API_KEY')
try:
    models = openai.Model.list()
    print('✅ OpenAI API连接成功')
except Exception as e:
    print(f'❌ OpenAI API连接失败: {e}')
"

# 使用内置验证工具
python -m auditluma.config validate
```

## 平台特定安装

### Windows

#### 使用Chocolatey

```powershell
# 安装Chocolatey（如果未安装）
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 安装Python
choco install python

# 安装Git
choco install git

# 安装Redis（可选）
choco install redis-64
```

#### 使用Windows Subsystem for Linux (WSL)

```bash
# 启用WSL
wsl --install

# 在WSL中安装
wsl
sudo apt update
sudo apt install python3 python3-pip git
git clone https://github.com/Vistaminc/AuditLuma.git
cd AuditLuma
pip3 install -r requirements.txt
```

### macOS

#### 使用Homebrew

```bash
# 安装Homebrew（如果未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装依赖
brew install python@3.9
brew install git
brew install redis  # 可选

# 克隆和安装
git clone https://github.com/Vistaminc/AuditLuma.git
cd AuditLuma
pip3 install -r requirements.txt
```

### Linux (Ubuntu/Debian)

```bash
# 更新包管理器
sudo apt update

# 安装Python和依赖
sudo apt install python3 python3-pip python3-venv git

# 安装Redis（可选）
sudo apt install redis-server

# 克隆和安装
git clone https://github.com/Vistaminc/AuditLuma.git
cd AuditLuma
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Linux (CentOS/RHEL)

```bash
# 安装EPEL仓库
sudo yum install epel-release

# 安装Python和依赖
sudo yum install python3 python3-pip git

# 安装Redis（可选）
sudo yum install redis

# 克隆和安装
git clone https://github.com/Vistaminc/AuditLuma.git
cd AuditLuma
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 高级安装选项

### 开发环境安装

```bash
# 克隆仓库
git clone https://github.com/Vistaminc/AuditLuma.git
cd AuditLuma

# 创建开发环境
python -m venv dev-env
source dev-env/bin/activate  # Linux/macOS
# dev-env\Scripts\activate  # Windows

# 安装开发依赖
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 安装pre-commit钩子
pre-commit install

# 运行测试
pytest tests/
```

### 生产环境安装

```bash
# 使用生产配置
cp config/config.yaml.example config/config.yaml
cp config/production.yaml.example config/production.yaml

# 安装生产依赖
pip install -r requirements.txt
pip install gunicorn  # 如果需要Web服务

# 设置系统服务
sudo cp scripts/auditluma.service /etc/systemd/system/
sudo systemctl enable auditluma
sudo systemctl start auditluma
```

### 集群部署

```bash
# 使用Docker Swarm
docker swarm init
docker stack deploy -c docker-stack.yml auditluma

# 或使用Kubernetes
kubectl apply -f k8s/
```

## 验证安装

### 基础验证

```bash
# 检查版本
python main.py --version

# 显示帮助信息
python main.py --help

# 显示架构信息
python main.py --show-architecture-info
```

### 功能验证

```bash
# 运行诊断工具
python -m auditluma.diagnostics run-all

# 测试配置
python -m auditluma.config validate

# 运行示例分析
python main.py --dry-run -d ./goalfile
```

### 性能测试

```bash
# 运行性能基准测试
python -m auditluma.benchmark run

# 测试不同架构性能
python main.py --enable-performance-comparison -d ./test-project
```

## 故障排除

### 常见安装问题

#### Python版本问题

```bash
# 检查Python版本
python --version

# 如果版本过低，安装新版本
# Ubuntu
sudo apt install python3.9

# macOS
brew install python@3.9

# Windows
# 从python.org下载安装
```

#### 依赖冲突

```bash
# 清理pip缓存
pip cache purge

# 重新安装依赖
pip uninstall -r requirements.txt -y
pip install -r requirements.txt

# 使用虚拟环境隔离
python -m venv fresh-env
source fresh-env/bin/activate
pip install -r requirements.txt
```

#### 网络问题

```bash
# 使用国内镜像源
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/

# 或配置pip
mkdir ~/.pip
cat > ~/.pip/pip.conf << EOF
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple/
trusted-host = pypi.tuna.tsinghua.edu.cn
EOF
```

#### 权限问题

```bash
# Linux/macOS
sudo chown -R $USER:$USER /path/to/AuditLuma
chmod +x main.py

# Windows（以管理员身份运行PowerShell）
icacls "C:\path\to\AuditLuma" /grant Users:F /T
```

### 获取帮助

如果遇到安装问题，可以：

1. 查看[故障排除指南](./troubleshooting.md)
2. 搜索[GitHub Issues](https://github.com/Vistaminc/AuditLuma/issues)
3. 提交新的Issue
4. 联系技术支持：QQ群 1047736593

## 卸载

### 完全卸载

```bash
# 停止服务（如果作为服务运行）
sudo systemctl stop auditluma
sudo systemctl disable auditluma

# 删除文件
rm -rf /path/to/AuditLuma

# 删除虚拟环境
rm -rf auditluma-env

# 删除配置文件（可选）
rm -rf ~/.auditluma

# 删除Docker镜像（如果使用Docker）
docker rmi auditluma/auditluma:latest
```

### 重置配置

```bash
# 备份当前配置
cp config/config.yaml config/config.yaml.backup

# 重置为默认配置
cp config/config.yaml.example config/config.yaml

# 清理缓存
rm -rf .cache/
redis-cli FLUSHALL  # 如果使用Redis
```

## 更新升级

### 从源码更新

```bash
# 拉取最新代码
git pull origin main

# 更新依赖
pip install -r requirements.txt --upgrade

# 迁移配置（如果需要）
python main.py --config-migrate

# 验证更新
python main.py --version
```

### Docker更新

```bash
# 拉取最新镜像
docker pull auditluma/auditluma:latest

# 重启容器
docker-compose down
docker-compose up -d
```

安装完成后，建议阅读[用户指南](./user-guide.md)开始使用AuditLuma。