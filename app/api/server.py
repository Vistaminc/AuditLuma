"""
AuditLuma API 服务器启动脚本
启动FastAPI应用服务器，提供AuditLuma的API接口
"""

import os
import sys
import argparse
import uvicorn
from pathlib import Path

# 确保可以导入项目根目录模块
sys.path.append(str(Path(__file__).parent.parent.parent))

from loguru import logger
from auditluma.utils import setup_logging

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="AuditLuma API 服务器")
    parser.add_argument(
        "--host", 
        type=str, 
        default="0.0.0.0", 
        help="主机地址 (默认: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=8000, 
        help="端口号 (默认: 8000)"
    )
    parser.add_argument(
        "--reload", 
        action="store_true", 
        help="启用热重载（开发模式）"
    )
    parser.add_argument(
        "--workers", 
        type=int, 
        default=1, 
        help="工作进程数 (默认: 1)"
    )
    parser.add_argument(
        "--log-level", 
        type=str, 
        default="info", 
        choices=["debug", "info", "warning", "error", "critical"],
        help="日志级别 (默认: info)"
    )
    
    return parser.parse_args()

def main():
    """主函数，启动API服务器"""
    # 解析命令行参数
    args = parse_args()
    
    # 设置日志
    setup_logging()
    logger.info(f"正在启动AuditLuma API服务器 (host={args.host}, port={args.port})")
    
    # 配置uvicorn启动参数
    uvicorn_config = {
        "app": "app.api.api:app",
        "host": args.host,
        "port": args.port,
        "reload": args.reload,
        "workers": args.workers,
        "log_level": args.log_level,
        "access_log": True
    }
    
    # 启动服务器
    logger.info("服务器配置：" + ", ".join([f"{k}={v}" for k, v in uvicorn_config.items()]))
    logger.info("API文档将在以下URL可用:")
    logger.info(f"Swagger UI: http://{args.host}:{args.port}/api/docs")
    logger.info(f"ReDoc: http://{args.host}:{args.port}/api/redoc")
    
    try:
        uvicorn.run(**uvicorn_config)
    except Exception as e:
        logger.error(f"启动服务器时出错: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
