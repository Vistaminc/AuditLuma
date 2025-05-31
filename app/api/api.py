"""
AuditLuma API 入口点 - FastAPI应用
提供AuditLuma核心功能的REST API接口
"""

import asyncio
import os
import time
from pathlib import Path
from typing import Dict, Any
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from loguru import logger

# 确保可以导入项目根目录模块
sys.path.append(str(Path(__file__).parent.parent.parent))

from auditluma.config import Config, load_config
from auditluma.utils import setup_logging

# 导入API模块
from app.api.routes import router
from app.api.utils import cleanup_old_scans

# 创建FastAPI应用
app = FastAPI(
    title="AuditLuma API",
    description="高级代码审计AI系统API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该设置为特定域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(router)

# 错误处理中间件
@app.middleware("http")
async def error_handler(request, call_next):
    try:
        return await call_next(request)
    except Exception as e:
        logger.error(f"API错误: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"服务器内部错误: {str(e)}"}
        )

# 初始化应用
@app.on_event("startup")
async def startup_event():
    """启动时初始化应用"""
    # 设置日志
    setup_logging()
    
    # 配置文件路径
    current_dir = Path(__file__).parent.parent.parent
    config_path = current_dir / "config" / "config.yaml"
    example_config_path = current_dir / "config" / "config.yaml.example"
    
    # 尝试加载配置文件
    if config_path.exists():
        try:
            load_config(str(config_path))
            logger.info(f"从 {config_path} 加载了配置")
        except Exception as e:
            logger.error(f"加载配置文件时出错: {e}")
            # 尝试加载示例配置
            if example_config_path.exists():
                try:
                    load_config(str(example_config_path))
                    logger.warning(f"使用示例配置文件: {example_config_path}")
                except Exception as ex:
                    logger.error(f"加载示例配置文件时出错: {ex}")
    elif example_config_path.exists():
        try:
            load_config(str(example_config_path))
            logger.warning(f"未找到config.yaml，使用示例配置文件: {example_config_path}")
        except Exception as e:
            logger.error(f"加载示例配置文件时出错: {e}")
    else:
        logger.warning("未找到config.yaml或示例配置文件，使用默认配置")

    # 创建临时文件和报告目录
    temp_dir = Path(Config.global_config.temp_dir)
    reports_dir = Path(Config.global_config.report_dir)
    
    for directory in [temp_dir, reports_dir]:
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"创建了目录: {directory}")
            
    # 启动定期清理任务
    asyncio.create_task(periodic_cleanup())

# 创建报告静态文件目录
@app.on_event("startup")
async def mount_static_files():
    try:
        reports_dir = Path(Config.global_config.report_dir)
        if not reports_dir.exists():
            reports_dir.mkdir(parents=True, exist_ok=True)
        app.mount("/reports", StaticFiles(directory=str(reports_dir)), name="reports")
        logger.info(f"已挂载报告目录: {reports_dir}")
    except Exception as e:
        logger.error(f"挂载报告目录失败: {e}")

# 定期清理旧扫描记录的任务
async def periodic_cleanup():
    """定期清理旧的扫描记录和临时文件"""
    cleanup_interval_hours = 1  # 每小时检查一次
    max_age_hours = 48  # 保留48小时内的扫描记录
    
    while True:
        try:
            await cleanup_old_scans(max_age_hours)
            logger.debug(f"执行了清理任务，移除了超过{max_age_hours}小时的旧扫描记录")
        except Exception as e:
            logger.error(f"执行清理任务时出错: {e}")
        
        # 等待下一次清理
        await asyncio.sleep(cleanup_interval_hours * 3600)

# 主路由
@app.get("/")
async def root():
    """API根路由，返回基本信息"""
    return {
        "name": "AuditLuma API",
        "description": "高级代码审计AI系统API",
        "version": "1.0.0", 
        "docs_url": "/api/docs"
    }

# 导出应用实例，用于其他模块导入和ASGI服务器启动
api_app = app
