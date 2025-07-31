"""
模型使用日志记录器
记录和监控各层级RAG架构中模型的使用情况
"""

import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import json

from loguru import logger


@dataclass
class ModelUsageRecord:
    """模型使用记录"""
    timestamp: datetime
    layer: str  # haystack, txtai, r2r, self_rag_validation, self_rag
    component: str  # 具体组件名称
    model_name: str
    operation: str  # 操作类型：retrieval, embedding, context_analysis, enhancement, validation, cross_validation
    input_size: int  # 输入大小（字符数或文本数量）
    output_size: int  # 输出大小
    execution_time: float  # 执行时间（秒）
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ModelUsageLogger:
    """模型使用日志记录器"""
    
    def __init__(self):
        """初始化模型使用日志记录器"""
        self.usage_records: List[ModelUsageRecord] = []
        self.session_stats = defaultdict(lambda: {
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "total_time": 0.0,
            "avg_time": 0.0
        })
        
        logger.info("📊 模型使用日志记录器初始化完成")
    
    def log_model_usage(self, 
                       layer: str,
                       component: str, 
                       model_name: str,
                       operation: str,
                       input_size: int = 0,
                       output_size: int = 0,
                       execution_time: float = 0.0,
                       success: bool = True,
                       error_message: Optional[str] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> None:
        """记录模型使用情况"""
        
        record = ModelUsageRecord(
            timestamp=datetime.now(),
            layer=layer,
            component=component,
            model_name=model_name,
            operation=operation,
            input_size=input_size,
            output_size=output_size,
            execution_time=execution_time,
            success=success,
            error_message=error_message,
            metadata=metadata or {}
        )
        
        self.usage_records.append(record)
        
        # 更新统计信息
        key = f"{layer}.{component}.{model_name}"
        stats = self.session_stats[key]
        stats["total_calls"] += 1
        
        if success:
            stats["successful_calls"] += 1
            status_icon = "✅"
        else:
            stats["failed_calls"] += 1
            status_icon = "❌"
        
        stats["total_time"] += execution_time
        if stats["total_calls"] > 0:
            stats["avg_time"] = stats["total_time"] / stats["total_calls"]
        
        # 记录详细日志
        layer_icons = {
            "haystack": "🚀",
            "txtai": "🔍", 
            "r2r": "🔗",
            "self_rag_validation": "✅",
            "self_rag": "📚"
        }
        
        icon = layer_icons.get(layer, "🔧")
        
        logger.info(
            f"{status_icon} {icon} {layer.upper()}层 - {component} - "
            f"模型: {model_name} - 操作: {operation} - "
            f"耗时: {execution_time:.3f}s - "
            f"输入: {input_size} - 输出: {output_size}"
        )
        
        if not success and error_message:
            logger.error(f"❌ 模型调用失败: {error_message}")
    
    def get_session_summary(self) -> Dict[str, Any]:
        """获取会话统计摘要"""
        total_calls = sum(stats["total_calls"] for stats in self.session_stats.values())
        successful_calls = sum(stats["successful_calls"] for stats in self.session_stats.values())
        failed_calls = sum(stats["failed_calls"] for stats in self.session_stats.values())
        total_time = sum(stats["total_time"] for stats in self.session_stats.values())
        
        # 按层级统计
        layer_stats = defaultdict(lambda: {
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "total_time": 0.0,
            "models_used": set()
        })
        
        for key, stats in self.session_stats.items():
            layer = key.split('.')[0]
            layer_stats[layer]["total_calls"] += stats["total_calls"]
            layer_stats[layer]["successful_calls"] += stats["successful_calls"]
            layer_stats[layer]["failed_calls"] += stats["failed_calls"]
            layer_stats[layer]["total_time"] += stats["total_time"]
            
            # 提取模型名称
            model_name = key.split('.')[2]
            layer_stats[layer]["models_used"].add(model_name)
        
        # 转换set为list以便JSON序列化
        for layer in layer_stats:
            layer_stats[layer]["models_used"] = list(layer_stats[layer]["models_used"])
        
        return {
            "session_overview": {
                "total_calls": total_calls,
                "successful_calls": successful_calls,
                "failed_calls": failed_calls,
                "success_rate": successful_calls / total_calls if total_calls > 0 else 0.0,
                "total_time": total_time,
                "avg_time_per_call": total_time / total_calls if total_calls > 0 else 0.0
            },
            "layer_statistics": dict(layer_stats),
            "detailed_stats": dict(self.session_stats)
        }
    
    def print_session_summary(self) -> None:
        """打印会话统计摘要"""
        summary = self.get_session_summary()
        overview = summary["session_overview"]
        layer_stats = summary["layer_statistics"]
        
        logger.info("=" * 80)
        logger.info("📊 模型使用统计摘要")
        logger.info("=" * 80)
        
        # 总体统计
        logger.info(f"🔢 总调用次数: {overview['total_calls']}")
        logger.info(f"✅ 成功调用: {overview['successful_calls']}")
        logger.info(f"❌ 失败调用: {overview['failed_calls']}")
        logger.info(f"📈 成功率: {overview['success_rate']:.2%}")
        logger.info(f"⏱️ 总耗时: {overview['total_time']:.3f}秒")
        logger.info(f"⏱️ 平均耗时: {overview['avg_time_per_call']:.3f}秒/次")
        
        # 各层统计
        logger.info("\n📋 各层级统计:")
        layer_icons = {
            "haystack": "🚀",
            "txtai": "🔍", 
            "r2r": "🔗",
            "self_rag_validation": "✅",
            "self_rag": "📚"
        }
        
        for layer, stats in layer_stats.items():
            icon = layer_icons.get(layer, "🔧")
            success_rate = stats["successful_calls"] / stats["total_calls"] if stats["total_calls"] > 0 else 0.0
            
            logger.info(f"{icon} {layer.upper()}层:")
            logger.info(f"  📞 调用次数: {stats['total_calls']}")
            logger.info(f"  📈 成功率: {success_rate:.2%}")
            logger.info(f"  ⏱️ 总耗时: {stats['total_time']:.3f}秒")
            logger.info(f"  🤖 使用模型: {', '.join(stats['models_used'])}")
        
        logger.info("=" * 80)
    
    def export_usage_data(self, filepath: str) -> None:
        """导出使用数据到文件"""
        try:
            export_data = {
                "export_time": datetime.now().isoformat(),
                "summary": self.get_session_summary(),
                "detailed_records": [
                    {
                        "timestamp": record.timestamp.isoformat(),
                        "layer": record.layer,
                        "component": record.component,
                        "model_name": record.model_name,
                        "operation": record.operation,
                        "input_size": record.input_size,
                        "output_size": record.output_size,
                        "execution_time": record.execution_time,
                        "success": record.success,
                        "error_message": record.error_message,
                        "metadata": record.metadata
                    }
                    for record in self.usage_records
                ]
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"📁 模型使用数据已导出到: {filepath}")
            
        except Exception as e:
            logger.error(f"❌ 导出模型使用数据失败: {e}")
    
    def clear_records(self) -> None:
        """清空记录"""
        self.usage_records.clear()
        self.session_stats.clear()
        logger.info("🧹 模型使用记录已清空")


# 全局模型使用日志记录器实例
model_usage_logger = ModelUsageLogger()


def log_model_call(layer: str, component: str, model_name: str, operation: str):
    """装饰器：记录模型调用"""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            input_size = len(str(kwargs.get('prompt', ''))) if 'prompt' in kwargs else 0
            
            try:
                result = await func(*args, **kwargs)
                execution_time = time.time() - start_time
                output_size = len(str(result)) if result else 0
                
                model_usage_logger.log_model_usage(
                    layer=layer,
                    component=component,
                    model_name=model_name,
                    operation=operation,
                    input_size=input_size,
                    output_size=output_size,
                    execution_time=execution_time,
                    success=True
                )
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                
                model_usage_logger.log_model_usage(
                    layer=layer,
                    component=component,
                    model_name=model_name,
                    operation=operation,
                    input_size=input_size,
                    output_size=0,
                    execution_time=execution_time,
                    success=False,
                    error_message=str(e)
                )
                
                raise
        
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            input_size = len(str(kwargs.get('prompt', ''))) if 'prompt' in kwargs else 0
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                output_size = len(str(result)) if result else 0
                
                model_usage_logger.log_model_usage(
                    layer=layer,
                    component=component,
                    model_name=model_name,
                    operation=operation,
                    input_size=input_size,
                    output_size=output_size,
                    execution_time=execution_time,
                    success=True
                )
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                
                model_usage_logger.log_model_usage(
                    layer=layer,
                    component=component,
                    model_name=model_name,
                    operation=operation,
                    input_size=input_size,
                    output_size=0,
                    execution_time=execution_time,
                    success=False,
                    error_message=str(e)
                )
                
                raise
        
        # 根据函数类型选择包装器
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator