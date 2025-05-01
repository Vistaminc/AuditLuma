"""
基础智能体类 - 提供所有智能体的通用功能
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable, Union
import uuid
import json
from datetime import datetime

from loguru import logger

from auditluma.config import Config
from auditluma.mcp.protocol import (
    AgentMessage, MessageType, MessagePriority, 
    message_bus, agent_coordinator
)
from auditluma.rag.self_rag import self_rag, Document


class BaseAgent(ABC):
    """所有智能体的基类"""
    
    def __init__(self, agent_id: Optional[str] = None, agent_type: str = "base", model_spec: Optional[str] = None):
        """初始化基础智能体
        
        Args:
            agent_id: 可选的智能体ID，如果不提供则自动生成
            agent_type: 智能体类型
            model_spec: 可选的模型规范，格式为"model@provider"
        """
        self.agent_id = agent_id or f"{agent_type}_{uuid.uuid4().hex[:8]}"
        self.agent_type = agent_type
        self.description = "基础智能体"
        self.task_queue = asyncio.Queue()
        self.running = False
        self.callback_handlers: Dict[MessageType, List[Callable]] = {}
        self.model_spec = model_spec
        
        # 注册到协调器
        agent_coordinator.register_agent(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            description=self.description
        )
        
        # 订阅消息总线
        message_bus.subscribe(self.agent_id, self._handle_message)
        
        # 注册默认消息处理器
        self._register_default_handlers()
        
        logger.info(f"初始化智能体: {self.agent_id} ({self.agent_type})")
    
    def _register_default_handlers(self) -> None:
        """注册默认消息类型处理器"""
        self.register_handler(MessageType.TASK, self._handle_task)
        self.register_handler(MessageType.QUERY, self._handle_query)
        self.register_handler(MessageType.COMMAND, self._handle_command)
    
    def register_handler(self, message_type: MessageType, handler: Callable) -> None:
        """注册特定消息类型的处理器"""
        if message_type not in self.callback_handlers:
            self.callback_handlers[message_type] = []
        self.callback_handlers[message_type].append(handler)
    
    async def _handle_message(self, message: AgentMessage) -> None:
        """处理接收到的消息"""
        logger.debug(f"{self.agent_id} 收到消息: {message.message_id} 类型: {message.message_type}")
        
        # 如果有这种消息类型的处理器，调用它们
        if message.message_type in self.callback_handlers:
            for handler in self.callback_handlers[message.message_type]:
                try:
                    await handler(message)
                except Exception as e:
                    logger.error(f"{self.agent_id} 处理消息时出错: {e}")
                    # 发送错误响应
                    await self.send_error(
                        receiver=message.sender,
                        content=f"处理消息时出错: {e}",
                        reply_to=message.message_id
                    )
        else:
            logger.warning(f"{self.agent_id} 没有处理器处理消息类型: {message.message_type}")
    
    async def _handle_task(self, message: AgentMessage) -> None:
        """处理任务消息的默认实现"""
        # 将任务放入队列
        await self.task_queue.put(message)
        
        # 发送确认
        await self.send_status(
            receiver=message.sender,
            content={"status": "accepted", "task_id": message.content.get("task_id")},
            reply_to=message.message_id
        )
    
    async def _handle_query(self, message: AgentMessage) -> None:
        """处理查询消息的默认实现"""
        # 子类应该重写这个方法
        await self.send_response(
            receiver=message.sender,
            content={"error": "未实现查询处理"},
            reply_to=message.message_id
        )
    
    async def _handle_command(self, message: AgentMessage) -> None:
        """处理命令消息的默认实现"""
        # 子类应该重写这个方法
        await self.send_response(
            receiver=message.sender,
            content={"error": "未实现命令处理"},
            reply_to=message.message_id
        )
    
    async def start(self) -> None:
        """启动智能体任务处理循环"""
        if self.running:
            logger.warning(f"{self.agent_id} 已经在运行")
            return
        
        self.running = True
        logger.info(f"启动智能体: {self.agent_id}")
        
        # 启动主任务循环
        asyncio.create_task(self._task_loop())
    
    async def stop(self) -> None:
        """停止智能体"""
        if not self.running:
            return
        
        self.running = False
        logger.info(f"停止智能体: {self.agent_id}")
        
        # 从消息总线取消订阅
        message_bus.unsubscribe(self.agent_id)
        
        # 从协调器注销
        agent_coordinator.unregister_agent(self.agent_id)
    
    async def _task_loop(self) -> None:
        """主任务处理循环"""
        while self.running:
            try:
                # 从队列获取任务，如果没有任务，等待
                message = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                
                # 处理任务
                task_id = message.content.get("task_id")
                task_type = message.content.get("task_type")
                task_data = message.content.get("data")
                
                logger.info(f"{self.agent_id} 开始处理任务: {task_id} ({task_type})")
                
                # 执行任务
                try:
                    result = await self.execute_task(task_type, task_data)
                    
                    # 更新任务状态
                    await agent_coordinator.update_task_status(
                        task_id=task_id,
                        agent_id=self.agent_id,
                        status="completed",
                        result=result
                    )
                    
                    # 发送结果
                    await self.send_result(
                        receiver=message.sender,
                        content={
                            "task_id": task_id,
                            "result": result
                        },
                        reply_to=message.message_id
                    )
                    
                    logger.info(f"{self.agent_id} 完成任务: {task_id}")
                except Exception as e:
                    logger.error(f"{self.agent_id} 执行任务时出错: {e}")
                    
                    # 更新任务状态
                    await agent_coordinator.update_task_status(
                        task_id=task_id,
                        agent_id=self.agent_id,
                        status="failed",
                        result={"error": str(e)}
                    )
                    
                    # 发送错误
                    await self.send_error(
                        receiver=message.sender,
                        content={
                            "task_id": task_id,
                            "error": str(e)
                        },
                        reply_to=message.message_id
                    )
                
                # 标记任务完成
                self.task_queue.task_done()
            
            except asyncio.TimeoutError:
                # 队列等待超时，继续循环
                pass
            except Exception as e:
                logger.error(f"{self.agent_id} 任务循环出错: {e}")
    
    @abstractmethod
    async def execute_task(self, task_type: str, task_data: Any) -> Any:
        """执行任务 - 子类必须实现"""
        pass
    
    async def send_message(self, 
                      message_type: MessageType, 
                      receiver: str, 
                      content: Any, 
                      reply_to: Optional[str] = None,
                      priority: MessagePriority = MessagePriority.MEDIUM) -> str:
        """发送消息到另一个智能体"""
        message = AgentMessage.create(
            sender=self.agent_id,
            receiver=receiver,
            message_type=message_type,
            content=content,
            reply_to=reply_to,
            priority=priority
        )
        
        await message_bus.publish(message)
        return message.message_id
    
    async def send_query(self, receiver: str, content: Any, **kwargs) -> str:
        """发送查询消息"""
        return await self.send_message(MessageType.QUERY, receiver, content, **kwargs)
    
    async def send_response(self, receiver: str, content: Any, **kwargs) -> str:
        """发送响应消息"""
        return await self.send_message(MessageType.RESPONSE, receiver, content, **kwargs)
    
    async def send_command(self, receiver: str, content: Any, **kwargs) -> str:
        """发送命令消息"""
        return await self.send_message(MessageType.COMMAND, receiver, content, **kwargs)
    
    async def send_result(self, receiver: str, content: Any, **kwargs) -> str:
        """发送结果消息"""
        return await self.send_message(MessageType.RESULT, receiver, content, **kwargs)
    
    async def send_status(self, receiver: str, content: Any, **kwargs) -> str:
        """发送状态消息"""
        return await self.send_message(MessageType.STATUS, receiver, content, **kwargs)
    
    async def send_error(self, receiver: str, content: Any, **kwargs) -> str:
        """发送错误消息"""
        return await self.send_message(MessageType.ERROR, receiver, content, **kwargs)
    
    async def broadcast(self, message_type: MessageType, content: Any) -> str:
        """向所有智能体广播消息"""
        return await self.send_message(message_type, "broadcast", content)
    
    async def retrieve_context(self, query: str, k: int = 5) -> List[Document]:
        """从Self-RAG检索相关上下文"""
        if not Config.self_rag.enabled:
            logger.warning("Self-RAG未启用，无法检索上下文")
            return []
        
        try:
            # 添加超时控制
            async def retrieve_with_timeout():
                return await self_rag.retrieve(query, k=k)
            
            try:
                # 设置15秒超时
                results = await asyncio.wait_for(retrieve_with_timeout(), timeout=15.0)
                return [doc for doc, _ in results]
            except asyncio.TimeoutError:
                logger.warning(f"检索上下文超时，将继续分析但可能缺少相关信息")
                return []
        except Exception as e:
            logger.error(f"检索上下文时出错: {e}")
            return []
