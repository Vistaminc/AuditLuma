"""
多智能体协作协议 (MCP) 实现
"""

from typing import Dict, List, Any, Optional, Callable, Union
from enum import Enum
from dataclasses import dataclass, field
import json
import asyncio
from datetime import datetime

from loguru import logger

from auditluma.config import Config


class MessageType(str, Enum):
    """消息类型枚举"""
    QUERY = "query"           # 询问或请求信息
    RESPONSE = "response"     # 对查询的响应
    COMMAND = "command"       # 执行命令的指令
    RESULT = "result"         # 命令结果
    STATUS = "status"         # 状态更新
    ERROR = "error"           # 错误通知
    TASK = "task"             # 任务分配
    FEEDBACK = "feedback"     # 反馈信息


class MessagePriority(str, Enum):
    """消息优先级枚举"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AgentMessage:
    """智能体间通信的消息"""
    message_id: str           # 唯一消息ID
    message_type: MessageType # 消息类型
    sender: str               # 发送者ID
    receiver: str             # 接收者ID
    content: Any              # 消息内容
    timestamp: float          # 时间戳
    priority: MessagePriority = MessagePriority.MEDIUM  # 优先级
    reply_to: Optional[str] = None  # 回复的消息ID
    metadata: Dict[str, Any] = field(default_factory=dict)  # 元数据

    @classmethod
    def create(cls, 
              sender: str,
              receiver: str,
              message_type: MessageType,
              content: Any,
              reply_to: Optional[str] = None,
              priority: MessagePriority = MessagePriority.MEDIUM,
              metadata: Optional[Dict[str, Any]] = None) -> 'AgentMessage':
        """创建新消息"""
        import uuid
        return cls(
            message_id=str(uuid.uuid4()),
            message_type=message_type,
            sender=sender,
            receiver=receiver,
            content=content,
            timestamp=datetime.now().timestamp(),
            priority=priority,
            reply_to=reply_to,
            metadata=metadata or {}
        )

    def to_dict(self) -> Dict[str, Any]:
        """将消息转换为字典"""
        return {
            "message_id": self.message_id,
            "message_type": self.message_type.value,
            "sender": self.sender,
            "receiver": self.receiver,
            "content": self.content,
            "timestamp": self.timestamp,
            "priority": self.priority.value,
            "reply_to": self.reply_to,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentMessage':
        """从字典创建消息"""
        return cls(
            message_id=data["message_id"],
            message_type=MessageType(data["message_type"]),
            sender=data["sender"],
            receiver=data["receiver"],
            content=data["content"],
            timestamp=data["timestamp"],
            priority=MessagePriority(data["priority"]),
            reply_to=data.get("reply_to"),
            metadata=data.get("metadata", {})
        )


class MessageBus:
    """消息总线，处理智能体之间的通信"""
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.message_history: List[AgentMessage] = []
        self.max_history_size = 1000

    async def publish(self, message: AgentMessage) -> None:
        """发布消息到总线"""
        logger.debug(f"发布消息: {message.message_id} 从 {message.sender} 到 {message.receiver}")
        
        # 添加到历史记录
        self.message_history.append(message)
        if len(self.message_history) > self.max_history_size:
            self.message_history.pop(0)
        
        # 向所有订阅者分发消息
        if message.receiver in self.subscribers:
            for callback in self.subscribers[message.receiver]:
                try:
                    await callback(message)
                except Exception as e:
                    logger.error(f"处理消息时出错: {e}")
        
        # 如果是广播，发送给所有订阅者
        if message.receiver == "broadcast":
            for receiver, callbacks in self.subscribers.items():
                if receiver != message.sender:  # 不要发回给发送者
                    for callback in callbacks:
                        try:
                            await callback(message)
                        except Exception as e:
                            logger.error(f"处理广播消息时出错: {e}")

    def subscribe(self, agent_id: str, callback: Callable) -> None:
        """注册一个智能体接收消息"""
        if agent_id not in self.subscribers:
            self.subscribers[agent_id] = []
        self.subscribers[agent_id].append(callback)
        logger.debug(f"智能体 {agent_id} 已订阅消息总线")

    def unsubscribe(self, agent_id: str) -> None:
        """取消智能体的消息订阅"""
        if agent_id in self.subscribers:
            del self.subscribers[agent_id]
            logger.debug(f"智能体 {agent_id} 已取消订阅消息总线")

    def get_message_history(self, 
                          agent_id: Optional[str] = None, 
                          limit: int = 100) -> List[AgentMessage]:
        """获取消息历史记录"""
        if agent_id:
            # 过滤特定智能体的消息
            filtered = [m for m in self.message_history if m.sender == agent_id or m.receiver == agent_id]
            return filtered[-limit:] if len(filtered) > limit else filtered
        else:
            # 返回所有消息的历史记录
            return self.message_history[-limit:] if len(self.message_history) > limit else self.message_history


# 全局消息总线实例
message_bus = MessageBus()


class AgentCoordinator:
    """智能体协调器，管理多个智能体之间的协作"""
    def __init__(self):
        self.agents = {}  # 注册的智能体
        self.tasks = {}   # 正在运行的任务
    
    def register_agent(self, agent_id: str, agent_type: str, description: str) -> None:
        """注册智能体到协调器"""
        self.agents[agent_id] = {
            "id": agent_id,
            "type": agent_type,
            "description": description,
            "status": "idle",
            "registered_at": datetime.now().timestamp()
        }
        logger.info(f"智能体已注册: {agent_id} ({agent_type})")
    
    def unregister_agent(self, agent_id: str) -> None:
        """从协调器中注销智能体"""
        if agent_id in self.agents:
            del self.agents[agent_id]
            logger.info(f"智能体已注销: {agent_id}")
    
    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """获取智能体信息"""
        return self.agents.get(agent_id)
    
    def get_all_agents(self) -> List[Dict[str, Any]]:
        """获取所有已注册的智能体"""
        return list(self.agents.values())
    
    def get_agents_by_type(self, agent_type: str) -> List[Dict[str, Any]]:
        """按类型获取智能体"""
        return [agent for agent in self.agents.values() if agent["type"] == agent_type]
    
    def get_agent_by_type(self, agent_type: str) -> Optional[str]:
        """获取指定类型的第一个可用智能体ID
        
        Args:
            agent_type: 智能体类型
            
        Returns:
            智能体ID，如果找不到则返回None
        """
        agents = self.get_agents_by_type(agent_type)
        if agents:
            # 返回第一个空闲的智能体，如果没有空闲的，则返回第一个
            idle_agents = [a for a in agents if a["status"] == "idle"]
            if idle_agents:
                return idle_agents[0]["id"]
            return agents[0]["id"]
        return None
    
    async def create_task(self, 
                       task_id: str, 
                       task_type: str, 
                       target_agents: List[str], 
                       data: Any) -> str:
        """创建新任务并分配给智能体"""
        self.tasks[task_id] = {
            "id": task_id,
            "type": task_type,
            "status": "created",
            "agents": target_agents,
            "data": data,
            "created_at": datetime.now().timestamp(),
            "updated_at": datetime.now().timestamp(),
            "results": {}
        }
        
        # 向每个目标智能体发送任务消息
        for agent_id in target_agents:
            if agent_id in self.agents:
                message = AgentMessage.create(
                    sender="coordinator",
                    receiver=agent_id,
                    message_type=MessageType.TASK,
                    content={
                        "task_id": task_id,
                        "task_type": task_type,
                        "data": data
                    },
                    priority=MessagePriority.HIGH
                )
                await message_bus.publish(message)
                
                # 更新智能体状态
                self.agents[agent_id]["status"] = "busy"
        
        logger.info(f"已创建任务: {task_id}, 分配给 {len(target_agents)} 个智能体")
        return task_id
    
    async def update_task_status(self, 
                            task_id: str, 
                            agent_id: str, 
                            status: str, 
                            result: Optional[Any] = None) -> None:
        """更新任务状态"""
        if task_id in self.tasks:
            self.tasks[task_id]["updated_at"] = datetime.now().timestamp()
            
            # 保存智能体的结果
            if result is not None:
                self.tasks[task_id]["results"][agent_id] = result
            
            # 检查是否所有智能体都已完成
            all_completed = True
            for agent_id in self.tasks[task_id]["agents"]:
                if agent_id not in self.tasks[task_id]["results"]:
                    all_completed = False
                    break
            
            # 如果所有智能体都已完成，将任务标记为已完成
            if all_completed:
                self.tasks[task_id]["status"] = "completed"
                logger.info(f"任务已完成: {task_id}")
                
                # 向所有参与的智能体发送完成通知
                for agent_id in self.tasks[task_id]["agents"]:
                    message = AgentMessage.create(
                        sender="coordinator",
                        receiver=agent_id,
                        message_type=MessageType.STATUS,
                        content={
                            "task_id": task_id,
                            "status": "completed",
                            "results": self.tasks[task_id]["results"]
                        }
                    )
                    await message_bus.publish(message)
                    
                    # 更新智能体状态为空闲
                    if agent_id in self.agents:
                        self.agents[agent_id]["status"] = "idle"
            else:
                # 如果任务仍在进行中，更新状态
                self.tasks[task_id]["status"] = status
    
    def get_task_info(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务信息"""
        return self.tasks.get(task_id)
    
    def get_all_tasks(self) -> List[Dict[str, Any]]:
        """获取所有任务"""
        return list(self.tasks.values())


# 全局智能体协调器实例
agent_coordinator = AgentCoordinator()
