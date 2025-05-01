"""
编排智能体 - 负责协调多个智能体的协作
"""

from typing import Dict, List, Any, Optional, Callable, Union
import asyncio
import json
from datetime import datetime

from loguru import logger

from auditluma.agents.base import BaseAgent
from auditluma.config import Config
from auditluma.mcp.protocol import (
    AgentMessage, MessageType, MessagePriority, 
    message_bus, agent_coordinator
)


class OrchestratorAgent(BaseAgent):
    """编排智能体 - 负责协调其他智能体的工作流程"""
    
    def __init__(self, agent_id: Optional[str] = None, model_spec: Optional[str] = None):
        """初始化编排智能体"""
        super().__init__(agent_id, agent_type="coordinator", model_spec=model_spec)
        self.description = "协调所有智能体和工作流程"
        
        # 初始化LLM客户端，使用特定任务的默认模型
        from auditluma.utils import init_llm_client
        # 使用指定模型或任务默认模型，格式为"model@provider"
        self.model_spec = model_spec or Config.default_models.summarization
        # 解析模型名称，只保存实际的模型名称部分
        self.model_name, _ = Config.parse_model_spec(self.model_spec)
        # 初始化LLM客户端
        self.llm_client = init_llm_client(self.model_spec)
        logger.info(f"编排智能体使用模型: {self.model_name}")
        
        # 跟踪工作流程状态
        self.workflow_status = {}
        self.pending_tasks = 0
        self.completed_tasks = 0
        
        # 特定消息处理器
        self.register_handler(MessageType.COMMAND, self._handle_workflow_command)
        self.register_handler(MessageType.STATUS, self._handle_status)
    
    async def execute_task(self, task_type: str, task_data: Any) -> Any:
        """执行任务 - 实现基类的抽象方法"""
        logger.info(f"编排智能体执行任务: {task_type}")
        
        if task_type == "coordinate_workflow":
            return await self._coordinate_workflow(task_data)
        elif task_type == "assign_tasks":
            return await self._assign_tasks(task_data)
        elif task_type == "monitor_progress":
            return await self._monitor_progress(task_data)
        else:
            logger.warning(f"未知的任务类型: {task_type}")
            return None
    
    async def _handle_workflow_command(self, message: AgentMessage) -> None:
        """处理工作流程命令消息"""
        workflow_data = message.content
        workflow_id = workflow_data.get("workflow_id", "unknown")
        action = workflow_data.get("action")
        
        logger.info(f"收到工作流程命令: {workflow_id}, 动作: {action}")
        
        if action == "start":
            await self._start_workflow(workflow_id, workflow_data)
        elif action == "stop":
            await self._stop_workflow(workflow_id)
        elif action == "pause":
            await self._pause_workflow(workflow_id)
        elif action == "resume":
            await self._resume_workflow(workflow_id)
        else:
            logger.warning(f"未知的工作流程动作: {action}")
    
    async def _handle_status(self, message: AgentMessage) -> None:
        """处理状态更新消息"""
        status_data = message.content
        agent_id = message.sender
        task_id = status_data.get("task_id", "unknown")
        status = status_data.get("status", "unknown")
        
        logger.debug(f"收到状态更新: 智能体={agent_id}, 任务={task_id}, 状态={status}")
        
        if status == "completed":
            self.completed_tasks += 1
            if task_id in self.workflow_status:
                self.workflow_status[task_id] = "completed"
        
        # 检查是否所有任务都已完成
        if self.pending_tasks > 0 and self.completed_tasks >= self.pending_tasks:
            logger.info(f"所有任务已完成 ({self.completed_tasks}/{self.pending_tasks})")
            await self._workflow_completed()
    
    async def _coordinate_workflow(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """协调整体工作流程"""
        workflow_type = data.get("workflow_type", "default")
        workflow_id = data.get("workflow_id", f"workflow_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        logger.info(f"开始协调工作流程: {workflow_id}, 类型: {workflow_type}")
        
        # 初始化工作流程状态
        self.workflow_status = {}
        self.pending_tasks = 0
        self.completed_tasks = 0
        
        # 根据工作流程类型分配不同的任务
        if workflow_type == "security_audit":
            return await self._coordinate_security_audit(data)
        elif workflow_type == "code_structure":
            return await self._coordinate_code_structure(data)
        elif workflow_type == "full_analysis":
            return await self._coordinate_full_analysis(data)
        else:
            logger.warning(f"未知的工作流程类型: {workflow_type}")
            return {"status": "error", "message": f"未知的工作流程类型: {workflow_type}"}
    
    async def _assign_tasks(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """分配任务给其他智能体"""
        tasks = data.get("tasks", [])
        workflow_id = data.get("workflow_id", "unknown")
        
        if not tasks:
            logger.warning(f"没有任务可分配，工作流程: {workflow_id}")
            return {"status": "warning", "message": "没有任务可分配"}
        
        logger.info(f"分配 {len(tasks)} 个任务，工作流程: {workflow_id}")
        
        self.pending_tasks = len(tasks)
        for task in tasks:
            task_id = task.get("task_id", f"task_{len(self.workflow_status)}")
            agent_type = task.get("agent_type")
            task_type = task.get("task_type")
            task_data = task.get("data", {})
            
            self.workflow_status[task_id] = "pending"
            
            # 通过协调器获取可用的智能体
            agent_id = agent_coordinator.get_agent_by_type(agent_type)
            if agent_id:
                logger.debug(f"将任务 {task_id} 分配给智能体 {agent_id}")
                await self.send_task(
                    receiver=agent_id,
                    task_type=task_type,
                    content=task_data,
                    message_id=task_id
                )
            else:
                logger.warning(f"找不到类型为 {agent_type} 的智能体，任务 {task_id} 未分配")
                self.workflow_status[task_id] = "failed"
                self.completed_tasks += 1
        
        return {
            "status": "success", 
            "message": f"已分配 {len(tasks)} 个任务",
            "pending_tasks": self.pending_tasks
        }
    
    async def _monitor_progress(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """监控工作流程进度"""
        workflow_id = data.get("workflow_id", "unknown")
        
        completed = sum(1 for status in self.workflow_status.values() if status == "completed")
        pending = sum(1 for status in self.workflow_status.values() if status == "pending")
        failed = sum(1 for status in self.workflow_status.values() if status == "failed")
        total = len(self.workflow_status)
        
        logger.info(f"工作流程 {workflow_id} 进度: {completed}/{total} 完成, {pending} 进行中, {failed} 失败")
        
        return {
            "workflow_id": workflow_id,
            "total_tasks": total,
            "completed": completed,
            "pending": pending,
            "failed": failed,
            "progress": (completed / total) * 100 if total > 0 else 0
        }
    
    async def _start_workflow(self, workflow_id: str, data: Dict[str, Any]) -> None:
        """启动工作流程"""
        logger.info(f"启动工作流程: {workflow_id}")
        
        # 发送工作流程开始通知给所有智能体
        await message_bus.broadcast(
            sender=self.agent_id,
            message_type=MessageType.TASK,
            content={
                "task_type": "workflow_start",
                "workflow_id": workflow_id,
                "workflow_type": data.get("workflow_type", "default")
            }
        )
    
    async def _stop_workflow(self, workflow_id: str) -> None:
        """停止工作流程"""
        logger.info(f"停止工作流程: {workflow_id}")
        
        # 发送工作流程停止命令给所有智能体
        await message_bus.broadcast(
            sender=self.agent_id,
            message_type=MessageType.COMMAND,
            content={
                "command": "stop_tasks",
                "workflow_id": workflow_id
            }
        )
    
    async def _pause_workflow(self, workflow_id: str) -> None:
        """暂停工作流程"""
        logger.info(f"暂停工作流程: {workflow_id}")
        
        # 发送工作流程暂停命令给所有智能体
        await message_bus.broadcast(
            sender=self.agent_id,
            message_type=MessageType.COMMAND,
            content={
                "command": "pause_tasks",
                "workflow_id": workflow_id
            }
        )
    
    async def _resume_workflow(self, workflow_id: str) -> None:
        """恢复工作流程"""
        logger.info(f"恢复工作流程: {workflow_id}")
        
        # 发送工作流程恢复命令给所有智能体
        await message_bus.broadcast(
            sender=self.agent_id,
            message_type=MessageType.COMMAND,
            content={
                "command": "resume_tasks",
                "workflow_id": workflow_id
            }
        )
    
    async def _workflow_completed(self) -> None:
        """工作流程完成处理"""
        logger.info("工作流程已完成")
        
        # 发送工作流程完成通知给所有智能体
        await message_bus.broadcast(
            sender=self.agent_id,
            message_type=MessageType.STATUS,
            content={
                "status": "workflow_completed"
            }
        )
    
    async def _coordinate_security_audit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """协调安全审计工作流程"""
        source_files = data.get("source_files", [])
        
        if not source_files:
            return {"status": "warning", "message": "没有源文件可审计"}
        
        tasks = []
        for i, file in enumerate(source_files):
            tasks.append({
                "task_id": f"security_audit_{i}",
                "agent_type": "security_analyst",
                "task_type": "analyze_security",
                "data": {"source_file": file}
            })
        
        # 分配安全审计任务
        return await self._assign_tasks({
            "workflow_id": data.get("workflow_id"),
            "tasks": tasks
        })
    
    async def _coordinate_code_structure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """协调代码结构分析工作流程"""
        code_units = data.get("code_units", [])
        
        if not code_units:
            return {"status": "warning", "message": "没有代码单元可分析"}
        
        tasks = []
        for i, unit in enumerate(code_units):
            tasks.append({
                "task_id": f"code_structure_{i}",
                "agent_type": "code_analyzer",
                "task_type": "analyze_structure",
                "data": {"code_unit": unit}
            })
        
        # 分配代码结构分析任务
        return await self._assign_tasks({
            "workflow_id": data.get("workflow_id"),
            "tasks": tasks
        })
    
    async def _coordinate_full_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """协调完整分析工作流程"""
        # 1. 代码结构分析
        structure_result = await self._coordinate_code_structure(data)
        
        # 等待代码结构分析完成
        while self.pending_tasks > self.completed_tasks:
            await asyncio.sleep(0.5)
        
        # 2. 安全审计
        security_result = await self._coordinate_security_audit(data)
        
        # 3. 最后将其他分析任务整合在一起
        return {
            "status": "success",
            "structure_result": structure_result,
            "security_result": security_result
        }
