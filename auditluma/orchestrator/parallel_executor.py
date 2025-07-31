"""
并行任务执行引擎 - 层级RAG架构并行处理组件
负责任务队列管理、并发控制和错误恢复
"""

import asyncio
import time
import uuid
from typing import List, Dict, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import traceback
from concurrent.futures import ThreadPoolExecutor
import threading

from loguru import logger

from auditluma.orchestrator.task_decomposer import AuditTask, TaskType, TaskPriority, TaskCollection


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class TaskExecution:
    """任务执行状态"""
    task: AuditTask
    status: TaskStatus = TaskStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    result: Any = None
    error: Optional[Exception] = None
    retry_count: int = 0
    worker_id: Optional[str] = None
    
    @property
    def execution_time(self) -> float:
        """获取执行时间"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
    
    @property
    def is_completed(self) -> bool:
        """是否已完成"""
        return self.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED]


@dataclass
class WorkerStats:
    """工作线程统计"""
    worker_id: str
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_execution_time: float = 0.0
    current_task: Optional[str] = None
    last_activity: Optional[float] = None
    
    @property
    def average_execution_time(self) -> float:
        """平均执行时间"""
        if self.tasks_completed > 0:
            return self.total_execution_time / self.tasks_completed
        return 0.0


@dataclass
class ExecutionResult:
    """执行结果"""
    task_executions: List[TaskExecution]
    total_execution_time: float
    successful_tasks: int
    failed_tasks: int
    timeout_tasks: int
    worker_stats: Dict[str, WorkerStats]
    performance_metrics: Dict[str, Any]


class TaskQueue:
    """任务队列管理器"""
    
    def __init__(self, max_size: int = 1000):
        """初始化任务队列"""
        self.max_size = max_size
        self._queue = asyncio.PriorityQueue(maxsize=max_size)
        self._pending_tasks: Dict[str, TaskExecution] = {}
        self._completed_tasks: Dict[str, TaskExecution] = {}
        self._lock = asyncio.Lock()
        
    async def put(self, task: AuditTask) -> bool:
        """添加任务到队列"""
        try:
            # 创建任务执行对象
            task_execution = TaskExecution(task=task)
            
            # 按优先级排序（数值越小优先级越高）
            priority = task.priority.value
            
            async with self._lock:
                if len(self._pending_tasks) >= self.max_size:
                    logger.warning(f"任务队列已满，无法添加任务: {task.id}")
                    return False
                
                await self._queue.put((priority, time.time(), task_execution))
                self._pending_tasks[task.id] = task_execution
                
            logger.debug(f"任务已添加到队列: {task.id}, 优先级: {priority}")
            return True
            
        except Exception as e:
            logger.error(f"添加任务到队列失败: {task.id}, {e}")
            return False
    
    async def get(self) -> Optional[TaskExecution]:
        """从队列获取任务"""
        try:
            priority, timestamp, task_execution = await self._queue.get()
            
            async with self._lock:
                task_execution.status = TaskStatus.RUNNING
                task_execution.start_time = time.time()
                
            return task_execution
            
        except asyncio.CancelledError:
            return None
        except Exception as e:
            logger.error(f"从队列获取任务失败: {e}")
            return None
    
    async def complete_task(self, task_execution: TaskExecution):
        """标记任务完成"""
        async with self._lock:
            task_id = task_execution.task.id
            if task_id in self._pending_tasks:
                del self._pending_tasks[task_id]
                self._completed_tasks[task_id] = task_execution
                task_execution.end_time = time.time()
    
    def get_pending_count(self) -> int:
        """获取待处理任务数"""
        return len(self._pending_tasks)
    
    def get_completed_count(self) -> int:
        """获取已完成任务数"""
        return len(self._completed_tasks)
    
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """获取任务状态"""
        if task_id in self._pending_tasks:
            return self._pending_tasks[task_id].status
        elif task_id in self._completed_tasks:
            return self._completed_tasks[task_id].status
        return None


class CircuitBreaker:
    """断路器模式实现"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        """初始化断路器"""
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "closed"  # closed, open, half_open
        self._lock = threading.Lock()
    
    def can_execute(self) -> bool:
        """检查是否可以执行"""
        with self._lock:
            if self.state == "closed":
                return True
            elif self.state == "open":
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = "half_open"
                    return True
                return False
            else:  # half_open
                return True
    
    def record_success(self):
        """记录成功"""
        with self._lock:
            self.failure_count = 0
            self.state = "closed"
    
    def record_failure(self):
        """记录失败"""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.warning(f"断路器开启，失败次数: {self.failure_count}")


class RetryPolicy:
    """重试策略"""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, 
                 max_delay: float = 60.0, backoff_multiplier: float = 2.0):
        """初始化重试策略"""
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_multiplier = backoff_multiplier
    
    def should_retry(self, attempt: int, error: Exception) -> bool:
        """判断是否应该重试"""
        if attempt >= self.max_attempts:
            return False
        
        # 某些错误不应该重试
        non_retryable_errors = [
            KeyboardInterrupt,
            SystemExit,
            asyncio.CancelledError
        ]
        
        return not any(isinstance(error, err_type) for err_type in non_retryable_errors)
    
    def get_delay(self, attempt: int) -> float:
        """获取重试延迟"""
        delay = self.base_delay * (self.backoff_multiplier ** attempt)
        return min(delay, self.max_delay)


class ResourceManager:
    """资源管理器 - 动态资源分配和监控"""
    
    def __init__(self, max_memory: int = 2 * 1024 * 1024 * 1024,  # 2GB
                 max_cpu_percent: float = 80.0):
        """初始化资源管理器"""
        self.max_memory = max_memory
        self.max_cpu_percent = max_cpu_percent
        self.current_memory_usage = 0
        self.current_cpu_usage = 0.0
        self._lock = threading.Lock()
        
        # 资源监控
        self.resource_stats = {
            "memory_usage": 0,
            "cpu_usage": 0.0,
            "active_tasks": 0,
            "resource_warnings": 0
        }
    
    def can_allocate_resources(self, estimated_memory: int = 0) -> bool:
        """检查是否可以分配资源"""
        with self._lock:
            # 检查内存
            if self.current_memory_usage + estimated_memory > self.max_memory:
                return False
            
            # 检查CPU（简化检查）
            if self.current_cpu_usage > self.max_cpu_percent:
                return False
            
            return True
    
    def allocate_resources(self, memory: int = 0) -> bool:
        """分配资源"""
        with self._lock:
            if self.can_allocate_resources(memory):
                self.current_memory_usage += memory
                self.resource_stats["active_tasks"] += 1
                return True
            return False
    
    def release_resources(self, memory: int = 0):
        """释放资源"""
        with self._lock:
            self.current_memory_usage = max(0, self.current_memory_usage - memory)
            self.resource_stats["active_tasks"] = max(0, self.resource_stats["active_tasks"] - 1)
    
    def get_resource_utilization(self) -> Dict[str, Any]:
        """获取资源利用率"""
        with self._lock:
            return {
                "memory_utilization": self.current_memory_usage / self.max_memory,
                "cpu_utilization": self.current_cpu_usage / 100.0,
                "memory_usage_mb": self.current_memory_usage / (1024 * 1024),
                "active_tasks": self.resource_stats["active_tasks"]
            }


class LoadBalancer:
    """负载均衡器 - 动态负载均衡"""
    
    def __init__(self, rebalance_threshold: float = 0.3):
        """初始化负载均衡器"""
        self.rebalance_threshold = rebalance_threshold
        self.worker_loads: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def update_worker_load(self, worker_id: str, load: float):
        """更新工作线程负载"""
        with self._lock:
            self.worker_loads[worker_id] = load
    
    def get_least_loaded_worker(self) -> Optional[str]:
        """获取负载最轻的工作线程"""
        with self._lock:
            if not self.worker_loads:
                return None
            return min(self.worker_loads.keys(), key=lambda w: self.worker_loads[w])
    
    def should_rebalance(self) -> bool:
        """判断是否需要重新平衡"""
        with self._lock:
            if len(self.worker_loads) < 2:
                return False
            
            loads = list(self.worker_loads.values())
            max_load = max(loads)
            min_load = min(loads)
            
            return (max_load - min_load) > self.rebalance_threshold
    
    def get_load_distribution(self) -> Dict[str, float]:
        """获取负载分布"""
        with self._lock:
            return self.worker_loads.copy()


class DeadlockDetector:
    """死锁检测器"""
    
    def __init__(self, detection_interval: float = 30.0):
        """初始化死锁检测器"""
        self.detection_interval = detection_interval
        self.task_dependencies: Dict[str, Set[str]] = {}
        self.task_waiting: Dict[str, Set[str]] = {}
        self._lock = threading.Lock()
        self._detection_task: Optional[asyncio.Task] = None
    
    def add_task_dependency(self, task_id: str, depends_on: Set[str]):
        """添加任务依赖关系"""
        with self._lock:
            self.task_dependencies[task_id] = depends_on.copy()
    
    def add_task_waiting(self, task_id: str, waiting_for: Set[str]):
        """添加任务等待关系"""
        with self._lock:
            self.task_waiting[task_id] = waiting_for.copy()
    
    def remove_task(self, task_id: str):
        """移除任务"""
        with self._lock:
            self.task_dependencies.pop(task_id, None)
            self.task_waiting.pop(task_id, None)
    
    def detect_deadlock(self) -> List[List[str]]:
        """检测死锁环"""
        with self._lock:
            cycles = []
            visited = set()
            rec_stack = set()
            
            def dfs(task_id: str, path: List[str]) -> bool:
                if task_id in rec_stack:
                    # 找到环
                    cycle_start = path.index(task_id)
                    cycle = path[cycle_start:] + [task_id]
                    cycles.append(cycle)
                    return True
                
                if task_id in visited:
                    return False
                
                visited.add(task_id)
                rec_stack.add(task_id)
                
                # 检查依赖和等待关系
                dependencies = self.task_dependencies.get(task_id, set())
                waiting_for = self.task_waiting.get(task_id, set())
                
                for dep_task in dependencies.union(waiting_for):
                    if dfs(dep_task, path + [task_id]):
                        rec_stack.remove(task_id)
                        return True
                
                rec_stack.remove(task_id)
                return False
            
            # 检查所有任务
            all_tasks = set(self.task_dependencies.keys()).union(set(self.task_waiting.keys()))
            for task_id in all_tasks:
                if task_id not in visited:
                    dfs(task_id, [])
            
            return cycles
    
    async def start_detection(self):
        """启动死锁检测"""
        if self._detection_task is None:
            self._detection_task = asyncio.create_task(self._detection_loop())
    
    async def stop_detection(self):
        """停止死锁检测"""
        if self._detection_task:
            self._detection_task.cancel()
            try:
                await self._detection_task
            except asyncio.CancelledError:
                pass
            self._detection_task = None
    
    async def _detection_loop(self):
        """死锁检测循环"""
        while True:
            try:
                await asyncio.sleep(self.detection_interval)
                
                cycles = self.detect_deadlock()
                if cycles:
                    logger.warning(f"检测到死锁环: {cycles}")
                    # 这里可以添加死锁解决策略
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"死锁检测异常: {e}")


class BatchProcessor:
    """批处理器 - 任务批处理优化"""
    
    def __init__(self, batch_size: int = 10, batch_timeout: float = 5.0):
        """初始化批处理器"""
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.pending_batches: Dict[str, List[AuditTask]] = {}
        self._lock = threading.Lock()
    
    def can_batch_tasks(self, task1: AuditTask, task2: AuditTask) -> bool:
        """判断两个任务是否可以批处理"""
        # 相同类型的任务可以批处理
        task1_type = getattr(task1, 'task_type', getattr(task1, 'type', None))
        task2_type = getattr(task2, 'task_type', getattr(task2, 'type', None))
        if task1_type != task2_type:
            return False
        
        # 相同优先级的任务可以批处理
        if task1.priority != task2.priority:
            return False
        
        # 没有依赖关系的任务可以批处理
        if task1.id in task2.dependencies or task2.id in task1.dependencies:
            return False
        
        return True
    
    def create_batches(self, tasks: List[AuditTask]) -> List[List[AuditTask]]:
        """创建任务批次"""
        if not tasks:
            return []
        
        batches = []
        current_batch = [tasks[0]]
        
        for task in tasks[1:]:
            # 检查是否可以加入当前批次
            can_add_to_batch = (
                len(current_batch) < self.batch_size and
                all(self.can_batch_tasks(task, batch_task) for batch_task in current_batch)
            )
            
            if can_add_to_batch:
                current_batch.append(task)
            else:
                batches.append(current_batch)
                current_batch = [task]
        
        if current_batch:
            batches.append(current_batch)
        
        logger.info(f"创建了 {len(batches)} 个批次，平均批次大小: {len(tasks) / len(batches):.1f}")
        return batches


class ParallelProcessingManager:
    """增强的并行处理管理器 - 支持层级RAG的核心并行执行引擎"""
    
    def __init__(self, max_workers: int = 10, task_timeout: float = 300.0,
                 enable_load_balancing: bool = True, enable_deadlock_detection: bool = True,
                 enable_batch_processing: bool = True):
        """初始化并行处理管理器"""
        self.max_workers = max_workers
        self.task_timeout = task_timeout
        self.enable_load_balancing = enable_load_balancing
        self.enable_deadlock_detection = enable_deadlock_detection
        self.enable_batch_processing = enable_batch_processing
        
        # 任务队列和控制
        self.task_queue = TaskQueue()
        self.semaphore = asyncio.Semaphore(max_workers)
        self.active_workers: Dict[str, WorkerStats] = {}
        
        # 错误处理和重试
        self.circuit_breaker = CircuitBreaker()
        self.retry_policy = RetryPolicy()
        
        # 新增的优化组件
        self.resource_manager = ResourceManager()
        self.load_balancer = LoadBalancer() if enable_load_balancing else None
        self.deadlock_detector = DeadlockDetector() if enable_deadlock_detection else None
        self.batch_processor = BatchProcessor() if enable_batch_processing else None
        
        # 性能监控
        self.metrics = {
            "tasks_processed": 0,
            "tasks_successful": 0,
            "tasks_failed": 0,
            "tasks_timeout": 0,
            "total_execution_time": 0.0,
            "average_queue_wait_time": 0.0,
            "worker_utilization": 0.0,
            "resource_utilization": 0.0,
            "load_balance_score": 0.0,
            "deadlocks_detected": 0,
            "batches_processed": 0
        }
        
        # 控制标志
        self._shutdown_event = asyncio.Event()
        self._workers_started = False
        
        logger.info(f"增强并行处理管理器初始化完成，最大工作线程数: {max_workers}")
        logger.info(f"负载均衡: {enable_load_balancing}, 死锁检测: {enable_deadlock_detection}, 批处理: {enable_batch_processing}")
    
    async def execute_tasks(self, tasks: List[AuditTask], 
                          task_executor: Callable) -> ExecutionResult:
        """执行任务列表 - 主要接口方法（增强版）"""
        if not tasks:
            logger.warning("没有任务需要执行")
            return ExecutionResult(
                task_executions=[],
                total_execution_time=0.0,
                successful_tasks=0,
                failed_tasks=0,
                timeout_tasks=0,
                worker_stats={},
                performance_metrics=self.metrics.copy()
            )
        
        start_time = time.time()
        logger.info(f"开始并行执行 {len(tasks)} 个任务")
        
        try:
            # 1. 启动死锁检测
            if self.deadlock_detector:
                await self.deadlock_detector.start_detection()
                # 添加任务依赖关系
                for task in tasks:
                    # 提取依赖任务的ID而不是TaskDependency对象
                    dependency_ids = set(dep.task_id if hasattr(dep, 'task_id') else str(dep) for dep in task.dependencies)
                    self.deadlock_detector.add_task_dependency(task.id, dependency_ids)
            
            # 2. 批处理优化
            if self.batch_processor:
                task_batches = self.batch_processor.create_batches(tasks)
                logger.info(f"任务批处理完成，批次数: {len(task_batches)}")
                self.metrics["batches_processed"] = len(task_batches)
            else:
                task_batches = [[task] for task in tasks]
            
            # 3. 将任务添加到队列
            await self._enqueue_task_batches(task_batches)
            
            # 4. 启动工作线程
            workers = await self._start_workers(task_executor)
            
            # 5. 启动负载均衡监控
            load_balance_task = None
            if self.load_balancer:
                load_balance_task = asyncio.create_task(self._load_balance_monitor())
            
            # 6. 等待所有任务完成
            await self._wait_for_completion()
            
            # 7. 停止负载均衡监控
            if load_balance_task:
                load_balance_task.cancel()
                try:
                    await load_balance_task
                except asyncio.CancelledError:
                    pass
            
            # 8. 停止工作线程
            await self._stop_workers(workers)
            
            # 9. 停止死锁检测
            if self.deadlock_detector:
                await self.deadlock_detector.stop_detection()
            
            # 10. 收集结果
            execution_result = await self._collect_results(start_time)
            
            logger.info(f"并行执行完成，耗时: {execution_result.total_execution_time:.2f}秒")
            logger.info(f"成功: {execution_result.successful_tasks}, 失败: {execution_result.failed_tasks}")
            logger.info(f"资源利用率: {self.resource_manager.get_resource_utilization()}")
            
            return execution_result
            
        except Exception as e:
            logger.error(f"并行执行过程中出错: {e}")
            logger.error(traceback.format_exc())
            
            # 清理资源
            if self.deadlock_detector:
                await self.deadlock_detector.stop_detection()
            
            # 返回错误结果
            return ExecutionResult(
                task_executions=[],
                total_execution_time=time.time() - start_time,
                successful_tasks=0,
                failed_tasks=len(tasks),
                timeout_tasks=0,
                worker_stats=self.active_workers.copy(),
                performance_metrics=self.metrics.copy()
            )
    
    async def _enqueue_task_batches(self, task_batches: List[List[AuditTask]]):
        """将任务批次添加到队列"""
        total_tasks = sum(len(batch) for batch in task_batches)
        logger.info(f"将 {total_tasks} 个任务（{len(task_batches)} 个批次）添加到队列")
        
        enqueued_count = 0
        for batch in task_batches:
            for task in batch:
                if await self.task_queue.put(task):
                    enqueued_count += 1
                else:
                    logger.warning(f"任务入队失败: {task.id}")
        
        logger.info(f"成功入队 {enqueued_count}/{total_tasks} 个任务")
    
    async def _enqueue_tasks(self, tasks: List[AuditTask]):
        """将任务添加到队列（兼容性方法）"""
        await self._enqueue_task_batches([[task] for task in tasks])
    
    async def _start_workers(self, task_executor: Callable) -> List[asyncio.Task]:
        """启动工作线程"""
        workers = []
        
        for i in range(self.max_workers):
            worker_id = f"worker_{i}_{uuid.uuid4().hex[:6]}"
            worker_stats = WorkerStats(worker_id=worker_id)
            self.active_workers[worker_id] = worker_stats
            
            worker_task = asyncio.create_task(
                self._worker_loop(worker_id, task_executor)
            )
            workers.append(worker_task)
        
        self._workers_started = True
        logger.info(f"启动了 {len(workers)} 个工作线程")
        return workers
    
    async def _worker_loop(self, worker_id: str, task_executor: Callable):
        """工作线程主循环"""
        worker_stats = self.active_workers[worker_id]
        logger.debug(f"工作线程启动: {worker_id}")
        
        while not self._shutdown_event.is_set():
            try:
                # 获取任务
                logger.debug(f"工作线程 {worker_id} 尝试获取任务...")
                task_execution = await asyncio.wait_for(
                    self.task_queue.get(), timeout=1.0
                )
                
                if task_execution is None:
                    logger.debug(f"工作线程 {worker_id} 获取到空任务，继续等待...")
                    continue
                
                logger.info(f"工作线程 {worker_id} 获取到任务: {task_execution.task.id}")
                
                # 更新工作线程状态
                worker_stats.current_task = task_execution.task.id
                worker_stats.last_activity = time.time()
                
                # 检查断路器
                if not self.circuit_breaker.can_execute():
                    logger.warning(f"断路器开启，跳过任务: {task_execution.task.id}")
                    task_execution.status = TaskStatus.FAILED
                    task_execution.error = Exception("Circuit breaker is open")
                    await self.task_queue.complete_task(task_execution)
                    continue
                
                # 执行任务
                await self._execute_single_task(task_execution, task_executor, worker_stats)
                
            except asyncio.TimeoutError:
                # 正常的超时，继续循环
                continue
            except asyncio.CancelledError:
                logger.debug(f"工作线程被取消: {worker_id}")
                break
            except Exception as e:
                logger.error(f"工作线程异常: {worker_id}, {e}")
                logger.error(traceback.format_exc())
        
        logger.debug(f"工作线程结束: {worker_id}")
    
    async def _execute_single_task(self, task_execution: TaskExecution, 
                                 task_executor: Callable, worker_stats: WorkerStats):
        """执行单个任务（增强版）"""
        task = task_execution.task
        max_attempts = self.retry_policy.max_attempts
        
        # 估算任务资源需求
        estimated_memory = getattr(task, 'estimated_memory', 50 * 1024 * 1024)  # 默认50MB
        
        # 检查资源可用性
        if not self.resource_manager.can_allocate_resources(estimated_memory):
            logger.warning(f"资源不足，跳过任务: {task.id}")
            task_execution.status = TaskStatus.FAILED
            task_execution.error = Exception("Insufficient resources")
            await self.task_queue.complete_task(task_execution)
            return
        
        # 分配资源
        if not self.resource_manager.allocate_resources(estimated_memory):
            logger.warning(f"资源分配失败，跳过任务: {task.id}")
            task_execution.status = TaskStatus.FAILED
            task_execution.error = Exception("Resource allocation failed")
            await self.task_queue.complete_task(task_execution)
            return
        
        try:
            for attempt in range(max_attempts):
                try:
                    # 使用信号量控制并发
                    async with self.semaphore:
                        # 更新死锁检测器
                        if self.deadlock_detector:
                            waiting_for = set(task.dependencies) if task.dependencies else set()
                            self.deadlock_detector.add_task_waiting(task.id, waiting_for)
                        
                        # 设置超时
                        result = await asyncio.wait_for(
                            task_executor(task),
                            timeout=self.task_timeout
                        )
                        
                        # 任务成功
                        task_execution.status = TaskStatus.COMPLETED
                        task_execution.result = result
                        self.circuit_breaker.record_success()
                        
                        # 更新统计
                        worker_stats.tasks_completed += 1
                        worker_stats.total_execution_time += task_execution.execution_time
                        
                        # 更新负载均衡器
                        if self.load_balancer:
                            current_load = worker_stats.tasks_completed / (worker_stats.tasks_completed + worker_stats.tasks_failed + 1)
                            self.load_balancer.update_worker_load(worker_stats.worker_id, current_load)
                        
                        break
                        
                except asyncio.TimeoutError:
                    logger.warning(f"任务超时: {task.id}, 尝试次数: {attempt + 1}")
                    task_execution.status = TaskStatus.TIMEOUT
                    task_execution.error = asyncio.TimeoutError(f"Task timeout after {self.task_timeout}s")
                    
                    if not self.retry_policy.should_retry(attempt, task_execution.error):
                        worker_stats.tasks_failed += 1
                        break
                        
                except Exception as e:
                    logger.error(f"任务执行失败: {task.id}, 尝试次数: {attempt + 1}, 错误: {e}")
                    task_execution.status = TaskStatus.FAILED
                    task_execution.error = e
                    task_execution.retry_count = attempt + 1
                    
                    self.circuit_breaker.record_failure()
                    
                    if not self.retry_policy.should_retry(attempt, e):
                        worker_stats.tasks_failed += 1
                        break
                    
                    # 等待重试
                    delay = self.retry_policy.get_delay(attempt)
                    await asyncio.sleep(delay)
        
        finally:
            # 释放资源
            self.resource_manager.release_resources(estimated_memory)
            
            # 从死锁检测器移除任务
            if self.deadlock_detector:
                self.deadlock_detector.remove_task(task.id)
            
            # 完成任务
            task_execution.worker_id = worker_stats.worker_id
            worker_stats.current_task = None
            await self.task_queue.complete_task(task_execution)
    
    async def _wait_for_completion(self):
        """等待所有任务完成"""
        logger.info("等待所有任务完成...")
        
        check_interval = 1.0
        last_pending_count = -1
        
        timeout_counter = 0
        max_timeout = 300  # 5分钟超时
        
        while True:
            pending_count = self.task_queue.get_pending_count()
            
            if pending_count == 0:
                logger.info("所有任务已完成")
                break
            
            if pending_count != last_pending_count:
                logger.info(f"剩余任务数: {pending_count}")
                last_pending_count = pending_count
                timeout_counter = 0  # 重置超时计数器
            else:
                timeout_counter += check_interval
                
            # 超时检查
            if timeout_counter >= max_timeout:
                logger.error(f"任务执行超时，剩余任务数: {pending_count}")
                # 获取待处理任务的详细信息
                pending_tasks = list(self.task_queue._pending_tasks.keys())
                logger.error(f"待处理任务ID: {pending_tasks}")
                break
            
            await asyncio.sleep(check_interval)
    
    async def _stop_workers(self, workers: List[asyncio.Task]):
        """停止工作线程"""
        logger.info("停止工作线程...")
        
        # 设置停止标志
        self._shutdown_event.set()
        
        # 等待工作线程结束
        try:
            await asyncio.wait_for(
                asyncio.gather(*workers, return_exceptions=True),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.warning("工作线程停止超时，强制取消")
            for worker in workers:
                worker.cancel()
        
        self._workers_started = False
        logger.info("所有工作线程已停止")
    
    async def _load_balance_monitor(self):
        """负载均衡监控"""
        monitor_interval = 10.0  # 10秒检查一次
        
        while True:
            try:
                await asyncio.sleep(monitor_interval)
                
                if self.load_balancer and self.load_balancer.should_rebalance():
                    logger.info("检测到负载不均衡，触发重新平衡")
                    load_distribution = self.load_balancer.get_load_distribution()
                    logger.info(f"当前负载分布: {load_distribution}")
                    
                    # 这里可以实现具体的负载重新分配逻辑
                    # 例如：暂停高负载工作线程，将任务重新分配给低负载工作线程
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"负载均衡监控异常: {e}")
    
    async def _collect_results(self, start_time: float) -> ExecutionResult:
        """收集执行结果（增强版）"""
        total_execution_time = time.time() - start_time
        
        # 收集任务执行结果
        task_executions = list(self.task_queue._completed_tasks.values())
        
        # 统计结果
        successful_tasks = sum(1 for te in task_executions if te.status == TaskStatus.COMPLETED)
        failed_tasks = sum(1 for te in task_executions if te.status == TaskStatus.FAILED)
        timeout_tasks = sum(1 for te in task_executions if te.status == TaskStatus.TIMEOUT)
        
        # 获取资源利用率
        resource_utilization = self.resource_manager.get_resource_utilization()
        
        # 计算负载均衡评分
        load_balance_score = 0.0
        if self.load_balancer:
            load_distribution = self.load_balancer.get_load_distribution()
            if load_distribution:
                loads = list(load_distribution.values())
                if loads:
                    load_variance = sum((load - sum(loads)/len(loads))**2 for load in loads) / len(loads)
                    load_balance_score = 1.0 / (1.0 + load_variance)  # 方差越小，评分越高
        
        # 更新性能指标
        self.metrics.update({
            "tasks_processed": len(task_executions),
            "tasks_successful": successful_tasks,
            "tasks_failed": failed_tasks,
            "tasks_timeout": timeout_tasks,
            "total_execution_time": total_execution_time,
            "resource_utilization": resource_utilization.get("memory_utilization", 0.0),
            "load_balance_score": load_balance_score
        })
        
        # 计算工作线程利用率
        if self.active_workers:
            total_worker_time = sum(ws.total_execution_time for ws in self.active_workers.values())
            max_possible_time = total_execution_time * len(self.active_workers)
            self.metrics["worker_utilization"] = total_worker_time / max_possible_time if max_possible_time > 0 else 0.0
        
        return ExecutionResult(
            task_executions=task_executions,
            total_execution_time=total_execution_time,
            successful_tasks=successful_tasks,
            failed_tasks=failed_tasks,
            timeout_tasks=timeout_tasks,
            worker_stats=self.active_workers.copy(),
            performance_metrics=self.metrics.copy()
        )
    
    def get_status(self) -> Dict[str, Any]:
        """获取当前状态（增强版）"""
        status = {
            "workers_started": self._workers_started,
            "active_workers": len(self.active_workers),
            "pending_tasks": self.task_queue.get_pending_count(),
            "completed_tasks": self.task_queue.get_completed_count(),
            "circuit_breaker_state": self.circuit_breaker.state,
            "metrics": self.metrics.copy(),
            "resource_utilization": self.resource_manager.get_resource_utilization()
        }
        
        # 添加负载均衡信息
        if self.load_balancer:
            status["load_distribution"] = self.load_balancer.get_load_distribution()
            status["should_rebalance"] = self.load_balancer.should_rebalance()
        
        # 添加死锁检测信息
        if self.deadlock_detector:
            deadlock_cycles = self.deadlock_detector.detect_deadlock()
            status["deadlock_cycles"] = deadlock_cycles
            status["deadlocks_detected"] = len(deadlock_cycles)
        
        # 添加批处理信息
        if self.batch_processor:
            status["batch_size"] = self.batch_processor.batch_size
            status["batches_processed"] = self.metrics.get("batches_processed", 0)
        
        return status
    
    async def shutdown(self):
        """关闭并行处理管理器"""
        logger.info("关闭并行处理管理器...")
        self._shutdown_event.set()
        
        # 清理资源
        self.active_workers.clear()
        
        logger.info("并行处理管理器已关闭")


class TaskScheduler:
    """任务调度器 - 优化任务执行顺序"""
    
    def __init__(self):
        """初始化任务调度器"""
        self.scheduling_strategies = {
            "priority": self._schedule_by_priority,
            "dependency": self._schedule_by_dependency,
            "estimated_time": self._schedule_by_estimated_time,
            "hybrid": self._schedule_hybrid
        }
    
    def schedule_tasks(self, task_collection: TaskCollection, 
                      strategy: str = "hybrid") -> List[AuditTask]:
        """调度任务执行顺序"""
        if not task_collection.tasks:
            return []
        
        scheduler_func = self.scheduling_strategies.get(strategy, self._schedule_hybrid)
        scheduled_tasks = scheduler_func(task_collection)
        
        logger.info(f"任务调度完成，策略: {strategy}, 任务数: {len(scheduled_tasks)}")
        return scheduled_tasks
    
    def _schedule_by_priority(self, task_collection: TaskCollection) -> List[AuditTask]:
        """按优先级调度"""
        return sorted(task_collection.tasks, key=lambda t: t.priority.value)
    
    def _schedule_by_dependency(self, task_collection: TaskCollection) -> List[AuditTask]:
        """按依赖关系调度"""
        execution_layers = task_collection.get_execution_order()
        scheduled_tasks = []
        
        for layer in execution_layers:
            # 在每层内部按优先级排序
            layer_sorted = sorted(layer, key=lambda t: t.priority.value)
            scheduled_tasks.extend(layer_sorted)
        
        return scheduled_tasks
    
    def _schedule_by_estimated_time(self, task_collection: TaskCollection) -> List[AuditTask]:
        """按预估时间调度（长任务优先）"""
        return sorted(task_collection.tasks, key=lambda t: t.estimated_duration, reverse=True)
    
    def _schedule_hybrid(self, task_collection: TaskCollection) -> List[AuditTask]:
        """混合调度策略"""
        # 首先按依赖关系分层
        execution_layers = task_collection.get_execution_order()
        scheduled_tasks = []
        
        for layer in execution_layers:
            # 在每层内部，按优先级和预估时间的组合排序
            layer_sorted = sorted(layer, key=lambda t: (
                t.priority.value,  # 优先级（数值越小越优先）
                -t.estimated_duration  # 预估时间（长任务优先，所以取负值）
            ))
            scheduled_tasks.extend(layer_sorted)
        
        return scheduled_tasks