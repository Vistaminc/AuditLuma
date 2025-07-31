"""
层级缓存系统

实现多级缓存架构，包括L1内存缓存、L2磁盘缓存和可选的分布式缓存。
支持缓存策略、失效机制和性能监控。
"""

import asyncio
import hashlib
import json
import logging
import pickle
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import OrderedDict
import threading
import weakref
import os
import tempfile

logger = logging.getLogger(__name__)


class CacheLevel(Enum):
    """缓存级别"""
    L1_MEMORY = "l1_memory"
    L2_DISK = "l2_disk"
    DISTRIBUTED = "distributed"


class EvictionPolicy(Enum):
    """缓存淘汰策略"""
    LRU = "lru"  # 最近最少使用
    LFU = "lfu"  # 最少使用频率
    TTL = "ttl"  # 基于时间
    FIFO = "fifo"  # 先进先出


@dataclass
class CacheEntry:
    """缓存条目"""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl: Optional[float] = None
    size: int = 0
    
    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl
    
    def touch(self):
        """更新访问时间和计数"""
        self.last_accessed = time.time()
        self.access_count += 1


@dataclass
class CacheStats:
    """缓存统计信息"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    max_size: int = 0
    hit_rate: float = 0.0
    memory_usage: int = 0
    
    def update_hit_rate(self):
        """更新命中率"""
        total = self.hits + self.misses
        self.hit_rate = self.hits / total if total > 0 else 0.0


class CacheInterface(ABC):
    """缓存接口"""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """设置缓存值"""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """删除缓存值"""
        pass
    
    @abstractmethod
    async def clear(self) -> bool:
        """清空缓存"""
        pass
    
    @abstractmethod
    def get_stats(self) -> CacheStats:
        """获取统计信息"""
        pass


class MemoryCache(CacheInterface):
    """L1内存缓存"""
    
    def __init__(self, max_size: int = 1000, max_memory: int = 256 * 1024 * 1024,
                 eviction_policy: EvictionPolicy = EvictionPolicy.LRU):
        self.max_size = max_size
        self.max_memory = max_memory
        self.eviction_policy = eviction_policy
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order = OrderedDict()  # 用于LRU
        self._stats = CacheStats(max_size=max_size)
        self._lock = threading.RLock()
        self._memory_usage = 0
    
    async def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._stats.misses += 1
                self._stats.update_hit_rate()
                return None
            
            if entry.is_expired():
                await self.delete(key)
                self._stats.misses += 1
                self._stats.update_hit_rate()
                return None
            
            entry.touch()
            self._update_access_order(key)
            self._stats.hits += 1
            self._stats.update_hit_rate()
            return entry.value
    
    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """设置缓存值"""
        with self._lock:
            # 计算值的大小
            try:
                size = len(pickle.dumps(value))
            except Exception:
                size = 1024  # 默认大小
            
            # 检查内存限制
            if size > self.max_memory:
                logger.warning(f"Value too large for cache: {size} bytes")
                return False
            
            # 如果键已存在，先删除旧值
            if key in self._cache:
                await self.delete(key)
            
            # 确保有足够空间
            while (len(self._cache) >= self.max_size or 
                   self._memory_usage + size > self.max_memory):
                if not await self._evict_one():
                    return False
            
            # 创建新条目
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                last_accessed=time.time(),
                ttl=ttl,
                size=size
            )
            
            self._cache[key] = entry
            self._access_order[key] = True
            self._memory_usage += size
            self._stats.size = len(self._cache)
            self._stats.memory_usage = self._memory_usage
            
            return True
    
    async def delete(self, key: str) -> bool:
        """删除缓存值"""
        with self._lock:
            entry = self._cache.pop(key, None)
            if entry is None:
                return False
            
            self._access_order.pop(key, None)
            self._memory_usage -= entry.size
            self._stats.size = len(self._cache)
            self._stats.memory_usage = self._memory_usage
            return True
    
    async def clear(self) -> bool:
        """清空缓存"""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._memory_usage = 0
            self._stats.size = 0
            self._stats.memory_usage = 0
            return True
    
    def get_stats(self) -> CacheStats:
        """获取统计信息"""
        with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                size=self._stats.size,
                max_size=self._stats.max_size,
                hit_rate=self._stats.hit_rate,
                memory_usage=self._stats.memory_usage
            )
    
    def _update_access_order(self, key: str):
        """更新访问顺序（用于LRU）"""
        if self.eviction_policy == EvictionPolicy.LRU:
            self._access_order.move_to_end(key)
    
    async def _evict_one(self) -> bool:
        """淘汰一个条目"""
        if not self._cache:
            return False
        
        key_to_evict = None
        
        if self.eviction_policy == EvictionPolicy.LRU:
            key_to_evict = next(iter(self._access_order))
        elif self.eviction_policy == EvictionPolicy.LFU:
            key_to_evict = min(self._cache.keys(), 
                             key=lambda k: self._cache[k].access_count)
        elif self.eviction_policy == EvictionPolicy.TTL:
            # 找到最早过期的条目
            expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
            if expired_keys:
                key_to_evict = min(expired_keys, 
                                 key=lambda k: self._cache[k].created_at)
            else:
                key_to_evict = next(iter(self._cache))
        elif self.eviction_policy == EvictionPolicy.FIFO:
            key_to_evict = min(self._cache.keys(), 
                             key=lambda k: self._cache[k].created_at)
        
        if key_to_evict:
            await self.delete(key_to_evict)
            self._stats.evictions += 1
            return True
        
        return False


class DiskCache(CacheInterface):
    """L2磁盘缓存"""
    
    def __init__(self, cache_dir: Optional[str] = None, max_size: int = 10000,
                 max_disk_usage: int = 2 * 1024 * 1024 * 1024):  # 2GB
        self.cache_dir = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir()) / "auditluma_cache"
        self.max_size = max_size
        self.max_disk_usage = max_disk_usage
        self._stats = CacheStats(max_size=max_size)
        self._lock = threading.RLock()
        self._index: Dict[str, Dict[str, Any]] = {}  # 缓存索引
        
        # 确保缓存目录存在
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # 加载现有索引
        asyncio.create_task(self._load_index())
    
    async def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        with self._lock:
            if key not in self._index:
                self._stats.misses += 1
                self._stats.update_hit_rate()
                return None
            
            entry_info = self._index[key]
            
            # 检查是否过期
            if entry_info.get('ttl') and time.time() - entry_info['created_at'] > entry_info['ttl']:
                await self.delete(key)
                self._stats.misses += 1
                self._stats.update_hit_rate()
                return None
            
            # 读取文件
            file_path = self.cache_dir / f"{self._hash_key(key)}.cache"
            try:
                with open(file_path, 'rb') as f:
                    value = pickle.load(f)
                
                # 更新访问信息
                entry_info['last_accessed'] = time.time()
                entry_info['access_count'] = entry_info.get('access_count', 0) + 1
                
                self._stats.hits += 1
                self._stats.update_hit_rate()
                return value
            
            except Exception as e:
                logger.error(f"Failed to read cache file {file_path}: {e}")
                await self.delete(key)
                self._stats.misses += 1
                self._stats.update_hit_rate()
                return None
    
    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """设置缓存值"""
        with self._lock:
            try:
                # 序列化值
                data = pickle.dumps(value)
                size = len(data)
                
                # 检查磁盘空间限制
                if size > self.max_disk_usage:
                    logger.warning(f"Value too large for disk cache: {size} bytes")
                    return False
                
                # 确保有足够空间
                while (len(self._index) >= self.max_size or 
                       self._get_total_disk_usage() + size > self.max_disk_usage):
                    if not await self._evict_one():
                        return False
                
                # 写入文件
                file_path = self.cache_dir / f"{self._hash_key(key)}.cache"
                with open(file_path, 'wb') as f:
                    f.write(data)
                
                # 更新索引
                self._index[key] = {
                    'created_at': time.time(),
                    'last_accessed': time.time(),
                    'access_count': 0,
                    'ttl': ttl,
                    'size': size,
                    'file_path': str(file_path)
                }
                
                self._stats.size = len(self._index)
                await self._save_index()
                return True
            
            except Exception as e:
                logger.error(f"Failed to write cache file: {e}")
                return False
    
    async def delete(self, key: str) -> bool:
        """删除缓存值"""
        with self._lock:
            if key not in self._index:
                return False
            
            entry_info = self._index.pop(key)
            file_path = Path(entry_info['file_path'])
            
            try:
                if file_path.exists():
                    file_path.unlink()
            except Exception as e:
                logger.error(f"Failed to delete cache file {file_path}: {e}")
            
            self._stats.size = len(self._index)
            await self._save_index()
            return True
    
    async def clear(self) -> bool:
        """清空缓存"""
        with self._lock:
            try:
                # 删除所有缓存文件
                for entry_info in self._index.values():
                    file_path = Path(entry_info['file_path'])
                    if file_path.exists():
                        file_path.unlink()
                
                self._index.clear()
                self._stats.size = 0
                await self._save_index()
                return True
            
            except Exception as e:
                logger.error(f"Failed to clear disk cache: {e}")
                return False
    
    def get_stats(self) -> CacheStats:
        """获取统计信息"""
        with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                size=self._stats.size,
                max_size=self._stats.max_size,
                hit_rate=self._stats.hit_rate,
                memory_usage=self._get_total_disk_usage()
            )
    
    def _hash_key(self, key: str) -> str:
        """生成键的哈希值"""
        return hashlib.md5(key.encode()).hexdigest()
    
    def _get_total_disk_usage(self) -> int:
        """获取总磁盘使用量"""
        return sum(entry['size'] for entry in self._index.values())
    
    async def _evict_one(self) -> bool:
        """淘汰一个条目"""
        if not self._index:
            return False
        
        # 使用LRU策略
        key_to_evict = min(self._index.keys(), 
                          key=lambda k: self._index[k]['last_accessed'])
        
        await self.delete(key_to_evict)
        self._stats.evictions += 1
        return True
    
    async def _load_index(self):
        """加载缓存索引"""
        index_file = self.cache_dir / "index.json"
        try:
            if index_file.exists():
                with open(index_file, 'r') as f:
                    self._index = json.load(f)
                self._stats.size = len(self._index)
        except Exception as e:
            logger.error(f"Failed to load cache index: {e}")
            self._index = {}
    
    async def _save_index(self):
        """保存缓存索引"""
        index_file = self.cache_dir / "index.json"
        try:
            with open(index_file, 'w') as f:
                json.dump(self._index, f)
        except Exception as e:
            logger.error(f"Failed to save cache index: {e}")


class DistributedCache(CacheInterface):
    """分布式缓存（Redis实现）"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 key_prefix: str = "auditluma:"):
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self._redis = None
        self._stats = CacheStats()
        self._lock = threading.RLock()
        
        # 尝试导入redis
        try:
            import redis.asyncio as redis
            self._redis_module = redis
        except ImportError:
            logger.warning("Redis not available, distributed cache disabled")
            self._redis_module = None
    
    async def _get_redis(self):
        """获取Redis连接"""
        if self._redis is None and self._redis_module:
            try:
                self._redis = self._redis_module.from_url(self.redis_url)
                await self._redis.ping()
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self._redis = None
        return self._redis
    
    async def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        redis = await self._get_redis()
        if not redis:
            self._stats.misses += 1
            self._stats.update_hit_rate()
            return None
        
        try:
            data = await redis.get(self.key_prefix + key)
            if data is None:
                self._stats.misses += 1
                self._stats.update_hit_rate()
                return None
            
            value = pickle.loads(data)
            self._stats.hits += 1
            self._stats.update_hit_rate()
            return value
        
        except Exception as e:
            logger.error(f"Failed to get from Redis: {e}")
            self._stats.misses += 1
            self._stats.update_hit_rate()
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """设置缓存值"""
        redis = await self._get_redis()
        if not redis:
            return False
        
        try:
            data = pickle.dumps(value)
            if ttl:
                await redis.setex(self.key_prefix + key, int(ttl), data)
            else:
                await redis.set(self.key_prefix + key, data)
            return True
        
        except Exception as e:
            logger.error(f"Failed to set in Redis: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """删除缓存值"""
        redis = await self._get_redis()
        if not redis:
            return False
        
        try:
            result = await redis.delete(self.key_prefix + key)
            return result > 0
        
        except Exception as e:
            logger.error(f"Failed to delete from Redis: {e}")
            return False
    
    async def clear(self) -> bool:
        """清空缓存"""
        redis = await self._get_redis()
        if not redis:
            return False
        
        try:
            keys = await redis.keys(self.key_prefix + "*")
            if keys:
                await redis.delete(*keys)
            return True
        
        except Exception as e:
            logger.error(f"Failed to clear Redis cache: {e}")
            return False
    
    def get_stats(self) -> CacheStats:
        """获取统计信息"""
        return CacheStats(
            hits=self._stats.hits,
            misses=self._stats.misses,
            evictions=self._stats.evictions,
            size=0,  # Redis不容易获取准确大小
            max_size=0,
            hit_rate=self._stats.hit_rate,
            memory_usage=0
        )


@dataclass
class CacheConfig:
    """缓存配置"""
    # L1内存缓存配置
    l1_max_size: int = 1000
    l1_max_memory: int = 256 * 1024 * 1024  # 256MB
    l1_eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    
    # L2磁盘缓存配置
    l2_cache_dir: Optional[str] = None
    l2_max_size: int = 10000
    l2_max_disk_usage: int = 2 * 1024 * 1024 * 1024  # 2GB
    
    # 分布式缓存配置
    distributed_enabled: bool = False
    redis_url: str = "redis://localhost:6379"
    redis_key_prefix: str = "auditluma:"
    
    # 通用配置
    default_ttl: Optional[float] = 3600  # 1小时
    enable_stats: bool = True
    stats_interval: float = 60  # 统计间隔（秒）


class HierarchicalCache:
    """层级缓存系统"""
    
    def __init__(self, config: Optional[CacheConfig] = None):
        self.config = config or CacheConfig()
        
        # 初始化各级缓存
        self.l1_cache = MemoryCache(
            max_size=self.config.l1_max_size,
            max_memory=self.config.l1_max_memory,
            eviction_policy=self.config.l1_eviction_policy
        )
        
        self.l2_cache = DiskCache(
            cache_dir=self.config.l2_cache_dir,
            max_size=self.config.l2_max_size,
            max_disk_usage=self.config.l2_max_disk_usage
        )
        
        self.distributed_cache = None
        if self.config.distributed_enabled:
            self.distributed_cache = DistributedCache(
                redis_url=self.config.redis_url,
                key_prefix=self.config.redis_key_prefix
            )
        
        # 统计信息
        self._global_stats = CacheStats()
        self._stats_lock = threading.RLock()
        
        # 启动统计任务
        if self.config.enable_stats:
            asyncio.create_task(self._stats_updater())
    
    async def get(self, key: str) -> Optional[Any]:
        """多级缓存获取"""
        start_time = time.time()
        
        try:
            # L1缓存
            value = await self.l1_cache.get(key)
            if value is not None:
                await self._record_hit(CacheLevel.L1_MEMORY, time.time() - start_time)
                return value
            
            # L2缓存
            value = await self.l2_cache.get(key)
            if value is not None:
                # 回填到L1缓存
                await self.l1_cache.set(key, value, self.config.default_ttl)
                await self._record_hit(CacheLevel.L2_DISK, time.time() - start_time)
                return value
            
            # 分布式缓存
            if self.distributed_cache:
                value = await self.distributed_cache.get(key)
                if value is not None:
                    # 回填到L1和L2缓存
                    await self.l1_cache.set(key, value, self.config.default_ttl)
                    await self.l2_cache.set(key, value, self.config.default_ttl)
                    await self._record_hit(CacheLevel.DISTRIBUTED, time.time() - start_time)
                    return value
            
            # 所有缓存都未命中
            await self._record_miss(time.time() - start_time)
            return None
        
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            await self._record_miss(time.time() - start_time)
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """多级缓存设置"""
        if ttl is None:
            ttl = self.config.default_ttl
        
        success = True
        
        try:
            # 设置到所有缓存级别
            l1_success = await self.l1_cache.set(key, value, ttl)
            l2_success = await self.l2_cache.set(key, value, ttl)
            
            distributed_success = True
            if self.distributed_cache:
                distributed_success = await self.distributed_cache.set(key, value, ttl)
            
            success = l1_success or l2_success or distributed_success
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            success = False
        
        return success
    
    async def delete(self, key: str) -> bool:
        """从所有缓存级别删除"""
        success = False
        
        try:
            l1_success = await self.l1_cache.delete(key)
            l2_success = await self.l2_cache.delete(key)
            
            distributed_success = True
            if self.distributed_cache:
                distributed_success = await self.distributed_cache.delete(key)
            
            success = l1_success or l2_success or distributed_success
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
        
        return success
    
    async def clear(self) -> bool:
        """清空所有缓存"""
        success = True
        
        try:
            await self.l1_cache.clear()
            await self.l2_cache.clear()
            
            if self.distributed_cache:
                await self.distributed_cache.clear()
            
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            success = False
        
        return success
    
    def get_stats(self) -> Dict[str, CacheStats]:
        """获取所有缓存级别的统计信息"""
        stats = {
            'l1_memory': self.l1_cache.get_stats(),
            'l2_disk': self.l2_cache.get_stats(),
            'global': self._global_stats
        }
        
        if self.distributed_cache:
            stats['distributed'] = self.distributed_cache.get_stats()
        
        return stats
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        stats = self.get_stats()
        
        total_hits = sum(s.hits for s in stats.values())
        total_misses = sum(s.misses for s in stats.values())
        total_requests = total_hits + total_misses
        
        return {
            'total_requests': total_requests,
            'total_hits': total_hits,
            'total_misses': total_misses,
            'overall_hit_rate': total_hits / total_requests if total_requests > 0 else 0.0,
            'l1_hit_rate': stats['l1_memory'].hit_rate,
            'l2_hit_rate': stats['l2_disk'].hit_rate,
            'memory_usage': stats['l1_memory'].memory_usage,
            'disk_usage': stats['l2_disk'].memory_usage,
            'cache_levels': len([k for k in stats.keys() if k != 'global'])
        }
    
    async def _record_hit(self, level: CacheLevel, response_time: float):
        """记录缓存命中"""
        with self._stats_lock:
            self._global_stats.hits += 1
            self._global_stats.update_hit_rate()
    
    async def _record_miss(self, response_time: float):
        """记录缓存未命中"""
        with self._stats_lock:
            self._global_stats.misses += 1
            self._global_stats.update_hit_rate()
    
    async def _stats_updater(self):
        """定期更新统计信息"""
        while True:
            try:
                await asyncio.sleep(self.config.stats_interval)
                
                # 更新全局统计
                stats = self.get_stats()
                logger.info(f"Cache performance: {self.get_performance_metrics()}")
                
            except Exception as e:
                logger.error(f"Stats updater error: {e}")


# 缓存装饰器
def cached(ttl: Optional[float] = None, key_prefix: str = ""):
    """缓存装饰器"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # 生成缓存键
            key_parts = [key_prefix, func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = ":".join(key_parts)
            
            # 尝试从缓存获取
            if hasattr(func, '_cache'):
                cached_result = await func._cache.get(cache_key)
                if cached_result is not None:
                    return cached_result
            
            # 执行函数
            result = await func(*args, **kwargs)
            
            # 存储到缓存
            if hasattr(func, '_cache') and result is not None:
                await func._cache.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    return decorator


# 全局缓存实例
_global_cache: Optional[HierarchicalCache] = None


def get_global_cache() -> HierarchicalCache:
    """获取全局缓存实例"""
    global _global_cache
    if _global_cache is None:
        _global_cache = HierarchicalCache()
    return _global_cache


def set_global_cache(cache: HierarchicalCache):
    """设置全局缓存实例"""
    global _global_cache
    _global_cache = cache