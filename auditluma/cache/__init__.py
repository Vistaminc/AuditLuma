"""
缓存模块

提供多级缓存系统支持，包括内存缓存、磁盘缓存和分布式缓存。
"""

from .hierarchical_cache import (
    HierarchicalCache,
    CacheLevel,
    CacheStats,
    CacheConfig,
    MemoryCache,
    DiskCache,
    DistributedCache,
    EvictionPolicy,
    cached,
    get_global_cache,
    set_global_cache
)

__all__ = [
    'HierarchicalCache',
    'CacheLevel', 
    'CacheStats',
    'CacheConfig',
    'MemoryCache',
    'DiskCache', 
    'DistributedCache',
    'EvictionPolicy',
    'cached',
    'get_global_cache',
    'set_global_cache'
]