"""
代码扫描器 - 扫描和收集源代码文件进行分析
"""

import os
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Set, Optional
import asyncio
import time

from loguru import logger

from auditluma.config import Config
from auditluma.models.code import SourceFile, FileType


class CodeScanner:
    """扫描和收集源代码文件的扫描器"""
    
    def __init__(self, target_dir: str):
        """初始化代码扫描器"""
        self.target_dir = Path(target_dir)
        self.ignored_extensions = set(Config.project.ignored_extensions)
        self.ignored_directories = set(Config.project.ignored_directories)
        self.max_file_size = Config.project.max_file_size
        
        logger.info(f"初始化代码扫描器，目标目录: {self.target_dir}")
    
    def scan(self) -> List[SourceFile]:
        """扫描目录并收集所有源文件"""
        if not self.target_dir.exists():
            logger.error(f"目标目录不存在: {self.target_dir}")
            return []
        
        logger.info(f"开始扫描目录: {self.target_dir}")
        start_time = time.time()
        
        source_files = []
        files_scanned = 0
        files_skipped = 0
        
        for root, dirs, files in os.walk(self.target_dir):
            # 跳过忽略的目录
            dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]
            
            for file in files:
                files_scanned += 1
                file_path = Path(root) / file
                
                if self._should_process_file(file_path):
                    try:
                        source_file = self._create_source_file(file_path)
                        if source_file:
                            source_files.append(source_file)
                        else:
                            files_skipped += 1
                    except Exception as e:
                        logger.warning(f"处理文件时出错: {file_path}, {e}")
                        files_skipped += 1
                else:
                    files_skipped += 1
        
        end_time = time.time()
        logger.info(f"扫描完成，耗时: {end_time - start_time:.2f}秒")
        logger.info(f"扫描了 {files_scanned} 个文件，跳过了 {files_skipped} 个文件，收集了 {len(source_files)} 个源文件")
        
        return source_files
    
    async def scan_async(self) -> List[SourceFile]:
        """异步扫描目录并收集所有源文件"""
        if not self.target_dir.exists():
            logger.error(f"目标目录不存在: {self.target_dir}")
            return []
        
        logger.info(f"开始异步扫描目录: {self.target_dir}")
        start_time = time.time()
        
        # 获取所有文件路径
        file_paths = []
        for root, dirs, files in os.walk(self.target_dir):
            # 跳过忽略的目录
            dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]
            
            for file in files:
                file_path = Path(root) / file
                if self._should_process_file(file_path):
                    file_paths.append(file_path)
        
        # 异步处理文件
        tasks = []
        semaphore = asyncio.Semaphore(20)  # 限制并发数
        
        async def process_file(path):
            async with semaphore:
                try:
                    return await asyncio.to_thread(self._create_source_file, path)
                except Exception as e:
                    logger.warning(f"异步处理文件时出错: {path}, {e}")
                    return None
        
        for path in file_paths:
            task = asyncio.create_task(process_file(path))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        source_files = [result for result in results if result is not None]
        
        end_time = time.time()
        logger.info(f"异步扫描完成，耗时: {end_time - start_time:.2f}秒")
        logger.info(f"扫描了 {len(file_paths)} 个文件，收集了 {len(source_files)} 个源文件")
        
        return source_files
    
    def _should_ignore_directory(self, dir_name: str) -> bool:
        """检查是否应该忽略目录"""
        if dir_name.startswith('.'):
            return True
        
        for ignored_dir in self.ignored_directories:
            if fnmatch.fnmatch(dir_name.lower(), ignored_dir.lower()):
                return True
        
        return False
    
    def _should_process_file(self, file_path: Path) -> bool:
        """检查是否应该处理文件"""
        # 检查文件大小
        try:
            if file_path.stat().st_size > self.max_file_size:
                return False
        except Exception:
            return False
        
        # 检查文件扩展名
        extension = file_path.suffix.lower()
        if extension in self.ignored_extensions:
            return False
        
        # 检查是否是文本文件或源代码文件
        file_type = FileType.from_extension(extension)
        if file_type == FileType.OTHER:
            # 尝试检查文件是否是文本文件
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    # 检查前几行以确定是否是文本文件
                    for _ in range(5):
                        if '\0' in f.readline():  # 二进制文件通常包含空字节
                            return False
                        if f.readline() == '':  # 到达文件末尾
                            break
            except Exception:
                return False
        
        return True
    
    def _create_source_file(self, file_path: Path) -> Optional[SourceFile]:
        """从文件路径创建SourceFile对象"""
        try:
            relative_path = file_path.relative_to(self.target_dir)
            return SourceFile.from_path(file_path, self.target_dir)
        except Exception as e:
            logger.warning(f"创建SourceFile时出错: {file_path}, {e}")
            return None


class DependencyScanner:
    """扫描项目依赖关系的扫描器"""
    
    def __init__(self, target_dir: str):
        """初始化依赖扫描器"""
        self.target_dir = Path(target_dir)
        self.dependency_files = {
            "python": ["requirements.txt", "setup.py", "Pipfile", "pyproject.toml"],
            "javascript": ["package.json", "yarn.lock", "package-lock.json"],
            "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
            "csharp": ["*.csproj", "*.sln", "packages.config"],
            "ruby": ["Gemfile", "Gemfile.lock"],
            "php": ["composer.json", "composer.lock"],
            "go": ["go.mod", "go.sum"]
        }
    
    def scan(self) -> Dict[str, List[Dict[str, Any]]]:
        """扫描项目依赖文件"""
        if not self.target_dir.exists():
            logger.error(f"目标目录不存在: {self.target_dir}")
            return {}
        
        logger.info(f"开始扫描项目依赖: {self.target_dir}")
        
        dependency_info = {}
        
        for lang, file_patterns in self.dependency_files.items():
            dependency_info[lang] = []
            
            for pattern in file_patterns:
                for root, _, files in os.walk(self.target_dir):
                    for file in files:
                        if fnmatch.fnmatch(file.lower(), pattern.lower()):
                            file_path = Path(root) / file
                            try:
                                dependency_data = self._parse_dependency_file(file_path, lang)
                                if dependency_data:
                                    dependency_info[lang].append({
                                        "file": str(file_path.relative_to(self.target_dir)),
                                        "dependencies": dependency_data
                                    })
                            except Exception as e:
                                logger.warning(f"解析依赖文件时出错: {file_path}, {e}")
        
        # 清理空语言条目
        dependency_info = {k: v for k, v in dependency_info.items() if v}
        
        logger.info(f"依赖扫描完成，发现 {sum(len(v) for v in dependency_info.values())} 个依赖文件")
        return dependency_info
    
    def _parse_dependency_file(self, file_path: Path, language: str) -> List[Dict[str, str]]:
        """解析不同类型的依赖文件"""
        try:
            if language == "python":
                return self._parse_python_dependencies(file_path)
            elif language == "javascript":
                return self._parse_javascript_dependencies(file_path)
            elif language == "java":
                return self._parse_java_dependencies(file_path)
            # 其他语言的解析方法可以根据需要添加
            else:
                return []
        except Exception as e:
            logger.warning(f"解析{language}依赖文件时出错: {file_path}, {e}")
            return []
    
    def _parse_python_dependencies(self, file_path: Path) -> List[Dict[str, str]]:
        """解析Python依赖文件"""
        dependencies = []
        
        if file_path.name == "requirements.txt":
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # 处理 package==version 或 package>=version 等格式
                            parts = line.split("==")
                            if len(parts) == 2:
                                dependencies.append({
                                    "name": parts[0].strip(),
                                    "version": parts[1].strip()
                                })
                            else:
                                parts = line.split(">=")
                                if len(parts) >= 2:
                                    dependencies.append({
                                        "name": parts[0].strip(),
                                        "version": f">={parts[1].strip()}"
                                    })
                                else:
                                    dependencies.append({
                                        "name": line,
                                        "version": "latest"
                                    })
            except Exception as e:
                logger.warning(f"解析requirements.txt时出错: {e}")
        
        return dependencies
    
    def _parse_javascript_dependencies(self, file_path: Path) -> List[Dict[str, str]]:
        """解析JavaScript依赖文件"""
        dependencies = []
        
        if file_path.name == "package.json":
            try:
                import json
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                    # 处理dependencies
                    if "dependencies" in data:
                        for name, version in data["dependencies"].items():
                            dependencies.append({
                                "name": name,
                                "version": version,
                                "type": "prod"
                            })
                    
                    # 处理devDependencies
                    if "devDependencies" in data:
                        for name, version in data["devDependencies"].items():
                            dependencies.append({
                                "name": name,
                                "version": version,
                                "type": "dev"
                            })
            except Exception as e:
                logger.warning(f"解析package.json时出错: {e}")
        
        return dependencies
    
    def _parse_java_dependencies(self, file_path: Path) -> List[Dict[str, str]]:
        """解析Java依赖文件"""
        dependencies = []
        
        if file_path.name == "pom.xml":
            try:
                import xml.etree.ElementTree as ET
                
                # 注册Maven命名空间
                namespaces = {"maven": "http://maven.apache.org/POM/4.0.0"}
                ET.register_namespace("", "http://maven.apache.org/POM/4.0.0")
                
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # 查找依赖节点
                dependency_nodes = root.findall(".//maven:dependencies/maven:dependency", namespaces)
                
                for dep in dependency_nodes:
                    group_id = dep.find("maven:groupId", namespaces)
                    artifact_id = dep.find("maven:artifactId", namespaces)
                    version = dep.find("maven:version", namespaces)
                    
                    if group_id is not None and artifact_id is not None:
                        dep_info = {
                            "name": f"{group_id.text}:{artifact_id.text}",
                            "version": version.text if version is not None else "未指定"
                        }
                        dependencies.append(dep_info)
            except Exception as e:
                logger.warning(f"解析pom.xml时出错: {e}")
        
        return dependencies
