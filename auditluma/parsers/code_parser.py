"""
代码解析器 - 负责将源代码解析为可分析的代码单元
支持多种编程语言的代码结构提取
"""

import ast
import re
import uuid
from typing import List, Dict, Any, Optional, Tuple, Union
import asyncio
from pathlib import Path

from loguru import logger

from auditluma.models.code import SourceFile, CodeUnit, FileType


async def extract_code_units(source_file: SourceFile) -> List[CodeUnit]:
    """从源文件中提取代码单元"""
    try:
        parser = get_parser_for_file_type(source_file.file_type)
        if parser:
            return await parser(source_file)
        else:
            logger.warning(f"不支持解析文件类型: {source_file.file_type}, 使用通用解析器")
            return await generic_parser(source_file)
    except Exception as e:
        logger.error(f"解析源文件时出错: {source_file.path}, {e}")
        # 如果解析失败，将整个文件作为一个代码单元返回
        return [create_whole_file_unit(source_file)]


def get_parser_for_file_type(file_type: FileType) -> Optional[callable]:
    """根据文件类型获取合适的解析器"""
    parsers = {
        FileType.PYTHON: python_parser,
        FileType.JAVASCRIPT: javascript_parser,
        FileType.TYPESCRIPT: javascript_parser,  # TypeScript使用与JavaScript相同的解析器
        FileType.JAVA: java_parser,
        FileType.CSHARP: csharp_parser,
        FileType.CPP: cpp_parser,
        FileType.C: cpp_parser,
        FileType.GO: go_parser,
        FileType.RUBY: ruby_parser,
        FileType.PHP: php_parser,
        FileType.HTML: html_parser,
        FileType.CSS: css_parser,
        FileType.JSON: json_parser,
        FileType.XML: xml_parser,
        FileType.YAML: yaml_parser,
        FileType.SQL: sql_parser
    }
    return parsers.get(file_type)


def create_whole_file_unit(source_file: SourceFile) -> CodeUnit:
    """将整个文件作为一个代码单元"""
    return CodeUnit(
        id=f"file_{uuid.uuid4().hex}",
        name=source_file.name,
        type="file",
        source_file=source_file,
        start_line=0,
        end_line=len(source_file.content.splitlines()),
        content=source_file.content,
        parent_id=None
    )


async def generic_parser(source_file: SourceFile) -> List[CodeUnit]:
    """通用代码解析器，适用于任何文本文件"""
    # 将整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units = [file_unit]
    
    # 尝试使用正则表达式识别可能的函数和类定义
    patterns = [
        # 尝试匹配函数定义
        (r"(?:function|def|func)\s+([a-zA-Z0-9_]+)\s*\(", "function"),
        # 尝试匹配类定义
        (r"(?:class|interface|struct)\s+([a-zA-Z0-9_]+)", "class"),
        # 尝试匹配方法定义
        (r"(?:public|private|protected)?\s+(?:static)?\s+(?:[a-zA-Z0-9_<>]+)\s+([a-zA-Z0-9_]+)\s*\(", "method")
    ]
    
    lines = source_file.content.splitlines()
    
    for pattern, unit_type in patterns:
        for i, line in enumerate(lines):
            matches = re.search(pattern, line)
            if matches:
                name = matches.group(1)
                # 简单估计单元结束位置（这不是很准确，但对于通用解析足够了）
                end_line = find_end_of_block(lines, i)
                
                content = "\n".join(lines[i:end_line+1])
                
                unit = CodeUnit(
                    id=f"{unit_type}_{uuid.uuid4().hex}",
                    name=name,
                    type=unit_type,
                    source_file=source_file,
                    start_line=i,
                    end_line=end_line,
                    content=content,
                    parent_id=file_unit.id
                )
                
                units.append(unit)
    
    return units


def find_end_of_block(lines: List[str], start_line: int) -> int:
    """估计代码块的结束行"""
    # 这是一个简单的启发式方法，可能不适用于所有语言
    # 对于许多语言，代码块通常使用括号、大括号或缩进来标识
    
    opening_brackets = 0
    opening_braces = 0
    indent_level = None
    
    # 检查第一行的缩进级别
    first_line = lines[start_line]
    indent_match = re.match(r'^(\s*)', first_line)
    if indent_match:
        indent_level = len(indent_match.group(1))
    
    for i in range(start_line, len(lines)):
        line = lines[i]
        
        # 统计括号和大括号的平衡
        opening_brackets += line.count('(') - line.count(')')
        opening_braces += line.count('{') - line.count('}')
        
        # 基于缩进的块结束检测
        if indent_level is not None:
            line_indent_match = re.match(r'^(\s*)', line)
            if line_indent_match:
                line_indent = len(line_indent_match.group(1))
                if line.strip() and line_indent <= indent_level:
                    if i > start_line:  # 不要在开始行就结束
                        return i - 1
        
        # 基于括号平衡的检测
        if opening_brackets == 0 and opening_braces == 0:
            # 对于某些语言，可能需要寻找终止符如分号
            if ';' in line:
                return i
    
    # 如果没找到明确的结束，返回文件末尾
    return len(lines) - 1


async def python_parser(source_file: SourceFile) -> List[CodeUnit]:
    """Python代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    try:
        # 解析Python代码
        tree = ast.parse(source_file.content)
        
        # 提取函数和类
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # 函数定义
                parent_id = file_unit.id
                
                # 获取函数源代码
                start_line = node.lineno - 1  # ast行号从1开始
                end_line = find_ast_node_end(node, source_file.content)
                content = "\n".join(source_file.content.splitlines()[start_line:end_line+1])
                
                function_unit = CodeUnit(
                    id=f"function_{uuid.uuid4().hex}",
                    name=node.name,
                    type="function",
                    source_file=source_file,
                    start_line=start_line,
                    end_line=end_line,
                    content=content,
                    parent_id=parent_id
                )
                
                units.append(function_unit)
                
            elif isinstance(node, ast.ClassDef):
                # 类定义
                parent_id = file_unit.id
                
                # 获取类源代码
                start_line = node.lineno - 1
                end_line = find_ast_node_end(node, source_file.content)
                content = "\n".join(source_file.content.splitlines()[start_line:end_line+1])
                
                class_unit = CodeUnit(
                    id=f"class_{uuid.uuid4().hex}",
                    name=node.name,
                    type="class",
                    source_file=source_file,
                    start_line=start_line,
                    end_line=end_line,
                    content=content,
                    parent_id=parent_id
                )
                
                units.append(class_unit)
                
                # 提取类方法
                for method in [n for n in ast.walk(node) if isinstance(n, ast.FunctionDef)]:
                    if method in node.body:
                        method_start_line = method.lineno - 1
                        method_end_line = find_ast_node_end(method, source_file.content)
                        method_content = "\n".join(source_file.content.splitlines()[method_start_line:method_end_line+1])
                        
                        method_unit = CodeUnit(
                            id=f"method_{uuid.uuid4().hex}",
                            name=f"{node.name}.{method.name}",
                            type="method",
                            source_file=source_file,
                            start_line=method_start_line,
                            end_line=method_end_line,
                            content=method_content,
                            parent_id=class_unit.id
                        )
                        
                        units.append(method_unit)
                        
    except SyntaxError as e:
        logger.error(f"Python语法错误: {source_file.path}, {e}")
    except Exception as e:
        logger.error(f"解析Python文件时出错: {source_file.path}, {e}")
    
    return units


def find_ast_node_end(node: ast.AST, source_code: str) -> int:
    """找到AST节点的结束行号"""
    try:
        # 对于有body的节点（如函数和类），找到最后一个子节点的结束位置
        if hasattr(node, 'body') and node.body:
            last_node = node.body[-1]
            if hasattr(last_node, 'end_lineno'):
                return last_node.end_lineno - 1
            else:
                return find_ast_node_end(last_node, source_code)
        
        # 对于有end_lineno属性的节点，直接使用它
        if hasattr(node, 'end_lineno'):
            return node.end_lineno - 1
        
        # 如果都不适用，使用启发式方法:
        # 从节点的起始行开始，向下扫描直到找到一个不是当前块一部分的行
        lines = source_code.splitlines()
        start_line = node.lineno - 1
        indent_match = re.match(r'^(\s*)', lines[start_line])
        node_indent = len(indent_match.group(1)) if indent_match else 0
        
        for i in range(start_line + 1, len(lines)):
            line = lines[i]
            if line.strip() and not line.strip().startswith('#'):
                indent_match = re.match(r'^(\s*)', line)
                if indent_match and len(indent_match.group(1)) <= node_indent:
                    return i - 1
        
        # 如果没找到，返回文件的最后一行
        return len(lines) - 1
        
    except Exception:
        # 发生错误时，返回节点的起始行作为结束行
        return node.lineno - 1


async def javascript_parser(source_file: SourceFile) -> List[CodeUnit]:
    """JavaScript/TypeScript代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # 尝试使用正则表达式匹配JavaScript函数和类
    lines = source_file.content.splitlines()
    
    # 函数定义模式 (包括箭头函数、命名函数和方法)
    function_patterns = [
        r"(?:function\s+)([a-zA-Z0-9_$]+)\s*\(",  # 命名函数
        r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*function\s*\(",  # 函数表达式
        r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*\([^)]*\)\s*=>\s*{",  # 箭头函数
        r"([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*{",  # 方法
        r"([a-zA-Z0-9_$]+)\s*:\s*function\s*\("  # 对象方法
    ]
    
    # 类定义模式
    class_patterns = [
        r"class\s+([a-zA-Z0-9_$]+)",  # ES6 类
    ]
    
    # 解析函数
    for pattern in function_patterns:
        for i, line in enumerate(lines):
            matches = re.search(pattern, line)
            if matches:
                name = matches.group(1)
                end_line = find_js_block_end(lines, i)
                
                content = "\n".join(lines[i:end_line+1])
                
                function_unit = CodeUnit(
                    id=f"function_{uuid.uuid4().hex}",
                    name=name,
                    type="function",
                    source_file=source_file,
                    start_line=i,
                    end_line=end_line,
                    content=content,
                    parent_id=file_unit.id
                )
                
                units.append(function_unit)
    
    # 解析类
    for pattern in class_patterns:
        for i, line in enumerate(lines):
            matches = re.search(pattern, line)
            if matches:
                class_name = matches.group(1)
                end_line = find_js_block_end(lines, i)
                
                content = "\n".join(lines[i:end_line+1])
                
                class_unit = CodeUnit(
                    id=f"class_{uuid.uuid4().hex}",
                    name=class_name,
                    type="class",
                    source_file=source_file,
                    start_line=i,
                    end_line=end_line,
                    content=content,
                    parent_id=file_unit.id
                )
                
                units.append(class_unit)
                
                # 尝试解析类方法
                class_content = content
                class_lines = class_content.splitlines()
                
                method_pattern = r"^\s*([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*{"
                for j, class_line in enumerate(class_lines):
                    method_match = re.search(method_pattern, class_line)
                    if method_match:
                        method_name = method_match.group(1)
                        # 跳过构造函数和特殊方法
                        if method_name == "constructor" or method_name.startswith("_"):
                            continue
                            
                        method_global_line = i + j
                        method_end_line = find_js_block_end(lines, method_global_line)
                        
                        method_content = "\n".join(lines[method_global_line:method_end_line+1])
                        
                        method_unit = CodeUnit(
                            id=f"method_{uuid.uuid4().hex}",
                            name=f"{class_name}.{method_name}",
                            type="method",
                            source_file=source_file,
                            start_line=method_global_line,
                            end_line=method_end_line,
                            content=method_content,
                            parent_id=class_unit.id
                        )
                        
                        units.append(method_unit)
    
    return units


def find_js_block_end(lines: List[str], start_line: int) -> int:
    """找到JavaScript代码块的结束行"""
    braces_count = 0
    in_string = False
    string_char = None
    
    # 检查第一行的开括号
    first_line = lines[start_line]
    for char in first_line:
        if char == '{' and not in_string:
            braces_count += 1
        elif char == '}' and not in_string:
            braces_count -= 1
        elif char in ['"', "'"]:
            if not in_string:
                in_string = True
                string_char = char
            elif char == string_char:
                in_string = False
    
    # 如果第一行没有开括号，查找下一行
    if braces_count == 0:
        for i in range(start_line + 1, min(start_line + 5, len(lines))):
            line = lines[i]
            if '{' in line:
                start_line = i
                braces_count = 1
                break
    else:
        braces_count = 1  # 重置为1，因为我们已经找到了开始括号
    
    # 寻找匹配的闭括号
    for i in range(start_line + 1, len(lines)):
        line = lines[i]
        
        for char in line:
            if char == '{' and not in_string:
                braces_count += 1
            elif char == '}' and not in_string:
                braces_count -= 1
                if braces_count == 0:
                    return i
            elif char in ['"', "'"]:
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
    
    # 如果没找到匹配的闭括号，返回文件结束
    return len(lines) - 1


async def java_parser(source_file: SourceFile) -> List[CodeUnit]:
    """Java代码解析器"""
    # 与通用解析类似，但针对Java语法定制
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    lines = source_file.content.splitlines()
    
    # Java类模式
    class_pattern = r"(?:public|private|protected)?\s+(?:static)?\s+(?:final)?\s+class\s+([a-zA-Z0-9_]+)"
    
    # Java方法模式
    method_pattern = r"(?:public|private|protected)?\s+(?:static)?\s+(?:final)?\s+(?:[a-zA-Z0-9_<>[\]]+)\s+([a-zA-Z0-9_]+)\s*\("
    
    # 解析类
    for i, line in enumerate(lines):
        class_match = re.search(class_pattern, line)
        if class_match:
            class_name = class_match.group(1)
            end_line = find_java_block_end(lines, i)
            
            content = "\n".join(lines[i:end_line+1])
            
            class_unit = CodeUnit(
                id=f"class_{uuid.uuid4().hex}",
                name=class_name,
                type="class",
                source_file=source_file,
                start_line=i,
                end_line=end_line,
                content=content,
                parent_id=file_unit.id
            )
            
            units.append(class_unit)
            
            # 解析类内的方法
            in_comment = False
            for j in range(i, end_line):
                line = lines[j]
                
                # 处理多行注释
                if "/*" in line:
                    in_comment = True
                if "*/" in line:
                    in_comment = False
                    continue
                if in_comment:
                    continue
                
                # 跳过单行注释
                if line.strip().startswith("//"):
                    continue
                
                method_match = re.search(method_pattern, line)
                if method_match:
                    method_name = method_match.group(1)
                    method_end = find_java_block_end(lines, j)
                    
                    method_content = "\n".join(lines[j:method_end+1])
                    
                    method_unit = CodeUnit(
                        id=f"method_{uuid.uuid4().hex}",
                        name=f"{class_name}.{method_name}",
                        type="method",
                        source_file=source_file,
                        start_line=j,
                        end_line=method_end,
                        content=method_content,
                        parent_id=class_unit.id
                    )
                    
                    units.append(method_unit)
    
    return units


def find_java_block_end(lines: List[str], start_line: int) -> int:
    """找到Java代码块的结束行"""
    braces_count = 0
    in_string = False
    in_char = False
    in_comment = False
    
    # 找到第一个开括号
    found_first_brace = False
    for i in range(start_line, len(lines)):
        line = lines[i]
        
        # 处理注释
        if "/*" in line and not in_string:
            in_comment = True
        if "*/" in line and in_comment:
            in_comment = False
            continue
        
        # 处理字符串
        for j, char in enumerate(line):
            if char == '"' and not in_char and not (j > 0 and line[j-1] == '\\'):
                in_string = not in_string
            elif char == "'" and not in_string and not (j > 0 and line[j-1] == '\\'):
                in_char = not in_char
            elif char == '{' and not in_string and not in_char and not in_comment:
                braces_count += 1
                found_first_brace = True
            elif char == '}' and not in_string and not in_char and not in_comment:
                braces_count -= 1
                if found_first_brace and braces_count == 0:
                    return i
        
        # 处理行尾注释
        if "//" in line and not in_string and not in_char:
            comment_start = line.index("//")
            line = line[:comment_start]
    
    return len(lines) - 1


async def csharp_parser(source_file: SourceFile) -> List[CodeUnit]:
    """C#代码解析器"""
    # C#的解析与Java类似，但有一些语法差异
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # C#代码解析逻辑...
    # (这里可以参考java_parser实现，适当修改正则表达式以匹配C#语法)
    
    return units


async def cpp_parser(source_file: SourceFile) -> List[CodeUnit]:
    """C/C++代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # C/C++代码解析逻辑...
    # (这里需要处理C/C++的语法特点，如.h头文件、命名空间等)
    
    return units


async def go_parser(source_file: SourceFile) -> List[CodeUnit]:
    """Go代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # Go代码解析逻辑...
    
    return units


async def ruby_parser(source_file: SourceFile) -> List[CodeUnit]:
    """Ruby代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # Ruby代码解析逻辑...
    
    return units


async def php_parser(source_file: SourceFile) -> List[CodeUnit]:
    """PHP代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # PHP代码解析逻辑...
    
    return units


async def html_parser(source_file: SourceFile) -> List[CodeUnit]:
    """HTML代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # HTML代码解析逻辑...
    # (可以提取脚本和样式部分作为单独的单元)
    
    return units


async def css_parser(source_file: SourceFile) -> List[CodeUnit]:
    """CSS代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # CSS代码解析逻辑...
    # (可以提取每个样式规则作为单独的单元)
    
    return units


async def json_parser(source_file: SourceFile) -> List[CodeUnit]:
    """JSON代码解析器"""
    units = []
    
    # JSON文件通常作为一个整体处理
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    return units


async def xml_parser(source_file: SourceFile) -> List[CodeUnit]:
    """XML代码解析器"""
    units = []
    
    # XML文件可以按元素或整体处理
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # XML代码解析逻辑...
    
    return units


async def yaml_parser(source_file: SourceFile) -> List[CodeUnit]:
    """YAML代码解析器"""
    units = []
    
    # YAML文件通常作为一个整体处理
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    return units


async def sql_parser(source_file: SourceFile) -> List[CodeUnit]:
    """SQL代码解析器"""
    units = []
    
    # 添加整个文件作为一个单元
    file_unit = create_whole_file_unit(source_file)
    units.append(file_unit)
    
    # SQL代码解析逻辑...
    # (可以提取每个SQL语句作为单独的单元)
    
    return units
