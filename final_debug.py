"""
最终调试 - 修复SQL模式匹配问题并完整测试
"""

import tempfile
import asyncio
from pathlib import Path

from auditluma.models.code import SourceFile, FileType
from auditluma.analyzers.global_context_analyzer import GlobalContextAnalyzer
from auditluma.analyzers.cross_file_analyzer import CrossFileAnalyzer


async def final_debug():
    """最终调试和测试"""
    print("🔍 最终调试测试...")
    
    # 创建更明确的测试文件
    temp_dir = Path(tempfile.mkdtemp())
    
    # 输入文件
    input_file = temp_dir / "input.py"
    input_file.write_text('''
def get_user_input():
    import flask
    return flask.request.args.get('user_id')

def get_search_term():
    import flask  
    return flask.request.form.get('search')
''')
    
    # 数据库文件 - 明确包含危险的SQL操作
    db_file = temp_dir / "database.py"
    db_file.write_text('''
import sqlite3
from input import get_user_input, get_search_term

def dangerous_query():
    user_id = get_user_input()  # 用户输入
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # 危险的SQL拼接 - 应该被检测
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def another_sql_injection():
    search = get_search_term()  # 另一个用户输入
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # 另一个SQL注入点
    sql = f"SELECT name FROM products WHERE name LIKE '%{search}%'"
    cursor.execute(sql)
    return cursor.fetchall()
''')
    
    # 转换为SourceFile
    source_files = []
    for py_file in temp_dir.glob("*.py"):
        source_file = SourceFile(
            path=py_file,
            relative_path=str(py_file.relative_to(temp_dir)),
            name=py_file.name,
            extension=py_file.suffix,
            file_type=FileType.PYTHON,
            size=py_file.stat().st_size,
            content=py_file.read_text(),
            modified_time=py_file.stat().st_mtime
        )
        source_files.append(source_file)
    
    # 构建全局上下文
    analyzer = GlobalContextAnalyzer()
    global_context = await analyzer.build_global_context(source_files)
    
    # 创建跨文件分析器
    cross_analyzer = CrossFileAnalyzer(global_context)
    
    print("🔍 测试SQL模式匹配:")
    sql_patterns = [r'execute\s*\(', r'SELECT.*FROM', r'cursor\.', r'\.execute\(']
    
    # 检查每个实体
    entities = global_context.get('entities', {})
    for entity_name, entity in entities.items():
        if entity.type == "function":
            print(f"\n   检查函数: {entity_name}")
            
            # 读取文件内容
            try:
                with open(entity.file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    
                print(f"   文件内容包含:")
                for pattern in sql_patterns:
                    import re
                    if re.search(pattern, file_content, re.IGNORECASE):
                        print(f"     ✅ 匹配模式: {pattern}")
                    else:
                        print(f"     ❌ 未匹配: {pattern}")
                        
                # 检查具体的SQL关键词
                sql_keywords = ['execute(', 'SELECT', 'FROM', 'cursor.']
                for keyword in sql_keywords:
                    if keyword.lower() in file_content.lower():
                        print(f"     ✅ 包含关键词: {keyword}")
                        
            except Exception as e:
                print(f"   ❌ 读取文件失败: {e}")
    
    # 手动测试模式匹配
    print(f"\n🔍 手动模式匹配测试:")
    sql_entities = cross_analyzer._find_entities_with_patterns(sql_patterns)
    print(f"   找到SQL实体: {len(sql_entities)}")
    for entity in sql_entities:
        print(f"   - {entity}")
    
    # 运行完整的跨文件分析
    print(f"\n🔍 运行完整跨文件漏洞检测:")
    vulnerabilities = cross_analyzer.detect_cross_file_vulnerabilities()
    print(f"   检测到漏洞: {len(vulnerabilities)}")
    
    for vuln in vulnerabilities:
        print(f"\n   🚨 {vuln.vulnerability_type}")
        print(f"      严重程度: {vuln.severity}")
        print(f"      源文件: {vuln.source_file}")
        print(f"      目标文件: {vuln.target_file}")
        print(f"      描述: {vuln.description}")
        print(f"      路径: {' -> '.join(vuln.data_flow_path)}")
    
    if len(vulnerabilities) > 0:
        print("\n🎉 成功检测到跨文件漏洞！")
    else:
        print("\n⚠️ 仍然没有检测到漏洞，需要进一步调试...")
    
    return vulnerabilities


if __name__ == "__main__":
    asyncio.run(final_debug()) 