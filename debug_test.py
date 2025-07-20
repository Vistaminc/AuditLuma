"""
调试测试 - 检查为什么跨文件分析器没有检测到漏洞
"""

import tempfile
import asyncio
from pathlib import Path

from auditluma.models.code import SourceFile, FileType
from auditluma.analyzers.global_context_analyzer import GlobalContextAnalyzer


async def debug_global_context():
    """调试全局上下文构建"""
    print("🔍 调试全局上下文构建...")
    
    # 创建简单的测试文件
    temp_dir = Path(tempfile.mkdtemp())
    
    # 简单的输入文件
    input_file = temp_dir / "input.py"
    input_file.write_text('''
def get_user_input():
    return request.args.get('user_id')
''')
    
    # 简单的数据库文件
    db_file = temp_dir / "database.py"
    db_file.write_text('''
from input import get_user_input

def query_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
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
    
    # 详细检查实体
    print(f"📊 实体详情:")
    entities = global_context.get('entities', {})
    for entity_name, entity in entities.items():
        print(f"   - {entity_name}: {entity.type} ({entity.file_path})")
    
    print(f"\n📊 调用图:")
    call_graph = global_context.get('call_graph')
    if call_graph:
        print(f"   - 节点数: {call_graph.number_of_nodes()}")
        print(f"   - 边数: {call_graph.number_of_edges()}")
        for source, target in call_graph.edges():
            print(f"   - {source} -> {target}")
    
    print(f"\n📊 导入图:")
    import_graph = global_context.get('import_graph')
    if import_graph:
        print(f"   - 节点数: {import_graph.number_of_nodes()}")
        print(f"   - 边数: {import_graph.number_of_edges()}")
        for source, target in import_graph.edges():
            print(f"   - {source} -> {target}")
    
    # 测试跨文件分析器
    from auditluma.analyzers.cross_file_analyzer import CrossFileAnalyzer
    
    cross_analyzer = CrossFileAnalyzer(global_context)
    
    # 手动测试模式匹配
    print(f"\n🔍 测试模式匹配:")
    
    # 测试输入模式
    input_patterns = [r'request\.', r'args\.get']
    input_entities = cross_analyzer._find_entities_with_patterns(input_patterns)
    print(f"   - 输入实体: {input_entities}")
    
    # 测试SQL模式
    sql_patterns = [r'execute\s*\(', r'SELECT.*FROM']
    sql_entities = cross_analyzer._find_entities_with_patterns(sql_patterns)
    print(f"   - SQL实体: {sql_entities}")
    
    # 检测漏洞
    vulnerabilities = cross_analyzer.detect_cross_file_vulnerabilities()
    print(f"\n🚨 检测到的漏洞: {len(vulnerabilities)}")
    for vuln in vulnerabilities:
        print(f"   - {vuln.vulnerability_type}: {vuln.description}")
    
    return global_context


if __name__ == "__main__":
    asyncio.run(debug_global_context()) 