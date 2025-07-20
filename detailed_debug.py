"""
详细调试 - 检查跨文件关系检测的每一步
"""

import tempfile
import asyncio
from pathlib import Path

from auditluma.models.code import SourceFile, FileType
from auditluma.analyzers.global_context_analyzer import GlobalContextAnalyzer
from auditluma.analyzers.cross_file_analyzer import CrossFileAnalyzer


async def detailed_debug():
    """详细调试跨文件检测"""
    print("🔍 详细调试跨文件检测...")
    
    # 创建测试文件
    temp_dir = Path(tempfile.mkdtemp())
    
    # 输入文件
    input_file = temp_dir / "input.py"
    input_file.write_text('''
def get_user_input():
    return request.args.get('user_id')
''')
    
    # 数据库文件
    db_file = temp_dir / "database.py"
    db_file.write_text('''
from input import get_user_input

def query_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def vulnerable_query():
    user_id = get_user_input()  # 调用input.py中的函数
    return query_user(user_id)  # 传递给SQL查询
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
    
    print("📊 实体列表:")
    entities = global_context.get('entities', {})
    for entity_name, entity in entities.items():
        print(f"   - {entity_name}")
        print(f"     类型: {entity.type}")
        print(f"     文件: {entity.file_path}")
    
    # 创建跨文件分析器
    cross_analyzer = CrossFileAnalyzer(global_context)
    
    # 手动测试每个步骤
    print(f"\n🔍 步骤1: 查找输入实体")
    input_patterns = [r'request\.', r'args\.get']
    input_entities = cross_analyzer._find_entities_with_patterns(input_patterns)
    print(f"   找到输入实体: {len(input_entities)}")
    for entity in input_entities:
        print(f"   - {entity}")
    
    print(f"\n🔍 步骤2: 查找SQL实体")
    sql_patterns = [r'execute\s*\(', r'SELECT.*FROM', r'cursor\.']
    sql_entities = cross_analyzer._find_entities_with_patterns(sql_patterns)
    print(f"   找到SQL实体: {len(sql_entities)}")
    for entity in sql_entities:
        print(f"   - {entity}")
    
    print(f"\n🔍 步骤3: 检查跨文件关系")
    for input_entity in input_entities:
        for sql_entity in sql_entities:
            input_ent = entities.get(input_entity)
            sql_ent = entities.get(sql_entity)
            
            if input_ent and sql_ent and input_ent.file_path != sql_ent.file_path:
                print(f"\n   检查: {input_entity} -> {sql_entity}")
                print(f"   输入文件: {input_ent.file_path}")
                print(f"   SQL文件: {sql_ent.file_path}")
                
                # 手动检查跨文件关系
                has_relationship = cross_analyzer._check_cross_file_relationship(input_ent, sql_ent)
                print(f"   有跨文件关系: {has_relationship}")
                
                # 检查数据流路径
                has_flow = cross_analyzer._has_data_flow_path(input_entity, sql_entity)
                print(f"   有数据流路径: {has_flow}")
                
                # 详细检查文件内容
                print(f"\n   详细检查SQL文件内容:")
                with open(sql_ent.file_path, 'r') as f:
                    sql_content = f.read()
                    print(f"   内容预览: {sql_content[:200]}...")
                    
                    # 检查导入
                    input_module = Path(input_ent.file_path).stem
                    print(f"   查找模块: {input_module}")
                    print(f"   包含'from {input_module} import': {'from ' + input_module + ' import' in sql_content}")
                    
                    # 检查函数调用
                    input_func = input_ent.name.split("::")[-1]
                    print(f"   查找函数调用: {input_func}")
                    print(f"   包含'{input_func}(': {input_func + '(' in sql_content}")
    
    print(f"\n🔍 步骤4: 运行完整检测")
    sql_vulns = cross_analyzer._detect_cross_file_sql_injection()
    print(f"   检测到SQL注入漏洞: {len(sql_vulns)}")
    for vuln in sql_vulns:
        print(f"   - {vuln.vulnerability_type}: {vuln.description}")
    
    return global_context


if __name__ == "__main__":
    asyncio.run(detailed_debug()) 