"""
简化测试 - 验证跨文件漏洞检测功能
避免编码问题，使用简单的ASCII字符
"""

import tempfile
import asyncio
from pathlib import Path

from auditluma.models.code import SourceFile, FileType
from auditluma.analyzers.global_context_analyzer import GlobalContextAnalyzer
from auditluma.analyzers.cross_file_analyzer import CrossFileAnalyzer


async def simple_test():
    """简化测试跨文件漏洞检测"""
    print("🔍 简化测试跨文件漏洞检测...")
    
    # 创建简单的测试文件 - 只使用ASCII字符
    temp_dir = Path(tempfile.mkdtemp())
    
    # 输入文件 - 用户输入源
    input_file = temp_dir / "input.py"
    input_file.write_text('''def get_user_input():
    return request.args.get("user_id")

def get_search_query():
    return request.form.get("search")
''', encoding='utf-8')
    
    # 数据库文件 - SQL执行点
    db_file = temp_dir / "database.py"  
    db_file.write_text('''from input import get_user_input

def execute_query():
    user_id = get_user_input()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    return cursor.fetchall()
''', encoding='utf-8')
    
    print(f"📁 创建测试文件在: {temp_dir}")
    print(f"   - {input_file.name}: {input_file.stat().st_size} bytes")
    print(f"   - {db_file.name}: {db_file.stat().st_size} bytes")
    
    # 验证文件内容
    print(f"\n📄 文件内容验证:")
    print(f"Input文件内容:")
    print(input_file.read_text(encoding='utf-8'))
    print(f"Database文件内容:")
    print(db_file.read_text(encoding='utf-8'))
    
    # 转换为SourceFile对象
    source_files = []
    for py_file in temp_dir.glob("*.py"):
        source_file = SourceFile(
            path=py_file,
            relative_path=str(py_file.relative_to(temp_dir)),
            name=py_file.name,
            extension=py_file.suffix,
            file_type=FileType.PYTHON,
            size=py_file.stat().st_size,
            content=py_file.read_text(encoding='utf-8'),
            modified_time=py_file.stat().st_mtime
        )
        source_files.append(source_file)
    
    print(f"\n📊 源文件对象: {len(source_files)}")
    
    # 构建全局上下文
    analyzer = GlobalContextAnalyzer()
    global_context = await analyzer.build_global_context(source_files)
    
    stats = global_context['statistics']
    print(f"\n📈 全局上下文统计:")
    print(f"   - 代码实体: {stats['total_entities']}")
    print(f"   - 调用关系: {stats['call_relationships']}")
    print(f"   - 跨文件流: {stats['cross_file_flows']}")
    
    # 创建跨文件分析器并测试
    cross_analyzer = CrossFileAnalyzer(global_context)
    
    # 测试模式匹配
    print(f"\n🔍 测试模式匹配:")
    
    # 测试输入模式
    input_patterns = [r'request\.', r'\.get\(']
    input_entities = cross_analyzer._find_entities_with_patterns(input_patterns)
    print(f"   输入实体: {len(input_entities)}")
    for entity in input_entities:
        print(f"   - {Path(entity).name}")
    
    # 测试SQL模式  
    sql_patterns = [r'execute\(', r'SELECT.*FROM', r'cursor\.']
    sql_entities = cross_analyzer._find_entities_with_patterns(sql_patterns)
    print(f"   SQL实体: {len(sql_entities)}")
    for entity in sql_entities:
        print(f"   - {Path(entity).name}")
    
    # 手动检查跨文件关系
    print(f"\n🔗 检查跨文件关系:")
    entities = global_context.get('entities', {})
    
    for input_entity in input_entities:
        for sql_entity in sql_entities:
            input_ent = entities.get(input_entity)
            sql_ent = entities.get(sql_entity)
            
            if input_ent and sql_ent and input_ent.file_path != sql_ent.file_path:
                print(f"   检查: {Path(input_ent.file_path).name} -> {Path(sql_ent.file_path).name}")
                
                # 检查跨文件关系
                has_relationship = cross_analyzer._check_cross_file_relationship(input_ent, sql_ent)
                print(f"   跨文件关系: {has_relationship}")
                
                if has_relationship:
                    print(f"   ✅ 发现跨文件数据流!")
                    
                    # 检查数据流路径
                    has_flow = cross_analyzer._has_data_flow_path(input_entity, sql_entity)
                    print(f"   数据流路径: {has_flow}")
    
    # 运行完整的漏洞检测
    print(f"\n🚨 运行跨文件漏洞检测:")
    vulnerabilities = cross_analyzer.detect_cross_file_vulnerabilities()
    
    print(f"   检测到漏洞: {len(vulnerabilities)}")
    
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n   漏洞 {i}:")
            print(f"   - 类型: {vuln.vulnerability_type}")
            print(f"   - 严重程度: {vuln.severity}")
            print(f"   - 源文件: {Path(vuln.source_file).name}")
            print(f"   - 目标文件: {Path(vuln.target_file).name}")
            print(f"   - 描述: {vuln.description}")
            print(f"   - 建议: {vuln.recommendation}")
            
        print(f"\n🎉 成功检测到 {len(vulnerabilities)} 个跨文件漏洞!")
    else:
        print(f"\n⚠️  没有检测到漏洞")
        
        # 提供调试信息
        print(f"\n🔧 调试信息:")
        print(f"   - 输入实体: {len(input_entities)} 个")
        print(f"   - SQL实体: {len(sql_entities)} 个")
        print(f"   - 调用关系: {stats['call_relationships']} 个")
        print(f"   - 跨文件流: {stats['cross_file_flows']} 个")
    
    return vulnerabilities


if __name__ == "__main__":
    result = asyncio.run(simple_test())
    print(f"\n📋 测试结果: {'通过' if len(result) > 0 else '需要进一步调试'}") 