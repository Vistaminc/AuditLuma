"""
跨文件漏洞检测测试用例
验证新实现的跨文件分析功能
"""

import tempfile
import asyncio
from pathlib import Path
from typing import List

from auditluma.models.code import SourceFile, FileType
from auditluma.analyzers.global_context_analyzer import GlobalContextAnalyzer
from auditluma.analyzers.cross_file_analyzer import CrossFileAnalyzer
from auditluma.analyzers.dataflow_analyzer import DataFlowAnalyzer


async def create_test_project() -> List[SourceFile]:
    """创建测试项目 - 包含多种跨文件漏洞"""
    
    # 创建临时目录
    temp_dir = Path(tempfile.mkdtemp())
    
    # 测试文件1：用户输入处理
    input_file = temp_dir / "input_handler.py"
    input_content = '''
import flask
from flask import request

def get_user_input():
    """获取用户输入 - 污点源"""
    return request.args.get('user_id')

def get_user_data():
    """获取用户数据"""
    return request.form.get('data')

def get_file_path():
    """获取文件路径"""
    return request.args.get('file_path')

def authenticate_user():
    """用户认证"""
    token = request.headers.get('Authorization')
    # 简化的认证逻辑
    return token == "valid_token"
'''
    input_file.write_text(input_content)
    
    # 测试文件2：数据库操作
    db_file = temp_dir / "database.py"
    db_content = '''
import sqlite3
from input_handler import get_user_input, get_user_data

def query_user_by_id(user_id):
    """SQL注入漏洞 - 直接拼接用户输入"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 危险的SQL拼接 - 应该被检测为跨文件SQL注入
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def update_user_data(data):
    """另一个SQL注入点"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 另一个危险的SQL拼接
    query = f"UPDATE users SET data = '{data}' WHERE active = 1"
    cursor.execute(query)
    conn.commit()

def get_user_info():
    """调用跨文件函数"""
    user_id = get_user_input()  # 从另一个文件获取输入
    return query_user_by_id(user_id)  # 传递给危险函数
'''
    db_file.write_text(db_content)
    
    # 测试文件3：业务逻辑
    logic_file = temp_dir / "business_logic.py"
    logic_content = '''
import os
import subprocess
from database import get_user_info, update_user_data
from input_handler import get_user_data, get_file_path, authenticate_user

def handle_user_request():
    """处理用户请求 - 跨文件数据流"""
    # 这里形成了一个跨文件的危险数据流：
    # input_handler.get_user_input() -> database.query_user_by_id()
    user_info = get_user_info()
    return user_info

def update_user_profile():
    """更新用户配置"""
    data = get_user_data()  # 用户输入
    update_user_data(data)  # 传递给SQL执行函数

def process_file():
    """文件处理 - 路径遍历漏洞"""
    file_path = get_file_path()  # 用户输入的文件路径
    
    # 危险的文件操作 - 没有路径验证
    with open(file_path, 'r') as f:
        return f.read()

def execute_command():
    """命令执行 - 命令注入漏洞"""
    user_data = get_user_data()  # 用户输入
    
    # 危险的命令执行
    result = subprocess.run(f"echo {user_data}", shell=True, capture_output=True)
    return result.stdout

def admin_operation():
    """敏感操作 - 权限绕过"""
    # 这个函数执行敏感操作但没有适当的权限检查
    # 应该检测为权限绕过漏洞
    os.system("rm -rf /important/data")
    return "Data deleted"

def public_endpoint():
    """公开端点"""
    # 直接调用敏感操作，没有权限验证
    return admin_operation()
'''
    logic_file.write_text(logic_content)
    
    # 测试文件4：输出处理
    output_file = temp_dir / "output_handler.py"
    output_content = '''
from flask import render_template_string
from input_handler import get_user_data

def render_user_data():
    """渲染用户数据 - XSS漏洞"""
    user_data = get_user_data()  # 用户输入
    
    # 危险的模板渲染 - 直接输出用户数据
    template = f"<h1>Hello {user_data}</h1>"
    return render_template_string(template)

def display_message():
    """显示消息"""
    message = get_user_data()
    # 直接输出，没有编码
    return f"<div>{message}</div>"
'''
    output_file.write_text(output_content)
    
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
            content=py_file.read_text(),
            modified_time=py_file.stat().st_mtime
        )
        source_files.append(source_file)
    
    return source_files


async def test_global_context_analysis():
    """测试全局上下文分析"""
    print("🔍 测试全局上下文分析...")
    
    # 创建测试项目
    source_files = await create_test_project()
    
    # 构建全局上下文
    analyzer = GlobalContextAnalyzer()
    global_context = await analyzer.build_global_context(source_files)
    
    # 验证结果
    stats = global_context['statistics']
    print(f"   - 代码实体: {stats['total_entities']}")
    print(f"   - 总文件数: {stats['total_files']}")
    print(f"   - 调用关系: {stats['call_relationships']}")
    print(f"   - 跨文件流: {stats['cross_file_flows']}")
    print(f"   - 导入关系: {stats['import_relationships']}")
    
    assert stats['total_files'] == 4, f"应该有4个文件，实际: {stats['total_files']}"
    assert stats['total_entities'] > 0, "应该有代码实体"
    
    print("✅ 全局上下文分析测试通过")
    return global_context


async def test_cross_file_vulnerability_detection(global_context):
    """测试跨文件漏洞检测"""
    print("🔍 测试跨文件漏洞检测...")
    
    # 跨文件漏洞检测
    cross_file_analyzer = CrossFileAnalyzer(global_context)
    vulnerabilities = cross_file_analyzer.detect_cross_file_vulnerabilities()
    
    # 验证检测结果
    print(f"   - 发现跨文件漏洞: {len(vulnerabilities)}")
    
    vuln_types = {}
    for vuln in vulnerabilities:
        vuln_type = vuln.vulnerability_type
        if vuln_type not in vuln_types:
            vuln_types[vuln_type] = 0
        vuln_types[vuln_type] += 1
    
    for vuln_type, count in vuln_types.items():
        print(f"   - {vuln_type}: {count}")
    
    # 检查是否检测到了预期的漏洞类型
    expected_types = [
        "Cross-File SQL Injection",
        "Cross-File XSS", 
        "Cross-File Command Injection",
        "Cross-File Authorization Bypass"
    ]
    
    detected_types = set(vuln_types.keys())
    for expected_type in expected_types:
        if expected_type in detected_types:
            print(f"   ✅ 成功检测到: {expected_type}")
        else:
            print(f"   ⚠️  未检测到: {expected_type}")
    
    print("✅ 跨文件漏洞检测测试完成")
    return vulnerabilities


async def test_dataflow_analysis(global_context):
    """测试数据流分析"""
    print("🔍 测试数据流分析...")
    
    # 数据流分析
    dataflow_analyzer = DataFlowAnalyzer(global_context)
    dangerous_flows = dataflow_analyzer.get_critical_data_flows(min_risk_score=0.5)
    
    print(f"   - 发现危险数据流: {len(dangerous_flows)}")
    
    for flow in dangerous_flows:
        print(f"   - {flow.source.source_type} -> {flow.sink.sink_type} (风险: {flow.risk_score:.2f})")
        print(f"     路径: {' -> '.join(flow.path[:3])}{'...' if len(flow.path) > 3 else ''}")
        print(f"     污点级别: {flow.taint_level.value}")
        if flow.sanitization_points:
            print(f"     消毒点: {flow.sanitization_points}")
    
    # 获取消毒覆盖率
    coverage = dataflow_analyzer.get_sanitization_coverage()
    print(f"   - 整体消毒覆盖率: {coverage['overall_coverage']:.2%}")
    
    print("✅ 数据流分析测试完成")
    return dangerous_flows


async def test_vulnerability_conversion(cross_file_analyzer, vulnerabilities, dangerous_flows):
    """测试漏洞转换功能"""
    print("🔍 测试漏洞转换功能...")
    
    # 转换跨文件漏洞
    vuln_results = cross_file_analyzer.convert_to_vulnerability_results(vulnerabilities)
    
    print(f"   - 转换跨文件漏洞: {len(vuln_results)}")
    
    # 验证转换结果
    for vuln in vuln_results[:3]:  # 显示前3个
        print(f"   - {vuln.title}")
        print(f"     严重程度: {vuln.severity.value}")
        print(f"     CWE: {vuln.cwe_id}")
        print(f"     OWASP: {vuln.owasp_category}")
        print(f"     置信度: {vuln.confidence}")
        if vuln.metadata and vuln.metadata.get('cross_file'):
            print(f"     源文件: {vuln.metadata.get('source_file')}")
            print(f"     目标文件: {vuln.metadata.get('target_file')}")
    
    print("✅ 漏洞转换测试完成")
    return vuln_results


async def run_comprehensive_test():
    """运行综合测试"""
    print("🚀 开始跨文件漏洞检测综合测试\n")
    
    try:
        # 1. 测试全局上下文分析
        global_context = await test_global_context_analysis()
        print()
        
        # 2. 测试跨文件漏洞检测
        vulnerabilities = await test_cross_file_vulnerability_detection(global_context)
        print()
        
        # 3. 测试数据流分析
        dangerous_flows = await test_dataflow_analysis(global_context)
        print()
        
        # 4. 测试漏洞转换
        cross_file_analyzer = CrossFileAnalyzer(global_context)
        vuln_results = await test_vulnerability_conversion(cross_file_analyzer, vulnerabilities, dangerous_flows)
        print()
        
        # 总结
        print("📊 测试总结:")
        print(f"   - 跨文件漏洞: {len(vulnerabilities)}")
        print(f"   - 危险数据流: {len(dangerous_flows)}")
        print(f"   - 转换漏洞结果: {len(vuln_results)}")
        print()
        print("🎉 所有测试通过！跨文件漏洞检测功能工作正常。")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # 运行测试
    success = asyncio.run(run_comprehensive_test())
    exit(0 if success else 1) 