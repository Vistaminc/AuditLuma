#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
跨文件安全分析演示脚本
展示 AuditLuma 的跨文件漏洞检测能力
"""

import tempfile
import sys
import os
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

def create_demo_project():
    """创建演示项目文件"""
    temp_dir = Path(tempfile.mkdtemp())
    
    # 创建输入处理模块
    input_handler = temp_dir / "input_handler.py"
    input_handler.write_text('''
"""
用户输入处理模块
包含潜在的用户输入来源
"""

def get_user_id():
    """从HTTP请求获取用户ID"""
    return request.args.get("user_id")

def get_search_term():
    """获取搜索关键词"""
    return request.form.get("search")

def get_filename():
    """获取文件名参数"""
    return request.args.get("filename")

def get_command():
    """获取要执行的命令"""
    return request.form.get("cmd")
''', encoding='utf-8')
    
    # 创建数据库操作模块
    database = temp_dir / "database.py"
    database.write_text('''
"""
数据库操作模块
包含SQL注入漏洞
"""

from input_handler import get_user_id, get_search_term

def get_user_profile():
    """获取用户资料 - 存在SQL注入风险"""
    user_id = get_user_id()
    # 直接拼接用户输入到SQL查询 - 漏洞!
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

def search_products():
    """搜索产品 - 存在SQL注入风险"""
    search_term = get_search_term()
    # 直接拼接搜索词 - 漏洞!
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    return execute_query(query)

def execute_query(sql):
    """执行SQL查询"""
    cursor.execute(sql)
    return cursor.fetchall()
''', encoding='utf-8')
    
    # 创建文件操作模块
    file_handler = temp_dir / "file_handler.py" 
    file_handler.write_text('''
"""
文件处理模块
包含路径遍历漏洞
"""

from input_handler import get_filename
import os

def read_user_file():
    """读取用户指定的文件 - 存在路径遍历风险"""
    filename = get_filename()
    # 直接使用用户输入构建文件路径 - 漏洞!
    file_path = f"/uploads/{filename}"
    with open(file_path, 'r') as f:
        return f.read()

def save_data(data):
    """保存数据到文件"""
    filename = get_filename()
    # 路径遍历漏洞!
    full_path = os.path.join("/data", filename)
    with open(full_path, 'w') as f:
        f.write(data)
''', encoding='utf-8')
    
    # 创建命令执行模块
    command_executor = temp_dir / "command_executor.py"
    command_executor.write_text('''
"""
命令执行模块
包含命令注入漏洞
"""

from input_handler import get_command
import subprocess
import os

def execute_user_command():
    """执行用户命令 - 存在命令注入风险"""
    cmd = get_command()
    # 直接执行用户输入的命令 - 漏洞!
    result = os.system(cmd)
    return result

def backup_files():
    """备份文件"""
    cmd = get_command()
    # 命令注入风险!
    full_cmd = f"tar -czf backup.tar.gz {cmd}"
    subprocess.run(full_cmd, shell=True)
''', encoding='utf-8')
    
    print(f"✅ 创建演示项目: {temp_dir}")
    print(f"📁 包含文件:")
    for file in temp_dir.glob("*.py"):
        print(f"   - {file.name}")
    
    return temp_dir

def main():
    """主函数"""
    print("🔍 AuditLuma 跨文件安全分析演示")
    print("=" * 50)
    
    # 创建演示项目
    demo_dir = create_demo_project()
    
    print(f"\n📋 使用说明:")
    print(f"现在您可以使用以下命令来测试不同的分析模式:")
    print()
    print(f"🔹 传统分析（跳过跨文件检测）:")
    print(f"   python main.py -d {demo_dir} -o ./reports --no-cross-file")
    print()
    print(f"🔹 跨文件分析:")
    print(f"   python main.py -d {demo_dir} -o ./reports")
    print()
    print(f"🔹 增强跨文件分析（AI增强）:")
    print(f"   python main.py -d {demo_dir} -o ./reports --enhanced-analysis")
    print()
    print(f"💡 期待结果:")
    print(f"   - 传统分析: 只检测单文件内的漏洞")
    print(f"   - 跨文件分析: 检测跨文件的数据流漏洞")
    print(f"   - 增强分析: AI增强的漏洞描述和修复建议")
    print()
    print(f"🎯 演示项目包含的跨文件漏洞类型:")
    print(f"   - SQL注入: input_handler.py → database.py")
    print(f"   - 路径遍历: input_handler.py → file_handler.py") 
    print(f"   - 命令注入: input_handler.py → command_executor.py")
    print()
    print(f"📝 演示完成后，您可以查看 ./reports 目录中的报告")
    
if __name__ == "__main__":
    main() 