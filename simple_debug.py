"""
简单调试脚本 - 专门调试调用图构建
"""

import ast
import tempfile
from pathlib import Path

# 创建测试文件
temp_dir = Path(tempfile.mkdtemp())

# 输入文件
input_file = temp_dir / "input.py"
input_file.write_text('''
def get_user_input():
    return "test"
''')

# 数据库文件 - 调用input中的函数
db_file = temp_dir / "database.py"
db_file.write_text('''
from input import get_user_input

def query_user():
    user_id = get_user_input()  # 这是一个跨文件函数调用
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
''')

print("🔍 测试AST解析和函数调用识别")

# 解析database.py文件
with open(db_file, 'r') as f:
    db_content = f.read()

print(f"Database文件内容:\n{db_content}")

# 解析AST
tree = ast.parse(db_content)

print("\n📊 AST分析:")
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
        print(f"   - 函数定义: {node.name}")
        
        # 分析函数内的调用
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    print(f"     - 调用函数: {child.func.id}")
                elif isinstance(child.func, ast.Attribute):
                    if isinstance(child.func.value, ast.Name):
                        print(f"     - 调用方法: {child.func.value.id}.{child.func.attr}")
                        
    elif isinstance(node, ast.Import):
        for alias in node.names:
            print(f"   - Import: {alias.name}")
    elif isinstance(node, ast.ImportFrom):
        print(f"   - From {node.module} import: {[alias.name for alias in node.names]}")

print(f"\n📁 临时目录: {temp_dir}")
print("测试完成") 