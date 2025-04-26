#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
示例代码文件 - 包含一些常见的安全漏洞
"""

import os
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # SQL注入漏洞示例
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE name LIKE '%" + query + "%'"  # 不安全的SQL查询
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    
    return render_template('results.html', results=results)


@app.route('/profile')
def profile():
    username = request.args.get('username', '')
    
    # 路径遍历漏洞示例
    file_path = os.path.join('user_files', username)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            content = f.read()
    else:
        content = "User not found"
    
    # XSS漏洞示例
    return f"<h1>用户资料</h1><div>{username}</div><div>{content}</div>"


@app.route('/execute')
def execute_command():
    # 命令注入漏洞示例
    cmd = request.args.get('cmd', 'echo hello')
    output = os.popen(cmd).read()
    return output


def insecure_auth(username, password):
    # 弱密码检查示例
    if password == "admin123":
        return True
    return False


@app.route('/download')
def download_file():
    filename = request.args.get('filename', '')
    
    # 目录遍历漏洞示例
    path = "files/" + filename
    
    # 敏感信息泄露示例
    if not os.path.exists(path):
        return "File not found: " + path
    
    with open(path, 'rb') as f:
        return f.read()


if __name__ == '__main__':
    app.run(debug=True)  # 在生产环境中启用调试模式是不安全的
