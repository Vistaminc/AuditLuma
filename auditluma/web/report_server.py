"""
Flask Web服务器 - 用于报告生成界面
"""

import os
import json
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from loguru import logger

from auditluma.visualizer.multi_format_generator import MultiFormatReportGenerator


app = Flask(__name__)
app.config['SECRET_KEY'] = 'auditluma-report-generator'

# 初始化报告生成器
report_generator = MultiFormatReportGenerator()

def get_history_files():
    """获取history目录中的所有分析数据文件"""
    history_dir = Path("history")
    if not history_dir.exists():
        return []
    
    files = []
    for file_path in history_dir.glob("Data_*.txt"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 改进显示名称生成
            stem = file_path.stem
            if stem.startswith("Data_"):
                # 判断是新格式还是旧格式
                # 旧格式: Data_YYYYMMDD_HHMMSS (纯数字时间戳)
                # 新格式: Data_项目名_YYYYMMDD_HHMMSS
                
                parts = stem.split("_")
                if len(parts) >= 3:
                    # 检查最后两部分是否为时间戳格式 (YYYYMMDD_HHMMSS)
                    last_two = "_".join(parts[-2:])
                    if len(parts[-2]) == 8 and parts[-2].isdigit() and len(parts[-1]) == 6 and parts[-1].isdigit():
                        # 新格式：Data_项目名_时间戳
                        project_parts = parts[1:-2]  # 除去"Data"和最后两个时间戳部分
                        if project_parts:
                            project_name = "_".join(project_parts)
                            display_name = f"{project_name} ({last_two})"
                        else:
                            display_name = f"项目 ({last_two})"
                    else:
                        # 项目名中包含下划线的情况，保持原逻辑
                        project_part = "_".join(parts[1:-2]) if len(parts) > 3 else parts[1]
                        time_part = "_".join(parts[-2:])
                        display_name = f"{project_part} ({time_part})"
                elif len(parts) == 3 and parts[1].isdigit() and len(parts[1]) == 8:
                    # 旧格式: Data_YYYYMMDD_HHMMSS
                    display_name = stem.replace("Data_", "分析数据_")
                else:
                    # 其他格式
                    display_name = stem.replace("Data_", "")
            else:
                display_name = stem
            
            files.append({
                "filename": file_path.name,
                "filepath": str(file_path),
                "display_name": display_name,
                "analysis_time": data.get("analysis_time", "未知时间"),
                "vulnerabilities_count": data.get("vulnerabilities_count", 0),
                "scanned_files": data.get("scan_info", {}).get("scanned_files", 0),
                "project_name": data.get("scan_info", {}).get("project_name", "未知项目")
            })
        except Exception as e:
            logger.warning(f"读取文件 {file_path} 失败: {e}")
    
    # 按时间排序，最新的在前
    files.sort(key=lambda x: x["filename"], reverse=True)
    return files


@app.route('/')
def index():
    """主页 - 显示报告生成界面"""
    return render_template('report_generator.html')


@app.route('/api/analysis-data')
def get_analysis_data():
    """API - 获取分析数据列表（兼容旧版本）"""
    try:
        files = get_history_files()
        return jsonify({"success": True, "files": files})
    except Exception as e:
        logger.error(f"获取分析数据失败: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/history')
def get_history():
    """API - 获取历史分析数据列表（新版本）"""
    try:
        files = get_history_files()
        return jsonify(files)
    except Exception as e:
        logger.error(f"获取历史数据失败: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    """API - 生成指定格式的报告"""
    try:
        data = request.get_json()
        data_file = data.get('data_file')
        report_format = data.get('format')
        
        if not data_file or not report_format:
            return jsonify({"success": False, "error": "缺少必要参数"}), 400
        
        # 构建完整的文件路径
        data_file_path = Path("history") / data_file
        if not data_file_path.exists():
            return jsonify({"success": False, "error": "数据文件不存在"}), 404
        
        # 根据格式生成报告
        if report_format == 'txt':
            report_path = report_generator.generate_txt_report(str(data_file_path))
        elif report_format == 'json':
            report_path = report_generator.generate_json_report(str(data_file_path))
        elif report_format == 'excel':
            report_path = report_generator.generate_excel_report(str(data_file_path))
        elif report_format == 'html':
            report_path = report_generator.generate_html_report(str(data_file_path))
        elif report_format == 'word':
            report_path = report_generator.generate_word_report(str(data_file_path))
        else:
            return jsonify({"success": False, "error": f"不支持的格式: {report_format}"}), 400
        
        return jsonify({
            "success": True, 
            "report_path": report_path,
            "message": f"{report_format.upper()}报告生成成功"
        })
        
    except Exception as e:
        logger.error(f"生成报告失败: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 AuditLuma 报告生成器启动中...")
    print("=" * 60)
    print("📁 请确保 history/ 目录包含分析数据文件")
    print("🌐 访问地址: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000) 