"""
跨文件分析器 - 检测跨文件的安全漏洞和数据流问题
"""

import ast
import re
import networkx as nx
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from auditluma.models.code import SourceFile, CodeUnit, VulnerabilityResult, SeverityLevel, FileType
from auditluma.rag.self_rag import self_rag
from .global_context_analyzer import GlobalContextAnalyzer, CrossFileFlow


@dataclass
class CrossFileVulnerability:
    """跨文件漏洞"""
    vulnerability_type: str
    severity: str
    source_file: str
    target_file: str
    description: str
    data_flow_path: List[str]
    recommendation: str
    confidence: float = 0.8


class CrossFileAnalyzer:
    """跨文件分析器 - 检测跨文件的安全漏洞"""
    
    def __init__(self, global_context: Dict[str, Any]):
        self.global_context = global_context
        self.call_graph = global_context["call_graph"]
        self.data_flow_graph = global_context["data_flow_graph"]
        self.entities = global_context["entities"]
        self.cross_file_flows = global_context["cross_file_flows"]
        self.import_graph = global_context["import_graph"]
        
        # Self-RAG增强上下文检索
        self.use_self_rag = True
        try:
            # 测试Self-RAG是否可用
            if hasattr(self_rag, 'retrieve') and hasattr(self_rag, 'embedder') and hasattr(self_rag, 'vector_store'):
                logger.debug("🤖 跨文件分析器启用Self-RAG增强")
            else:
                self.use_self_rag = False
                logger.debug("Self-RAG不可用，跨文件分析器使用基础模式")
        except Exception as e:
            self.use_self_rag = False
            logger.debug(f"Self-RAG初始化检查失败: {e}")
        
        # 定义危险函数和输入源的模式
        self.dangerous_patterns = {
            'sql_execution': [
                r'execute\s*\(',
                r'query\s*\(',
                r'cursor\.',
                r'sql\s*=',
                r'SELECT\s+.*FROM',
                r'INSERT\s+INTO',
                r'UPDATE\s+.*SET',
                r'DELETE\s+FROM'
            ],
            'command_execution': [
                r'os\.system\s*\(',
                r'subprocess\.',
                r'eval\s*\(',
                r'exec\s*\(',
                r'shell=True'
            ],
            'file_operations': [
                r'open\s*\(',
                r'file\s*\(',
                r'os\.path\.',
                r'pathlib\.'
            ],
            'network_operations': [
                r'requests\.',
                r'urllib\.',
                r'socket\.',
                r'http\.'
            ]
        }
        
        self.input_patterns = [
            r'request\.',
            r'input\s*\(',
            r'raw_input\s*\(',
            r'argv',
            r'environ',
            r'form\.',
            r'args\.',
            r'json\.',
            r'params\.'
        ]
        
        self.sanitization_patterns = [
            r'escape',
            r'sanitize',
            r'clean',
            r'validate',
            r'filter',
            r'quote',
            r'encode'
        ]
    
    def detect_cross_file_vulnerabilities(self) -> List[CrossFileVulnerability]:
        """检测跨文件漏洞"""
        vulnerabilities = []
        
        logger.info("🔍 开始跨文件漏洞检测...")
        
        # Self-RAG增强：检索相关的安全知识
        if self.use_self_rag:
            try:
                security_context = self._retrieve_security_context()
                if security_context:
                    logger.debug(f"🧠 Self-RAG检索到 {len(security_context)} 条相关安全知识")
            except Exception as e:
                logger.warning(f"Self-RAG上下文检索失败: {e}")
        
        # 1. 检测跨文件SQL注入
        sql_vulns = self._detect_cross_file_sql_injection()
        vulnerabilities.extend(sql_vulns)
        
        # 2. 检测跨文件XSS
        xss_vulns = self._detect_cross_file_xss()
        vulnerabilities.extend(xss_vulns)
        
        # 3. 检测跨文件权限绕过
        auth_vulns = self._detect_cross_file_authorization_bypass()
        vulnerabilities.extend(auth_vulns)
        
        # 4. 检测跨文件命令注入
        cmd_vulns = self._detect_cross_file_command_injection()
        vulnerabilities.extend(cmd_vulns)
        
        # 5. 检测跨文件路径遍历
        path_vulns = self._detect_cross_file_path_traversal()
        vulnerabilities.extend(path_vulns)
        
        logger.info(f"✅ 跨文件漏洞检测完成，发现 {len(vulnerabilities)} 个跨文件漏洞")
        
        return vulnerabilities
    
    def _detect_cross_file_sql_injection(self) -> List[CrossFileVulnerability]:
        """检测跨文件SQL注入"""
        vulnerabilities = []
        
        # 寻找输入源和SQL执行点
        input_entities = self._find_entities_with_patterns(self.input_patterns)
        sql_entities = self._find_entities_with_patterns(self.dangerous_patterns['sql_execution'])
        
        for input_entity in input_entities:
            for sql_entity in sql_entities:
                input_file = self.entities[input_entity].file_path
                sql_file = self.entities[sql_entity].file_path
                
                # 只检查跨文件的情况
                if input_file != sql_file:
                    # 检查是否有数据流路径
                    if self._has_data_flow_path(input_entity, sql_entity):
                        path = self._find_shortest_path(input_entity, sql_entity)
                        
                        # 检查路径上是否有SQL注入防护
                        if not self._has_sql_protection_in_path(path):
                            vuln = CrossFileVulnerability(
                                vulnerability_type="Cross-File SQL Injection",
                                severity="HIGH",
                                source_file=input_file,
                                target_file=sql_file,
                                description=f"用户输入从 {input_file} 流向 {sql_file} 的SQL执行点，可能存在SQL注入风险",
                                data_flow_path=path,
                                recommendation="在SQL执行前对用户输入进行验证和转义，使用参数化查询",
                                confidence=0.8
                            )
                            
                            # Self-RAG增强漏洞描述
                            if self.use_self_rag:
                                try:
                                    security_context = self._retrieve_security_context()
                                    vuln = self._enhance_vulnerability_with_context(vuln, security_context)
                                except Exception as e:
                                    logger.debug(f"Self-RAG增强SQL注入漏洞失败: {e}")
                            
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_cross_file_xss(self) -> List[CrossFileVulnerability]:
        """检测跨文件XSS"""
        vulnerabilities = []
        
        input_entities = self._find_entities_with_patterns(self.input_patterns)
        output_patterns = [
            r'render',
            r'response',
            r'write',
            r'print',
            r'return.*html',
            r'template'
        ]
        output_entities = self._find_entities_with_patterns(output_patterns)
        
        for input_entity in input_entities:
            for output_entity in output_entities:
                input_file = self.entities[input_entity].file_path
                output_file = self.entities[output_entity].file_path
                
                if input_file != output_file:
                    if self._has_data_flow_path(input_entity, output_entity):
                        path = self._find_shortest_path(input_entity, output_entity)
                        
                        # 检查是否有输出编码保护
                        if not self._has_xss_protection_in_path(path):
                            vuln = CrossFileVulnerability(
                                vulnerability_type="Cross-File XSS",
                                severity="HIGH",
                                source_file=input_file,
                                target_file=output_file,
                                description=f"用户输入从 {input_file} 流向 {output_file} 的输出点，可能存在XSS风险",
                                data_flow_path=path,
                                recommendation="在输出前对用户输入进行HTML编码或使用安全的模板引擎",
                                confidence=0.7
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_cross_file_authorization_bypass(self) -> List[CrossFileVulnerability]:
        """检测跨文件权限绕过"""
        vulnerabilities = []
        
        # 查找敏感操作
        sensitive_patterns = [
            r'delete',
            r'admin',
            r'payment',
            r'transfer',
            r'sensitive',
            r'critical',
            r'remove',
            r'drop'
        ]
        sensitive_entities = self._find_entities_with_patterns(sensitive_patterns)
        
        # 查找认证检查
        auth_patterns = [
            r'login',
            r'authenticate',
            r'check_permission',
            r'authorize',
            r'verify',
            r'token',
            r'session'
        ]
        auth_entities = self._find_entities_with_patterns(auth_patterns)
        
        for sensitive_entity in sensitive_entities:
            sensitive_file = self.entities[sensitive_entity].file_path
            
            # 检查是否有认证保护
            has_auth_protection = False
            for auth_entity in auth_entities:
                auth_file = self.entities[auth_entity].file_path
                
                # 检查认证是否在敏感操作之前被调用
                if self._has_data_flow_path(auth_entity, sensitive_entity):
                    has_auth_protection = True
                    break
            
            if not has_auth_protection:
                vuln = CrossFileVulnerability(
                    vulnerability_type="Cross-File Authorization Bypass",
                    severity="CRITICAL",
                    source_file="multiple",
                    target_file=sensitive_file,
                    description=f"敏感操作 {sensitive_entity} 可能缺乏适当的权限验证",
                    data_flow_path=[sensitive_entity],
                    recommendation="在执行敏感操作前添加适当的权限验证",
                    confidence=0.6
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_cross_file_command_injection(self) -> List[CrossFileVulnerability]:
        """检测跨文件命令注入"""
        vulnerabilities = []
        
        input_entities = self._find_entities_with_patterns(self.input_patterns)
        cmd_entities = self._find_entities_with_patterns(self.dangerous_patterns['command_execution'])
        
        for input_entity in input_entities:
            for cmd_entity in cmd_entities:
                input_file = self.entities[input_entity].file_path
                cmd_file = self.entities[cmd_entity].file_path
                
                if input_file != cmd_file:
                    if self._has_data_flow_path(input_entity, cmd_entity):
                        path = self._find_shortest_path(input_entity, cmd_entity)
                        
                        # 检查是否有命令注入保护
                        if not self._has_command_protection_in_path(path):
                            vuln = CrossFileVulnerability(
                                vulnerability_type="Cross-File Command Injection",
                                severity="CRITICAL",
                                source_file=input_file,
                                target_file=cmd_file,
                                description=f"用户输入从 {input_file} 流向 {cmd_file} 的命令执行点，可能存在命令注入风险",
                                data_flow_path=path,
                                recommendation="验证和转义用户输入，避免直接拼接到系统命令中",
                                confidence=0.9
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_cross_file_path_traversal(self) -> List[CrossFileVulnerability]:
        """检测跨文件路径遍历"""
        vulnerabilities = []
        
        input_entities = self._find_entities_with_patterns(self.input_patterns)
        file_entities = self._find_entities_with_patterns(self.dangerous_patterns['file_operations'])
        
        for input_entity in input_entities:
            for file_entity in file_entities:
                input_file = self.entities[input_entity].file_path
                file_op_file = self.entities[file_entity].file_path
                
                if input_file != file_op_file:
                    if self._has_data_flow_path(input_entity, file_entity):
                        path = self._find_shortest_path(input_entity, file_entity)
                        
                        # 检查是否有路径遍历保护
                        if not self._has_path_protection_in_path(path):
                            vuln = CrossFileVulnerability(
                                vulnerability_type="Cross-File Path Traversal",
                                severity="MEDIUM",
                                source_file=input_file,
                                target_file=file_op_file,
                                description=f"用户输入从 {input_file} 流向 {file_op_file} 的文件操作点，可能存在路径遍历风险",
                                data_flow_path=path,
                                recommendation="验证文件路径，限制访问范围，使用安全的文件操作API",
                                confidence=0.6
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _find_entities_with_patterns(self, patterns: List[str]) -> List[str]:
        """查找包含特定模式的实体"""
        matching_entities = []
        
        for entity_name, entity in self.entities.items():
            # 首先尝试直接从文件内容匹配（更可靠）
            if hasattr(entity, 'file_path'):
                try:
                    # 尝试多种编码方式读取文件
                    file_content = None
                    for encoding in ['utf-8', 'gbk', 'latin-1']:
                        try:
                            with open(entity.file_path, 'r', encoding=encoding) as f:
                                file_content = f.read()
                            break
                        except UnicodeDecodeError:
                            continue
                    
                    if file_content is None:
                        # 如果所有编码都失败，跳过文件内容匹配
                        raise Exception("无法解码文件")
                    
                    for pattern in patterns:
                        if re.search(pattern, file_content, re.IGNORECASE):
                            matching_entities.append(entity_name)
                            break
                    else:
                        # 如果文件内容没匹配到，再尝试AST
                        if entity.ast_node:
                            try:
                                import astor
                                code_str = astor.to_source(entity.ast_node)
                            except ImportError:
                                code_str = str(entity.ast_node)
                            
                            for pattern in patterns:
                                if re.search(pattern, code_str, re.IGNORECASE):
                                    matching_entities.append(entity_name)
                                    break
                except Exception:
                    # 文件读取失败，回退到AST方法
                    if entity.ast_node:
                        try:
                            import astor
                            code_str = astor.to_source(entity.ast_node)
                        except ImportError:
                            code_str = str(entity.ast_node)
                        
                        for pattern in patterns:
                            if re.search(pattern, code_str, re.IGNORECASE):
                                matching_entities.append(entity_name)
                                break
        
        return matching_entities
    
    def _has_data_flow_path(self, source: str, target: str) -> bool:
        """检查两个实体间是否有数据流路径"""
        try:
            # 首先检查节点是否存在于调用图中
            if (self.call_graph.has_node(source) and 
                self.call_graph.has_node(target) and 
                nx.has_path(self.call_graph, source, target)):
                return True
                
            # 如果调用图为空或没有路径，使用基于文件内容的简单检测
            source_entity = self.entities.get(source)
            target_entity = self.entities.get(target)
            
            if not source_entity or not target_entity:
                return False
            
            # 如果是不同文件，检查是否有跨文件调用的可能性
            if source_entity.file_path != target_entity.file_path:
                # 检查目标文件是否导入了源文件的模块
                return self._check_cross_file_relationship(source_entity, target_entity)
            
        except (nx.NetworkXError, Exception) as e:
            logger.debug(f"检查数据流路径时出错: {e}")
            
        return False
    
    def _check_cross_file_relationship(self, source_entity, target_entity) -> bool:
        """检查两个实体间是否有跨文件关系"""
        try:
            # 读取目标文件内容 - 尝试多种编码
            target_content = None
            for encoding in ['utf-8', 'gbk', 'latin-1']:
                try:
                    with open(target_entity.file_path, 'r', encoding=encoding) as f:
                        target_content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if target_content is None:
                return False
            
            # 检查目标文件是否导入了源文件的模块
            source_module = Path(source_entity.file_path).stem
            source_func_name = source_entity.name.split("::")[-1]
            
            # 检查几种可能的导入模式
            import_patterns = [
                f"from {source_module} import",
                f"import {source_module}",
                f"from .{source_module} import"
            ]
            
            has_import = any(pattern in target_content for pattern in import_patterns)
            
            # 检查是否调用了源函数
            has_call = source_func_name in target_content and f"{source_func_name}(" in target_content
            
            return has_import and has_call
            
        except Exception as e:
            logger.debug(f"检查跨文件关系时出错: {e}")
            return False
    
    def _find_shortest_path(self, source: str, target: str) -> List[str]:
        """查找最短路径"""
        try:
            # 检查节点是否存在
            if not self.call_graph.has_node(source) or not self.call_graph.has_node(target):
                return [source, target]
            
            return nx.shortest_path(self.call_graph, source, target)
        except (nx.NetworkXNoPath, nx.NetworkXError):
            return [source, target]
    
    def _has_sql_protection_in_path(self, path: List[str]) -> bool:
        """检查路径上是否有SQL注入保护"""
        protection_patterns = [
            r'escape',
            r'quote',
            r'parameterized',
            r'prepared',
            r'bind',
            r'placeholder'
        ]
        return self._has_protection_patterns_in_path(path, protection_patterns)
    
    def _has_xss_protection_in_path(self, path: List[str]) -> bool:
        """检查路径上是否有XSS保护"""
        protection_patterns = [
            r'escape',
            r'encode',
            r'htmlentities',
            r'htmlspecialchars',
            r'sanitize',
            r'safe'
        ]
        return self._has_protection_patterns_in_path(path, protection_patterns)
    
    def _has_command_protection_in_path(self, path: List[str]) -> bool:
        """检查路径上是否有命令注入保护"""
        protection_patterns = [
            r'escape',
            r'quote',
            r'sanitize',
            r'validate',
            r'whitelist',
            r'shlex'
        ]
        return self._has_protection_patterns_in_path(path, protection_patterns)
    
    def _has_path_protection_in_path(self, path: List[str]) -> bool:
        """检查路径上是否有路径遍历保护"""
        protection_patterns = [
            r'realpath',
            r'abspath',
            r'normpath',
            r'validate',
            r'whitelist',
            r'basename',
            r'secure_filename'
        ]
        return self._has_protection_patterns_in_path(path, protection_patterns)
    
    def _has_protection_patterns_in_path(self, path: List[str], patterns: List[str]) -> bool:
        """检查路径上是否有保护模式"""
        for entity_name in path:
            if entity_name in self.entities:
                entity = self.entities[entity_name]
                if entity.ast_node:
                    try:
                        import astor
                        code_str = astor.to_source(entity.ast_node)
                    except ImportError:
                        code_str = str(entity.ast_node)
                    
                    for pattern in patterns:
                        if re.search(pattern, code_str, re.IGNORECASE):
                            return True
        return False
    
    def convert_to_vulnerability_results(self, cross_file_vulns: List[CrossFileVulnerability]) -> List[VulnerabilityResult]:
        """将跨文件漏洞转换为标准漏洞结果"""
        vulnerability_results = []
        
        for vuln in cross_file_vulns:
            # 创建虚拟的源文件和代码单元来表示跨文件漏洞
            from auditluma.models.code import SourceFile, CodeUnit
            import uuid
            
            source_file = SourceFile(
                path=Path(vuln.source_file),
                relative_path=vuln.source_file,
                name=Path(vuln.source_file).name,
                extension=Path(vuln.source_file).suffix,
                file_type=FileType.from_extension(Path(vuln.source_file).suffix),
                size=0,
                content="# Cross-file vulnerability",
                modified_time=0
            )
            
            dummy_unit = CodeUnit(
                id=f"cross_file_{uuid.uuid4().hex[:8]}",
                name="cross_file_vulnerability",
                type="cross_file",
                source_file=source_file,
                start_line=1,
                end_line=1,
                content="# Cross-file vulnerability detected",
                parent_id=None
            )
            
            severity_mapping = {
                'CRITICAL': SeverityLevel.CRITICAL,
                'HIGH': SeverityLevel.HIGH,
                'MEDIUM': SeverityLevel.MEDIUM,
                'LOW': SeverityLevel.LOW
            }
            
            vuln_result = VulnerabilityResult(
                id=str(uuid.uuid4()),
                title=vuln.vulnerability_type,
                description=vuln.description,
                code_unit=dummy_unit,
                file_path=vuln.source_file,
                start_line=1,
                end_line=1,
                vulnerability_type=vuln.vulnerability_type,
                severity=severity_mapping.get(vuln.severity, SeverityLevel.MEDIUM),
                cwe_id=self._get_cwe_id(vuln.vulnerability_type),
                owasp_category=self._get_owasp_category(vuln.vulnerability_type),
                confidence=vuln.confidence,
                snippet="# Cross-file vulnerability",
                recommendation=vuln.recommendation,
                metadata={
                    "cross_file": True,
                    "source_file": vuln.source_file,
                    "target_file": vuln.target_file,
                    "data_flow_path": vuln.data_flow_path
                }
            )
            
            vulnerability_results.append(vuln_result)
        
        return vulnerability_results
    
    def _get_cwe_id(self, vuln_type: str) -> Optional[str]:
        """根据漏洞类型获取CWE ID"""
        cwe_mapping = {
            "Cross-File SQL Injection": "CWE-89",
            "Cross-File XSS": "CWE-79",
            "Cross-File Authorization Bypass": "CWE-285",
            "Cross-File Command Injection": "CWE-78",
            "Cross-File Path Traversal": "CWE-22"
        }
        return cwe_mapping.get(vuln_type)
    
    def _get_owasp_category(self, vuln_type: str) -> Optional[str]:
        """根据漏洞类型获取OWASP分类"""
        owasp_mapping = {
            "Cross-File SQL Injection": "A03:2021",  # Injection
            "Cross-File XSS": "A03:2021",            # Injection
            "Cross-File Authorization Bypass": "A01:2021",  # Broken Access Control
            "Cross-File Command Injection": "A03:2021",     # Injection
            "Cross-File Path Traversal": "A01:2021"         # Broken Access Control
        }
        return owasp_mapping.get(vuln_type) 

    def _retrieve_security_context(self) -> List[Dict[str, Any]]:
        """使用Self-RAG检索相关的安全上下文
        
        Returns:
            相关的安全知识文档列表
        """
        if not self.use_self_rag:
            return []
        
        security_queries = [
            "SQL injection vulnerability cross-file data flow",
            "Cross-file XSS attack vector user input",
            "Command injection vulnerability subprocess execution",
            "Path traversal file operation security",
            "Authorization bypass access control"
        ]
        
        all_contexts = []
        
        for query in security_queries:
            try:
                # Self-RAG的retrieve是异步方法，这里我们先跳过
                # 在实际使用中，应该在异步上下文中调用
                logger.debug(f"跳过Self-RAG查询 '{query}' (需要异步上下文)")
                # contexts = await self_rag.retrieve(query, k=3)
                # all_contexts.extend(contexts)
            except Exception as e:
                logger.debug(f"检索查询 '{query}' 失败: {e}")
        
        # 去重并限制数量
        unique_contexts = []
        seen_ids = set()
        
        for context in all_contexts:
            context_id = context.get('id', '')
            if context_id not in seen_ids:
                seen_ids.add(context_id)
                unique_contexts.append(context)
                
            if len(unique_contexts) >= 10:  # 限制最多10个上下文
                break
        
        return unique_contexts
    
    def _enhance_vulnerability_with_context(self, vulnerability: CrossFileVulnerability, 
                                          security_context: List[Dict[str, Any]]) -> CrossFileVulnerability:
        """使用Self-RAG上下文增强漏洞描述
        
        Args:
            vulnerability: 原始漏洞对象
            security_context: Self-RAG检索的安全上下文
            
        Returns:
            增强后的漏洞对象
        """
        if not security_context or not self.use_self_rag:
            return vulnerability
        
        try:
            # 构建与漏洞类型相关的查询
            vuln_query = f"{vulnerability.vulnerability_type} {vulnerability.source_file} {vulnerability.target_file}"
            
            # 检索更具体的上下文（需要异步上下文）
            # specific_contexts = await self_rag.retrieve(vuln_query, k=2)
            specific_contexts = []  # 暂时跳过
            
            if specific_contexts:
                # 从上下文中提取相关信息来增强描述
                enhanced_description = vulnerability.description
                enhanced_recommendation = vulnerability.recommendation
                
                for context in specific_contexts:
                    content = context.get('content', '')
                    if 'recommendation' in content.lower() or 'solution' in content.lower():
                        # 如果上下文包含修复建议，增强推荐
                        enhanced_recommendation += f"\n\n基于代码库分析: {content[:200]}..."
                    elif 'vulnerability' in content.lower() or 'security' in content.lower():
                        # 如果上下文包含安全信息，增强描述
                        enhanced_description += f"\n\n相关代码模式: {content[:150]}..."
                
                # 更新漏洞对象
                vulnerability.description = enhanced_description
                vulnerability.recommendation = enhanced_recommendation
                vulnerability.confidence = min(vulnerability.confidence + 0.1, 1.0)  # 略微提高置信度
                
        except Exception as e:
            logger.debug(f"使用Self-RAG增强漏洞描述失败: {e}")
        
        return vulnerability 