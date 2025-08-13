#!/usr/bin/env python3
"""
Data Flow Analysis Engine for SAST
Tracks variable assignments, function calls, and data propagation
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class DataFlowType(str, Enum):
    """Types of data flow analysis"""
    VARIABLE_ASSIGNMENT = "variable_assignment"
    FUNCTION_CALL = "function_call"
    PARAMETER_PASSING = "parameter_passing"
    RETURN_VALUE = "return_value"
    IMPORT_STATEMENT = "import_statement"
    CLASS_INSTANTIATION = "class_instantiation"
    METHOD_CALL = "method_call"
    ATTRIBUTE_ACCESS = "attribute_access"

class DataFlowDirection(str, Enum):
    """Direction of data flow"""
    IN = "in"           # Data flowing into a function/variable
    OUT = "out"         # Data flowing out of a function/variable
    THROUGH = "through" # Data flowing through a function/variable

@dataclass
class DataFlowNode:
    """Represents a node in the data flow graph"""
    id: str
    name: str
    node_type: str  # 'variable', 'function', 'parameter', 'return'
    file_path: str
    line_number: int
    column: int
    value: Optional[str] = None
    data_type: Optional[str] = None
    is_tainted: bool = False
    taint_source: Optional[str] = None
    taint_reason: Optional[str] = None

@dataclass
class DataFlowEdge:
    """Represents an edge in the data flow graph"""
    source_id: str
    target_id: str
    flow_type: DataFlowType
    direction: DataFlowDirection
    line_number: int
    context: Optional[str] = None

@dataclass
class DataFlowPath:
    """Represents a complete data flow path"""
    path_id: str
    nodes: List[DataFlowNode]
    edges: List[DataFlowEdge]
    source: DataFlowNode
    sink: DataFlowNode
    risk_level: str = "low"
    description: str = ""

class DataFlowAnalyzer:
    """Main data flow analysis engine"""
    
    def __init__(self):
        self.nodes: Dict[str, DataFlowNode] = {}
        self.edges: List[DataFlowEdge] = []
        self.paths: List[DataFlowPath] = []
        self.taint_sources: Set[str] = set()
        self.taint_sinks: Set[str] = set()
        self.sanitizers: Set[str] = set()
        
        # Initialize common taint sources and sinks
        self._initialize_taint_patterns()
    
    def _initialize_taint_patterns(self):
        """Initialize common taint sources and sinks"""
        # Taint sources (user input)
        self.taint_sources = {
            'request.args', 'request.form', 'request.json', 'request.query_string',
            'request.cookies', 'request.headers', 'request.files',
            'input()', 'raw_input()', 'sys.argv', 'os.environ',
            'flask.request', 'django.http.HttpRequest',
            'urllib.parse.parse_qs', 'urllib.parse.parse_qsl'
        }
        
        # Taint sinks (dangerous operations)
        self.taint_sinks = {
            'eval', 'exec', 'os.system', 'subprocess.call', 'subprocess.Popen',
            'sqlite3.execute', 'sqlite3.executemany', 'mysql.connector.execute',
            'psycopg2.execute', 'pymongo.collection.find', 'pymongo.collection.update',
            'open', 'file', 'pickle.loads', 'yaml.load', 'json.loads',
            'xml.etree.ElementTree.fromstring', 'xml.dom.minidom.parseString'
        }
        
        # Sanitizers (functions that clean data)
        self.sanitizers = {
            'html.escape', 'cgi.escape', 'urllib.parse.quote',
            're.escape', 'json.dumps', 'base64.b64encode',
            'hashlib.md5', 'hashlib.sha1', 'hashlib.sha256'
        }
    
    def analyze_file(self, file_path: Path, language: str) -> List[DataFlowPath]:
        """Analyze a single file for data flow patterns"""
        try:
            if language == 'python':
                return self._analyze_python_file(file_path)
            elif language in ['javascript', 'typescript']:
                return self._analyze_javascript_file(file_path)
            elif language == 'java':
                return self._analyze_java_file(file_path)
            else:
                logger.warning(f"Language {language} not supported for data flow analysis")
                return []
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return []
    
    def _analyze_python_file(self, file_path: Path) -> List[DataFlowPath]:
        """Analyze Python file using AST"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            analyzer = PythonDataFlowAnalyzer(str(file_path))
            analyzer.analyze(tree)
            
            # Extract nodes and edges
            self.nodes.update(analyzer.nodes)
            self.edges.extend(analyzer.edges)
            
            # Find taint paths
            return self._find_taint_paths()
            
        except Exception as e:
            logger.error(f"Error parsing Python file {file_path}: {e}")
            return []
    
    def _analyze_javascript_file(self, file_path: Path) -> List[DataFlowPath]:
        """Analyze JavaScript/TypeScript file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Use regex-based analysis for JavaScript (simplified)
            analyzer = JavaScriptDataFlowAnalyzer(str(file_path))
            analyzer.analyze(content)
            
            self.nodes.update(analyzer.nodes)
            self.edges.extend(analyzer.edges)
            
            return self._find_taint_paths()
            
        except Exception as e:
            logger.error(f"Error analyzing JavaScript file {file_path}: {e}")
            return []
    
    def _analyze_java_file(self, file_path: Path) -> List[DataFlowPath]:
        """Analyze Java file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Use regex-based analysis for Java (simplified)
            analyzer = JavaDataFlowAnalyzer(str(file_path))
            analyzer.analyze(content)
            
            self.nodes.update(analyzer.nodes)
            self.edges.extend(analyzer.edges)
            
            return self._find_taint_paths()
            
        except Exception as e:
            logger.error(f"Error analyzing Java file {file_path}: {e}")
            return []
    
    def _find_taint_paths(self) -> List[DataFlowPath]:
        """Find all taint paths from sources to sinks"""
        paths = []
        
        for source_node in self._get_taint_sources():
            for sink_node in self._get_taint_sinks():
                path = self._find_path_between(source_node, sink_node)
                if path:
                    paths.append(path)
        
        return paths
    
    def _get_taint_sources(self) -> List[DataFlowNode]:
        """Get all nodes that are taint sources"""
        return [node for node in self.nodes.values() if node.is_tainted]
    
    def _get_taint_sinks(self) -> List[DataFlowNode]:
        """Get all nodes that are taint sinks"""
        return [node for node in self.nodes.values() 
                if any(sink in node.name for sink in self.taint_sinks)]
    
    def _find_path_between(self, source: DataFlowNode, sink: DataFlowNode) -> Optional[DataFlowPath]:
        """Find a path between source and sink using BFS"""
        if source.id == sink.id:
            return None
        
        visited = set()
        queue = [(source, [source], [])]
        
        while queue:
            current_node, node_path, edge_path = queue.pop(0)
            
            if current_node.id == sink.id:
                return DataFlowPath(
                    path_id=f"path_{len(self.paths) + 1}",
                    nodes=node_path,
                    edges=edge_path,
                    source=source,
                    sink=sink,
                    risk_level=self._calculate_risk_level(node_path),
                    description=self._generate_path_description(node_path)
                )
            
            if current_node.id in visited:
                continue
            
            visited.add(current_node.id)
            
            # Find outgoing edges
            for edge in self.edges:
                if edge.source_id == current_node.id:
                    target_node = self.nodes.get(edge.target_id)
                    if target_node and edge.target_id not in visited:
                        new_node_path = node_path + [target_node]
                        new_edge_path = edge_path + [edge]
                        queue.append((target_node, new_node_path, new_edge_path))
        
        return None
    
    def _calculate_risk_level(self, nodes: List[DataFlowNode]) -> str:
        """Calculate risk level based on path characteristics"""
        taint_count = sum(1 for node in nodes if node.is_tainted)
        sanitizer_count = sum(1 for node in nodes 
                            if any(san in node.name for san in self.sanitizers))
        
        if taint_count > 3 and sanitizer_count == 0:
            return "high"
        elif taint_count > 1 and sanitizer_count == 0:
            return "medium"
        elif sanitizer_count > 0:
            return "low"
        else:
            return "info"
    
    def _generate_path_description(self, nodes: List[DataFlowNode]) -> str:
        """Generate a description of the data flow path"""
        if len(nodes) < 2:
            return "Direct assignment"
        
        path_description = []
        for i in range(len(nodes) - 1):
            current = nodes[i]
            next_node = nodes[i + 1]
            
            if current.node_type == 'variable' and next_node.node_type == 'variable':
                path_description.append(f"Variable '{current.name}' assigned to '{next_node.name}'")
            elif current.node_type == 'variable' and next_node.node_type == 'function':
                path_description.append(f"Variable '{current.name}' passed to function '{next_node.name}'")
            elif current.node_type == 'function' and next_node.node_type == 'variable':
                path_description.append(f"Function '{current.name}' returns to variable '{next_node.name}'")
        
        return " -> ".join(path_description)
    
    def get_data_flow_summary(self) -> Dict[str, Any]:
        """Get a summary of the data flow analysis"""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "total_paths": len(self.paths),
            "taint_sources": len(self._get_taint_sources()),
            "taint_sinks": len(self._get_taint_sinks()),
            "high_risk_paths": len([p for p in self.paths if p.risk_level == "high"]),
            "medium_risk_paths": len([p for p in self.paths if p.risk_level == "medium"]),
            "low_risk_paths": len([p for p in self.paths if p.risk_level == "low"])
        }

class PythonDataFlowAnalyzer(ast.NodeVisitor):
    """AST-based data flow analyzer for Python"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.nodes: Dict[str, DataFlowNode] = {}
        self.edges: List[DataFlowEdge] = []
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None
        self.node_counter = 0
    
    def _create_node_id(self) -> str:
        """Create a unique node ID"""
        self.node_counter += 1
        return f"{self.file_path}_{self.node_counter}"
    
    def analyze(self, tree: ast.AST):
        """Analyze the AST tree"""
        self.visit(tree)
    
    def visit_Assign(self, node: ast.Assign):
        """Visit assignment nodes"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_id = self._create_node_id()
                target_node = DataFlowNode(
                    id=target_id,
                    name=target.id,
                    node_type='variable',
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    value=self._get_node_value(node.value),
                    is_tainted=self._is_tainted_source(node.value)
                )
                self.nodes[target_id] = target_node
                
                # Create edge from value to target
                if isinstance(node.value, ast.Name):
                    value_node = self._find_variable_node(node.value.id)
                    if value_node:
                        edge = DataFlowEdge(
                            source_id=value_node.id,
                            target_id=target_id,
                            flow_type=DataFlowType.VARIABLE_ASSIGNMENT,
                            direction=DataFlowDirection.THROUGH,
                            line_number=node.lineno
                        )
                        self.edges.append(edge)
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition nodes"""
        func_id = self._create_node_id()
        func_node = DataFlowNode(
            id=func_id,
            name=node.name,
            node_type='function',
            file_path=self.file_path,
            line_number=node.lineno,
            column=node.col_offset
        )
        self.nodes[func_id] = func_node
        
        # Analyze function parameters
        for arg in node.args.args:
            arg_id = self._create_node_id()
            arg_node = DataFlowNode(
                id=arg_id,
                name=arg.arg,
                node_type='parameter',
                file_path=self.file_path,
                line_number=node.lineno,
                column=node.col_offset,
                is_tainted=True,  # Function parameters are potential taint sources
                taint_source="function_parameter"
            )
            self.nodes[arg_id] = arg_node
            
            # Create edge from parameter to function
            edge = DataFlowEdge(
                source_id=arg_id,
                target_id=func_id,
                flow_type=DataFlowType.PARAMETER_PASSING,
                direction=DataFlowDirection.IN,
                line_number=node.lineno
            )
            self.edges.append(edge)
        
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = None
    
    def visit_Call(self, node: ast.Call):
        """Visit function call nodes"""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            # Check if this is a taint sink
            if func_name in self._get_taint_sinks():
                sink_id = self._create_node_id()
                sink_node = DataFlowNode(
                    id=sink_id,
                    name=func_name,
                    node_type='function_call',
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset
                )
                self.nodes[sink_id] = sink_node
                
                # Create edges from arguments to sink
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        arg_node = self._find_variable_node(arg.id)
                        if arg_node:
                            edge = DataFlowEdge(
                                source_id=arg_node.id,
                                target_id=sink_id,
                                flow_type=DataFlowType.FUNCTION_CALL,
                                direction=DataFlowDirection.IN,
                                line_number=node.lineno
                            )
                            self.edges.append(edge)
        
        self.generic_visit(node)
    
    def _get_node_value(self, node: ast.AST) -> Optional[str]:
        """Extract string value from AST node"""
        if isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return None
    
    def _is_tainted_source(self, node: ast.AST) -> bool:
        """Check if a node represents a taint source"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return f"{self._get_node_value(node.func.value)}.{node.func.attr}" in self._get_taint_sources()
            elif isinstance(node.func, ast.Name):
                return node.func.id in self._get_taint_sources()
        return False
    
    def _get_taint_sources(self) -> Set[str]:
        """Get taint sources for Python"""
        return {
            'request.args', 'request.form', 'request.json', 'request.query_string',
            'request.cookies', 'request.headers', 'request.files',
            'input', 'raw_input', 'sys.argv', 'os.environ',
            'flask.request', 'django.http.HttpRequest'
        }
    
    def _get_taint_sinks(self) -> Set[str]:
        """Get taint sinks for Python"""
        return {
            'eval', 'exec', 'os.system', 'subprocess.call', 'subprocess.Popen',
            'sqlite3.execute', 'sqlite3.executemany', 'mysql.connector.execute',
            'psycopg2.execute', 'pymongo.collection.find', 'pymongo.collection.update',
            'open', 'file', 'pickle.loads', 'yaml.load', 'json.loads'
        }
    
    def _find_variable_node(self, var_name: str) -> Optional[DataFlowNode]:
        """Find a variable node by name"""
        for node in self.nodes.values():
            if node.name == var_name and node.node_type == 'variable':
                return node
        return None

class JavaScriptDataFlowAnalyzer:
    """Regex-based data flow analyzer for JavaScript/TypeScript"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.nodes: Dict[str, DataFlowNode] = {}
        self.edges: List[DataFlowEdge] = []
        self.node_counter = 0
    
    def _create_node_id(self) -> str:
        """Create a unique node ID"""
        self.node_counter += 1
        return f"{self.file_path}_{self.node_counter}"
    
    def analyze(self, content: str):
        """Analyze JavaScript content using regex patterns"""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            self._analyze_line(line, line_num)
    
    def _analyze_line(self, line: str, line_num: int):
        """Analyze a single line for data flow patterns"""
        # Variable assignments
        var_pattern = r'(\w+)\s*=\s*([^;]+)'
        for match in re.finditer(var_pattern, line):
            var_name = match.group(1)
            var_value = match.group(2).strip()
            
            var_id = self._create_node_id()
            var_node = DataFlowNode(
                id=var_id,
                name=var_name,
                node_type='variable',
                file_path=self.file_path,
                line_number=line_num,
                column=line.find(var_name),
                value=var_value,
                is_tainted=self._is_tainted_source(var_value)
            )
            self.nodes[var_id] = var_node
        
        # Function definitions
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, line):
            func_name = match.group(1)
            params = match.group(2).split(',')
            
            func_id = self._create_node_id()
            func_node = DataFlowNode(
                id=func_id,
                name=func_name,
                node_type='function',
                file_path=self.file_path,
                line_number=line_num,
                column=line.find('function')
            )
            self.nodes[func_id] = func_node
            
            # Analyze parameters
            for param in params:
                param = param.strip()
                if param:
                    param_id = self._create_node_id()
                    param_node = DataFlowNode(
                        id=param_id,
                        name=param,
                        node_type='parameter',
                        file_path=self.file_path,
                        line_number=line_num,
                        column=line.find(param),
                        is_tainted=True,
                        taint_source="function_parameter"
                    )
                    self.nodes[param_id] = param_node
    
    def _is_tainted_source(self, value: str) -> bool:
        """Check if a value represents a taint source"""
        taint_patterns = [
            r'document\.getElementById',
            r'document\.querySelector',
            r'location\.search',
            r'location\.hash',
            r'window\.location',
            r'event\.target',
            r'localStorage\.getItem',
            r'sessionStorage\.getItem'
        ]
        
        return any(re.search(pattern, value) for pattern in taint_patterns)

class JavaDataFlowAnalyzer:
    """Regex-based data flow analyzer for Java"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.nodes: Dict[str, DataFlowNode] = {}
        self.edges: List[DataFlowEdge] = []
        self.node_counter = 0
    
    def _create_node_id(self) -> str:
        """Create a unique node ID"""
        self.node_counter += 1
        return f"{self.file_path}_{self.node_counter}"
    
    def analyze(self, content: str):
        """Analyze Java content using regex patterns"""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            self._analyze_line(line, line_num)
    
    def _analyze_line(self, line: str, line_num: int):
        """Analyze a single line for data flow patterns"""
        # Variable declarations and assignments
        var_pattern = r'(\w+)\s+(\w+)\s*=\s*([^;]+)'
        for match in re.finditer(var_pattern, line):
            var_type = match.group(1)
            var_name = match.group(2)
            var_value = match.group(3).strip()
            
            var_id = self._create_node_id()
            var_node = DataFlowNode(
                id=var_id,
                name=var_name,
                node_type='variable',
                file_path=self.file_path,
                line_number=line_num,
                column=line.find(var_name),
                value=var_value,
                data_type=var_type,
                is_tainted=self._is_tainted_source(var_value)
            )
            self.nodes[var_id] = var_node
        
        # Method definitions
        method_pattern = r'(\w+)\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(method_pattern, line):
            return_type = match.group(1)
            method_name = match.group(2)
            params = match.group(3).split(',')
            
            method_id = self._create_node_id()
            method_node = DataFlowNode(
                id=method_id,
                name=method_name,
                node_type='function',
                file_path=self.file_path,
                line_number=line_num,
                column=line.find(method_name),
                data_type=return_type
            )
            self.nodes[method_id] = method_node
    
    def _is_tainted_source(self, value: str) -> bool:
        """Check if a value represents a taint source"""
        taint_patterns = [
            r'request\.getParameter',
            r'request\.getHeader',
            r'request\.getCookie',
            r'request\.getAttribute',
            r'request\.getSession',
            r'System\.getenv',
            r'System\.getProperty'
        ]
        
        return any(re.search(pattern, value) for pattern in taint_patterns)
