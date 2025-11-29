"""
solutions/syntaxer/source_parser.py

Tree-sitter based Java source code parser.

Provides AST extraction from Java source files using tree-sitter.
This module is designed to work alongside bytecode analysis for
comprehensive program understanding.

DTU 02242 Program Analysis - Group 21
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Iterator
from enum import Enum, auto

import tree_sitter
import tree_sitter_java

# Initialize tree-sitter
JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())


class SourceNodeType(Enum):
    """Types of AST nodes from source analysis."""
    CLASS = auto()
    METHOD = auto()
    FIELD = auto()
    STATEMENT = auto()
    EXPRESSION = auto()
    IF = auto()
    WHILE = auto()
    FOR = auto()
    RETURN = auto()
    THROW = auto()
    ASSERT = auto()
    BLOCK = auto()
    INVOKE = auto()
    ASSIGNMENT = auto()
    VARIABLE_DECL = auto()
    BINARY_EXPR = auto()
    UNARY_EXPR = auto()
    LITERAL = auto()
    IDENTIFIER = auto()
    OTHER = auto()


@dataclass
class SourceNode:
    """
    AST node from source analysis.
    
    Represents a node in the Java source AST with type information
    and position data for correlation with bytecode.
    """
    node_type: SourceNodeType
    text: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    children: list[SourceNode] = field(default_factory=list)
    raw_node: Any = None  # tree-sitter node
    
    @classmethod
    def from_ts_node(
        cls,
        ts_node: tree_sitter.Node,
        node_type: SourceNodeType = SourceNodeType.OTHER
    ) -> SourceNode:
        """Create SourceNode from tree-sitter node."""
        return cls(
            node_type=node_type,
            text=ts_node.text.decode() if ts_node.text else "",
            start_line=ts_node.start_point[0] + 1,
            end_line=ts_node.end_point[0] + 1,
            start_column=ts_node.start_point[1],
            end_column=ts_node.end_point[1],
            raw_node=ts_node,
        )


@dataclass
class SourceMethod:
    """
    Parsed method from source code.
    
    Contains the method's AST and metadata for correlation with bytecode.
    """
    name: str
    return_type: str
    parameters: list[tuple[str, str]]  # (type, name) pairs
    body: Optional[SourceNode] = None
    start_line: int = 0
    end_line: int = 0
    modifiers: list[str] = field(default_factory=list)
    statements: list[SourceNode] = field(default_factory=list)
    
    def has_assertion(self) -> bool:
        """Check if method contains any assert statements."""
        return self._find_node_type(SourceNodeType.ASSERT) is not None
    
    def _find_node_type(
        self,
        node_type: SourceNodeType,
        node: SourceNode = None
    ) -> Optional[SourceNode]:
        """Recursively search for a node type."""
        if node is None:
            for stmt in self.statements:
                result = self._find_node_type(node_type, stmt)
                if result:
                    return result
            return None
        
        if node.node_type == node_type:
            return node
        
        for child in node.children:
            result = self._find_node_type(node_type, child)
            if result:
                return result
        
        return None


@dataclass
class SourceClass:
    """
    Parsed class from source code.
    """
    name: str
    package: str
    methods: dict[str, SourceMethod] = field(default_factory=dict)
    fields: list[tuple[str, str, str]] = field(default_factory=list)  # (modifiers, type, name)
    start_line: int = 0
    end_line: int = 0


class SourceParser:
    """
    Java source parser using tree-sitter.
    
    Extracts AST information from Java source files for correlation
    with bytecode analysis.
    
    Example:
        parser = SourceParser()
        source_class = parser.parse_file("Simple.java")
        method = source_class.methods.get("assertPositive")
        if method.has_assertion():
            print("Method has assertions")
    """
    
    def __init__(self):
        """Initialize the parser."""
        self.parser = tree_sitter.Parser(JAVA_LANGUAGE)
        self.log = logging.getLogger(__name__)
    
    def parse_file(self, file_path: str | Path) -> Optional[SourceClass]:
        """
        Parse a Java source file.
        
        Args:
            file_path: Path to Java source file
            
        Returns:
            SourceClass with parsed content, or None on error
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.log.error(f"Source file not found: {file_path}")
            return None
        
        with open(file_path, "rb") as f:
            source = f.read()
        
        return self.parse_source(source, file_path.stem)
    
    def parse_source(
        self,
        source: bytes,
        expected_class: str = None
    ) -> Optional[SourceClass]:
        """
        Parse Java source code.
        
        Args:
            source: Java source code as bytes
            expected_class: Expected class name (optional filter)
            
        Returns:
            SourceClass with parsed content
        """
        tree = self.parser.parse(source)
        
        # Find package declaration
        package = self._find_package(tree.root_node)
        
        # Find class declaration
        class_node = self._find_class(tree.root_node, expected_class)
        
        if class_node is None:
            self.log.warning("Could not find class in source")
            return None
        
        class_name = self._get_class_name(class_node)
        
        source_class = SourceClass(
            name=class_name,
            package=package,
            start_line=class_node.start_point[0] + 1,
            end_line=class_node.end_point[0] + 1,
        )
        
        # Parse methods
        for method_node in self._find_methods(class_node):
            method = self._parse_method(method_node)
            if method:
                source_class.methods[method.name] = method
        
        return source_class
    
    def _find_package(self, root: tree_sitter.Node) -> str:
        """Extract package name from source."""
        query = tree_sitter.Query(
            JAVA_LANGUAGE,
            "(package_declaration (scoped_identifier) @package)"
        )
        
        cursor = tree_sitter.QueryCursor(query)
        captures = cursor.captures(root)
        
        for name, nodes in captures.items():
            if name == "package" and nodes:
                return nodes[0].text.decode() if nodes[0].text else ""
        
        return ""
    
    def _find_class(
        self,
        root: tree_sitter.Node,
        expected: str = None
    ) -> Optional[tree_sitter.Node]:
        """Find class declaration node."""
        query_str = "(class_declaration) @class"
        query = tree_sitter.Query(JAVA_LANGUAGE, query_str)
        
        cursor = tree_sitter.QueryCursor(query)
        captures = cursor.captures(root)
        
        for name, nodes in captures.items():
            if name == "class":
                for node in nodes:
                    class_name = self._get_class_name(node)
                    if expected is None or class_name == expected:
                        return node
        
        return None
    
    def _get_class_name(self, class_node: tree_sitter.Node) -> str:
        """Get class name from class declaration."""
        name_node = class_node.child_by_field_name("name")
        if name_node and name_node.text:
            return name_node.text.decode()
        return ""
    
    def _find_methods(
        self,
        class_node: tree_sitter.Node
    ) -> Iterator[tree_sitter.Node]:
        """Find all method declarations in a class."""
        query = tree_sitter.Query(
            JAVA_LANGUAGE,
            "(method_declaration) @method"
        )
        
        cursor = tree_sitter.QueryCursor(query)
        captures = cursor.captures(class_node)
        
        for name, nodes in captures.items():
            if name == "method":
                yield from nodes
    
    def _parse_method(
        self,
        method_node: tree_sitter.Node
    ) -> Optional[SourceMethod]:
        """Parse a method declaration into SourceMethod."""
        # Get method name
        name_node = method_node.child_by_field_name("name")
        if not name_node or not name_node.text:
            return None
        
        method_name = name_node.text.decode()
        
        # Get return type
        return_type = ""
        type_node = method_node.child_by_field_name("type")
        if type_node and type_node.text:
            return_type = type_node.text.decode()
        
        # Get parameters
        parameters = []
        params_node = method_node.child_by_field_name("parameters")
        if params_node:
            for param in params_node.children:
                if param.type == "formal_parameter":
                    param_type = ""
                    param_name = ""
                    
                    type_n = param.child_by_field_name("type")
                    if type_n and type_n.text:
                        param_type = type_n.text.decode()
                    
                    name_n = param.child_by_field_name("name")
                    if name_n and name_n.text:
                        param_name = name_n.text.decode()
                    
                    if param_type and param_name:
                        parameters.append((param_type, param_name))
        
        # Get modifiers
        modifiers = []
        for child in method_node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.text:
                        modifiers.append(mod.text.decode())
        
        method = SourceMethod(
            name=method_name,
            return_type=return_type,
            parameters=parameters,
            modifiers=modifiers,
            start_line=method_node.start_point[0] + 1,
            end_line=method_node.end_point[0] + 1,
        )
        
        # Parse body
        body_node = method_node.child_by_field_name("body")
        if body_node:
            method.body = SourceNode.from_ts_node(body_node, SourceNodeType.BLOCK)
            method.statements = self._parse_statements(body_node)
        
        return method
    
    def _parse_statements(
        self,
        block_node: tree_sitter.Node
    ) -> list[SourceNode]:
        """Parse statements in a block."""
        statements = []
        
        for child in block_node.children:
            if child.type in ("{", "}"):
                continue
            
            stmt = self._parse_statement(child)
            if stmt:
                statements.append(stmt)
        
        return statements
    
    def _parse_statement(
        self,
        node: tree_sitter.Node
    ) -> Optional[SourceNode]:
        """Parse a single statement."""
        type_map = {
            "if_statement": SourceNodeType.IF,
            "while_statement": SourceNodeType.WHILE,
            "for_statement": SourceNodeType.FOR,
            "return_statement": SourceNodeType.RETURN,
            "throw_statement": SourceNodeType.THROW,
            "assert_statement": SourceNodeType.ASSERT,
            "block": SourceNodeType.BLOCK,
            "expression_statement": SourceNodeType.EXPRESSION,
            "local_variable_declaration": SourceNodeType.VARIABLE_DECL,
        }
        
        node_type = type_map.get(node.type, SourceNodeType.STATEMENT)
        source_node = SourceNode.from_ts_node(node, node_type)
        
        # Parse children for compound statements
        if node_type in (SourceNodeType.IF, SourceNodeType.WHILE, 
                         SourceNodeType.FOR, SourceNodeType.BLOCK):
            for child in node.children:
                if child.type == "block":
                    block_stmts = self._parse_statements(child)
                    source_node.children.extend(block_stmts)
        
        return source_node


def parse_java_source(file_path: str | Path) -> Optional[SourceClass]:
    """
    Convenience function to parse a Java source file.
    
    Args:
        file_path: Path to Java source file
        
    Returns:
        SourceClass with parsed content
    """
    parser = SourceParser()
    return parser.parse_file(file_path)
