"""
solutions/syntaxer/__init__.py

Syntactic Analysis module for JPAMB.

Provides unified interface for both source-level and bytecode-level analysis:
- Source parsing with tree-sitter (Java AST extraction)
- Bytecode CFG construction
- Statement-level grouping

This module bridges source and bytecode analysis for comprehensive
program understanding.

DTU 02242 Program Analysis - Group 21
"""

from dataclasses import dataclass
from typing import Any, Optional

from solutions.syntaxer.source_parser import (
    SourceParser,
    SourceClass,
    SourceMethod,
    SourceNode,
    SourceNodeType,
    parse_java_source,
)

from solutions.ir import (
    MethodIR,
    CFGNode,
    Statement,
    BasicBlock,
    ExceptionHandler,
    NodeType,
    StatementType,
)

from solutions.components.bytecode_analysis import (
    CFGBuilder,
    classify_opcode,
    build_cfg_from_json,
)

from solutions.statement_grouper import (
    StatementGrouper,
    group_statements,
)


__all__ = [
    # Source analysis
    "SourceParser",
    "SourceClass",
    "SourceMethod",
    "SourceNode",
    "SourceNodeType",
    "parse_java_source",
    
    # IR
    "MethodIR",
    "CFGNode",
    "Statement",
    "BasicBlock",
    "ExceptionHandler",
    "NodeType",
    "StatementType",
    
    # CFG building
    "CFGBuilder",
    "classify_opcode",
    "build_cfg_from_json",
    
    # Statement grouping
    "StatementGrouper",
    "group_statements",
]


class UnifiedAnalyzer:
    """
    Unified analyzer combining source and bytecode analysis.
    
    Provides a single interface for analyzing Java methods using
    both source-level AST and bytecode-level CFG/statements.
    
    Example:
        analyzer = UnifiedAnalyzer()
        result = analyzer.analyze_method(method_id)
        
        # Access source info (if available)
        if result.source_method:
            print(f"Has assertion: {result.source_method.has_assertion()}")
        
        # Access bytecode IR
        print(f"CFG nodes: {len(result.ir.cfg)}")
        print(f"Statements: {len(result.ir.statements)}")
    """
    
    def __init__(self, suite=None):
        """
        Initialize the analyzer.
        
        Args:
            suite: Optional jpamb.model.Suite instance
        """
        from jpamb.model import Suite
        self.suite = suite or Suite()
        self.source_parser = SourceParser()
    
    def analyze_method(self, method_id) -> "AnalysisResult":
        """
        Analyze a method using both source and bytecode.
        
        Args:
            method_id: JPAMB method ID (AbsMethodID)
            
        Returns:
            AnalysisResult with source and bytecode info
        """
        # Build bytecode IR
        ir = MethodIR.from_suite_method(method_id)
        
        # Try to get source info
        source_method = None
        try:
            source_path = self.suite.sourcefile(method_id.classname)
            if source_path.exists():
                source_class = self.source_parser.parse_file(source_path)
                if source_class:
                    source_method = source_class.methods.get(method_id.extension.name)
        except Exception:
            pass  # Source analysis is optional
        
        return AnalysisResult(
            method_id=method_id,
            ir=ir,
            source_method=source_method,
        )
    
    def analyze_class(self, class_name) -> dict[str, "AnalysisResult"]:
        """
        Analyze all methods in a class.
        
        Args:
            class_name: JPAMB class name
            
        Returns:
            Dict mapping method names to AnalysisResult
        """
        import json
        
        # Load decompiled class
        decompiled_path = self.suite.decompiledfile(class_name)
        with open(decompiled_path) as f:
            class_data = json.load(f)
        
        results = {}
        
        for method_data in class_data.get("methods", []):
            method_name = method_data.get("name", "")
            
            # Skip constructors and static initializers
            if method_name in ("<init>", "<clinit>"):
                continue
            
            # Build method ID
            # This is simplified - full implementation would build proper signature
            try:
                ir = MethodIR._from_method_data(
                    method_data,
                    str(class_name),
                    method_name,
                    method_name
                )
                
                results[method_name] = AnalysisResult(
                    method_id=method_name,
                    ir=ir,
                    source_method=None,
                )
            except Exception:
                pass
        
        return results


@dataclass
class AnalysisResult:
    """
    Result of unified source+bytecode analysis.
    
    Attributes:
        method_id: Method identifier
        ir: Bytecode-level MethodIR
        source_method: Source-level SourceMethod (if available)
    """
    method_id: Any
    ir: MethodIR
    source_method: Optional[SourceMethod] = None
    
    def has_source(self) -> bool:
        """Check if source analysis is available."""
        return self.source_method is not None
    
    def has_assertion(self) -> bool:
        """
        Check if method contains assertions.
        
        Uses source analysis if available, falls back to bytecode.
        """
        if self.source_method:
            return self.source_method.has_assertion()
        
        # Check bytecode for AssertionError
        for node in self.ir.cfg.values():
            instr = node.instr_str.lower()
            if "assertionerror" in instr:
                return True
        
        return False
    
    def get_cfg(self) -> dict[int, CFGNode]:
        """Get the CFG."""
        return self.ir.cfg
    
    def get_statements(self) -> list[Statement]:
        """Get grouped statements."""
        return self.ir.statements
    
    def get_basic_blocks(self) -> list[BasicBlock]:
        """Get basic blocks."""
        return self.ir.basic_blocks
