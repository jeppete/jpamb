"""
solutions/ir.py

Intermediate Representation (IR) module for JPAMB bytecode analysis.

This module provides the MethodIR class which unifies CFG (Control Flow Graph)
and statement-level AST representations for downstream analysis components:
- IIN (dynamic traces): Trace execution on CFG
- NAB/NAN (refinement): Static analysis on statements
- NCR (removal): Delete/modify CFG nodes

DTU 02242 Program Analysis - Group 21
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional, Iterator

from jpamb import jvm
from jpamb.model import Suite


class NodeType(Enum):
    """
    Classification of CFG nodes based on their control flow behavior.
    
    Used for analysis categorization and statement grouping.
    """
    ENTRY = auto()          # Method entry point
    EXIT = auto()           # Method exit (return/throw)
    ASSIGN = auto()         # Assignment/store operations
    LOAD = auto()           # Load operations
    PUSH = auto()           # Push constant operations
    BRANCH = auto()         # Conditional branch (if/ifz)
    JUMP = auto()           # Unconditional jump (goto)
    SWITCH = auto()         # Table switch
    INVOKE = auto()         # Method invocation
    RETURN = auto()         # Return statement
    THROW = auto()          # Throw exception
    NEW = auto()            # Object/array creation
    BINARY = auto()         # Binary operation
    UNARY = auto()          # Unary operation (negate, cast)
    ARRAY_ACCESS = auto()   # Array load/store
    FIELD_ACCESS = auto()   # Field get/put
    DUP = auto()            # Stack duplication
    OTHER = auto()          # Other operations


class StatementType(Enum):
    """
    High-level statement classification for grouped bytecode sequences.
    
    Aggregates multiple bytecodes into logical statements.
    """
    ASSIGN = auto()         # Variable assignment (load + op + store)
    IF = auto()             # Conditional branch with condition
    INVOKE = auto()         # Method call with arguments
    RETURN = auto()         # Return statement with optional value
    THROW = auto()          # Exception throw
    SWITCH = auto()         # Switch statement
    LOOP_HEADER = auto()    # Loop condition check
    NEW_OBJECT = auto()     # Object instantiation
    NEW_ARRAY = auto()      # Array creation
    ARRAY_ASSIGN = auto()   # Array element assignment
    FIELD_ASSIGN = auto()   # Field assignment
    EXPR = auto()           # Expression (side-effect free)
    NOP = auto()            # No operation / fallthrough


@dataclass(frozen=True)
class ExceptionHandler:
    """
    Represents a try-catch exception handler range.
    
    Attributes:
        start_pc: Start of protected region (inclusive)
        end_pc: End of protected region (exclusive)
        handler_pc: Start of handler code
        catch_type: Exception class name (None for catch-all/finally)
    """
    start_pc: int
    end_pc: int
    handler_pc: int
    catch_type: Optional[str] = None
    
    @classmethod
    def from_json(cls, data: dict) -> ExceptionHandler:
        """Parse exception handler from jvm2json format."""
        return cls(
            start_pc=data.get("start", 0),
            end_pc=data.get("end", 0),
            handler_pc=data.get("handler", 0),
            catch_type=data.get("catchType")
        )


@dataclass
class CFGNode:
    """
    Control Flow Graph node representing a single bytecode instruction.
    
    Attributes:
        pc: Program counter (bytecode offset)
        opcode: Opcode object from jpamb.jvm.opcode
        instr_str: Human-readable instruction string
        successors: List of successor PC values
        predecessors: List of predecessor PC values
        node_type: Classification of the instruction
        exception_handlers: Exception handlers covering this instruction
        is_leader: Whether this is a basic block leader
        basic_block_id: ID of the containing basic block
    """
    pc: int
    opcode: Any  # jvm.Opcode
    instr_str: str
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    node_type: NodeType = NodeType.OTHER
    exception_handlers: list[ExceptionHandler] = field(default_factory=list)
    is_leader: bool = False
    basic_block_id: Optional[int] = None
    
    def __hash__(self) -> int:
        return hash(self.pc)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CFGNode):
            return False
        return self.pc == other.pc
    
    def is_branch(self) -> bool:
        """Check if this node is a branching instruction."""
        return self.node_type in (NodeType.BRANCH, NodeType.SWITCH)
    
    def is_jump(self) -> bool:
        """Check if this node is an unconditional jump."""
        return self.node_type == NodeType.JUMP
    
    def is_terminator(self) -> bool:
        """Check if this node terminates execution (return/throw)."""
        return self.node_type in (NodeType.RETURN, NodeType.THROW, NodeType.EXIT)
    
    def has_fallthrough(self) -> bool:
        """Check if control can fall through to next instruction."""
        return not (self.is_jump() or self.is_terminator())


@dataclass
class Statement:
    """
    High-level statement grouping multiple bytecode instructions.
    
    Groups related bytecodes into logical statements for easier analysis.
    For example, an assignment statement might group:
    - iload_1 (load value)
    - iconst_1 (load constant)
    - iadd (add)
    - istore_2 (store result)
    
    Attributes:
        start_pc: First bytecode offset in statement
        end_pc: Last bytecode offset in statement (inclusive)
        stmt_type: Statement classification
        children: Nested statements (for compound statements)
        pcs: All PC values in this statement
        target_pcs: Branch/jump target PCs (for control flow)
        variables_read: Local variable indices read
        variables_written: Local variable indices written
        description: Human-readable description
    """
    start_pc: int
    end_pc: int
    stmt_type: StatementType
    children: list[Statement] = field(default_factory=list)
    pcs: list[int] = field(default_factory=list)
    target_pcs: list[int] = field(default_factory=list)
    variables_read: set[int] = field(default_factory=set)
    variables_written: set[int] = field(default_factory=set)
    description: str = ""
    
    def contains_pc(self, pc: int) -> bool:
        """Check if this statement contains the given PC."""
        return pc in self.pcs or self.start_pc <= pc <= self.end_pc
    
    def __repr__(self) -> str:
        return f"Statement({self.stmt_type.name}, pc={self.start_pc}-{self.end_pc})"


@dataclass
class BasicBlock:
    """
    Basic block in the CFG - maximal sequence of instructions with single entry/exit.
    
    Attributes:
        block_id: Unique identifier for this block
        start_pc: First instruction PC
        end_pc: Last instruction PC
        nodes: List of CFGNodes in this block
        successor_blocks: IDs of successor basic blocks
        predecessor_blocks: IDs of predecessor basic blocks
    """
    block_id: int
    start_pc: int
    end_pc: int
    nodes: list[CFGNode] = field(default_factory=list)
    successor_blocks: list[int] = field(default_factory=list)
    predecessor_blocks: list[int] = field(default_factory=list)
    
    def __len__(self) -> int:
        return len(self.nodes)


@dataclass
class MethodIR:
    """
    Complete Intermediate Representation for a single method.
    
    Unifies CFG and statement-level representations for comprehensive
    bytecode analysis. This is the primary interface for downstream
    components (IIN, NAB, NCR).
    
    Attributes:
        method_id: Fully qualified method identifier
        method_name: Simple method name
        class_name: Fully qualified class name
        cfg: Mapping from PC to CFGNode
        statements: List of high-level statements
        basic_blocks: List of basic blocks
        exception_handlers: All exception handlers in method
        max_locals: Maximum local variable slots
        max_stack: Maximum operand stack depth
        entry_pc: Entry point PC (usually 0)
        exit_pcs: Set of exit point PCs
        line_info: Mapping from PC to source line number
    """
    method_id: str
    method_name: str
    class_name: str
    cfg: dict[int, CFGNode] = field(default_factory=dict)
    statements: list[Statement] = field(default_factory=list)
    basic_blocks: list[BasicBlock] = field(default_factory=list)
    exception_handlers: list[ExceptionHandler] = field(default_factory=list)
    max_locals: int = 0
    max_stack: int = 0
    entry_pc: int = 0
    exit_pcs: set[int] = field(default_factory=set)
    line_info: dict[int, int] = field(default_factory=dict)
    
    @classmethod
    def from_class(
        cls,
        class_path: str | Path,
        method_signature: str
    ) -> MethodIR:
        """
        Create MethodIR from a decompiled class file and method signature.
        
        Args:
            class_path: Path to decompiled JSON file (from jvm2json)
            method_signature: Method signature like 'assertPositive:(I)V'
            
        Returns:
            Complete MethodIR for the specified method
            
        Example:
            ir = MethodIR.from_class('target/decompiled/jpamb/cases/Simple.json', 
                                      'assertPositive:(I)V')
            assert ir.cfg[0].successors == [3, 10]  # if branch
        """
        
        class_path = Path(class_path)
        
        # Parse method name and descriptor
        if ':' in method_signature:
            method_name, descriptor = method_signature.split(':', 1)
        else:
            method_name = method_signature
            descriptor = None
        
        # Load class JSON
        with open(class_path) as f:
            class_data = json.load(f)
        
        class_name = class_data.get("name", "").replace("/", ".")
        
        # Find the method
        method_data = None
        for m in class_data.get("methods", []):
            if m["name"] == method_name:
                # If descriptor provided, match it
                if descriptor is not None:
                    m_desc = _build_descriptor(m)
                    if m_desc == descriptor:
                        method_data = m
                        break
                else:
                    method_data = m
                    break
        
        if method_data is None:
            raise ValueError(f"Method {method_signature} not found in {class_path}")
        
        # Build the IR
        return cls._from_method_data(
            method_data,
            class_name,
            method_name,
            method_signature
        )
    
    @classmethod
    def from_method_id(cls, method_id: jvm.AbsMethodID) -> MethodIR:
        """
        Create MethodIR from a JPAMB method ID.
        
        Args:
            method_id: AbsMethodID from jpamb.jvm
            
        Returns:
            Complete MethodIR for the method
        """
        suite = Suite()
        decompiled_path = suite.decompiledfile(method_id.classname)
        
        # Build method signature
        signature = f"{method_id.extension.name}:{method_id.extension.encode()}"
        
        return cls.from_class(decompiled_path, signature)
    
    @classmethod
    def from_suite_method(cls, method_id: jvm.AbsMethodID) -> MethodIR:
        """
        Create MethodIR using Suite to find method data.
        
        Uses the existing jpamb.model.Suite infrastructure.
        """
        
        suite = Suite()
        method_data = suite.findmethod(method_id)
        
        class_name = str(method_id.classname)
        method_name = method_id.extension.name
        signature = f"{method_name}:{method_id.extension.encode()}"
        
        return cls._from_method_data(
            method_data,
            class_name,
            method_name,
            signature
        )
    
    @classmethod
    def _from_method_data(
        cls,
        method_data: dict,
        class_name: str,
        method_name: str,
        method_id: str
    ) -> MethodIR:
        """Build MethodIR from parsed method JSON data."""
        from solutions.components.bytecode_analysis import CFGBuilder, ExceptionHandler as BAExceptionHandler
        from solutions.statement_grouper import StatementGrouper
        
        code = method_data.get("code", {})
        bytecode = code.get("bytecode", [])
        exceptions = code.get("exceptions", [])
        lines = code.get("lines", [])
        
        # Build index to offset mapping for exception handlers
        index_to_offset = {}
        for i, inst in enumerate(bytecode):
            offset = inst.get("offset", -1)
            if offset >= 0:
                index_to_offset[i] = offset
        
        # Create IR instance
        ir = cls(
            method_id=method_id,
            method_name=method_name,
            class_name=class_name,
            max_locals=code.get("max_locals", 0),
            max_stack=code.get("max_stack", 0),
        )
        
        # Parse exception handlers (using bytecode_analysis version with index conversion)
        ba_handlers = [
            BAExceptionHandler.from_json(e, index_to_offset) for e in exceptions
        ]
        # Convert to ir.ExceptionHandler for compatibility
        ir.exception_handlers = [
            ExceptionHandler(
                start_pc=h.start_pc,
                end_pc=h.end_pc,
                handler_pc=h.handler_pc,
                catch_type=h.catch_type
            ) for h in ba_handlers
        ]
        
        # Build line info
        for line_entry in lines:
            ir.line_info[line_entry["offset"]] = line_entry["line"]
        
        # Build CFG (pass the bytecode_analysis handlers)
        builder = CFGBuilder(bytecode, ba_handlers)
        ir.cfg = builder.build()
        ir.basic_blocks = builder.get_basic_blocks()
        
        # Find entry and exit points
        if ir.cfg:
            ir.entry_pc = min(ir.cfg.keys())
            ir.exit_pcs = {
                pc for pc, node in ir.cfg.items()
                if node.is_terminator()
            }
        
        # Group into statements
        grouper = StatementGrouper(ir.cfg, ir.basic_blocks)
        ir.statements = grouper.group()
        
        return ir
    
    def get_node(self, pc: int) -> Optional[CFGNode]:
        """Get CFG node at given PC."""
        return self.cfg.get(pc)
    
    def successors(self, pc: int) -> list[int]:
        """Get successor PCs for instruction at given PC."""
        node = self.cfg.get(pc)
        return node.successors if node else []
    
    def predecessors(self, pc: int) -> list[int]:
        """Get predecessor PCs for instruction at given PC."""
        node = self.cfg.get(pc)
        return node.predecessors if node else []
    
    def iter_nodes(self) -> Iterator[CFGNode]:
        """Iterate over all CFG nodes in PC order."""
        for pc in sorted(self.cfg.keys()):
            yield self.cfg[pc]
    
    def iter_basic_blocks(self) -> Iterator[BasicBlock]:
        """Iterate over basic blocks."""
        yield from self.basic_blocks
    
    def get_basic_block(self, pc: int) -> Optional[BasicBlock]:
        """Get the basic block containing the given PC."""
        node = self.cfg.get(pc)
        if node and node.basic_block_id is not None:
            for bb in self.basic_blocks:
                if bb.block_id == node.basic_block_id:
                    return bb
        return None
    
    def get_statement_at(self, pc: int) -> Optional[Statement]:
        """Get the statement containing the given PC."""
        for stmt in self.statements:
            if stmt.contains_pc(pc):
                return stmt
        return None
    
    def get_handlers_at(self, pc: int) -> list[ExceptionHandler]:
        """Get exception handlers covering the given PC."""
        return [
            h for h in self.exception_handlers
            if h.start_pc <= pc < h.end_pc
        ]
    
    def get_source_line(self, pc: int) -> Optional[int]:
        """Get source line number for PC (if available)."""
        # Find the closest line info at or before this PC
        best_line = None
        best_pc = -1
        for info_pc, line in self.line_info.items():
            if info_pc <= pc and info_pc > best_pc:
                best_pc = info_pc
                best_line = line
        return best_line
    
    def to_dot(self) -> str:
        """
        Generate DOT graph representation for visualization.
        
        Returns:
            DOT format string for Graphviz
        """
        lines = ['digraph CFG {']
        lines.append('  rankdir=TB;')
        lines.append('  node [shape=box, fontname="monospace"];')
        
        # Nodes
        for pc in sorted(self.cfg.keys()):
            node = self.cfg[pc]
            label = f"{pc}: {node.instr_str}"
            color = "black"
            if node.is_leader:
                color = "blue"
            if node.is_terminator():
                color = "red"
            lines.append(f'  n{pc} [label="{label}", color="{color}"];')
        
        # Edges
        for pc, node in self.cfg.items():
            for succ in node.successors:
                style = "solid"
                # Check if this is an exception edge
                for h in self.exception_handlers:
                    if h.start_pc <= pc < h.end_pc and succ == h.handler_pc:
                        style = "dashed"
                        break
                lines.append(f'  n{pc} -> n{succ} [style="{style}"];')
        
        lines.append('}')
        return '\n'.join(lines)
    
    def summary(self) -> str:
        """Generate a human-readable summary of the method IR."""
        lines = [
            f"Method: {self.method_id}",
            f"Class: {self.class_name}",
            f"Nodes: {len(self.cfg)}",
            f"Basic Blocks: {len(self.basic_blocks)}",
            f"Statements: {len(self.statements)}",
            f"Exception Handlers: {len(self.exception_handlers)}",
            f"Max Locals: {self.max_locals}",
            f"Max Stack: {self.max_stack}",
            f"Entry: {self.entry_pc}",
            f"Exits: {sorted(self.exit_pcs)}",
        ]
        return '\n'.join(lines)


def _build_descriptor(method_data: dict) -> str:
    """Build JVM method descriptor from method data."""
    params = []
    for p in method_data.get("params", []):
        t = p.get("type", {})
        params.append(_type_to_descriptor(t))
    
    ret = method_data.get("returns", {})
    ret_type = ret.get("type") if ret else None
    ret_desc = _type_to_descriptor({"base": ret_type} if ret_type else {})
    
    return f"({''.join(params)}){ret_desc}"


def _type_to_descriptor(type_data: dict) -> str:
    """Convert type data to JVM descriptor."""
    if not type_data:
        return "V"
    
    base = type_data.get("base")
    kind = type_data.get("kind")
    
    if kind == "array":
        inner = _type_to_descriptor(type_data.get("type", {}))
        return f"[{inner}"
    
    if kind == "class":
        name = type_data.get("name", "java/lang/Object")
        return f"L{name};"
    
    if base:
        type_map = {
            "int": "I",
            "integer": "I",
            "boolean": "Z",
            "byte": "B",
            "char": "C",
            "short": "S",
            "long": "J",
            "float": "F",
            "double": "D",
            "void": "V",
        }
        return type_map.get(str(base).lower(), "I")
    
    return "V"
