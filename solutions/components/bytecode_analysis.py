#!/usr/bin/env python3
"""
Bytecode syntactic analysis module (ISY).

Provides comprehensive CFG, basic block, and call graph analysis for bytecode.
This module implements the ISY (Implement Syntactic Analysis) component for
DTU 02242 Program Analysis.

Features:
- Control Flow Graph (CFG) construction with proper index→offset conversion
- Exception handler edges for try-catch blocks  
- Basic block identification and construction
- Call graph for inter-procedural analysis
- Dead code detection (unreachable instructions/methods)

DTU 02242 Program Analysis - Group 21
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import jpamb
from jpamb import jvm
from jpamb.jvm import opcode as opc

# Import NodeType from ir.py to ensure consistency
from solutions.ir import NodeType


# =============================================================================
# Helper Functions for Node Classification
# =============================================================================


def classify_opcode(opcode: Any) -> NodeType:
    """
    Classify an opcode into a NodeType category.
    
    Args:
        opcode: Parsed opcode object from jpamb.jvm.opcode
        
    Returns:
        NodeType classification
    """
    tname = type(opcode).__name__
    
    type_map = {
        "Push": NodeType.PUSH,
        "Load": NodeType.LOAD,
        "Store": NodeType.ASSIGN,
        "Binary": NodeType.BINARY,
        "Negate": NodeType.UNARY,
        "Cast": NodeType.UNARY,
        "Incr": NodeType.ASSIGN,
        "Dup": NodeType.DUP,
        "If": NodeType.BRANCH,
        "Ifz": NodeType.BRANCH,
        "Goto": NodeType.JUMP,
        "TableSwitch": NodeType.SWITCH,
        "LookupSwitch": NodeType.SWITCH,
        "Return": NodeType.RETURN,
        "Throw": NodeType.THROW,
        "InvokeVirtual": NodeType.INVOKE,
        "InvokeStatic": NodeType.INVOKE,
        "InvokeSpecial": NodeType.INVOKE,
        "InvokeInterface": NodeType.INVOKE,
        "New": NodeType.NEW,
        "NewArray": NodeType.NEW,
        "ArrayLoad": NodeType.ARRAY_ACCESS,
        "ArrayStore": NodeType.ARRAY_ACCESS,
        "ArrayLength": NodeType.ARRAY_ACCESS,
        "Get": NodeType.FIELD_ACCESS,
        "Put": NodeType.FIELD_ACCESS,
    }
    
    return type_map.get(tname, NodeType.OTHER)


def classify_opr(opr: str) -> NodeType:
    """Classify instruction by its operation string."""
    opr_map = {
        "push": NodeType.PUSH,
        "load": NodeType.LOAD,
        "store": NodeType.ASSIGN,
        "incr": NodeType.ASSIGN,
        "binary": NodeType.BINARY,
        "negate": NodeType.UNARY,
        "cast": NodeType.UNARY,
        "dup": NodeType.DUP,
        "if": NodeType.BRANCH,
        "ifz": NodeType.BRANCH,
        "goto": NodeType.JUMP,
        "tableswitch": NodeType.SWITCH,
        "lookupswitch": NodeType.SWITCH,
        "return": NodeType.RETURN,
        "throw": NodeType.THROW,
        "invoke": NodeType.INVOKE,
        "new": NodeType.NEW,
        "newarray": NodeType.NEW,
        "array_load": NodeType.ARRAY_ACCESS,
        "array_store": NodeType.ARRAY_ACCESS,
        "arraylength": NodeType.ARRAY_ACCESS,
        "get": NodeType.FIELD_ACCESS,
        "put": NodeType.FIELD_ACCESS,
    }
    return opr_map.get(opr, NodeType.OTHER)


# =============================================================================
# Exception Handler
# =============================================================================

@dataclass(frozen=True)
class ExceptionHandler:
    """
    Represents a try-catch exception handler range.
    
    Attributes:
        start_pc: Start of protected region (inclusive, byte offset)
        end_pc: End of protected region (exclusive, byte offset)
        handler_pc: Start of handler code (byte offset)
        catch_type: Exception class name (None for catch-all/finally)
    """
    start_pc: int
    end_pc: int
    handler_pc: int
    catch_type: Optional[str] = None
    
    @classmethod
    def from_json(cls, data: dict, index_to_offset: Dict[int, int] = None) -> ExceptionHandler:
        """
        Parse exception handler from jvm2json format.
        
        Note: Exception handler start/end/handler are instruction indices,
        not byte offsets. We convert them if index_to_offset is provided.
        """
        start = data.get("start", 0)
        end = data.get("end", 0)
        handler = data.get("handler", 0)
        
        # Convert indices to offsets if mapping provided
        if index_to_offset:
            start = index_to_offset.get(start, start)
            end = index_to_offset.get(end, end)
            handler = index_to_offset.get(handler, handler)
        
        return cls(
            start_pc=start,
            end_pc=end,
            handler_pc=handler,
            catch_type=data.get("catchType")
        )


# =============================================================================
# CFG Node (Simple version for dead code analysis)
# =============================================================================

@dataclass
class CFGNode:
    """A node in the control flow graph."""
    offset: int
    instruction: dict
    successors: Set[int] = field(default_factory=set)
    predecessors: Set[int] = field(default_factory=set)
    node_type: NodeType = NodeType.OTHER
    is_leader: bool = False
    basic_block_id: Optional[int] = None
    exception_handlers: List[ExceptionHandler] = field(default_factory=list)
    
    @property
    def pc(self) -> int:
        """Alias for offset (for compatibility with ir.py)."""
        return self.offset
    
    @property
    def opcode(self) -> Any:
        """Return instruction dict as opcode (for compatibility)."""
        return self.instruction
    
    def is_branch(self) -> bool:
        """Check if this node is a branching instruction."""
        return self.node_type in (NodeType.BRANCH, NodeType.SWITCH)
    
    def is_jump(self) -> bool:
        """Check if this node is an unconditional jump."""
        return self.node_type == NodeType.JUMP
    
    def is_terminator(self) -> bool:
        """Check if this node terminates execution (return/throw)."""
        return self.node_type in (NodeType.RETURN, NodeType.THROW, NodeType.EXIT)
    
    @property
    def instr_str(self) -> str:
        """Human-readable instruction string."""
        opr = self.instruction.get("opr", "unknown")
        return f"{opr}"


@dataclass
class CFG:
    """Control Flow Graph for a method."""
    method_name: str
    nodes: Dict[int, CFGNode] = field(default_factory=dict)
    entry_offset: int = 0
    
    def add_edge(self, from_offset: int, to_offset: int):
        """Add an edge from one node to another."""
        if from_offset in self.nodes and to_offset in self.nodes:
            self.nodes[from_offset].successors.add(to_offset)
            self.nodes[to_offset].predecessors.add(from_offset)
    
    def get_reachable_nodes(self) -> Set[int]:
        """Find all nodes reachable from entry using DFS."""
        reachable = set()
        worklist = [self.entry_offset]
        
        while worklist:
            offset = worklist.pop()
            if offset in reachable or offset not in self.nodes:
                continue
            
            reachable.add(offset)
            for succ in self.nodes[offset].successors:
                if succ not in reachable:
                    worklist.append(succ)
        
        return reachable
    
    def get_unreachable_nodes(self) -> Set[int]:
        """Find all unreachable nodes in the CFG."""
        reachable = self.get_reachable_nodes()
        all_nodes = set(self.nodes.keys())
        return all_nodes - reachable


@dataclass
class CallGraph:
    """Call graph tracking method invocations."""
    calls: Dict[str, Set[str]] = field(default_factory=dict)
    all_methods: Set[str] = field(default_factory=set)
    
    def add_call(self, caller: str, callee: str):
        """Record that caller invokes callee."""
        if caller not in self.calls:
            self.calls[caller] = set()
        self.calls[caller].add(callee)
    
    def add_method(self, method_name: str):
        """Register a method."""
        self.all_methods.add(method_name)
    
    def get_reachable_from(self, entry_points: Set[str]) -> Set[str]:
        """Compute reachable methods from entry points."""
        reachable = set()
        worklist = list(entry_points)
        
        while worklist:
            method = worklist.pop()
            if method in reachable:
                continue
            
            reachable.add(method)
            
            # Add all methods called by this method
            if method in self.calls:
                for callee in self.calls[method]:
                    if callee not in reachable:
                        worklist.append(callee)
        
        return reachable


@dataclass
class AnalysisResult:
    """Results from bytecode syntactic analysis."""
    cfgs: Dict[str, CFG]
    call_graph: CallGraph
    entry_points: Set[str]
    unreachable_methods: Set[str]
    dead_instructions: Dict[str, Set[int]]  # method -> set of dead offsets
    total_instructions: int = 0  # Total number of instructions across all methods
    
    def get_dead_instruction_count(self) -> int:
        """Get total count of dead instructions."""
        return sum(len(offsets) for offsets in self.dead_instructions.values())
    
    def get_debloat_percentage(self) -> float:
        """Calculate percentage of instructions that are dead code."""
        if self.total_instructions == 0:
            return 0.0
        return (self.get_dead_instruction_count() / self.total_instructions) * 100.0


class BytecodeAnalyzer:
    """Bytecode syntactic analyzer using CFG and call graph."""
    
    def __init__(self, suite: jpamb.Suite):
        self.suite = suite
        self.cfgs: Dict[str, CFG] = {}
        self.call_graph = CallGraph()
    
    def analyze_class(self, classname: jvm.ClassName) -> AnalysisResult:
        """
        Analyze a class and return dead code findings.
        
        Returns:
            AnalysisResult with CFGs, call graph, and dead code locations
        """
        try:
            cls = self.suite.findclass(classname)
        except Exception as e:
            raise ValueError(f"Could not load class {classname}: {e}")
        
        methods = cls.get("methods", [])
        
        # Build CFGs and call graph
        for method in methods:
            method_name = method.get("name", "<unknown>")
            full_name = f"{classname}.{method_name}"
            
            self.call_graph.add_method(full_name)
            
            code = method.get("code")
            if code:
                cfg = self.build_cfg(full_name, code)
                self.cfgs[full_name] = cfg
                self.extract_calls(full_name, code)
        
        # Find entry points
        entry_points = self.get_entry_points(cls, classname)
        
        # Find unreachable methods
        reachable_methods = self.call_graph.get_reachable_from(entry_points)
        unreachable_methods = self.call_graph.all_methods - reachable_methods
        
        # Find dead instructions in reachable methods
        dead_instructions = {}
        for method_name, cfg in self.cfgs.items():
            if method_name in reachable_methods:
                unreachable = cfg.get_unreachable_nodes()
                if unreachable:
                    dead_instructions[method_name] = unreachable
        
        # Count total instructions across all methods
        total_instructions = sum(len(cfg.nodes) for cfg in self.cfgs.values())
        
        return AnalysisResult(
            cfgs=self.cfgs,
            call_graph=self.call_graph,
            entry_points=entry_points,
            unreachable_methods=unreachable_methods,
            dead_instructions=dead_instructions,
            total_instructions=total_instructions
        )
    
    def build_cfg(self, method_name: str, code: dict) -> CFG:
        """Build control flow graph from bytecode."""
        cfg = CFG(method_name=method_name)
        bytecode = code.get("bytecode", [])
        
        if not bytecode:
            return cfg
        
        # Build index-to-offset mapping
        # In jpamb's bytecode JSON, jump targets are instruction indices (0-based
        # position in the bytecode list), not byte offsets. We need to convert.
        index_to_offset: Dict[int, int] = {}
        for i, inst in enumerate(bytecode):
            offset = inst.get("offset", -1)
            if offset >= 0:
                index_to_offset[i] = offset
        
        def resolve_target(target_index: int) -> int | None:
            """Convert a target index to its corresponding byte offset."""
            return index_to_offset.get(target_index)
        
        # Create nodes
        for inst in bytecode:
            offset = inst.get("offset", -1)
            if offset >= 0:
                cfg.nodes[offset] = CFGNode(offset=offset, instruction=inst)
        
        # Add edges based on control flow
        for i, inst in enumerate(bytecode):
            offset = inst.get("offset", -1)
            if offset < 0 or offset not in cfg.nodes:
                continue
            
            opr = inst.get("opr", "")
            
            if opr in ("if", "ifz"):
                # Branch: add both target and fall-through edges
                target_index = inst.get("target")
                if target_index is not None:
                    target_offset = resolve_target(target_index)
                    if target_offset is not None:
                        cfg.add_edge(offset, target_offset)
                
                if i + 1 < len(bytecode):
                    next_offset = bytecode[i + 1].get("offset")
                    if next_offset is not None:
                        cfg.add_edge(offset, next_offset)
            
            elif opr == "goto":
                # Unconditional jump
                target_index = inst.get("target")
                if target_index is not None:
                    target_offset = resolve_target(target_index)
                    if target_offset is not None:
                        cfg.add_edge(offset, target_offset)
            
            elif opr in ("return", "throw"):
                # Method exits - no successors
                pass
            
            elif opr in ("tableswitch", "lookupswitch"):
                # Switch statements - default and targets are also indices
                default_index = inst.get("default")
                if default_index is not None:
                    default_offset = resolve_target(default_index)
                    if default_offset is not None:
                        cfg.add_edge(offset, default_offset)
                
                # Handle targets - can be list of ints or list of dicts
                for case in inst.get("targets", []):
                    if isinstance(case, int):
                        # tableswitch: targets is list of indices
                        target_offset = resolve_target(case)
                        if target_offset is not None:
                            cfg.add_edge(offset, target_offset)
                    elif isinstance(case, dict):
                        # lookupswitch: targets is list of {match, target} dicts
                        target_index = case.get("target")
                        if target_index is not None:
                            target_offset = resolve_target(target_index)
                            if target_offset is not None:
                                cfg.add_edge(offset, target_offset)
            
            else:
                # Normal instruction - fall through
                if i + 1 < len(bytecode):
                    next_offset = bytecode[i + 1].get("offset")
                    if next_offset is not None:
                        cfg.add_edge(offset, next_offset)
        
        return cfg
    
    def extract_calls(self, caller: str, code: dict):
        """Extract method calls from bytecode."""
        bytecode = code.get("bytecode", [])
        
        for inst in bytecode:
            if inst.get("opr") == "invoke":
                method_info = inst.get("method", {})
                ref = method_info.get("ref", {})
                callee_class = ref.get("name", "")
                callee_name = method_info.get("name", "")
                
                if callee_class and callee_name:
                    callee = f"{callee_class}.{callee_name}"
                    self.call_graph.add_call(caller, callee)
    
    def get_entry_points(self, cls: dict, classname: jvm.ClassName) -> Set[str]:
        """Identify entry points - methods that can be called externally."""
        entry_points = set()
        methods = cls.get("methods", [])
        
        for method in methods:
            method_name = method.get("name", "<unknown>")
            full_name = f"{classname}.{method_name}"
            access = method.get("access", [])
            
            # Entry points: main, public methods, static initializers, constructors
            if (method_name == "main" or 
                "public" in access or 
                "protected" in access or
                method_name == "<clinit>" or
                (method_name == "<init>" and "public" in access)):
                entry_points.add(full_name)
        
        return entry_points


# =============================================================================
# Basic Block
# =============================================================================

@dataclass
class BasicBlock:
    """
    Basic block in the CFG - maximal sequence of instructions with single entry/exit.
    
    Attributes:
        block_id: Unique identifier for this block
        start_pc: First instruction PC (byte offset)
        end_pc: Last instruction PC (byte offset)
        nodes: List of CFGNodes in this block
        successor_blocks: IDs of successor basic blocks
        predecessor_blocks: IDs of predecessor basic blocks
    """
    block_id: int
    start_pc: int
    end_pc: int
    nodes: List[CFGNode] = field(default_factory=list)
    successor_blocks: List[int] = field(default_factory=list)
    predecessor_blocks: List[int] = field(default_factory=list)
    
    def __len__(self) -> int:
        return len(self.nodes)


# =============================================================================
# Enhanced CFG Builder (compatible with ir.py)
# =============================================================================

class CFGBuilder:
    """
    Builds Control Flow Graph from JVM bytecode.
    
    This class provides a more detailed CFG with:
    - Parsed opcode objects
    - Basic block identification
    - Exception handler edges
    - Node type classification
    
    Compatible with solutions/ir.py MethodIR.
    
    Example:
        builder = CFGBuilder(bytecode_list, exception_handlers)
        cfg = builder.build()
        blocks = builder.get_basic_blocks()
    """
    
    def __init__(
        self,
        bytecode: List[dict],
        exception_handlers: List[ExceptionHandler] = None
    ):
        """
        Initialize CFG builder.
        
        Args:
            bytecode: List of bytecode instruction dicts from jvm2json
            exception_handlers: List of exception handlers for the method
        """
        self.bytecode = bytecode
        self.exception_handlers = exception_handlers or []
        
        # Intermediate data structures
        self._opcodes: Dict[int, Any] = {}  # offset -> parsed opcode
        self._pc_list: List[int] = []  # ordered list of offsets
        self._leaders: Set[int] = set()  # basic block leaders
        self._cfg: Dict[int, CFGNode] = {}  # final CFG (offset -> node)
        self._basic_blocks: List[BasicBlock] = []
        
        # Index to offset mapping
        self._index_to_offset: Dict[int, int] = {}
        
    def build(self) -> Dict[int, CFGNode]:
        """
        Build the complete CFG.
        
        Returns:
            Dictionary mapping byte offset to CFGNode
        """
        if not self.bytecode:
            return {}
        
        # Pass 1: Parse opcodes and build index mapping
        self._parse_opcodes()
        
        # Pass 2: Find leaders (basic block starts)
        self._find_leaders()
        
        # Pass 3: Build CFG nodes with successors
        self._build_nodes()
        
        # Pass 4: Compute predecessors and assign basic blocks
        self._compute_predecessors()
        self._build_basic_blocks()
        
        return self._cfg
    
    def get_basic_blocks(self) -> List[BasicBlock]:
        """Get the computed basic blocks (after build())."""
        return self._basic_blocks
    
    def _parse_opcodes(self) -> None:
        """Parse all bytecode instructions into opcode objects."""
        for i, instr in enumerate(self.bytecode):
            offset = instr.get("offset", -1)
            if offset < 0:
                continue
                
            self._index_to_offset[i] = offset
            self._pc_list.append(offset)
            
            # Try to parse opcode
            try:
                opcode = opc.Opcode.from_json(instr)
            except (NotImplementedError, KeyError):
                opcode = None
            
            self._opcodes[offset] = opcode
        
        self._pc_list.sort()
    
    def _resolve_target(self, target_index: int) -> Optional[int]:
        """Convert instruction index to byte offset."""
        return self._index_to_offset.get(target_index)
    
    def _find_leaders(self) -> None:
        """
        Identify basic block leaders.
        
        Leaders are:
        1. First instruction of method
        2. Target of any branch/jump
        3. Instruction following a branch/jump
        4. Exception handler entry points
        """
        if not self._pc_list:
            return
        
        # First instruction is always a leader
        self._leaders.add(self._pc_list[0])
        
        # Find targets and instructions after branches
        for i, instr in enumerate(self.bytecode):
            offset = instr.get("offset", -1)
            if offset < 0:
                continue
            
            opr = instr.get("opr", "")
            targets = self._get_branch_targets(instr)
            
            if targets:
                # All targets are leaders
                self._leaders.update(targets)
                
                # Instruction after branch is also a leader (for conditional)
                if opr in ("if", "ifz") and i + 1 < len(self.bytecode):
                    next_offset = self.bytecode[i + 1].get("offset")
                    if next_offset is not None:
                        self._leaders.add(next_offset)
            
            # Instructions after gotos/returns/throws are leaders
            if opr in ("goto", "return", "throw") and i + 1 < len(self.bytecode):
                next_offset = self.bytecode[i + 1].get("offset")
                if next_offset is not None:
                    self._leaders.add(next_offset)
        
        # Exception handler entry points are leaders
        for handler in self.exception_handlers:
            if handler.handler_pc in self._opcodes or handler.handler_pc in [self._index_to_offset.get(i) for i in range(len(self.bytecode))]:
                self._leaders.add(handler.handler_pc)
    
    def _get_branch_targets(self, instr: dict) -> List[int]:
        """Get all possible jump targets for an instruction (as byte offsets)."""
        targets = []
        opr = instr.get("opr", "")
        
        if opr in ("if", "ifz", "goto"):
            target_index = instr.get("target")
            if target_index is not None:
                target_offset = self._resolve_target(target_index)
                if target_offset is not None:
                    targets.append(target_offset)
        
        elif opr == "tableswitch":
            default_index = instr.get("default")
            if default_index is not None:
                default_offset = self._resolve_target(default_index)
                if default_offset is not None:
                    targets.append(default_offset)
            for case in instr.get("targets", []):
                if isinstance(case, int):
                    case_offset = self._resolve_target(case)
                    if case_offset is not None:
                        targets.append(case_offset)
        
        elif opr == "lookupswitch":
            default_index = instr.get("default")
            if default_index is not None:
                default_offset = self._resolve_target(default_index)
                if default_offset is not None:
                    targets.append(default_offset)
            for case in instr.get("targets", []):
                if isinstance(case, dict):
                    target_index = case.get("target")
                    if target_index is not None:
                        target_offset = self._resolve_target(target_index)
                        if target_offset is not None:
                            targets.append(target_offset)
        
        return targets
    
    def _build_nodes(self) -> None:
        """Build CFG nodes with successor edges."""
        for i, instr in enumerate(self.bytecode):
            offset = instr.get("offset", -1)
            if offset < 0:
                continue
            
            opcode = self._opcodes.get(offset)
            opr = instr.get("opr", "")
            
            # Classify node type
            if opcode:
                node_type = classify_opcode(opcode)
            else:
                node_type = classify_opr(opr)
            
            # Get exception handlers covering this instruction
            handlers = [
                h for h in self.exception_handlers
                if h.start_pc <= offset < h.end_pc
            ]
            
            # Create node
            node = CFGNode(
                offset=offset,
                instruction=instr,
                node_type=node_type,
                is_leader=(offset in self._leaders),
                exception_handlers=handlers,
            )
            
            # Compute successors
            successors = self._compute_successors(i, instr)
            node.successors = set(successors)
            
            # Add exception handler targets as successors
            for handler in handlers:
                node.successors.add(handler.handler_pc)
            
            self._cfg[offset] = node
    
    def _compute_successors(self, index: int, instr: dict) -> List[int]:
        """Compute successor byte offsets for an instruction."""
        opr = instr.get("opr", "")
        offset = instr.get("offset", -1)
        successors = []
        
        # Return and throw have no successors
        if opr in ("return", "throw"):
            return successors
        
        # Get next instruction offset
        next_offset = None
        if index + 1 < len(self.bytecode):
            next_offset = self.bytecode[index + 1].get("offset")
        
        if opr in ("if", "ifz"):
            # Conditional: fallthrough + target
            if next_offset is not None:
                successors.append(next_offset)
            target_index = instr.get("target")
            if target_index is not None:
                target_offset = self._resolve_target(target_index)
                if target_offset is not None:
                    successors.append(target_offset)
        
        elif opr == "goto":
            # Unconditional: only target
            target_index = instr.get("target")
            if target_index is not None:
                target_offset = self._resolve_target(target_index)
                if target_offset is not None:
                    successors.append(target_offset)
        
        elif opr in ("tableswitch", "lookupswitch"):
            # Switch: default + all case targets
            successors.extend(self._get_branch_targets(instr))
            # Remove duplicates
            successors = list(dict.fromkeys(successors))
        
        else:
            # Sequential instruction: fallthrough
            if next_offset is not None:
                successors.append(next_offset)
        
        return successors
    
    def _compute_predecessors(self) -> None:
        """Compute predecessor edges from successors."""
        for offset, node in self._cfg.items():
            for succ_offset in node.successors:
                if succ_offset in self._cfg:
                    self._cfg[succ_offset].predecessors.add(offset)
    
    def _build_basic_blocks(self) -> None:
        """Build basic blocks from leaders."""
        sorted_leaders = sorted(self._leaders)
        
        block_id = 0
        for i, leader_pc in enumerate(sorted_leaders):
            # Find end of this block
            if i + 1 < len(sorted_leaders):
                next_leader = sorted_leaders[i + 1]
            else:
                next_leader = float('inf')
            
            # Collect nodes in this block
            block_nodes = []
            for pc in self._pc_list:
                if pc >= leader_pc and pc < next_leader:
                    if pc in self._cfg:
                        node = self._cfg[pc]
                        node.basic_block_id = block_id
                        block_nodes.append(node)
            
            if block_nodes:
                block = BasicBlock(
                    block_id=block_id,
                    start_pc=block_nodes[0].offset,
                    end_pc=block_nodes[-1].offset,
                    nodes=block_nodes,
                )
                self._basic_blocks.append(block)
                block_id += 1
        
        # Compute successor/predecessor blocks
        for block in self._basic_blocks:
            if block.nodes:
                last_node = block.nodes[-1]
                for succ_offset in last_node.successors:
                    if succ_offset in self._cfg:
                        succ_block_id = self._cfg[succ_offset].basic_block_id
                        if succ_block_id is not None and succ_block_id not in block.successor_blocks:
                            block.successor_blocks.append(succ_block_id)
        
        # Compute predecessor blocks
        for block in self._basic_blocks:
            for succ_id in block.successor_blocks:
                for other in self._basic_blocks:
                    if other.block_id == succ_id:
                        if block.block_id not in other.predecessor_blocks:
                            other.predecessor_blocks.append(block.block_id)


def build_cfg_from_json(method_json: dict) -> tuple:
    """
    Convenience function to build CFG from method JSON.
    
    Args:
        method_json: Method dict from jvm2json output
        
    Returns:
        Tuple of (cfg dict, basic_blocks list)
    """
    code = method_json.get("code", {})
    bytecode = code.get("bytecode", [])
    exceptions = code.get("exceptions", [])
    
    # Build index to offset mapping first
    index_to_offset = {}
    for i, inst in enumerate(bytecode):
        offset = inst.get("offset", -1)
        if offset >= 0:
            index_to_offset[i] = offset
    
    handlers = [ExceptionHandler.from_json(e, index_to_offset) for e in exceptions]
    
    builder = CFGBuilder(bytecode, handlers)
    cfg = builder.build()
    blocks = builder.get_basic_blocks()
    
    return cfg, blocks

