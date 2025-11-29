#!/usr/bin/env python3
"""
Bytecode syntactic analysis module.

Provides CFG and call graph analysis for finding dead code.
Can be used as a standalone tool or called by other analyses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

import jpamb
from jpamb import jvm


@dataclass
class CFGNode:
    """A node in the control flow graph."""
    offset: int
    instruction: dict
    successors: Set[int] = field(default_factory=set)
    predecessors: Set[int] = field(default_factory=set)


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

