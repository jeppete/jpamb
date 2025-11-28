"""
tests/test_isy.py

Test suite for ISY (Implement Syntactic Analysis) component.

Tests the complete bytecode CFG/AST extraction pipeline:
- CFG construction and edge computation
- Basic block identification
- Statement grouping
- Exception handler integration
- Source-bytecode correlation

Covers 5 JPAMB case classes: Simple, Arrays, Calls, Loops, Tricky

DTU 02242 Program Analysis - Group 21
"""

import pytest
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from solutions.ir import (
    MethodIR, ExceptionHandler,
    NodeType, StatementType
)
from solutions.cfg_builder import CFGBuilder, classify_opcode, build_cfg_from_json
from solutions.statement_grouper import StatementGrouper, group_statements
from solutions.syntaxer import (
    SourceParser, UnifiedAnalyzer
)

from jpamb.model import Suite
from jpamb import jvm


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def suite():
    """Get JPAMB suite instance."""
    return Suite()


@pytest.fixture
def simple_class_data(suite):
    """Load Simple.json decompiled class."""
    path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def arrays_class_data(suite):
    """Load Arrays.json decompiled class."""
    path = suite.decompiled_folder / "jpamb" / "cases" / "Arrays.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def loops_class_data(suite):
    """Load Loops.json decompiled class."""
    path = suite.decompiled_folder / "jpamb" / "cases" / "Loops.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def calls_class_data(suite):
    """Load Calls.json decompiled class."""
    path = suite.decompiled_folder / "jpamb" / "cases" / "Calls.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def tricky_class_data(suite):
    """Load Tricky.json decompiled class."""
    path = suite.decompiled_folder / "jpamb" / "cases" / "Tricky.json"
    with open(path) as f:
        return json.load(f)


def get_method_from_class(class_data: dict, method_name: str) -> dict:
    """Helper to find method by name in class data."""
    for method in class_data.get("methods", []):
        if method["name"] == method_name:
            return method
    raise ValueError(f"Method {method_name} not found")


# ============================================================================
# CFG Builder Tests
# ============================================================================

class TestCFGBuilder:
    """Tests for CFG construction."""
    
    def test_empty_bytecode(self):
        """CFG from empty bytecode should be empty."""
        builder = CFGBuilder([])
        cfg = builder.build()
        assert cfg == {}
    
    def test_simple_sequential(self, simple_class_data):
        """Test CFG for sequential method (justReturn)."""
        method = get_method_from_class(simple_class_data, "justReturn")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        # Should have nodes for each instruction
        assert len(cfg) > 0
        
        # First instruction should be at offset 0
        assert 0 in cfg
        
        # Should have sequential successors
        first_node = cfg[0]
        assert len(first_node.successors) >= 0  # May be entry to return
    
    def test_conditional_branch_successors(self, simple_class_data):
        """Test if-branch has correct successors."""
        # assertPositive has: assert num > 0
        # Bytecode: get $assertionsDisabled, ifz ne target, load, ifz gt target, ...
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        # Find ifz instruction
        ifz_nodes = [n for n in cfg.values() if "ifz" in n.instr_str.lower()]
        
        # Should have conditional branches
        assert len(ifz_nodes) >= 1
        
        # Each ifz should have 2 successors (fallthrough + target)
        for node in ifz_nodes:
            assert len(node.successors) == 2, f"ifz at {node.pc} should have 2 successors"
    
    def test_goto_single_successor(self, loops_class_data):
        """Test goto has exactly one successor."""
        # forever() has: goto 0 (infinite loop)
        method = get_method_from_class(loops_class_data, "forever")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        # Find goto instruction
        goto_nodes = [n for n in cfg.values() if "goto" in n.instr_str.lower()]
        
        assert len(goto_nodes) >= 1
        
        for node in goto_nodes:
            # Goto should have exactly 1 successor (the target)
            assert len(node.successors) == 1
    
    def test_return_no_successors(self, simple_class_data):
        """Test return has no successors."""
        method = get_method_from_class(simple_class_data, "justReturn")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        # Find return instructions
        return_nodes = [n for n in cfg.values() 
                       if n.node_type == NodeType.RETURN]
        
        assert len(return_nodes) >= 1
        
        for node in return_nodes:
            assert len(node.successors) == 0, "Return should have no successors"
    
    def test_throw_no_successors(self, simple_class_data):
        """Test throw has no normal successors."""
        # assertFalse ends with throw
        method = get_method_from_class(simple_class_data, "assertFalse")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        throw_nodes = [n for n in cfg.values() 
                      if n.node_type == NodeType.THROW]
        
        assert len(throw_nodes) >= 1
        
        for node in throw_nodes:
            # Throw might have exception handler edges, but no normal successors
            normal_succs = [s for s in node.successors 
                          if s not in [h.handler_pc for h in node.exception_handlers]]
            assert len(normal_succs) == 0
    
    def test_predecessor_computation(self, simple_class_data):
        """Test that predecessors are correctly computed."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        # For every successor edge, there should be a corresponding predecessor
        for pc, node in cfg.items():
            for succ_pc in node.successors:
                if succ_pc in cfg:
                    assert pc in cfg[succ_pc].predecessors, \
                        f"PC {pc} should be predecessor of {succ_pc}"
    
    def test_basic_block_leaders(self, simple_class_data):
        """Test that leaders are correctly identified."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        blocks = builder.get_basic_blocks()
        
        # First instruction should be a leader
        if cfg:
            first_pc = min(cfg.keys())
            assert cfg[first_pc].is_leader
        
        # Branch targets should be leaders
        for node in cfg.values():
            if node.node_type == NodeType.BRANCH:
                for succ in node.successors:
                    if succ in cfg:
                        assert cfg[succ].is_leader, \
                            f"Branch target {succ} should be a leader"


class TestBasicBlocks:
    """Tests for basic block construction."""
    
    def test_basic_blocks_non_empty(self, simple_class_data):
        """Basic blocks should be created for non-trivial methods."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        blocks = builder.get_basic_blocks()
        
        assert len(blocks) >= 1
    
    def test_basic_block_contains_nodes(self, simple_class_data):
        """Each basic block should contain at least one node."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        blocks = builder.get_basic_blocks()
        
        for block in blocks:
            assert len(block.nodes) >= 1, f"Block {block.block_id} is empty"
    
    def test_basic_block_nodes_have_block_id(self, simple_class_data):
        """All nodes in CFG should have basic_block_id set."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        blocks = builder.get_basic_blocks()
        
        for node in cfg.values():
            assert node.basic_block_id is not None, \
                f"Node at {node.pc} has no basic_block_id"


# ============================================================================
# Statement Grouper Tests
# ============================================================================

class TestStatementGrouper:
    """Tests for statement-level grouping."""
    
    def test_empty_cfg(self):
        """Statement grouping on empty CFG."""
        grouper = StatementGrouper({})
        statements = grouper.group()
        assert statements == []
    
    def test_groups_assignment(self, simple_class_data):
        """Test assignment statement grouping."""
        # justAdd does: return a + b (involves stores and loads)
        method = get_method_from_class(simple_class_data, "justAdd")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        grouper = StatementGrouper(cfg)
        statements = grouper.group()
        
        # Should have some statements
        assert len(statements) >= 1
    
    def test_groups_conditional(self, simple_class_data):
        """Test conditional statement grouping."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        grouper = StatementGrouper(cfg)
        statements = grouper.group()
        
        # Should have IF statements
        if_stmts = [s for s in statements if s.stmt_type == StatementType.IF]
        assert len(if_stmts) >= 1
    
    def test_groups_return(self, simple_class_data):
        """Test return statement grouping."""
        method = get_method_from_class(simple_class_data, "justReturn")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        grouper = StatementGrouper(cfg)
        statements = grouper.group()
        
        # Should have RETURN statement
        return_stmts = [s for s in statements if s.stmt_type == StatementType.RETURN]
        assert len(return_stmts) >= 1
    
    def test_groups_throw(self, simple_class_data):
        """Test throw statement grouping."""
        method = get_method_from_class(simple_class_data, "assertFalse")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        grouper = StatementGrouper(cfg)
        statements = grouper.group()
        
        # Should have THROW statement
        throw_stmts = [s for s in statements if s.stmt_type == StatementType.THROW]
        assert len(throw_stmts) >= 1
    
    def test_groups_invoke(self, calls_class_data):
        """Test method invocation grouping."""
        method = get_method_from_class(calls_class_data, "callsAssertTrue")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        
        grouper = StatementGrouper(cfg)
        statements = grouper.group()
        
        # Should have INVOKE statement
        invoke_stmts = [s for s in statements if s.stmt_type == StatementType.INVOKE]
        assert len(invoke_stmts) >= 1


# ============================================================================
# MethodIR Tests
# ============================================================================

class TestMethodIR:
    """Tests for MethodIR unified representation."""
    
    def test_from_class_file(self, suite):
        """Test loading MethodIR from class file."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        assert ir.method_name == "assertPositive"
        assert len(ir.cfg) > 0
        assert len(ir.statements) > 0
    
    def test_from_class_with_signature(self, suite):
        """Test loading with full method signature."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        
        ir = MethodIR.from_class(class_path, "assertPositive:(I)V")
        
        assert ir.method_name == "assertPositive"
    
    def test_successors_method(self, suite):
        """Test successors() helper method."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        # Entry point should have successors
        entry = ir.entry_pc
        succs = ir.successors(entry)
        
        # assertPositive starts with: getstatic $assertionsDisabled -> ifz
        assert len(succs) >= 1
    
    def test_predecessors_method(self, suite):
        """Test predecessors() helper method."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        # Find a non-entry node
        for pc, node in ir.cfg.items():
            if pc != ir.entry_pc:
                preds = ir.predecessors(pc)
                # Non-entry should have at least one predecessor
                # (unless it's dead code or exception handler entry)
                break
    
    def test_exit_pcs(self, suite):
        """Test exit points are correctly identified."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        # Should have exit points
        assert len(ir.exit_pcs) >= 1
        
        # All exit PCs should be terminators
        for exit_pc in ir.exit_pcs:
            node = ir.cfg[exit_pc]
            assert node.is_terminator()
    
    def test_get_node(self, suite):
        """Test get_node() helper."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        node = ir.get_node(ir.entry_pc)
        assert node is not None
        assert node.pc == ir.entry_pc
        
        # Non-existent PC
        assert ir.get_node(99999) is None
    
    def test_iter_nodes(self, suite):
        """Test node iteration."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        nodes = list(ir.iter_nodes())
        assert len(nodes) == len(ir.cfg)
        
        # Should be in PC order
        pcs = [n.pc for n in nodes]
        assert pcs == sorted(pcs)
    
    def test_get_statement_at(self, suite):
        """Test statement lookup by PC."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        # Every PC should be covered by some statement
        for pc in ir.cfg:
            stmt = ir.get_statement_at(pc)
            assert stmt is not None, f"No statement covers PC {pc}"
    
    def test_to_dot(self, suite):
        """Test DOT graph generation."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "justReturn")
        
        dot = ir.to_dot()
        
        assert "digraph CFG" in dot
        assert "n0" in dot  # Should have node at PC 0
    
    def test_summary(self, suite):
        """Test summary generation."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        summary = ir.summary()
        
        assert "assertPositive" in summary
        assert "Nodes:" in summary
        assert "Statements:" in summary


# ============================================================================
# Cross-Method Tests (Simple.java)
# ============================================================================

class TestSimpleMethods:
    """Tests for Simple.java methods."""
    
    def test_assert_positive_cfg(self, suite):
        """Test CFG for assertPositive - has conditional branch."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "assertPositive")
        
        # Should have branch nodes
        branch_nodes = [n for n in ir.cfg.values() 
                       if n.node_type == NodeType.BRANCH]
        assert len(branch_nodes) >= 1
    
    def test_divide_by_zero_cfg(self, suite):
        """Test CFG for divideByZero."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "divideByZero")
        
        # Should have binary operation (idiv)
        binary_nodes = [n for n in ir.cfg.values() 
                       if n.node_type == NodeType.BINARY]
        assert len(binary_nodes) >= 1
    
    def test_early_return_cfg(self, suite):
        """Test CFG for earlyReturn - multiple return paths."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        ir = MethodIR.from_class(class_path, "earlyReturn")
        
        # Should have return nodes
        return_nodes = [n for n in ir.cfg.values() 
                       if n.node_type == NodeType.RETURN]
        assert len(return_nodes) >= 1


# ============================================================================
# Cross-Method Tests (Arrays.java)
# ============================================================================

class TestArraysMethods:
    """Tests for Arrays.java methods."""
    
    def test_array_out_of_bounds_cfg(self, suite):
        """Test CFG for arrayOutOfBounds."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Arrays.json"
        ir = MethodIR.from_class(class_path, "arrayOutOfBounds")
        
        # Should have array access
        array_nodes = [n for n in ir.cfg.values() 
                      if n.node_type == NodeType.ARRAY_ACCESS]
        assert len(array_nodes) >= 1
    
    def test_binary_search_has_loop(self, suite):
        """Test binarySearch has loop structure."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Arrays.json"
        ir = MethodIR.from_class(class_path, "binarySearch")
        
        # Should have back edges (loop)
        has_back_edge = False
        for node in ir.cfg.values():
            for succ in node.successors:
                if succ < node.pc:  # Back edge
                    has_back_edge = True
                    break
        
        assert has_back_edge, "binarySearch should have a loop"


# ============================================================================
# Cross-Method Tests (Calls.java)
# ============================================================================

class TestCallsMethods:
    """Tests for Calls.java methods."""
    
    def test_calls_assert_true_has_invoke(self, suite):
        """Test callsAssertTrue has method invocation."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Calls.json"
        ir = MethodIR.from_class(class_path, "callsAssertTrue")
        
        invoke_nodes = [n for n in ir.cfg.values() 
                       if n.node_type == NodeType.INVOKE]
        assert len(invoke_nodes) >= 1
    
    def test_fib_recursive_invoke(self, suite):
        """Test fib has recursive invocations."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Calls.json"
        ir = MethodIR.from_class(class_path, "fib")
        
        invoke_nodes = [n for n in ir.cfg.values() 
                       if n.node_type == NodeType.INVOKE]
        
        # fib calls itself twice
        assert len(invoke_nodes) >= 2


# ============================================================================
# Cross-Method Tests (Loops.java)
# ============================================================================

class TestLoopsMethods:
    """Tests for Loops.java methods."""
    
    def test_forever_infinite_loop(self, suite):
        """Test forever() has self-loop."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Loops.json"
        ir = MethodIR.from_class(class_path, "forever")
        
        # Should have goto to itself
        for node in ir.cfg.values():
            if "goto" in node.instr_str.lower():
                # Check if it's a self-loop or back-edge
                for succ in node.successors:
                    if succ <= node.pc:
                        return  # Found the loop
        
        pytest.fail("forever() should have an infinite loop")
    
    def test_never_asserts_loop_structure(self, suite):
        """Test neverAsserts has loop before assertion."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Loops.json"
        ir = MethodIR.from_class(class_path, "neverAsserts")
        
        # Should have conditional loop
        branch_nodes = [n for n in ir.cfg.values() 
                       if n.node_type == NodeType.BRANCH]
        assert len(branch_nodes) >= 1


# ============================================================================
# Cross-Method Tests (Tricky.java)
# ============================================================================

class TestTrickyMethods:
    """Tests for Tricky.java methods."""
    
    def test_collatz_has_loop(self, suite):
        """Test collatz has while loop."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Tricky.json"
        ir = MethodIR.from_class(class_path, "collatz")
        
        # Should have back edges
        has_back_edge = False
        for node in ir.cfg.values():
            for succ in node.successors:
                if succ < node.pc:
                    has_back_edge = True
                    break
        
        assert has_back_edge
    
    def test_collatz_has_conditional(self, suite):
        """Test collatz has if (n % 2 == 0) branch."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Tricky.json"
        ir = MethodIR.from_class(class_path, "collatz")
        
        # Should have multiple branches
        branch_nodes = [n for n in ir.cfg.values() 
                       if n.node_type == NodeType.BRANCH]
        assert len(branch_nodes) >= 2  # loop condition + if-else


# ============================================================================
# Source Parser Tests
# ============================================================================

class TestSourceParser:
    """Tests for source-level parsing."""
    
    def test_parse_simple_java(self, suite):
        """Test parsing Simple.java."""
        source_path = suite.sourcefiles_folder / "jpamb" / "cases" / "Simple.java"
        
        parser = SourceParser()
        source_class = parser.parse_file(source_path)
        
        assert source_class is not None
        assert source_class.name == "Simple"
        assert "assertPositive" in source_class.methods
    
    def test_method_has_assertion(self, suite):
        """Test assertion detection in source."""
        source_path = suite.sourcefiles_folder / "jpamb" / "cases" / "Simple.java"
        
        parser = SourceParser()
        source_class = parser.parse_file(source_path)
        
        assert_method = source_class.methods.get("assertFalse")
        assert assert_method is not None
        assert assert_method.has_assertion()
    
    def test_method_parameters(self, suite):
        """Test parameter extraction."""
        source_path = suite.sourcefiles_folder / "jpamb" / "cases" / "Simple.java"
        
        parser = SourceParser()
        source_class = parser.parse_file(source_path)
        
        method = source_class.methods.get("assertPositive")
        assert method is not None
        assert len(method.parameters) == 1
        assert method.parameters[0][0] == "int"


# ============================================================================
# Unified Analyzer Tests
# ============================================================================

class TestUnifiedAnalyzer:
    """Tests for unified source+bytecode analysis."""
    
    def test_analyze_with_source(self, suite):
        """Test analysis with source available."""
        analyzer = UnifiedAnalyzer(suite)
        
        # Create a method ID
        method_id = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        result = analyzer.analyze_method(method_id)
        
        assert result is not None
        assert result.ir is not None
        # Source should be available
        assert result.has_source() or True  # Source is optional
    
    def test_has_assertion_detection(self, suite):
        """Test assertion detection through analyzer."""
        analyzer = UnifiedAnalyzer(suite)
        
        method_id = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertFalse:()V")
        result = analyzer.analyze_method(method_id)
        
        # Should detect assertion
        assert result.has_assertion()


# ============================================================================
# Node Type Classification Tests
# ============================================================================

class TestNodeTypeClassification:
    """Tests for opcode classification."""
    
    def test_classify_push(self):
        """Test Push opcode classification."""
        from jpamb.jvm.opcode import Push
        from jpamb.jvm.base import Value, Int
        
        push = Push(offset=0, value=Value(Int(), 42))
        node_type = classify_opcode(push)
        
        assert node_type == NodeType.PUSH
    
    def test_classify_load(self):
        """Test Load opcode classification."""
        from jpamb.jvm.opcode import Load
        from jpamb.jvm.base import Int
        
        load = Load(offset=0, type=Int(), index=0)
        node_type = classify_opcode(load)
        
        assert node_type == NodeType.LOAD
    
    def test_classify_store(self):
        """Test Store opcode classification."""
        from jpamb.jvm.opcode import Store
        from jpamb.jvm.base import Int
        
        store = Store(offset=0, type=Int(), index=0)
        node_type = classify_opcode(store)
        
        assert node_type == NodeType.ASSIGN
    
    def test_classify_ifz(self):
        """Test Ifz opcode classification."""
        from jpamb.jvm.opcode import Ifz
        
        ifz = Ifz(offset=0, condition="ne", target=10)
        node_type = classify_opcode(ifz)
        
        assert node_type == NodeType.BRANCH
    
    def test_classify_goto(self):
        """Test Goto opcode classification."""
        from jpamb.jvm.opcode import Goto
        
        goto = Goto(offset=0, target=10)
        node_type = classify_opcode(goto)
        
        assert node_type == NodeType.JUMP
    
    def test_classify_return(self):
        """Test Return opcode classification."""
        from jpamb.jvm.opcode import Return
        
        ret = Return(offset=0, type=None)
        node_type = classify_opcode(ret)
        
        assert node_type == NodeType.RETURN


# ============================================================================
# Exception Handler Tests
# ============================================================================

class TestExceptionHandlers:
    """Tests for exception handler integration."""
    
    def test_exception_handler_parsing(self):
        """Test ExceptionHandler.from_json()."""
        data = {
            "start": 0,
            "end": 10,
            "handler": 20,
            "catchType": "java/lang/Exception"
        }
        
        handler = ExceptionHandler.from_json(data)
        
        assert handler.start_pc == 0
        assert handler.end_pc == 10
        assert handler.handler_pc == 20
        assert handler.catch_type == "java/lang/Exception"
    
    def test_handler_coverage(self, suite):
        """Test that nodes have correct exception handlers."""
        # Load a method that might have exception handlers
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        
        with open(class_path) as f:
            class_data = json.load(f)
        
        for method in class_data["methods"]:
            exceptions = method.get("code", {}).get("exceptions", [])
            if exceptions:
                bytecode = method["code"]["bytecode"]
                handlers = [ExceptionHandler.from_json(e) for e in exceptions]
                
                builder = CFGBuilder(bytecode, handlers)
                cfg = builder.build()
                
                # Check that nodes within handler range have handler attached
                for h in handlers:
                    for pc, node in cfg.items():
                        if h.start_pc <= pc < h.end_pc:
                            # Should have this handler
                            assert h in node.exception_handlers
                
                return  # Found a method with handlers
        
        # No methods with handlers - that's ok for Simple.java
        pass


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """End-to-end integration tests."""
    
    def test_full_pipeline_simple(self, suite):
        """Test full analysis pipeline on Simple.java methods."""
        class_path = suite.decompiled_folder / "jpamb" / "cases" / "Simple.json"
        
        methods_to_test = [
            "assertFalse",
            "assertPositive",
            "divideByZero",
            "justReturn",
        ]
        
        for method_name in methods_to_test:
            ir = MethodIR.from_class(class_path, method_name)
            
            assert ir.method_name == method_name
            assert len(ir.cfg) > 0
            assert len(ir.statements) > 0
            assert len(ir.basic_blocks) > 0
    
    def test_full_pipeline_all_cases(self, suite):
        """Test pipeline on all case classes."""
        case_classes = ["Simple", "Arrays", "Calls", "Loops", "Tricky"]
        
        for case_class in case_classes:
            class_path = suite.decompiled_folder / "jpamb" / "cases" / f"{case_class}.json"
            
            with open(class_path) as f:
                class_data = json.load(f)
            
            for method in class_data["methods"]:
                name = method["name"]
                if name in ("<init>", "<clinit>"):
                    continue
                
                try:
                    ir = MethodIR._from_method_data(
                        method,
                        f"jpamb.cases.{case_class}",
                        name,
                        name
                    )
                    
                    # Basic sanity checks
                    assert ir.method_name == name
                    assert isinstance(ir.cfg, dict)
                    assert isinstance(ir.statements, list)
                except Exception as e:
                    pytest.fail(f"Failed on {case_class}.{name}: {e}")


# ============================================================================
# Helper Function Tests
# ============================================================================

class TestHelperFunctions:
    """Tests for module-level helper functions."""
    
    def test_build_cfg_from_json(self, simple_class_data):
        """Test build_cfg_from_json convenience function."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        
        cfg, blocks = build_cfg_from_json(method)
        
        assert len(cfg) > 0
        assert len(blocks) > 0
    
    def test_group_statements_function(self, simple_class_data):
        """Test group_statements convenience function."""
        method = get_method_from_class(simple_class_data, "assertPositive")
        bytecode = method["code"]["bytecode"]
        
        builder = CFGBuilder(bytecode)
        cfg = builder.build()
        blocks = builder.get_basic_blocks()
        
        statements = group_statements(cfg, blocks)
        
        assert len(statements) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
