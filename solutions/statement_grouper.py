"""
solutions/statement_grouper.py

Statement-level grouping of JVM bytecode instructions.

This module groups related bytecode sequences into high-level statements:
- Assignment statements (load + operation + store)
- Conditional statements (condition evaluation + branch)
- Method invocations (argument setup + invoke)
- Return statements (value preparation + return)

DTU 02242 Program Analysis - Group 21
"""

from __future__ import annotations

from typing import Optional

from jpamb.jvm import opcode as opc
from solutions.ir import (
    CFGNode, BasicBlock, Statement, StatementType, NodeType
)


class StatementGrouper:
    """
    Groups bytecode instructions into high-level statements.
    
    The grouper analyzes CFG patterns to identify statement boundaries
    and classify bytecode sequences into logical operations.
    
    Grouping strategy:
    1. Identify statement terminators (store, invoke, return, branch)
    2. Work backwards to find statement starts
    3. Classify based on terminator and components
    
    Example:
        grouper = StatementGrouper(cfg, basic_blocks)
        statements = grouper.group()
    """
    
    def __init__(
        self,
        cfg: dict[int, CFGNode],
        basic_blocks: list[BasicBlock] = None
    ):
        """
        Initialize statement grouper.
        
        Args:
            cfg: CFG dictionary mapping PC to CFGNode
            basic_blocks: Optional list of basic blocks for block-level grouping
        """
        self.cfg = cfg
        self.basic_blocks = basic_blocks or []
        self._pc_list = sorted(cfg.keys())
        self._statements: list[Statement] = []
        self._assigned_pcs: set[int] = set()
        
    def group(self) -> list[Statement]:
        """
        Group bytecode into statements.
        
        Returns:
            List of Statement objects
        """
        if not self.cfg:
            return []
        
        self._statements = []
        self._assigned_pcs = set()
        
        # Process in reverse PC order to find statement boundaries
        for i in range(len(self._pc_list) - 1, -1, -1):
            pc = self._pc_list[i]
            
            if pc in self._assigned_pcs:
                continue
            
            node = self.cfg[pc]
            stmt = self._identify_statement(i, node)
            
            if stmt:
                self._statements.append(stmt)
                self._assigned_pcs.update(stmt.pcs)
        
        # Add remaining unassigned instructions as simple statements
        for pc in self._pc_list:
            if pc not in self._assigned_pcs:
                node = self.cfg[pc]
                stmt = Statement(
                    start_pc=pc,
                    end_pc=pc,
                    stmt_type=self._simple_type(node),
                    pcs=[pc],
                    description=node.instr_str
                )
                self._statements.append(stmt)
        
        # Sort by start PC
        self._statements.sort(key=lambda s: s.start_pc)
        
        return self._statements
    
    def _identify_statement(self, index: int, node: CFGNode) -> Optional[Statement]:
        """
        Identify statement starting from a potential terminator.
        
        Args:
            index: Index in PC list
            node: CFGNode at the index
            
        Returns:
            Statement if identified, None otherwise
        """
        pc = node.pc
        
        # Check for different statement patterns
        
        # Store instruction -> Assignment statement
        if node.node_type == NodeType.ASSIGN:
            return self._identify_assignment(index, node)
        
        # Branch instruction -> Conditional statement
        if node.node_type == NodeType.BRANCH:
            return self._identify_conditional(index, node)
        
        # Return instruction
        if node.node_type == NodeType.RETURN:
            return self._identify_return(index, node)
        
        # Throw instruction
        if node.node_type == NodeType.THROW:
            return self._identify_throw(index, node)
        
        # Invoke instruction
        if node.node_type == NodeType.INVOKE:
            return self._identify_invoke(index, node)
        
        # Jump instruction
        if node.node_type == NodeType.JUMP:
            return self._identify_jump(index, node)
        
        # Switch instruction
        if node.node_type == NodeType.SWITCH:
            return self._identify_switch(index, node)
        
        # New object/array
        if node.node_type == NodeType.NEW:
            return self._identify_new(index, node)
        
        # Array store
        if node.node_type == NodeType.ARRAY_ACCESS:
            opcode = node.opcode
            if isinstance(opcode, opc.ArrayStore):
                return self._identify_array_store(index, node)
        
        return None
    
    def _identify_assignment(
        self,
        index: int,
        store_node: CFGNode
    ) -> Statement:
        """
        Identify an assignment statement ending with store.
        
        Pattern: load/push* -> op* -> store
        """
        pc = store_node.pc
        pcs = [pc]
        
        # Track what local is being stored to
        opcode = store_node.opcode
        var_written = set()
        if hasattr(opcode, 'index'):
            var_written.add(opcode.index)
        
        # Look backwards for contributing instructions
        i = index - 1
        stack_depth = 1  # Need one value on stack for store
        
        var_read = set()
        
        while i >= 0 and stack_depth > 0:
            prev_pc = self._pc_list[i]
            
            if prev_pc in self._assigned_pcs:
                break
            
            prev_node = self.cfg[prev_pc]
            
            # Don't cross basic block boundaries for simple assignments
            if prev_node.is_leader and i != index:
                break
            
            # Compute stack effect
            push_count, pop_count = self._stack_effect(prev_node)
            
            # Include this instruction
            pcs.insert(0, prev_pc)
            stack_depth = stack_depth - push_count + pop_count
            
            # Track variables read
            if prev_node.node_type == NodeType.LOAD:
                if hasattr(prev_node.opcode, 'index'):
                    var_read.add(prev_node.opcode.index)
            
            i -= 1
        
        return Statement(
            start_pc=pcs[0],
            end_pc=pcs[-1],
            stmt_type=StatementType.ASSIGN,
            pcs=pcs,
            variables_read=var_read,
            variables_written=var_written,
            description=f"assign to local {var_written}"
        )
    
    def _identify_conditional(
        self,
        index: int,
        branch_node: CFGNode
    ) -> Statement:
        """
        Identify a conditional statement with branch.
        
        Pattern: condition_setup* -> if/ifz
        """
        pc = branch_node.pc
        pcs = [pc]
        
        # Get branch targets
        target_pcs = []
        opcode = branch_node.opcode
        if hasattr(opcode, 'target'):
            target_pcs.append(opcode.target)
        
        # Look backwards for condition evaluation
        i = index - 1
        
        # Determine how many values the branch consumes
        if isinstance(opcode, opc.If):
            stack_depth = 2  # Compares two values
        else:
            stack_depth = 1  # Compares one value against zero
        
        var_read = set()
        
        while i >= 0 and stack_depth > 0:
            prev_pc = self._pc_list[i]
            
            if prev_pc in self._assigned_pcs:
                break
            
            prev_node = self.cfg[prev_pc]
            
            # Don't cross block boundaries
            if prev_node.is_leader and i != index:
                break
            
            push_count, pop_count = self._stack_effect(prev_node)
            
            pcs.insert(0, prev_pc)
            stack_depth = stack_depth - push_count + pop_count
            
            if prev_node.node_type == NodeType.LOAD:
                if hasattr(prev_node.opcode, 'index'):
                    var_read.add(prev_node.opcode.index)
            
            i -= 1
        
        # Determine if this is a loop header
        stmt_type = StatementType.IF
        # Check if any target is before current PC (back edge = loop)
        for target in target_pcs:
            if target < pc:
                stmt_type = StatementType.LOOP_HEADER
                break
        
        return Statement(
            start_pc=pcs[0],
            end_pc=pcs[-1],
            stmt_type=stmt_type,
            pcs=pcs,
            target_pcs=target_pcs,
            variables_read=var_read,
            description=f"if {opcode.condition if hasattr(opcode, 'condition') else '?'} goto {target_pcs}"
        )
    
    def _identify_return(
        self,
        index: int,
        return_node: CFGNode
    ) -> Statement:
        """
        Identify a return statement.
        
        Pattern: value_setup* -> return
        """
        pc = return_node.pc
        pcs = [pc]
        
        opcode = return_node.opcode
        
        # Check if this is a void return
        if hasattr(opcode, 'type') and opcode.type is None:
            return Statement(
                start_pc=pc,
                end_pc=pc,
                stmt_type=StatementType.RETURN,
                pcs=pcs,
                description="return void"
            )
        
        # Value return - look for value setup
        i = index - 1
        stack_depth = 1
        var_read = set()
        
        while i >= 0 and stack_depth > 0:
            prev_pc = self._pc_list[i]
            
            if prev_pc in self._assigned_pcs:
                break
            
            prev_node = self.cfg[prev_pc]
            
            if prev_node.is_leader and i != index:
                break
            
            push_count, pop_count = self._stack_effect(prev_node)
            
            pcs.insert(0, prev_pc)
            stack_depth = stack_depth - push_count + pop_count
            
            if prev_node.node_type == NodeType.LOAD:
                if hasattr(prev_node.opcode, 'index'):
                    var_read.add(prev_node.opcode.index)
            
            i -= 1
        
        return Statement(
            start_pc=pcs[0],
            end_pc=pcs[-1],
            stmt_type=StatementType.RETURN,
            pcs=pcs,
            variables_read=var_read,
            description="return value"
        )
    
    def _identify_throw(
        self,
        index: int,
        throw_node: CFGNode
    ) -> Statement:
        """
        Identify a throw statement.
        
        Pattern: exception_setup* -> throw
        """
        pc = throw_node.pc
        pcs = [pc]
        
        # Look backwards for exception object creation
        i = index - 1
        stack_depth = 1  # throw consumes one reference
        
        while i >= 0 and stack_depth > 0:
            prev_pc = self._pc_list[i]
            
            if prev_pc in self._assigned_pcs:
                break
            
            prev_node = self.cfg[prev_pc]
            
            if prev_node.is_leader and i != index:
                break
            
            push_count, pop_count = self._stack_effect(prev_node)
            
            pcs.insert(0, prev_pc)
            stack_depth = stack_depth - push_count + pop_count
            
            i -= 1
        
        return Statement(
            start_pc=pcs[0],
            end_pc=pcs[-1],
            stmt_type=StatementType.THROW,
            pcs=pcs,
            description="throw exception"
        )
    
    def _identify_invoke(
        self,
        index: int,
        invoke_node: CFGNode
    ) -> Statement:
        """
        Identify a method invocation statement.
        
        Pattern: args* -> invoke
        """
        pc = invoke_node.pc
        pcs = [pc]
        
        opcode = invoke_node.opcode
        
        # Determine how many arguments the invoke consumes
        arg_count = 0
        method_name = "unknown"
        
        if hasattr(opcode, 'method'):
            method = opcode.method
            method_name = str(method)
            
            # Count parameters
            if hasattr(method, 'extension') and hasattr(method.extension, 'params'):
                arg_count = len(method.extension.params)
            
            # Add receiver for instance methods
            if isinstance(opcode, (opc.InvokeVirtual, opc.InvokeSpecial, opc.InvokeInterface)):
                arg_count += 1
        
        # Look backwards for arguments
        i = index - 1
        stack_depth = arg_count
        var_read = set()
        
        while i >= 0 and stack_depth > 0:
            prev_pc = self._pc_list[i]
            
            if prev_pc in self._assigned_pcs:
                break
            
            prev_node = self.cfg[prev_pc]
            
            if prev_node.is_leader and i != index:
                break
            
            push_count, pop_count = self._stack_effect(prev_node)
            
            pcs.insert(0, prev_pc)
            stack_depth = stack_depth - push_count + pop_count
            
            if prev_node.node_type == NodeType.LOAD:
                if hasattr(prev_node.opcode, 'index'):
                    var_read.add(prev_node.opcode.index)
            
            i -= 1
        
        return Statement(
            start_pc=pcs[0],
            end_pc=pcs[-1],
            stmt_type=StatementType.INVOKE,
            pcs=pcs,
            variables_read=var_read,
            description=f"invoke {method_name}"
        )
    
    def _identify_jump(
        self,
        index: int,
        goto_node: CFGNode
    ) -> Statement:
        """Identify an unconditional jump."""
        pc = goto_node.pc
        opcode = goto_node.opcode
        
        target = opcode.target if hasattr(opcode, 'target') else pc
        
        return Statement(
            start_pc=pc,
            end_pc=pc,
            stmt_type=StatementType.IF,  # Treat as degenerate if
            pcs=[pc],
            target_pcs=[target],
            description=f"goto {target}"
        )
    
    def _identify_switch(
        self,
        index: int,
        switch_node: CFGNode
    ) -> Statement:
        """Identify a switch statement."""
        pc = switch_node.pc
        pcs = [pc]
        
        opcode = switch_node.opcode
        
        # Get all targets
        target_pcs = []
        if hasattr(opcode, 'default'):
            target_pcs.append(opcode.default)
        if hasattr(opcode, 'targets'):
            target_pcs.extend(opcode.targets)
        
        # Look for switch value
        i = index - 1
        stack_depth = 1
        
        while i >= 0 and stack_depth > 0:
            prev_pc = self._pc_list[i]
            
            if prev_pc in self._assigned_pcs:
                break
            
            prev_node = self.cfg[prev_pc]
            
            push_count, pop_count = self._stack_effect(prev_node)
            
            pcs.insert(0, prev_pc)
            stack_depth = stack_depth - push_count + pop_count
            
            i -= 1
        
        return Statement(
            start_pc=pcs[0],
            end_pc=pcs[-1],
            stmt_type=StatementType.SWITCH,
            pcs=pcs,
            target_pcs=target_pcs,
            description=f"switch {len(target_pcs)} targets"
        )
    
    def _identify_new(
        self,
        index: int,
        new_node: CFGNode
    ) -> Statement:
        """Identify object/array creation."""
        pc = new_node.pc
        opcode = new_node.opcode
        
        if isinstance(opcode, opc.NewArray):
            return Statement(
                start_pc=pc,
                end_pc=pc,
                stmt_type=StatementType.NEW_ARRAY,
                pcs=[pc],
                description=f"new array {opcode.type}"
            )
        else:
            class_name = opcode.classname if hasattr(opcode, 'classname') else "?"
            return Statement(
                start_pc=pc,
                end_pc=pc,
                stmt_type=StatementType.NEW_OBJECT,
                pcs=[pc],
                description=f"new {class_name}"
            )
    
    def _identify_array_store(
        self,
        index: int,
        store_node: CFGNode
    ) -> Statement:
        """Identify array element assignment."""
        pc = store_node.pc
        pcs = [pc]
        
        # Array store needs: arrayref, index, value (3 items)
        i = index - 1
        stack_depth = 3
        var_read = set()
        
        while i >= 0 and stack_depth > 0:
            prev_pc = self._pc_list[i]
            
            if prev_pc in self._assigned_pcs:
                break
            
            prev_node = self.cfg[prev_pc]
            
            if prev_node.is_leader and i != index:
                break
            
            push_count, pop_count = self._stack_effect(prev_node)
            
            pcs.insert(0, prev_pc)
            stack_depth = stack_depth - push_count + pop_count
            
            if prev_node.node_type == NodeType.LOAD:
                if hasattr(prev_node.opcode, 'index'):
                    var_read.add(prev_node.opcode.index)
            
            i -= 1
        
        return Statement(
            start_pc=pcs[0],
            end_pc=pcs[-1],
            stmt_type=StatementType.ARRAY_ASSIGN,
            pcs=pcs,
            variables_read=var_read,
            description="array element assignment"
        )
    
    def _stack_effect(self, node: CFGNode) -> tuple[int, int]:
        """
        Compute stack effect of an instruction.
        
        Returns:
            Tuple of (values_pushed, values_popped)
        """
        opcode = node.opcode
        
        # Push instructions add one value
        if node.node_type == NodeType.PUSH:
            return (1, 0)
        
        # Load instructions add one value
        if node.node_type == NodeType.LOAD:
            return (1, 0)
        
        # Store instructions consume one value
        if node.node_type == NodeType.ASSIGN:
            if isinstance(opcode, opc.Incr):
                return (0, 0)  # iinc doesn't touch stack
            return (0, 1)
        
        # Binary ops: pop 2, push 1
        if node.node_type == NodeType.BINARY:
            return (1, 2)
        
        # Unary ops: pop 1, push 1
        if node.node_type == NodeType.UNARY:
            return (1, 1)
        
        # Dup: push 1 (conceptually)
        if node.node_type == NodeType.DUP:
            words = opcode.words if hasattr(opcode, 'words') else 1
            return (words, 0)
        
        # New object: push 1
        if node.node_type == NodeType.NEW:
            if isinstance(opcode, opc.NewArray):
                return (1, 1)  # pop count, push array
            return (1, 0)
        
        # Field get: push 1, pop 0 or 1
        if node.node_type == NodeType.FIELD_ACCESS:
            if hasattr(opcode, 'static') and opcode.static:
                return (1, 0)
            return (1, 1)  # Instance field: pop objectref, push value
        
        # Array load: pop 2, push 1
        if node.node_type == NodeType.ARRAY_ACCESS:
            if isinstance(opcode, opc.ArrayLoad):
                return (1, 2)
            elif isinstance(opcode, opc.ArrayStore):
                return (0, 3)
            elif isinstance(opcode, opc.ArrayLength):
                return (1, 1)
        
        # Invoke: complex - depends on method signature
        if node.node_type == NodeType.INVOKE:
            # Simplified: assume returns one value
            return (1, 0)  # Actual args handled in invoke identification
        
        # Default: no effect
        return (0, 0)
    
    def _simple_type(self, node: CFGNode) -> StatementType:
        """Get simple statement type for isolated instruction."""
        type_map = {
            NodeType.ASSIGN: StatementType.ASSIGN,
            NodeType.BRANCH: StatementType.IF,
            NodeType.RETURN: StatementType.RETURN,
            NodeType.THROW: StatementType.THROW,
            NodeType.INVOKE: StatementType.INVOKE,
            NodeType.NEW: StatementType.NEW_OBJECT,
            NodeType.SWITCH: StatementType.SWITCH,
        }
        return type_map.get(node.node_type, StatementType.EXPR)


def group_statements(
    cfg: dict[int, CFGNode],
    basic_blocks: list[BasicBlock] = None
) -> list[Statement]:
    """
    Convenience function to group statements.
    
    Args:
        cfg: CFG dictionary
        basic_blocks: Optional basic blocks
        
    Returns:
        List of Statement objects
    """
    grouper = StatementGrouper(cfg, basic_blocks)
    return grouper.group()
