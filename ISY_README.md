# ISY – Implement Syntactic Analysis

## Overview

ISY (Implement Syntactic Analysis) provides bytecode-level Control Flow Graph (CFG) and statement-level AST extraction for JPAMB methods. This module bridges the gap between raw bytecode and higher-level analysis, enabling downstream components to work with structured representations.

This module implements foundational infrastructure for our DTU 02242 project: **bytecode CFG construction** and **statement grouping** that support dynamic tracing (IIN), abstract interpretation (IAB/NAB), and code removal (NCR).

## Course Definition (02242)

> **"Implement syntactic analysis of the code"**
> 
> (formula: 5 per language feature, 10 for full parsing)

This module implements full bytecode parsing with:
1. **CFG Construction**: Basic blocks, branch targets, exception handlers
2. **Statement Grouping**: High-level statement classification from bytecode sequences
3. **Source Correlation**: Optional tree-sitter based Java source AST

### Scoring
- **Full CFG parsing with exception handling**: 10 points
- **Supports**: branches, loops, switches, invokes, returns, throws

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ISY Syntactic Analysis                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Input Sources                     Output Representations       │
│   ─────────────                     ─────────────────────       │
│   • .class files (jvm2json)         • CFG (dict[pc, CFGNode])   │
│   • .java source files              • Statements (list)          │
│   • Method signatures               • BasicBlocks (list)         │
│                                                                  │
│              ↓                                                   │
│   ┌──────────────────────────────────────────────────┐          │
│   │              CFGBuilder (3-pass)                  │          │
│   │  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  │          │
│   │  │ Parse       │→ │ Find        │→ │ Build    │  │          │
│   │  │ Opcodes     │  │ Leaders     │  │ Edges    │  │          │
│   │  └─────────────┘  └─────────────┘  └──────────┘  │          │
│   └──────────────────────────────────────────────────┘          │
│                         ↓                                        │
│   ┌──────────────────────────────────────────────────┐          │
│   │            StatementGrouper                       │          │
│   │  Groups bytecodes into logical statements:        │          │
│   │  • ASSIGN: load + op + store                      │          │
│   │  • IF: condition + branch                         │          │
│   │  • INVOKE: args + call                            │          │
│   │  • RETURN: value + return                         │          │
│   └──────────────────────────────────────────────────┘          │
│                         ↓                                        │
│   ┌──────────────────────────────────────────────────┐          │
│   │               MethodIR                            │          │
│   │  Unified representation for downstream use:       │          │
│   │  • IIN: Trace execution on CFG                    │          │
│   │  • NAB: Static analysis on statements             │          │
│   │  • NCR: Delete/modify CFG nodes                   │          │
│   └──────────────────────────────────────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. MethodIR (Unified Representation)

The `MethodIR` class provides the main entry point for bytecode analysis:

```python
from solutions.ir import MethodIR

# Load from decompiled class file
ir = MethodIR.from_class(
    'target/decompiled/jpamb/cases/Simple.json',
    'assertPositive:(I)V'
)

# Access CFG
print(f"Entry PC: {ir.entry_pc}")
print(f"Exit PCs: {ir.exit_pcs}")
print(f"CFG nodes: {len(ir.cfg)}")

# Iterate over nodes
for node in ir.iter_nodes():
    print(f"  {node.pc}: {node.instr_str} -> {node.successors}")

# Access statements
for stmt in ir.statements:
    print(f"  {stmt.stmt_type.name}: PC {stmt.start_pc}-{stmt.end_pc}")

# Access basic blocks
for bb in ir.basic_blocks:
    print(f"  Block {bb.block_id}: {len(bb.nodes)} nodes")
```

### 2. CFGNode (Control Flow Graph Node)

Each CFG node represents a single bytecode instruction:

```python
from solutions.ir import CFGNode, NodeType

# Node properties
node = ir.cfg[0]
print(f"PC: {node.pc}")
print(f"Opcode: {node.opcode}")
print(f"Instruction: {node.instr_str}")
print(f"Successors: {node.successors}")
print(f"Predecessors: {node.predecessors}")
print(f"Type: {node.node_type}")  # NodeType.BRANCH, etc.
print(f"Is leader: {node.is_leader}")
print(f"Exception handlers: {node.exception_handlers}")

# Check node properties
if node.is_branch():
    print("This is a conditional branch")
if node.is_terminator():
    print("This terminates execution")
```

### 3. CFGBuilder (Three-Pass Builder)

The CFG builder constructs the control flow graph in three passes:

```python
from solutions.cfg_builder import CFGBuilder, build_cfg_from_json

# Direct usage
builder = CFGBuilder(bytecode_list, exception_handlers)
cfg = builder.build()
basic_blocks = builder.get_basic_blocks()

# Convenience function
cfg, blocks = build_cfg_from_json(method_json)
```

**Pass 1: Parse Opcodes**
- Converts jvm2json bytecode to opcode objects

**Pass 2: Find Leaders**
- First instruction of method
- Targets of branches/jumps
- Instructions after branches
- Exception handler entry points

**Pass 3: Build Edges**
- Compute successors for each instruction
- Compute predecessors (inverse)
- Assign basic block IDs

### 4. StatementGrouper (High-Level Statements)

Groups related bytecodes into logical statements:

```python
from solutions.statement_grouper import StatementGrouper, group_statements
from solutions.ir import StatementType

# Group statements
grouper = StatementGrouper(cfg, basic_blocks)
statements = grouper.group()

# Analyze statements
for stmt in statements:
    if stmt.stmt_type == StatementType.IF:
        print(f"Conditional at PC {stmt.start_pc}, targets: {stmt.target_pcs}")
    elif stmt.stmt_type == StatementType.ASSIGN:
        print(f"Assignment to locals: {stmt.variables_written}")
    elif stmt.stmt_type == StatementType.INVOKE:
        print(f"Method call: {stmt.description}")
```

**Statement Types:**
| Type | Description | Pattern |
|------|-------------|---------|
| ASSIGN | Variable assignment | load* + op* + store |
| IF | Conditional branch | condition + if/ifz |
| LOOP_HEADER | Loop condition | back-edge branch |
| INVOKE | Method call | args + invoke |
| RETURN | Return statement | value? + return |
| THROW | Exception throw | exception + throw |
| SWITCH | Switch statement | value + tableswitch |
| NEW_OBJECT | Object creation | new |
| NEW_ARRAY | Array creation | newarray |
| ARRAY_ASSIGN | Array store | array + index + value + aastore |

### 5. UnifiedAnalyzer (Source + Bytecode)

Combines source and bytecode analysis:

```python
from solutions.syntaxer import UnifiedAnalyzer

analyzer = UnifiedAnalyzer()
result = analyzer.analyze_method(method_id)

# Access source info (if available)
if result.has_source():
    print(f"Has assertion: {result.source_method.has_assertion()}")
    print(f"Parameters: {result.source_method.parameters}")

# Access bytecode IR
print(f"CFG nodes: {len(result.ir.cfg)}")
print(f"Statements: {len(result.ir.statements)}")

# Unified assertion detection
if result.has_assertion():
    print("Method contains assertions (source or bytecode)")
```

## Node Type Classification

The ISY module classifies bytecode instructions into semantic categories:

| NodeType | Opcodes | Description |
|----------|---------|-------------|
| PUSH | iconst, ldc, aconst_null | Push constant |
| LOAD | iload, aload | Load local variable |
| ASSIGN | istore, astore, iinc | Store to local |
| BINARY | iadd, isub, imul, idiv | Binary operation |
| UNARY | ineg, i2s | Unary operation |
| BRANCH | if_icmp*, ifz, if | Conditional branch |
| JUMP | goto | Unconditional jump |
| SWITCH | tableswitch | Switch statement |
| INVOKE | invoke* | Method invocation |
| RETURN | return, ireturn, areturn | Method return |
| THROW | athrow | Exception throw |
| NEW | new | Object creation |
| ARRAY_ACCESS | aaload, aastore, arraylength | Array access |
| FIELD_ACCESS | getfield, getstatic | Field access |
| DUP | dup | Stack duplication |

## Integration with Other Components

### IIN (Dynamic Traces)

Use CFG for execution tracing:

```python
# Trace execution on CFG
ir = MethodIR.from_class(class_path, method_sig)

def trace_execution(ir, start_pc=0):
    visited = set()
    worklist = [start_pc]
    
    while worklist:
        pc = worklist.pop()
        if pc in visited:
            continue
        visited.add(pc)
        
        node = ir.get_node(pc)
        print(f"Execute: {node.instr_str}")
        
        worklist.extend(ir.successors(pc))
```

### NAB (Abstract Interpretation)

Use statements for abstract analysis:

```python
from solutions.nab_integration import ReducedProductState

# Analyze each statement
for stmt in ir.statements:
    if stmt.stmt_type == StatementType.ASSIGN:
        # Update abstract state for variables written
        for var in stmt.variables_written:
            state[var] = analyze_assignment(stmt)
```

### NCR (Code Removal)

Use CFG for dead code elimination:

```python
# Find unreachable nodes
reachable = compute_reachable(ir.entry_pc, ir.cfg)
dead_code = set(ir.cfg.keys()) - reachable

# Remove dead nodes
for pc in dead_code:
    del ir.cfg[pc]
```

## Visualization

Generate DOT graph for visualization:

```python
ir = MethodIR.from_class(class_path, method_sig)
dot = ir.to_dot()

# Save to file
with open("cfg.dot", "w") as f:
    f.write(dot)

# Render with Graphviz
# dot -Tpng cfg.dot -o cfg.png
```

**Example output:**
```dot
digraph CFG {
  rankdir=TB;
  node [shape=box, fontname="monospace"];
  n0 [label="0: getstatic $assertionsDisabled", color="blue"];
  n3 [label="3: ifz ne 18", color="black"];
  n6 [label="6: iload_0", color="black"];
  ...
  n0 -> n3 [style="solid"];
  n3 -> n6 [style="solid"];
  n3 -> n18 [style="solid"];
}
```

## Testing

Run the ISY test suite:

```bash
# Run all tests
uv run python -m pytest tests/test_isy.py -v

# Run with coverage
uv run python -m pytest tests/test_isy.py --cov=solutions.ir --cov=solutions.cfg_builder --cov=solutions.statement_grouper --cov-report=term-missing
```

**Test Coverage:** 86% (exceeds 80% requirement)

**Test Cases:**
- CFG construction (8 tests)
- Basic blocks (3 tests)
- Statement grouping (6 tests)
- MethodIR interface (10 tests)
- Cross-method tests for Simple, Arrays, Calls, Loops, Tricky (12 tests)
- Source parsing (3 tests)
- Unified analyzer (2 tests)
- Node type classification (6 tests)
- Exception handlers (2 tests)
- Integration tests (2 tests)
- Helper functions (2 tests)

## File Structure

```
solutions/
├── ir.py                    # MethodIR, CFGNode, Statement, BasicBlock
├── cfg_builder.py           # CFGBuilder, classify_opcode
├── statement_grouper.py     # StatementGrouper
└── syntaxer/
    ├── __init__.py          # UnifiedAnalyzer, exports
    └── source_parser.py     # SourceParser (tree-sitter)

tests/
└── test_isy.py              # 55 test cases
```

## Dependencies

- **Pure Python 3.11+**: Uses only stdlib (`dataclasses`, `enum`, `json`, `pathlib`)
- **tree-sitter**: For Java source parsing (already in project)
- **jpamb.jvm.opcode**: For bytecode opcode definitions (existing)

## Example: Analyzing assertPositive

```python
from solutions.ir import MethodIR

ir = MethodIR.from_class(
    'target/decompiled/jpamb/cases/Simple.json',
    'assertPositive:(I)V'
)

print(ir.summary())
# Method: assertPositive:(I)V
# Class: jpamb/cases/Simple
# Nodes: 9
# Basic Blocks: 3
# Statements: 5
# Exception Handlers: 0
# Max Locals: 1
# Max Stack: 2
# Entry: 0
# Exits: [14, 17]

# CFG structure:
# 0: getstatic $assertionsDisabled -> [3]
# 3: ifz ne 18 -> [6, 18]          # if assertions disabled, skip
# 6: iload_0 -> [7]                 # load num
# 7: ifz gt 18 -> [10, 18]          # if num > 0, skip
# 10: new AssertionError -> [13]
# 13: dup -> [14]
# 14: invokespecial <init> -> [17]
# 17: athrow -> []
# 18: return -> []
```

## API Reference

### MethodIR

| Method | Description |
|--------|-------------|
| `from_class(path, sig)` | Load from decompiled JSON |
| `from_method_id(mid)` | Load from AbsMethodID |
| `from_suite_method(mid)` | Load using Suite |
| `get_node(pc)` | Get CFGNode at PC |
| `successors(pc)` | Get successor PCs |
| `predecessors(pc)` | Get predecessor PCs |
| `iter_nodes()` | Iterate nodes in PC order |
| `iter_basic_blocks()` | Iterate basic blocks |
| `get_basic_block(pc)` | Get containing block |
| `get_statement_at(pc)` | Get containing statement |
| `get_handlers_at(pc)` | Get exception handlers |
| `get_source_line(pc)` | Get source line number |
| `to_dot()` | Generate DOT graph |
| `summary()` | Generate text summary |

### CFGNode

| Property | Type | Description |
|----------|------|-------------|
| `pc` | int | Program counter |
| `opcode` | Opcode | Parsed opcode object |
| `instr_str` | str | Human-readable instruction |
| `successors` | list[int] | Successor PCs |
| `predecessors` | list[int] | Predecessor PCs |
| `node_type` | NodeType | Semantic classification |
| `is_leader` | bool | Basic block leader |
| `exception_handlers` | list | Covering handlers |

### Statement

| Property | Type | Description |
|----------|------|-------------|
| `start_pc` | int | First PC in statement |
| `end_pc` | int | Last PC in statement |
| `stmt_type` | StatementType | Statement classification |
| `pcs` | list[int] | All PCs in statement |
| `target_pcs` | list[int] | Branch targets |
| `variables_read` | set[int] | Locals read |
| `variables_written` | set[int] | Locals written |
| `description` | str | Human-readable description |
