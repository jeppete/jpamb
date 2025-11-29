#!/usr/bin/env python3
"""
Complete Fine-Grained Debloating Pipeline

This script provides a complete pipeline that connects ALL features:
- ISY: Bytecode parsing → CFG + statements  
- IIN: Concrete interpreter → execution traces
- NAN: Trace abstraction → ReducedProductState
- IAI: Abstract interpreter with SignSet domain
- IBA: Unbounded analysis with IntervalDomain + widening
- NAB: Reduced product (Sign × Interval × NonNull)
- NCR: Dead code removal via NOP replacement

Usage:
    python solutions/pipeline_evaluation.py                          # Run on ALL methods (always regenerates traces)
    python solutions/pipeline_evaluation.py Simple.assertPositive    # Run on specific method
    python solutions/pipeline_evaluation.py --all                    # Run on ALL methods
    python solutions/pipeline_evaluation.py --clean                  # Clean stale traces (for deleted classes)
    python solutions/pipeline_evaluation.py --list                   # List available methods

DTU 02242 Program Analysis - Group 21
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass

# Add project path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jpamb import jvm
from jpamb.model import Suite
from solutions.components.abstract_domain import SignSet, IntervalDomain, NonNullDomain
from solutions.components.bytecode_analysis import BytecodeAnalyzer, CFG
from solutions.nab_integration import ReducedProductState
from solutions.components.abstract_interpreter import product_unbounded_run, ProductValue
from solutions.code_rewriter import CodeRewriter


# =============================================================================
# Data Classes for Pipeline Results
# =============================================================================

@dataclass
class ISYResult:
    """Result from ISY (Interpret Syntactic Information) step."""
    method_id: str
    class_name: str
    method_name: str
    bytecode: List[dict]
    instruction_count: int
    cfg: CFG  # CFG from BytecodeAnalyzer
    all_offsets: Set[int]
    # Line number table: offset -> line number
    line_table: Dict[int, int] = None
    # All unique statement line numbers
    all_statements: Set[int] = None


@dataclass
class IINResult:
    """Result from IIN (Implement Interpreter) step."""
    method_id: str
    trace_file: Optional[Path]
    samples: Dict[int, List[int]]  # local_idx -> sample values
    executed_pcs: Set[int]
    uncovered_pcs: Set[int]
    branch_outcomes: Dict[int, List[bool]]


@dataclass
class NANResult:
    """Result from NAN (Integrate Abstractions) step."""
    method_id: str
    initial_states: Dict[int, ReducedProductState]  # local_idx -> abstract state


@dataclass 
class IAIResult:
    """Result from IAI+IBA+NAB (Abstract Interpretation) step."""
    method_id: str
    visited_pcs: Set[int]
    unreachable_pcs: Set[int]
    outcomes: Set[str]
    dead_code_count: int
    # Statement-level dead code info
    dead_statements: Set[int] = None  # Line numbers of dead statements
    dead_statement_count: int = 0
    total_statements: int = 0


@dataclass
class NCRResult:
    """Result from NCR (Code Rewriting) step."""
    method_id: str
    original_size: int
    rewritten_size: int
    bytes_nopified: int
    output_file: Optional[Path]
    valid: bool


@dataclass
class PipelineResult:
    """Complete pipeline result for a method."""
    method_id: str
    isy: Optional[ISYResult] = None
    iin: Optional[IINResult] = None
    nan: Optional[NANResult] = None
    iai: Optional[IAIResult] = None
    ncr: Optional[NCRResult] = None
    error: Optional[str] = None


# =============================================================================
# ISY - Interpret Syntactic Information
# =============================================================================

def step_isy(method_id: str, suite: Suite, verbose: bool = True) -> ISYResult:
    """
    ISY (Interpret Syntactic Information) - 6 points
    
    Parse bytecode into structured format with CFG information.
    Uses BytecodeAnalyzer for consistent analysis with debloater.
    """
    if verbose:
        print("=" * 80)
        print("STEP 0: ISY - Parse Bytecode → CFG + Statements (using BytecodeAnalyzer)")
        print("=" * 80)
    
    # Parse method ID
    method = jvm.AbsMethodID.decode(method_id)
    class_name = str(method.classname).replace(".", "/")
    method_name = method.methodid.name
    
    # Load bytecode from JSON (decompiled class file)
    json_path = Path(f"target/decompiled/{class_name}.json")
    
    if not json_path.exists():
        raise FileNotFoundError(f"Decompiled JSON not found: {json_path}")
    
    with open(json_path) as f:
        data = json.load(f)
    
    # Find method in class
    method_data = None
    for m in data.get('methods', []):
        if m.get('name') == method_name:
            method_data = m
            break
    
    if not method_data:
        raise ValueError(f"Method {method_name} not found in {class_name}")
    
    code = method_data.get('code', {})
    bytecode = code.get('bytecode', [])
    
    # Use BytecodeAnalyzer to build CFG (same as debloater)
    analyzer = BytecodeAnalyzer(suite)
    full_method_name = f"{method.classname}.{method_name}"
    cfg = analyzer.build_cfg(full_method_name, code)
    
    # Get all offsets from CFG nodes
    all_offsets = set(cfg.nodes.keys())
    
    # Build line number table (offset -> line number)
    line_entries = code.get('lines', [])
    line_table = _build_line_table(line_entries, all_offsets)
    all_statements = set(line_table.values()) if line_table else set()
    
    if verbose:
        print(f"\nMethod: {method_id}")
        print(f"  Class: {class_name}")
        print(f"  Method: {method_name}")
        print(f"  Instructions: {len(bytecode)}")
        print(f"  Statements: {len(all_statements)}")
        print(f"  CFG Nodes: {len(cfg.nodes)}")
        
        print(f"\nBytecode ({len(bytecode)} instructions):")
        print("-" * 60)
        for bc in bytecode:
            offset = bc.get('offset', 0)
            line = line_table.get(offset, "?")
            print(f"  [{offset:3d}] L{line}: {_format_instruction(bc)}")
        
        print("\n✓ ISY complete")
    
    return ISYResult(
        method_id=method_id,
        class_name=class_name,
        method_name=method_name,
        bytecode=bytecode,
        instruction_count=len(bytecode),
        cfg=cfg,
        all_offsets=all_offsets,
        line_table=line_table,
        all_statements=all_statements
    )


def _build_line_table(line_entries: List[dict], all_offsets: Set[int]) -> Dict[int, int]:
    """
    Build a mapping from bytecode offset to source line number.
    
    The line number table entries indicate that a range of bytecode offsets
    starting at 'offset' corresponds to 'line'. We expand this to map each
    individual offset to its line.
    """
    if not line_entries:
        return {}
    
    # Sort entries by offset
    sorted_entries = sorted(line_entries, key=lambda e: e.get('offset', 0))
    
    line_table = {}
    for i, entry in enumerate(sorted_entries):
        start_offset = entry.get('offset', 0)
        line = entry.get('line', 0)
        
        # Find the end offset (start of next entry or infinity)
        if i + 1 < len(sorted_entries):
            end_offset = sorted_entries[i + 1].get('offset', 0)
        else:
            end_offset = float('inf')
        
        # Map all offsets in this range to this line
        for offset in all_offsets:
            if start_offset <= offset < end_offset:
                line_table[offset] = line
    
    return line_table


def _format_instruction(bc: dict) -> str:
    """Format a bytecode instruction for display."""
    opr = bc.get('opr', 'unknown')
    
    if opr == 'push':
        val = bc.get('value', {})
        if isinstance(val, dict):
            return f"PUSH {val.get('value', val)}"
        return f"PUSH {val}"
    elif opr == 'load':
        return f"LOAD local_{bc.get('index', 0)}"
    elif opr == 'store':
        return f"STORE local_{bc.get('index', 0)}"
    elif opr == 'get':
        field = bc.get('field', {})
        return f"GETSTATIC {field.get('class', '')}.{field.get('name', '')}"
    elif opr == 'put':
        field = bc.get('field', {})
        return f"PUTSTATIC {field.get('class', '')}.{field.get('name', '')}"
    elif opr == 'ifz':
        return f"IF{bc.get('condition', '').upper()}Z → {bc.get('target', 0)}"
    elif opr == 'if':
        return f"IF_{bc.get('condition', '').upper()} → {bc.get('target', 0)}"
    elif opr == 'goto':
        return f"GOTO {bc.get('target', 0)}"
    elif opr == 'invoke':
        method = bc.get('method', {})
        ref = method.get('ref', {})
        return f"INVOKE {ref.get('name', '')}.{method.get('name', '')}"
    elif opr == 'new':
        return f"NEW {bc.get('class', '')}"
    elif opr == 'binary':
        return f"{bc.get('operant', 'OP').upper()}"
    elif opr == 'return':
        return "RETURN" if bc.get('type') is None else f"RETURN ({bc.get('type')})"
    elif opr == 'throw':
        return "ATHROW"
    elif opr == 'dup':
        return "DUP"
    elif opr == 'incr':
        return f"IINC local_{bc.get('index', 0)} by {bc.get('amount', 1)}"
    elif opr == 'negate':
        return "NEG"
    elif opr == 'newarray':
        return f"NEWARRAY {bc.get('dim', 1)}D"
    elif opr == 'arraylength':
        return "ARRAYLENGTH"
    elif opr == 'array_load':
        return "ARRAYLOAD"
    elif opr == 'array_store':
        return "ARRAYSTORE"
    else:
        return opr.upper()


# =============================================================================
# IIN - Implement Interpreter (Load Traces)
# =============================================================================

def step_iin(method_id: str, verbose: bool = True) -> IINResult:
    """
    IIN (Implement Interpreter) - 7 points
    
    Load execution traces from concrete interpreter runs.
    Traces contain observed values, executed PCs, and branch outcomes.
    """
    if verbose:
        print("\n" + "=" * 80)
        print("STEP 1: IIN - Load Execution Traces")
        print("=" * 80)
    
    # Convert method_id to trace filename
    # jpamb.cases.Simple.assertPositive:(I)V → jpamb.cases.Simple_assertPositive_IV.json
    trace_name = method_id.replace(".", "_").replace(":", "_").replace("(", "_").replace(")", "")
    trace_name = trace_name.replace(";", "").replace("[", "[")
    
    # Try different filename patterns
    patterns = [
        f"traces/{trace_name}.json",
        f"traces/{method_id.replace('.', '_').replace(':', '_').replace('(', '_').replace(')', '')}.json",
    ]
    
    trace_path = None
    for pattern in patterns:
        p = Path(pattern)
        if p.exists():
            trace_path = p
            break
    
    # Also search traces directory
    if trace_path is None:
        traces_dir = Path("traces")
        if traces_dir.exists():
            method = jvm.AbsMethodID.decode(method_id)
            for f in traces_dir.glob("*.json"):
                if method.methodid.name in f.name:
                    # Check if class matches
                    class_short = str(method.classname).split(".")[-1]
                    if class_short in f.name:
                        trace_path = f
                        break
    
    if trace_path is None or not trace_path.exists():
        if verbose:
            print(f"\n⚠ No trace file found for {method_id}")
            print("  Using default empty traces")
        
        return IINResult(
            method_id=method_id,
            trace_file=None,
            samples={},
            executed_pcs=set(),
            uncovered_pcs=set(),
            branch_outcomes={}
        )
    
    with open(trace_path) as f:
        trace = json.load(f)
    
    coverage = trace.get('coverage', {})
    values = trace.get('values', {})
    
    # Extract samples for each local variable
    samples = {}
    for key, val in values.items():
        if key.startswith('local_'):
            idx = int(key.split('_')[1])
            samples[idx] = val.get('samples', [])
    
    executed_pcs = set(coverage.get('executed_pcs', []))
    uncovered_pcs = set(coverage.get('uncovered_pcs', []))
    
    # Parse branch outcomes
    branch_outcomes = {}
    for pc_str, outcomes in coverage.get('branches', {}).items():
        branch_outcomes[int(pc_str)] = outcomes
    
    if verbose:
        print(f"\nTrace file: {trace_path}")
        print("\nExecution Coverage:")
        print(f"  Executed PCs: {sorted(executed_pcs)}")
        print(f"  Uncovered PCs: {sorted(uncovered_pcs)}")
        
        print("\nBranch Outcomes:")
        for pc, outcomes in sorted(branch_outcomes.items()):
            print(f"  PC {pc}: {outcomes}")
        
        print("\nObserved Values:")
        for idx, vals in sorted(samples.items()):
            if vals:
                print(f"  local_{idx}: {vals[:10]}{'...' if len(vals) > 10 else ''}")
        
        print("\n✓ IIN complete")
    
    return IINResult(
        method_id=method_id,
        trace_file=trace_path,
        samples=samples,
        executed_pcs=executed_pcs,
        uncovered_pcs=uncovered_pcs,
        branch_outcomes=branch_outcomes
    )


# =============================================================================
# NAN - Integrate Abstractions at Number Level
# =============================================================================

def step_nan(iin_result: IINResult, verbose: bool = True) -> NANResult:
    """
    NAN (Integrate Abstractions at Number Level) - 10 points
    
    Build ReducedProductState for each local variable from observed samples.
    Combines Sign × Interval × NonNull domains.
    """
    if verbose:
        print("\n" + "=" * 80)
        print("STEP 2: NAN - Build ReducedProductState from Traces")
        print("=" * 80)
    
    initial_states = {}
    
    for idx, samples in iin_result.samples.items():
        if not samples:
            # No samples - use top (unknown)
            sign = SignSet.top()
            interval = IntervalDomain.top()
        else:
            # Abstract samples to Sign and Interval domains
            sign = SignSet.abstract(samples)
            interval = IntervalDomain.abstract(samples)
        
        # NonNull is top for primitives
        nonnull = NonNullDomain.top()
        
        # Build ReducedProductState
        state = ReducedProductState(
            sign=sign,
            interval=interval,
            nonnull=nonnull,
            is_reference=False
        )
        
        # Apply mutual refinement
        state.inform_each_other()
        
        initial_states[idx] = state
        
        if verbose:
            print(f"\nlocal_{idx}:")
            print(f"  Samples: {samples[:5]}{'...' if len(samples) > 5 else ''}")
            print(f"  Sign: {sign}")
            print(f"  Interval: {interval}")
            print(f"  ReducedProduct: {state}")
    
    if verbose:
        print("\n✓ NAN complete: Built ReducedProductState for each local")
    
    return NANResult(
        method_id=iin_result.method_id,
        initial_states=initial_states
    )


# =============================================================================
# IAI+IBA+NAB - Abstract Interpretation with Reduced Product
# =============================================================================

def step_iai(
    isy_result: ISYResult,
    nan_result: NANResult,
    suite: Suite,
    verbose: bool = True
) -> IAIResult:
    """
    IAI + IBA + NAB - Abstract Interpretation with Three-Domain Reduced Product
    
    - IAI (Implement Abstract Interpreter): 7 points - SignSet domain
    - IBA (Implement Unbounded Analysis): 7 points - IntervalDomain + widening  
    - NAB (Integrate Abstractions): 5 points per domain - Reduced product
    
    Uses ProductValue (Interval + Nullness) for maximum precision.
    The interval info comes from NAN's dynamic trace abstraction.
    """
    if verbose:
        print("\n" + "=" * 80)
        print("STEP 3: IAI+IBA+NAB - Abstract Interpretation")
        print("=" * 80)
        print("\nDomains Active:")
        print("  1. SignSet (IAI) - tracks {+, 0, -}")
        print("  2. IntervalDomain (IBA) - tracks [low, high] with widening")
        print("  3. NonNullDomain (NAB) - tracks null/non-null")
    
    method = jvm.AbsMethodID.decode(isy_result.method_id)
    
    # Create ProductValue initial locals from NAN results
    # This uses the INTERVAL info from dynamic traces for better precision
    product_init_locals = {}
    for idx, state in nan_result.initial_states.items():
        # Convert ReducedProductState to ProductValue
        product_init_locals[idx] = ProductValue(
            interval=state.interval,
            nullness=state.nonnull
        )
    
    if verbose:
        print("\nInitial Abstract State (from dynamic traces):")
        for idx, pv in product_init_locals.items():
            print(f"  local_{idx} = {pv}")
    
    # Run product domain abstract interpreter (uses interval + nullness)
    if verbose:
        print("\nRunning product_unbounded_run() with dynamic trace refinement...")
    
    outcomes, visited = product_unbounded_run(suite, method, product_init_locals)
    
    # Compute unreachable PCs
    unreachable = isy_result.all_offsets - visited
    
    # Compute dead statements
    # A statement is FULLY dead only if ALL its instructions are dead
    # A statement is PARTIALLY dead if SOME of its instructions are dead
    fully_dead_statements = set()
    partially_dead_statements = set()
    
    if isy_result.line_table:
        # Group instructions by line number
        line_to_pcs = {}
        for pc, line in isy_result.line_table.items():
            if line not in line_to_pcs:
                line_to_pcs[line] = set()
            line_to_pcs[line].add(pc)
        
        for line, pcs in line_to_pcs.items():
            dead_pcs = pcs & unreachable
            if dead_pcs:
                if dead_pcs == pcs:
                    # ALL instructions for this line are dead
                    fully_dead_statements.add(line)
                else:
                    # SOME instructions for this line are dead
                    partially_dead_statements.add(line)
    
    # Use fully dead statements as the primary metric
    dead_statements = fully_dead_statements
    total_statements = len(isy_result.all_statements) if isy_result.all_statements else 0
    
    if verbose:
        print("\nResults:")
        print(f"  Visited PCs: {sorted(visited)}")
        print(f"  All PCs: {sorted(isy_result.all_offsets)}")
        print(f"  Unreachable PCs: {sorted(unreachable)}")
        print(f"  Outcomes: {outcomes}")
        
        if unreachable:
            print("\nDead Code Found:")
            print(f"  Instructions: {len(unreachable)} dead / {len(isy_result.all_offsets)} total")
            print(f"  Statements (fully dead): {len(fully_dead_statements)} / {total_statements} (lines: {sorted(fully_dead_statements)})")
            if partially_dead_statements:
                print(f"  Statements (partially dead): {len(partially_dead_statements)} (lines: {sorted(partially_dead_statements)})")
            for offset in sorted(unreachable):
                bc = next((b for b in isy_result.bytecode if b.get('offset') == offset), {})
                line = isy_result.line_table.get(offset, "?") if isy_result.line_table else "?"
                print(f"  [{offset:3d}] L{line}: {_format_instruction(bc)} - DEAD")
        else:
            print("\nNo dead code found (all instructions reachable)")
        
        print("\n✓ IAI+IBA+NAB complete")
    
    return IAIResult(
        method_id=isy_result.method_id,
        visited_pcs=visited,
        unreachable_pcs=unreachable,
        outcomes=outcomes,
        dead_code_count=len(unreachable),
        dead_statements=dead_statements,
        dead_statement_count=len(dead_statements),
        total_statements=total_statements
    )


# =============================================================================
# NCR - Analysis-informed Code Rewriting
# =============================================================================

def step_ncr(
    isy_result: ISYResult,
    iai_result: IAIResult,
    verbose: bool = True
) -> NCRResult:
    """
    NCR (Analysis-informed Code Rewriting) - 10 points
    
    Remove dead code by replacing unreachable instructions with NOPs.
    """
    if verbose:
        print("\n" + "=" * 80)
        print("STEP 4: NCR - Dead Code Removal")
        print("=" * 80)
    
    # Find class file
    class_file = Path(f"target/classes/{isy_result.class_name}.class")
    
    if not class_file.exists():
        if verbose:
            print(f"\n⚠ Class file not found: {class_file}")
            print("  Skipping NCR step")
        
        return NCRResult(
            method_id=isy_result.method_id,
            original_size=0,
            rewritten_size=0,
            bytes_nopified=0,
            output_file=None,
            valid=False
        )
    
    # Check if we already have a debloated version (for accumulating changes across methods)
    output_dir = Path(f"target/debloated/{isy_result.class_name}").parent
    output_file = output_dir / f"{isy_result.class_name.split('/')[-1]}.class"
    
    # Only process if there's dead code OR we already have a debloated version (accumulating)
    if not iai_result.unreachable_pcs and not output_file.exists():
        if verbose:
            print("\nNo dead code to remove - skipping class file")
            print("\n✓ NCR complete (no changes needed)")
        
        return NCRResult(
            method_id=isy_result.method_id,
            original_size=0,
            rewritten_size=0,
            bytes_nopified=0,
            output_file=None,
            valid=True
        )
    
    # Use debloated file as input if it exists (to accumulate changes from previous methods)
    input_file = output_file if output_file.exists() else class_file
    
    if verbose:
        print(f"\nInput: {input_file}")
        if iai_result.unreachable_pcs:
            print(f"Dead PCs: {sorted(iai_result.unreachable_pcs)}")
        else:
            print("No dead code in this method (preserving previous changes)")
    
    # Read input (either original or previously debloated)
    with open(input_file, 'rb') as f:
        original = f.read()
    
    # Rewrite with NOPs (or keep unchanged if no dead code in this method)
    if iai_result.unreachable_pcs:
        output_dir.mkdir(parents=True, exist_ok=True)
        rewriter = CodeRewriter()
        rewritten = rewriter.rewrite(
            input_file,
            iai_result.unreachable_pcs,
            isy_result.method_name
        )
        
        # Save debloated file
        with open(output_file, 'wb') as f:
            f.write(rewritten)
    else:
        rewritten = original
    
    # Calculate bytes NOPified
    bytes_nopified = 0
    for offset in iai_result.unreachable_pcs:
        bc = next((b for b in isy_result.bytecode if b.get('offset') == offset), {})
        # Estimate instruction size (simplified)
        opr = bc.get('opr', '')
        if opr in ('new', 'invoke', 'get', 'put', 'ifz', 'if', 'goto'):
            bytes_nopified += 3
        elif opr in ('push',) and bc.get('value', {}).get('type') in ('integer',):
            bytes_nopified += 2
        else:
            bytes_nopified += 1
    
    # Verify with javap
    result = subprocess.run(
        ['javap', '-c', str(output_file)],
        capture_output=True,
        text=True
    )
    valid = result.returncode == 0
    
    if verbose:
        print(f"\nOutput: {output_file}")
        print(f"Original size: {len(original)} bytes")
        print(f"Rewritten size: {len(rewritten)} bytes")
        print(f"Bytes NOPified: ~{bytes_nopified} bytes")
        print(f"Valid class file: {'✓' if valid else '✗'}")
        
        print("\n✓ NCR complete")
    
    return NCRResult(
        method_id=isy_result.method_id,
        original_size=len(original),
        rewritten_size=len(rewritten),
        bytes_nopified=bytes_nopified,
        output_file=output_file,
        valid=valid
    )


# =============================================================================
# Complete Pipeline
# =============================================================================

def run_pipeline(method_id: str, verbose: bool = True) -> PipelineResult:
    """
    Run the complete debloating pipeline on a single method.
    
    Pipeline Steps:
        0. ISY: Parse bytecode → CFG + statements
        1. IIN: Load execution traces
        2. NAN: Build ReducedProductState from traces
        3. IAI+IBA+NAB: Abstract interpretation with reduced product
        4. NCR: Dead code removal
    
    Returns:
        PipelineResult with all step results
    """
    if verbose:
        print("╔" + "═" * 78 + "╗")
        print("║" + " COMPLETE FINE-GRAINED DEBLOATING PIPELINE".center(78) + "║")
        print("║" + " DTU 02242 Program Analysis - Group 21".center(78) + "║")
        print("╚" + "═" * 78 + "╝")
        print(f"\nTarget Method: {method_id}")
    
    result = PipelineResult(method_id=method_id)
    
    try:
        # Initialize Suite once
        suite = Suite()
        
        # Step 0: ISY
        result.isy = step_isy(method_id, suite, verbose)
        
        # Step 1: IIN
        result.iin = step_iin(method_id, verbose)
        
        # Step 2: NAN
        result.nan = step_nan(result.iin, verbose)
        
        # Step 3: IAI+IBA+NAB
        result.iai = step_iai(result.isy, result.nan, suite, verbose)
        
        # Step 4: NCR
        result.ncr = step_ncr(result.isy, result.iai, verbose)
        
        if verbose:
            print("\n" + "=" * 80)
            print("PIPELINE COMPLETE")
            print("=" * 80)
            print(f"\nSummary for {method_id}:")
            print(f"  Instructions: {result.isy.instruction_count}")
            print(f"  Dead code: {result.iai.dead_code_count} instructions")
            if result.isy.instruction_count > 0:
                print(f"  Removal: {result.iai.dead_code_count / result.isy.instruction_count * 100:.1f}%")
        
    except Exception as e:
        result.error = str(e)
        if verbose:
            print(f"\n✗ Pipeline failed: {e}")
            import traceback
            traceback.print_exc()
    
    return result


def generate_traces(trace_dir: Path = Path("traces"), verbose: bool = True, clean: bool = True) -> bool:
    """
    Generate execution traces for ALL JPAMB test cases using the concrete interpreter.
    
    This is the IIN (Implement Interpreter) step that must run before analysis.
    
    Args:
        trace_dir: Directory to write traces to
        verbose: Show detailed output
        clean: If True, remove ALL existing trace files before regenerating
    
    Returns:
        True if trace generation succeeded
    """
    if verbose:
        print("=" * 80)
        print("STEP 0: IIN - Generate Execution Traces for ALL Methods")
        print("=" * 80)
    
    # Clean ALL trace files before regenerating to ensure fresh data
    if clean and trace_dir.exists():
        existing_traces = list(trace_dir.glob("*.json"))
        if existing_traces:
            if verbose:
                print(f"\nClearing {len(existing_traces)} existing trace files...")
            for trace_file in existing_traces:
                trace_file.unlink()
            if verbose:
                print(f"✓ Cleared all trace files from {trace_dir}/")
    
    # Also clear initial_states.json if it exists
    states_file = Path("initial_states.json")
    if clean and states_file.exists():
        states_file.unlink()
        if verbose:
            print(f"✓ Cleared {states_file}")
    
    if verbose:
        print(f"\nRunning: uv run jpamb trace --trace-dir {trace_dir}")
    
    # Run jpamb trace command to generate traces for all methods
    result = subprocess.run(
        ["uv", "run", "jpamb", "trace", "--trace-dir", str(trace_dir)],
        capture_output=True,
        text=True
    )
    
    if verbose:
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
    
    if result.returncode != 0:
        if verbose:
            print(f"\n✗ Trace generation failed with code {result.returncode}")
        return False
    
    # Count generated traces
    trace_files = list(trace_dir.glob("*.json"))
    if verbose:
        print(f"\n✓ Generated {len(trace_files)} trace files in {trace_dir}/")
    
    # Generate initial_states.json using jpamb refine
    # This consolidates trace info into a single file for consistency
    states_file = Path("initial_states.json")
    if verbose:
        print(f"\nRunning: uv run jpamb refine --trace-dir {trace_dir} --output {states_file}")
    
    refine_result = subprocess.run(
        ["uv", "run", "jpamb", "refine", "--trace-dir", str(trace_dir), "--output", str(states_file)],
        capture_output=True,
        text=True
    )
    
    if verbose:
        if refine_result.stdout:
            print(refine_result.stdout)
        if refine_result.stderr:
            print(refine_result.stderr)
    
    if refine_result.returncode != 0:
        if verbose:
            print(f"\n⚠ Refine step failed with code {refine_result.returncode}")
        # Don't fail the whole pipeline, traces are still usable
    elif verbose:
        print(f"✓ Generated {states_file}")
    
    return True


def _clean_stale_traces(trace_dir: Path, verbose: bool = False) -> int:
    """
    Remove trace files for classes that no longer exist in target/decompiled.
    
    Returns:
        Number of stale trace files removed
    """
    decompiled_dir = Path("target/decompiled")
    if not decompiled_dir.exists():
        return 0
    
    # Get set of existing class names from decompiled JSONs
    existing_classes = set()
    for json_file in decompiled_dir.rglob("*.json"):
        # Convert path to class name: target/decompiled/jpamb/cases/Simple.json → jpamb.cases.Simple
        rel_path = json_file.relative_to(decompiled_dir)
        class_name = str(rel_path.with_suffix("")).replace("/", ".").replace("\\", ".")
        existing_classes.add(class_name)
    
    # Check each trace file
    stale_count = 0
    for trace_file in trace_dir.glob("*.json"):
        # Extract class name from trace filename
        # jpamb.cases.Simple_assertPositive_IV.json → jpamb.cases.Simple
        trace_name = trace_file.stem
        parts = trace_name.split("_")
        
        # Find class name (everything before method_descriptor)
        if len(parts) >= 2:
            remaining = "_".join(parts[:-1])  # Remove descriptor
            dot_parts = remaining.split(".")
            if len(dot_parts) >= 3:
                # Last dot_part contains ClassName_methodName
                last = dot_parts[-1]
                underscore_idx = last.find("_")
                if underscore_idx > 0:
                    class_name = ".".join(dot_parts[:-1]) + "." + last[:underscore_idx]
                    
                    # Check if class exists
                    if class_name not in existing_classes:
                        if verbose:
                            print(f"  Removing stale trace: {trace_file.name} (class {class_name} no longer exists)")
                        trace_file.unlink()
                        stale_count += 1
    
    return stale_count


def run_pipeline_all(verbose: bool = False) -> List[PipelineResult]:
    """
    Run the pipeline on ALL JPAMB methods from decompiled JSON files.
    
    This analyzes ALL methods comprehensively, including those without traces.
    Methods without traces are analyzed using static-only analysis.
    
    Always regenerates traces before analysis to ensure fresh data.
    
    Args:
        verbose: Show detailed output for each method
    
    Returns:
        List of PipelineResult for each method
    """
    print("╔" + "═" * 78 + "╗")
    print("║" + " COMPLETE FINE-GRAINED DEBLOATING PIPELINE".center(78) + "║")
    print("║" + " Running on ALL JPAMB Methods (Comprehensive)".center(78) + "║")
    print("╚" + "═" * 78 + "╝")
    
    traces_dir = Path("traces")
    
    # Step 0: Always generate traces for ALL methods
    print("\n" + "─" * 80)
    print("PHASE 1: Generate Execution Traces (IIN)")
    print("─" * 80)
    if not generate_traces(traces_dir, verbose=True):
        print("Failed to generate traces")
        return []
    
    print("\n" + "─" * 80)
    print("PHASE 2: Enumerate ALL Methods from Decompiled JSON")
    print("─" * 80)
    
    # Get ALL methods from decompiled JSON files (comprehensive)
    all_methods = list_all_methods_from_decompiled()
    
    # Also get methods with traces for comparison
    traced_methods = set(list_available_methods())
    
    print(f"\nTotal methods from decompiled JSON: {len(all_methods)}")
    print(f"Methods with execution traces: {len(traced_methods)}")
    print(f"Methods for static-only analysis: {len(all_methods) - len(traced_methods)}")
    
    print("\n" + "─" * 80)
    print("PHASE 3: Analyze All Methods (ISY → NAN → IAI → NCR)")
    print("─" * 80)
    
    results = []
    
    print(f"\nAnalyzing {len(all_methods)} methods...\n")
    
    for method_id in all_methods:
        has_trace = method_id in traced_methods
        trace_marker = "✓" if has_trace else "○"
        print(f"[{trace_marker}] Processing: {method_id}")
        
        result = run_pipeline(method_id, verbose=verbose)
        results.append(result)
        
        # Brief summary
        if result.error:
            print(f"    ✗ Error: {result.error[:50]}...")
        elif result.iai:
            stmt_info = ""
            if result.iai.dead_statement_count > 0:
                stmt_info = f", {result.iai.dead_statement_count} statements"
            trace_note = " (static-only)" if not has_trace else ""
            print(f"    ✓ Dead code: {result.iai.dead_code_count} instructions{stmt_info}{trace_note}")
        print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    # Methods that at least have ISY result (bytecode parsed)
    has_isy = [r for r in results if r.isy is not None]
    # Methods that also have IAI result (abstract interpretation completed)
    has_iai = [r for r in has_isy if r.iai is not None]
    # Methods with dead code detected
    dead_code_found = [r for r in has_iai if r.iai.dead_code_count > 0]
    # Methods that failed (no ISY)
    failed = [r for r in results if r.isy is None]
    # Methods where ISY worked but IAI failed
    iai_failed = [r for r in has_isy if r.iai is None]
    
    print(f"\nTotal methods analyzed: {len(results)}")
    print(f"  - With traces: {len(traced_methods)}")
    print(f"  - Static-only: {len(results) - len(traced_methods)}")
    print(f"Bytecode parsed (ISY): {len(has_isy)}")
    print(f"Abstract interpretation (IAI): {len(has_iai)}")
    if iai_failed:
        print(f"  - Skipped (unsupported opcodes): {len(iai_failed)}")
    print(f"Methods with dead code: {len(dead_code_found)}")
    
    if dead_code_found:
        print("\nMethods with dead code:")
        print(f"  {'Method':<50} {'Instructions':<15} {'Statements':<15}")
        print("  " + "-" * 80)
        for r in dead_code_found:
            instr_pct = r.iai.dead_code_count / r.isy.instruction_count * 100
            stmt_pct = (r.iai.dead_statement_count / r.iai.total_statements * 100) if r.iai.total_statements > 0 else 0
            short_name = r.method_id.split(".")[-1]
            print(f"  {short_name:<50} {r.iai.dead_code_count:>3} ({instr_pct:>4.1f}%)      {r.iai.dead_statement_count:>3} ({stmt_pct:>4.1f}%)")
    
    # Totals - use ALL bytecode as denominator
    total_dead_instr = sum(r.iai.dead_code_count for r in has_iai)
    total_instr_all = sum(r.isy.instruction_count for r in has_isy)
    total_dead_stmt = sum(r.iai.dead_statement_count for r in has_iai)
    total_stmt = sum(r.iai.total_statements for r in has_iai)
    skipped_instr = sum(r.isy.instruction_count for r in iai_failed)
    
    print("\n" + "=" * 80)
    print("TOTALS")
    print("=" * 80)
    
    if total_instr_all > 0:
        print(f"\nInstruction-level: {total_dead_instr}/{total_instr_all} dead ({total_dead_instr/total_instr_all*100:.1f}%)")
        if iai_failed:
            print(f"  (Note: {len(iai_failed)} methods with {skipped_instr} instructions skipped due to unsupported opcodes)")
    if total_stmt > 0:
        print(f"Statement-level:   {total_dead_stmt}/{total_stmt} dead ({total_dead_stmt/total_stmt*100:.1f}%)")
    
    # List debloated classes
    debloated_dir = Path("target/debloated/jpamb/cases")
    if debloated_dir.exists():
        debloated_classes = list(debloated_dir.glob("*.class"))
        if debloated_classes:
            print(f"\nDebloated classes ({len(debloated_classes)}):")
            for c in sorted(debloated_classes):
                print(f"  {c.name}")
    
    return results


def _trace_to_method_id(trace_name: str) -> Optional[str]:
    """Convert trace filename to method_id.
    
    Example: jpamb.cases.Simple_assertPositive_IV → jpamb.cases.Simple.assertPositive:(I)V
    """
    parts = trace_name.split("_")
    if len(parts) < 2:
        return None
    
    # Last part is descriptor
    descriptor = parts[-1]
    remaining = "_".join(parts[:-1])
    
    # Find class/method boundary
    dot_parts = remaining.split(".")
    if len(dot_parts) < 3:
        return None
    
    # Last part contains ClassName_methodName
    last = dot_parts[-1]
    underscore_idx = last.find("_")
    if underscore_idx <= 0:
        return None
    
    class_name = ".".join(dot_parts[:-1]) + "." + last[:underscore_idx]
    method_name = last[underscore_idx + 1:]
    
    # Reconstruct descriptor: IV → (I)V
    if len(descriptor) > 0:
        ret = descriptor[-1]
        params = descriptor[:-1]
        desc = f"({params}){ret}"
    else:
        desc = "()V"
    
    return f"{class_name}.{method_name}:{desc}"


def list_available_methods() -> List[str]:
    """List all methods that have trace files available."""
    traces_dir = Path("traces")
    if not traces_dir.exists():
        return []
    
    methods = []
    for trace_file in sorted(traces_dir.glob("*.json")):
        method_id = _trace_to_method_id(trace_file.stem)
        if method_id:
            methods.append(method_id)
    
    return methods


def list_all_methods_from_decompiled() -> List[str]:
    """
    List ALL methods from decompiled JSON files.
    
    This is comprehensive - includes all methods in all classes,
    not just those with traces.
    """
    decompiled_dir = Path("target/decompiled/jpamb/cases")
    if not decompiled_dir.exists():
        return []
    
    def _type_to_descriptor(type_info) -> str:
        """Convert JSON type info to JVM descriptor."""
        if type_info is None:
            return "V"
        
        if isinstance(type_info, dict):
            # Handle wrapped type: {'annotations': [], 'type': {...}} or {'annotations': [], 'type': None}
            if 'type' in type_info and 'kind' not in type_info and 'base' not in type_info:
                inner_type = type_info['type']
                if inner_type is None:
                    return "V"
                type_info = inner_type
            
            if 'base' in type_info:
                base = type_info['base']
                base_map = {
                    'int': 'I', 'long': 'J', 'float': 'F', 'double': 'D',
                    'byte': 'B', 'char': 'C', 'short': 'S', 'boolean': 'Z', 'void': 'V'
                }
                return base_map.get(base, 'I')
            elif 'kind' in type_info and type_info['kind'] == 'array':
                # Array uses 'type' not 'inner' for the element type
                inner = _type_to_descriptor(type_info.get('type'))
                return '[' + inner
            elif 'kind' in type_info and type_info['kind'] == 'class':
                name = type_info.get('name', 'java/lang/Object')
                return 'L' + name + ';'
        
        return 'I'  # Default to int
    
    def _build_descriptor(method) -> str:
        """Build JVM method descriptor from params and returns."""
        params = method.get('params', [])
        returns = method.get('returns', None)
        
        param_desc = ""
        for p in params:
            param_desc += _type_to_descriptor(p)
        
        ret_desc = _type_to_descriptor(returns)
        
        return f"({param_desc}){ret_desc}"
    
    methods = []
    for json_file in sorted(decompiled_dir.glob("*.json")):
        try:
            with open(json_file) as f:
                data = json.load(f)
            
            class_name = "jpamb.cases." + json_file.stem
            
            for method in data.get('methods', []):
                method_name = method.get('name')
                
                desc = _build_descriptor(method)
                method_id = f"{class_name}.{method_name}:{desc}"
                methods.append(method_id)
        except Exception:
            pass
    
    return methods


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point with command-line argument handling."""
    clean_only = False
    args = sys.argv[1:]
    
    # Check for --clean flag
    if "--clean" in args:
        clean_only = True
        args.remove("--clean")
    
    # Handle --clean flag (just clean stale traces)
    if clean_only:
        trace_dir = Path("traces")
        if trace_dir.exists():
            stale_count = _clean_stale_traces(trace_dir, verbose=True)
            print(f"\nCleaned {stale_count} stale trace files")
        else:
            print("No traces directory found")
        return
    
    if args:
        arg = args[0]
        
        if arg == "--list":
            traced_methods = set(list_available_methods())
            all_methods = list_all_methods_from_decompiled()
            
            print(f"All methods from decompiled JSON ({len(all_methods)} total):")
            print("  [✓] = has trace, [○] = static-only analysis\n")
            
            for m in all_methods:
                marker = "✓" if m in traced_methods else "○"
                print(f"  [{marker}] {m}")
            
            print(f"\n  Total: {len(all_methods)} methods")
            print(f"  With traces: {len(traced_methods)}")
            print(f"  Static-only: {len(all_methods) - len(traced_methods)}")
            return
        
        elif arg == "--all":
            run_pipeline_all(verbose=False)
            return
        
        elif arg == "--help":
            print(__doc__)
            return
        
        else:
            # Treat as method name (partial match)
            if ":" in arg:
                method_id = arg
            else:
                # Partial match - find in ALL methods
                methods = list_all_methods_from_decompiled()
                matches = [m for m in methods if arg.lower() in m.lower()]
                if len(matches) == 1:
                    method_id = matches[0]
                elif len(matches) > 1:
                    print(f"Multiple matches for '{arg}':")
                    for m in matches:
                        print(f"  {m}")
                    return
                else:
                    print(f"No method found matching '{arg}'")
                    print("Use --list to see available methods")
                    return
            
            run_pipeline(method_id, verbose=True)
            return
    
    # Default: run on ALL methods
    run_pipeline_all(verbose=False)


if __name__ == "__main__":
    main()
