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
    python solutions/pipeline_evaluation.py                          # Run on default method
    python solutions/pipeline_evaluation.py Simple.assertPositive    # Run on specific method
    python solutions/pipeline_evaluation.py --all                    # Run on ALL methods
    python solutions/pipeline_evaluation.py --list                   # List available methods

DTU 02242 Program Analysis - Group 21
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass

# Add project path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jpamb import jvm
from jpamb.model import Suite
from solutions.abstract_domain import SignSet, IntervalDomain, NonNullDomain
from solutions.nab_integration import ReducedProductState
from solutions.abstract_interpreter import unbounded_abstract_run
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
    cfg_edges: List[Tuple[int, int]]
    all_offsets: Set[int]


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
    Uses the Suite to load method bytecode directly.
    """
    if verbose:
        print("=" * 80)
        print("STEP 0: ISY - Parse Bytecode → CFG + Statements")
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
    
    bytecode = method_data.get('code', {}).get('bytecode', [])
    
    # Extract CFG edges and offsets
    cfg_edges = []
    all_offsets = set()
    
    for bc in bytecode:
        offset = bc.get('offset', 0)
        all_offsets.add(offset)
        opr = bc.get('opr', '')
        
        # Branch instructions create CFG edges
        if opr in ('ifz', 'if', 'goto'):
            target = bc.get('target', 0)
            cfg_edges.append((offset, target))
        elif opr == 'tableswitch' or opr == 'lookupswitch':
            for target in bc.get('targets', []):
                cfg_edges.append((offset, target))
            if 'default' in bc:
                cfg_edges.append((offset, bc['default']))
    
    if verbose:
        print(f"\nMethod: {method_id}")
        print(f"  Class: {class_name}")
        print(f"  Method: {method_name}")
        print(f"  Instructions: {len(bytecode)}")
        print(f"  CFG Edges: {len(cfg_edges)}")
        
        print(f"\nBytecode ({len(bytecode)} instructions):")
        print("-" * 60)
        for bc in bytecode:
            offset = bc.get('offset', 0)
            print(f"  [{offset:3d}] {_format_instruction(bc)}")
        
        print("\n✓ ISY complete")
    
    return ISYResult(
        method_id=method_id,
        class_name=class_name,
        method_name=method_name,
        bytecode=bytecode,
        instruction_count=len(bytecode),
        cfg_edges=cfg_edges,
        all_offsets=all_offsets
    )


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
    
    Uses SignArithmetic and IntervalArithmetic internally for all operations.
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
    
    # Create initial locals from NAN results (use SignSet for abstract interpreter)
    init_locals = {}
    for idx, state in nan_result.initial_states.items():
        init_locals[idx] = state.sign
    
    if verbose:
        print("\nInitial Abstract State:")
        for idx, sign in init_locals.items():
            print(f"  local_{idx} = {sign}")
    
    # Run abstract interpreter with unbounded analysis
    if verbose:
        print("\nRunning unbounded_abstract_run()...")
    
    outcomes, visited = unbounded_abstract_run(suite, method, init_locals)
    
    # Compute unreachable PCs
    unreachable = isy_result.all_offsets - visited
    
    if verbose:
        print("\nResults:")
        print(f"  Visited PCs: {sorted(visited)}")
        print(f"  All PCs: {sorted(isy_result.all_offsets)}")
        print(f"  Unreachable PCs: {sorted(unreachable)}")
        print(f"  Outcomes: {outcomes}")
        
        if unreachable:
            print(f"\nDead Code Found ({len(unreachable)} instructions):")
            for offset in sorted(unreachable):
                bc = next((b for b in isy_result.bytecode if b.get('offset') == offset), {})
                print(f"  [{offset:3d}] {_format_instruction(bc)} - DEAD")
        else:
            print("\nNo dead code found (all instructions reachable)")
        
        print("\n✓ IAI+IBA+NAB complete")
    
    return IAIResult(
        method_id=isy_result.method_id,
        visited_pcs=visited,
        unreachable_pcs=unreachable,
        outcomes=outcomes,
        dead_code_count=len(unreachable)
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


def generate_traces(trace_dir: Path = Path("traces"), verbose: bool = True) -> bool:
    """
    Generate execution traces for ALL JPAMB test cases using the concrete interpreter.
    
    This is the IIN (Implement Interpreter) step that must run before analysis.
    
    Returns:
        True if trace generation succeeded
    """
    if verbose:
        print("=" * 80)
        print("STEP 0: IIN - Generate Execution Traces for ALL Methods")
        print("=" * 80)
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
    
    return True


def run_pipeline_all(verbose: bool = False, regenerate_traces: bool = True) -> List[PipelineResult]:
    """
    Run the pipeline on ALL JPAMB methods.
    
    Args:
        verbose: Show detailed output for each method
        regenerate_traces: If True, regenerate traces before analysis
    
    Returns:
        List of PipelineResult for each method
    """
    print("╔" + "═" * 78 + "╗")
    print("║" + " COMPLETE FINE-GRAINED DEBLOATING PIPELINE".center(78) + "║")
    print("║" + " Running on ALL JPAMB Methods".center(78) + "║")
    print("╚" + "═" * 78 + "╝")
    
    traces_dir = Path("traces")
    
    # Step 0: Generate traces for ALL methods
    if regenerate_traces or not traces_dir.exists() or not list(traces_dir.glob("*.json")):
        print("\n" + "─" * 80)
        print("PHASE 1: Generate Execution Traces (IIN)")
        print("─" * 80)
        if not generate_traces(traces_dir, verbose=True):
            print("Failed to generate traces")
            return []
    else:
        print(f"\nUsing existing traces in {traces_dir}/")
        print("  (Use --regenerate to regenerate traces)")
    
    print("\n" + "─" * 80)
    print("PHASE 2: Analyze All Methods (ISY → NAN → IAI → NCR)")
    print("─" * 80)
    
    # Find all trace files
    if not traces_dir.exists():
        print("No traces directory found")
        return []
    
    results = []
    trace_files = sorted(traces_dir.glob("*.json"))
    
    print(f"\nFound {len(trace_files)} trace files\n")
    
    for trace_file in trace_files:
        method_id = _trace_to_method_id(trace_file.stem)
        if method_id:
            print(f"Processing: {method_id}")
            result = run_pipeline(method_id, verbose=verbose)
            results.append(result)
            
            # Brief summary
            if result.error:
                print(f"  ✗ Error: {result.error[:50]}...")
            elif result.iai:
                print(f"  ✓ Dead code: {result.iai.dead_code_count} instructions")
            print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    success = [r for r in results if r.error is None]
    failed = [r for r in results if r.error is not None]
    dead_code_found = [r for r in success if r.iai and r.iai.dead_code_count > 0]
    
    print(f"\nTotal methods: {len(results)}")
    print(f"Successful: {len(success)}")
    print(f"Failed: {len(failed)}")
    print(f"Methods with dead code: {len(dead_code_found)}")
    
    if dead_code_found:
        print("\nMethods with dead code:")
        for r in dead_code_found:
            pct = r.iai.dead_code_count / r.isy.instruction_count * 100
            print(f"  {r.method_id}: {r.iai.dead_code_count} instructions ({pct:.1f}%)")
    
    total_dead = sum(r.iai.dead_code_count for r in success if r.iai)
    total_instr = sum(r.isy.instruction_count for r in success if r.isy)
    
    if total_instr > 0:
        print(f"\nTotal: {total_dead}/{total_instr} dead instructions ({total_dead/total_instr*100:.1f}%)")
    
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


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point with command-line argument handling."""
    regenerate = False
    args = sys.argv[1:]
    
    # Check for --regenerate flag
    if "--regenerate" in args:
        regenerate = True
        args.remove("--regenerate")
    
    if args:
        arg = args[0]
        
        if arg == "--list":
            print("Available methods with traces:")
            for m in list_available_methods():
                print(f"  {m}")
            return
        
        elif arg == "--all":
            run_pipeline_all(verbose=False, regenerate_traces=regenerate)
            return
        
        elif arg == "--help":
            print(__doc__)
            return
        
        else:
            # Treat as method name (partial match)
            if ":" in arg:
                method_id = arg
            else:
                # Partial match - find in traces
                methods = list_available_methods()
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
    run_pipeline_all(verbose=False, regenerate_traces=regenerate)


if __name__ == "__main__":
    main()
