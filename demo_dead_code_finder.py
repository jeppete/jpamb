#!/usr/bin/env python3
"""
Dead Code Finder Demo

This script demonstrates how to use the Abstract Interpreter (IAI) to find
dead code in Java bytecode. It analyzes all JPAMB Java classes and reports
which instructions are unreachable.

Usage:
    python demo_dead_code_finder.py                  # Analyze all classes
    python demo_dead_code_finder.py Simple           # Analyze specific class
    python demo_dead_code_finder.py --method assertPositive  # Analyze specific method
    python demo_dead_code_finder.py --verbose        # Show detailed bytecode

DTU 02242 Program Analysis - Group 21
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from jpamb import jvm
from jpamb.model import Suite
from solutions.components.abstract_interpreter import unbounded_abstract_run, get_unreachable_pcs
from solutions.components.abstract_domain import SignSet


# =============================================================================
# Helper Functions
# =============================================================================

def get_methods_from_class(class_name: str) -> List[Tuple[str, str, dict]]:
    """
    Get all methods from a Java class.
    
    Returns: List of (method_name, method_id, method_data)
    """
    path = Path(f'target/decompiled/jpamb/cases/{class_name}.json')
    if not path.exists():
        return []
    
    with open(path) as f:
        data = json.load(f)
    
    methods = []
    for m in data.get('methods', []):
        name = m['name']
        if name.startswith('<'):  # Skip <init>, <clinit>
            continue
        
        # Build method descriptor
        params = m.get('params', [])
        ret = m.get('returns', {})
        
        param_str = ''
        for p in params:
            ptype = p.get('type', {}).get('base', 'I')
            type_map = {
                'int': 'I', 'boolean': 'Z', 'char': 'C', 'byte': 'B',
                'short': 'S', 'long': 'J', 'float': 'F', 'double': 'D'
            }
            param_str += type_map.get(ptype, 'L')  # L for reference types
        
        ret_type = ret.get('base', 'void') if ret else 'void'
        ret_map = {'void': 'V', 'int': 'I', 'boolean': 'Z'}
        ret_str = ret_map.get(ret_type, 'V')
        
        method_id = f"jpamb.cases.{class_name}.{name}:({param_str}){ret_str}"
        methods.append((name, method_id, m))
    
    return methods


def format_bytecode_instruction(bc: dict) -> str:
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
    elif opr == 'binary':
        return f"{bc.get('operant', 'OP').upper()}"
    elif opr == 'return':
        return "RETURN" if bc.get('type') is None else f"RETURN ({bc.get('type')})"
    elif opr == 'throw':
        return "ATHROW"
    else:
        return opr.upper()


def analyze_method(
    suite: Suite,
    class_name: str,
    method_name: str,
    method_id: str,
    method_data: dict,
    verbose: bool = False,
    init_locals: Optional[Dict[int, SignSet]] = None
) -> dict:
    """
    Analyze a single method for dead code.
    
    Returns dict with analysis results.
    """
    result = {
        'class': class_name,
        'method': method_name,
        'method_id': method_id,
        'error': None,
        'outcomes': set(),
        'visited_pcs': set(),
        'unreachable_pcs': set(),
        'bytecode': [],
        'dead_instructions': []
    }
    
    try:
        method = jvm.AbsMethodID.decode(method_id)
        
        # Run abstract interpretation
        outcomes, visited = unbounded_abstract_run(
            suite, method, 
            init_locals=init_locals,
            widening_threshold=3
        )
        unreachable = get_unreachable_pcs(suite, method, init_locals=init_locals)
        
        result['outcomes'] = outcomes
        result['visited_pcs'] = visited
        result['unreachable_pcs'] = unreachable
        
        # Get bytecode for detailed analysis
        bytecode = method_data.get('code', {}).get('bytecode', [])
        result['bytecode'] = bytecode
        
        # Identify dead instructions
        for bc in bytecode:
            offset = bc.get('offset', 0)
            if offset in unreachable:
                result['dead_instructions'].append({
                    'offset': offset,
                    'instruction': format_bytecode_instruction(bc),
                    'raw': bc
                })
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def print_method_analysis(result: dict, verbose: bool = False):
    """Print analysis results for a method."""
    print(f"\n{'─' * 70}")
    print(f"Method: {result['class']}.{result['method']}")
    print(f"{'─' * 70}")
    
    if result['error']:
        print(f"  ⚠ Error: {result['error']}")
        return
    
    print(f"  Outcomes: {result['outcomes']}")
    print(f"  Visited: {len(result['visited_pcs'])} instructions")
    print(f"  Dead: {len(result['unreachable_pcs'])} instructions")
    
    if result['dead_instructions']:
        print("\n  Dead Instructions:")
        for instr in result['dead_instructions']:
            print(f"    [{instr['offset']:3d}] {instr['instruction']}")
    
    if verbose and result['bytecode']:
        print("\n  Full Bytecode (dead marked with ✗):")
        for bc in result['bytecode']:
            offset = bc.get('offset', 0)
            is_dead = offset in result['unreachable_pcs']
            marker = "✗" if is_dead else " "
            instr = format_bytecode_instruction(bc)
            print(f"    {marker} [{offset:3d}] {instr}")


def analyze_class(class_name: str, suite: Suite, verbose: bool = False) -> List[dict]:
    """Analyze all methods in a Java class."""
    methods = get_methods_from_class(class_name)
    
    if not methods:
        print(f"No methods found in {class_name}")
        return []
    
    print(f"\n{'═' * 70}")
    print(f" Analyzing: {class_name}.java ({len(methods)} methods)")
    print(f"{'═' * 70}")
    
    results = []
    for name, method_id, method_data in methods:
        result = analyze_method(suite, class_name, name, method_id, method_data, verbose)
        results.append(result)
        print_method_analysis(result, verbose)
    
    return results


def print_summary(all_results: List[dict]):
    """Print summary of all analysis results."""
    print(f"\n{'═' * 70}")
    print(" SUMMARY: Dead Code Detection Results")
    print(f"{'═' * 70}")
    
    total_methods = len(all_results)
    successful = [r for r in all_results if r['error'] is None]
    with_dead_code = [r for r in successful if len(r['unreachable_pcs']) > 0]
    
    print(f"\nMethods analyzed: {total_methods}")
    print(f"Successful: {len(successful)}")
    print(f"Methods with dead code: {len(with_dead_code)}")
    
    total_visited = sum(len(r['visited_pcs']) for r in successful)
    total_dead = sum(len(r['unreachable_pcs']) for r in successful)
    
    print(f"\nTotal instructions visited: {total_visited}")
    print(f"Total dead instructions: {total_dead}")
    if total_visited > 0:
        print(f"Dead code percentage: {total_dead / (total_visited + total_dead) * 100:.1f}%")
    
    if with_dead_code:
        print(f"\n{'─' * 70}")
        print("Methods with Dead Code:")
        print(f"{'─' * 70}")
        print(f"  {'Class.Method':<40} {'Dead':<8} {'Outcomes'}")
        for r in sorted(with_dead_code, key=lambda x: -len(x['unreachable_pcs'])):
            name = f"{r['class']}.{r['method']}"
            dead = len(r['unreachable_pcs'])
            outcomes = ', '.join(sorted(r['outcomes']))[:30]
            print(f"  {name:<40} {dead:<8} {outcomes}")


def demo_refinement():
    """Demonstrate how dynamic refinement improves dead code detection."""
    print(f"\n{'═' * 70}")
    print(" DEMO: Dynamic Refinement Improves Dead Code Detection")
    print(f"{'═' * 70}")
    
    suite = Suite()
    
    # Example: assertPositive with different input knowledge
    print("\nMethod: Simple.assertPositive(int x)")
    print("  if (x <= 0) throw AssertionError;  // Dead if x always positive")
    
    method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
    
    # Without refinement (x could be anything)
    print("\n1. Without refinement (x = ⊤ = any value):")
    outcomes_top, visited_top = unbounded_abstract_run(suite, method, init_locals=None)
    unreachable_top = get_unreachable_pcs(suite, method, init_locals=None)
    print(f"   Outcomes: {outcomes_top}")
    print(f"   Dead code: {len(unreachable_top)} instructions")
    
    # With positive refinement (x > 0)
    print("\n2. With refinement (x = {+} = positive only):")
    init_positive = {0: SignSet(frozenset({"+"})) }
    outcomes_pos, visited_pos = unbounded_abstract_run(suite, method, init_locals=init_positive)
    unreachable_pos = get_unreachable_pcs(suite, method, init_locals=init_positive)
    print(f"   Outcomes: {outcomes_pos}")
    print(f"   Dead code: {len(unreachable_pos)} instructions")
    
    # With zero refinement (x = 0)
    print("\n3. With refinement (x = {0} = zero only):")
    init_zero = {0: SignSet(frozenset({"0"})) }
    outcomes_zero, visited_zero = unbounded_abstract_run(suite, method, init_locals=init_zero)
    unreachable_zero = get_unreachable_pcs(suite, method, init_locals=init_zero)
    print(f"   Outcomes: {outcomes_zero}")
    print(f"   Dead code: {len(unreachable_zero)} instructions")
    

# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point."""
    args = sys.argv[1:]
    
    verbose = '--verbose' in args or '-v' in args
    if verbose:
        args = [a for a in args if a not in ('--verbose', '-v')]
    
    show_refinement = '--demo-refinement' in args
    if show_refinement:
        args = [a for a in args if a != '--demo-refinement']
    
    # Available Java classes
    all_classes = ['Simple', 'Arrays', 'Calls', 'Loops', 'Tricky', 'Debloating', 'Dependent']
    
    suite = Suite()
    all_results = []
    
    if '--help' in args or '-h' in args:
        print(__doc__)
        print("\nAvailable classes:", ', '.join(all_classes))
        return
    
    if show_refinement:
        demo_refinement()
        return
    
    if '--method' in args:
        idx = args.index('--method')
        if idx + 1 < len(args):
            method_filter = args[idx + 1].lower()
            args = args[:idx] + args[idx+2:]
            
            # Find methods matching filter
            for cls in all_classes:
                methods = get_methods_from_class(cls)
                for name, method_id, method_data in methods:
                    if method_filter in name.lower():
                        result = analyze_method(suite, cls, name, method_id, method_data, verbose)
                        all_results.append(result)
                        print_method_analysis(result, verbose=True)
            
            if not all_results:
                print(f"No methods found matching '{method_filter}'")
            return
    
    # Filter classes if specified
    if args:
        classes_to_analyze = [c for c in all_classes if c.lower() in [a.lower() for a in args]]
        if not classes_to_analyze:
            print(f"Unknown class(es): {args}")
            print(f"Available: {', '.join(all_classes)}")
            return
    else:
        classes_to_analyze = all_classes
    
    # Analyze each class
    for class_name in classes_to_analyze:
        results = analyze_class(class_name, suite, verbose)
        all_results.extend(results)
    
    # Print summary
    print_summary(all_results)
    
    # Demo refinement if analyzing all
    if not args:
        demo_refinement()


if __name__ == "__main__":
    main()
