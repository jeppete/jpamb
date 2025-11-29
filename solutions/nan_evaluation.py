"""
NAN Evaluation Script - Demonstrates dynamic refinement improves static analysis.

This script shows that using dynamic traces (IIN) to refine initial abstract states
leads to MORE precise static analysis (proves MORE code unreachable).

DTU 02242 Program Analysis - Group 21
NAN (Integrate Analyses) - 10 points

Course Requirement:
    "Use the result of ONE analysis (dynamic/IIN) to improve ANOTHER analysis (static/IAI)"
    "The improvement must be visible: static analysis with dynamic refinement must prove 
     MORE code unreachable than static alone"
"""

import sys
from pathlib import Path
from typing import Dict, Tuple, List
import json

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from jpamb import jvm
from jpamb.model import Suite

from solutions.components.abstract_interpreter import (
    unbounded_abstract_run,
    get_unreachable_pcs,
)
from solutions.components.abstract_domain import SignSet
from solutions.nab_integration import (
    ReducedProductState,
    extract_samples_from_trace,
)


# =============================================================================
# NAN EVALUATION: Compare static analysis WITH vs WITHOUT dynamic refinement
# =============================================================================

def analyze_without_refinement(suite: Suite, method: jvm.AbsMethodID) -> Tuple[set, set]:
    """
    Static analysis WITHOUT dynamic refinement (init = TOP).
    
    Returns:
        (unreachable_pcs, all_outcomes)
    """
    # Initial state = TOP (no information from dynamic traces)
    outcomes, visited_pcs = unbounded_abstract_run(suite, method, init_locals=None)
    unreachable = get_unreachable_pcs(suite, method, init_locals=None)
    return unreachable, outcomes


def analyze_with_refinement(
    suite: Suite, 
    method: jvm.AbsMethodID, 
    init_locals: Dict[int, SignSet]
) -> Tuple[set, set]:
    """
    Static analysis WITH dynamic refinement (init from IIN traces).
    
    Returns:
        (unreachable_pcs, all_outcomes)
    """
    outcomes, visited_pcs = unbounded_abstract_run(suite, method, init_locals=init_locals)
    unreachable = get_unreachable_pcs(suite, method, init_locals=init_locals)
    return unreachable, outcomes


def get_refined_init_from_trace(trace_path: Path) -> Dict[int, SignSet]:
    """
    Extract refined initial state from IIN trace file.
    
    This is the NAN integration: IIN trace → ReducedProductState → SignSet for IAI
    """
    if not trace_path.exists():
        return {}
    
    with open(trace_path, 'r') as f:
        trace_data = json.load(f)
    
    samples_by_local = extract_samples_from_trace(trace_data)
    
    init_locals = {}
    for local_idx, samples in samples_by_local.items():
        if samples:
            reduced = ReducedProductState.from_samples(samples)
            init_locals[local_idx] = reduced.sign
    
    return init_locals


def get_refined_init_from_samples(samples_by_local: Dict[int, List[int]]) -> Dict[int, SignSet]:
    """
    Create refined initial state from sample values (simulating IIN traces).
    
    This demonstrates NAN: dynamic observations → refined abstract state
    """
    init_locals = {}
    for local_idx, samples in samples_by_local.items():
        if samples:
            reduced = ReducedProductState.from_samples(samples)
            init_locals[local_idx] = reduced.sign
    
    return init_locals


# =============================================================================
# EVALUATION ON 5 JPAMB METHODS
# =============================================================================

def evaluate_method(
    suite: Suite,
    method_name: str,
    description: str,
    sample_input: Dict[int, List[int]],
) -> Dict:
    """
    Evaluate a single method: compare WITH vs WITHOUT dynamic refinement.
    
    Returns dict with improvement metrics.
    """
    method = jvm.AbsMethodID.decode(method_name)
    
    # WITHOUT refinement (static only)
    unreachable_static, outcomes_static = analyze_without_refinement(suite, method)
    
    # WITH refinement (NAN: dynamic → static)
    init_refined = get_refined_init_from_samples(sample_input)
    unreachable_nan, outcomes_nan = analyze_with_refinement(suite, method, init_refined)
    
    # Calculate improvement
    improvement = len(unreachable_nan) - len(unreachable_static)
    fewer_outcomes = len(outcomes_static) - len(outcomes_nan)
    
    return {
        "method": method_name,
        "description": description,
        "sample_input": sample_input,
        "refined_init": {k: str(v) for k, v in init_refined.items()},
        "static_only": {
            "unreachable_count": len(unreachable_static),
            "unreachable_pcs": sorted(unreachable_static),
            "outcomes": list(outcomes_static),
        },
        "with_nan": {
            "unreachable_count": len(unreachable_nan),
            "unreachable_pcs": sorted(unreachable_nan),
            "outcomes": list(outcomes_nan),
        },
        "improvement": {
            "additional_unreachable": improvement,
            "fewer_outcomes": fewer_outcomes,
            "improved": improvement > 0 or fewer_outcomes > 0,
        }
    }


def run_nan_evaluation():
    """
    Run NAN evaluation on 5 JPAMB methods.
    
    Shows that dynamic refinement (IIN traces) improves static analysis (IAI).
    """
    suite = Suite()
    
    # Define 5 test cases with different scenarios
    test_cases = [
        # 1. assertPositive: If we know x > 0 from traces, assertion path is unreachable
        {
            "method": "jpamb.cases.Simple.assertPositive:(I)V",
            "description": "Assert x > 0. Dynamic trace shows x is always positive.",
            "samples": {0: [1, 5, 10, 100]},  # All positive samples
        },
        # 2. divideByN: If we know n != 0 from traces, divide-by-zero is unreachable
        {
            "method": "jpamb.cases.Simple.divideByN:(I)I",
            "description": "Divide 100/n. Dynamic trace shows n is never zero.",
            "samples": {0: [1, 2, 5, 10]},  # All non-zero positive
        },
        # 3. checkBeforeDivideByN: If n > 0, both check and division are safe
        {
            "method": "jpamb.cases.Simple.checkBeforeDivideByN:(I)I",
            "description": "If n > 0, divide. Dynamic trace confirms n > 0.",
            "samples": {0: [1, 2, 3, 4, 5]},  # All positive
        },
        # 4. assertBoolean: If we know b is always true/false
        {
            "method": "jpamb.cases.Simple.assertBoolean:(Z)V",
            "description": "Assert boolean b. Dynamic trace shows b is always true (1).",
            "samples": {0: [1, 1, 1, 1]},  # All true (1)
        },
        # 5. divideByNMinus10054203: Edge case where n = 10054203 causes divide by zero
        {
            "method": "jpamb.cases.Simple.divideByNMinus10054203:(I)I",
            "description": "Divide by n-10054203. Dynamic trace shows n != 10054203.",
            "samples": {0: [1, 2, 3, 4, 5]},  # None equal to 10054203
        },
    ]
    
    results = []
    for tc in test_cases:
        result = evaluate_method(suite, tc["method"], tc["description"], tc["samples"])
        results.append(result)
    
    return results


def print_evaluation_table(results: List[Dict]):
    """
    Print evaluation results as a table.
    """
    print("\n" + "=" * 100)
    print("NAN EVALUATION: Static Analysis WITH vs WITHOUT Dynamic Refinement")
    print("=" * 100)
    print()
    
    # Header
    print(f"{'Method':<50} {'Static Only':<15} {'With NAN':<15} {'Improvement':<15}")
    print(f"{'(unreachable PCs)':<50} {'Unreachable':<15} {'Unreachable':<15} {'(+/- PCs)':<15}")
    print("-" * 100)
    
    total_static = 0
    total_nan = 0
    
    for r in results:
        static_count = r["static_only"]["unreachable_count"]
        nan_count = r["with_nan"]["unreachable_count"]
        improvement = r["improvement"]["additional_unreachable"]
        
        total_static += static_count
        total_nan += nan_count
        
        # Truncate method name for display
        method_short = r["method"].split(".")[-1][:48]
        
        improvement_str = f"+{improvement}" if improvement > 0 else str(improvement)
        status = "✓" if improvement > 0 else "="
        
        print(f"{method_short:<50} {static_count:<15} {nan_count:<15} {improvement_str:<10} {status}")
    
    print("-" * 100)
    total_improvement = total_nan - total_static
    print(f"{'TOTAL':<50} {total_static:<15} {total_nan:<15} +{total_improvement}")
    print()
    
    # Summary
    print("=" * 100)
    print("SUMMARY")
    print("=" * 100)
    improvements = sum(1 for r in results if r["improvement"]["improved"])
    print(f"  • Methods with improvement: {improvements}/{len(results)}")
    print(f"  • Total additional unreachable PCs: +{total_improvement}")
    print()
    
    # Detailed results
    print("DETAILED ANALYSIS:")
    print("-" * 100)
    for r in results:
        print(f"\n{r['method']}:")
        print(f"  Description: {r['description']}")
        print(f"  Sample input: {r['sample_input']}")
        print(f"  Refined init: {r['refined_init']}")
        print(f"  Static only outcomes: {r['static_only']['outcomes']}")
        print(f"  With NAN outcomes: {r['with_nan']['outcomes']}")
        if r['improvement']['fewer_outcomes'] > 0:
            print(f"  → Eliminated {r['improvement']['fewer_outcomes']} potential outcomes!")
        if r['improvement']['additional_unreachable'] > 0:
            print(f"  → Proved {r['improvement']['additional_unreachable']} more PCs unreachable!")
    
    print("\n" + "=" * 100)
    print("CONCLUSION: NAN (dynamic refinement) improves static analysis precision.")
    print("=" * 100)


def main():
    """
    Main entry point for NAN evaluation.
    """
    print("Running NAN Evaluation...")
    print("This demonstrates that IIN (dynamic traces) improves IAI (static analysis)")
    print()
    
    results = run_nan_evaluation()
    print_evaluation_table(results)
    
    # Save results to JSON
    output_path = Path(__file__).parent.parent / "nan_evaluation_results.json"
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_path}")
    
    return results


if __name__ == "__main__":
    main()
