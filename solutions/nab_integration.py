"""
NAB Integration Module - Integrates IIN traces with IAB abstract domains.

This module provides the core integration between dynamic execution traces
produced by IIN (Interpreter) and the abstract domains defined in IAB
(Abstractions). It implements the dynamic refinement heuristic that uses
observed concrete values to set initial abstract states for static analysis.

DTU 02242 Program Analysis - Group 21
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass

# Import from existing IAB module
from solutions.abstractions import (
    SignDomain, 
    SignValue,
    IntervalDomain, 
    IntervalValue,
    DomainRefinement
)


@dataclass
class AbstractValue:
    """Combined abstract value with both sign and interval domains."""
    sign: SignDomain
    interval: IntervalDomain
    local_index: int
    
    def __str__(self):
        return f"local_{self.local_index}: sign={self.sign}, interval={self.interval}"
    
    def __repr__(self):
        return f"AbstractValue(local_{self.local_index}, sign={self.sign}, interval={self.interval})"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "local_index": self.local_index,
            "sign": str(self.sign),
            "sign_value": self.sign.value.name,
            "interval": str(self.interval),
            "interval_bounds": {
                "low": self.interval.value.low,
                "high": self.interval.value.high
            }
        }


@dataclass
class IntegrationResult:
    """Result of NAB integration for a method."""
    method_name: str
    abstract_values: Dict[int, AbstractValue]
    trace_path: str
    confidence: float
    samples_count: Dict[int, int]
    
    def __str__(self):
        values_str = ", ".join(str(v) for v in self.abstract_values.values())
        return f"IntegrationResult({self.method_name}: [{values_str}], confidence={self.confidence:.2f})"


def extract_samples_from_trace(trace_data: Dict[str, Any]) -> Dict[int, List[int]]:
    """
    Extract concrete sample values from IIN trace data.
    
    Args:
        trace_data: Parsed JSON trace data from IIN
        
    Returns:
        Dictionary mapping local variable indices to lists of observed values
    """
    samples = {}
    
    if "values" not in trace_data:
        return samples
    
    for local_key, analysis in trace_data["values"].items():
        # Parse local variable index from key like "local_0"
        try:
            local_idx = int(local_key.split("_")[1])
        except (IndexError, ValueError):
            continue
        
        # Extract samples from analysis
        if "samples" in analysis and analysis["samples"]:
            # Filter to only integer values
            int_samples = [v for v in analysis["samples"] if isinstance(v, (int, bool))]
            if int_samples:
                samples[local_idx] = int_samples
    
    return samples


def refine_from_trace(samples: List[int]) -> Tuple[SignDomain, IntervalDomain]:
    """
    Refine abstract domains from concrete sample values.
    
    This is the core dynamic refinement heuristic: we observe concrete
    execution values and infer the tightest abstract domain that contains
    all observed values. This is our approved novelty contribution.
    
    Args:
        samples: List of concrete integer values observed during execution
        
    Returns:
        Tuple of (SignDomain, IntervalDomain) refined from samples
    """
    # Use existing IAB refinement
    return DomainRefinement.from_concrete_values(samples)


def integrate_abstractions(trace_path: str) -> Dict[int, AbstractValue]:
    """
    Main NAB integration function: reads IIN trace and produces refined abstract state.
    
    This function implements the integration between:
    - IIN (Interpreter): produces traces/<method>.json with concrete execution data
    - IAB (Abstractions): provides SignDomain, IntervalDomain, refine_from_trace()
    
    The integration uses dynamic traces to set initial abstract states (e.g., x>0)
    for subsequent static analysis, as described in our approved proposal.
    
    Args:
        trace_path: Path to IIN JSON trace file in traces/ directory
        
    Returns:
        Dictionary mapping local variable indices to AbstractValue objects
        containing refined sign and interval domains
        
    Example:
        >>> result = integrate_abstractions("traces/jpamb.cases.Simple_assertPositive_IV.json")
        >>> result[0].sign.value  # SignValue.POSITIVE for samples [1,1,1,1,1]
    """
    # Read IIN trace file
    path = Path(trace_path)
    if not path.exists():
        raise FileNotFoundError(f"Trace file not found: {trace_path}")
    
    with open(path, 'r') as f:
        trace_data = json.load(f)
    
    # Extract concrete samples from trace
    samples_by_local = extract_samples_from_trace(trace_data)
    
    # Refine abstract domains for each local variable
    abstract_values: Dict[int, AbstractValue] = {}
    
    for local_idx, samples in samples_by_local.items():
        # Apply IAB refinement to get sign and interval domains
        sign_domain, interval_domain = refine_from_trace(samples)
        
        # Create combined abstract value
        abstract_values[local_idx] = AbstractValue(
            sign=sign_domain,
            interval=interval_domain,
            local_index=local_idx
        )
    
    # For local variables with no samples, return TOP
    if not abstract_values:
        # Return empty dict - caller can handle as needed
        pass
    
    return abstract_values


def integrate_abstractions_full(trace_path: str) -> IntegrationResult:
    """
    Full NAB integration with additional metadata.
    
    Args:
        trace_path: Path to IIN JSON trace file
        
    Returns:
        IntegrationResult with abstract values and metadata
    """
    path = Path(trace_path)
    if not path.exists():
        raise FileNotFoundError(f"Trace file not found: {trace_path}")
    
    with open(path, 'r') as f:
        trace_data = json.load(f)
    
    # Get method name
    method_name = trace_data.get("method", "unknown")
    
    # Extract samples
    samples_by_local = extract_samples_from_trace(trace_data)
    
    # Compute abstract values
    abstract_values = integrate_abstractions(trace_path)
    
    # Calculate confidence based on sample coverage
    confidence = _calculate_integration_confidence(trace_data, samples_by_local)
    
    # Count samples per local
    samples_count = {idx: len(samples) for idx, samples in samples_by_local.items()}
    
    return IntegrationResult(
        method_name=method_name,
        abstract_values=abstract_values,
        trace_path=str(trace_path),
        confidence=confidence,
        samples_count=samples_count
    )


def _calculate_integration_confidence(
    trace_data: Dict[str, Any], 
    samples: Dict[int, List[int]]
) -> float:
    """
    Calculate confidence score for the integration result.
    
    Higher confidence when:
    - More samples are observed
    - Better code coverage
    - Branch coverage is available
    """
    confidence = 0.5  # Base confidence
    
    # Boost for having samples
    if samples:
        total_samples = sum(len(s) for s in samples.values())
        sample_boost = min(0.2, total_samples * 0.02)
        confidence += sample_boost
    
    # Boost for coverage information
    if "coverage" in trace_data:
        coverage = trace_data["coverage"]
        executed = len(coverage.get("executed_pcs", []))
        uncovered = len(coverage.get("uncovered_pcs", []))
        total = executed + uncovered
        
        if total > 0:
            coverage_ratio = executed / total
            confidence += coverage_ratio * 0.2
        
        # Branch coverage boost
        if coverage.get("branches"):
            confidence += 0.1
    
    return min(0.95, confidence)


def integrate_all_traces(traces_dir: str = "traces") -> Dict[str, IntegrationResult]:
    """
    Integrate all trace files in a directory.
    
    Args:
        traces_dir: Directory containing IIN trace JSON files
        
    Returns:
        Dictionary mapping method names to IntegrationResult objects
    """
    traces_path = Path(traces_dir)
    if not traces_path.exists():
        return {}
    
    results = {}
    for trace_file in traces_path.glob("*.json"):
        try:
            result = integrate_abstractions_full(str(trace_file))
            results[result.method_name] = result
        except Exception as e:
            # Log error but continue with other files
            print(f"Warning: Failed to integrate {trace_file}: {e}")
    
    return results


def get_sign_for_local(trace_path: str, local_idx: int) -> SignValue:
    """
    Convenience function to get sign for a specific local variable.
    
    Args:
        trace_path: Path to IIN trace file
        local_idx: Local variable index
        
    Returns:
        SignValue for the local variable, or TOP if not found
    """
    abstract_values = integrate_abstractions(trace_path)
    
    if local_idx in abstract_values:
        return abstract_values[local_idx].sign.value
    
    return SignValue.TOP


def get_interval_for_local(trace_path: str, local_idx: int) -> IntervalValue:
    """
    Convenience function to get interval for a specific local variable.
    
    Args:
        trace_path: Path to IIN trace file
        local_idx: Local variable index
        
    Returns:
        IntervalValue for the local variable, or TOP if not found
    """
    abstract_values = integrate_abstractions(trace_path)
    
    if local_idx in abstract_values:
        return abstract_values[local_idx].interval.value
    
    return IntervalValue(None, None)  # TOP


# Proposal example implementation
def process_example() -> Dict[int, AbstractValue]:
    """
    Proposal example §1.3.1: process(int x) with samples [5, 10, ...]
    
    From proposal: "dynamic traces to set initial abstracts like x>0"
    
    When we observe positive samples [5, 10], we refine:
    - sign(x) = positive (SignValue.POSITIVE)
    - interval(x) = [5, 10]
    
    This is our dynamic refinement heuristic: using IIN traces to
    initialize abstract states for static analysis.
    """
    # Simulate the proposal example
    samples = [5, 10, 15, 20, 25]  # Positive samples from dynamic execution
    
    sign_domain, interval_domain = refine_from_trace(samples)
    
    return {
        1: AbstractValue(
            sign=sign_domain,
            interval=interval_domain,
            local_index=1
        )
    }


if __name__ == "__main__":
    # Demonstrate proposal example
    print("NAB Integration - Proposal Example §1.3.1")
    print("=" * 50)
    
    result = process_example()
    for local_idx, abstract_val in result.items():
        print(f"  {abstract_val}")
        print(f"    → sign = {abstract_val.sign.value.name}")
        print(f"    → interval = {abstract_val.interval}")
    
    print()
    print("Integrating actual traces from traces/ directory...")
    print("-" * 50)
    
    # Integrate actual traces
    all_results = integrate_all_traces("traces")
    
    for method_name, result in list(all_results.items())[:5]:  # Show first 5
        print(f"\n{method_name}:")
        for local_idx, abstract_val in result.abstract_values.items():
            print(f"  {abstract_val}")
