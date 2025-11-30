#!/usr/bin/env python3
"""
Dynamic Profiler - Execute methods with sample inputs to gather runtime information.

This module provides dynamic profiling capabilities:
- Generate sample inputs for methods
- Execute with coverage tracking
- Record value ranges for variables
- Identify hot/cold code paths

IMPORTANT: Dynamic profiling is UNSOUND for dead code detection!
Just because code wasn't executed doesn't mean it's dead.
This data should only be used for:
- Providing hints/confidence levels
- Identifying optimization opportunities
- Supplementing static analysis results
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path

import jpamb
from jpamb import jvm

log = logging.getLogger(__name__)


@dataclass
class CoverageData:
    """Coverage data from dynamic execution."""
    executed_indices: Set[int] = field(default_factory=set)  # Instruction indices that were executed
    all_indices: Set[int] = field(default_factory=set)  # All instruction indices in method
    branch_outcomes: Dict[int, List[bool]] = field(default_factory=dict)  # index -> [taken/not taken]
    execution_count: Dict[int, int] = field(default_factory=dict)  # index -> count
    
    def get_coverage_percentage(self) -> float:
        """Calculate percentage of instructions covered."""
        if not self.all_indices:
            return 0.0
        return (len(self.executed_indices) / len(self.all_indices)) * 100.0
    
    def get_uncovered_indices(self) -> Set[int]:
        """Get instruction indices that were never executed."""
        return self.all_indices - self.executed_indices
    
    def get_cold_indices(self, threshold: int = 1) -> Set[int]:
        """Get indices executed fewer than threshold times."""
        cold = set()
        for idx in self.all_indices:
            if self.execution_count.get(idx, 0) <= threshold:
                cold.add(idx)
        return cold


@dataclass
class ValueRangeData:
    """Observed value ranges for variables."""
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    observed_values: List[int] = field(default_factory=list)
    sample_count: int = 0
    
    def record(self, value: int):
        """Record an observed value."""
        self.sample_count += 1
        if len(self.observed_values) < 100:  # Keep first 100 samples
            self.observed_values.append(value)
        
        if self.min_value is None or value < self.min_value:
            self.min_value = value
        if self.max_value is None or value > self.max_value:
            self.max_value = value
    
    def get_range(self) -> Tuple[Optional[int], Optional[int]]:
        """Get observed [min, max] range."""
        return (self.min_value, self.max_value)
    
    def is_always_positive(self) -> bool:
        return self.min_value is not None and self.min_value > 0
    
    def is_never_negative(self) -> bool:
        return self.min_value is not None and self.min_value >= 0
    
    def is_never_zero(self) -> bool:
        return 0 not in self.observed_values and self.sample_count > 0


@dataclass
class MethodProfile:
    """Complete profile for a single method."""
    method_id: jvm.AbsMethodID
    coverage: CoverageData = field(default_factory=CoverageData)
    local_ranges: Dict[int, ValueRangeData] = field(default_factory=dict)  # local_idx -> ranges
    stack_ranges: Dict[int, ValueRangeData] = field(default_factory=dict)  # pc -> top-of-stack range
    execution_count: int = 0
    outcomes: List[str] = field(default_factory=list)  # Results like "ok", "divide by zero", etc.
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "method": str(self.method_id),
            "execution_count": self.execution_count,
            "coverage_percentage": self.coverage.get_coverage_percentage(),
            "executed_indices": sorted(list(self.coverage.executed_indices)),
            "uncovered_indices": sorted(list(self.coverage.get_uncovered_indices())),
            "hot_spots": self._get_hot_spots(),
            "cold_spots": sorted(list(self.coverage.get_cold_indices())),
            "local_ranges": {
                str(idx): {
                    "min": data.min_value,
                    "max": data.max_value,
                    "samples": data.observed_values[:10],
                    "always_positive": data.is_always_positive(),
                    "never_negative": data.is_never_negative(),
                    "never_zero": data.is_never_zero(),
                }
                for idx, data in self.local_ranges.items()
            },
            "outcomes": self.outcomes,
            "branch_coverage": self._get_branch_coverage(),
        }
    
    def _get_hot_spots(self, threshold: int = 10) -> List[int]:
        """Get indices executed more than threshold times."""
        return sorted([
            idx for idx, count in self.coverage.execution_count.items()
            if count > threshold
        ])
    
    def _get_branch_coverage(self) -> dict:
        """Analyze branch coverage."""
        result = {}
        for idx, outcomes in self.coverage.branch_outcomes.items():
            taken = sum(outcomes)
            not_taken = len(outcomes) - taken
            result[str(idx)] = {
                "taken": taken,
                "not_taken": not_taken,
                "both_covered": taken > 0 and not_taken > 0,
            }
        return result


@dataclass
class ProfilingResult:
    """Aggregate profiling results for a class."""
    classname: jvm.ClassName
    method_profiles: Dict[str, MethodProfile] = field(default_factory=dict)
    total_executions: int = 0
    errors: List[str] = field(default_factory=list)
    
    def get_uncovered_code_hints(self) -> Dict[str, Set[int]]:
        """
        Get hints about potentially uncovered code.
        
        WARNING: This is NOT proof of dead code! Just hints based on
        dynamic execution which may not have covered all paths.
        """
        hints = {}
        for method_name, profile in self.method_profiles.items():
            uncovered = profile.coverage.get_uncovered_indices()
            if uncovered:
                hints[method_name] = uncovered
        return hints
    
    def get_value_range_hints(self) -> Dict[str, Dict[int, Tuple[int, int]]]:
        """Get observed value ranges for each method's locals."""
        hints = {}
        for method_name, profile in self.method_profiles.items():
            if profile.local_ranges:
                hints[method_name] = {
                    idx: data.get_range()
                    for idx, data in profile.local_ranges.items()
                }
        return hints
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "class": str(self.classname),
            "total_executions": self.total_executions,
            "methods": {
                name: profile.to_dict()
                for name, profile in self.method_profiles.items()
            },
            "errors": self.errors,
            "summary": {
                "methods_profiled": len(self.method_profiles),
                "average_coverage": self._get_average_coverage(),
            }
        }
    
    def _get_average_coverage(self) -> float:
        """Calculate average coverage across all methods."""
        if not self.method_profiles:
            return 0.0
        coverages = [p.coverage.get_coverage_percentage() for p in self.method_profiles.values()]
        return sum(coverages) / len(coverages)


class InputGenerator:
    """Generates sample inputs for method parameters."""
    
    # Default sample values for different types
    INT_SAMPLES = [0, 1, -1, 2, -2, 5, 10, -10, 100, -100, 1000, 
                   2147483647, -2147483648]  # Include edge cases
    BOOL_SAMPLES = [True, False]
    
    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)
        self.rng = random.Random(seed)
    
    def generate_inputs(self, params: jvm.ParameterType, 
                       num_samples: int = 20) -> List[jpamb.model.Input]:
        """Generate sample inputs for a method's parameters."""
        inputs = []
        
        # Generate systematic samples first
        systematic = self._generate_systematic(params)
        inputs.extend(systematic[:num_samples])
        
        # Add random samples if needed
        while len(inputs) < num_samples:
            random_input = self._generate_random(params)
            if random_input:
                inputs.append(random_input)
        
        return inputs[:num_samples]
    
    def _generate_systematic(self, params: jvm.ParameterType) -> List[jpamb.model.Input]:
        """Generate systematic test inputs."""
        # ParameterType is iterable and has len()
        param_list = list(params)  # Convert to list for easier access
        
        if not param_list:
            return [jpamb.model.Input(tuple())]
        
        # For now, handle common cases
        inputs = []
        
        # Single int parameter
        if len(param_list) == 1 and isinstance(param_list[0], jvm.Int):
            for val in self.INT_SAMPLES:
                inputs.append(jpamb.model.Input((jvm.Value.int(val),)))
        
        # Two int parameters
        elif len(param_list) == 2 and all(isinstance(t, jvm.Int) for t in param_list):
            # Combine interesting values
            for v1 in self.INT_SAMPLES[:7]:
                for v2 in self.INT_SAMPLES[:7]:
                    inputs.append(jpamb.model.Input((jvm.Value.int(v1), jvm.Value.int(v2))))
        
        # Three int parameters
        elif len(param_list) == 3 and all(isinstance(t, jvm.Int) for t in param_list):
            for v1 in self.INT_SAMPLES[:5]:
                for v2 in self.INT_SAMPLES[:5]:
                    for v3 in self.INT_SAMPLES[:5]:
                        inputs.append(jpamb.model.Input((
                            jvm.Value.int(v1), jvm.Value.int(v2), jvm.Value.int(v3)
                        )))
        
        # Boolean parameter
        elif len(param_list) == 1 and isinstance(param_list[0], jvm.Boolean):
            for val in self.BOOL_SAMPLES:
                inputs.append(jpamb.model.Input((jvm.Value.boolean(val),)))
        
        # No parameters
        elif len(param_list) == 0:
            inputs.append(jpamb.model.Input(tuple()))
        
        return inputs
    
    def _generate_random(self, params: jvm.ParameterType) -> Optional[jpamb.model.Input]:
        """Generate a random input."""
        param_list = list(params)
        
        if not param_list:
            return jpamb.model.Input(tuple())
        
        values = []
        for param_type in param_list:
            if isinstance(param_type, jvm.Int):
                # Mix of small and large random values
                if self.rng.random() < 0.7:
                    val = self.rng.randint(-1000, 1000)
                else:
                    val = self.rng.randint(-2147483648, 2147483647)
                values.append(jvm.Value.int(val))
            elif isinstance(param_type, jvm.Boolean):
                values.append(jvm.Value.boolean(self.rng.choice([True, False])))
            else:
                # Unsupported type
                return None
        
        return jpamb.model.Input(tuple(values))


class DynamicProfiler:
    """
    Execute methods with sample inputs and collect runtime profiles.
    
    IMPORTANT: Results from dynamic profiling are UNSOUND for dead code detection!
    Use only for hints, confidence levels, and optimization guidance.
    """
    
    def __init__(self, suite: jpamb.Suite, 
                 num_samples: int = 20,
                 max_steps: int = 1000,
                 seed: Optional[int] = 42):
        """
        Initialize the dynamic profiler.
        
        Args:
            suite: JPAMB Suite for bytecode access
            num_samples: Number of sample inputs to generate per method
            max_steps: Maximum execution steps before timeout
            seed: Random seed for reproducibility
        """
        self.suite = suite
        self.num_samples = num_samples
        self.max_steps = max_steps
        self.input_generator = InputGenerator(seed)
    
    def profile_class(self, classname: jvm.ClassName) -> ProfilingResult:
        """
        Profile all methods in a class.
        
        Args:
            classname: The class to profile
            
        Returns:
            ProfilingResult with coverage and value range data
        """
        result = ProfilingResult(classname=classname)
        
        try:
            cls = self.suite.findclass(classname)
            methods = cls.get("methods", [])
            
            for method_dict in methods:
                method_name = method_dict.get("name", "<unknown>")
                
                # Skip constructors and static initializers
                if method_name in ("<init>", "<clinit>"):
                    continue
                
                # Skip methods without code
                code = method_dict.get("code")
                if not code:
                    continue
                
                try:
                    profile = self._profile_method(classname, method_dict)
                    if profile:
                        full_name = f"{classname}.{method_name}"
                        result.method_profiles[full_name] = profile
                        result.total_executions += profile.execution_count
                except Exception as e:
                    result.errors.append(f"{method_name}: {str(e)}")
                    log.debug(f"Error profiling {method_name}: {e}")
        
        except Exception as e:
            result.errors.append(f"Class loading error: {str(e)}")
            log.warning(f"Failed to profile class {classname}: {e}")
        
        return result
    
    def _profile_method(self, classname: jvm.ClassName, 
                        method_dict: dict) -> Optional[MethodProfile]:
        """Profile a single method with multiple sample inputs."""
        method_name = method_dict.get("name", "<unknown>")
        code = method_dict.get("code", {})
        bytecode = code.get("bytecode", [])
        
        if not bytecode:
            return None
        
        # Build method ID
        try:
            params = jvm.ParameterType.from_json(
                method_dict.get("params", []), annotated=True
            )
            returns_info = method_dict.get("returns", {})
            return_type_json = returns_info.get("type")
            return_type = jvm.Type.from_json(return_type_json) if return_type_json else None
            
            method_id = jvm.MethodID(name=method_name, params=params, return_type=return_type)
            abs_method = jvm.AbsMethodID(classname=classname, extension=method_id)
        except Exception as e:
            log.debug(f"Could not build method ID for {method_name}: {e}")
            return None
        
        # Initialize profile
        profile = MethodProfile(method_id=abs_method)
        profile.coverage.all_indices = set(range(len(bytecode)))
        
        # Generate sample inputs
        inputs = self.input_generator.generate_inputs(params, self.num_samples)
        
        # Execute with each input
        for input_data in inputs:
            try:
                self._execute_and_record(abs_method, input_data, profile, bytecode)
                profile.execution_count += 1
            except Exception as e:
                log.debug(f"Execution error for {method_name}: {e}")
                # Record the error as an outcome
                profile.outcomes.append(f"error: {type(e).__name__}")
        
        return profile
    
    def _execute_and_record(self, method_id: jvm.AbsMethodID,
                            input_data: jpamb.model.Input,
                            profile: MethodProfile,
                            bytecode: list):
        """Execute method and record coverage/values."""
        # Import here to avoid circular imports
        from interpreter import Frame, State, Stack, PC, Bytecode, step, suite as global_suite, bc as global_bc, logger as interp_logger
        
        # Temporarily disable debug logging during execution
        interp_logger.disable("")
        
        try:
            # Create execution frame
            frame = Frame.from_method(method_id)
            for i, v in enumerate(input_data.values):
                frame.locals[i] = v
                # Record initial parameter values
                if isinstance(v.value, int):
                    if i not in profile.local_ranges:
                        profile.local_ranges[i] = ValueRangeData()
                    profile.local_ranges[i].record(v.value)
            
            state = State({}, Stack.empty().push(frame))
            
            # Execute with step limit
            for step_count in range(self.max_steps):
                current_frame = state.frames.peek()
                pc_index = current_frame.pc.offset  # This is actually the instruction index
                
                # Record coverage
                profile.coverage.executed_indices.add(pc_index)
                profile.coverage.execution_count[pc_index] = \
                    profile.coverage.execution_count.get(pc_index, 0) + 1
                
                # Record local variable values
                for idx, value in current_frame.locals.items():
                    if isinstance(value.value, int):
                        if idx not in profile.local_ranges:
                            profile.local_ranges[idx] = ValueRangeData()
                        profile.local_ranges[idx].record(value.value)
                
                # Get current instruction for branch tracking
                try:
                    opr = global_bc[current_frame.pc]
                    
                    # Track branch decisions
                    if hasattr(opr, 'condition') and hasattr(opr, 'target'):
                        # This is a branch instruction - we'll record after step
                        old_pc = current_frame.pc.offset
                except Exception:
                    pass
                
                # Take a step
                result = step(state)
                
                if isinstance(result, str):
                    # Execution terminated
                    profile.outcomes.append(result)
                    break
                
                state = result
            else:
                # Hit step limit (infinite loop)
                profile.outcomes.append("*")
        finally:
            # Re-enable logging
            interp_logger.enable("")
    
    def profile_method_with_inputs(self, method_id: jvm.AbsMethodID,
                                   inputs: List[jpamb.model.Input]) -> MethodProfile:
        """
        Profile a specific method with given inputs.
        
        Args:
            method_id: The method to profile
            inputs: List of inputs to use
            
        Returns:
            MethodProfile with coverage and value data
        """
        method_dict = self.suite.findmethod(method_id)
        bytecode = method_dict.get("code", {}).get("bytecode", [])
        
        profile = MethodProfile(method_id=method_id)
        profile.coverage.all_indices = set(range(len(bytecode)))
        
        for input_data in inputs:
            try:
                self._execute_and_record(method_id, input_data, profile, bytecode)
                profile.execution_count += 1
            except Exception as e:
                profile.outcomes.append(f"error: {type(e).__name__}")
        
        return profile


def print_profiling_report(result: ProfilingResult):
    """Print a human-readable profiling report."""
    print("\n" + "=" * 70)
    print("DYNAMIC PROFILING REPORT")
    print("=" * 70)
    print("\n⚠️  WARNING: Dynamic profiling is UNSOUND for dead code detection!")
    print("    Results are hints only - code not executed may still be reachable.\n")
    
    print(f"Class: {result.classname}")
    print(f"Total executions: {result.total_executions}")
    print(f"Methods profiled: {len(result.method_profiles)}")
    print(f"Average coverage: {result._get_average_coverage():.1f}%")
    
    if result.errors:
        print(f"\n❌ Errors ({len(result.errors)}):")
        for error in result.errors[:5]:
            print(f"  - {error}")
        if len(result.errors) > 5:
            print(f"  ... and {len(result.errors) - 5} more")
    
    print("\n" + "-" * 70)
    print("METHOD DETAILS")
    print("-" * 70)
    
    for method_name, profile in sorted(result.method_profiles.items()):
        coverage_pct = profile.coverage.get_coverage_percentage()
        uncovered = len(profile.coverage.get_uncovered_indices())
        
        status = "✅" if coverage_pct == 100 else "⚠️" if coverage_pct >= 80 else "❌"
        print(f"\n{status} {method_name}")
        print(f"   Coverage: {coverage_pct:.1f}% ({uncovered} indices not executed)")
        print(f"   Executions: {profile.execution_count}")
        
        # Show outcomes
        outcome_counts = {}
        for outcome in profile.outcomes:
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        if outcome_counts:
            outcomes_str = ", ".join(f"{k}: {v}" for k, v in sorted(outcome_counts.items()))
            print(f"   Outcomes: {outcomes_str}")
        
        # Show value ranges for parameters
        if profile.local_ranges:
            print(f"   Value ranges:")
            for idx in sorted(profile.local_ranges.keys())[:5]:  # First 5 locals
                data = profile.local_ranges[idx]
                range_str = f"[{data.min_value}, {data.max_value}]"
                hints = []
                if data.is_always_positive():
                    hints.append("always >0")
                if data.is_never_negative():
                    hints.append("never <0")
                if data.is_never_zero():
                    hints.append("never 0")
                hint_str = f" ({', '.join(hints)})" if hints else ""
                print(f"     local_{idx}: {range_str}{hint_str}")
        
        # Show uncovered indices
        uncovered_indices = profile.coverage.get_uncovered_indices()
        if uncovered_indices and len(uncovered_indices) <= 10:
            print(f"   ⚠️ Not executed: indices {sorted(uncovered_indices)}")
        elif uncovered_indices:
            print(f"   ⚠️ Not executed: {len(uncovered_indices)} indices")
    
    print("\n" + "=" * 70)

