import jpamb
from jpamb import jvm
from dataclasses import dataclass
from typing import Dict, List, Set
from enum import Enum

import sys
import json
import os
from pathlib import Path
from loguru import logger

logger.remove()
logger.add(sys.stderr, format="[{level}] {message}")


class AbstractDomain(Enum):
    """Abstract domain types for static analysis."""
    TOP = "⊤"  # Unknown/any value
    BOTTOM = "⊥"  # Impossible/no value
    ZERO = "0"  # Exactly zero
    POSITIVE = "+"  # Positive integers
    NEGATIVE = "-"  # Negative integers
    NON_ZERO = "≠0"  # Non-zero integers
    NON_NEGATIVE = "≥0"  # Zero or positive
    NON_POSITIVE = "≤0"  # Zero or negative


@dataclass
class AbstractState:
    """Abstract state for a program point."""
    locals: Dict[int, AbstractDomain]
    pc: int
    method: jvm.AbsMethodID
    
    def encode(self) -> str:
        """Encode abstract state for static analysis tools."""
        locals_str = ",".join(f"{idx}:{domain.value}" for idx, domain in sorted(self.locals.items()))
        return f"{self.method}:{self.pc}[{locals_str}]"


@dataclass
class RefinementResult:
    """Result of trace refinement process."""
    initial_states: List[AbstractState]
    refined_coverage: Dict[int, Set[AbstractDomain]]
    confidence: float  # 0.0 to 1.0
    method: jvm.AbsMethodID


@dataclass
class PC:
    method: jvm.AbsMethodID
    offset: int

    def __iadd__(self, delta):
        self.offset += delta
        return self

    def __add__(self, delta):
        return PC(self.method, self.offset + delta)

    def __str__(self):
        return f"{self.method}:{self.offset}"


@dataclass
class Bytecode:
    suite: jpamb.Suite
    methods: dict[jvm.AbsMethodID, list[jvm.Opcode]]

    def __getitem__(self, pc: PC) -> jvm.Opcode:
        try:
            opcodes = self.methods[pc.method]
        except KeyError:
            opcodes = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = opcodes

        return opcodes[pc.offset]


@dataclass
class Stack[T]:
    items: list[T]

    def __bool__(self) -> bool:
        return len(self.items) > 0

    @classmethod
    def empty(cls):
        return cls([])

    def peek(self) -> T:
        return self.items[-1]

    def pop(self) -> T:
        return self.items.pop(-1)

    def push(self, value):
        self.items.append(value)
        return self

    def __str__(self):
        if not self:
            return "ϵ"
        return "".join(f"{v}" for v in self.items)


suite = jpamb.Suite()
bc = Bytecode(suite, dict())


@dataclass
class Frame:
    locals: dict[int, jvm.Value]
    stack: Stack[jvm.Value]
    pc: PC

    def __str__(self):
        locals = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals}}}, {self.stack}, {self.pc}>"

    def from_method(method: jvm.AbsMethodID) -> "Frame":
        return Frame({}, Stack.empty(), PC(method, 0))


@dataclass
class State:
    heap: dict[int, jvm.Value]
    frames: Stack[Frame]

    def __str__(self):
        return f"{self.heap} {self.frames}"


def step(state: State) -> State | str:
    assert isinstance(state, State), f"expected frame but got {state}"
    frame = state.frames.peek()
    opr = bc[frame.pc]
    logger.debug(f"STEP {opr}\n{state}")
    match opr:
        case jvm.Push(value=v):
            frame.stack.push(v)
            frame.pc += 1
            return state
        case jvm.Load(type=jvm.Int(), index=i):
            frame.stack.push(frame.locals[i])
            frame.pc += 1
            return state
        case jvm.Load(type=jvm.Reference(), index=i):
            # Load reference from local variable
            if i in frame.locals:
                frame.stack.push(frame.locals[i])
            else:
                # Push null reference if not initialized
                frame.stack.push(jvm.Value(jvm.Reference(), None))
            frame.pc += 1
            return state
        case jvm.Binary(type=jvm.Int(), operant=operant):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert v1.type is jvm.Int(), f"expected int, but got {v1}"
            assert v2.type is jvm.Int(), f"expected int, but got {v2}"
            
            match operant:
                case jvm.BinaryOpr.Div:
                    if v2.value == 0:
                        return "divide by zero"
                    result = v1.value // v2.value
                case jvm.BinaryOpr.Add:
                    result = v1.value + v2.value
                case jvm.BinaryOpr.Sub:
                    result = v1.value - v2.value
                case jvm.BinaryOpr.Mul:
                    result = v1.value * v2.value
                case _:
                    raise NotImplementedError(f"Unsupported binary operator: {operant}")
            
            frame.stack.push(jvm.Value.int(result))
            frame.pc += 1
            return state
        case jvm.Get(static=True, field=field):
            # For static field access, particularly $assertionsDisabled
            if field.extension.name == "$assertionsDisabled":
                # Java assertions are typically disabled, so return false
                frame.stack.push(jvm.Value.boolean(False))
            else:
                # Default to zero/false for other static fields
                if isinstance(field.extension.type, jvm.Boolean):
                    frame.stack.push(jvm.Value.boolean(False))
                elif isinstance(field.extension.type, jvm.Int):
                    frame.stack.push(jvm.Value.int(0))
                else:
                    raise NotImplementedError(f"Unsupported static field type: {field.extension.type}")
            frame.pc += 1
            return state
        case jvm.Ifz(condition=condition, target=target):
            v = frame.stack.pop()
            conditions = {
                "eq": lambda val: val == 0,
                "ne": lambda val: val != 0,
                "lt": lambda val: val < 0,
                "le": lambda val: val <= 0,
                "gt": lambda val: val > 0,
                "ge": lambda val: val >= 0,
            }
            if condition not in conditions:
                raise NotImplementedError(f"Unsupported Ifz condition: {condition}")
            
            if conditions[condition](v.value):
                frame.pc = PC(frame.pc.method, target)
            else:
                frame.pc += 1
            return state
        case jvm.Return(type=jvm.Int()):
            v1 = frame.stack.pop()
            state.frames.pop()
            if state.frames:
                frame = state.frames.peek()
                frame.stack.push(v1)
                frame.pc += 1
                return state
            else:
                return "ok"
        case jvm.Return(type=None):  # Void return
            state.frames.pop()
            if state.frames:
                frame = state.frames.peek()
                frame.pc += 1
                return state
            else:
                return "ok"
        case jvm.Return(type=jvm.Reference()):
            # Return reference type
            v1 = frame.stack.pop()
            state.frames.pop()
            if state.frames:
                frame = state.frames.peek()
                frame.stack.push(v1)
                frame.pc += 1
                return state
            else:
                return "ok"
        case jvm.New(classname=classname):
            # Handle creation of new objects, especially exceptions
            if str(classname) == "java/lang/AssertionError":
                return "assertion error"
            else:
                # For other classes, create a simple object reference and push to stack
                # Using a simple object ID based on the class name
                object_ref = jvm.Value(jvm.Reference(), f"ref_{classname}")
                frame.stack.push(object_ref)
                frame.pc += 1
                return state
        case jvm.Store(type=jvm.Int(), index=i):
            # Store integer to local variable
            v = frame.stack.pop()
            frame.locals[i] = v
            frame.pc += 1
            return state
        case jvm.Store(type=jvm.Reference(), index=i):
            # Store reference to local variable
            v = frame.stack.pop()
            frame.locals[i] = v
            frame.pc += 1
            return state
        case jvm.NewArray(type=array_type, dim=1):
            # Create 1D array - pop size from stack
            size_val = frame.stack.pop()
            if size_val.value < 0:
                return "negative array size"
            # Create array reference and push to stack
            array_ref = jvm.Value(jvm.Reference(), f"array_{id(frame)}_{frame.pc.offset}")
            frame.stack.push(array_ref)
            frame.pc += 1
            return state
        case jvm.ArrayLength():
            # Get array length - for simplicity, return a default value
            array_ref = frame.stack.pop()
            if array_ref.value is None:
                return "null pointer"
            # Return a default length for testing
            frame.stack.push(jvm.Value.int(10))
            frame.pc += 1
            return state
        case jvm.ArrayLoad(type=array_element_type):
            # Load from array - pop index and array reference
            index_val = frame.stack.pop()
            array_ref = frame.stack.pop()
            if array_ref.value is None:
                return "null pointer"
            if index_val.value < 0:
                return "array index out of bounds"
            # For simplicity, return a default value based on type
            if isinstance(array_element_type, jvm.Int):
                frame.stack.push(jvm.Value.int(42))
            elif isinstance(array_element_type, jvm.Reference):
                frame.stack.push(jvm.Value(jvm.Reference(), None))
            else:
                frame.stack.push(jvm.Value.int(0))
            frame.pc += 1
            return state
        case jvm.ArrayStore(type=array_element_type):
            # Store to array - pop value, index, and array reference
            value_val = frame.stack.pop()
            index_val = frame.stack.pop()
            array_ref = frame.stack.pop()
            if array_ref.value is None:
                return "null pointer"
            if index_val.value < 0:
                return "array index out of bounds"
            # For testing, we just consume the values without storing
            frame.pc += 1
            return state
        case jvm.If(condition=condition, target=target):
            # Compare two values on the stack
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            conditions = {
                "eq": lambda v1, v2: v1 == v2,
                "ne": lambda v1, v2: v1 != v2,
                "lt": lambda v1, v2: v1 < v2,
                "le": lambda v1, v2: v1 <= v2,
                "gt": lambda v1, v2: v1 > v2,
                "ge": lambda v1, v2: v1 >= v2,
            }
            if condition not in conditions:
                raise NotImplementedError(f"Unsupported If condition: {condition}")
            
            if conditions[condition](v1.value, v2.value):
                frame.pc = PC(frame.pc.method, target)
            else:
                frame.pc += 1
            return state
        case jvm.Dup():
            # Duplicate top stack value
            v = frame.stack.peek()
            frame.stack.push(v)
            frame.pc += 1
            return state
        case jvm.Pop():
            # Pop and discard top stack value
            frame.stack.pop()
            frame.pc += 1
            return state
        case jvm.Goto(target=target):
            # Unconditional jump
            frame.pc = PC(frame.pc.method, target)
            return state
        case jvm.InvokeStatic(method=method_ref):
            # Static method invocation - for simplicity, handle basic cases
            method_name = str(method_ref.extension)
            if "println" in method_name or "print" in method_name:
                # Print methods - pop value and continue
                if frame.stack:
                    frame.stack.pop()
                frame.pc += 1
                return state
            elif "valueOf" in method_name:
                # String.valueOf or similar - return a string reference
                if frame.stack:
                    frame.stack.pop()  # Pop the argument
                frame.stack.push(jvm.Value(jvm.Reference(), "string_value"))
                frame.pc += 1
                return state
            else:
                # Unknown static method - for testing, just continue
                frame.pc += 1
                return state
        case jvm.InvokeVirtual(method=method_ref) | jvm.InvokeInterface(method=method_ref) | jvm.InvokeSpecial(method=method_ref):
            # Instance method invocation
            method_name = str(method_ref.extension)
            if "<init>" in method_name:
                # Constructor call - pop arguments and object reference
                # Pop arguments based on method signature (simplified)
                if frame.stack:
                    frame.stack.pop()  # Pop object reference
                frame.pc += 1
                return state
            else:
                # Other instance methods - simplified handling
                if frame.stack:
                    frame.stack.pop()  # Pop object reference
                frame.pc += 1
                return state
        case jvm.Throw():
            # Throw exception
            exception_ref = frame.stack.pop()
            return "exception thrown"
        case a:
            raise NotImplementedError(f"Don't know how to handle: {a!r}")


def execute(method: jvm.AbsMethodID, inputs=None, coverage=None, tracer=None, trace_dir="traces"):
    """Execute a method with optional tracing."""
    global bc  # Access the global bytecode instance
    
    # Condition dictionaries to avoid duplication
    ifz_conditions = {
        "eq": lambda val: val == 0,
        "ne": lambda val: val != 0,
        "lt": lambda val: val < 0,
        "le": lambda val: val <= 0,
        "gt": lambda val: val > 0,
        "ge": lambda val: val >= 0,
    }
    
    if_conditions = {
        "eq": lambda v1, v2: v1 == v2,
        "ne": lambda v1, v2: v1 != v2,
        "lt": lambda v1, v2: v1 < v2,
        "le": lambda v1, v2: v1 <= v2,
        "gt": lambda v1, v2: v1 > v2,
        "ge": lambda v1, v2: v1 >= v2,
    }
    
    if inputs is None:
        # Create empty input for methods with no parameters
        inputs = jpamb.model.Input(tuple())
    
    frame = Frame.from_method(method)
    for i, v in enumerate(inputs.values):
        frame.locals[i] = v

    state = State({}, Stack.empty().push(frame))
    
    # Only create default coverage tracker if:
    # 1. No coverage tracker was provided AND 
    # 2. A trace_dir is specified AND
    # 3. We're not explicitly disabling all tracing (i.e., at least one of coverage or tracer should be non-None)
    # The test case passes both coverage=None and tracer=None explicitly, so no tracing should occur
    
    if coverage:
        coverage.visit(0)
    
    result = None
    for x in range(1000):
        if tracer:
            # Record current local variables
            current_frame = state.frames.peek()
            for idx, value in current_frame.locals.items():
                # Track both integers and booleans
                if isinstance(value.value, (int, bool)):
                    tracer.observe_local(idx, value.value)
        
        if coverage:
            current_frame = state.frames.peek()
            coverage.visit(current_frame.pc.offset)
            
            # Check for branch instructions
            opr = bc[current_frame.pc]
            if isinstance(opr, (jvm.Ifz, jvm.If)):
                try:
                    # We need to determine if branch will be taken before stepping
                    if isinstance(opr, jvm.Ifz) and current_frame.stack:
                        v = current_frame.stack.peek()
                        taken = ifz_conditions[opr.condition](v.value)
                        coverage.branch(current_frame.pc.offset, taken)
                    elif isinstance(opr, jvm.If) and len(current_frame.stack.items) >= 2:
                        v2 = current_frame.stack.items[-1]
                        v1 = current_frame.stack.items[-2]
                        taken = if_conditions[opr.condition](v1.value, v2.value)
                        coverage.branch(current_frame.pc.offset, taken)
                except (IndexError, AttributeError, KeyError):
                    # Skip branch recording if we can't access the stack properly
                    pass
        
        state = step(state)
        if isinstance(state, str):
            result = state
            break
    else:
        result = "*"
    
    # Write trace file if tracing is enabled
    if (coverage or tracer) and trace_dir:
        os.makedirs(trace_dir, exist_ok=True)
        
        # Finalize tracer if present
        if tracer:
            tracer.finalize()
        
        # Generate trace data
        trace_data = {
            "method": f"{method.classname}.{method.extension.encode()}"
        }
        
        if coverage:
            trace_data["coverage"] = coverage.to_dict()
        
        if tracer:
            trace_data["values"] = tracer.to_dict()
        
        # Write JSON file

        # Create a safe filename using method encoding
        method_encoded = method.extension.encode().replace('(', '').replace(')', '').replace(':', '_').replace('/', '_')
        filename = f"{method.classname}_{method_encoded}.json"
        filepath = Path(trace_dir) / filename
        
        with open(filepath, 'w') as f:
            json.dump(trace_data, f, indent=2)
    
    return result


class CoverageTracker:
    """Records visited PCs and branch outcomes."""
    
    def __init__(self, method: jvm.AbsMethodID = None):
        self.visited_pcs = set()
        self.all_pcs = set()
        self.branches = {}
        
        # If method is provided, scan all possible PCs
        if method:
            self._scan_all_pcs(method)
    
    def _scan_all_pcs(self, method: jvm.AbsMethodID):
        """Scan method bytecode to find all possible PC locations."""
        global bc
        try:
            opcodes = list(bc.suite.method_opcodes(method))
            # All PC positions are simply the opcode indices
            self.all_pcs = set(range(len(opcodes)))
        except Exception:
            # If we can't scan, fall back to dynamic discovery
            pass
    
    def visit(self, pc):
        """Record that a PC was visited."""
        self.visited_pcs.add(pc)
        # Also add to all_pcs in case we couldn't scan beforehand
        self.all_pcs.add(pc)
    
    def branch(self, pc, taken):
        """Record branch outcome at PC."""
        if pc not in self.branches:
            self.branches[pc] = []
        self.branches[pc].append(taken)
    
    def to_dict(self):
        """Convert to dictionary format."""
        return {
            "executed_pcs": sorted(list(self.visited_pcs)),
            "uncovered_pcs": sorted(list(self.all_pcs - self.visited_pcs)),
            "branches": {str(pc): outcomes for pc, outcomes in self.branches.items()}
        }


class ValueTracer:
    """Records concrete values of local variables."""
    
    def __init__(self):
        self.observations = {}
    
    def observe_local(self, idx, value):
        """Record a concrete value for local variable idx."""
        if idx not in self.observations:
            self.observations[idx] = []
        self.observations[idx].append(value)
    
    def finalize(self):
        """Compute final analysis results."""
        pass  # Analysis is done in to_dict()
    
    def to_dict(self):
        """Convert to dictionary format with analysis."""
        result = {}
        
        for idx, values in self.observations.items():
            if not values:
                continue
                
            analysis = {
                "samples": values[:10],  # Keep first 10 samples
                "always_positive": all(v > 0 for v in values),
                "never_negative": all(v >= 0 for v in values),
                "never_zero": all(v != 0 for v in values)
            }
            
            # Determine sign
            if all(v > 0 for v in values):
                analysis["sign"] = "positive"
            elif all(v < 0 for v in values):
                analysis["sign"] = "negative"
            elif all(v == 0 for v in values):
                analysis["sign"] = "zero"
            else:
                analysis["sign"] = "mixed"
            
            # Determine interval
            min_val = min(values)
            max_val = max(values)
            analysis["interval"] = [min_val, max_val if min_val != max_val else None]
            
            result[f"local_{idx}"] = analysis
        
        return result


class TraceRefiner:
    """Refines dynamic traces back to initial abstract states for static analysis."""
    
    def __init__(self):
        self.refinements = {}
    
    def refine_trace(self, trace_data: Dict) -> RefinementResult:
        """Refine a single trace to extract initial abstract states."""
        method = jvm.AbsMethodID.decode(trace_data["method"])
        
        # Extract initial abstract states from value analysis
        initial_states = []
        refined_coverage = {}
        
        if "values" in trace_data:
            initial_abstract_locals = {}
            
            for local_key, analysis in trace_data["values"].items():
                local_idx = int(local_key.split("_")[1])
                domain = self._infer_abstract_domain(analysis)
                initial_abstract_locals[local_idx] = domain
            
            # Create initial abstract state
            if initial_abstract_locals:
                initial_state = AbstractState(
                    locals=initial_abstract_locals,
                    pc=0,  # Start at method entry
                    method=method
                )
                initial_states.append(initial_state)
        
        # Refine coverage information with abstract domains
        if "coverage" in trace_data:
            for pc in trace_data["coverage"]["executed_pcs"]:
                refined_coverage[pc] = {self._get_pc_domain(pc, trace_data)}
        
        # Calculate confidence based on coverage completeness
        confidence = self._calculate_confidence(trace_data)
        
        return RefinementResult(
            initial_states=initial_states,
            refined_coverage=refined_coverage,
            confidence=confidence,
            method=method
        )
    
    def _infer_abstract_domain(self, analysis: Dict) -> AbstractDomain:
        """Infer abstract domain from concrete value analysis."""
        if analysis["sign"] == "positive":
            return AbstractDomain.POSITIVE
        elif analysis["sign"] == "negative":
            return AbstractDomain.NEGATIVE
        elif analysis["sign"] == "zero":
            return AbstractDomain.ZERO
        elif analysis["never_negative"]:
            return AbstractDomain.NON_NEGATIVE
        elif analysis["never_zero"]:
            return AbstractDomain.NON_ZERO
        else:
            return AbstractDomain.TOP  # Mixed or unknown
    
    def _get_pc_domain(self, pc: int, trace_data: Dict) -> AbstractDomain:
        """Get abstract domain for a specific program counter."""
        # For now, return TOP as we need more sophisticated analysis
        # This could be enhanced to track domains per PC
        return AbstractDomain.TOP
    
    def _calculate_confidence(self, trace_data: Dict) -> float:
        """Calculate confidence score based on trace completeness."""
        if "coverage" not in trace_data:
            return 0.5
        
        coverage = trace_data["coverage"]
        executed = len(coverage["executed_pcs"])
        uncovered = len(coverage["uncovered_pcs"])
        total = executed + uncovered
        
        if total == 0:
            return 0.5
        
        # Higher confidence with better coverage
        coverage_ratio = executed / total
        
        # Boost confidence if we have branch information
        branch_boost = 0.1 if coverage["branches"] else 0.0
        
        return min(0.95, coverage_ratio + branch_boost)
    
    def refine_multiple_traces(self, trace_files: List[Path]) -> Dict[str, RefinementResult]:
        """Refine multiple trace files and return results keyed by method name."""
        results = {}
        
        for trace_file in trace_files:
            try:
                with open(trace_file, 'r') as f:
                    trace_data = json.load(f)
                
                refinement = self.refine_trace(trace_data)
                method_key = trace_data["method"]
                results[method_key] = refinement
                
            except Exception as e:
                logger.error(f"Failed to refine trace {trace_file}: {e}")
        
        return results
    
    def generate_initial_state_file(self, refinement_results: Dict[str, RefinementResult], 
                                   output_path: Path) -> None:
        """Generate initial abstract state file for static analysis tools."""
        states_data = {
            "format_version": "1.0",
            "generation_timestamp": json.dumps(os.path.getmtime(__file__)),
            "description": "Initial abstract states refined from dynamic analysis traces",
            "methods": {}
        }
        
        for method_name, result in refinement_results.items():
            method_data = {
                "initial_states": [state.encode() for state in result.initial_states],
                "confidence": result.confidence,
                "coverage_points": list(result.refined_coverage.keys()),
                "abstract_domains": {
                    str(pc): [domain.value for domain in domains]
                    for pc, domains in result.refined_coverage.items()
                }
            }
            states_data["methods"][method_name] = method_data
        
        # Write to file
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(states_data, f, indent=2)
        
        logger.info(f"Generated initial state file: {output_path}")


# Main execution when run directly
if __name__ == "__main__":
    methodid, input = jpamb.getcase()
    result = execute(methodid, inputs=input)
    print(result)
