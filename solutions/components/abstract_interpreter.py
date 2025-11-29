# solutions/abstract_interpreter.py
from __future__ import annotations

from typing import Dict, Iterable, Tuple, TYPE_CHECKING

import jpamb
from jpamb import jvm

from solutions.components.abstract_domain import (
    SignSet, SignArithmetic,
    IntervalDomain, IntervalArithmetic,
    NonNullDomain,
)
from solutions.components.abstract_state import Bytecode, PC, PerVarFrame, Stack
from dataclasses import dataclass

# Type hints for ISY module (avoid circular imports)
if TYPE_CHECKING:
    from solutions.ir import MethodIR, CFGNode
    from solutions.nab_integration import ReducedProductState


def _name(obj: object) -> str:
    n = getattr(obj, "name", None)
    return n.lower() if isinstance(n, str) else str(obj).lower()


def _eval_zero_compare(cond: object | None, v: SignSet) -> set[bool]:
    """
    Evaluate a zero comparison against a SignSet.

    Returns the set of booleans that are *possible* at runtime.
    """
    if cond is None:
        return {True, False}

    cname = _name(cond)
    out: set[bool] = set()

    # If v is ⊥ we treat it as “unknown” here, both branches possible
    for s in v.signs or {"+", "0", "-"}:
        if "eq" in cname:
            out.add(s == "0")
        elif "ne" in cname:
            out.add(s != "0")
        elif "lt" in cname:
            out.add(s == "-")
        elif "le" in cname:
            out.add(s in {"-", "0"})
        elif "gt" in cname:
            out.add(s == "+")
        elif "ge" in cname:
            out.add(s in {"+", "0"})
        else:
            # Unknown condition object, conservative
            return {True, False}

    return out or {True, False}



def astep(
    bc: Bytecode,
    frame: PerVarFrame[SignSet],
) -> Iterable[PerVarFrame[SignSet] | str]:
    """
    One abstract step from a single abstract frame.

    Yields successor frames and/or final outcome strings:

        "ok",
        "divide by zero",
        "null pointer",
        "out of bounds",
        "assertion error"

    This function is side‑effect free on the input frame, so it can be
    safely reused by the unbounded (fixpoint) analysis.
    """
    pc = frame.pc
    try:
        op = bc[pc]
    except IndexError:
        # Stepping into nowhere terminates this path silently
        return

    tname = type(op).__name__

    # ---------- PUSH ----------
    if tname == "Push":
        n = frame.copy()
        v = getattr(op, "value", None)
        inner = getattr(v, "value", None)  # jpamb may wrap constants

        if isinstance(v, int):
            n.stack.push(SignSet.const(v))
        elif isinstance(inner, int):
            n.stack.push(SignSet.const(int(inner)))
        else:
            # Non‑integral constants are abstracted as ⊤ in the sign domain
            n.stack.push(SignSet.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- LOAD ----------
    if tname == "Load":
        n = frame.copy()
        idx = int(getattr(op, "index", 0))
        n.stack.push(n.locals.get(idx, SignSet.top()))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- STORE ----------
    if tname == "Store":
        n = frame.copy()
        idx = int(getattr(op, "index", 0))
        val = n.stack.pop() if n.stack else SignSet.top()
        n.locals[idx] = val

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- INCR (iinc) ----------
    if tname == "Incr":
        n = frame.copy()
        idx = int(getattr(op, "index", getattr(op, "var", 0)))
        delta = int(getattr(op, "value", getattr(op, "amount", getattr(op, "delta", 0))))
        base = n.locals.get(idx, SignSet.top())
        n.locals[idx] = SignArithmetic.add(base, SignSet.const(delta))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- CAST ----------
    if tname == "Cast":
        n = frame.copy()
        val = n.stack.pop() if n.stack else SignSet.top()
        # Cast opcode uses to_ (with underscore)
        to_ty = getattr(op, "to_", getattr(op, "type", getattr(op, "to", None)))

        # Int cast: keep the same sign info
        if isinstance(to_ty, jvm.Int):
            out = val
        # Boolean cast: concrete values are 0 or 1, so signs ⊆ {0,+}
        elif isinstance(to_ty, jvm.Boolean):
            zero = "0" in val.signs
            truthy = any(s != "0" for s in val.signs) or val.is_top()
            signs: set[str] = set()
            if zero:
                signs.add("0")
            if truthy:
                signs.add("+")
            out = SignSet(frozenset(signs)) if signs else SignSet.top()
        # Double/Float casts: preserve sign information
        elif isinstance(to_ty, (jvm.Double, jvm.Float)):
            out = val  # Sign is preserved through floating point conversion
        else:
            # Other casts are irrelevant to the sign domain
            out = SignSet.top()

        n.stack.push(out)
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- NEGATE ----------
    if tname == "Negate":
        n = frame.copy()
        v = n.stack.pop() if n.stack else SignSet.top()
        n.stack.push(SignArithmetic.neg(v))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- BINARY ----------
    if tname == "Binary":
        n = frame.copy()

        # Ensure stack height consistent with the JVM verifier
        while len(n.stack) < 2:
            n.stack.push(SignSet.top())

        right = n.stack.pop()
        left = n.stack.pop()
        kind = _name(getattr(op, "operant", None))

        # Helper flags for division / remainder.
        right_definitely_zero = right.signs == {"0"}

        if "add" in kind:
            n.stack.push(SignArithmetic.add(left, right))

        elif "sub" in kind:
            n.stack.push(SignArithmetic.sub(left, right))

        elif "mul" in kind:
            n.stack.push(SignArithmetic.mul(left, right))

        elif "div" in kind:
            res, dz = SignArithmetic.div(left, right)
            if dz:
                # Always report potential division by zero
                yield "divide by zero"
            # Only keep the normal successor if there is a non‑exceptional case
            if not right_definitely_zero and res:
                n.stack.push(res)
                nxt = bc.next_pc(pc)
                if nxt is not None:
                    yield n.with_pc(nxt)
            return

        elif "rem" in kind:
            # For remainder we treat “b == 0” like division
            if right_definitely_zero:
                yield "divide by zero"
                return

            res, dz = SignArithmetic.rem(left, right)
            if dz:
                yield "divide by zero"
            if res:
                n.stack.push(res)
            else:
                n.stack.push(SignSet.top())

        else:
            # Unknown operator, conservative
            n.stack.push(SignSet.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- IFZ (compare with 0) ----------
    if tname == "Ifz":
        # We must pop the condition in all successors
        n = frame.copy()
        v = n.stack.pop() if n.stack else SignSet.top()
        cond = getattr(op, "condition", None)
        poss = _eval_zero_compare(cond, v)

        target = getattr(op, "target", None)
        if True in poss and target is not None:
            # target is an instruction index, convert to byte offset
            target_offset = bc.index_to_offset(pc.method, int(target))
            t = n.with_pc(PC(pc.method, target_offset))
            yield t

        if False in poss:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                yield n.with_pc(nxt)
        return

    # ---------- IF (icmp) ----------
    if tname == "If":
        # In the sign domain we cannot say much about comparisons of two
        # arbitrary integers, so both branches are conservatively possible
        n = frame.copy()
        while len(n.stack) < 2:
            n.stack.push(SignSet.top())
        n.stack.pop()
        n.stack.pop()

        target = getattr(op, "target", None)
        if target is not None:
            # target is an instruction index, convert to byte offset
            target_offset = bc.index_to_offset(pc.method, int(target))
            t = n.with_pc(PC(pc.method, target_offset))
            yield t

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- GOTO ----------
    if tname == "Goto":
        n = frame.copy()
        target = getattr(op, "target", None)
        if target is not None:
            # target is an instruction index, convert to byte offset
            target_offset = bc.index_to_offset(pc.method, int(target))
            yield n.with_pc(PC(pc.method, target_offset))
        else:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                yield n.with_pc(nxt)
        return

    # ---------- GET (fields) ----------
    if tname == "Get":
        n = frame.copy()
        static = bool(getattr(op, "static", False))
        field = getattr(op, "field", None)

        # Instance fields: pop receiver (may be null).
        if not static:
            if not n.stack:
                n.stack.push(SignSet.top())
            # Receiver might be null, we cannot track nullness in this
            # domain so we always consider the NPE possible
            yield "null pointer"
            _recv = n.stack.pop()

        # Push an abstract value for the field.
        ftype = getattr(getattr(field, "extension", field), "type", None)
        if isinstance(ftype, jvm.Int):
            n.stack.push(SignSet.top())
        elif isinstance(ftype, jvm.Boolean):
            # Booleans are 0/1 → {0,+}
            n.stack.push(SignSet(frozenset({"+", "0"})))
        else:
            n.stack.push(SignSet.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- PUT (fields) ----------
    if tname == "Put":
        n = frame.copy()
        static = bool(getattr(op, "static", False))

        # Pop the value to store
        if n.stack:
            _val = n.stack.pop()

        # Instance fields: pop receiver (may be null).
        if not static:
            if not n.stack:
                n.stack.push(SignSet.top())
            # Receiver might be null, we cannot track nullness in this
            # domain so we always consider the NPE possible
            yield "null pointer"
            _recv = n.stack.pop()

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- ARRAYS (coarse) ----------
    if tname == "NewArray":
        n = frame.copy()
        if n.stack:
            _len = n.stack.pop()   # length (sign not relevant)
        n.stack.push(SignSet.top())  # array reference
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayLoad":
        n = frame.copy()
        while len(n.stack) < 2:
            n.stack.push(SignSet.top())
        _idx = n.stack.pop()
        _arr = n.stack.pop()
        # Array may be null or index may be out of bounds
        yield "null pointer"
        yield "out of bounds"
        n.stack.push(SignSet.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayStore":
        n = frame.copy()
        while len(n.stack) < 3:
            n.stack.push(SignSet.top())
        _val = n.stack.pop()
        _idx = n.stack.pop()
        _arr = n.stack.pop()
        yield "null pointer"
        yield "out of bounds"
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayLength":
        n = frame.copy()
        if n.stack:
            _arr = n.stack.pop()
        yield "null pointer"
        # Array length is ≥ 0, but we just approximate with ⊤ here
        n.stack.push(SignSet.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- INVOKEs (coarse, context‑insensitive) ----------
    if tname.startswith("Invoke"):
        n = frame.copy()

        # Extract arg types/return type robustly across jpamb versions
        def _desc(m):
            d = getattr(m, "desc", None)
            if d is not None:
                return list(getattr(d, "args", [])), getattr(d, "returns", None)
            ext = getattr(m, "extension", None)
            if ext is not None:
                return list(getattr(ext, "params", [])), getattr(ext, "return_type", None)
            return [], None

        method_obj = getattr(op, "method", None)
        arg_types, returns = _desc(method_obj)
        nargs = len(arg_types)

        # Non‑static invocations have a receiver on the stack
        access = getattr(op, "access", None)
        access_name = _name(access) if access is not None else ""
        is_static = "static" in access_name or tname == "InvokeStatic"
        if not is_static:
            nargs += 1  # receiver + args

        # Pop arguments (and receiver, if any).  If the stack is too
        # small we pad with ⊤ to keep heights consistent
        while len(n.stack) < nargs:
            n.stack.push(SignSet.top())
        for _ in range(nargs):
            n.stack.pop()

        # Receiver could be null.
        if not is_static:
            yield "null pointer"

        # Push abstract return value if any.
        if returns is not None:
            n.stack.push(SignSet.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- NEW ----------
    if tname == "New":
        n = frame.copy()
        cname = getattr(op, "classname", None)

        # If the new object is AssertionError, some patterns immediately
        # throw it.  We let the Throw instruction handle the actual error
        # reporting, so here we only keep the stack well‑formed
        if cname is not None and getattr(cname, "slashed", lambda: "")() == "java/lang/AssertionError":
            # No push; Throw will terminate the path
            pass
        else:
            n.stack.push(SignSet.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- DUP ----------
    if tname == "Dup":
        n = frame.copy()
        if n.stack:
            n.stack.push(n.stack.peek())
        else:
            n.stack.push(SignSet.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- THROW ----------
    if tname == "Throw":
        # We conservatively treat all throws as assertion failures for the
        # purposes of this project
        yield "assertion error"
        return

    # ---------- RETURN ----------
    if tname.endswith("Return") or tname == "Return":
        # Any kind of return is treated as normal termination
        yield "ok"
        return

    # ---------- default: unknown opcode → fallthrough ----------
    n = frame.copy()
    nxt = bc.next_pc(pc)
    if nxt is not None:
        yield n.with_pc(nxt)


# ---------------------------------------------------------------------------
# Many‑step and bounded run
# ---------------------------------------------------------------------------


def manystep(
    bc: Bytecode,
    state: Dict[PC, PerVarFrame[SignSet]],
) -> Tuple[Dict[PC, PerVarFrame[SignSet]], set[str]]:
    """
    For every abstract frame in the current state we take a single abstract
    step, join frames that land at the same program counter, and collect
    any final outcomes encountered along the way
    """
    new_state: Dict[PC, PerVarFrame[SignSet]] = {}
    finals: set[str] = set()

    for pc, frame in state.items():
        for out in astep(bc, frame):
            if isinstance(out, str):
                finals.add(out)
            else:
                k = out.pc
                if k in new_state:
                    new_state[k] = new_state[k] | out
                else:
                    new_state[k] = out

    return new_state, finals


def bounded_abstract_run(
    suite: jpamb.Suite,
    method: jvm.AbsMethodID,
    init_locals: Dict[int, SignSet] | None = None,
    max_steps: int = 100,
) -> set[str]:
    """
    The unbounded static analysis will reuse the same `astep` / `manystep`
    primitives but iterate them to a fixpoint instead of truncating at
    max_steps
    """
    bc = Bytecode(suite)
    start = PC(method, 0)
    init = PerVarFrame(locals=dict(init_locals or {}), stack=Stack.empty(), pc=start)
    state: Dict[PC, PerVarFrame[SignSet]] = {start: init}

    finals: set[str] = set()
    for _ in range(max_steps):
        if not state:
            break
        state, step_finals = manystep(bc, state)
        finals |= step_finals

    return finals


class AbstractInterpreter:
    """
    Thin OO wrapper to mirror the concrete interpreter interface
    """

    def __init__(self, suite: jpamb.Suite, max_steps: int = 100) -> None:
        self.suite = suite
        self.max_steps = max_steps

    def analyze(self, method: jvm.AbsMethodID, init_locals: Dict[int, SignSet] | None = None) -> set[str]:
        return bounded_abstract_run(self.suite, method, init_locals=init_locals, max_steps=self.max_steps)


# ---------------------------------------------------------------------------
# IBA: Unbounded abstract interpretation with widening and narrowing
# ---------------------------------------------------------------------------


def unbounded_abstract_run(
    suite: jpamb.Suite,
    method: jvm.AbsMethodID,
    init_locals: Dict[int, SignSet] | None = None,
    widening_threshold: int = 3,
    enable_narrowing: bool = True,
    narrowing_iterations: int = 2,
) -> Tuple[set[str], set[int]]:
    """
    IBA: Unbounded abstract interpretation with widening and optional narrowing.
    
    This implements the course requirement for IBA (7 points):
    - Worklist-based fixpoint iteration with widening for termination
    - Optional narrowing pass after fixpoint to recover precision
    
    Algorithm:
        1. WIDENING PHASE: Iterate with widening until fixpoint
           - After `widening_threshold` iterations at a PC, apply widening
           - Widening ensures termination by extrapolating to ±∞
           
        2. NARROWING PHASE (optional): Improve precision
           - Run `narrowing_iterations` more passes with narrowing
           - Narrowing replaces ±∞ with finite bounds when sound
    
    Args:
        suite: JPAMB Suite for method lookup
        method: Method to analyze
        init_locals: Initial abstract values (from NAN refinement)
        widening_threshold: Apply widening after this many joins at a PC
        enable_narrowing: Whether to run narrowing phase (default: True)
        narrowing_iterations: Number of narrowing passes (default: 2)
        
    Returns:
        Tuple of (final_outcomes, visited_pcs):
        - final_outcomes: Set of possible outcomes ("ok", "divide by zero", etc.)
        - visited_pcs: Set of all reachable program counter offsets
        
    Example:
        >>> # Analyze infinite loop: while(true) { x++; }
        >>> outcomes, visited = unbounded_abstract_run(suite, method)
        >>> # Terminates due to widening; x is [0, +∞)
    """
    bc = Bytecode(suite)
    start = PC(method, 0)
    init = PerVarFrame(locals=dict(init_locals or {}), stack=Stack.empty(), pc=start)
    
    # =========================================================================
    # PHASE 1: WIDENING - Reach fixpoint with guaranteed termination
    # =========================================================================
    worklist: list[PC] = [start]
    state: Dict[PC, PerVarFrame[SignSet]] = {start: init}
    join_counts: Dict[PC, int] = {start: 1}
    
    finals: set[str] = set()
    visited_pcs: set[int] = set()
    
    while worklist:
        pc = worklist.pop(0)  # FIFO for breadth-first
        visited_pcs.add(pc.offset)
        
        frame = state.get(pc)
        if frame is None:
            continue
        
        for out in astep(bc, frame):
            if isinstance(out, str):
                finals.add(out)
            else:
                target_pc = out.pc
                
                if target_pc in state:
                    old_frame = state[target_pc]
                    count = join_counts.get(target_pc, 0) + 1
                    join_counts[target_pc] = count
                    
                    # Apply widening after threshold to ensure termination
                    if count > widening_threshold:
                        new_frame = _widen_frame(old_frame, out)
                    else:
                        new_frame = old_frame | out
                    
                    # Only add to worklist if state changed
                    if not (new_frame <= old_frame):
                        state[target_pc] = new_frame
                        if target_pc not in worklist:
                            worklist.append(target_pc)
                else:
                    state[target_pc] = out
                    join_counts[target_pc] = 1
                    worklist.append(target_pc)
    
    # =========================================================================
    # PHASE 2: NARROWING - Improve precision after widening fixpoint
    # =========================================================================
    if enable_narrowing:
        for _ in range(narrowing_iterations):
            changed = False
            
            # Process all PCs in order
            for pc in sorted(state.keys(), key=lambda p: p.offset):
                frame = state.get(pc)
                if frame is None:
                    continue
                
                for out in astep(bc, frame):
                    if isinstance(out, str):
                        finals.add(out)
                    else:
                        target_pc = out.pc
                        
                        if target_pc in state:
                            old_frame = state[target_pc]
                            # Apply narrowing: meet with new value
                            new_frame = _narrow_frame(old_frame, out)
                            
                            # Only update if more precise
                            if new_frame <= old_frame and new_frame != old_frame:
                                state[target_pc] = new_frame
                                changed = True
            
            if not changed:
                break  # Narrowing fixpoint reached
    
    return finals, visited_pcs


def _widen_frame(old: PerVarFrame[SignSet], new: PerVarFrame[SignSet]) -> PerVarFrame[SignSet]:
    """
    Apply widening to an abstract frame.
    
    IBA widening for SignSet: if the new value contains more signs,
    go directly to TOP to ensure termination.
    """
    # For locals: widen each variable
    widened_locals: Dict[int, SignSet] = {}
    all_keys = set(old.locals) | set(new.locals)
    for idx in all_keys:
        v_old = old.locals.get(idx, SignSet.bottom())
        v_new = new.locals.get(idx, SignSet.bottom())
        
        # Widening: if new has more signs, go to TOP
        if v_new.signs - v_old.signs:  # new has signs not in old
            widened_locals[idx] = SignSet.top()
        else:
            widened_locals[idx] = v_old | v_new
    
    # Stack widening (similar approach)
    widened_stack_items = []
    for s_old, s_new in zip(old.stack, new.stack):
        if s_new.signs - s_old.signs:
            widened_stack_items.append(SignSet.top())
        else:
            widened_stack_items.append(s_old | s_new)
    
    return PerVarFrame(widened_locals, Stack(widened_stack_items), old.pc)


def _narrow_frame(old: PerVarFrame[SignSet], new: PerVarFrame[SignSet]) -> PerVarFrame[SignSet]:
    """
    Apply narrowing to an abstract frame to improve precision.
    
    IBA narrowing for SignSet: meet (intersection) to get more precise result.
    """
    # For locals: narrow each variable
    narrowed_locals: Dict[int, SignSet] = {}
    all_keys = set(old.locals) | set(new.locals)
    for idx in all_keys:
        v_old = old.locals.get(idx, SignSet.top())
        v_new = new.locals.get(idx, SignSet.top())
        
        # Narrowing: meet (intersection) for more precision
        narrowed_locals[idx] = v_old & v_new
    
    # Stack narrowing
    narrowed_stack_items = []
    for s_old, s_new in zip(old.stack, new.stack):
        narrowed_stack_items.append(s_old & s_new)
    
    return PerVarFrame(narrowed_locals, Stack(narrowed_stack_items), old.pc)


def get_unreachable_pcs(
    suite: jpamb.Suite,
    method: jvm.AbsMethodID,
    init_locals: Dict[int, SignSet] | None = None,
) -> set[int]:
    """
    Compute unreachable program counters using abstract interpretation.
    
    Returns the set of bytecode offsets that cannot be reached from the
    method entry point, based on abstract interpretation with the given
    initial state.
    
    Args:
        suite: JPAMB Suite for method lookup
        method: Method to analyze
        init_locals: Initial abstract values (from NAN refinement)
        
    Returns:
        Set of bytecode offsets that are unreachable
        
    Example:
        >>> from solutions.nab_integration import ReducedProductState
        >>> # If we know x > 0 from dynamic traces
        >>> refined = ReducedProductState.from_samples([5, 10, 15])
        >>> init = {0: SignSet(frozenset({"+"})) if refined.sign.value.name == "POSITIVE" else SignSet.top()}
        >>> unreachable = get_unreachable_pcs(suite, method, init)
    """
    # Run unbounded analysis to get visited PCs
    _, visited_pcs = unbounded_abstract_run(suite, method, init_locals)
    
    # Get all PCs in the method
    bc = Bytecode(suite)
    bc._ensure(method)
    assert bc._sorted_offsets is not None
    all_pcs = set(bc._sorted_offsets.get(method, []))
    
    # Unreachable = all - visited
    return all_pcs - visited_pcs


# ---------------------------------------------------------------------------
# ISY Integration: Abstract interpreter using MethodIR
# ---------------------------------------------------------------------------


def analyze_with_ir(
    ir: "MethodIR",
    init_locals: Dict[int, SignSet] | None = None,
    max_steps: int = 100,
) -> Tuple[set[str], set[int], set[int]]:
    """
    Abstract interpretation using ISY MethodIR as input.
    
    This function integrates the abstract interpreter with the ISY syntactic
    analysis module, using the CFG from MethodIR for analysis.
    
    Args:
        ir: MethodIR from ISY module (solutions/ir.py)
        init_locals: Initial abstract values for local variables
        max_steps: Maximum interpretation steps (for bounded analysis)
        
    Returns:
        Tuple of (outcomes, visited_pcs, unreachable_pcs):
        - outcomes: Set of possible outcomes
        - visited_pcs: Reachable program counters
        - unreachable_pcs: Unreachable program counters
        
    Example:
        >>> from solutions.ir import MethodIR
        >>> from solutions.nab_integration import ReducedProductState
        >>> 
        >>> # Load method IR from ISY
        >>> ir = MethodIR.from_class('target/decompiled/jpamb/cases/Simple.json', 
        ...                          'assertPositive:(I)V')
        >>> 
        >>> # Get refined initial state from NAN
        >>> refined = ReducedProductState.from_samples([5, 10, 15])
        >>> init = {0: SignSet.from_reduced(refined)}
        >>> 
        >>> # Analyze using ISY CFG
        >>> outcomes, visited, unreachable = analyze_with_ir(ir, init)
    """
    # Import here to avoid circular dependency
    
    # Get all PCs from CFG
    all_pcs = set(ir.cfg.keys())
    
    # Build abstract state from IR
    init_frame = _build_initial_frame_from_ir(ir, init_locals)
    
    # Run bounded analysis on IR CFG
    visited_pcs: set[int] = set()
    finals: set[str] = set()
    
    # Worklist using IR successors
    worklist: list[int] = [ir.entry_pc]
    state: Dict[int, PerVarFrame[SignSet]] = {ir.entry_pc: init_frame}
    
    steps = 0
    while worklist and steps < max_steps:
        steps += 1
        pc = worklist.pop(0)
        visited_pcs.add(pc)
        
        frame = state.get(pc)
        if frame is None:
            continue
        
        node = ir.get_node(pc)
        if node is None:
            continue
        
        # Process node based on type
        outcomes = _process_ir_node(node, frame, ir)
        
        for out in outcomes:
            if isinstance(out, str):
                finals.add(out)
            else:
                target_pc = out.pc.offset
                
                if target_pc in state:
                    old_frame = state[target_pc]
                    new_frame = old_frame | out
                    if not (new_frame <= old_frame):
                        state[target_pc] = new_frame
                        if target_pc not in worklist:
                            worklist.append(target_pc)
                else:
                    state[target_pc] = out
                    worklist.append(target_pc)
    
    unreachable_pcs = all_pcs - visited_pcs
    return finals, visited_pcs, unreachable_pcs


def _build_initial_frame_from_ir(ir: "MethodIR", init_locals: Dict[int, SignSet] | None) -> PerVarFrame[SignSet]:
    """Build initial abstract frame from MethodIR."""
    
    # Build the full method ID string like "jpamb.cases.Simple.assertPositive:(I)V"
    full_method_id = f"{ir.class_name}.{ir.method_id}"
    method_id = jvm.AbsMethodID.decode(full_method_id)
    start_pc = PC(method_id, ir.entry_pc)
    
    return PerVarFrame(
        locals=dict(init_locals or {}),
        stack=Stack.empty(),
        pc=start_pc
    )


def _process_ir_node(node: "CFGNode", frame: PerVarFrame[SignSet], ir: "MethodIR") -> list:
    """
    Process a CFG node from IR, yielding successor frames or outcomes.
    
    This maps IR node types to abstract interpretation semantics.
    """
    from solutions.ir import NodeType
    
    results = []
    n = frame.copy()
    
    # Check node type and handle accordingly
    if node.node_type == NodeType.RETURN:
        results.append("ok")
    elif node.node_type == NodeType.THROW:
        results.append("assertion error")
    else:
        # For other nodes, propagate to successors
        method_id = frame.pc.method
        for succ_pc in node.successors:
            results.append(n.with_pc(PC(method_id, succ_pc)))
    
    return results


# Helper to convert NAB ReducedProductState to SignSet (compatibility)
def signset_from_reduced(reduced: "ReducedProductState") -> SignSet:
    """
    Convert a ReducedProductState from NAB to a SignSet for abstract interpretation.
    
    Since NAB now uses SignSet directly, this is just an accessor.
    """
    return reduced.sign


# ===========================================================================
# INTERVAL DOMAIN ABSTRACT INTERPRETER
# ===========================================================================
# This interpreter uses IntervalDomain for more precise analysis than SignSet.
# It can detect dead code in cases like:
#   - if (x > 10) { if (x < 5) { /* dead */ } }
#   - if (x >= 0 && x <= 10) { if (x > 15) { /* dead */ } }
# ===========================================================================


def _eval_zero_compare_interval(cond: object | None, v: IntervalDomain) -> set[bool]:
    """
    Evaluate a zero comparison against an IntervalDomain.
    Returns the set of booleans that are *possible* at runtime.
    """
    if cond is None:
        return {True, False}

    cname = _name(cond)

    if "eq" in cname:
        return v.eval_eq_zero()
    elif "ne" in cname:
        return v.eval_ne_zero()
    elif "lt" in cname:
        return v.eval_lt_zero()
    elif "le" in cname:
        return v.eval_le_zero()
    elif "gt" in cname:
        return v.eval_gt_zero()
    elif "ge" in cname:
        return v.eval_ge_zero()
    else:
        return {True, False}


def _refine_zero_compare_interval(cond: object | None, v: IntervalDomain, branch: bool) -> IntervalDomain:
    """
    Refine an IntervalDomain based on a zero comparison and which branch was taken.
    
    Args:
        cond: The comparison condition (eq, ne, lt, le, gt, ge)
        v: The interval to refine
        branch: True if the branch was taken, False if it fell through
        
    Returns:
        Refined interval domain
    """
    if cond is None:
        return v
    
    cname = _name(cond)
    
    if "eq" in cname:
        return v.refine_eq_zero() if branch else v.refine_ne_zero()
    elif "ne" in cname:
        return v.refine_ne_zero() if branch else v.refine_eq_zero()
    elif "lt" in cname:
        return v.refine_lt_zero() if branch else v.refine_ge_zero()
    elif "le" in cname:
        return v.refine_le_zero() if branch else v.refine_gt_zero()
    elif "gt" in cname:
        return v.refine_gt_zero() if branch else v.refine_le_zero()
    elif "ge" in cname:
        return v.refine_ge_zero() if branch else v.refine_lt_zero()
    else:
        return v


def _eval_const_compare_interval(cond: object | None, left: IntervalDomain, k: int) -> set[bool]:
    """
    Evaluate a comparison against a constant: left <cond> k
    Returns the set of booleans that are *possible* at runtime.
    """
    if cond is None:
        return {True, False}

    cname = _name(cond)

    if "eq" in cname:
        return left.eval_eq_const(k)
    elif "ne" in cname:
        return left.eval_ne_const(k)
    elif "lt" in cname:
        return left.eval_lt_const(k)
    elif "le" in cname:
        return left.eval_le_const(k)
    elif "gt" in cname:
        return left.eval_gt_const(k)
    elif "ge" in cname:
        return left.eval_ge_const(k)
    else:
        return {True, False}


def _refine_const_compare_interval(cond: object | None, v: IntervalDomain, k: int, branch: bool) -> IntervalDomain:
    """
    Refine an IntervalDomain based on a constant comparison and which branch was taken.
    """
    if cond is None:
        return v
    
    cname = _name(cond)
    
    if "eq" in cname:
        return v.refine_eq_const(k) if branch else v.refine_ne_const(k)
    elif "ne" in cname:
        return v.refine_ne_const(k) if branch else v.refine_eq_const(k)
    elif "lt" in cname:
        return v.refine_lt_const(k) if branch else v.refine_ge_const(k)
    elif "le" in cname:
        return v.refine_le_const(k) if branch else v.refine_gt_const(k)
    elif "gt" in cname:
        return v.refine_gt_const(k) if branch else v.refine_le_const(k)
    elif "ge" in cname:
        return v.refine_ge_const(k) if branch else v.refine_lt_const(k)
    else:
        return v


def _find_loaded_local_before(bc: Bytecode, pc: PC) -> int | None:
    """
    Look at the instruction before pc to see if it was a Load.
    If so, return the local variable index that was loaded.
    
    This enables branch refinement: when we see "iload_0; ifgt target",
    we know the comparison was on local variable 0.
    """
    bc._ensure(pc.method)
    assert bc._sorted_offsets is not None and bc._ops is not None
    
    sorted_offsets = bc._sorted_offsets.get(pc.method, [])
    try:
        idx = sorted_offsets.index(pc.offset)
        if idx > 0:
            prev_offset = sorted_offsets[idx - 1]
            ops = bc._ops.get(pc.method, [])
            idx_map = bc._idx.get(pc.method, {})
            prev_idx = idx_map.get(prev_offset)
            if prev_idx is not None:
                prev_op = ops[prev_idx]
                if type(prev_op).__name__ == "Load":
                    return int(getattr(prev_op, "index", 0))
    except (ValueError, IndexError):
        pass
    return None


def _find_loaded_local_for_icmp(bc: Bytecode, pc: PC) -> int | None:
    """
    For an If (icmp) instruction, look back to find which local the LEFT
    operand came from.
    
    Pattern: iload_X; iconst/bipush K; if_icmpXX target
    We want to find X so we can refine local X after the comparison.
    """
    bc._ensure(pc.method)
    assert bc._sorted_offsets is not None and bc._ops is not None
    
    sorted_offsets = bc._sorted_offsets.get(pc.method, [])
    try:
        idx = sorted_offsets.index(pc.offset)
        # Look 2 instructions back (skip the Push for the constant)
        if idx >= 2:
            prev_prev_offset = sorted_offsets[idx - 2]
            ops = bc._ops.get(pc.method, [])
            idx_map = bc._idx.get(pc.method, {})
            prev_prev_idx = idx_map.get(prev_prev_offset)
            if prev_prev_idx is not None:
                prev_prev_op = ops[prev_prev_idx]
                if type(prev_prev_op).__name__ == "Load":
                    return int(getattr(prev_prev_op, "index", 0))
    except (ValueError, IndexError):
        pass
    return None


def interval_astep(
    bc: Bytecode,
    frame: PerVarFrame[IntervalDomain],
) -> Iterable[PerVarFrame[IntervalDomain] | str]:
    """
    One abstract step using IntervalDomain for more precise analysis.
    
    This is similar to astep() but uses IntervalDomain instead of SignSet,
    enabling detection of dead code based on value ranges.
    """
    pc = frame.pc
    try:
        op = bc[pc]
    except IndexError:
        return

    tname = type(op).__name__

    # ---------- PUSH ----------
    if tname == "Push":
        n = frame.copy()
        v = getattr(op, "value", None)
        inner = getattr(v, "value", None)

        if isinstance(v, int):
            n.stack.push(IntervalDomain.const(v))
        elif isinstance(inner, int):
            n.stack.push(IntervalDomain.const(int(inner)))
        else:
            n.stack.push(IntervalDomain.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- LOAD ----------
    if tname == "Load":
        n = frame.copy()
        idx = int(getattr(op, "index", 0))
        n.stack.push(n.locals.get(idx, IntervalDomain.top()))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- STORE ----------
    if tname == "Store":
        n = frame.copy()
        idx = int(getattr(op, "index", 0))
        val = n.stack.pop() if n.stack else IntervalDomain.top()
        n.locals[idx] = val

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- INCR (iinc) ----------
    if tname == "Incr":
        n = frame.copy()
        idx = int(getattr(op, "index", getattr(op, "var", 0)))
        delta = int(getattr(op, "value", getattr(op, "amount", getattr(op, "delta", 0))))
        base = n.locals.get(idx, IntervalDomain.top())
        n.locals[idx] = IntervalArithmetic.add(base, IntervalDomain.const(delta))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- CAST ----------
    if tname == "Cast":
        n = frame.copy()
        val = n.stack.pop() if n.stack else IntervalDomain.top()
        # For most casts, preserve the interval
        n.stack.push(val)
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- NEGATE ----------
    if tname == "Negate":
        n = frame.copy()
        v = n.stack.pop() if n.stack else IntervalDomain.top()
        n.stack.push(IntervalArithmetic.neg(v))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- BINARY ----------
    if tname == "Binary":
        n = frame.copy()

        while len(n.stack) < 2:
            n.stack.push(IntervalDomain.top())

        right = n.stack.pop()
        left = n.stack.pop()
        kind = _name(getattr(op, "operant", None))

        if "add" in kind:
            n.stack.push(IntervalArithmetic.add(left, right))

        elif "sub" in kind:
            n.stack.push(IntervalArithmetic.sub(left, right))

        elif "mul" in kind:
            n.stack.push(IntervalArithmetic.mul(left, right))

        elif "div" in kind:
            res, dz = IntervalArithmetic.div(left, right)
            if dz:
                yield "divide by zero"
            # Check if division is definitely by zero
            if right.value.low == 0 and right.value.high == 0:
                return  # Definitely divide by zero, no normal successor
            n.stack.push(res)

        elif "rem" in kind:
            if 0 in right:
                yield "divide by zero"
            if right.value.low == 0 and right.value.high == 0:
                return
            n.stack.push(IntervalDomain.top())  # Modulo is complex

        else:
            n.stack.push(IntervalDomain.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- IFZ (compare with 0) - WITH BRANCH REFINEMENT ----------
    if tname == "Ifz":
        v = frame.stack.peek() if frame.stack else IntervalDomain.top()
        cond = getattr(op, "condition", None)
        poss = _eval_zero_compare_interval(cond, v)

        target = getattr(op, "target", None)
        
        # Try to find which local variable was loaded for this comparison
        # Look at the previous instruction to see if it was a Load
        loaded_local = _find_loaded_local_before(bc, pc)
        
        # Branch taken (condition is true)
        if True in poss and target is not None:
            target_offset = bc.index_to_offset(pc.method, int(target))
            n_taken = frame.copy()
            n_taken.stack.pop()  # Pop the compared value
            
            # Refine the local variable if we know which one was loaded
            if loaded_local is not None:
                old_val = n_taken.locals.get(loaded_local, IntervalDomain.top())
                refined = _refine_zero_compare_interval(cond, old_val, True)
                n_taken.locals[loaded_local] = refined
            
            yield n_taken.with_pc(PC(pc.method, target_offset))

        # Branch not taken (fall through, condition is false)
        if False in poss:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                n_fall = frame.copy()
                n_fall.stack.pop()  # Pop the compared value
                
                # Refine for the false branch
                if loaded_local is not None:
                    old_val = n_fall.locals.get(loaded_local, IntervalDomain.top())
                    refined = _refine_zero_compare_interval(cond, old_val, False)
                    n_fall.locals[loaded_local] = refined
                
                yield n_fall.with_pc(nxt)
        return

    # ---------- IF (icmp) - WITH CONSTANT COMPARISON AND REFINEMENT ----------
    if tname == "If":
        while len(frame.stack) < 2:
            frame.stack.push(IntervalDomain.top())
        
        right = frame.stack.items[-1]  # Peek without pop
        left = frame.stack.items[-2]   # Peek without pop
        cond = getattr(op, "condition", None)

        # Check if right is a constant - enables precise comparison
        right_const = None
        if (right.value.low is not None and right.value.high is not None and
            right.value.low == right.value.high):
            right_const = right.value.low

        if right_const is not None:
            poss = _eval_const_compare_interval(cond, left, right_const)
        else:
            poss = {True, False}

        target = getattr(op, "target", None)
        
        # Try to find which local was loaded for the left operand
        loaded_local = _find_loaded_local_for_icmp(bc, pc)
        
        # Branch taken
        if True in poss and target is not None:
            target_offset = bc.index_to_offset(pc.method, int(target))
            n_taken = frame.copy()
            n_taken.stack.pop()  # Pop right
            n_taken.stack.pop()  # Pop left
            
            # Refine if comparing with constant and we know the local
            if loaded_local is not None and right_const is not None:
                old_val = n_taken.locals.get(loaded_local, IntervalDomain.top())
                refined = _refine_const_compare_interval(cond, old_val, right_const, True)
                n_taken.locals[loaded_local] = refined
            
            yield n_taken.with_pc(PC(pc.method, target_offset))

        # Branch not taken
        if False in poss:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                n_fall = frame.copy()
                n_fall.stack.pop()  # Pop right
                n_fall.stack.pop()  # Pop left
                
                if loaded_local is not None and right_const is not None:
                    old_val = n_fall.locals.get(loaded_local, IntervalDomain.top())
                    refined = _refine_const_compare_interval(cond, old_val, right_const, False)
                    n_fall.locals[loaded_local] = refined
                
                yield n_fall.with_pc(nxt)
        return

    # ---------- GOTO ----------
    if tname == "Goto":
        n = frame.copy()
        target = getattr(op, "target", None)
        if target is not None:
            target_offset = bc.index_to_offset(pc.method, int(target))
            yield n.with_pc(PC(pc.method, target_offset))
        else:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                yield n.with_pc(nxt)
        return

    # ---------- GET (fields) ----------
    if tname == "Get":
        n = frame.copy()
        static = bool(getattr(op, "static", False))

        if not static:
            if not n.stack:
                n.stack.push(IntervalDomain.top())
            yield "null pointer"
            _recv = n.stack.pop()

        n.stack.push(IntervalDomain.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- PUT (fields) ----------
    if tname == "Put":
        n = frame.copy()
        static = bool(getattr(op, "static", False))

        # Pop the value to store
        if n.stack:
            _val = n.stack.pop()

        # Instance fields: pop receiver (may be null).
        if not static:
            if not n.stack:
                n.stack.push(IntervalDomain.top())
            yield "null pointer"
            _recv = n.stack.pop()

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- ARRAYS ----------
    if tname == "NewArray":
        n = frame.copy()
        if n.stack:
            _len = n.stack.pop()
        n.stack.push(IntervalDomain.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayLoad":
        n = frame.copy()
        while len(n.stack) < 2:
            n.stack.push(IntervalDomain.top())
        _idx = n.stack.pop()
        _arr = n.stack.pop()
        yield "null pointer"
        yield "out of bounds"
        n.stack.push(IntervalDomain.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayStore":
        n = frame.copy()
        while len(n.stack) < 3:
            n.stack.push(IntervalDomain.top())
        _val = n.stack.pop()
        _idx = n.stack.pop()
        _arr = n.stack.pop()
        yield "null pointer"
        yield "out of bounds"
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayLength":
        n = frame.copy()
        if n.stack:
            _arr = n.stack.pop()
        yield "null pointer"
        # Array length is >= 0
        n.stack.push(IntervalDomain.range(0, None))
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- INVOKEs ----------
    if tname.startswith("Invoke"):
        n = frame.copy()

        def _desc(m):
            d = getattr(m, "desc", None)
            if d is not None:
                return list(getattr(d, "args", [])), getattr(d, "returns", None)
            ext = getattr(m, "extension", None)
            if ext is not None:
                return list(getattr(ext, "params", [])), getattr(ext, "return_type", None)
            return [], None

        method_obj = getattr(op, "method", None)
        arg_types, returns = _desc(method_obj)
        nargs = len(arg_types)

        access = getattr(op, "access", None)
        access_name = _name(access) if access is not None else ""
        is_static = "static" in access_name or tname == "InvokeStatic"
        if not is_static:
            nargs += 1

        while len(n.stack) < nargs:
            n.stack.push(IntervalDomain.top())
        for _ in range(nargs):
            n.stack.pop()

        if not is_static:
            yield "null pointer"

        if returns is not None:
            n.stack.push(IntervalDomain.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- NEW ----------
    if tname == "New":
        n = frame.copy()
        cname = getattr(op, "classname", None)
        if cname is not None and getattr(cname, "slashed", lambda: "")() == "java/lang/AssertionError":
            pass
        else:
            n.stack.push(IntervalDomain.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- DUP ----------
    if tname == "Dup":
        n = frame.copy()
        if n.stack:
            n.stack.push(n.stack.peek())
        else:
            n.stack.push(IntervalDomain.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- THROW ----------
    if tname == "Throw":
        yield "assertion error"
        return

    # ---------- RETURN ----------
    if tname.endswith("Return") or tname == "Return":
        yield "ok"
        return

    # ---------- default: fallthrough ----------
    n = frame.copy()
    nxt = bc.next_pc(pc)
    if nxt is not None:
        yield n.with_pc(nxt)


def interval_unbounded_run(
    suite: jpamb.Suite,
    method: jvm.AbsMethodID,
    init_locals: Dict[int, IntervalDomain] | None = None,
    widening_threshold: int = 3,
) -> Tuple[set[str], set[int]]:
    """
    Unbounded abstract interpretation using IntervalDomain.
    
    This provides more precise analysis than SignSet for cases involving:
    - Comparisons with constants (x > 10, x < 5)
    - Range checks (x >= 0 && x <= 100)
    - Arithmetic constraints
    
    Returns:
        Tuple of (final_outcomes, visited_pcs)
    """
    bc = Bytecode(suite)
    start = PC(method, 0)
    init = PerVarFrame(locals=dict(init_locals or {}), stack=Stack.empty(), pc=start)
    
    worklist: list[PC] = [start]
    state: Dict[PC, PerVarFrame[IntervalDomain]] = {start: init}
    join_counts: Dict[PC, int] = {start: 1}
    
    finals: set[str] = set()
    visited_pcs: set[int] = set()
    
    while worklist:
        pc = worklist.pop(0)
        visited_pcs.add(pc.offset)
        
        frame = state.get(pc)
        if frame is None:
            continue
        
        for out in interval_astep(bc, frame):
            if isinstance(out, str):
                finals.add(out)
            else:
                target_pc = out.pc
                
                if target_pc in state:
                    old_frame = state[target_pc]
                    count = join_counts.get(target_pc, 0) + 1
                    join_counts[target_pc] = count
                    
                    # Apply widening after threshold
                    if count > widening_threshold:
                        new_frame = _widen_interval_frame(old_frame, out)
                    else:
                        new_frame = old_frame | out
                    
                    if not (new_frame <= old_frame):
                        state[target_pc] = new_frame
                        if target_pc not in worklist:
                            worklist.append(target_pc)
                else:
                    state[target_pc] = out
                    join_counts[target_pc] = 1
                    worklist.append(target_pc)
    
    return finals, visited_pcs


def _widen_interval_frame(old: PerVarFrame[IntervalDomain], new: PerVarFrame[IntervalDomain]) -> PerVarFrame[IntervalDomain]:
    """Apply widening to an interval frame."""
    widened_locals: Dict[int, IntervalDomain] = {}
    all_keys = set(old.locals) | set(new.locals)
    for idx in all_keys:
        v_old = old.locals.get(idx, IntervalDomain.bottom())
        v_new = new.locals.get(idx, IntervalDomain.bottom())
        widened_locals[idx] = v_old.widening(v_new)
    
    widened_stack_items = []
    for s_old, s_new in zip(old.stack, new.stack):
        widened_stack_items.append(s_old.widening(s_new))
    
    return PerVarFrame(widened_locals, Stack(widened_stack_items), old.pc)


def interval_get_unreachable_pcs(
    suite: jpamb.Suite,
    method: jvm.AbsMethodID,
    init_locals: Dict[int, IntervalDomain] | None = None,
) -> set[int]:
    """
    Compute unreachable program counters using interval abstract interpretation.
    """
    _, visited_pcs = interval_unbounded_run(suite, method, init_locals)
    
    bc = Bytecode(suite)
    bc._ensure(method)
    assert bc._sorted_offsets is not None
    all_pcs = set(bc._sorted_offsets.get(method, []))
    
    return all_pcs - visited_pcs


# ===========================================================================
# PRODUCT DOMAIN: Combines IntervalDomain + NonNullDomain for maximum precision
# ===========================================================================
# This domain tracks both:
# - Integer values with intervals (for numeric comparisons)
# - Reference nullness (for null checks)
# ===========================================================================


@dataclass(frozen=True)
class ProductValue:
    """
    Product domain value combining interval and nullness information.
    
    For integer values: uses interval, nullness is TOP
    For references: uses nullness, interval is TOP
    """
    interval: IntervalDomain
    nullness: NonNullDomain
    
    @classmethod
    def top(cls) -> "ProductValue":
        return cls(IntervalDomain.top(), NonNullDomain.top())
    
    @classmethod
    def bottom(cls) -> "ProductValue":
        return cls(IntervalDomain.bottom(), NonNullDomain.bottom())
    
    @classmethod
    def from_int_const(cls, n: int) -> "ProductValue":
        return cls(IntervalDomain.const(n), NonNullDomain.top())
    
    @classmethod
    def from_new(cls) -> "ProductValue":
        """Value from 'new' instruction - definitely non-null."""
        return cls(IntervalDomain.top(), NonNullDomain.definitely_non_null())
    
    @classmethod
    def from_null(cls) -> "ProductValue":
        """Value from null constant."""
        return cls(IntervalDomain.top(), NonNullDomain.maybe_null())
    
    def is_bottom(self) -> bool:
        return self.interval.is_bottom() or self.nullness.is_bottom()
    
    def is_top(self) -> bool:
        return self.interval.is_top() and self.nullness.is_top()
    
    def __le__(self, other: "ProductValue") -> bool:
        return self.interval <= other.interval and self.nullness <= other.nullness
    
    def __or__(self, other: "ProductValue") -> "ProductValue":
        return ProductValue(
            self.interval | other.interval,
            self.nullness | other.nullness
        )
    
    def __and__(self, other: "ProductValue") -> "ProductValue":
        return ProductValue(
            self.interval & other.interval,
            self.nullness & other.nullness
        )
    
    def widening(self, other: "ProductValue") -> "ProductValue":
        return ProductValue(
            self.interval.widening(other.interval),
            self.nullness.widening(other.nullness)
        )
    
    def __repr__(self) -> str:
        return f"({self.interval}, {self.nullness})"


class ProductArithmetic:
    """Arithmetic operations on ProductValue."""
    
    @staticmethod
    def add(a: ProductValue, b: ProductValue) -> ProductValue:
        return ProductValue(
            IntervalArithmetic.add(a.interval, b.interval),
            NonNullDomain.top()  # Result is integer, not reference
        )
    
    @staticmethod
    def sub(a: ProductValue, b: ProductValue) -> ProductValue:
        return ProductValue(
            IntervalArithmetic.sub(a.interval, b.interval),
            NonNullDomain.top()
        )
    
    @staticmethod
    def mul(a: ProductValue, b: ProductValue) -> ProductValue:
        return ProductValue(
            IntervalArithmetic.mul(a.interval, b.interval),
            NonNullDomain.top()
        )
    
    @staticmethod
    def div(a: ProductValue, b: ProductValue) -> Tuple[ProductValue, bool]:
        res, dz = IntervalArithmetic.div(a.interval, b.interval)
        return ProductValue(res, NonNullDomain.top()), dz
    
    @staticmethod
    def neg(a: ProductValue) -> ProductValue:
        return ProductValue(
            IntervalArithmetic.neg(a.interval),
            NonNullDomain.top()
        )


def product_astep(
    bc: Bytecode,
    frame: PerVarFrame[ProductValue],
) -> Iterable[PerVarFrame[ProductValue] | str]:
    """
    One abstract step using ProductValue (Interval + Nullness) for maximum precision.
    
    Detects dead code from:
    - Numeric comparisons (via IntervalDomain)
    - Null checks (via NonNullDomain)
    """
    pc = frame.pc
    try:
        op = bc[pc]
    except IndexError:
        return

    tname = type(op).__name__

    # ---------- PUSH ----------
    if tname == "Push":
        n = frame.copy()
        v = getattr(op, "value", None)
        inner = getattr(v, "value", None)

        if isinstance(v, int):
            n.stack.push(ProductValue.from_int_const(v))
        elif isinstance(inner, int):
            n.stack.push(ProductValue.from_int_const(int(inner)))
        elif v is None or (hasattr(v, 'value') and inner is None):
            # null constant (aconst_null)
            n.stack.push(ProductValue.from_null())
        else:
            n.stack.push(ProductValue.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- LOAD ----------
    if tname == "Load":
        n = frame.copy()
        idx = int(getattr(op, "index", 0))
        n.stack.push(n.locals.get(idx, ProductValue.top()))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- STORE ----------
    if tname == "Store":
        n = frame.copy()
        idx = int(getattr(op, "index", 0))
        val = n.stack.pop() if n.stack else ProductValue.top()
        n.locals[idx] = val

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- INCR (iinc) ----------
    if tname == "Incr":
        n = frame.copy()
        idx = int(getattr(op, "index", getattr(op, "var", 0)))
        delta = int(getattr(op, "value", getattr(op, "amount", getattr(op, "delta", 0))))
        base = n.locals.get(idx, ProductValue.top())
        n.locals[idx] = ProductArithmetic.add(base, ProductValue.from_int_const(delta))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- CAST ----------
    if tname == "Cast":
        n = frame.copy()
        val = n.stack.pop() if n.stack else ProductValue.top()
        n.stack.push(val)  # Preserve product value through cast
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- NEGATE ----------
    if tname == "Negate":
        n = frame.copy()
        v = n.stack.pop() if n.stack else ProductValue.top()
        n.stack.push(ProductArithmetic.neg(v))

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- BINARY ----------
    if tname == "Binary":
        n = frame.copy()

        while len(n.stack) < 2:
            n.stack.push(ProductValue.top())

        right = n.stack.pop()
        left = n.stack.pop()
        kind = _name(getattr(op, "operant", None))

        if "add" in kind:
            n.stack.push(ProductArithmetic.add(left, right))
        elif "sub" in kind:
            n.stack.push(ProductArithmetic.sub(left, right))
        elif "mul" in kind:
            n.stack.push(ProductArithmetic.mul(left, right))
        elif "div" in kind:
            res, dz = ProductArithmetic.div(left, right)
            if dz:
                yield "divide by zero"
            if right.interval.value.low == 0 and right.interval.value.high == 0:
                return
            n.stack.push(res)
        elif "rem" in kind:
            if 0 in right.interval:
                yield "divide by zero"
            if right.interval.value.low == 0 and right.interval.value.high == 0:
                return
            n.stack.push(ProductValue.top())
        else:
            n.stack.push(ProductValue.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- IFZ (compare with 0) ----------
    if tname == "Ifz":
        v = frame.stack.peek() if frame.stack else ProductValue.top()
        cond = getattr(op, "condition", None)
        poss = _eval_zero_compare_interval(cond, v.interval)

        target = getattr(op, "target", None)
        loaded_local = _find_loaded_local_before(bc, pc)
        
        if True in poss and target is not None:
            target_offset = bc.index_to_offset(pc.method, int(target))
            n_taken = frame.copy()
            n_taken.stack.pop()
            
            if loaded_local is not None:
                old_val = n_taken.locals.get(loaded_local, ProductValue.top())
                refined_interval = _refine_zero_compare_interval(cond, old_val.interval, True)
                n_taken.locals[loaded_local] = ProductValue(refined_interval, old_val.nullness)
            
            yield n_taken.with_pc(PC(pc.method, target_offset))

        if False in poss:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                n_fall = frame.copy()
                n_fall.stack.pop()
                
                if loaded_local is not None:
                    old_val = n_fall.locals.get(loaded_local, ProductValue.top())
                    refined_interval = _refine_zero_compare_interval(cond, old_val.interval, False)
                    n_fall.locals[loaded_local] = ProductValue(refined_interval, old_val.nullness)
                
                yield n_fall.with_pc(nxt)
        return

    # ---------- IFNULL / IFNONNULL ----------
    if tname == "IfNull" or (tname == "Ifz" and "null" in str(getattr(op, "condition", "")).lower()):
        v = frame.stack.peek() if frame.stack else ProductValue.top()
        target = getattr(op, "target", None)
        loaded_local = _find_loaded_local_before(bc, pc)
        
        # Check if null branch is possible
        null_possible = v.nullness.is_top() or v.nullness.is_maybe_null()
        nonnull_possible = v.nullness.is_top() or v.nullness.is_definitely_non_null()
        
        # If definitely non-null, ifnull branch is dead
        if v.nullness.is_definitely_non_null():
            null_possible = False
        
        if null_possible and target is not None:
            target_offset = bc.index_to_offset(pc.method, int(target))
            n_taken = frame.copy()
            n_taken.stack.pop()
            
            if loaded_local is not None:
                old_val = n_taken.locals.get(loaded_local, ProductValue.top())
                n_taken.locals[loaded_local] = ProductValue(old_val.interval, NonNullDomain.maybe_null())
            
            yield n_taken.with_pc(PC(pc.method, target_offset))

        if nonnull_possible:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                n_fall = frame.copy()
                n_fall.stack.pop()
                
                if loaded_local is not None:
                    old_val = n_fall.locals.get(loaded_local, ProductValue.top())
                    n_fall.locals[loaded_local] = ProductValue(old_val.interval, NonNullDomain.definitely_non_null())
                
                yield n_fall.with_pc(nxt)
        return

    # ---------- IF (icmp) ----------
    if tname == "If":
        while len(frame.stack) < 2:
            frame.stack.push(ProductValue.top())
        
        right = frame.stack.items[-1]
        left = frame.stack.items[-2]
        cond = getattr(op, "condition", None)

        right_const = None
        if (right.interval.value.low is not None and right.interval.value.high is not None and
            right.interval.value.low == right.interval.value.high):
            right_const = right.interval.value.low

        if right_const is not None:
            poss = _eval_const_compare_interval(cond, left.interval, right_const)
        else:
            poss = {True, False}

        target = getattr(op, "target", None)
        loaded_local = _find_loaded_local_for_icmp(bc, pc)
        
        if True in poss and target is not None:
            target_offset = bc.index_to_offset(pc.method, int(target))
            n_taken = frame.copy()
            n_taken.stack.pop()
            n_taken.stack.pop()
            
            if loaded_local is not None and right_const is not None:
                old_val = n_taken.locals.get(loaded_local, ProductValue.top())
                refined = _refine_const_compare_interval(cond, old_val.interval, right_const, True)
                n_taken.locals[loaded_local] = ProductValue(refined, old_val.nullness)
            
            yield n_taken.with_pc(PC(pc.method, target_offset))

        if False in poss:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                n_fall = frame.copy()
                n_fall.stack.pop()
                n_fall.stack.pop()
                
                if loaded_local is not None and right_const is not None:
                    old_val = n_fall.locals.get(loaded_local, ProductValue.top())
                    refined = _refine_const_compare_interval(cond, old_val.interval, right_const, False)
                    n_fall.locals[loaded_local] = ProductValue(refined, old_val.nullness)
                
                yield n_fall.with_pc(nxt)
        return

    # ---------- GOTO ----------
    if tname == "Goto":
        n = frame.copy()
        target = getattr(op, "target", None)
        if target is not None:
            target_offset = bc.index_to_offset(pc.method, int(target))
            yield n.with_pc(PC(pc.method, target_offset))
        else:
            nxt = bc.next_pc(pc)
            if nxt is not None:
                yield n.with_pc(nxt)
        return

    # ---------- GET (fields) ----------
    if tname == "Get":
        n = frame.copy()
        static = bool(getattr(op, "static", False))

        if not static:
            if not n.stack:
                n.stack.push(ProductValue.top())
            recv = n.stack.pop()
            
            # If receiver is definitely non-null, no NPE
            if not recv.nullness.is_definitely_non_null():
                yield "null pointer"

        n.stack.push(ProductValue.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- PUT (fields) ----------
    if tname == "Put":
        n = frame.copy()
        static = bool(getattr(op, "static", False))

        # Pop the value to store
        if n.stack:
            _val = n.stack.pop()

        # Instance fields: pop receiver (may be null).
        if not static:
            if not n.stack:
                n.stack.push(ProductValue.top())
            recv = n.stack.pop()
            
            # If receiver is definitely non-null, no NPE
            if not recv.nullness.is_definitely_non_null():
                yield "null pointer"

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- NEW - produces definitely non-null reference ----------
    if tname == "New":
        n = frame.copy()
        cname = getattr(op, "classname", None)
        if cname is not None and getattr(cname, "slashed", lambda: "")() == "java/lang/AssertionError":
            pass
        else:
            n.stack.push(ProductValue.from_new())  # Definitely non-null!

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- ARRAYS ----------
    if tname == "NewArray":
        n = frame.copy()
        if n.stack:
            n.stack.pop()
        # New array is definitely non-null
        n.stack.push(ProductValue.from_new())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayLoad":
        n = frame.copy()
        while len(n.stack) < 2:
            n.stack.push(ProductValue.top())
        _idx = n.stack.pop()
        arr = n.stack.pop()
        
        if not arr.nullness.is_definitely_non_null():
            yield "null pointer"
        yield "out of bounds"
        
        n.stack.push(ProductValue.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayStore":
        n = frame.copy()
        while len(n.stack) < 3:
            n.stack.push(ProductValue.top())
        _val = n.stack.pop()
        _idx = n.stack.pop()
        arr = n.stack.pop()
        
        if not arr.nullness.is_definitely_non_null():
            yield "null pointer"
        yield "out of bounds"
        
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    if tname == "ArrayLength":
        n = frame.copy()
        if n.stack:
            arr = n.stack.pop()
            if not arr.nullness.is_definitely_non_null():
                yield "null pointer"
        # Length is >= 0
        n.stack.push(ProductValue(IntervalDomain.range(0, None), NonNullDomain.top()))
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- INVOKEs ----------
    if tname.startswith("Invoke"):
        n = frame.copy()

        def _desc(m):
            d = getattr(m, "desc", None)
            if d is not None:
                return list(getattr(d, "args", [])), getattr(d, "returns", None)
            ext = getattr(m, "extension", None)
            if ext is not None:
                return list(getattr(ext, "params", [])), getattr(ext, "return_type", None)
            return [], None

        method_obj = getattr(op, "method", None)
        arg_types, returns = _desc(method_obj)
        nargs = len(arg_types)

        access = getattr(op, "access", None)
        access_name = _name(access) if access is not None else ""
        is_static = "static" in access_name or tname == "InvokeStatic"
        
        if not is_static:
            nargs += 1

        while len(n.stack) < nargs:
            n.stack.push(ProductValue.top())
        
        # Pop args and check receiver for non-static
        args = [n.stack.pop() for _ in range(nargs)]
        
        if not is_static and args:
            receiver = args[-1]  # Last popped is first pushed (receiver)
            if not receiver.nullness.is_definitely_non_null():
                yield "null pointer"

        if returns is not None:
            n.stack.push(ProductValue.top())

        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- DUP ----------
    if tname == "Dup":
        n = frame.copy()
        if n.stack:
            n.stack.push(n.stack.peek())
        else:
            n.stack.push(ProductValue.top())
        nxt = bc.next_pc(pc)
        if nxt is not None:
            yield n.with_pc(nxt)
        return

    # ---------- THROW ----------
    if tname == "Throw":
        yield "assertion error"
        return

    # ---------- RETURN ----------
    if tname.endswith("Return") or tname == "Return":
        yield "ok"
        return

    # ---------- default: fallthrough ----------
    n = frame.copy()
    nxt = bc.next_pc(pc)
    if nxt is not None:
        yield n.with_pc(nxt)


def product_unbounded_run(
    suite: jpamb.Suite,
    method: jvm.AbsMethodID,
    init_locals: Dict[int, ProductValue] | None = None,
    widening_threshold: int = 3,
) -> Tuple[set[str], set[int]]:
    """
    Unbounded abstract interpretation using ProductValue (Interval + Nullness).
    
    This provides the most precise analysis by combining:
    - IntervalDomain for numeric comparisons
    - NonNullDomain for null checks
    
    Returns:
        Tuple of (final_outcomes, visited_pcs)
    """
    bc = Bytecode(suite)
    start = PC(method, 0)
    init = PerVarFrame(locals=dict(init_locals or {}), stack=Stack.empty(), pc=start)
    
    worklist: list[PC] = [start]
    state: Dict[PC, PerVarFrame[ProductValue]] = {start: init}
    join_counts: Dict[PC, int] = {start: 1}
    
    finals: set[str] = set()
    visited_pcs: set[int] = set()
    
    while worklist:
        pc = worklist.pop(0)
        visited_pcs.add(pc.offset)
        
        frame = state.get(pc)
        if frame is None:
            continue
        
        for out in product_astep(bc, frame):
            if isinstance(out, str):
                finals.add(out)
            else:
                target_pc = out.pc
                
                if target_pc in state:
                    old_frame = state[target_pc]
                    count = join_counts.get(target_pc, 0) + 1
                    join_counts[target_pc] = count
                    
                    if count > widening_threshold:
                        new_frame = _widen_product_frame(old_frame, out)
                    else:
                        new_frame = old_frame | out
                    
                    if not (new_frame <= old_frame):
                        state[target_pc] = new_frame
                        if target_pc not in worklist:
                            worklist.append(target_pc)
                else:
                    state[target_pc] = out
                    join_counts[target_pc] = 1
                    worklist.append(target_pc)
    
    return finals, visited_pcs


def _widen_product_frame(old: PerVarFrame[ProductValue], new: PerVarFrame[ProductValue]) -> PerVarFrame[ProductValue]:
    """Apply widening to a product frame."""
    widened_locals: Dict[int, ProductValue] = {}
    all_keys = set(old.locals) | set(new.locals)
    for idx in all_keys:
        v_old = old.locals.get(idx, ProductValue.bottom())
        v_new = new.locals.get(idx, ProductValue.bottom())
        widened_locals[idx] = v_old.widening(v_new)
    
    widened_stack_items = []
    for s_old, s_new in zip(old.stack, new.stack):
        widened_stack_items.append(s_old.widening(s_new))
    
    return PerVarFrame(widened_locals, Stack(widened_stack_items), old.pc)
