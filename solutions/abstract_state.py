# solutions/ai_state.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Generic, Iterator, List, TypeVar

import jpamb
from jpamb import jvm

AV = TypeVar("AV")  # abstract value type


# --- Tiny stack wrapper ------------------------------------------------------


@dataclass
class Stack(Generic[AV]):
    items: List[AV]

    @classmethod
    def empty(cls) -> "Stack[AV]":
        return cls([])

    def push(self, value: AV) -> None:
        self.items.append(value)

    def pop(self) -> AV:
        return self.items.pop()

    def peek(self) -> AV:
        return self.items[-1]

    def __len__(self) -> int:  # trivial
        return len(self.items)

    def __bool__(self) -> bool:  # trivial
        return bool(self.items)

    def copy(self) -> "Stack[AV]":
        # shallow copy is enough; AV is assumed immutable
        return Stack(list(self.items))

    def __iter__(self) -> Iterator[AV]:
        return iter(self.items)

    def __repr__(self) -> str:  # cosmetic only
        if not self.items:
            return "ϵ"
        return "[" + ", ".join(repr(v) for v in self.items) + "]"


# --- Program counter ---------------------------------------------------------


@dataclass(frozen=True)
class PC:
    """
    JVM-style program counter: (method, bytecode offset)
    """
    method: jvm.AbsMethodID
    offset: int

    def next(self, delta: int = 1) -> "PC":
        # Note: "delta" is a bytecode offset delta, not a list index.
        return PC(self.method, self.offset + delta)

    def __str__(self) -> str:  # cosmetic only
        return f"{self.method}:{self.offset}"


# --- Lazy bytecode cache (exact offset mapping) ------------------------------


@dataclass
class Bytecode:
    """
    Helper that lets us index bytecode by (method, offset).

    For each method we cache:
      * the list of opcodes in bytecode order, and
      * a mapping offset -> index into that list
    """

    suite: jpamb.Suite
    _ops: Dict[jvm.AbsMethodID, List[jvm.Opcode]] | None = None
    _idx: Dict[jvm.AbsMethodID, Dict[int, int]] | None = None
    _sorted_offsets: Dict[jvm.AbsMethodID, List[int]] | None = None

    def __post_init__(self) -> None:
        if self._ops is None:
            self._ops = {}
        if self._idx is None:
            self._idx = {}
        if self._sorted_offsets is None:
            self._sorted_offsets = {}

    # Internal helpers --------------------------------------------------------

    def _ensure(self, method: jvm.AbsMethodID) -> None:
        """
        Lazily populate caches for a method.
        """
        assert self._ops is not None and self._idx is not None and self._sorted_offsets is not None
        if method in self._ops:
            return

        ops = list(self.suite.method_opcodes(method))
        self._ops[method] = ops

        idx: Dict[int, int] = {}
        so: List[int] = []
        for i, op in enumerate(ops):
            # jpamb exposes the actual bytecode offset as op.offset.
            off = int(getattr(op, "offset", 0))
            idx[off] = i
            so.append(off)
        so.sort()

        self._idx[method] = idx
        self._sorted_offsets[method] = so

    # Public API --------------------------------------------------------------

    def __getitem__(self, pc: PC) -> jvm.Opcode:
        """
        Look up the opcode at a given (method, offset).

        If the offset does not correspond to an opcode (e.g. broken jump
        target) we raise IndexError; the abstract interpreter treats that as
        a terminated path.
        """
        self._ensure(pc.method)
        assert self._ops is not None and self._idx is not None
        idx = self._idx[pc.method].get(pc.offset)
        if idx is None:
            raise IndexError(f"no opcode at offset {pc.offset}")
        return self._ops[pc.method][idx]  # type: ignore[index]

    def next_pc(self, pc: PC) -> PC | None:
        """
        Successor program counter for fall‑through control flow.

        We do *not* guess if the given offset has no exact successor, because
        jpamb's offsets are exact; a missing successor just means the path
        terminates.
        """
        self._ensure(pc.method)
        assert self._sorted_offsets is not None
        so = self._sorted_offsets[pc.method]
        # find smallest offset > pc.offset
        for off in so:
            if off > pc.offset:
                return PC(pc.method, off)
        return None

    def index_to_offset(self, method: jvm.AbsMethodID, index: int) -> int:
        """
        Convert instruction index to byte offset.
        
        In jpamb's bytecode JSON, jump targets are specified as instruction
        indices (0-based position in the bytecode list), but PCs use byte
        offsets. This method converts from index to offset.
        
        Args:
            method: The method containing the instruction
            index: The instruction index (0-based)
            
        Returns:
            The byte offset of the instruction at that index
        """
        self._ensure(method)
        assert self._ops is not None
        ops = self._ops[method]
        if 0 <= index < len(ops):
            return int(getattr(ops[index], "offset", 0))
        # If index is out of bounds, return it as-is (may cause IndexError later)
        return index


# --- Per‑instruction abstract frame -----------------------------------------


@dataclass
class PerVarFrame(Generic[AV]):
    """
    Abstract frame:

      * locals: mapping from local index -> abstract value
      * stack:  abstract operand stack
      * pc:     current program counter

    Order: pointwise ≤ over locals and stack.  The JVM verifier guarantees
    consistent stack heights per program point; the unbounded analysis relies
    on that.
    """

    locals: Dict[int, AV]
    stack: Stack[AV]
    pc: PC

    # Lattice order: pointwise ≤ over locals and stack.
    def __le__(self, other: "PerVarFrame[AV]") -> bool:
        if self.pc != other.pc:
            return False

        # Locals: for every local we know about, the other frame must know
        # at least as much.
        for idx, v in self.locals.items():
            ov = other.locals.get(idx)
            if ov is None:
                return False
            if not (v <= ov):  # type: ignore[operator]
                return False

        # Operand stack: same height, pointwise ≤.
        if len(self.stack) != len(other.stack):
            return False
        for v1, v2 in zip(self.stack, other.stack):
            if not (v1 <= v2):  # type: ignore[operator]
                return False
        return True

    # Pointwise join ----------------------------------------------------------

    def join(self, other: "PerVarFrame[AV]") -> "PerVarFrame[AV]":
        assert self.pc == other.pc

        # locals
        new_locals: Dict[int, AV] = {}
        all_keys = set(self.locals) | set(other.locals)
        for idx in all_keys:
            v1 = self.locals.get(idx)
            v2 = other.locals.get(idx)
            if v1 is None:
                assert v2 is not None
                new_locals[idx] = v2
            elif v2 is None:
                new_locals[idx] = v1
            else:
                new_locals[idx] = v1 | v2  # type: ignore[operator]

        # stack (same height at the same pc)
        assert len(self.stack) == len(other.stack)
        joined_stack = [a | b for a, b in zip(self.stack, other.stack)]  # type: ignore[operator]
        return PerVarFrame(new_locals, Stack(joined_stack), self.pc)

    def __or__(self, other: "PerVarFrame[AV]") -> "PerVarFrame[AV]":
        return self.join(other)

    # Utilities ---------------------------------------------------------------

    def copy(self) -> "PerVarFrame[AV]":
        return PerVarFrame(dict(self.locals), self.stack.copy(), self.pc)

    def with_pc(self, pc: PC) -> "PerVarFrame[AV]":
        f = self.copy()
        f.pc = pc
        return f
