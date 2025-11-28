# solutions/abstract_domain.py
"""
Abstract domains for JPAMB static analysis.

This module provides:
- SignSet: A 3-value sign domain ({"+", "0", "-"}) for integer sign analysis
- SignArithmetic: Arithmetic operations on SignSet
- IntervalDomain: Interval domain for integer range analysis
- IntervalArithmetic: Arithmetic operations on IntervalDomain
- NonNullDomain: A nullness domain for reference analysis (IAB novel abstraction)
- NullnessValue: Enum for nullness lattice elements
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Literal, Optional, TypeAlias


# --- Sign abstract domain ----------------------------------------------------


Sign: TypeAlias = Literal["+", "0", "-"]


@dataclass(frozen=True)
class SignSet:
    """
    Sign abstraction for integers:

      "+"   – positive
      "0"   – zero
      "-"   – negative

    Lattice order:   subset on the underlying sign sets
    Bottom element:  ⊥ = ∅
    Top element:     ⊤ = {"+", "0", "-"}
    """

    signs: FrozenSet[Sign]

    # Constructors / special elements -----------------------------------------

    @classmethod
    def bottom(cls) -> "SignSet":
        """The impossible abstract value."""
        return cls(frozenset())

    @classmethod
    def top(cls) -> "SignSet":
        """The completely unknown integer."""
        return cls(frozenset({"+", "0", "-"}))

    @classmethod
    def const(cls, n: int) -> "SignSet":
        """Abstract a single concrete integer."""
        if n == 0:
            s = {"0"}
        elif n > 0:
            s = {"+"}
        else:
            s = {"-"}
        return cls(frozenset(s))

    @classmethod
    def abstract(cls, values: Iterable[int]) -> "SignSet":
        """Best abstraction of a finite set of integers."""
        s: set[Sign] = set()
        for v in values:
            if v == 0:
                s.add("0")
            elif v > 0:
                s.add("+")
            else:
                s.add("-")
        return cls(frozenset(s))

    # Lattice structure -------------------------------------------------------

    def is_bottom(self) -> bool:
        return not self.signs

    def is_top(self) -> bool:
        return self.signs == {"+", "0", "-"}

    def __bool__(self) -> bool:
        # bool(⊥) is False, everything else is True.
        return bool(self.signs)

    def __le__(self, other: "SignSet") -> bool:
        return self.signs.issubset(other.signs)

    def __or__(self, other: "SignSet") -> "SignSet":
        return SignSet(self.signs | other.signs)

    def __and__(self, other: "SignSet") -> "SignSet":
        return SignSet(self.signs & other.signs)

    # Convenience -------------------------------------------------------------

    def __contains__(self, n: int) -> bool:
        """
        n ∈ self  iff  sign(n) ∈ self.signs
        """
        if n == 0:
            return "0" in self.signs
        if n > 0:
            return "+" in self.signs
        return "-" in self.signs

    def __repr__(self) -> str:  # cosmetic
        if not self.signs:
            return "⊥"
        if self.signs == {"+", "0", "-"}:
            return "⊤"
        return "{" + ",".join(sorted(self.signs)) + "}"


class SignArithmetic:
    """
    Operations enumerate all combinations of operand signs.  This keeps
    things simple and guarantees monotonicity for the unbounded analysis
    """

    @staticmethod
    def add(a: SignSet, b: SignSet) -> SignSet:
        if a.is_bottom() or b.is_bottom():
            return SignSet.bottom()

        out: set[Sign] = set()
        for sa in a.signs:
            for sb in b.signs:
                match (sa, sb):
                    case ("0", "0"):
                        out.add("0")
                    case ("0", "+") | ("+", "0") | ("+", "+"):
                        out.add("+")
                    case ("0", "-") | ("-", "0") | ("-", "-"):
                        out.add("-")
                    case ("+", "-") | ("-", "+"):
                        out.update({"+", "0", "-"})
        return SignSet(frozenset(out)) if out else SignSet.bottom()

    @staticmethod
    def sub(a: SignSet, b: SignSet) -> SignSet:
        if a.is_bottom() or b.is_bottom():
            return SignSet.bottom()

        m = {"+": "-", "-": "+", "0": "0"}
        neg_b = SignSet(frozenset(m[s] for s in b.signs))
        return SignArithmetic.add(a, neg_b)

    @staticmethod
    def mul(a: SignSet, b: SignSet) -> SignSet:
        if a.is_bottom() or b.is_bottom():
            return SignSet.bottom()

        out: set[Sign] = set()
        for sa in a.signs:
            for sb in b.signs:
                match (sa, sb):
                    case ("0", _) | (_, "0"):
                        out.add("0")
                    case ("+", "+") | ("-", "-"):
                        out.add("+")
                    case ("+", "-") | ("-", "+"):
                        out.add("-")
        return SignSet(frozenset(out)) if out else SignSet.bottom()

    @staticmethod
    def div(a: SignSet, b: SignSet) -> tuple[SignSet, bool]:
        """
        Abstract division a / b.

        Returns:
          (result_signs, may_divide_by_zero)

        The result only accounts for the non‑zero divisor cases; if the
        divisor is definitely zero, the result is ⊥
        """
        if a.is_bottom() or b.is_bottom():
            return (SignSet.bottom(), False)

        out: set[Sign] = set()
        may_div_zero = "0" in b.signs
        non_zero_b = SignSet(frozenset(s for s in b.signs if s != "0"))

        for sa in a.signs:
            for sb in non_zero_b.signs:
                match (sa, sb):
                    case ("0", _):
                        out.add("0")
                    case ("+", "+") | ("-", "-"):
                        out.add("+")
                    case ("+", "-") | ("-", "+"):
                        out.add("-")
        return (SignSet(frozenset(out)) if out else SignSet.bottom(), may_div_zero)

    @staticmethod
    def rem(a: SignSet, b: SignSet) -> tuple[SignSet, bool]:
        """
        Abstract remainder a % b

        JVM requires b != 0 at runtime; we flag if b might be 0.
        Sign of the remainder follows the dividend (except it can be 0)

        As with div, the result only accounts for the non‑zero divisor
        cases; if the divisor is definitely zero, the result is ⊥
        """
        if a.is_bottom() or b.is_bottom():
            return (SignSet.bottom(), False)

        may_div_zero = "0" in b.signs

        # If we only know that b == 0 then there is no non‑exceptional case.
        non_zero_possible = any(s != "0" for s in b.signs)
        if not non_zero_possible:
            return (SignSet.bottom(), may_div_zero)

        out: set[Sign] = set()
        for sa in a.signs:
            if sa == "0":
                out.add("0")
            elif sa == "+":
                out.update({"+", "0"})
            elif sa == "-":
                out.update({"-", "0"})
        return (SignSet(frozenset(out)) if out else SignSet.bottom(), may_div_zero)

    @staticmethod
    def neg(a: SignSet) -> SignSet:
        """
        Unary negate
        """
        if a.is_bottom():
            return SignSet.bottom()

        m = {"+": "-", "-": "+", "0": "0"}
        return SignSet(frozenset(m[s] for s in a.signs))


# --- Interval abstract domain ------------------------------------------------


@dataclass(frozen=True)
class IntervalValue:
    """
    Interval bounds representation.
    
    None represents infinity (-∞ for low, +∞ for high).
    """
    low: Optional[int]   # None represents -∞
    high: Optional[int]  # None represents +∞
    
    def __post_init__(self):
        # Validate interval bounds - but allow creation of BOTTOM during class definition
        if (self.low is not None and self.high is not None and 
            self.low > self.high and not (self.low == 1 and self.high == 0)):
            raise ValueError(f"Invalid interval: [{self.low}, {self.high}]")
    
    def __str__(self):
        low_str = "-∞" if self.low is None else str(self.low)
        high_str = "+∞" if self.high is None else str(self.high)
        return f"[{low_str}, {high_str}]"
    
    def is_bottom(self) -> bool:
        """Check if this is the bottom element (empty interval)."""
        return (self.low is not None and self.high is not None and 
                self.low > self.high)
    
    def is_top(self) -> bool:
        """Check if this is the top element (unbounded interval)."""
        return self.low is None and self.high is None
    
    def contains(self, value: int) -> bool:
        """Check if value is contained in this interval."""
        if self.is_bottom():
            return False
        low_ok = self.low is None or value >= self.low
        high_ok = self.high is None or value <= self.high
        return low_ok and high_ok


@dataclass
class IntervalDomain:
    """
    Interval domain for integer values.
    
    Represents ranges of integers with optional bounds.
    Supports lattice operations (join, meet, widening) and arithmetic.
    """
    value: IntervalValue
    
    # Class-level constants (must be set after class definition)
    BOTTOM: "IntervalValue"
    TOP: "IntervalValue"
    
    def __init__(self, value: Optional[IntervalValue] = None):
        if value is None:
            self.value = IntervalValue(None, None)  # TOP
        else:
            self.value = value
    
    @classmethod
    def bottom(cls) -> "IntervalDomain":
        """The impossible abstract value (empty interval)."""
        return cls(IntervalValue(1, 0))
    
    @classmethod
    def top(cls) -> "IntervalDomain":
        """The completely unknown integer (unbounded)."""
        return cls(IntervalValue(None, None))
    
    @classmethod
    def const(cls, n: int) -> "IntervalDomain":
        """Abstract a single concrete integer."""
        return cls(IntervalValue(n, n))
    
    @classmethod
    def range(cls, low: Optional[int], high: Optional[int]) -> "IntervalDomain":
        """Create an interval with given bounds."""
        return cls(IntervalValue(low, high))
    
    @classmethod
    def abstract(cls, values: Iterable[int]) -> "IntervalDomain":
        """Best abstraction of a finite set of integers."""
        vals = list(values)
        if not vals:
            return cls.bottom()
        return cls(IntervalValue(min(vals), max(vals)))
    
    def __str__(self):
        return str(self.value)
    
    def __repr__(self):
        return f"IntervalDomain({self.value})"
    
    def __eq__(self, other):
        if not isinstance(other, IntervalDomain):
            return False
        return (self.value.low == other.value.low and 
                self.value.high == other.value.high)
    
    def __hash__(self):
        return hash((self.value.low, self.value.high))
    
    def is_bottom(self) -> bool:
        return self.value.is_bottom()
    
    def is_top(self) -> bool:
        return self.value.is_top()
    
    def __bool__(self) -> bool:
        return not self.is_bottom()
    
    def __le__(self, other: "IntervalDomain") -> bool:
        """Check if self is a subset of other."""
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        
        low_ok = (other.value.low is None or 
                  (self.value.low is not None and self.value.low >= other.value.low))
        high_ok = (other.value.high is None or 
                   (self.value.high is not None and self.value.high <= other.value.high))
        return low_ok and high_ok
    
    def __or__(self, other: "IntervalDomain") -> "IntervalDomain":
        """Join (union) operation."""
        return self.join(other)
    
    def __and__(self, other: "IntervalDomain") -> "IntervalDomain":
        """Meet (intersection) operation."""
        return self.meet(other)
    
    def __contains__(self, n: int) -> bool:
        """Check if n is in this interval."""
        return self.value.contains(n)
    
    def join(self, other: "IntervalDomain") -> "IntervalDomain":
        """Union of two intervals (least upper bound)."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        
        # Union: take minimum of lows and maximum of highs
        new_low = None
        if self.value.low is None or other.value.low is None:
            new_low = None
        else:
            new_low = min(self.value.low, other.value.low)
        
        new_high = None
        if self.value.high is None or other.value.high is None:
            new_high = None
        else:
            new_high = max(self.value.high, other.value.high)
        
        return IntervalDomain(IntervalValue(new_low, new_high))
    
    def meet(self, other: "IntervalDomain") -> "IntervalDomain":
        """Intersection of two intervals (greatest lower bound)."""
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        
        # Intersection: take maximum of lows and minimum of highs
        new_low = None
        if self.value.low is None:
            new_low = other.value.low
        elif other.value.low is None:
            new_low = self.value.low
        else:
            new_low = max(self.value.low, other.value.low)
        
        new_high = None
        if self.value.high is None:
            new_high = other.value.high
        elif other.value.high is None:
            new_high = self.value.high
        else:
            new_high = min(self.value.high, other.value.high)
        
        # Check if intersection is empty
        if (new_low is not None and new_high is not None and new_low > new_high):
            return IntervalDomain.bottom()
        
        return IntervalDomain(IntervalValue(new_low, new_high))
    
    def widening(self, other: "IntervalDomain") -> "IntervalDomain":
        """
        Widening operator for ensuring termination in loops.
        
        IBA (Implement Unbounded Static Analysis) - 7 points
        
        Classic interval widening: when a bound is unstable (changes between 
        iterations), immediately extrapolate to infinity (-∞ or +∞).
        
        Algorithm:
            old ∇ new = 
                low:  -∞ if new.low < old.low else old.low
                high: +∞ if new.high > old.high else old.high
        
        This guarantees termination because:
        - The lattice of intervals with {-∞, +∞} is finite height
        - Widening can only increase to ±∞ (never oscillates)
        
        Example:
            [0,0] ∇ [0,1] = [0, +∞]   (high increased → widen to +∞)
            [0,5] ∇ [-1,5] = [-∞, 5]  (low decreased → widen to -∞)
            [0,5] ∇ [-1,10] = [-∞, +∞] (both changed → TOP)
        
        Args:
            other: The new interval from the current iteration
            
        Returns:
            Widened interval that guarantees termination
        """
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        
        # Widening: if bound decreases/increases, make it infinite
        new_low = self.value.low
        new_high = self.value.high
        
        # If other's low bound is smaller (or becomes unbounded), widen to -∞
        if other.value.low is None:
            new_low = None
        elif self.value.low is not None and other.value.low < self.value.low:
            new_low = None
        
        # If other's high bound is larger (or becomes unbounded), widen to +∞
        if other.value.high is None:
            new_high = None
        elif self.value.high is not None and other.value.high > self.value.high:
            new_high = None
        
        return IntervalDomain(IntervalValue(new_low, new_high))
    
    def narrowing(self, other: "IntervalDomain") -> "IntervalDomain":
        """
        Narrowing operator for improving precision after widening.
        
        IBA (Implement Unbounded Static Analysis) - 7 points
        
        After fixpoint is reached with widening, narrowing can recover some
        precision by iterating once more with meet operations, replacing 
        infinite bounds with finite ones if the other interval has them.
        
        Algorithm:
            old Δ new =
                low:  new.low if old.low == -∞ and new.low is finite else old.low
                high: new.high if old.high == +∞ and new.high is finite else old.high
        
        This is sound because:
        - We only narrow infinite bounds to finite ones
        - The finite bound comes from a sound analysis (the iteration step)
        - old ⊇ new is a precondition (new is more precise)
        
        Example:
            [-∞, +∞] Δ [0, 100] = [0, 100]  (both bounds recovered)
            [-∞, 10] Δ [0, 10] = [0, 10]    (low bound recovered)
            [0, +∞] Δ [0, 50] = [0, 50]     (high bound recovered)
        
        Args:
            other: The interval from the narrowing iteration
            
        Returns:
            Narrowed interval with improved precision
        """
        if self.is_bottom():
            return self
        if other.is_bottom():
            return other  # Narrowing to bottom is valid
        
        new_low = self.value.low
        new_high = self.value.high
        
        # Narrow low bound: if self is -∞ and other has a finite bound, use it
        if self.value.low is None and other.value.low is not None:
            new_low = other.value.low
        
        # Narrow high bound: if self is +∞ and other has a finite bound, use it
        if self.value.high is None and other.value.high is not None:
            new_high = other.value.high
        
        return IntervalDomain(IntervalValue(new_low, new_high))


class IntervalArithmetic:
    """Arithmetic operations on IntervalDomain."""
    
    @staticmethod
    def add(a: IntervalDomain, b: IntervalDomain) -> IntervalDomain:
        """Addition: [a,b] + [c,d] = [a+c, b+d]."""
        if a.is_bottom() or b.is_bottom():
            return IntervalDomain.bottom()
        
        new_low = None
        if a.value.low is not None and b.value.low is not None:
            new_low = a.value.low + b.value.low
        
        new_high = None
        if a.value.high is not None and b.value.high is not None:
            new_high = a.value.high + b.value.high
        
        return IntervalDomain(IntervalValue(new_low, new_high))
    
    @staticmethod
    def sub(a: IntervalDomain, b: IntervalDomain) -> IntervalDomain:
        """Subtraction: [a,b] - [c,d] = [a-d, b-c]."""
        if a.is_bottom() or b.is_bottom():
            return IntervalDomain.bottom()
        
        new_low = None
        if a.value.low is not None and b.value.high is not None:
            new_low = a.value.low - b.value.high
        
        new_high = None
        if a.value.high is not None and b.value.low is not None:
            new_high = a.value.high - b.value.low
        
        return IntervalDomain(IntervalValue(new_low, new_high))
    
    @staticmethod
    def mul(a: IntervalDomain, b: IntervalDomain) -> IntervalDomain:
        """Multiplication: compute all corner products."""
        if a.is_bottom() or b.is_bottom():
            return IntervalDomain.bottom()
        
        # Handle unbounded cases
        if a.is_top() or b.is_top():
            return IntervalDomain.top()
        
        # Bounded case: [a,b] * [c,d] = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)]
        if (a.value.low is None or a.value.high is None or
            b.value.low is None or b.value.high is None):
            return IntervalDomain.top()
        
        products = [
            a.value.low * b.value.low,
            a.value.low * b.value.high,
            a.value.high * b.value.low,
            a.value.high * b.value.high
        ]
        
        return IntervalDomain(IntervalValue(min(products), max(products)))
    
    @staticmethod
    def div(a: IntervalDomain, b: IntervalDomain) -> tuple[IntervalDomain, bool]:
        """
        Division a / b.
        Returns (result, may_divide_by_zero).
        """
        if a.is_bottom() or b.is_bottom():
            return (IntervalDomain.bottom(), False)
        
        may_div_zero = 0 in b
        
        # Conservative: if divisor may include zero, result is TOP
        if may_div_zero:
            return (IntervalDomain.top(), True)
        
        # Both bounded and non-zero divisor
        if (a.value.low is None or a.value.high is None or
            b.value.low is None or b.value.high is None):
            return (IntervalDomain.top(), False)
        
        # Compute division bounds
        quotients = [
            a.value.low // b.value.low,
            a.value.low // b.value.high,
            a.value.high // b.value.low,
            a.value.high // b.value.high
        ]
        
        return (IntervalDomain(IntervalValue(min(quotients), max(quotients))), False)
    
    @staticmethod
    def neg(a: IntervalDomain) -> IntervalDomain:
        """Unary negate: -[a,b] = [-b, -a]."""
        if a.is_bottom():
            return IntervalDomain.bottom()
        
        new_low = None if a.value.high is None else -a.value.high
        new_high = None if a.value.low is None else -a.value.low
        
        return IntervalDomain(IntervalValue(new_low, new_high))


# --- NonNull abstract domain (IAB: Novel Abstraction) ------------------------
#
# This domain tracks whether a reference is definitely non-null, possibly null,
# or definitely null. It is NOT taught in DTU 02242 lectures (Sign, Interval,
# Constant, Parity are taught), making it eligible for IAB points.
#
# Lattice structure:
#
#                    TOP (unknown nullness)
#                   /   \
#    DEFINITELY_NON_NULL  MAYBE_NULL
#                   \   /
#                   BOTTOM (unreachable)
#
# Note: This is a different lattice from the lecture domains. In particular,
# DEFINITELY_NON_NULL and MAYBE_NULL are incomparable (neither subsumes the other).


from enum import Enum, auto


class NullnessValue(Enum):
    """
    Nullness lattice element values.
    
    Lattice structure (4-element diamond):
        TOP = unknown/any nullness
        DEFINITELY_NON_NULL = known to be not null
        MAYBE_NULL = may or may not be null (includes definitely null)
        BOTTOM = unreachable/impossible
        
    Note: DEFINITELY_NON_NULL and MAYBE_NULL are incomparable.
    Their join is TOP, their meet is BOTTOM.
    """
    BOTTOM = auto()              # Unreachable / impossible
    DEFINITELY_NON_NULL = auto() # Known to be non-null (e.g., after 'new')
    MAYBE_NULL = auto()          # May be null (includes aconst_null)
    TOP = auto()                 # Unknown / any reference


@dataclass(frozen=True)
class NonNullDomain:
    """
    NonNull Domain for reference nullness analysis.
    
    This is a NOVEL abstraction NOT taught in DTU 02242 lectures, making it
    eligible for IAB (Implement Novel Abstractions) points.
    
    The domain tracks whether object references are:
    - DEFINITELY_NON_NULL: guaranteed non-null (e.g., result of 'new')
    - MAYBE_NULL: possibly null (e.g., parameter, aconst_null)
    - TOP: unknown (conservative default)
    - BOTTOM: unreachable code
    
    Key use cases:
    1. Dead code elimination: if ref is DEFINITELY_NON_NULL, then
       ifnull branch is dead (unreachable).
    2. Null pointer exception analysis: if ref is DEFINITELY_NON_NULL,
       getfield/invokevirtual cannot throw NPE.
    3. Array analysis integration: if array is DEFINITELY_NON_NULL,
       arraylength is safe (only out-of-bounds possible).
    
    Transfer functions:
    - new / anewarray → DEFINITELY_NON_NULL
    - aconst_null → MAYBE_NULL  
    - ifnull branch: if taken → MAYBE_NULL, if not taken → DEFINITELY_NON_NULL
    - ifnonnull branch: if taken → DEFINITELY_NON_NULL, if not taken → MAYBE_NULL
    """
    
    value: NullnessValue
    
    # --- Constructors / special elements ---
    
    @classmethod
    def bottom(cls) -> "NonNullDomain":
        """Unreachable / impossible value."""
        return cls(NullnessValue.BOTTOM)
    
    @classmethod
    def top(cls) -> "NonNullDomain":
        """Unknown nullness (conservative)."""
        return cls(NullnessValue.TOP)
    
    @classmethod
    def definitely_non_null(cls) -> "NonNullDomain":
        """Definitely not null (e.g., after 'new')."""
        return cls(NullnessValue.DEFINITELY_NON_NULL)
    
    @classmethod
    def maybe_null(cls) -> "NonNullDomain":
        """May be null (includes definitely null)."""
        return cls(NullnessValue.MAYBE_NULL)
    
    @classmethod
    def from_new(cls) -> "NonNullDomain":
        """Result of 'new' instruction → definitely non-null."""
        return cls.definitely_non_null()
    
    @classmethod
    def from_null_constant(cls) -> "NonNullDomain":
        """Result of 'aconst_null' instruction → maybe null."""
        return cls.maybe_null()
    
    # --- Lattice predicates ---
    
    def is_bottom(self) -> bool:
        """Check if this is the bottom element."""
        return self.value == NullnessValue.BOTTOM
    
    def is_top(self) -> bool:
        """Check if this is the top element."""
        return self.value == NullnessValue.TOP
    
    def is_definitely_non_null(self) -> bool:
        """Check if definitely non-null."""
        return self.value == NullnessValue.DEFINITELY_NON_NULL
    
    def is_maybe_null(self) -> bool:
        """Check if possibly null."""
        return self.value == NullnessValue.MAYBE_NULL
    
    def __bool__(self) -> bool:
        """bool(⊥) is False, everything else is True."""
        return self.value != NullnessValue.BOTTOM
    
    # --- Lattice operations ---
    
    def __le__(self, other: "NonNullDomain") -> bool:
        """
        Lattice ordering:
            BOTTOM ≤ everything
            everything ≤ TOP
            DEFINITELY_NON_NULL ≤ TOP
            MAYBE_NULL ≤ TOP
            DEFINITELY_NON_NULL and MAYBE_NULL are incomparable
        """
        if self.value == NullnessValue.BOTTOM:
            return True
        if other.value == NullnessValue.TOP:
            return True
        if self.value == NullnessValue.TOP:
            return other.value == NullnessValue.TOP
        # Same value
        return self.value == other.value
    
    def __or__(self, other: "NonNullDomain") -> "NonNullDomain":
        """
        Join (least upper bound).
        
        Join table:
            ⊥ ⊔ x = x
            x ⊔ ⊤ = ⊤
            NON_NULL ⊔ NON_NULL = NON_NULL
            MAYBE_NULL ⊔ MAYBE_NULL = MAYBE_NULL
            NON_NULL ⊔ MAYBE_NULL = ⊤  (incomparable → go to TOP)
        """
        # Bottom is identity for join
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        
        # Top absorbs in join
        if self.is_top() or other.is_top():
            return NonNullDomain.top()
        
        # Same values
        if self.value == other.value:
            return self
        
        # Incomparable: DEFINITELY_NON_NULL ⊔ MAYBE_NULL = TOP
        return NonNullDomain.top()
    
    def __and__(self, other: "NonNullDomain") -> "NonNullDomain":
        """
        Meet (greatest lower bound).
        
        Meet table:
            ⊤ ⊓ x = x
            x ⊓ ⊥ = ⊥
            NON_NULL ⊓ NON_NULL = NON_NULL
            MAYBE_NULL ⊓ MAYBE_NULL = MAYBE_NULL
            NON_NULL ⊓ MAYBE_NULL = ⊥  (incomparable → go to BOTTOM)
        """
        # Top is identity for meet
        if self.is_top():
            return other
        if other.is_top():
            return self
        
        # Bottom absorbs in meet
        if self.is_bottom() or other.is_bottom():
            return NonNullDomain.bottom()
        
        # Same values
        if self.value == other.value:
            return self
        
        # Incomparable: DEFINITELY_NON_NULL ⊓ MAYBE_NULL = BOTTOM
        return NonNullDomain.bottom()
    
    def widening(self, other: "NonNullDomain") -> "NonNullDomain":
        """
        Widening for fixpoint computation.
        
        For this finite lattice (4 elements), widening = join is sufficient
        to guarantee termination.
        """
        return self | other
    
    # --- Branch refinement operations ---
    
    def refine_ifnull_true(self) -> "NonNullDomain":
        """
        Refine when ifnull branch is taken (value IS null).
        
        If we reach this branch, the reference was null → MAYBE_NULL.
        (We use MAYBE_NULL because the domain doesn't have DEFINITELY_NULL.)
        """
        if self.is_bottom():
            return self
        if self.is_definitely_non_null():
            # Contradiction: definitely non-null but ifnull taken → BOTTOM
            return NonNullDomain.bottom()
        return NonNullDomain.maybe_null()
    
    def refine_ifnull_false(self) -> "NonNullDomain":
        """
        Refine when ifnull branch is NOT taken (value is NOT null).
        
        If we fall through ifnull, the reference was non-null → DEFINITELY_NON_NULL.
        """
        if self.is_bottom():
            return self
        if self.is_maybe_null():
            # Refine: we now know it's not null
            return NonNullDomain.definitely_non_null()
        return NonNullDomain.definitely_non_null()
    
    def refine_ifnonnull_true(self) -> "NonNullDomain":
        """
        Refine when ifnonnull branch is taken (value is NOT null).
        
        → DEFINITELY_NON_NULL
        """
        if self.is_bottom():
            return self
        return NonNullDomain.definitely_non_null()
    
    def refine_ifnonnull_false(self) -> "NonNullDomain":
        """
        Refine when ifnonnull branch is NOT taken (value IS null).
        
        → MAYBE_NULL (the value is null)
        """
        if self.is_bottom():
            return self
        if self.is_definitely_non_null():
            # Contradiction: definitely non-null but ifnonnull not taken → BOTTOM
            return NonNullDomain.bottom()
        return NonNullDomain.maybe_null()
    
    # --- Dead code detection helpers ---
    
    def ifnull_definitely_false(self) -> bool:
        """
        Returns True if 'ifnull' branch can NEVER be taken.
        
        This is the key method for dead code elimination:
        if the reference is DEFINITELY_NON_NULL, the ifnull branch is dead.
        """
        return self.is_definitely_non_null()
    
    def ifnull_definitely_true(self) -> bool:
        """
        Returns True if 'ifnull' branch is ALWAYS taken.
        
        We can only determine this if we had a DEFINITELY_NULL value,
        but our lattice uses MAYBE_NULL which includes both null and non-null.
        For MAYBE_NULL, the branch may or may not be taken.
        """
        # Conservative: we cannot prove ifnull is always taken
        # because MAYBE_NULL includes non-null possibilities
        return False
    
    def ifnonnull_definitely_false(self) -> bool:
        """
        Returns True if 'ifnonnull' branch can NEVER be taken.
        
        Similar to ifnull_definitely_true, we'd need DEFINITELY_NULL.
        """
        # Conservative: we cannot prove this
        return False
    
    def ifnonnull_definitely_true(self) -> bool:
        """
        Returns True if 'ifnonnull' branch is ALWAYS taken.
        
        If the reference is DEFINITELY_NON_NULL, ifnonnull is always taken.
        """
        return self.is_definitely_non_null()
    
    def may_be_null(self) -> bool:
        """
        Returns True if a NullPointerException is possible.
        
        Used to determine if getfield/invokevirtual/arraylength can throw NPE.
        """
        if self.is_bottom():
            return False
        if self.is_definitely_non_null():
            return False
        return True  # TOP or MAYBE_NULL → NPE possible
    
    # --- Representation ---
    
    def __repr__(self) -> str:
        if self.is_bottom():
            return "⊥"
        if self.is_top():
            return "⊤"
        if self.is_definitely_non_null():
            return "NonNull"
        if self.is_maybe_null():
            return "MaybeNull"
        return f"NonNullDomain({self.value})"
    
    def __str__(self) -> str:
        return repr(self)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NonNullDomain):
            return NotImplemented
        return self.value == other.value
    
    def __hash__(self) -> int:
        return hash(self.value)
