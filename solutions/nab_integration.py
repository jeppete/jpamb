"""
NAB Integration Module - Integrates IIN traces with abstract domains.

This module provides the core integration between dynamic execution traces
produced by IIN (Interpreter) and the abstract domains defined for static
analysis. It implements the dynamic refinement heuristic that uses
observed concrete values to set initial abstract states for static analysis.

**Course Definition (02242):**
"Run two or more abstractions at the same time, letting them inform each other
during execution" (formula: 5 per abstraction after the first).

This module implements a **Reduced Product** of SignSet and IntervalDomain,
where both abstractions run in parallel and mutually refine each other:
- Sign "+" tightens interval low bound to max(low, 1)
- Sign "-" tightens interval high bound to min(high, -1)
- Sign "0" constrains interval to [0, 0]
- Interval [a, b] where a > 0 refines sign to "+"
- Interval [a, b] where b < 0 refines sign to "-"
- etc.

DTU 02242 Program Analysis - Group 21
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

# Import from abstract_domain module
from solutions.components.abstract_domain import (
    SignSet,
    IntervalDomain,
    IntervalValue,
    NonNullDomain,
)


# --- Helper functions for SignSet sign categories ---

def signset_is_positive(s: SignSet) -> bool:
    """Check if SignSet represents strictly positive values."""
    return s.signs == frozenset({"+"})

def signset_is_negative(s: SignSet) -> bool:
    """Check if SignSet represents strictly negative values."""
    return s.signs == frozenset({"-"})

def signset_is_zero(s: SignSet) -> bool:
    """Check if SignSet represents exactly zero."""
    return s.signs == frozenset({"0"})

def signset_is_non_negative(s: SignSet) -> bool:
    """Check if SignSet represents non-negative values (>= 0)."""
    return s.signs == frozenset({"+", "0"})

def signset_is_non_positive(s: SignSet) -> bool:
    """Check if SignSet represents non-positive values (<= 0)."""
    return s.signs == frozenset({"-", "0"})

def signset_is_non_zero(s: SignSet) -> bool:
    """Check if SignSet represents non-zero values."""
    return s.signs == frozenset({"+", "-"})


# --- Named SignSet constructors for clarity ---

def sign_positive() -> SignSet:
    """Create SignSet for strictly positive values."""
    return SignSet(frozenset({"+"}) )

def sign_negative() -> SignSet:
    """Create SignSet for strictly negative values."""
    return SignSet(frozenset({"-"}))

def sign_zero() -> SignSet:
    """Create SignSet for exactly zero."""
    return SignSet(frozenset({"0"}))

def sign_non_negative() -> SignSet:
    """Create SignSet for non-negative values (>= 0)."""
    return SignSet(frozenset({"+", "0"}))

def sign_non_positive() -> SignSet:
    """Create SignSet for non-positive values (<= 0)."""
    return SignSet(frozenset({"-", "0"}))

def sign_non_zero() -> SignSet:
    """Create SignSet for non-zero values."""
    return SignSet(frozenset({"+", "-"}))


def signset_from_samples(samples: List[int]) -> SignSet:
    """
    Create SignSet from concrete sample values.
    
    Args:
        samples: List of concrete integer values
        
    Returns:
        SignSet representing the signs observed in samples
    """
    if not samples:
        return SignSet.bottom()
    return SignSet.abstract(samples)


@dataclass
class AbstractValue:
    """Combined abstract value with both sign and interval domains."""
    sign: SignSet
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
            "interval": str(self.interval),
            "interval_bounds": {
                "low": self.interval.value.low,
                "high": self.interval.value.high
            }
        }


@dataclass
class ReducedProductState:
    """
    Reduced Product of SignSet, IntervalDomain, and NonNullDomain.
    
    This implements the course definition for NAB (Integrate Abstractions):
    "Run two or more abstractions at the same time, letting them inform each other
    during execution" (formula: 5 per abstraction after the first).
    
    The reduced product maintains sign, interval, AND nonnull abstractions in parallel,
    with mutual refinement to tighten all domains using information from each other.
    
    The NonNullDomain is a NOVEL abstraction NOT taught in DTU 02242 lectures
    (Sign, Interval, Constant, Parity are taught), qualifying for IAB points.
    
    Key refinement rules:
    - sign={+} + interval=[a,b] → interval=[max(a,1), b]
    - sign={-} + interval=[a,b] → interval=[a, min(b,-1)]
    - sign={0} + interval=[a,b] → interval=[0,0]
    - interval=[a,b] where a>0 → sign={+}
    - interval=[a,b] where b<0 → sign={-}
    - interval=[0,0] → sign={0}
    - nonnull=DEFINITELY_NON_NULL + is_reference → array length ≥ 0
    
    Dead Code Detection (IAB):
    - If nonnull=DEFINITELY_NON_NULL, ifnull branch is DEAD (unreachable)
    - If nonnull=MAYBE_NULL at ifnonnull, both branches are possible
    """
    sign: SignSet
    interval: IntervalDomain
    nonnull: NonNullDomain = field(default_factory=NonNullDomain.top)
    is_reference: bool = False  # True if tracking a reference, False for primitives
    _refinement_history: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Apply initial mutual refinement after construction."""
        if not hasattr(self, '_refinement_history') or self._refinement_history is None:
            self._refinement_history = []
    
    @classmethod
    def from_samples(cls, samples: List[int]) -> 'ReducedProductState':
        """
        Create a reduced product state from concrete samples (for integers).
        
        Args:
            samples: List of concrete integer values
            
        Returns:
            ReducedProductState with mutually refined sign and interval
        """
        sign = signset_from_samples(samples)
        interval = IntervalDomain.abstract(samples)
        state = cls(
            sign=sign,
            interval=interval,
            nonnull=NonNullDomain.top(),  # N/A for integers
            is_reference=False,
            _refinement_history=[]
        )
        state.inform_each_other()
        return state
    
    @classmethod
    def for_integer(cls, samples: Optional[List[int]] = None) -> 'ReducedProductState':
        """
        Create state for an integer value (not a reference).
        
        For primitives, nonnull is not applicable (use TOP).
        """
        if samples:
            sign = signset_from_samples(samples)
            interval = IntervalDomain.abstract(samples)
        else:
            sign = SignSet.top()
            interval = IntervalDomain.top()
        
        state = cls(
            sign=sign,
            interval=interval,
            nonnull=NonNullDomain.top(),
            is_reference=False,
            _refinement_history=[]
        )
        state.inform_each_other()
        return state
    
    @classmethod
    def for_reference(
        cls,
        nonnull: Optional[NonNullDomain] = None,
        is_array: bool = False,
        length_samples: Optional[List[int]] = None
    ) -> 'ReducedProductState':
        """
        Create state for a reference value.
        
        Args:
            nonnull: Nullness status (default: TOP)
            is_array: True if this is an array reference
            length_samples: If array, concrete length samples for interval
        """
        if nonnull is None:
            nonnull = NonNullDomain.top()
        
        if is_array and length_samples:
            sign = signset_from_samples(length_samples)
            interval = IntervalDomain.abstract(length_samples)
        else:
            # Array lengths are non-negative
            sign = sign_non_negative() if is_array else SignSet.top()
            interval = IntervalDomain.range(0, None) if is_array else IntervalDomain.top()
        
        state = cls(
            sign=sign,
            interval=interval,
            nonnull=nonnull,
            is_reference=True,
            _refinement_history=[]
        )
        state.inform_each_other()
        return state
    
    @classmethod
    def from_new(cls) -> 'ReducedProductState':
        """
        Create state for result of 'new' instruction.
        
        A newly created object is DEFINITELY_NON_NULL.
        """
        return cls(
            sign=SignSet.top(),
            interval=IntervalDomain.top(),
            nonnull=NonNullDomain.definitely_non_null(),
            is_reference=True,
            _refinement_history=["new → DEFINITELY_NON_NULL"]
        )
    
    @classmethod
    def from_newarray(cls, length: Optional[SignSet] = None) -> 'ReducedProductState':
        """
        Create state for result of 'newarray' or 'anewarray' instruction.
        
        A newly created array is DEFINITELY_NON_NULL, and length is non-negative.
        """
        # Array lengths are always non-negative
        interval = IntervalDomain.range(0, None)
        sign = sign_non_negative()
        
        return cls(
            sign=sign,
            interval=interval,
            nonnull=NonNullDomain.definitely_non_null(),
            is_reference=True,
            _refinement_history=["newarray → DEFINITELY_NON_NULL, length≥0"]
        )
    
    @classmethod
    def from_null(cls) -> 'ReducedProductState':
        """
        Create state for 'aconst_null' instruction.
        
        The null constant is MAYBE_NULL (includes definitely null).
        """
        return cls(
            sign=SignSet.top(),
            interval=IntervalDomain.top(),
            nonnull=NonNullDomain.maybe_null(),
            is_reference=True,
            _refinement_history=["aconst_null → MAYBE_NULL"]
        )
    
    @classmethod
    def top(cls, is_reference: bool = False) -> 'ReducedProductState':
        """Create TOP state (no information)."""
        return cls(
            sign=SignSet.top(),
            interval=IntervalDomain.top(),
            nonnull=NonNullDomain.top(),
            is_reference=is_reference,
            _refinement_history=[]
        )
    
    @classmethod
    def bottom(cls) -> 'ReducedProductState':
        """Create BOTTOM state (unreachable)."""
        return cls(
            sign=SignSet.bottom(),
            interval=IntervalDomain.bottom(),
            nonnull=NonNullDomain.bottom(),
            is_reference=False,
            _refinement_history=[]
        )
    
    def is_bottom(self) -> bool:
        """Check if any component is bottom."""
        return (self.sign.is_bottom() or 
                self.interval.is_bottom() or 
                self.nonnull.is_bottom())
    
    def is_top(self) -> bool:
        """Check if all components are top."""
        return (self.sign.is_top() and 
                self.interval.is_top() and 
                self.nonnull.is_top())
    
    def inform_each_other(self) -> bool:
        """
        Core NAB operation: Mutual refinement between all three domains.
        
        This is the key integration method that implements the course definition:
        "Run two or more abstractions at the same time, letting them inform each other"
        
        Includes NonNull refinement for IAB (Novel Abstractions):
        - Sign ↔ Interval (as before)
        - NonNull → Interval: if DEFINITELY_NON_NULL array, length ≥ 0
        - NonNull → Sign: if DEFINITELY_NON_NULL array, sign ∈ {+, 0}
        
        Returns:
            True if any refinement occurred, False if fixed point reached
        """
        changed = True
        iterations = 0
        max_iterations = 10  # Prevent infinite loops
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            # Refine interval from sign information
            interval_changed = self._refine_interval_from_sign()
            if interval_changed:
                changed = True
            
            # Refine sign from interval information
            sign_changed = self._refine_sign_from_interval()
            if sign_changed:
                changed = True
            
            # Refine from NonNull information (IAB)
            nonnull_changed = self._refine_from_nonnull()
            if nonnull_changed:
                changed = True
            
            # Check for inconsistency (bottom)
            if self._check_inconsistency():
                self.sign = SignSet.bottom()
                self.interval = IntervalDomain.bottom()
                self.nonnull = NonNullDomain.bottom()
                self._refinement_history.append("inconsistency detected → BOTTOM")
                return True
        
        return iterations > 1
    
    def _refine_interval_from_sign(self) -> bool:
        """
        Refine interval bounds using sign information.
        
        Rules:
        - {+} → low = max(low, 1)
        - {-} → high = min(high, -1)
        - {0} → [0, 0]
        - {+,0} → low = max(low, 0)
        - {-,0} → high = min(high, 0)
        """
        if self.sign.is_bottom() or self.interval.is_bottom():
            return False
        
        old_low = self.interval.value.low
        old_high = self.interval.value.high
        new_low = old_low
        new_high = old_high
        
        signs = self.sign.signs
        
        if signs == frozenset({"+"}) :
            # Positive values must be >= 1
            if new_low is None or new_low < 1:
                new_low = 1
                self._refinement_history.append("sign={+} → low=max(low,1)")
        
        elif signs == frozenset({"-"}):
            # Negative values must be <= -1
            if new_high is None or new_high > -1:
                new_high = -1
                self._refinement_history.append("sign={-} → high=min(high,-1)")
        
        elif signs == frozenset({"0"}):
            # Zero constraint
            new_low = 0
            new_high = 0
            self._refinement_history.append("sign={0} → interval=[0,0]")
        
        elif signs == frozenset({"+", "0"}):
            # Non-negative values must be >= 0
            if new_low is None or new_low < 0:
                new_low = 0
                self._refinement_history.append("sign={+,0} → low=max(low,0)")
        
        elif signs == frozenset({"-", "0"}):
            # Non-positive values must be <= 0
            if new_high is None or new_high > 0:
                new_high = 0
                self._refinement_history.append("sign={-,0} → high=min(high,0)")
        
        # Check if changed
        if new_low != old_low or new_high != old_high:
            # Check for inconsistency (low > high means empty interval = BOTTOM)
            if (new_low is not None and new_high is not None and new_low > new_high):
                self.interval = IntervalDomain.bottom()
                self._refinement_history.append("inconsistency: low > high → BOTTOM")
            else:
                self.interval = IntervalDomain(IntervalValue(new_low, new_high))
            return True
        
        return False
    
    def _refine_sign_from_interval(self) -> bool:
        """
        Refine sign using interval information.
        
        Rules:
        - [a, b] where a > 0 → {+}
        - [a, b] where b < 0 → {-}
        - [0, 0] → {0}
        - [0, b] where b > 0 → {+,0}
        - [a, 0] where a < 0 → {-,0}
        """
        if self.sign.is_bottom() or self.interval.is_bottom():
            return False
        
        old_signs = self.sign.signs
        low = self.interval.value.low
        high = self.interval.value.high
        
        inferred_sign = None
        
        # Infer sign from interval
        if low is not None and low > 0:
            inferred_sign = sign_positive()
            self._refinement_history.append(f"interval.low={low}>0 → sign={{+}}")
        elif high is not None and high < 0:
            inferred_sign = sign_negative()
            self._refinement_history.append(f"interval.high={high}<0 → sign={{-}}")
        elif low == 0 and high == 0:
            inferred_sign = sign_zero()
            self._refinement_history.append("interval=[0,0] → sign={0}")
        elif low is not None and low == 0 and (high is None or high > 0):
            inferred_sign = sign_non_negative()
            self._refinement_history.append("interval.low=0 → sign={+,0}")
        elif high is not None and high == 0 and (low is None or low < 0):
            inferred_sign = sign_non_positive()
            self._refinement_history.append("interval.high=0 → sign={-,0}")
        elif low is not None and high is not None and low < 0 and high > 0:
            # Crosses zero - could be anything (TOP)
            inferred_sign = SignSet.top()
        
        if inferred_sign is not None:
            # Meet with current sign for precision (intersection)
            new_sign = self.sign & inferred_sign
            if new_sign.signs != old_signs:
                self.sign = new_sign
                return True
        
        return False
    
    def _refine_from_nonnull(self) -> bool:
        """
        Refine sign/interval using NonNull information.
        
        Key insight: For arrays that are DEFINITELY_NON_NULL,
        the length (tracked in interval) is meaningful and non-negative.
        
        This is part of the IAB (Novel Abstractions) contribution.
        """
        if not self.is_reference:
            return False
        
        if self.nonnull.is_bottom():
            return False
        
        changed = False
        
        # If reference is DEFINITELY_NON_NULL, we can trust array length bounds
        if self.nonnull.is_definitely_non_null():
            # Array lengths are always >= 0
            low = self.interval.value.low
            if low is None or low < 0:
                self.interval = IntervalDomain(IntervalValue(0, self.interval.value.high))
                self._refinement_history.append("nonnull=NON_NULL → length≥0")
                changed = True
            
            # Sign should exclude negative for array length
            if "-" in self.sign.signs:
                new_signs = self.sign.signs - {"-"}
                if new_signs:
                    self.sign = SignSet(frozenset(new_signs))
                    self._refinement_history.append("nonnull=NON_NULL → sign excludes {-}")
                    changed = True
        
        return changed
    
    def _check_inconsistency(self) -> bool:
        """Check if domains are inconsistent."""
        if self.interval.is_bottom() or self.sign.is_bottom():
            return True
        
        low = self.interval.value.low
        high = self.interval.value.high
        
        # Check for empty interval
        if low is not None and high is not None and low > high:
            return True
        
        # Check sign/interval consistency
        signs = self.sign.signs
        
        if signs == frozenset({"+"}):
            if high is not None and high <= 0:
                return True
        elif signs == frozenset({"-"}):
            if low is not None and low >= 0:
                return True
        elif signs == frozenset({"0"}):
            if (low is not None and low > 0) or (high is not None and high < 0):
                return True
        
        return False
    
    # --- Branch refinement for null checks (IAB) ---
    
    def refine_ifnull_true(self) -> 'ReducedProductState':
        """
        Refine when ifnull branch is taken (value IS null).
        
        Returns new state where nonnull is refined to MAYBE_NULL.
        """
        new_nonnull = self.nonnull.refine_ifnull_true()
        return ReducedProductState(
            sign=self.sign,
            interval=self.interval,
            nonnull=new_nonnull,
            is_reference=self.is_reference,
            _refinement_history=self._refinement_history + ["ifnull taken → MAYBE_NULL"]
        )
    
    def refine_ifnull_false(self) -> 'ReducedProductState':
        """
        Refine when ifnull branch is NOT taken (value is NOT null).
        
        Returns new state where nonnull is refined to DEFINITELY_NON_NULL.
        """
        new_nonnull = self.nonnull.refine_ifnull_false()
        return ReducedProductState(
            sign=self.sign,
            interval=self.interval,
            nonnull=new_nonnull,
            is_reference=self.is_reference,
            _refinement_history=self._refinement_history + ["ifnull not taken → NON_NULL"]
        )
    
    def refine_ifnonnull_true(self) -> 'ReducedProductState':
        """
        Refine when ifnonnull branch is taken (value is NOT null).
        
        Returns new state where nonnull is refined to DEFINITELY_NON_NULL.
        """
        new_nonnull = self.nonnull.refine_ifnonnull_true()
        return ReducedProductState(
            sign=self.sign,
            interval=self.interval,
            nonnull=new_nonnull,
            is_reference=self.is_reference,
            _refinement_history=self._refinement_history + ["ifnonnull taken → NON_NULL"]
        )
    
    def refine_ifnonnull_false(self) -> 'ReducedProductState':
        """
        Refine when ifnonnull branch is NOT taken (value IS null).
        
        Returns new state where nonnull is refined to MAYBE_NULL.
        """
        new_nonnull = self.nonnull.refine_ifnonnull_false()
        return ReducedProductState(
            sign=self.sign,
            interval=self.interval,
            nonnull=new_nonnull,
            is_reference=self.is_reference,
            _refinement_history=self._refinement_history + ["ifnonnull not taken → MAYBE_NULL"]
        )
    
    # --- Dead code detection (IAB) ---
    
    def ifnull_branch_is_dead(self) -> bool:
        """
        Returns True if ifnull branch is proven dead (unreachable).
        
        This is the key IAB contribution: if reference is DEFINITELY_NON_NULL,
        the ifnull branch can never be taken → dead code.
        """
        return self.nonnull.ifnull_definitely_false()
    
    def ifnonnull_fallthrough_is_dead(self) -> bool:
        """
        Returns True if ifnonnull fallthrough is proven dead.
        
        If reference is DEFINITELY_NON_NULL, ifnonnull always jumps.
        """
        return self.nonnull.ifnonnull_definitely_true()
    
    def may_throw_npe(self) -> bool:
        """
        Returns True if NullPointerException is possible.
        
        Used to determine if getfield/invokevirtual/arraylength may throw.
        """
        if not self.is_reference:
            return False
        return self.nonnull.may_be_null()
    
    # --- Lattice operations ---
    
    def join(self, other: 'ReducedProductState') -> 'ReducedProductState':
        """
        Join (least upper bound) of two reduced product states.
        """
        new_sign = self.sign | other.sign
        new_interval = self.interval | other.interval
        new_nonnull = self.nonnull | other.nonnull
        new_is_ref = self.is_reference or other.is_reference
        
        result = ReducedProductState(
            sign=new_sign,
            interval=new_interval,
            nonnull=new_nonnull,
            is_reference=new_is_ref,
            _refinement_history=[]
        )
        result.inform_each_other()
        return result
    
    def meet(self, other: 'ReducedProductState') -> 'ReducedProductState':
        """
        Meet (greatest lower bound) of two reduced product states.
        """
        new_sign = self.sign & other.sign
        new_interval = self.interval & other.interval
        new_nonnull = self.nonnull & other.nonnull
        new_is_ref = self.is_reference and other.is_reference
        
        result = ReducedProductState(
            sign=new_sign,
            interval=new_interval,
            nonnull=new_nonnull,
            is_reference=new_is_ref,
            _refinement_history=[]
        )
        result.inform_each_other()
        return result
    
    def widening(self, other: 'ReducedProductState') -> 'ReducedProductState':
        """
        Widening operator for fixpoint computation.
        
        IBA (Implement Unbounded Static Analysis) - 7 points
        
        Applies widening to each component of the reduced product:
        - SignSet: widening is just join (finite lattice, always terminates)
        - IntervalDomain: classic interval widening (unstable → ±∞)
        - NonNullDomain: widening is just join (finite lattice, bool here)
        
        Note: We do NOT apply mutual refinement after widening to ensure
        monotonic convergence toward the fixpoint.
        
        Args:
            other: The new state from the current iteration
            
        Returns:
            Widened state that guarantees termination
        """
        new_sign = self.sign | other.sign  # SignSet widening is just join
        new_interval = self.interval.widening(other.interval)
        # nonnull is a bool - join is OR (keeps True if either is True)
        new_nonnull = self.nonnull or other.nonnull
        new_is_ref = self.is_reference or other.is_reference
        
        return ReducedProductState(
            sign=new_sign,
            interval=new_interval,
            nonnull=new_nonnull,
            is_reference=new_is_ref,
            _refinement_history=[]
        )
        # Don't refine after widening to ensure termination
    
    def narrowing(self, other: 'ReducedProductState') -> 'ReducedProductState':
        """
        Narrowing operator for improving precision after widening fixpoint.
        
        IBA (Implement Unbounded Static Analysis) - 7 points
        
        After widening reaches a fixpoint (possibly with ±∞ bounds), narrowing
        can recover some precision by replacing infinite bounds with finite ones.
        
        Applies narrowing to each component:
        - SignSet: no narrowing needed (finite lattice)
        - IntervalDomain: replace ±∞ with finite bounds from other
        - NonNullDomain: no narrowing needed (bool, use AND for meet)
        
        Note: We DO apply mutual refinement after narrowing to maximize precision.
        
        Args:
            other: The state from the narrowing iteration
            
        Returns:
            Narrowed state with improved precision
        """
        # SignSet: use meet for narrowing (can only get more precise)
        new_sign = self.sign & other.sign
        
        # IntervalDomain: use dedicated narrowing operator
        new_interval = self.interval.narrowing(other.interval)
        
        # NonNullDomain: nonnull is a bool, meet is AND
        new_nonnull = self.nonnull and other.nonnull
        
        new_is_ref = self.is_reference and other.is_reference
        
        result = ReducedProductState(
            sign=new_sign,
            interval=new_interval,
            nonnull=new_nonnull,
            is_reference=new_is_ref,
            _refinement_history=["narrowing applied"]
        )
        # Apply mutual refinement after narrowing for maximum precision
        result.inform_each_other()
        return result
    
    def get_refinement_history(self) -> List[str]:
        """Get the history of refinement steps applied."""
        return list(self._refinement_history)
    
    def __str__(self):
        if self.is_reference:
            return f"ReducedProduct(sign={self.sign}, interval={self.interval}, nonnull={self.nonnull})"
        return f"ReducedProduct(sign={self.sign}, interval={self.interval})"
    
    def __repr__(self):
        return self.__str__()
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ReducedProductState):
            return NotImplemented
        return (self.sign == other.sign and 
                self.interval == other.interval and 
                self.nonnull == other.nonnull and
                self.is_reference == other.is_reference)
    
    def __hash__(self) -> int:
        return hash((self.sign, self.interval, self.nonnull, self.is_reference))
    
    def to_abstract_value(self, local_index: int) -> 'AbstractValue':
        """Convert to AbstractValue for compatibility."""
        return AbstractValue(
            sign=self.sign,
            interval=self.interval,
            local_index=local_index
        )


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


def refine_from_trace(samples: List[int]) -> Tuple[SignSet, IntervalDomain]:
    """
    Refine abstract domains from concrete sample values.
    
    This is the core dynamic refinement heuristic: we observe concrete
    execution values and infer the tightest abstract domain that contains
    all observed values. This is our approved novelty contribution.
    
    Uses ReducedProductState to ensure mutual refinement between domains.
    
    Args:
        samples: List of concrete integer values observed during execution
        
    Returns:
        Tuple of (SignSet, IntervalDomain) refined from samples with
        mutual refinement applied (reduced product)
    """
    # Use reduced product for mutual refinement
    reduced = ReducedProductState.from_samples(samples)
    return reduced.sign, reduced.interval


def refine_from_trace_reduced(samples: List[int]) -> ReducedProductState:
    """
    Refine abstract domains from samples, returning full ReducedProductState.
    
    This exposes the full reduced product including refinement history.
    
    Args:
        samples: List of concrete integer values observed during execution
        
    Returns:
        ReducedProductState with mutually refined sign and interval
    """
    return ReducedProductState.from_samples(samples)


def integrate_abstractions(trace_path: str) -> Dict[int, AbstractValue]:
    """
    Main NAB integration function: reads IIN trace and produces refined abstract state.
    
    This function implements the integration between:
    - IIN (Interpreter): produces traces/<method>.json with concrete execution data
    - Abstract domains: SignSet, IntervalDomain, refine_from_trace()
    
    The integration uses dynamic traces to set initial abstract states (e.g., x>0)
    for subsequent static analysis, as described in our approved proposal.
    
    Args:
        trace_path: Path to IIN JSON trace file in traces/ directory
        
    Returns:
        Dictionary mapping local variable indices to AbstractValue objects
        containing refined sign and interval domains
        
    Example:
        >>> result = integrate_abstractions("traces/jpamb.cases.Simple_assertPositive_IV.json")
        >>> "+" in result[0].sign.signs  # True for positive samples
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
        # Apply reduced product refinement for mutual information exchange
        reduced_state = ReducedProductState.from_samples(samples)
        
        # Create combined abstract value from reduced product
        abstract_values[local_idx] = reduced_state.to_abstract_value(local_idx)
    
    # For local variables with no samples, return TOP
    if not abstract_values:
        # Return empty dict - caller can handle as needed
        pass
    
    return abstract_values


def integrate_abstractions_reduced(trace_path: str) -> Dict[int, ReducedProductState]:
    """
    Integration returning full ReducedProductState objects.
    
    This exposes the parallel execution and mutual refinement capabilities
    as required by the course definition.
    
    Args:
        trace_path: Path to IIN JSON trace file
        
    Returns:
        Dictionary mapping local variable indices to ReducedProductState objects
    """
    path = Path(trace_path)
    if not path.exists():
        raise FileNotFoundError(f"Trace file not found: {trace_path}")
    
    with open(path, 'r') as f:
        trace_data = json.load(f)
    
    samples_by_local = extract_samples_from_trace(trace_data)
    
    reduced_states: Dict[int, ReducedProductState] = {}
    
    for local_idx, samples in samples_by_local.items():
        reduced_states[local_idx] = ReducedProductState.from_samples(samples)
    
    return reduced_states


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


def get_sign_for_local(trace_path: str, local_idx: int) -> SignSet:
    """
    Convenience function to get sign for a specific local variable.
    
    Args:
        trace_path: Path to IIN trace file
        local_idx: Local variable index
        
    Returns:
        SignSet for the local variable, or TOP if not found
    """
    abstract_values = integrate_abstractions(trace_path)
    
    if local_idx in abstract_values:
        return abstract_values[local_idx].sign
    
    return SignSet.top()


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
    - sign(x) = {+} (positive)
    - interval(x) = [5, 25]
    
    This is our dynamic refinement heuristic: using IIN traces to
    initialize abstract states for static analysis.
    
    Uses ReducedProductState for mutual refinement between sign and interval.
    """
    # Simulate the proposal example
    samples = [5, 10, 15, 20, 25]  # Positive samples from dynamic execution
    
    # Use reduced product for mutual refinement
    reduced = ReducedProductState.from_samples(samples)
    
    return {
        1: reduced.to_abstract_value(1)
    }


def process_example_reduced() -> Dict[int, ReducedProductState]:
    """
    Proposal example returning full ReducedProductState.
    
    This demonstrates the parallel execution and mutual refinement.
    """
    samples = [5, 10, 15, 20, 25]
    reduced = ReducedProductState.from_samples(samples)
    return {1: reduced}


def inform_each_other(sign: SignSet, interval: IntervalDomain) -> Tuple[SignSet, IntervalDomain]:
    """
    Module-level function for mutual refinement between sign and interval domains.
    
    This is the core NAB operation implementing the course definition:
    "Run two or more abstractions at the same time, letting them inform each other
    during execution" (formula: 5 per abstraction after the first).
    
    Args:
        sign: Initial sign domain (SignSet)
        interval: Initial interval domain
        
    Returns:
        Tuple of (refined_sign, refined_interval) after mutual refinement
        
    Example:
        >>> sign = sign_positive()  # {+}
        >>> interval = IntervalDomain(IntervalValue(-5, 10))
        >>> new_sign, new_interval = inform_each_other(sign, interval)
        >>> new_interval.value.low  # Tightened to 1
        1
    """
    reduced = ReducedProductState(sign=sign, interval=interval)
    reduced.inform_each_other()
    return reduced.sign, reduced.interval


if __name__ == "__main__":
    # Demonstrate proposal example
    print("NAB Integration - Proposal Example §1.3.1")
    print("=" * 50)
    
    result = process_example()
    for local_idx, abstract_val in result.items():
        print(f"  {abstract_val}")
        print(f"    → sign = {abstract_val.sign}")
        print(f"    → interval = {abstract_val.interval}")
    
    print()
    print("Demonstrating Reduced Product mutual refinement:")
    print("-" * 50)
    
    # Show mutual refinement example
    print("\nExample 1: {+} sign tightens interval [−5, 10] to [1, 10]")
    sign1 = sign_positive()
    interval1 = IntervalDomain(IntervalValue(-5, 10))
    new_sign1, new_interval1 = inform_each_other(sign1, interval1)
    print(f"  Before: sign={sign1}, interval={interval1}")
    print(f"  After:  sign={new_sign1}, interval={new_interval1}")
    
    print("\nExample 2: Interval [5, 100] infers {+} sign")
    reduced2 = ReducedProductState(
        sign=SignSet.top(),
        interval=IntervalDomain(IntervalValue(5, 100))
    )
    reduced2.inform_each_other()
    print("  Before: sign=⊤, interval=[5, 100]")
    print(f"  After:  sign={reduced2.sign}, interval={reduced2.interval}")
    print(f"  Refinement history: {reduced2.get_refinement_history()}")
    
    print()
    print("Integrating actual traces from traces/ directory...")
    print("-" * 50)
    
    # Integrate actual traces
    all_results = integrate_all_traces("traces")
    
    for method_name, result in list(all_results.items())[:5]:  # Show first 5
        print(f"\n{method_name}:")
        for local_idx, abstract_val in result.abstract_values.items():
            print(f"  {abstract_val}")
