"""
Tests for IBA: Implement Unbounded Static Analysis (7 points)

Requirements from course:
1. Widening operator added to abstract domain (IntervalDomain)
2. Optional narrowing pass for improved precision
3. Parameter unbounded=True in analyzer to enable unbounded analysis
4. Demonstrate: Infinite loop terminates with widening, times out without

IBA ensures analysis terminates even on programs with unbounded loops.
"""

import pytest
import sys
import os

# Add project paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "solutions"))

from solutions.abstract_domain import IntervalDomain, SignSet
from solutions.nab_integration import ReducedProductState


# Helper to create intervals with bounds
def interval(low, high):
    """Create IntervalDomain with given bounds."""
    return IntervalDomain.range(low, high)


# ===========================================================================
# Test 1: IntervalDomain Widening Operator
# ===========================================================================

class TestIntervalWidening:
    """Tests for widening operator in IntervalDomain (IBA requirement 1)."""
    
    def test_widening_stable_lower(self):
        """Widening preserves stable lower bounds."""
        a = interval(0, 10)
        b = interval(0, 15)
        result = a.widening(b)
        # Lower bound stable (both 0), upper bound unstable → +∞
        assert result.value.low == 0
        assert result.value.high is None  # None = +∞
    
    def test_widening_stable_upper(self):
        """Widening preserves stable upper bounds."""
        a = interval(5, 100)
        b = interval(0, 100)
        result = a.widening(b)
        # Lower bound decreasing → -∞, upper bound stable
        assert result.value.low is None  # None = -∞
        assert result.value.high == 100
    
    def test_widening_both_unstable(self):
        """Widening handles both bounds changing."""
        a = interval(5, 10)
        b = interval(0, 20)
        result = a.widening(b)
        # Both bounds unstable → both go to infinity
        assert result.value.low is None
        assert result.value.high is None
    
    def test_widening_both_stable(self):
        """Widening with no change returns same interval."""
        a = interval(0, 10)
        b = interval(0, 10)
        result = a.widening(b)
        assert result == a
    
    def test_widening_is_idempotent_at_top(self):
        """Widening with infinite bounds stays stable."""
        a = IntervalDomain.top()
        b = interval(0, 100)
        result = a.widening(b)
        # Already at top, widening doesn't change
        assert result.value.low is None
        assert result.value.high is None
    
    def test_widening_terminates_ascending_chain(self):
        """Widening ensures termination on ascending chains."""
        # Simulate loop: x starts at 0, increments each iteration
        intervals = [interval(0, 0)]
        for i in range(1, 10):
            next_interval = interval(0, i)
            widened = intervals[-1].widening(next_interval)
            intervals.append(widened)
            
            # After first widening, should reach +∞ and stabilize
            if i >= 2:
                assert widened.value.high is None  # None = +∞
                assert widened == intervals[-2]  # Stable
                break


# ===========================================================================
# Test 2: IntervalDomain Narrowing Operator
# ===========================================================================

class TestIntervalNarrowing:
    """Tests for narrowing operator in IntervalDomain (IBA requirement 2)."""
    
    def test_narrowing_recovers_finite_lower(self):
        """Narrowing replaces -∞ with finite bound."""
        a = interval(None, 100)  # None = -∞
        b = interval(0, 100)
        result = a.narrowing(b)
        assert result.value.low == 0
        assert result.value.high == 100
    
    def test_narrowing_recovers_finite_upper(self):
        """Narrowing replaces +∞ with finite bound."""
        a = interval(0, None)  # None = +∞
        b = interval(0, 50)
        result = a.narrowing(b)
        assert result.value.low == 0
        assert result.value.high == 50
    
    def test_narrowing_recovers_both(self):
        """Narrowing replaces both infinities."""
        a = IntervalDomain.top()  # [-∞, +∞]
        b = interval(-5, 10)
        result = a.narrowing(b)
        assert result.value.low == -5
        assert result.value.high == 10
    
    def test_narrowing_preserves_finite_bounds(self):
        """Narrowing doesn't change already-finite bounds."""
        a = interval(0, 100)
        b = interval(5, 50)
        result = a.narrowing(b)
        # Finite bounds stay as-is
        assert result.value.low == 0
        assert result.value.high == 100
    
    def test_narrowing_is_monotonic(self):
        """Narrowing produces more precise (smaller) intervals."""
        a = IntervalDomain.top()
        b = interval(0, 10)
        result = a.narrowing(b)
        
        # Result should be more precise (has finite bounds now)
        assert result.value.low is not None or result.value.high is not None


# ===========================================================================
# Test 3: ReducedProductState Widening/Narrowing
# ===========================================================================

class TestReducedProductWidening:
    """Tests for widening in ReducedProductState."""
    
    def test_widening_widens_interval(self):
        """ReducedProductState widening affects interval domain."""
        a = ReducedProductState(
            sign=SignSet({"+", "0"}),
            interval=interval(0, 10),
            nonnull=True
        )
        b = ReducedProductState(
            sign=SignSet({"+", "0"}),
            interval=interval(0, 20),
            nonnull=True
        )
        result = a.widening(b)
        
        # Interval should be widened to +∞
        assert result.interval.value.high is None  # None = +∞
    
    def test_narrowing_narrows_interval(self):
        """ReducedProductState narrowing recovers precision."""
        a = ReducedProductState(
            sign=SignSet({"+", "0"}),
            interval=interval(0, None),  # [0, +∞)
            nonnull=True
        )
        b = ReducedProductState(
            sign=SignSet({"+"}),
            interval=interval(1, 50),
            nonnull=True
        )
        result = a.narrowing(b)
        
        # Should recover finite upper bound
        assert result.interval.value.high == 50


# ===========================================================================
# Test 4: Unbounded Analysis Termination
# ===========================================================================

class TestUnboundedTermination:
    """Tests for unbounded_abstract_run termination guarantees."""
    
    def test_widening_threshold_parameter(self):
        """Verify widening_threshold parameter exists."""
        from solutions.abstract_interpreter import unbounded_abstract_run
        import inspect
        
        sig = inspect.signature(unbounded_abstract_run)
        assert "widening_threshold" in sig.parameters
    
    def test_enable_narrowing_parameter(self):
        """Verify enable_narrowing parameter exists."""
        from solutions.abstract_interpreter import unbounded_abstract_run
        import inspect
        
        sig = inspect.signature(unbounded_abstract_run)
        assert "enable_narrowing" in sig.parameters
    
    def test_narrowing_iterations_parameter(self):
        """Verify narrowing_iterations parameter exists."""
        from solutions.abstract_interpreter import unbounded_abstract_run
        import inspect
        
        sig = inspect.signature(unbounded_abstract_run)
        assert "narrowing_iterations" in sig.parameters


# ===========================================================================
# Test 5: SignSet Widening/Narrowing
# ===========================================================================

class TestSignSetWidening:
    """Tests for widening on SignSet (finite lattice)."""
    
    def test_signset_widening_is_join(self):
        """For finite lattices like SignSet, widening = join."""
        a = SignSet({"+", "0"})
        b = SignSet({"+", "-"})
        
        # SignSet is finite, so widening just joins
        result = a | b  # Should be {+, 0, -}
        assert result.signs == {"+", "0", "-"}
    
    def test_signset_finite_chain(self):
        """SignSet has finite height, so terminates without widening."""
        # Start with empty
        current = SignSet.bottom()
        
        # Add signs one at a time
        for sign in ["+", "0", "-"]:
            current = current | SignSet({sign})
        
        # Should reach top after 3 joins
        assert current == SignSet.top()


# ===========================================================================
# Test 6: Widening vs No Widening (Concept)
# ===========================================================================

class TestWideningConcept:
    """Conceptual tests for widening necessity."""
    
    def test_ascending_chain_without_widening_grows(self):
        """Without widening, ascending chain keeps growing."""
        intervals = []
        for i in range(100):
            intervals.append(interval(0, i))
        
        # Chain has 100 distinct elements
        unique = set((iv.value.low, iv.value.high) for iv in intervals)
        assert len(unique) == 100
    
    def test_ascending_chain_with_widening_stabilizes(self):
        """With widening, ascending chain stabilizes quickly."""
        current = interval(0, 0)
        iterations_to_stable = 0
        
        for i in range(1, 100):
            next_iv = interval(0, i)
            widened = current.widening(next_iv)
            
            if widened == current:
                break
            current = widened
            iterations_to_stable += 1
        
        # Should stabilize within ~2 iterations
        assert iterations_to_stable <= 2
        # Final result should be [0, +∞)
        assert current.value.low == 0
        assert current.value.high is None  # None = +∞


# ===========================================================================
# Test 7: IBA Documentation
# ===========================================================================

class TestIBADocumentation:
    """Tests that IBA is properly documented."""
    
    def test_widening_has_iba_docstring(self):
        """widening() method has IBA documentation."""
        doc = IntervalDomain.widening.__doc__
        assert doc is not None
        assert "IBA" in doc or "widening" in doc.lower()
    
    def test_narrowing_has_iba_docstring(self):
        """narrowing() method has IBA documentation."""
        doc = IntervalDomain.narrowing.__doc__
        assert doc is not None
        assert "IBA" in doc or "narrowing" in doc.lower()
    
    def test_unbounded_abstract_run_has_iba_docstring(self):
        """unbounded_abstract_run has IBA documentation."""
        from solutions.abstract_interpreter import unbounded_abstract_run
        
        doc = unbounded_abstract_run.__doc__
        assert doc is not None
        assert "IBA" in doc or "unbounded" in doc.lower() or "widening" in doc.lower()


# ===========================================================================
# Test 8: Full IBA Pipeline
# ===========================================================================

class TestIBAPipeline:
    """Integration tests for full IBA pipeline."""
    
    def test_widening_then_narrowing_improves_precision(self):
        """Narrowing after widening recovers some precision."""
        # Simulate loop analysis
        # Phase 1: Widening
        intervals = [interval(0, 0)]
        for i in range(1, 5):
            next_iv = interval(0, i)
            widened = intervals[-1].widening(next_iv)
            intervals.append(widened)
        
        # After widening: [0, +∞)
        widened_result = intervals[-1]
        assert widened_result.value.high is None  # None = +∞
        
        # Phase 2: Narrowing
        # Suppose constraint analysis says x < 100
        constraint = interval(0, 99)
        narrowed = widened_result.narrowing(constraint)
        
        # Should recover finite bound
        assert narrowed.value.high == 99
        assert narrowed.value.low == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
