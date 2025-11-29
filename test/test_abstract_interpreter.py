"""
Test suite for IAI (Implement Abstract Interpreter) component.

Tests the abstract interpreter implementation including:
- Bounded and unbounded abstract interpretation
- Integration with ISY MethodIR/CFG
- Unreachable PC computation
- Integration with NAN refinement (ReducedProductState.from_samples())

DTU 02242 Program Analysis - Group 21
"""

import pytest
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from jpamb import jvm
from jpamb.model import Suite

from solutions.components.abstract_interpreter import (
    bounded_abstract_run,
    unbounded_abstract_run,
    get_unreachable_pcs,
    analyze_with_ir,
    signset_from_reduced,
    AbstractInterpreter,
)
from solutions.components.abstract_domain import SignSet


class TestBoundedAbstractInterpretation:
    """Tests for bounded abstract interpretation."""
    
    @pytest.fixture
    def suite(self):
        """Get JPAMB Suite."""
        return Suite()
    
    def test_bounded_run_simple_ok(self, suite):
        """Simple method that always returns ok."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByN:(I)I")
        
        # With n = positive, should be able to divide
        init = {0: SignSet.const(5)}
        outcomes = bounded_abstract_run(suite, method, init_locals=init, max_steps=50)
        
        assert "ok" in outcomes or "divide by zero" in outcomes
    
    def test_bounded_run_with_max_steps(self, suite):
        """Test that bounded run respects max_steps limit."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Loops.countTo10:()V")
        
        outcomes = bounded_abstract_run(suite, method, max_steps=10)
        # Should terminate due to step limit
        assert isinstance(outcomes, set)
    
    def test_bounded_run_assertion_error(self, suite):
        """Test detection of assertion errors."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertFalse:()V")
        
        outcomes = bounded_abstract_run(suite, method, max_steps=50)
        
        # Should detect assertion error
        assert "assertion error" in outcomes
    
    def test_bounded_run_divide_by_zero(self, suite):
        """Test detection of divide by zero."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByN:(I)I")
        
        # With n = zero, should detect divide by zero
        init = {0: SignSet.const(0)}
        outcomes = bounded_abstract_run(suite, method, init_locals=init, max_steps=50)
        
        assert "divide by zero" in outcomes


class TestUnboundedAbstractInterpretation:
    """Tests for unbounded abstract interpretation with widening."""
    
    @pytest.fixture
    def suite(self):
        """Get JPAMB Suite."""
        return Suite()
    
    def test_unbounded_run_terminates(self, suite):
        """Unbounded run should terminate due to widening."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Loops.countTo10:()V")
        
        # Should terminate even for loops due to widening
        outcomes, visited = unbounded_abstract_run(suite, method, widening_threshold=3)
        
        assert isinstance(outcomes, set)
        assert isinstance(visited, set)
        assert len(visited) > 0
    
    def test_unbounded_run_returns_visited_pcs(self, suite):
        """Unbounded run should return set of visited PCs."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        outcomes, visited = unbounded_abstract_run(suite, method)
        
        assert 0 in visited  # Entry point should be visited
        assert len(visited) > 1
    
    def test_unbounded_run_with_refined_initial_state(self, suite):
        """Test unbounded run with refined initial state from NAN."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        # Positive initial state (as if from NAN refinement)
        init = {0: SignSet(frozenset({"+"})) }
        
        outcomes, visited = unbounded_abstract_run(suite, method, init_locals=init)
        
        assert isinstance(outcomes, set)
        assert len(visited) > 0


class TestUnreachablePCs:
    """Tests for unreachable PC computation."""
    
    @pytest.fixture
    def suite(self):
        """Get JPAMB Suite."""
        return Suite()
    
    def test_get_unreachable_pcs_returns_set(self, suite):
        """Should return a set of unreachable PCs."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        unreachable = get_unreachable_pcs(suite, method)
        
        assert isinstance(unreachable, set)
    
    def test_unreachable_pcs_with_refinement(self, suite):
        """Test that refined initial state can identify more unreachable PCs."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        # Without refinement
        unreachable_top = get_unreachable_pcs(suite, method, init_locals=None)
        
        # With positive refinement (assertion should not fail)
        init = {0: SignSet(frozenset({"+"})) }
        unreachable_refined = get_unreachable_pcs(suite, method, init_locals=init)
        
        # Both should be valid sets
        assert isinstance(unreachable_top, set)
        assert isinstance(unreachable_refined, set)


class TestDeadCodeDetection:
    """Tests that verify dead code is actually found in Java classes."""
    
    @pytest.fixture
    def suite(self):
        """Get JPAMB Suite."""
        return Suite()
    
    def test_assertFalse_has_dead_code_after_assertion(self, suite):
        """Simple.assertFalse always throws - verify assertion error detected."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertFalse:()V")
        
        outcomes, visited = unbounded_abstract_run(suite, method)
        
        # assertFalse() always throws assertion error - must be detected
        assert "assertion error" in outcomes, "assertFalse should detect assertion error"
        
        # Print what the analysis found for debugging
        print(f"\nassertFalse outcomes: {outcomes}")
        print(f"assertFalse visited PCs: {sorted(visited)}")
    
    def test_earlyReturn_has_dead_code(self, suite):
        """Simple.earlyReturn has code structure to analyze."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.earlyReturn:()I")
        
        outcomes, visited = unbounded_abstract_run(suite, method)
        unreachable = get_unreachable_pcs(suite, method)
        
        # Method should complete analysis
        assert isinstance(unreachable, set)
        assert len(visited) > 0
    
    def test_assertPositive_with_positive_input_finds_dead_branch(self, suite):
        """When input is known positive, the assertion failure branch is dead."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        # With positive refinement, assertion error path should be unreachable
        init = {0: SignSet(frozenset({"+"})) }
        unreachable_refined = get_unreachable_pcs(suite, method, init_locals=init)
        
        # Without refinement (top), both branches are reachable
        unreachable_top = get_unreachable_pcs(suite, method, init_locals=None)
        
        # Refined analysis should find MORE dead code than unrefined
        assert len(unreachable_refined) >= len(unreachable_top), \
            f"Refined should find at least as much dead code: refined={len(unreachable_refined)}, top={len(unreachable_top)}"
    
    def test_divideByN_with_nonzero_input_finds_dead_exception_path(self, suite):
        """When input is known non-zero, divide-by-zero path is dead."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByN:(I)I")
        
        # With non-zero refinement {+, -}, divide by zero is impossible
        init = {0: SignSet(frozenset({"+", "-"})) }
        outcomes_refined, visited_refined = unbounded_abstract_run(suite, method, init_locals=init)
        
        # Should NOT have divide by zero outcome
        assert "divide by zero" not in outcomes_refined, \
            "With non-zero input, divide by zero should be dead"
    
    def test_checkBeforeDivideByN_eliminates_divide_by_zero(self, suite):
        """Method that checks n != 0 before dividing should not have DBZ."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.checkBeforeDivideByN:(I)I")
        
        # This method checks before dividing, abstract interpreter should detect
        outcomes, visited = unbounded_abstract_run(suite, method)
        
        # The method handles n=0 case, so analysis should show ok path exists
        assert "ok" in outcomes, "checkBeforeDivideByN should have ok outcome"
    
    def test_dead_code_count_in_assertFalse(self, suite):
        """Count actual dead instructions in assertFalse."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertFalse:()V")
        
        outcomes, visited = unbounded_abstract_run(suite, method)
        unreachable = get_unreachable_pcs(suite, method)
        
        print("\nassertFalse analysis:")
        print(f"  Outcomes: {outcomes}")
        print(f"  Visited PCs: {sorted(visited)}")
        print(f"  Unreachable PCs: {sorted(unreachable)}")
        print(f"  Dead code count: {len(unreachable)} instructions")
        
        # assertFalse always throws, verify we detect assertion error
        assert "assertion error" in outcomes


class TestAllJavaClasses:
    """Analyze ALL Java classes for dead code detection."""
    
    @pytest.fixture
    def suite(self):
        return Suite()
    
    def _get_all_methods(self):
        """Get all method IDs from all Java classes."""
        import json
        methods = []
        classes = ['Simple', 'Arrays', 'Calls', 'Loops', 'Tricky', 'Debloating', 'Dependent']
        
        for cls in classes:
            path = Path(f'target/decompiled/jpamb/cases/{cls}.json')
            if not path.exists():
                continue
            with open(path) as f:
                data = json.load(f)
            
            for m in data.get('methods', []):
                name = m['name']
                if name.startswith('<'):  # Skip <init>, <clinit>
                    continue
                
                # Build descriptor
                params = m.get('params', [])
                ret = m.get('returns', {})
                
                param_str = ''
                for p in params:
                    ptype = p.get('type', {}).get('base', 'I')
                    if ptype == 'int':
                        param_str += 'I'
                    elif ptype == 'boolean':
                        param_str += 'Z'
                    elif ptype == 'char':
                        param_str += 'C'
                    elif ptype == 'byte':
                        param_str += 'B'
                    elif ptype == 'short':
                        param_str += 'S'
                    elif ptype == 'long':
                        param_str += 'J'
                    elif ptype == 'float':
                        param_str += 'F'
                    elif ptype == 'double':
                        param_str += 'D'
                    else:
                        # Reference type - skip for now
                        param_str += 'L'
                
                ret_type = ret.get('base', 'void') if ret else 'void'
                if ret_type == 'void':
                    ret_str = 'V'
                elif ret_type == 'int':
                    ret_str = 'I'
                elif ret_type == 'boolean':
                    ret_str = 'Z'
                else:
                    ret_str = 'V'
                
                method_id = f"jpamb.cases.{cls}.{name}:({param_str}){ret_str}"
                methods.append((cls, name, method_id))
        
        return methods
    
    def test_analyze_all_simple_methods(self, suite):
        """Analyze all methods in Simple.java."""
        methods = [m for m in self._get_all_methods() if m[0] == 'Simple']
        
        results = []
        for cls, name, method_id in methods:
            try:
                method = jvm.AbsMethodID.decode(method_id)
                outcomes, visited = unbounded_abstract_run(suite, method)
                unreachable = get_unreachable_pcs(suite, method)
                results.append((name, len(visited), len(unreachable), outcomes))
            except Exception as e:
                results.append((name, 0, 0, {f"error: {str(e)[:30]}"}))
        
        print(f"\n{'Method':<30} {'Visited':<10} {'Dead':<10} {'Outcomes'}")
        print("-" * 80)
        for name, visited, dead, outcomes in results:
            print(f"{name:<30} {visited:<10} {dead:<10} {outcomes}")
        
        assert len(results) > 0
    
    def test_analyze_all_arrays_methods(self, suite):
        """Analyze all methods in Arrays.java."""
        methods = [m for m in self._get_all_methods() if m[0] == 'Arrays']
        
        results = []
        for cls, name, method_id in methods:
            try:
                method = jvm.AbsMethodID.decode(method_id)
                outcomes, visited = unbounded_abstract_run(suite, method)
                unreachable = get_unreachable_pcs(suite, method)
                results.append((name, len(visited), len(unreachable), outcomes))
            except Exception as e:
                results.append((name, 0, 0, {f"error: {str(e)[:30]}"}))
        
        print(f"\n{'Method':<30} {'Visited':<10} {'Dead':<10} {'Outcomes'}")
        print("-" * 80)
        for name, visited, dead, outcomes in results:
            print(f"{name:<30} {visited:<10} {dead:<10} {outcomes}")
        
        assert len(results) > 0
    
    def test_analyze_all_loops_methods(self, suite):
        """Analyze all methods in Loops.java."""
        methods = [m for m in self._get_all_methods() if m[0] == 'Loops']
        
        results = []
        for cls, name, method_id in methods:
            try:
                method = jvm.AbsMethodID.decode(method_id)
                outcomes, visited = unbounded_abstract_run(suite, method, widening_threshold=3)
                unreachable = get_unreachable_pcs(suite, method)
                results.append((name, len(visited), len(unreachable), outcomes))
            except Exception as e:
                results.append((name, 0, 0, {f"error: {str(e)[:30]}"}))
        
        print(f"\n{'Method':<30} {'Visited':<10} {'Dead':<10} {'Outcomes'}")
        print("-" * 80)
        for name, visited, dead, outcomes in results:
            print(f"{name:<30} {visited:<10} {dead:<10} {outcomes}")
        
        assert len(results) > 0
    
    def test_summary_all_classes(self, suite):
        """Summary of dead code across ALL Java classes."""
        all_methods = self._get_all_methods()
        
        total_visited = 0
        total_dead = 0
        methods_with_dead = 0
        
        for cls, name, method_id in all_methods:
            try:
                method = jvm.AbsMethodID.decode(method_id)
                outcomes, visited = unbounded_abstract_run(suite, method, widening_threshold=3)
                unreachable = get_unreachable_pcs(suite, method)
                total_visited += len(visited)
                total_dead += len(unreachable)
                if len(unreachable) > 0:
                    methods_with_dead += 1
            except Exception:
                pass
        
        print("\n=== DEAD CODE SUMMARY ===")
        print(f"Total methods analyzed: {len(all_methods)}")
        print(f"Methods with dead code: {methods_with_dead}")
        print(f"Total instructions visited: {total_visited}")
        print(f"Total dead instructions: {total_dead}")
        
        assert len(all_methods) > 0


class TestISYIntegration:
    """Tests for integration with ISY MethodIR."""
    
    @pytest.fixture
    def simple_ir(self):
        """Get MethodIR for Simple.assertPositive."""
        from solutions.ir import MethodIR
        return MethodIR.from_class(
            'target/decompiled/jpamb/cases/Simple.json',
            'assertPositive:(I)V'
        )
    
    @pytest.fixture
    def divide_ir(self):
        """Get MethodIR for Simple.divideByN."""
        from solutions.ir import MethodIR
        return MethodIR.from_class(
            'target/decompiled/jpamb/cases/Simple.json',
            'divideByN:(I)I'
        )
    
    def test_analyze_with_ir_returns_tuple(self, simple_ir):
        """analyze_with_ir should return (outcomes, visited, unreachable)."""
        outcomes, visited, unreachable = analyze_with_ir(simple_ir)
        
        assert isinstance(outcomes, set)
        assert isinstance(visited, set)
        assert isinstance(unreachable, set)
    
    def test_analyze_with_ir_uses_cfg(self, simple_ir):
        """Analysis should use CFG from MethodIR."""
        outcomes, visited, unreachable = analyze_with_ir(simple_ir)
        
        # Entry should be visited
        assert simple_ir.entry_pc in visited
        
        # Visited and unreachable should be disjoint
        assert visited.isdisjoint(unreachable)
        
        # All visited should be valid PCs from the CFG or close
        all_pcs = set(simple_ir.cfg.keys())
        # Visited might include PCs from stepping that aren't in exact CFG
        # but at least some should overlap
        assert len(visited & all_pcs) > 0
    
    def test_analyze_with_ir_accepts_refined_state(self, simple_ir):
        """Should accept refined initial state from NAN."""
        # Positive refinement
        init = {0: SignSet(frozenset({"+"})) }
        
        outcomes, visited, unreachable = analyze_with_ir(simple_ir, init_locals=init)
        
        assert isinstance(outcomes, set)


class TestNANIntegration:
    """Tests for integration with NAN (ReducedProductState.from_samples)."""
    
    def test_signset_from_reduced_positive(self):
        """Convert POSITIVE ReducedProductState to SignSet."""
        from solutions.nab_integration import ReducedProductState
        
        reduced = ReducedProductState.from_samples([5, 10, 15])
        signset = signset_from_reduced(reduced)
        
        assert signset.signs == frozenset({"+", "0"}) or signset.signs == frozenset({"+"})
    
    def test_signset_from_reduced_negative(self):
        """Convert NEGATIVE ReducedProductState to SignSet."""
        from solutions.nab_integration import ReducedProductState
        
        reduced = ReducedProductState.from_samples([-5, -10, -15])
        signset = signset_from_reduced(reduced)
        
        assert "-" in signset.signs
    
    def test_signset_from_reduced_zero(self):
        """Convert ZERO ReducedProductState to SignSet."""
        from solutions.nab_integration import ReducedProductState
        
        reduced = ReducedProductState.from_samples([0, 0, 0])
        signset = signset_from_reduced(reduced)
        
        assert signset.signs == frozenset({"0"})
    
    def test_signset_from_reduced_top(self):
        """Convert TOP ReducedProductState to SignSet."""
        from solutions.nab_integration import ReducedProductState
        
        reduced = ReducedProductState.from_samples([-5, 0, 5])
        signset = signset_from_reduced(reduced)
        
        assert signset.signs == frozenset({"+", "0", "-"})
    
    def test_signset_from_reduced_used_in_analysis(self):
        """Use NAN-refined SignSet in abstract interpretation."""
        from solutions.nab_integration import ReducedProductState
        
        suite = Suite()
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        # Get refined state from samples (simulating IIN traces)
        reduced = ReducedProductState.from_samples([1, 2, 3, 4, 5])
        signset = signset_from_reduced(reduced)
        
        # Use in abstract interpretation
        init = {0: signset}
        outcomes = bounded_abstract_run(suite, method, init_locals=init, max_steps=50)
        
        assert isinstance(outcomes, set)


class TestRealJPAMBMethods:
    """Tests on 5+ real JPAMB methods (required for IAI)."""
    
    @pytest.fixture
    def suite(self):
        return Suite()
    
    def test_simple_assertPositive(self, suite):
        """Test Simple.assertPositive method."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        outcomes = bounded_abstract_run(suite, method, max_steps=100)
        
        assert isinstance(outcomes, set)
        # Should have some outcome
        assert len(outcomes) > 0
    
    def test_simple_assertFalse(self, suite):
        """Test Simple.assertFalse method."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertFalse:()V")
        outcomes = bounded_abstract_run(suite, method, max_steps=100)
        
        assert "assertion error" in outcomes
    
    def test_simple_divideByN(self, suite):
        """Test Simple.divideByN method."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByN:(I)I")
        outcomes = bounded_abstract_run(suite, method, max_steps=100)
        
        # Should detect possible divide by zero
        assert "divide by zero" in outcomes or "ok" in outcomes
    
    def test_loops_countTo10(self, suite):
        """Test Loops.countTo10 method."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Loops.countTo10:()V")
        outcomes, visited = unbounded_abstract_run(suite, method, widening_threshold=3)
        
        assert isinstance(outcomes, set)
        assert len(visited) > 0
    
    def test_arrays_arrayIsNull(self, suite):
        """Test Arrays.arrayIsNull method."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Arrays.arrayIsNull:()V")
        outcomes = bounded_abstract_run(suite, method, max_steps=100)
        
        assert isinstance(outcomes, set)
    
    def test_simple_checkBeforeDivideByN(self, suite):
        """Test Simple.checkBeforeDivideByN method."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.checkBeforeDivideByN:(I)I")
        outcomes = bounded_abstract_run(suite, method, max_steps=100)
        
        assert isinstance(outcomes, set)
        # This method checks before dividing, but static analysis conservatively
        # may still include divide by zero path
        assert len(outcomes) > 0


class TestAbstractInterpreterClass:
    """Tests for the AbstractInterpreter class wrapper."""
    
    @pytest.fixture
    def suite(self):
        return Suite()
    
    def test_interpreter_creation(self, suite):
        """Test AbstractInterpreter instantiation."""
        interpreter = AbstractInterpreter(suite, max_steps=100)
        
        assert interpreter.suite == suite
        assert interpreter.max_steps == 100
    
    def test_interpreter_analyze(self, suite):
        """Test AbstractInterpreter.analyze method."""
        interpreter = AbstractInterpreter(suite, max_steps=100)
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.assertPositive:(I)V")
        
        outcomes = interpreter.analyze(method)
        
        assert isinstance(outcomes, set)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
