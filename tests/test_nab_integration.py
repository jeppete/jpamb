"""
Test suite for NAB Integration module.

Tests the integration between IIN (dynamic traces) and IAB (abstract domains).
Verifies that dynamic refinement heuristics correctly infer abstract states
from concrete execution samples.

DTU 02242 Program Analysis - Group 21
"""

import pytest
import json
import tempfile
import os
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import NAB integration module
from solutions.nab_integration import (
    integrate_abstractions,
    integrate_abstractions_full,
    integrate_all_traces,
    extract_samples_from_trace,
    refine_from_trace,
    get_sign_for_local,
    get_interval_for_local,
    process_example,
    AbstractValue,
    IntegrationResult,
)

# Import IAB abstract domains
from solutions.abstractions import (
    SignDomain,
    SignValue,
    IntervalDomain,
    IntervalValue,
)


class TestProposalExample:
    """Tests for the proposal example from §1.3.1."""
    
    def test_proposal_example_positive_samples(self):
        """
        Proposal example: process(int x) with samples [5, 10, ...]
        should refine local_1 to sign = positive.
        """
        result = process_example()
        
        assert 1 in result
        assert result[1].sign.value == SignValue.POSITIVE
        assert result[1].local_index == 1
    
    def test_proposal_example_interval(self):
        """
        Proposal example: samples [5, 10, 15, 20, 25] should give
        interval [5, 25].
        """
        result = process_example()
        
        assert 1 in result
        assert result[1].interval.value.low == 5
        assert result[1].interval.value.high == 25


class TestSignDomainRefinement:
    """Tests for sign domain refinement from samples."""
    
    def test_positive_samples_give_positive_sign(self):
        """All positive samples should refine to POSITIVE sign."""
        samples = [5, 10, 15, 100, 999]
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.POSITIVE
    
    def test_negative_samples_give_negative_sign(self):
        """All negative samples should refine to NEGATIVE sign."""
        samples = [-5, -10, -15, -100, -999]
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.NEGATIVE
    
    def test_zero_samples_give_zero_sign(self):
        """All zero samples should refine to ZERO sign."""
        samples = [0, 0, 0, 0]
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.ZERO
    
    def test_mixed_positive_negative_give_non_zero(self):
        """Mixed positive and negative (no zero) should give NON_ZERO."""
        samples = [5, -10, 15, -20]
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.NON_ZERO
    
    def test_positive_and_zero_give_non_negative(self):
        """Positive and zero samples should give NON_NEGATIVE."""
        samples = [0, 5, 10, 0, 15]
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.NON_NEGATIVE
    
    def test_negative_and_zero_give_non_positive(self):
        """Negative and zero samples should give NON_POSITIVE."""
        samples = [0, -5, -10, 0, -15]
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.NON_POSITIVE
    
    def test_all_signs_give_top(self):
        """Positive, negative, and zero should give TOP."""
        samples = [-5, 0, 5, -10, 10]
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.TOP
    
    def test_empty_samples_give_bottom(self):
        """Empty samples should give BOTTOM."""
        samples = []
        sign_domain, _ = refine_from_trace(samples)
        
        assert sign_domain.value == SignValue.BOTTOM


class TestIntervalDomainRefinement:
    """Tests for interval domain refinement from samples."""
    
    def test_interval_bounds_from_samples(self):
        """Interval should have min and max of samples."""
        samples = [5, 10, 15, 20, 25]
        _, interval_domain = refine_from_trace(samples)
        
        assert interval_domain.value.low == 5
        assert interval_domain.value.high == 25
    
    def test_single_sample_interval(self):
        """Single sample should give point interval."""
        samples = [42]
        _, interval_domain = refine_from_trace(samples)
        
        assert interval_domain.value.low == 42
        assert interval_domain.value.high == 42
    
    def test_negative_interval(self):
        """Negative samples should give negative interval."""
        samples = [-100, -50, -25, -10]
        _, interval_domain = refine_from_trace(samples)
        
        assert interval_domain.value.low == -100
        assert interval_domain.value.high == -10
    
    def test_mixed_interval(self):
        """Mixed samples should span negative to positive."""
        samples = [-50, -25, 0, 25, 50]
        _, interval_domain = refine_from_trace(samples)
        
        assert interval_domain.value.low == -50
        assert interval_domain.value.high == 50
    
    def test_empty_samples_give_bottom_interval(self):
        """Empty samples should give bottom interval."""
        samples = []
        _, interval_domain = refine_from_trace(samples)
        
        assert interval_domain.is_bottom()


class TestTraceExtraction:
    """Tests for extracting samples from IIN trace data."""
    
    def test_extract_samples_from_trace_data(self):
        """Extract samples from typical IIN trace format."""
        trace_data = {
            "method": "test.Method.foo:(I)V",
            "values": {
                "local_0": {
                    "samples": [1, 2, 3, 4, 5],
                    "sign": "positive"
                }
            }
        }
        
        samples = extract_samples_from_trace(trace_data)
        
        assert 0 in samples
        assert samples[0] == [1, 2, 3, 4, 5]
    
    def test_extract_multiple_locals(self):
        """Extract samples for multiple local variables."""
        trace_data = {
            "values": {
                "local_0": {"samples": [1, 2, 3]},
                "local_1": {"samples": [-1, -2, -3]},
                "local_2": {"samples": [0, 0, 0]}
            }
        }
        
        samples = extract_samples_from_trace(trace_data)
        
        assert len(samples) == 3
        assert samples[0] == [1, 2, 3]
        assert samples[1] == [-1, -2, -3]
        assert samples[2] == [0, 0, 0]
    
    def test_extract_empty_values(self):
        """Handle trace with no values section."""
        trace_data = {
            "method": "test.Method.foo:(I)V",
            "coverage": {"executed_pcs": [0, 1, 2]}
        }
        
        samples = extract_samples_from_trace(trace_data)
        
        assert samples == {}


class TestIntegration:
    """Integration tests using actual trace file format."""
    
    @pytest.fixture
    def temp_trace_file(self):
        """Create a temporary trace file for testing."""
        trace_data = {
            "method": "jpamb.cases.Test.process:(I)V",
            "coverage": {
                "executed_pcs": [0, 1, 2, 3],
                "uncovered_pcs": [4, 5],
                "branches": {"1": [True]}
            },
            "values": {
                "local_0": {
                    "samples": [5, 10, 15, 20, 25],
                    "always_positive": True,
                    "never_negative": True,
                    "never_zero": True,
                    "sign": "positive",
                    "interval": [5, 25]
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(trace_data, f)
            temp_path = f.name
        
        yield temp_path
        
        # Cleanup
        os.unlink(temp_path)
    
    def test_integrate_abstractions_from_file(self, temp_trace_file):
        """Test main integration function with temp file."""
        result = integrate_abstractions(temp_trace_file)
        
        assert 0 in result
        assert result[0].sign.value == SignValue.POSITIVE
        assert result[0].interval.value.low == 5
        assert result[0].interval.value.high == 25
    
    def test_integrate_abstractions_full(self, temp_trace_file):
        """Test full integration with metadata."""
        result = integrate_abstractions_full(temp_trace_file)
        
        assert isinstance(result, IntegrationResult)
        assert result.method_name == "jpamb.cases.Test.process:(I)V"
        assert 0 in result.abstract_values
        assert result.confidence > 0.5
    
    def test_abstract_value_to_dict(self, temp_trace_file):
        """Test AbstractValue serialization."""
        result = integrate_abstractions(temp_trace_file)
        
        assert 0 in result
        value_dict = result[0].to_dict()
        
        assert "local_index" in value_dict
        assert "sign" in value_dict
        assert "interval" in value_dict
        assert value_dict["local_index"] == 0


class TestRealTraces:
    """Tests against actual traces in traces/ directory."""
    
    @pytest.fixture
    def traces_dir(self):
        """Get the traces directory path."""
        base_dir = Path(__file__).parent.parent
        traces_path = base_dir / "traces"
        if traces_path.exists():
            return traces_path
        return None
    
    def test_integrate_real_trace_positive(self, traces_dir):
        """Test integration with real assertPositive trace."""
        if traces_dir is None:
            pytest.skip("traces directory not found")
        
        trace_file = traces_dir / "jpamb.cases.Simple_assertPositive_IV.json"
        if not trace_file.exists():
            pytest.skip("assertPositive trace not found")
        
        result = integrate_abstractions(str(trace_file))
        
        # local_0 should have positive samples [1,1,1,1,1]
        assert 0 in result
        assert result[0].sign.value == SignValue.POSITIVE
    
    def test_integrate_all_traces(self, traces_dir):
        """Test integration of all traces in directory."""
        if traces_dir is None:
            pytest.skip("traces directory not found")
        
        results = integrate_all_traces(str(traces_dir))
        
        # Should have results for multiple methods
        assert len(results) > 0
        
        # Each result should have valid structure
        for method_name, result in results.items():
            assert isinstance(result, IntegrationResult)
            assert result.method_name == method_name


class TestEdgeCases:
    """Edge case tests."""
    
    def test_file_not_found(self):
        """Should raise FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            integrate_abstractions("nonexistent_file.json")
    
    def test_get_sign_for_local_convenience(self):
        """Test convenience function for getting sign."""
        # Create temp file
        trace_data = {
            "values": {
                "local_0": {"samples": [5, 10, 15]}
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(trace_data, f)
            temp_path = f.name
        
        try:
            sign = get_sign_for_local(temp_path, 0)
            assert sign == SignValue.POSITIVE
            
            # Non-existent local should return TOP
            sign_missing = get_sign_for_local(temp_path, 99)
            assert sign_missing == SignValue.TOP
        finally:
            os.unlink(temp_path)
    
    def test_get_interval_for_local_convenience(self):
        """Test convenience function for getting interval."""
        trace_data = {
            "values": {
                "local_0": {"samples": [5, 10, 15]}
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(trace_data, f)
            temp_path = f.name
        
        try:
            interval = get_interval_for_local(temp_path, 0)
            assert interval.low == 5
            assert interval.high == 15
            
            # Non-existent local should return TOP
            interval_missing = get_interval_for_local(temp_path, 99)
            assert interval_missing.low is None
            assert interval_missing.high is None
        finally:
            os.unlink(temp_path)


class TestBooleanSamples:
    """Tests for handling boolean samples."""
    
    def test_boolean_true_samples(self):
        """Boolean True values should be treated as 1."""
        trace_data = {
            "values": {
                "local_0": {"samples": [True, True, True]}
            }
        }
        
        samples = extract_samples_from_trace(trace_data)
        
        assert 0 in samples
        # True is treated as integer 1
        assert all(isinstance(s, (int, bool)) for s in samples[0])
    
    def test_mixed_boolean_integer(self):
        """Mixed boolean and integer samples."""
        trace_data = {
            "values": {
                "local_0": {"samples": [True, 1, False, 0]}
            }
        }
        
        samples = extract_samples_from_trace(trace_data)
        
        assert 0 in samples
        assert len(samples[0]) == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
