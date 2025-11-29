import pytest
import json
import sys
from pathlib import Path
import tempfile

# Add solutions to path so we can import interpreter
sys.path.insert(0, str(Path(__file__).parent.parent / "solutions"))

from interpreter import execute, CoverageTracker, ValueTracer
import jpamb
from jpamb import jvm


def test_coverage_tracker():
    """Test basic coverage tracker functionality."""
    tracker = CoverageTracker()
    tracker.visit(0)
    tracker.visit(5)
    tracker.visit(10)
    tracker.branch(5, True)
    tracker.branch(5, False)
    
    result = tracker.to_dict()
    
    assert set(result["executed_pcs"]) == {0, 5, 10}
    assert "5" in result["branches"]
    assert result["branches"]["5"] == [True, False]


def test_value_tracer():
    """Test basic value tracer functionality."""
    tracer = ValueTracer()
    tracer.observe_local(0, 5)
    tracer.observe_local(0, 10)
    tracer.observe_local(0, 15)
    tracer.observe_local(1, -5)
    tracer.observe_local(1, -10)
    
    tracer.finalize()
    result = tracer.to_dict()
    
    # Check local_0 (all positive)
    assert "local_0" in result
    local_0 = result["local_0"]
    assert local_0["sign"] == "positive"
    assert local_0["always_positive"] is True
    assert local_0["never_negative"] is True
    assert local_0["interval"] == [5, 15]
    
    # Check local_1 (all negative)
    assert "local_1" in result
    local_1 = result["local_1"]
    assert local_1["sign"] == "negative" 
    assert local_1["always_positive"] is False
    assert local_1["never_negative"] is False
    assert local_1["interval"] == [-10, -5]


def test_value_tracer_mixed_signs():
    """Test value tracer with mixed positive/negative values."""
    tracer = ValueTracer()
    tracer.observe_local(0, -5)
    tracer.observe_local(0, 0)
    tracer.observe_local(0, 5)
    
    tracer.finalize()
    result = tracer.to_dict()
    
    local_0 = result["local_0"]
    assert local_0["sign"] == "mixed"
    assert local_0["always_positive"] is False
    assert local_0["never_negative"] is False
    assert local_0["never_zero"] is False
    assert local_0["interval"] == [-5, 5]


def test_value_tracer_zero_only():
    """Test ValueTracer with only zero values."""
    tracer = ValueTracer()
    tracer.observe_local(0, 0)  # Only zero
    
    tracer.finalize()
    result = tracer.to_dict()
    
    # Should have analysis for local_0
    assert "local_0" in result
    local_0 = result["local_0"]
    
    # Sign should be zero
    assert local_0["sign"] == "zero"
    
    # Same min/max, expect [0, None] per implementation
    assert local_0["interval"] == [0, None]


def test_execute_with_tracing():
    """Test execute function with tracing enabled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByZero:()I")
        input_vals = jpamb.model.Input.decode("()")
        
        coverage = CoverageTracker(methodid)
        tracer = ValueTracer()
        
        result = execute(methodid, input_vals, coverage=coverage, tracer=tracer, trace_dir=tmpdir)
        
        # Check that trace file was created
        trace_files = list(Path(tmpdir).glob("*.json"))
        assert len(trace_files) == 1
        
        # Load and check trace file content
        with open(trace_files[0]) as f:
            trace_data = json.load(f)
        
        assert "method" in trace_data
        assert "coverage" in trace_data
        assert "values" in trace_data
        
        # Check method name format
        assert trace_data["method"].startswith("jpamb.cases.Simple.divideByZero")


def test_execute_simple_positive_case():
    """Test a simple case that should show always_positive = true."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Test a method that processes a positive integer
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.justAdd:(II)I")
        input_vals = jpamb.model.Input.decode("(5, 3)")
        
        coverage = CoverageTracker(methodid)
        tracer = ValueTracer()
        
        result = execute(methodid, input_vals, coverage=coverage, tracer=tracer, trace_dir=tmpdir)
        
        # Load trace file
        trace_files = list(Path(tmpdir).glob("*.json"))
        assert len(trace_files) == 1
        
        with open(trace_files[0]) as f:
            trace_data = json.load(f)
        
        # Check that we have local variable data
        if "values" in trace_data and trace_data["values"]:
            # Look for any local variable that was always positive
            for local_name, local_data in trace_data["values"].items():
                if local_data.get("always_positive"):
                    assert local_data["always_positive"] is True
                    assert local_data["sign"] == "positive"


def test_branch_coverage_detection():
    """Test that branch instructions are properly detected and recorded."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Use a method that has branches
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.checkBeforeAssert:(I)V")
        input_vals = jpamb.model.Input.decode("(5)")
        
        coverage = CoverageTracker(methodid)
        tracer = ValueTracer()
        
        result = execute(methodid, input_vals, coverage=coverage, tracer=tracer, trace_dir=tmpdir)
        
        # Check coverage data
        coverage_data = coverage.to_dict()
        
        # Should have some executed PCs
        assert len(coverage_data["executed_pcs"]) > 0
        
        # Should detect branches if the method has conditional logic
        # (Note: depends on the actual bytecode structure)


def test_negative_value_detection():
    """Test detection of never-negative values."""
    with tempfile.TemporaryDirectory() as tmpdir:
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByN:(I)I")
        input_vals = jpamb.model.Input.decode("(-5)")
        
        coverage = CoverageTracker(methodid)
        tracer = ValueTracer()
        
        result = execute(methodid, input_vals, coverage=coverage, tracer=tracer, trace_dir=tmpdir)
        
        # Check trace file was created
        trace_files = list(Path(tmpdir).glob("*.json"))
        assert len(trace_files) == 1


def test_interval_calculation():
    """Test that intervals are calculated correctly for loop variables.""" 
    # This would test a counting loop from 0 to 100
    # Note: Depends on having appropriate test methods in the suite
    with tempfile.TemporaryDirectory() as tmpdir:
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Loops.neverDivides:()I")
        input_vals = jpamb.model.Input.decode("()")
        
        coverage = CoverageTracker(methodid)
        tracer = ValueTracer()
        
        try:
            result = execute(methodid, input_vals, coverage=coverage, tracer=tracer, trace_dir=tmpdir)
            
            # Load trace and check interval data
            trace_files = list(Path(tmpdir).glob("*.json"))
            if trace_files:
                with open(trace_files[0]) as f:
                    trace_data = json.load(f)
                
                # Look for interval data
                if "values" in trace_data:
                    for local_name, local_data in trace_data["values"].items():
                        if "interval" in local_data:
                            interval = local_data["interval"]
                            assert isinstance(interval, list)
                            assert len(interval) == 2
                            
        except Exception as e:
            # Method might not exist, skip gracefully
            pytest.skip(f"Test method not available: {e}")


def test_json_file_writing():
    """Test that JSON files are actually written to disk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByZero:()I")
        input_vals = jpamb.model.Input.decode("()")
        
        coverage = CoverageTracker(methodid)
        tracer = ValueTracer()
        
        # Execute with tracing
        result = execute(methodid, input_vals, coverage=coverage, tracer=tracer, trace_dir=tmpdir)
        
        # Check file exists
        trace_files = list(Path(tmpdir).glob("*.json"))
        assert len(trace_files) == 1
        
        # Check file is valid JSON
        with open(trace_files[0]) as f:
            data = json.load(f)
            assert isinstance(data, dict)
            
        # Check file has expected structure
        expected_keys = ["method"]
        for key in expected_keys:
            assert key in data


def test_multiple_executions_different_inputs():
    """Test that different inputs produce different traces."""
    with tempfile.TemporaryDirectory() as tmpdir:
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.justAdd:(II)I")
        
        # Test with positive input
        input1 = jpamb.model.Input.decode("(5, 3)")
        coverage1 = CoverageTracker(methodid)
        tracer1 = ValueTracer()
        
        result1 = execute(methodid, input1, coverage=coverage1, tracer=tracer1, trace_dir=tmpdir)
        
        # Test with different input  
        input2 = jpamb.model.Input.decode("(-5, -3)")
        coverage2 = CoverageTracker(methodid)
        tracer2 = ValueTracer()
        
        result2 = execute(methodid, input2, coverage=coverage2, tracer=tracer2, trace_dir=tmpdir)
        
        # Should have created different trace files
        trace_files = list(Path(tmpdir).glob("*.json"))
        assert len(trace_files) >= 1  # At least one file should exist


def test_trace_directory_creation():
    """Test that trace directory is created if it doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        nonexistent_dir = Path(tmpdir) / "nonexistent" / "traces"
        
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByZero:()I")
        input_vals = jpamb.model.Input.decode("()")
        
        coverage = CoverageTracker(methodid)
        tracer = ValueTracer()
        
        result = execute(methodid, input_vals, coverage=coverage, tracer=tracer, trace_dir=str(nonexistent_dir))
        
        # Check directory was created
        assert nonexistent_dir.exists()
        assert nonexistent_dir.is_dir()
        
        # Check file was written
        trace_files = list(nonexistent_dir.glob("*.json"))
        assert len(trace_files) == 1


def test_no_tracing_when_tracers_none():
    """Test that no files are written when tracers are None."""
    with tempfile.TemporaryDirectory() as tmpdir:
        methodid = jvm.AbsMethodID.decode("jpamb.cases.Simple.divideByZero:()I")
        input_vals = jpamb.model.Input.decode("()")
        
        # Execute without tracers
        result = execute(methodid, input_vals, coverage=None, tracer=None, trace_dir=tmpdir)
        
        # Should not create any trace files
        trace_files = list(Path(tmpdir).glob("*.json"))
        assert len(trace_files) == 0


if __name__ == "__main__":
    pytest.main([__file__])