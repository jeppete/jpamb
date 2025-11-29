import json
import tempfile
from pathlib import Path
from jpamb import jvm

# Import the new classes from the interpreter
import sys
sys.path.append(str(Path(__file__).parent.parent / "solutions"))
from interpreter import TraceRefiner, AbstractDomain, AbstractState, RefinementResult


class TestTraceRefiner:
    """Test cases for the TraceRefiner functionality."""

    def test_abstract_domain_inference_positive(self):
        """Test inference of positive abstract domain."""
        refiner = TraceRefiner()
        analysis = {
            "sign": "positive",
            "always_positive": True,
            "never_negative": True,
            "never_zero": True
        }
        
        domain = refiner._infer_abstract_domain(analysis)
        assert domain == AbstractDomain.POSITIVE

    def test_abstract_domain_inference_negative(self):
        """Test inference of negative abstract domain."""
        refiner = TraceRefiner()
        analysis = {
            "sign": "negative",
            "always_positive": False,
            "never_negative": False,
            "never_zero": True
        }
        
        domain = refiner._infer_abstract_domain(analysis)
        assert domain == AbstractDomain.NEGATIVE

    def test_abstract_domain_inference_zero(self):
        """Test inference of zero abstract domain."""
        refiner = TraceRefiner()
        analysis = {
            "sign": "zero",
            "always_positive": False,
            "never_negative": True,
            "never_zero": False
        }
        
        domain = refiner._infer_abstract_domain(analysis)
        assert domain == AbstractDomain.ZERO

    def test_abstract_domain_inference_non_negative(self):
        """Test inference of non-negative abstract domain."""
        refiner = TraceRefiner()
        analysis = {
            "sign": "mixed",
            "always_positive": False,
            "never_negative": True,
            "never_zero": False
        }
        
        domain = refiner._infer_abstract_domain(analysis)
        assert domain == AbstractDomain.NON_NEGATIVE

    def test_abstract_domain_inference_non_zero(self):
        """Test inference of non-zero abstract domain."""
        refiner = TraceRefiner()
        analysis = {
            "sign": "mixed",
            "always_positive": False,
            "never_negative": False,
            "never_zero": True
        }
        
        domain = refiner._infer_abstract_domain(analysis)
        assert domain == AbstractDomain.NON_ZERO

    def test_abstract_domain_inference_top(self):
        """Test inference of TOP abstract domain for mixed values."""
        refiner = TraceRefiner()
        analysis = {
            "sign": "mixed",
            "always_positive": False,
            "never_negative": False,
            "never_zero": False
        }
        
        domain = refiner._infer_abstract_domain(analysis)
        assert domain == AbstractDomain.TOP

    def test_confidence_calculation_full_coverage(self):
        """Test confidence calculation with full coverage."""
        refiner = TraceRefiner()
        trace_data = {
            "coverage": {
                "executed_pcs": [0, 1, 2, 3],
                "uncovered_pcs": [],
                "branches": {"1": [True], "3": [False]}
            }
        }
        
        confidence = refiner._calculate_confidence(trace_data)
        assert confidence == 0.95  # Full coverage + branch boost, capped at 0.95

    def test_confidence_calculation_partial_coverage(self):
        """Test confidence calculation with partial coverage."""
        refiner = TraceRefiner()
        trace_data = {
            "coverage": {
                "executed_pcs": [0, 1],
                "uncovered_pcs": [2, 3],
                "branches": {}
            }
        }
        
        confidence = refiner._calculate_confidence(trace_data)
        assert confidence == 0.5  # 50% coverage, no branch boost

    def test_confidence_calculation_no_coverage(self):
        """Test confidence calculation with no coverage data."""
        refiner = TraceRefiner()
        trace_data = {}
        
        confidence = refiner._calculate_confidence(trace_data)
        assert confidence == 0.5  # Default confidence

    def test_refine_simple_trace(self):
        """Test refining a simple trace with value analysis."""
        refiner = TraceRefiner()
        trace_data = {
            "method": "jpamb.cases.Simple.justAdd:(II)I",
            "coverage": {
                "executed_pcs": [0, 1, 2, 3],
                "uncovered_pcs": [],
                "branches": {}
            },
            "values": {
                "local_0": {
                    "samples": [1, 1, 1, 1],
                    "always_positive": True,
                    "never_negative": True,
                    "never_zero": True,
                    "sign": "positive",
                    "interval": [1, None]
                },
                "local_1": {
                    "samples": [2, 2, 2, 2],
                    "always_positive": True,
                    "never_negative": True,
                    "never_zero": True,
                    "sign": "positive",
                    "interval": [2, None]
                }
            }
        }
        
        result = refiner.refine_trace(trace_data)
        
        assert isinstance(result, RefinementResult)
        assert len(result.initial_states) == 1
        assert result.confidence == 0.95  # Capped confidence
        assert len(result.refined_coverage) == 4
        
        initial_state = result.initial_states[0]
        assert len(initial_state.locals) == 2
        assert initial_state.locals[0] == AbstractDomain.POSITIVE
        assert initial_state.locals[1] == AbstractDomain.POSITIVE
        assert initial_state.pc == 0

    def test_refine_trace_no_values(self):
        """Test refining a trace with no value analysis."""
        refiner = TraceRefiner()
        trace_data = {
            "method": "jpamb.cases.Simple.justReturn:()I",
            "coverage": {
                "executed_pcs": [0, 1],
                "uncovered_pcs": [],
                "branches": {}
            }
        }
        
        result = refiner.refine_trace(trace_data)
        
        assert isinstance(result, RefinementResult)
        assert len(result.initial_states) == 0  # No values to analyze
        assert result.confidence == 0.95  # Capped confidence
        assert len(result.refined_coverage) == 2

    def test_abstract_state_encoding(self):
        """Test encoding of abstract states."""
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.test:(I)V")
        state = AbstractState(
            locals={0: AbstractDomain.POSITIVE, 1: AbstractDomain.ZERO},
            pc=5,
            method=method
        )
        
        encoded = state.encode()
        expected = f"{method}:5[0:+,1:0]"
        assert encoded == expected

    def test_refine_multiple_traces_success(self):
        """Test refining multiple trace files successfully."""
        refiner = TraceRefiner()
        
        # Create temporary trace files
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            
            # Create first trace file
            trace1_data = {
                "method": "jpamb.cases.Simple.justAdd:(II)I",
                "coverage": {"executed_pcs": [0, 1], "uncovered_pcs": [], "branches": {}},
                "values": {
                    "local_0": {
                        "samples": [1], "always_positive": True, "never_negative": True, 
                        "never_zero": True, "sign": "positive", "interval": [1, None]
                    }
                }
            }
            
            trace1_path = trace_dir / "trace1.json"
            with open(trace1_path, 'w') as f:
                json.dump(trace1_data, f)
            
            # Create second trace file
            trace2_data = {
                "method": "jpamb.cases.Simple.justReturn:()I",
                "coverage": {"executed_pcs": [0], "uncovered_pcs": [], "branches": {}}
            }
            
            trace2_path = trace_dir / "trace2.json"
            with open(trace2_path, 'w') as f:
                json.dump(trace2_data, f)
            
            # Refine multiple traces
            results = refiner.refine_multiple_traces([trace1_path, trace2_path])
            
            assert len(results) == 2
            assert "jpamb.cases.Simple.justAdd:(II)I" in results
            assert "jpamb.cases.Simple.justReturn:()I" in results

    def test_refine_multiple_traces_with_errors(self):
        """Test refining multiple traces with some invalid files."""
        refiner = TraceRefiner()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            
            # Create valid trace file
            valid_trace_data = {
                "method": "jpamb.cases.Simple.justReturn:()I",
                "coverage": {"executed_pcs": [0], "uncovered_pcs": [], "branches": {}}
            }
            
            valid_trace_path = trace_dir / "valid.json"
            with open(valid_trace_path, 'w') as f:
                json.dump(valid_trace_data, f)
            
            # Create invalid trace file
            invalid_trace_path = trace_dir / "invalid.json"
            with open(invalid_trace_path, 'w') as f:
                f.write("invalid json content")
            
            # Refine traces (should handle errors gracefully)
            results = refiner.refine_multiple_traces([valid_trace_path, invalid_trace_path])
            
            assert len(results) == 1  # Only valid trace should be processed
            assert "jpamb.cases.Simple.justReturn:()I" in results

    def test_generate_initial_state_file(self):
        """Test generating initial state file."""
        refiner = TraceRefiner()
        
        # Create mock refinement results
        method = jvm.AbsMethodID.decode("jpamb.cases.Simple.test:(I)V")
        initial_state = AbstractState(
            locals={0: AbstractDomain.POSITIVE},
            pc=0,
            method=method
        )
        
        refinement_result = RefinementResult(
            initial_states=[initial_state],
            refined_coverage={0: {AbstractDomain.POSITIVE}, 1: {AbstractDomain.TOP}},
            confidence=0.9,
            method=method
        )
        
        results = {
            "jpamb.cases.Simple.test:(I)V": refinement_result
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "output.json"
            
            refiner.generate_initial_state_file(results, output_path)
            
            # Verify file was created
            assert output_path.exists()
            
            # Verify content
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert "format_version" in data
            assert "methods" in data
            assert "jpamb.cases.Simple.test:(I)V" in data["methods"]
            
            method_data = data["methods"]["jpamb.cases.Simple.test:(I)V"]
            assert method_data["confidence"] == 0.9
            assert len(method_data["initial_states"]) == 1
            assert len(method_data["coverage_points"]) == 2

    def test_integration_with_real_trace_file(self):
        """Integration test with a real trace file format."""
        refiner = TraceRefiner()
        
        # Create trace data matching the actual format from our traces
        trace_data = {
            "method": "jpamb.cases.Simple.divideByN:(I)I",
            "coverage": {
                "executed_pcs": [0, 1, 2, 3],
                "uncovered_pcs": [],
                "branches": {}
            },
            "values": {
                "local_0": {
                    "samples": [1, 1, 1, 1],
                    "always_positive": True,
                    "never_negative": True,
                    "never_zero": True,
                    "sign": "positive",
                    "interval": [1, None]
                }
            }
        }
        
        result = refiner.refine_trace(trace_data)
        
        # Verify the result matches expected structure
        assert "Simple" in str(result.method.classname.name)
        assert "divideByN" in str(result.method.extension)
        assert len(result.initial_states) == 1
        
        # Check that the initial state correctly captures the input parameter
        initial_state = result.initial_states[0]
        assert initial_state.locals[0] == AbstractDomain.POSITIVE
        assert initial_state.pc == 0

    def test_abstract_domain_enum_values(self):
        """Test that abstract domain enum has correct values."""
        assert AbstractDomain.TOP.value == "⊤"
        assert AbstractDomain.BOTTOM.value == "⊥"
        assert AbstractDomain.ZERO.value == "0"
        assert AbstractDomain.POSITIVE.value == "+"
        assert AbstractDomain.NEGATIVE.value == "-"
        assert AbstractDomain.NON_ZERO.value == "≠0"
        assert AbstractDomain.NON_NEGATIVE.value == "≥0"
        assert AbstractDomain.NON_POSITIVE.value == "≤0"