#!/usr/bin/env python3
"""Check for methods with ISY but no IAI."""

import sys
from solutions.pipeline_evaluation import run_pipeline

# Test the failing method
method = "jpamb.cases.AbstractInterpreterCases.squareCheck:(I)I"
print(f"Testing: {method}")
result = run_pipeline(method, verbose=True)

print(f"Methods with ISY: {len(all_with_isy)}")
print(f"Methods with both ISY and IAI: {len(all_with_iai)}")
print(f"Methods with ISY but no IAI: {len(has_isy_no_iai)}")
print(f"Missing instructions: {missing}")
print(f"Total instructions (all ISY): {sum(r.isy.instruction_count for r in all_with_isy)}")
print(f"Total instructions (only ISY+IAI): {sum(r.isy.instruction_count for r in all_with_iai)}")
print()

if has_isy_no_iai:
    print("Methods missing IAI:")
    for r in has_isy_no_iai:
        print(f"  {r.method_id}: {r.isy.instruction_count} instructions")
