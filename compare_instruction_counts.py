#!/usr/bin/env python3
"""
Compare instruction counts between pipeline and debloater approaches.
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from jpamb import jvm

# Get instruction counts from pipeline approach (ALL methods from decompiled)
def get_pipeline_counts():
    """Get instruction counts from pipeline_evaluation.py approach (comprehensive).
    
    Counts instructions directly from JSON like debloater does.
    """
    from solutions.pipeline_evaluation import list_all_methods_from_decompiled
    
    # Build a map of method_id -> instruction count from JSON
    decompiled_dir = Path("target/decompiled/jpamb/cases")
    json_counts = {}
    
    for json_file in decompiled_dir.glob("*.json"):
        with open(json_file) as f:
            data = json.load(f)
        
        class_name = "jpamb.cases." + json_file.stem
        
        for method in data.get('methods', []):
            method_name = method.get('name')
            bytecode = method.get('code', {}).get('bytecode', [])
            
            # Build descriptor using jvm.MethodID
            params = jvm.ParameterType.from_json(
                method.get("params", []), annotated=True
            )
            returns_info = method.get("returns", {})
            return_type_json = returns_info.get("type")
            if return_type_json is None:
                return_type = None
            else:
                return_type = jvm.Type.from_json(return_type_json)
            
            method_id_obj = jvm.MethodID(
                name=method_name, 
                params=params, 
                return_type=return_type
            )
            
            encoded = method_id_obj.encode()
            desc = encoded.split(":", 1)[1] if ":" in encoded else "()V"
            
            method_id = f"{class_name}.{method_name}:{desc}"
            json_counts[method_id] = len(bytecode)
    
    # Return only methods that list_all_methods_from_decompiled returns
    all_methods = set(list_all_methods_from_decompiled())
    return {m: c for m, c in json_counts.items() if m in all_methods}

def _trace_to_method_id(trace_name: str):
    """Convert trace filename to method_id."""
    parts = trace_name.split("_")
    if len(parts) < 2:
        return None
    
    descriptor = parts[-1]
    remaining = "_".join(parts[:-1])
    
    dot_parts = remaining.split(".")
    if len(dot_parts) < 3:
        return None
    
    last = dot_parts[-1]
    underscore_idx = last.find("_")
    if underscore_idx <= 0:
        return None
    
    class_name = ".".join(dot_parts[:-1]) + "." + last[:underscore_idx]
    method_name = last[underscore_idx + 1:]
    
    if len(descriptor) > 0:
        ret = descriptor[-1]
        params = descriptor[:-1]
        desc = f"({params}){ret}"
    else:
        desc = "()V"
    
    return f"{class_name}.{method_name}:{desc}"

# Get instruction counts from debloater approach
def get_debloater_counts():
    """Get instruction counts from debloater.py approach."""
    from jpamb import jvm
    
    counts = {}
    
    # Read decompiled JSON files
    decompiled_dir = Path("target/decompiled/jpamb/cases")
    
    for json_file in decompiled_dir.glob("*.json"):
        with open(json_file) as f:
            data = json.load(f)
        
        class_name = "jpamb.cases." + json_file.stem
        
        for method in data.get('methods', []):
            method_name = method.get('name')
            bytecode = method.get('code', {}).get('bytecode', [])
            
            # Build descriptor properly like debloater does
            params = jvm.ParameterType.from_json(
                method.get("params", []), annotated=True
            )
            returns_info = method.get("returns", {})
            return_type_json = returns_info.get("type")
            if return_type_json is None:
                return_type = None
            else:
                return_type = jvm.Type.from_json(return_type_json)
            
            method_id_obj = jvm.MethodID(
                name=method_name, 
                params=params, 
                return_type=return_type
            )
            
            # encode() returns "name:(params)return", extract descriptor
            encoded = method_id_obj.encode()
            desc = encoded.split(":", 1)[1] if ":" in encoded else "()V"
            
            method_id = f"{class_name}.{method_name}:{desc}"
            counts[method_id] = len(bytecode)
    
    
    return counts

def main():
    print("Comparing instruction counts between approaches...")
    print("=" * 80)
    
    pipeline_counts = get_pipeline_counts()
    debloater_counts = get_debloater_counts()
    
    # Find common methods
    common_methods = set(pipeline_counts.keys()) & set(debloater_counts.keys())
    pipeline_only = set(pipeline_counts.keys()) - set(debloater_counts.keys())
    debloater_only = set(debloater_counts.keys()) - set(pipeline_counts.keys())
    
    print(f"\nPipeline approach: {len(pipeline_counts)} methods")
    print(f"Debloater approach: {len(debloater_counts)} methods")
    print(f"Common methods: {len(common_methods)}")
    print(f"Pipeline only: {len(pipeline_only)}")
    print(f"Debloater only: {len(debloater_only)}")
    
    # Show methods only in debloater
    if debloater_only:
        print(f"\nMethods only in debloater ({len(debloater_only)}):")
        debloater_only_instr = 0
        for method_id in sorted(debloater_only):
            count = debloater_counts[method_id]
            debloater_only_instr += count
            short_name = method_id.split(".")[-1]
            print(f"  {short_name} ({count} instr)")
        print(f"  Total: {debloater_only_instr} instructions")
    
    # Show methods only in pipeline
    if pipeline_only:
        print(f"\nMethods only in pipeline ({len(pipeline_only)}):")
        pipeline_only_instr = 0
        for method_id in sorted(pipeline_only):
            count = pipeline_counts[method_id]
            pipeline_only_instr += count
            short_name = method_id.split(".")[-1]
            print(f"  {short_name} ({count} instr)")
        print(f"  Total: {pipeline_only_instr} instructions")
    
    # Compare counts
    differences = []
    for method_id in sorted(common_methods):
        pipeline_count = pipeline_counts[method_id]
        debloater_count = debloater_counts[method_id]
        
        if pipeline_count != debloater_count:
            differences.append((method_id, pipeline_count, debloater_count))
    
    if differences:
        print(f"\nFound {len(differences)} methods with different instruction counts:")
        print("-" * 80)
        print(f"{'Method':<50} {'Pipeline':<12} {'Debloater':<12} {'Diff'}")
        print("-" * 80)
        
        for method_id, p_count, d_count in differences:
            short_name = method_id.split(".")[-1]
            diff = d_count - p_count
            print(f"{short_name:<50} {p_count:<12} {d_count:<12} {diff:+d}")
    else:
        print("\nAll common methods have the same instruction count! ✓")
    
    # Show totals
    pipeline_total = sum(pipeline_counts.values())
    debloater_total = sum(debloater_counts.values())
    
    print("\n" + "=" * 80)
    print("TOTALS:")
    print(f"  Pipeline:  {pipeline_total} instructions")
    print(f"  Debloater: {debloater_total} instructions")
    print(f"  Difference: {debloater_total - pipeline_total:+d}")

if __name__ == "__main__":
    main()
