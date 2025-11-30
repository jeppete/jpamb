#!/usr/bin/env python3
"""
Verify abstract interpreter using javap as ground truth.

This script parses javap output to get the correct bytecode structure,
then compares with the abstract interpreter's dead code detection.
"""

import subprocess
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional


@dataclass
class JavapMethod:
    """Parsed method from javap output."""
    name: str
    bytecode: List[Tuple[int, str, Optional[int]]]  # (offset, instruction, jump_target)
    line_table: Dict[int, int]  # line -> offset
    offset_to_line: Dict[int, int]  # offset -> line (computed)
    
    def get_all_offsets(self) -> Set[int]:
        return {offset for offset, _, _ in self.bytecode}
    
    def get_line_for_offset(self, offset: int) -> Optional[int]:
        """Find the source line for a bytecode offset."""
        # Find the largest line table entry <= offset
        best_line = None
        best_offset = -1
        for line, line_offset in self.line_table.items():
            if line_offset <= offset and line_offset > best_offset:
                best_line = line
                best_offset = line_offset
        return best_line


def parse_javap_output(javap_output: str) -> Dict[str, JavapMethod]:
    """Parse javap -c -l output into structured data."""
    methods = {}
    
    lines = javap_output.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Look for method signature
        method_match = re.match(r'\s+public static \w+ (\w+)\(', line)
        if method_match:
            method_name = method_match.group(1)
            bytecode = []
            line_table = {}
            
            i += 1
            # Skip to Code:
            while i < len(lines) and 'Code:' not in lines[i]:
                i += 1
            i += 1
            
            # Parse bytecode
            while i < len(lines):
                bc_line = lines[i].strip()
                
                if bc_line.startswith('LineNumberTable:'):
                    i += 1
                    # Parse line number table
                    while i < len(lines):
                        ln_line = lines[i].strip()
                        ln_match = re.match(r'line (\d+): (\d+)', ln_line)
                        if ln_match:
                            line_num = int(ln_match.group(1))
                            offset = int(ln_match.group(2))
                            line_table[line_num] = offset
                            i += 1
                        else:
                            break
                    break
                
                # Parse bytecode instruction
                bc_match = re.match(r'(\d+): (\w+)', bc_line)
                if bc_match:
                    offset = int(bc_match.group(1))
                    instr = bc_match.group(2)
                    
                    # Extract jump target if present
                    jump_target = None
                    target_match = re.search(r'\s+(\d+)(?:\s|$)', bc_line)
                    if target_match and instr in ('if_icmple', 'if_icmpge', 'if_icmplt', 'if_icmpgt',
                                                    'if_icmpeq', 'if_icmpne', 'ifle', 'ifge', 'iflt',
                                                    'ifgt', 'ifeq', 'ifne', 'ifnull', 'ifnonnull',
                                                    'goto', 'goto_w'):
                        jump_target = int(target_match.group(1))
                    
                    bytecode.append((offset, instr, jump_target))
                
                i += 1
                if not bc_line or bc_line.startswith('public') or bc_line.startswith('static'):
                    break
            
            # Compute offset_to_line mapping
            offset_to_line = {}
            sorted_lines = sorted(line_table.items(), key=lambda x: x[1])
            for offset, _, _ in bytecode:
                for line, line_offset in reversed(sorted_lines):
                    if line_offset <= offset:
                        offset_to_line[offset] = line
                        break
            
            methods[method_name] = JavapMethod(
                name=method_name,
                bytecode=bytecode,
                line_table=line_table,
                offset_to_line=offset_to_line
            )
        
        i += 1
    
    return methods


def analyze_dead_code_ground_truth(method: JavapMethod) -> Dict[str, Set[int]]:
    """
    Analyze dead code using javap bytecode as ground truth.
    
    This performs a simple reachability analysis based on control flow.
    Returns dict with 'expected_dead_lines' based on the bytecode structure.
    """
    # Build control flow
    offsets = method.get_all_offsets()
    offset_list = sorted(offsets)
    
    # For each conditional branch, identify the dead branch based on the condition
    # This is a simplified analysis - the real abstract interpreter does more
    
    result = {
        'all_offsets': offsets,
        'branch_info': [],
    }
    
    for offset, instr, target in method.bytecode:
        if target is not None:
            result['branch_info'].append({
                'offset': offset,
                'instruction': instr,
                'target': target,
                'line': method.offset_to_line.get(offset)
            })
    
    return result


def run_abstract_interpreter_on_method(suite, classname, method_name, method_dict):
    """Run abstract interpreter on a single method and return dead offsets."""
    import sys
    sys.path.insert(0, 'solutions')
    from jpamb import jvm
    from components.abstract_interpreter import product_unbounded_run
    
    params = jvm.ParameterType.from_json(method_dict.get('params', []), annotated=True)
    returns_info = method_dict.get('returns', {})
    return_type_json = returns_info.get('type')
    return_type = jvm.Type.from_json(return_type_json) if return_type_json else None
    
    method_id = jvm.MethodID(name=method_name, params=params, return_type=return_type)
    abs_method = jvm.AbsMethodID(classname=classname, extension=method_id)
    
    outcomes, visited_pcs = product_unbounded_run(suite, abs_method)
    
    bytecode = method_dict['code']['bytecode']
    all_pcs = {inst['offset'] for inst in bytecode}
    unreachable = all_pcs - visited_pcs
    
    return unreachable, visited_pcs


def main():
    import sys
    sys.path.insert(0, 'solutions')
    import jpamb
    from jpamb import jvm
    
    # Get javap output
    class_file = 'target/classes/jpamb/cases/AbstractInterpreterCases.class'
    result = subprocess.run(
        ['javap', '-c', '-l', class_file],
        capture_output=True, text=True
    )
    javap_output = result.stdout
    
    # Parse javap
    javap_methods = parse_javap_output(javap_output)
    
    print("=" * 70)
    print("ABSTRACT INTERPRETER VERIFICATION (using javap as ground truth)")
    print("=" * 70)
    
    # Load suite and class
    suite = jpamb.Suite()
    classname = jvm.ClassName('jpamb/cases/AbstractInterpreterCases')
    cls = suite.findclass(classname)
    
    # Test specific methods known to have dead code
    test_methods = [
        'contradictoryConditions',
        'signContradiction', 
        'positiveNotZero',
        'rangeAnalysis',
        'constantPropagation',
        'arithmeticConstraints',
    ]
    
    for method_name in test_methods:
        if method_name not in javap_methods:
            print(f"\n{method_name}: NOT FOUND in javap output")
            continue
            
        javap_method = javap_methods[method_name]
        
        # Find method in JSON
        method_dict = None
        for m in cls['methods']:
            if m['name'] == method_name:
                method_dict = m
                break
        
        if not method_dict:
            print(f"\n{method_name}: NOT FOUND in JSON")
            continue
        
        print(f"\n{'=' * 70}")
        print(f"METHOD: {method_name}")
        print(f"{'=' * 70}")
        
        # Run abstract interpreter
        try:
            dead_offsets, visited = run_abstract_interpreter_on_method(
                suite, classname, method_name, method_dict
            )
        except Exception as e:
            print(f"  ERROR running abstract interpreter: {e}")
            continue
        
        # Get JSON offsets
        json_offsets = {inst['offset'] for inst in method_dict['code']['bytecode']}
        javap_offsets = javap_method.get_all_offsets()
        
        print(f"\nOFFSET COMPARISON:")
        print(f"  javap offsets:  {sorted(javap_offsets)}")
        print(f"  JSON offsets:   {sorted(json_offsets)}")
        
        if javap_offsets != json_offsets:
            print(f"  ⚠️  MISMATCH! JSON has different offsets than javap")
            missing_in_json = javap_offsets - json_offsets
            extra_in_json = json_offsets - javap_offsets
            if missing_in_json:
                print(f"  Missing in JSON: {sorted(missing_in_json)}")
            if extra_in_json:
                print(f"  Extra in JSON: {sorted(extra_in_json)}")
        else:
            print(f"  ✓ Offsets match")
        
        # Compare line tables
        print(f"\nLINE TABLE COMPARISON:")
        json_lines = {l['offset']: l['line'] for l in method_dict['code']['lines']}
        javap_lines = {v: k for k, v in javap_method.line_table.items()}  # offset -> line
        
        print(f"  javap line table: {javap_method.line_table}")
        print(f"  JSON line table:  { {l['line']: l['offset'] for l in method_dict['code']['lines']} }")
        
        mismatches = []
        for line, offset in javap_method.line_table.items():
            json_offset = None
            for l in method_dict['code']['lines']:
                if l['line'] == line:
                    json_offset = l['offset']
                    break
            if json_offset != offset:
                mismatches.append((line, offset, json_offset))
        
        if mismatches:
            print(f"  ⚠️  LINE TABLE MISMATCHES:")
            for line, javap_off, json_off in mismatches:
                print(f"     Line {line}: javap={javap_off}, json={json_off}")
        else:
            print(f"  ✓ Line tables match")
        
        # Show branch/jump target comparison
        print(f"\nJUMP TARGET COMPARISON:")
        json_bytecode = method_dict['code']['bytecode']
        
        for offset, instr, javap_target in javap_method.bytecode:
            if javap_target is not None:
                # Find corresponding JSON instruction
                json_target = None
                for inst in json_bytecode:
                    if inst['offset'] == offset:
                        json_target = inst.get('target')
                        break
                
                if json_target != javap_target:
                    print(f"  ⚠️  Offset {offset} ({instr}): javap->{javap_target}, json->{json_target}")
                else:
                    print(f"  ✓ Offset {offset} ({instr}): target={javap_target}")
        
        # Show dead code detection results
        print(f"\nABSTRACT INTERPRETER RESULTS:")
        print(f"  Visited offsets: {sorted(visited)}")
        print(f"  Dead offsets:    {sorted(dead_offsets)}")
        
        # Map dead offsets to lines using JAVAP line table (ground truth)
        dead_lines_javap = set()
        for offset in dead_offsets:
            line = javap_method.get_line_for_offset(offset)
            if line:
                dead_lines_javap.add(line)
        
        # Map dead offsets to lines using JSON line table
        dead_lines_json = set()
        json_line_entries = sorted(method_dict['code']['lines'], key=lambda x: x['offset'])
        for offset in dead_offsets:
            for entry in reversed(json_line_entries):
                if entry['offset'] <= offset:
                    dead_lines_json.add(entry['line'])
                    break
        
        print(f"\n  Dead lines (using javap line table): {sorted(dead_lines_javap)}")
        print(f"  Dead lines (using JSON line table):  {sorted(dead_lines_json)}")
        
        if dead_lines_javap != dead_lines_json:
            print(f"  ⚠️  Line mapping differs due to incorrect JSON line table!")


if __name__ == '__main__':
    main()

