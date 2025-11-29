#!/usr/bin/env python3
"""
Run debloater analysis using javap as ground truth for bytecode.

This bypasses the buggy jvm2json output and uses javap directly to get
correct bytecode offsets, line tables, and jump targets.
"""

import subprocess
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

sys.path.insert(0, 'solutions')

import jpamb
from jpamb import jvm


@dataclass
class JavapInstruction:
    """A single bytecode instruction from javap."""
    offset: int
    opcode: str
    operands: str
    jump_target: Optional[int] = None


@dataclass  
class JavapMethod:
    """Parsed method from javap output."""
    name: str
    signature: str
    instructions: List[JavapInstruction]
    line_table: Dict[int, int]  # line_number -> offset
    
    def get_all_offsets(self) -> Set[int]:
        return {inst.offset for inst in self.instructions}
    
    def get_line_for_offset(self, offset: int) -> Optional[int]:
        """Find the source line for a bytecode offset."""
        best_line = None
        best_offset = -1
        for line, line_offset in self.line_table.items():
            if line_offset <= offset and line_offset > best_offset:
                best_line = line
                best_offset = line_offset
        return best_line
    
    def get_offsets_for_line(self, line: int) -> Set[int]:
        """Get all bytecode offsets that map to a source line."""
        offsets = set()
        all_offsets = sorted(self.get_all_offsets())
        
        # Find range of offsets for this line
        line_start = self.line_table.get(line)
        if line_start is None:
            return offsets
        
        # Find next line's offset
        next_offset = float('inf')
        for l, off in self.line_table.items():
            if off > line_start and off < next_offset:
                next_offset = off
        
        for off in all_offsets:
            if line_start <= off < next_offset:
                offsets.add(off)
        
        return offsets


def parse_javap(class_file: Path) -> Dict[str, JavapMethod]:
    """Parse javap output for a class file."""
    result = subprocess.run(
        ['javap', '-c', '-l', '-p', str(class_file)],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        raise RuntimeError(f"javap failed: {result.stderr}")
    
    return parse_javap_output(result.stdout)


def parse_javap_output(output: str) -> Dict[str, JavapMethod]:
    """Parse javap -c -l output into structured data."""
    methods = {}
    lines = output.split('\n')
    i = 0
    
    # Opcodes that have jump targets
    JUMP_OPCODES = {
        'if_icmple', 'if_icmpge', 'if_icmplt', 'if_icmpgt', 'if_icmpeq', 'if_icmpne',
        'if_acmpeq', 'if_acmpne',
        'ifle', 'ifge', 'iflt', 'ifgt', 'ifeq', 'ifne',
        'ifnull', 'ifnonnull',
        'goto', 'goto_w', 'jsr', 'jsr_w'
    }
    
    while i < len(lines):
        line = lines[i]
        
        # Look for method signature
        # Match patterns like: public static int methodName(int);
        method_match = re.match(r'\s+(public|private|protected|static|\s)+\s*(\S+)\s+(\w+)\(([^)]*)\);?', line)
        if method_match:
            return_type = method_match.group(2)
            method_name = method_match.group(3)
            params = method_match.group(4)
            signature = f"{return_type} {method_name}({params})"
            
            instructions = []
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
                
                if bc_line.startswith('LocalVariableTable:') or bc_line.startswith('StackMapTable:'):
                    break
                
                # Parse bytecode instruction: "offset: opcode operands"
                bc_match = re.match(r'(\d+): (\w+)\s*(.*)', bc_line)
                if bc_match:
                    offset = int(bc_match.group(1))
                    opcode = bc_match.group(2)
                    operands = bc_match.group(3).strip()
                    
                    # Extract jump target
                    jump_target = None
                    if opcode in JUMP_OPCODES:
                        target_match = re.search(r'\b(\d+)\b', operands)
                        if target_match:
                            jump_target = int(target_match.group(1))
                    
                    instructions.append(JavapInstruction(
                        offset=offset,
                        opcode=opcode,
                        operands=operands,
                        jump_target=jump_target
                    ))
                
                i += 1
                
                # Check if we've reached the next method or end
                if not bc_line or (bc_line and not bc_line[0].isdigit() and 'Exception' not in bc_line):
                    if 'public' in bc_line or 'private' in bc_line or 'static' in bc_line:
                        i -= 1
                        break
            
            methods[method_name] = JavapMethod(
                name=method_name,
                signature=signature,
                instructions=instructions,
                line_table=line_table
            )
        
        i += 1
    
    return methods


def simulate_abstract_interpretation(method: JavapMethod) -> Set[int]:
    """
    Simulate what the abstract interpreter would find as dead code.
    
    This is a simplified version - we'll use the actual abstract interpreter
    but with corrected control flow from javap.
    """
    # For now, we'll run the actual abstract interpreter and then
    # map its results using the correct javap line table
    return set()


def run_abstract_interpreter(suite, classname: jvm.ClassName, method_name: str) -> Tuple[Set[int], Set[int]]:
    """Run the abstract interpreter on a method, return (dead_offsets, visited_offsets)."""
    from components.abstract_interpreter import product_unbounded_run
    
    cls = suite.findclass(classname)
    
    for m in cls['methods']:
        if m['name'] == method_name:
            params = jvm.ParameterType.from_json(m.get('params', []), annotated=True)
            returns_info = m.get('returns', {})
            return_type_json = returns_info.get('type')
            return_type = jvm.Type.from_json(return_type_json) if return_type_json else None
            
            method_id = jvm.MethodID(name=method_name, params=params, return_type=return_type)
            abs_method = jvm.AbsMethodID(classname=classname, extension=method_id)
            
            outcomes, visited_pcs = product_unbounded_run(suite, abs_method)
            
            bytecode = m['code']['bytecode']
            all_pcs = {inst['offset'] for inst in bytecode}
            dead_offsets = all_pcs - visited_pcs
            
            return dead_offsets, visited_pcs
    
    return set(), set()


def analyze_class_with_javap(class_file: Path, source_file: Path) -> Dict:
    """
    Analyze a class using javap as ground truth for line mapping.
    """
    # Parse javap
    javap_methods = parse_javap(class_file)
    
    # Load the jpamb suite
    suite = jpamb.Suite()
    
    # Derive classname from class file path
    rel_path = class_file.relative_to('target/classes')
    class_name = str(rel_path.with_suffix('')).replace('/', '.')
    classname = jvm.ClassName(class_name.replace('.', '/'))
    
    results = {
        'class': class_name,
        'source_file': str(source_file),
        'methods': {},
        'summary': {
            'total_dead_lines': set(),
            'total_methods_analyzed': 0,
            'methods_with_dead_code': 0,
        }
    }
    
    # Analyze each method
    for method_name, javap_method in javap_methods.items():
        if method_name in ('<init>', '<clinit>'):
            continue
        
        try:
            dead_offsets, visited_offsets = run_abstract_interpreter(suite, classname, method_name)
        except Exception as e:
            results['methods'][method_name] = {'error': str(e)}
            continue
        
        results['summary']['total_methods_analyzed'] += 1
        
        if not dead_offsets:
            results['methods'][method_name] = {
                'dead_offsets': [],
                'dead_lines': [],
                'status': 'no_dead_code'
            }
            continue
        
        results['summary']['methods_with_dead_code'] += 1
        
        # Map dead offsets to lines using JAVAP line table (ground truth)
        dead_lines = set()
        dead_line_details = []
        
        for offset in sorted(dead_offsets):
            line = javap_method.get_line_for_offset(offset)
            if line:
                dead_lines.add(line)
                dead_line_details.append({
                    'offset': offset,
                    'line': line,
                })
        
        results['summary']['total_dead_lines'].update(dead_lines)
        
        results['methods'][method_name] = {
            'dead_offsets': sorted(dead_offsets),
            'dead_lines': sorted(dead_lines),
            'dead_line_details': dead_line_details,
            'visited_offsets': sorted(visited_offsets),
            'all_offsets': sorted(javap_method.get_all_offsets()),
            'status': 'has_dead_code'
        }
    
    results['summary']['total_dead_lines'] = sorted(results['summary']['total_dead_lines'])
    
    return results


def print_report(results: Dict, source_file: Path):
    """Print a formatted report of the analysis."""
    print("=" * 70)
    print("DEBLOATER ANALYSIS (using javap ground truth)")
    print("=" * 70)
    print(f"\nClass: {results['class']}")
    print(f"Source: {results['source_file']}")
    
    # Load source for context
    source_lines = {}
    if source_file.exists():
        with open(source_file) as f:
            for i, line in enumerate(f, 1):
                source_lines[i] = line.rstrip()
    
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Methods analyzed: {results['summary']['total_methods_analyzed']}")
    print(f"  Methods with dead code: {results['summary']['methods_with_dead_code']}")
    print(f"  Total dead lines: {len(results['summary']['total_dead_lines'])}")
    
    if results['summary']['total_dead_lines']:
        print(f"\n  Dead source lines: {results['summary']['total_dead_lines']}")
    
    print(f"\n{'=' * 70}")
    print("METHOD DETAILS")
    print(f"{'=' * 70}")
    
    for method_name, method_result in sorted(results['methods'].items()):
        if 'error' in method_result:
            print(f"\n{method_name}: ERROR - {method_result['error']}")
            continue
        
        if method_result['status'] == 'no_dead_code':
            print(f"\n{method_name}: ✓ No dead code detected")
            continue
        
        dead_lines = method_result['dead_lines']
        dead_offsets = method_result['dead_offsets']
        
        print(f"\n{method_name}:")
        print(f"  Dead bytecode offsets: {dead_offsets}")
        print(f"  Dead source lines: {dead_lines}")
        
        # Show source context for dead lines
        if source_lines and dead_lines:
            print(f"\n  Dead code preview:")
            for line_num in dead_lines[:5]:  # Show first 5
                if line_num in source_lines:
                    print(f"    {line_num:4}: {source_lines[line_num][:60]}")
            if len(dead_lines) > 5:
                print(f"    ... and {len(dead_lines) - 5} more lines")
    
    print(f"\n{'=' * 70}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Run debloater with javap ground truth')
    parser.add_argument('--class', dest='class_name', default='jpamb.cases.AbstractInterpreterCases',
                       help='Class to analyze (default: jpamb.cases.AbstractInterpreterCases)')
    parser.add_argument('--all', action='store_true', help='Analyze all case classes')
    args = parser.parse_args()
    
    if args.all:
        cases_dir = Path('target/classes/jpamb/cases')
        class_files = list(cases_dir.glob('*.class'))
        # Filter out inner classes
        class_files = [f for f in class_files if '$' not in f.name]
    else:
        class_name = args.class_name.replace('.', '/')
        class_files = [Path(f'target/classes/{class_name}.class')]
    
    all_dead_lines = set()
    
    for class_file in class_files:
        if not class_file.exists():
            print(f"Class file not found: {class_file}")
            continue
        
        # Find source file
        rel_path = class_file.relative_to('target/classes')
        source_file = Path('src/main/java') / rel_path.with_suffix('.java')
        
        print(f"\nAnalyzing: {class_file.stem}")
        print("-" * 50)
        
        try:
            results = analyze_class_with_javap(class_file, source_file)
            print_report(results, source_file)
            all_dead_lines.update(results['summary']['total_dead_lines'])
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
    
    if args.all:
        print(f"\n{'=' * 70}")
        print("AGGREGATE RESULTS")
        print(f"{'=' * 70}")
        print(f"Total unique dead lines across all classes: {len(all_dead_lines)}")


if __name__ == '__main__':
    main()

