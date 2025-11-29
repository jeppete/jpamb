#!/usr/bin/env python3
"""
Debloater - Orchestrator for finding dead code.

Coordinates two pipelines:
1. Source pipeline: Syntactic analysis on source code
2. Bytecode pipeline: Multiple analyses on bytecode (sequential optimization)

Then maps bytecode results to source level and combines both.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from pathlib import Path

import jpamb
from jpamb import jvm

# Import analysis modules (using relative imports from components dir)
from bytecode_analysis import BytecodeAnalyzer, AnalysisResult as BytecodeResult
from syntaxer import BloatFinder
from syntaxer.utils import create_java_parser

# Import abstract interpreter with all domains (using full path from project root)
from solutions.components.abstract_interpreter import (
    interval_unbounded_run,
    product_unbounded_run,
    Bytecode,
    ProductValue,
)
from solutions.components.abstract_domain import IntervalDomain, NonNullDomain


# Add project root and components directory to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
COMPONENTS_DIR = Path(__file__).parent / "components"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(COMPONENTS_DIR) not in sys.path:
    sys.path.insert(0, str(COMPONENTS_DIR))


log = logging.getLogger(__name__)


@dataclass
class SourceFinding:
    """A single finding from source-level analysis."""
    line: int
    kind: str  # "unused_import", "dead_branch", "unused_field", etc.
    message: str
    details: dict = field(default_factory=dict)
    confidence: str = "medium"  # "low", "medium", "high"
    verified_by_bytecode: bool = False  # True if bytecode analysis confirmed this


@dataclass
class SourceAnalysisResult:
    """Results from source-level syntactic analysis."""
    findings: List[SourceFinding] = field(default_factory=list)
    dead_lines: Set[int] = field(default_factory=set)
    suspected_unused_imports: Dict[str, int] = field(default_factory=dict)  # class_path -> line
    
    def add_finding(self, line: int, kind: str, message: str, confidence: str = "medium", 
                   verified_by_bytecode: bool = False, **details):
        """Add a finding from source analysis."""
        self.findings.append(SourceFinding(line, kind, message, details, confidence, verified_by_bytecode))
        self.dead_lines.add(line)
    
    def add_suspected_unused_import(self, class_path: str, line: int):
        """Track a suspected unused import for bytecode verification."""
        self.suspected_unused_imports[class_path] = line


@dataclass
class MappedBytecodeResult:
    """Bytecode results mapped to source code level."""
    dead_lines: Set[int] = field(default_factory=set)
    dead_methods: Set[str] = field(default_factory=set)
    details: List[dict] = field(default_factory=list)


@dataclass
class CombinedResult:
    """Combined results from both pipelines."""
    suggestions: List[dict] = field(default_factory=list)
    by_line: Dict[int, List[dict]] = field(default_factory=dict)
    total_dead_lines: int = 0


class Debloater:
    """
    Main debloater orchestrator.
    
    Runs two parallel pipelines:
    1. Source pipeline: Fast syntactic analysis on Java source
    2. Bytecode pipeline: Multi-phase analysis on bytecode (optimized sequentially)
    
    Then combines results and presents to developer.
    """
    
    def __init__(self, suite: jpamb.Suite, 
                 enable_abstract_interpreter: bool = True,
                 abstract_domain: str = "product"):
        """
        Initialize the debloater.
        
        Args:
            suite: JPAMB Suite for bytecode access
            enable_abstract_interpreter: If True, run Phase 2 abstract interpretation
            abstract_domain: Which domain to use ("sign", "interval", "product")
        """
        self.suite = suite
        self.results = {}
        self.enable_abstract_interpreter = enable_abstract_interpreter
        self.abstract_domain = abstract_domain
    
    def analyze_class(self, classname: jvm.ClassName, source_file: Optional[Path] = None,
                      verbose: bool = True):
        """
        Run complete debloating analysis on a class.
        
        Args:
            classname: The class to analyze
            source_file: Optional path to source file for source analysis
            verbose: If True, print detailed report at the end
        """
        log.info("="*70)
        log.info("DEBLOATER ANALYSIS: %s", classname)
        log.info("="*70)
        
        # ===================================================================
        # PIPELINE 1: Source Analysis (if source file provided)
        # ===================================================================
        if source_file and source_file.exists():
            log.info("\n[Pipeline 1] Source Analysis")
            source_result = self.run_source_pipeline(source_file)
            self.results['source'] = source_result
        else:
            log.info("\n[Pipeline 1] Source Analysis: Skipped (no source file)")
            self.results['source'] = SourceAnalysisResult()
        
        # ===================================================================
        # PIPELINE 2: Bytecode Analysis (multi-phase, optimized)
        # ===================================================================
        log.info("\n[Pipeline 2] Bytecode Analysis")
        bytecode_result = self.run_bytecode_pipeline(classname)
        self.results['bytecode'] = bytecode_result
        
        # ===================================================================
        # VERIFICATION: Check suspected unused imports with bytecode
        # ===================================================================
        if source_result.suspected_unused_imports:
            log.info("\n[Verification] Checking unused imports with bytecode")
            confirmed_unused = self.verify_unused_imports_with_bytecode(
                classname, 
                source_result.suspected_unused_imports
            )
            
            # Add confirmed unused imports as findings
            for import_path, line_num in source_result.suspected_unused_imports.items():
                if import_path in confirmed_unused:
                    class_name = import_path.split("/")[-1]
                    source_result.add_finding(
                        line=line_num,
                        kind="unused_import",
                        message=f"Import '{class_name}' is never used (verified by bytecode); candidate for removal.",
                        confidence="high",
                        verified_by_bytecode=True,  # Mark as verified!
                        import_path=import_path
                    )
                    log.info(f"  ✓ Confirmed unused: {import_path}")
                else:
                    log.info(f"  ✗ Actually used: {import_path} (found in bytecode)")
        
        # ===================================================================
        # MAPPING: Bytecode offsets → Source lines
        # ===================================================================
        log.info("\n[Mapping] Bytecode results to source level")
        mapped_bytecode = self.map_bytecode_to_source(classname, bytecode_result)
        self.results['bytecode_mapped'] = mapped_bytecode
        
        # ===================================================================
        # COMBINE: Merge and deduplicate results
        # ===================================================================
        log.info("\n[Combine] Merging results from both pipelines")
        combined = self.combine_results(
            self.results['source'],
            mapped_bytecode
        )
        self.results['combined'] = combined
        
        # ===================================================================
        # REPORT: Present findings
        # ===================================================================
        if verbose:
            self.report()
    
    def extract_import_path_from_line(self, source_file: Path, line_num: int) -> Optional[str]:
        """Extract the full import path from a source line."""
        try:
            with open(source_file, 'r') as f:
                lines = f.readlines()
                if 0 <= line_num - 1 < len(lines):
                    line = lines[line_num - 1]
                    # Parse: import java.util.HashMap; -> java/util/HashMap
                    line = line.replace("import", "").replace(";", "").strip()
                    if line.startswith("static"):
                        line = line.replace("static", "").strip()
                    return line.replace(".", "/")
        except Exception as e:
            log.warning(f"Could not extract import from line {line_num}: {e}")
        return None
    
    def verify_unused_imports_with_bytecode(self, classname: jvm.ClassName, 
                                            suspected_imports: Dict[str, int]) -> Set[str]:
        """
        Verify suspected unused imports by checking bytecode references.
        
        Args:
            classname: The class being analyzed
            suspected_imports: Dict of {full_class_path: line_number}
            
        Returns:
            Set of confirmed unused import paths
        """
        if not suspected_imports:
            return set()
        
        log.info(f"  Verifying {len(suspected_imports)} suspected unused imports...")
        
        try:
            cls = self.suite.findclass(classname)
            
            # Collect all class references in bytecode
            referenced_classes = set()
            
            # Check methods
            for method in cls.get("methods", []):
                code = method.get("code")
                if not code:
                    continue
                
                bytecode = code.get("bytecode", [])
                for inst in bytecode:
                    # Check for class references in various opcodes
                    opr = inst.get("opr", "")
                    
                    # new, checkcast, instanceof
                    if opr in ("new", "checkcast", "instanceof"):
                        class_ref = inst.get("class", "")
                        if class_ref:
                            referenced_classes.add(class_ref)
                    
                    # Method invocations
                    elif opr == "invoke":
                        method_info = inst.get("method", {})
                        ref = method_info.get("ref", {})
                        class_ref = ref.get("name", "")
                        if class_ref:
                            referenced_classes.add(class_ref)
                        
                        # Also check argument types
                        for arg_type in method_info.get("args", []):
                            if isinstance(arg_type, str):
                                referenced_classes.add(arg_type)
                            elif isinstance(arg_type, dict):
                                arg_name = arg_type.get("name", "")
                                if arg_name:
                                    referenced_classes.add(arg_name)
                    
                    # Field access
                    elif opr in ("get", "put"):
                        field_info = inst.get("field", {})
                        field_class = field_info.get("class", "")
                        if field_class:
                            referenced_classes.add(field_class)
                        
                        field_type = field_info.get("type")
                        if isinstance(field_type, str):
                            referenced_classes.add(field_type)
            
            # Check fields
            for field in cls.get("fields", []):
                field_type = field.get("type", {})
                if isinstance(field_type, dict):
                    type_name = field_type.get("name", "")
                    if type_name:
                        referenced_classes.add(type_name)
            
            # Now check which suspected imports are NOT in referenced classes
            confirmed_unused = set()
            for import_path in suspected_imports.keys():
                # The import path is like "java/util/HashMap"
                # Referenced classes are like "java/util/HashMap"
                if import_path not in referenced_classes:
                    confirmed_unused.add(import_path)
                    log.debug(f"    Confirmed unused: {import_path}")
                else:
                    log.debug(f"    Actually used: {import_path}")
            
            log.info(f"  Confirmed {len(confirmed_unused)} truly unused imports")
            return confirmed_unused
        
        except Exception as e:
            log.warning(f"  Bytecode verification failed: {e}")
            return set()
    
    def run_source_pipeline(self, source_file: Path) -> SourceAnalysisResult:
        """
        Run source-level syntactic analysis using the source syntaxer.
        
        Uses tree-sitter based BloatFinder to detect:
        - Dead branches
        - Unused imports  
        - Unused fields
        - Unused local variables
        - Logging code
        - Debug/test code patterns
        
        Args:
            source_file: Path to .java file
            
        Returns:
            SourceAnalysisResult with findings
        """
        result = SourceAnalysisResult()
        
        try:
            parser = create_java_parser()
            source_bytes = source_file.read_bytes()
            tree = parser.parse(source_bytes)
            
            finder = BloatFinder(tree, source_bytes)
            
            # Convert syntaxer Issues to SourceFindings
            for issue in finder.issues:
                # Check if this is a suspected unused import
                if issue.kind == "unused_import_suspected":
                    # Extract import path from the source
                    # We need to parse the import statement to get the full path
                    import_path = self.extract_import_path_from_line(source_file, issue.line)
                    if import_path:
                        result.add_suspected_unused_import(import_path, issue.line)
                    # Don't add as finding yet - wait for bytecode verification
                else:
                    result.add_finding(
                        line=issue.line,
                        kind=issue.kind,
                        message=issue.message,
                        col=issue.col
                    )
            
            log.info("  Source findings: %d", len(result.findings))
        
        except Exception as e:
            log.error("  Source analysis failed: %s", e)
            # Return empty result rather than crashing
        
        return result
    
    def run_bytecode_pipeline(self, classname: jvm.ClassName) -> BytecodeResult:
        """
        Run multi-phase bytecode analysis with sequential optimization.
        
        Phase 1: Bytecode syntactic (CFG + call graph)
        Phase 2: Abstract interpretation (optional, configurable domain)
        Phase 3: [Future] Data flow (optimized by Phase 1+2)
        
        Args:
            classname: Class to analyze
            
        Returns:
            BytecodeResult with all findings
        """
        # Phase 1: Bytecode Syntactic Analysis
        log.info("  Phase 1: CFG + Call Graph Analysis")
        bytecode_analyzer = BytecodeAnalyzer(self.suite)
        
        try:
            result = bytecode_analyzer.analyze_class(classname)
            log.info("    → Found %d unreachable methods", len(result.unreachable_methods))
            log.info("    → Found %d methods with dead instructions (CFG)", 
                    len(result.dead_instructions))
        except Exception as e:
            log.error("  Bytecode analysis failed: %s", e)
            raise
        
        # Phase 2: Abstract Interpretation (optional)
        if self.enable_abstract_interpreter:
            domain_names = {
                "sign": "SignSet",
                "interval": "IntervalDomain", 
                "product": "ProductDomain (Interval + Nullness)"
            }
            domain_name = domain_names.get(self.abstract_domain, self.abstract_domain)
            log.info(f"  Phase 2: Abstract Interpretation ({domain_name})")
            
            abstract_dead = self.run_abstract_interpretation(classname, result)
            
            # Merge abstract interpretation results into main result
            phase2_new = 0
            for method_name, dead_offsets in abstract_dead.items():
                if method_name not in result.dead_instructions:
                    result.dead_instructions[method_name] = set()
                
                # Add newly found dead instructions
                new_dead = dead_offsets - result.dead_instructions[method_name]
                phase2_new += len(new_dead)
                result.dead_instructions[method_name] |= dead_offsets
            
            log.info("    → Abstract interpretation found %d additional dead instructions", phase2_new)
            log.info("    → Total dead instructions: %d", result.get_dead_instruction_count())
        else:
            log.info("  Phase 2: Abstract Interpretation (DISABLED)")
        
        # Phase 3: Data Flow Analysis (TODO)
        # log.info("  Phase 3: Data Flow Analysis")
        # ...
        
        return result
    
    def run_abstract_interpretation(self, classname: jvm.ClassName, 
                                    phase1_result: BytecodeResult) -> Dict[str, Set[int]]:
        """
        Run abstract interpretation on all methods to find dead code.
        
        Uses ProductDomain (IntervalDomain + NonNullDomain) for maximum precision:
        - Dead branches from constant comparisons (if x > 10; if x < 5)
        - Dead branches from value propagation (x = 15; if x < 10)
        - Dead null checks after 'new' (obj = new X(); if (obj == null))
        - Dead code after contradictory conditions
        
        Args:
            classname: Class to analyze
            phase1_result: Results from Phase 1 (CFG analysis)
            
        Returns:
            Dict mapping method name to set of dead instruction offsets
        """
        dead_by_method: Dict[str, Set[int]] = {}
        
        try:
            cls = self.suite.findclass(classname)
            methods = cls.get("methods", [])
            
            for method_dict in methods:
                method_name = method_dict.get("name", "<unknown>")
                full_name = f"{classname}.{method_name}"
                
                # Skip already-known unreachable methods
                if full_name in phase1_result.unreachable_methods:
                    continue
                
                # Skip methods without code (abstract/native)
                code = method_dict.get("code")
                if not code:
                    continue
                
                bytecode = code.get("bytecode", [])
                if not bytecode:
                    continue
                
                try:
                    # Build method ID for abstract interpreter
                    params = jvm.ParameterType.from_json(
                        method_dict.get("params", []), annotated=True
                    )
                    returns_info = method_dict.get("returns", {})
                    return_type_json = returns_info.get("type")
                    if return_type_json is None:
                        return_type = None
                    else:
                        return_type = jvm.Type.from_json(return_type_json)
                    
                    method_id = jvm.MethodID(
                        name=method_name, 
                        params=params, 
                        return_type=return_type
                    )
                    abs_method = jvm.AbsMethodID(classname=classname, extension=method_id)
                    
                    # Run abstract interpretation with configured domain
                    if self.abstract_domain == "product":
                        outcomes, visited_pcs = product_unbounded_run(self.suite, abs_method)
                    elif self.abstract_domain == "interval":
                        outcomes, visited_pcs = interval_unbounded_run(self.suite, abs_method)
                    else:  # "sign"
                        from solutions.components.abstract_interpreter import unbounded_abstract_run
                        outcomes, visited_pcs = unbounded_abstract_run(self.suite, abs_method)
                    
                    # Get all PCs in this method
                    all_pcs = {inst.get("offset", -1) for inst in bytecode if inst.get("offset", -1) >= 0}
                    
                    # Find unreachable PCs
                    unreachable_pcs = all_pcs - visited_pcs
                    
                    if unreachable_pcs:
                        dead_by_method[full_name] = unreachable_pcs
                        log.debug(f"    {method_name}: {len(unreachable_pcs)} dead instructions")
                    
                except Exception as e:
                    # Log but continue - some methods may fail (e.g., unsupported opcodes)
                    log.debug(f"    {method_name}: skipped ({e})")
                    continue
        
        except Exception as e:
            log.warning(f"  Abstract interpretation error: {e}")
        
        return dead_by_method
    
    def map_bytecode_to_source(self, classname: jvm.ClassName, 
                               bytecode_result: BytecodeResult) -> MappedBytecodeResult:
        """
        Map bytecode findings to source code locations.
        
        Uses line number tables in bytecode to map offsets → lines.
        
        Args:
            classname: Class being analyzed
            bytecode_result: Results from bytecode analysis
            
        Returns:
            MappedBytecodeResult with source-level locations
        """
        mapped = MappedBytecodeResult()
        
        try:
            cls = self.suite.findclass(classname)
            methods = cls.get("methods", [])
            
            # Map dead instructions to source lines
            for method_dict in methods:
                method_name = method_dict.get("name", "<unknown>")
                full_name = f"{classname}.{method_name}"
                
                if full_name not in bytecode_result.dead_instructions:
                    continue
                
                dead_offsets = bytecode_result.dead_instructions[full_name]
                code = method_dict.get("code", {})
                line_table = code.get("lines", [])
                
                for offset in dead_offsets:
                    line_num = self.offset_to_line(offset, line_table)
                    if line_num:
                        mapped.dead_lines.add(line_num)
                        mapped.details.append({
                            'line': line_num,
                            'method': full_name,
                            'offset': offset,
                            'type': 'dead_instruction',
                            'source': 'bytecode'
                        })
            
            # Map unreachable methods to source lines
            for method_dict in methods:
                method_name = method_dict.get("name", "<unknown>")
                full_name = f"{classname}.{method_name}"
                
                if full_name in bytecode_result.unreachable_methods:
                    # Get method's starting line
                    code = method_dict.get("code", {})
                    line_table = code.get("lines", [])
                    if line_table:
                        method_line = line_table[0].get("line")
                        method_offset = line_table[0].get("offset", 0)
                        mapped.dead_methods.add(full_name)
                        mapped.dead_lines.add(method_line)
                        mapped.details.append({
                            'line': method_line,
                            'method': full_name,
                            'offset': method_offset,
                            'type': 'unreachable_method',
                            'source': 'bytecode'
                        })
            
            log.info("  Mapped to %d source lines", len(mapped.dead_lines))
        
        except Exception as e:
            log.warning("  Mapping failed: %s", e)
        
        return mapped
    
    def offset_to_line(self, offset: int, line_table: List[dict]) -> Optional[int]:
        """
        Convert bytecode offset to source line number.
        
        Args:
            offset: Bytecode offset
            line_table: Line number table from bytecode
            
        Returns:
            Source line number, or None if not found
        """
        best_line = None
        for entry in line_table:
            entry_offset = entry.get("offset", -1)
            if entry_offset <= offset:
                best_line = entry.get("line")
            else:
                break
        return best_line
    
    def combine_results(self, source_result: SourceAnalysisResult,
                       bytecode_mapped: MappedBytecodeResult) -> CombinedResult:
        """
        Combine results from both pipelines, deduplicating by line number.
        
        When both pipelines find dead code on the same line, mark as 'both' with high confidence.
        
        Args:
            source_result: Findings from source analysis
            bytecode_mapped: Bytecode findings mapped to source
            
        Returns:
            CombinedResult with merged, deduplicated suggestions
        """
        combined = CombinedResult()
        
        # Build temporary mapping to detect overlaps
        source_lines = {}  # line -> list of findings
        bytecode_lines = {}  # line -> list of findings
        
        # Collect source findings by line
        for finding in source_result.findings:
            line = finding.line
            if line not in source_lines:
                source_lines[line] = []
            
            # Mark source as 'both' if verified by bytecode
            source_type = 'both' if finding.verified_by_bytecode else 'source_analysis'
            
            source_lines[line].append({
                'line': line,
                'type': finding.kind,
                'message': finding.message,
                'source': source_type,
                'confidence': finding.confidence,
                'verified_by_bytecode': finding.verified_by_bytecode,
                'details': finding.details
            })
        
        # Collect bytecode findings by line
        for detail in bytecode_mapped.details:
            line = detail['line']
            if line not in bytecode_lines:
                bytecode_lines[line] = []
            
            # Format message based on available info
            if 'offset' in detail:
                msg = f"{detail['method']}: offset {detail['offset']}"
            else:
                msg = f"{detail['method']}"
            
            bytecode_lines[line].append({
                'line': line,
                'type': detail['type'],
                'message': msg,
                'source': 'bytecode_analysis',
                'details': detail
            })
        
        # Merge and detect overlaps
        all_lines = set(source_lines.keys()) | set(bytecode_lines.keys())
        
        for line in sorted(all_lines):
            has_source = line in source_lines
            has_bytecode = line in bytecode_lines
            
            # Check if source findings are already verified by bytecode
            already_verified = False
            if has_source:
                already_verified = any(f.get('verified_by_bytecode', False) for f in source_lines[line])
            
            if already_verified:
                # Source finding already verified by bytecode (e.g., unused import)
                # Just add the source findings as-is (they're already marked as 'both')
                for finding in source_lines[line]:
                    combined.suggestions.append(finding)
                    if line not in combined.by_line:
                        combined.by_line[line] = []
                    combined.by_line[line].append(finding)
                
                # Also add bytecode findings if they exist (but as separate items)
                if has_bytecode:
                    for finding in bytecode_lines[line]:
                        # Mark these as supplementary
                        finding['supplementary'] = True
                        combined.suggestions.append(finding)
                        combined.by_line[line].append(finding)
            
            elif has_source and has_bytecode:
                # BOTH pipelines found dead code on this line (and not pre-verified)
                # Merge into single high-confidence finding
                source_msgs = [f['message'] for f in source_lines[line]]
                bytecode_msgs = [f['message'] for f in bytecode_lines[line]]
                
                # Create combined finding
                suggestion = {
                    'line': line,
                    'type': 'dead_code_verified',
                    'message': f"Dead code verified by both pipelines: {source_msgs[0]}",
                    'source': 'both',
                    'confidence': 'high',
                    'source_findings': source_lines[line],
                    'bytecode_findings': bytecode_lines[line],
                    'details': {
                        'source_count': len(source_lines[line]),
                        'bytecode_count': len(bytecode_lines[line])
                    }
                }
                combined.suggestions.append(suggestion)
                combined.by_line[line] = [suggestion]
                
            elif has_source:
                # Source only
                for finding in source_lines[line]:
                    combined.suggestions.append(finding)
                    if line not in combined.by_line:
                        combined.by_line[line] = []
                    combined.by_line[line].append(finding)
            
            else:  # has_bytecode
                # Bytecode only
                for finding in bytecode_lines[line]:
                    combined.suggestions.append(finding)
                    if line not in combined.by_line:
                        combined.by_line[line] = []
                    combined.by_line[line].append(finding)
        
        combined.total_dead_lines = len(combined.by_line)
        
        # Count by source
        both_count = sum(1 for s in combined.suggestions if s.get('source') == 'both')
        source_only = sum(1 for s in combined.suggestions if s.get('source') == 'source_analysis')
        bytecode_only = sum(1 for s in combined.suggestions if s.get('source') == 'bytecode_analysis')
        
        log.info("  Combined: %d unique suggestions", len(combined.suggestions))
        log.info("    Verified by both: %d", both_count)
        log.info("    Source only: %d", source_only)
        log.info("    Bytecode only: %d", bytecode_only)
        
        return combined
    
    def report(self):
        """Generate comprehensive report of all findings."""
        source_result = self.results.get('source')
        bytecode_result = self.results.get('bytecode')
        combined = self.results.get('combined')
        
        print("\n" + "="*70)
        print("DEBLOATING ANALYSIS REPORT")
        print("="*70)
        
        # Source pipeline results
        if source_result and source_result.findings:
            print(f"\n📝 Source Analysis: {len(source_result.findings)} findings")
            for finding in source_result.findings[:5]:  # Show first 5
                print(f"  Line {finding.line}: {finding.message}")
            if len(source_result.findings) > 5:
                print(f"  ... and {len(source_result.findings) - 5} more")
        else:
            print(f"\n📝 Source Analysis: No findings")
        
        # Bytecode pipeline results
        if bytecode_result:
            print(f"\n🔍 Bytecode Analysis:")
            print(f"  Unreachable methods: {len(bytecode_result.unreachable_methods)}")
            dead_count = bytecode_result.get_dead_instruction_count()
            total_count = bytecode_result.total_instructions
            percentage = bytecode_result.get_debloat_percentage()
            print(f"  Dead instructions: {dead_count} / {total_count} ({percentage:.1f}%)")
        
        # Combined results
        if combined:
            # Count by confidence
            both_count = sum(1 for s in combined.suggestions if s.get('source') == 'both')
            source_only = sum(1 for s in combined.suggestions if s.get('source') == 'source_analysis')
            bytecode_only = sum(1 for s in combined.suggestions if s.get('source') == 'bytecode_analysis')
            
            print(f"\n✨ Combined Results:")
            print(f"  Total suggestions: {len(combined.suggestions)}")
            print(f"  Lines with dead code: {combined.total_dead_lines}")
            print(f"\n  By Confidence:")
            print(f"    ✅ Verified by both: {both_count} (high confidence)")
            print(f"    📝 Source only: {source_only}")
            print(f"    🔍 Bytecode only: {bytecode_only}")
            
            print(f"\n📋 Suggestions by Line:")
            for line in sorted(combined.by_line.keys())[:10]:  # Show first 10
                suggestions = combined.by_line[line]
                for sugg in suggestions:
                    if sugg['source'] == 'both':
                        source_icon = "✅"
                    elif sugg['source'] == 'source_analysis':
                        source_icon = "📝"
                    else:
                        source_icon = "🔍"
                    print(f"  {source_icon} Line {line}: {sugg['message']}")
            
            if combined.total_dead_lines > 10:
                print(f"  ... and {combined.total_dead_lines - 10} more lines")
        
        print("\n" + "="*70)


@dataclass
class BatchResult:
    """Aggregate results from analyzing multiple files."""
    total_files: int = 0
    successful_files: int = 0
    failed_files: int = 0
    total_dead_lines: int = 0
    total_verified: int = 0
    total_source_only: int = 0
    total_bytecode_only: int = 0
    total_instructions: int = 0  # Total bytecode instructions across all files
    total_dead_instructions: int = 0  # Total dead bytecode instructions
    results_by_file: Dict[str, CombinedResult] = field(default_factory=dict)
    errors_by_file: Dict[str, str] = field(default_factory=dict)
    
    def get_debloat_percentage(self) -> float:
        """Calculate percentage of instructions that are dead code."""
        if self.total_instructions == 0:
            return 0.0
        return (self.total_dead_instructions / self.total_instructions) * 100.0


class BatchDebloater:
    """Handles debloating multiple files/directories."""
    
    def __init__(self, suite):
        self.suite = suite
        self.debloater = Debloater(suite)
    
    def find_java_files(self, directory: Path) -> List[tuple[Path, jvm.ClassName]]:
        """
        Find all Java files in a directory and map to classnames.
        
        Returns:
            List of (source_file, classname) tuples
        """
        java_files = []
        
        # Look for Java files in standard Maven/Gradle structure
        project_root = Path.cwd()
        src_dir = project_root / "src" / "main" / "java"
        
        # If directory is not the project root, but is a subdirectory of src/main/java
        if not directory.is_absolute():
            directory = project_root / directory
        
        for java_file in directory.rglob("*.java"):
            # Try to determine classname from file path
            try:
                # Get relative path from src/main/java
                if src_dir.exists() and src_dir in java_file.parents:
                    rel_path = java_file.relative_to(src_dir)
                    # Convert path to classname: jpamb/cases/Foo.java -> jpamb/cases/Foo
                    classname = jvm.ClassName(str(rel_path.with_suffix("")).replace("\\", "/"))
                else:
                    # Fallback: just use the filename without extension
                    rel_path = java_file.relative_to(directory)
                    classname = jvm.ClassName(str(rel_path.with_suffix("")).replace("\\", "/"))
                
                java_files.append((java_file, classname))
            except Exception as e:
                log.warning(f"Could not determine classname for {java_file}: {e}")
        
        return java_files
    
    def analyze_files(self, files: List[tuple[Path, jvm.ClassName]], 
                     show_progress: bool = True) -> BatchResult:
        """
        Analyze multiple files.
        
        Args:
            files: List of (source_file, classname) tuples
            show_progress: Show progress for each file
            
        Returns:
            BatchResult with aggregate statistics
        """
        batch_result = BatchResult()
        batch_result.total_files = len(files)
        
        print(f"\n{'='*70}")
        print(f"BATCH DEBLOATING ANALYSIS")
        print(f"{'='*70}")
        print(f"Processing {len(files)} file(s)...\n")
        
        for idx, (source_file, classname) in enumerate(files, 1):
            if show_progress:
                print(f"\n[{idx}/{len(files)}] Analyzing: {source_file.name}")
                print("-" * 70)
            
            try:
                # Analyze this file
                self.debloater.analyze_class(classname, source_file, verbose=False)
                
                # Get results
                combined = self.debloater.results.get('combined')
                bytecode_result = self.debloater.results.get('bytecode')
                
                if combined:
                    batch_result.successful_files += 1
                    batch_result.results_by_file[str(source_file)] = combined
                    batch_result.total_dead_lines += combined.total_dead_lines
                    
                    # Count by confidence
                    verified = sum(1 for s in combined.suggestions if s.get('source') == 'both')
                    source_only = sum(1 for s in combined.suggestions if s.get('source') == 'source_analysis')
                    bytecode_only = sum(1 for s in combined.suggestions if s.get('source') == 'bytecode_analysis')
                    
                    batch_result.total_verified += verified
                    batch_result.total_source_only += source_only
                    batch_result.total_bytecode_only += bytecode_only
                    
                    # Track instruction counts
                    if bytecode_result:
                        batch_result.total_instructions += bytecode_result.total_instructions
                        batch_result.total_dead_instructions += bytecode_result.get_dead_instruction_count()
                    
                    if show_progress:
                        print(f"  ✓ Found {combined.total_dead_lines} dead lines")
                        print(f"    Verified: {verified}, Source: {source_only}, Bytecode: {bytecode_only}")
                
            except Exception as e:
                batch_result.failed_files += 1
                batch_result.errors_by_file[str(source_file)] = str(e)
                if show_progress:
                    print(f"  ✗ Error: {e}")
        
        return batch_result
    
    def print_batch_summary(self, batch_result: BatchResult):
        """Print aggregate summary of batch analysis."""
        print(f"\n{'='*70}")
        print("BATCH ANALYSIS SUMMARY")
        print(f"{'='*70}\n")
        
        print(f"📊 Files Processed:")
        print(f"  Total: {batch_result.total_files}")
        print(f"  ✓ Successful: {batch_result.successful_files}")
        print(f"  ✗ Failed: {batch_result.failed_files}")
        
        print(f"\n🎯 Aggregate Results:")
        print(f"  Total dead lines across all files: {batch_result.total_dead_lines}")
        print(f"  ✅ Verified by both: {batch_result.total_verified}")
        print(f"  📝 Source only: {batch_result.total_source_only}")
        print(f"  🔍 Bytecode only: {batch_result.total_bytecode_only}")
        
        print(f"\n📊 Bytecode Metrics:")
        percentage = batch_result.get_debloat_percentage()
        print(f"  Dead instructions: {batch_result.total_dead_instructions} / {batch_result.total_instructions} ({percentage:.1f}%)")
        
        if batch_result.errors_by_file:
            print(f"\n❌ Errors:")
            for file, error in batch_result.errors_by_file.items():
                print(f"  {Path(file).name}: {error}")
        
        print(f"\n{'='*70}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Debloater - Find dead code using source and bytecode analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single file
  python debloater.py jpamb.cases.Simple src/main/java/jpamb/cases/Simple.java
  
  # Batch mode - multiple files
  python debloater.py --batch jpamb.cases.Simple:src/main/java/jpamb/cases/Simple.java \\
                              jpamb.cases.Loops:src/main/java/jpamb/cases/Loops.java
  
  # Directory mode - all Java files in directory
  python debloater.py --dir src/main/java/jpamb/cases
        """
    )
    
    parser.add_argument("classname", nargs="?", help="Java classname (e.g., jpamb.cases.Simple)")
    parser.add_argument("source_file", nargs="?", help="Path to Java source file")
    parser.add_argument("--batch", nargs="+", metavar="CLASS:FILE",
                       help="Batch mode: analyze multiple files (format: classname:sourcefile)")
    parser.add_argument("--dir", type=Path, metavar="DIRECTORY",
                       help="Directory mode: analyze all Java files in directory")
    parser.add_argument("--quiet", "-q", action="store_true",
                       help="Quiet mode: only show summary for batch processing")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")
    
    suite = jpamb.Suite()
    
    # BATCH MODE: Multiple files specified
    if args.batch:
        files_to_analyze = []
        for item in args.batch:
            if ":" in item:
                classname_str, source_path = item.split(":", 1)
                parts = classname_str.split(".")
                classname = jvm.ClassName("/".join(parts))
                files_to_analyze.append((Path(source_path), classname))
            else:
                log.error(f"Invalid batch format: {item} (expected 'classname:sourcefile')")
                sys.exit(1)
        
        batch_debloater = BatchDebloater(suite)
        batch_result = batch_debloater.analyze_files(files_to_analyze, show_progress=not args.quiet)
        batch_debloater.print_batch_summary(batch_result)
    
    # DIRECTORY MODE: Scan directory for all Java files
    elif args.dir:
        if not args.dir.exists():
            log.error(f"Directory not found: {args.dir}")
            sys.exit(1)
        
        batch_debloater = BatchDebloater(suite)
        files_to_analyze = batch_debloater.find_java_files(args.dir)
        
        if not files_to_analyze:
            log.error(f"No Java files found in {args.dir}")
            sys.exit(1)
        
        batch_result = batch_debloater.analyze_files(files_to_analyze, show_progress=not args.quiet)
        batch_debloater.print_batch_summary(batch_result)
    
    # SINGLE FILE MODE: Original behavior
    elif args.classname:
        source_file = Path(args.source_file) if args.source_file else None
        
        # Parse classname
        parts = args.classname.split(".")
        classname = jvm.ClassName("/".join(parts))
        
        debloater = Debloater(suite)
        
        try:
            debloater.analyze_class(classname, source_file, verbose=True)
        except Exception as e:
            log.error(f"Error: {e}", exc_info=True)
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
