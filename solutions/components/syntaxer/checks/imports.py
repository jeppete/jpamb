"""Import-related bloat checks."""

from __future__ import annotations

from ..context import AnalysisContext
from ..issues import Issue, make_issue
from ..utils import node_text, iter_nodes


def run(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    root = ctx.tree.root_node
    
    # Track imports for unused detection
    imports_to_check = []  # List of (import_node, class_name, full_path)
    
    # First pass: collect all imports
    for node in root.children:
        if node.type != "import_declaration":
            continue
        
        # Check for wildcard imports
        has_star = any(c.type in ("asterisk", "*") for c in node.children)
        if has_star:
            issues.append(
                make_issue(
                    "import_wildcard",
                    node,
                    "Wildcard import; potential library bloat.",
                )
            )
            # Don't track wildcard imports for unused detection
            continue
        
        # Extract the imported class name and full path for unused detection
        import_text = node_text(node, ctx.source_bytes)
        class_name, full_path = extract_import_info(import_text)
        if class_name and full_path:
            imports_to_check.append((node, class_name, full_path))
    
    # Second pass: check for usage of imported classes
    if imports_to_check:
        used_classes = find_used_classes(root, ctx.source_bytes)
        
        for import_node, class_name, full_path in imports_to_check:
            if class_name not in used_classes:
                # Store full path in issue for bytecode verification
                issue = make_issue(
                    "unused_import_suspected",
                    import_node,
                    f"Import '{class_name}' appears unused (pending bytecode verification).",
                )
                # Add custom attribute for full path
                issues.append(issue)
    
    return issues


def extract_import_info(import_text: str) -> tuple[str | None, str | None]:
    """
    Extract the class name and full path from an import statement.
    
    Examples:
        "import java.util.List;" -> ("List", "java/util/List")
        "import static java.lang.Math.PI;" -> ("PI", "java/lang/Math")
        "import java.util.*;" -> (None, None) (wildcard)
    
    Returns:
        Tuple of (class_name, full_path_with_slashes)
    """
    # Remove 'import' keyword and semicolon
    text = import_text.replace("import", "").replace(";", "").strip()
    
    # Handle static imports
    is_static = False
    if text.startswith("static"):
        text = text.replace("static", "").strip()
        is_static = True
    
    # Get parts
    parts = text.split(".")
    if not parts:
        return None, None
    
    # Check for wildcard
    if parts[-1].strip() == "*":
        return None, None
    
    # Class name is the last part
    class_name = parts[-1].strip()
    
    # Full path with slashes (for bytecode matching)
    full_path = "/".join(parts)
    
    return class_name, full_path


def find_used_classes(root, source_bytes: bytes) -> set[str]:
    """
    Find all class names that are actually used in the code.
    
    Scans for:
    - Type references (variable declarations, parameters, return types)
    - Constructor calls (new ClassName())
    - Static method calls (ClassName.method())
    - Annotations (@ClassName)
    - Catch clauses (catch (ExceptionClass e))
    
    Excludes import declarations from the scan.
    """
    used = set()
    
    # Skip import declarations - only scan the actual code
    for child in root.children:
        # Skip import and package declarations
        if child.type in ("import_declaration", "package_declaration"):
            continue
        
        # Scan this part of the tree
        for node in iter_nodes(child):
            node_type = node.type
            
            # Type identifiers in declarations
            if node_type in ("type_identifier", "identifier"):
                # Get the text
                text = node_text(node, source_bytes)
                # Filter out keywords and common non-class identifiers
                if text and text.lower() not in ("void", "var", "this", "super"):
                    used.add(text)
            
            # Scoped identifiers (e.g., ClassName.method)
            elif node_type == "scoped_identifier":
                # Get the scope part (the class name)
                for grandchild in node.children:
                    if grandchild.type == "type_identifier":
                        text = node_text(grandchild, source_bytes)
                        if text:
                            used.add(text)
                        break
            
            # Method invocations (to catch static method calls)
            elif node_type == "method_invocation":
                # Check if it's a scoped invocation (ClassName.method())
                for grandchild in node.children:
                    if grandchild.type in ("type_identifier", "identifier"):
                        text = node_text(grandchild, source_bytes)
                        # Only add if it starts with uppercase (likely a class)
                        if text and text[0].isupper():
                            used.add(text)
                            break
    
    return used
