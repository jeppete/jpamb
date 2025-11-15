"""Import-related bloat checks."""

from __future__ import annotations

from ..context import AnalysisContext
from ..issues import Issue, make_issue


def run(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    root = ctx.tree.root_node
    for node in root.children:
        if node.type != "import_declaration":
            continue
        has_star = any(c.type in ("asterisk", "*") for c in node.children)
        if has_star:
            issues.append(
                make_issue(
                    "import_wildcard",
                    node,
                    "Wildcard import; potential library bloat.",
                )
            )
    return issues
