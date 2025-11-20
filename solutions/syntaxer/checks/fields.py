"""Field-related heuristics (unused fields, suspect feature flags)."""

from __future__ import annotations

from ..context import AnalysisContext
from ..issues import Issue, make_issue

def run_unused_fields(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    for name, decl_node in ctx.field_decls.items():
        uses = ctx.field_uses.get(name, 0)
        if uses <= 1:
            issues.append(
                make_issue(
                    "unused_field",
                    decl_node,
                    f"Field '{name}' appears unused; candidate for removal.",
                )
            )
    return issues