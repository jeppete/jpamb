"""Detect branches whose condition is always false."""

from __future__ import annotations

from ..context import AnalysisContext
from ..issues import Issue, make_issue
from ..utils import iter_nodes


def run(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    root = ctx.tree.root_node
    for node in iter_nodes(root):
        if node.type != "if_statement":
            continue
        cond = node.child_by_field_name("condition")
        if cond is None:
            continue

        inner = cond
        if (
            inner.type == "parenthesized_expression"
            and inner.named_child_count == 1
        ):
            inner = inner.named_children[0]

        is_dead = False
        if inner.type == "false":
            is_dead = True
        elif inner.type == "identifier":
            name = ctx.text(inner)
            if ctx.const_bools.get(name) is False:
                is_dead = True

        if is_dead:
            issues.append(
                make_issue(
                    "dead_branch",
                    node,
                    "if-condition is always false; branch is dead-code candidate.",
                )
            )
    return issues
