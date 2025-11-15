"""Detection of trivial wrappers and wrapper chains."""

from __future__ import annotations

from typing import Dict, Tuple

import tree_sitter

from ..context import AnalysisContext
from ..issues import Issue, make_issue
from ..utils import iter_nodes


def run_trivial_wrappers(ctx: AnalysisContext) -> list[Issue]:
    wrappers = _collect_wrappers(ctx)
    issues: list[Issue] = []
    for method_name, (target_name, node) in wrappers.items():
        issues.append(
            make_issue(
                "trivial_wrapper",
                node,
                f"Method '{method_name}' is a trivial wrapper around '{target_name}'.",
            )
        )
    return issues


def run_wrapper_chains(ctx: AnalysisContext) -> list[Issue]:
    wrappers = _collect_wrappers(ctx)
    issues: list[Issue] = []

    for start_name, (target, start_node) in wrappers.items():
        chain = [start_name]
        seen = {start_name}
        cur = target

        while cur in wrappers and cur not in seen:
            chain.append(cur)
            seen.add(cur)
            cur = wrappers[cur][0]

        if len(chain) >= 2:
            chain_str = " -> ".join(chain + [cur])
            issues.append(
                make_issue(
                    "wrapper_chain",
                    start_node,
                    f"Trivial wrapper chain detected: {chain_str}.",
                )
            )
    return issues


def _collect_wrappers(ctx: AnalysisContext) -> Dict[str, Tuple[str, tree_sitter.Node]]:
    wrappers: Dict[str, Tuple[str, tree_sitter.Node]] = {}
    for node in iter_nodes(ctx.tree.root_node):
        if node.type != "method_declaration":
            continue

        name_node = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name_node is None or body is None or body.type != "block":
            continue

        method_name = ctx.text(name_node)
        stmts = [
            c for c in body.named_children
            if c.type.endswith("statement")
            or c.type in ("local_variable_declaration",)
        ]
        if len(stmts) != 1 or stmts[0].type != "return_statement":
            continue

        ret = stmts[0]
        value = ret.child_by_field_name("value")
        if value is None and ret.named_child_count > 0:
            value = ret.named_children[0]
        if value is None or value.type != "method_invocation":
            continue

        target_name_node = value.child_by_field_name("name")
        if target_name_node is None:
            continue

        target_name = ctx.text(target_name_node)
        if target_name != method_name:
            wrappers[method_name] = (target_name, node)

    return wrappers
