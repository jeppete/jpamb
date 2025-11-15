"""Checks related to block structure (empty blocks, unreachable statements)."""

from __future__ import annotations

from ..context import AnalysisContext
from ..issues import Issue, make_issue
from ..utils import iter_nodes


def run_empty_blocks(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    root = ctx.tree.root_node
    for node in iter_nodes(root):
        if node.type == "if_statement":
            cons = node.child_by_field_name("consequence")
            if cons is not None and cons.type == "block":
                if _is_block_effectively_empty(cons):
                    issues.append(
                        make_issue(
                            "empty_if",
                            cons,
                            "Empty if-body; likely unnecessary.",
                        )
                    )

        if node.type == "catch_clause":
            body = node.child_by_field_name("body")
            if body is not None and _is_block_effectively_empty(body):
                issues.append(
                    make_issue(
                        "empty_catch",
                        body,
                        "Empty catch block; swallowed exceptions / bloated.",
                    )
                )

        if node.type == "method_declaration":
            body = node.child_by_field_name("body")
            if body is not None and body.type == "block":
                if _is_block_effectively_empty(body):
                    name_node = node.child_by_field_name("name")
                    name = ctx.text(name_node) if name_node else "<?>"
                    issues.append(
                        make_issue(
                            "empty_method",
                            node,
                            f"Method '{name}' has an empty body.",
                        )
                    )
    return issues


def run_unreachable_code(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    root = ctx.tree.root_node
    for node in iter_nodes(root):
        if node.type != "block":
            continue

        unreachable = False
        for child in node.named_children:
            if unreachable:
                issues.append(
                    make_issue(
                        "unreachable_code",
                        child,
                        "Statement appears after return/throw; unreachable-code bloat.",
                    )
                )
                continue

            if child.type in ("return_statement", "throw_statement"):
                unreachable = True
    return issues


def _is_block_effectively_empty(block_node) -> bool:
    for c in block_node.named_children:
        if (
            c.type.endswith("statement")
            or c.type in (
                "local_variable_declaration",
                "expression_statement",
                "if_statement",
                "try_statement",
            )
        ):
            return False
    return True
