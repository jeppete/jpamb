"""Checks focused on logging-heavy code and broad catches."""

from __future__ import annotations

import tree_sitter

from ..context import AnalysisContext
from ..issues import Issue, make_issue
from ..utils import iter_nodes


def run_logging_patterns(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    root = ctx.tree.root_node

    # Logging-heavy methods
    for method in iter_nodes(root):
        if method.type != "method_declaration":
            continue

        body = method.child_by_field_name("body")
        if body is None or body.type != "block":
            continue

        total_stmts = 0
        log_calls = 0
        for node in iter_nodes(body):
            if node.type.endswith("statement"):
                total_stmts += 1
                if _is_logging_call(ctx, node):
                    log_calls += 1

        if total_stmts >= 3 and log_calls / max(total_stmts, 1) >= 0.6:
            name_node = method.child_by_field_name("name")
            name = ctx.text(name_node) if name_node else "<?>"
            issues.append(
                make_issue(
                    "suspect_debug_region",
                    method,
                    f"Method '{name}' appears dominated by logging/printing; potential leftover debug helper.",
                )
            )

    # Broad catches that only log
    for node in iter_nodes(root):
        if node.type != "catch_clause":
            continue

        param = node.child_by_field_name("parameter")
        body = node.child_by_field_name("body")
        if body is None or param is None:
            continue

        is_broad = False
        if param.named_child_count:
            type_text_parts = []
            for c in param.named_children:
                if c.type in (
                    "catch_type",
                    "type_identifier",
                    "scoped_type_identifier",
                    "union_type",
                ):
                    type_text_parts.append(ctx.text(c))
            type_text = " ".join(type_text_parts)
            if "Exception" in type_text or "Throwable" in type_text:
                is_broad = True

        if not is_broad:
            continue

        has_real_stmt = False
        for c in body.named_children:
            if c.type.endswith("statement"):
                if not _is_logging_call(ctx, c):
                    has_real_stmt = True
                    break

        if not has_real_stmt:
            issues.append(
                make_issue(
                    "suspect_swallowing_handler",
                    body,
                    "Broad catch with empty/only-logging body; potential legacy/diagnostic bloat.",
                )
            )

    return issues


def _is_logging_call(ctx: AnalysisContext, node: tree_sitter.Node) -> bool:
    call = None
    if node.type == "expression_statement" and node.named_child_count == 1:
        child = node.named_children[0]
        if child.type == "method_invocation":
            call = child
    elif node.type == "method_invocation":
        call = node

    if call is None:
        return False

    name_node = call.child_by_field_name("name")
    if name_node is None:
        return False

    method_name = ctx.text(name_node)
    if method_name in ("debug", "info", "warn", "error", "trace", "log", "println", "printStackTrace"):
        return True

    recv = call.child_by_field_name("object") or call.child_by_field_name("receiver")
    scope = call.child_by_field_name("scope")

    recv_text = ctx.text(recv).lower()
    scope_text = ctx.text(scope)

    if "logger" in recv_text or "log" in recv_text:
        return True
    if "system.out" in scope_text.lower():
        return True
    return False
