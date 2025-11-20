"""Heuristics about parameters and locals."""

from __future__ import annotations

from ..context import AnalysisContext
from ..issues import Issue, make_issue
from ..utils import iter_nodes


def run_unused_params_and_dead_stores(ctx: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    root = ctx.tree.root_node

    for method in iter_nodes(root):
        if method.type != "method_declaration":
            continue

        body = method.child_by_field_name("body")
        if body is None or body.type != "block":
            continue

        param_names = set()
        params = method.child_by_field_name("parameters")
        if params is not None:
            for p in params.named_children:
                if p.type in ("formal_parameter", "spread_parameter"):
                    pname = _get_decl_name(ctx, p)
                    if pname:
                        param_names.add(pname)

        local_decls: dict[str, object] = {}
        for node in iter_nodes(body):
            if node.type == "local_variable_declaration":
                for child in node.named_children:
                    if child.type == "variable_declarator":
                        lname = _get_decl_name(ctx, child)
                        if lname:
                            local_decls[lname] = child

        read_names = set()
        for node in iter_nodes(body):
            if node.type != "identifier":
                continue

            name = ctx.text(node)
            parent = node.parent

            if parent is not None:
                if parent.type == "variable_declarator" and _get_decl_name(ctx, parent) == name:
                    continue
                if (
                    parent.type in ("formal_parameter", "spread_parameter")
                    and _get_decl_name(ctx, parent) == name
                ):
                    continue

            if name in param_names or name in local_decls:
                read_names.add(name)

        for pname in sorted(param_names - read_names):
            issues.append(
                make_issue(
                    "suspect_unused_param",
                    method,
                    f"Parameter '{pname}' is never read; candidate for API / code cleanup.",
                )
            )

        for lname, decl_node in local_decls.items():
            if lname not in read_names:
                issues.append(
                    make_issue(
                        "suspect_dead_store",
                        decl_node,
                        f"Local variable '{lname}' is written but never read; dead-store candidate.",
                    )
                )
    return issues


def _get_decl_name(ctx: AnalysisContext, node) -> str | None:
    name_node = node.child_by_field_name("name")
    if name_node is not None and name_node.type == "identifier":
        return ctx.text(name_node)

    id_candidates = [c for c in node.named_children if c.type == "identifier"]
    if id_candidates:
        return ctx.text(id_candidates[-1])
    return None
