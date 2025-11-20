"""Analysis context shared across checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator

import tree_sitter

from .utils import iter_nodes, node_text


@dataclass
class AnalysisContext:
    """Holds the parsed tree, source bytes, and derived facts."""

    tree: tree_sitter.Tree
    source_bytes: bytes
    field_decls: Dict[str, tree_sitter.Node] = field(init=False, default_factory=dict)
    field_uses: Dict[str, int] = field(init=False, default_factory=dict)
    const_bools: Dict[str, bool] = field(init=False, default_factory=dict)

    def __post_init__(self):
        self._collect_fields_and_constants()
        self._count_field_uses()

    # ----- general helpers -----

    def text(self, node: tree_sitter.Node | None) -> str:
        return node_text(node, self.source_bytes) if node is not None else ""

    def iter_nodes(self) -> Iterator[tree_sitter.Node]:
        return iter_nodes(self.tree.root_node)

    # ----- collection passes -----

    def _collect_fields_and_constants(self):
        root = self.tree.root_node
        for node in iter_nodes(root):
            if node.type != "field_declaration":
                continue

            declarator = node.child_by_field_name("declarator")
            if declarator is None:
                continue  # skip multi-declarator forms

            name_node = declarator.child_by_field_name("name")
            if name_node is None:
                continue

            name = self.text(name_node)
            self.field_decls[name] = node
            self.field_uses[name] = 0

            value_node = declarator.child_by_field_name("value")
            type_node = node.child_by_field_name("type")
            if (
                type_node is not None
                and type_node.type == "boolean_type"
                and value_node is not None
                and value_node.type in ("true", "false")
            ):
                self.const_bools[name] = (value_node.type == "true")

    def _count_field_uses(self):
        root = self.tree.root_node
        for node in iter_nodes(root):
            if node.type == "identifier":
                name = self.text(node)
                if name in self.field_uses:
                    self.field_uses[name] += 1  # includes declaration occurrence
