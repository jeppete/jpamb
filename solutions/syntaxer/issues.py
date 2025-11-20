"""Issue data model for syntaxer findings."""

from __future__ import annotations

from dataclasses import dataclass

import tree_sitter


@dataclass(frozen=True)
class Issue:
    """Structured representation of a detected bloat smell."""

    kind: str
    line: int
    col: int
    message: str


def make_issue(kind: str, node: tree_sitter.Node, message: str) -> Issue:
    """Create an Issue using the node's start point (converted to 1-based)."""
    line, col = node.start_point
    return Issue(kind=kind, line=line + 1, col=col + 1, message=message)
