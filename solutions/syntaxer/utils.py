"""Shared utilities for Tree-sitter parsing and node helpers."""

from __future__ import annotations

from typing import Iterator

import tree_sitter
import tree_sitter_java


def create_java_parser() -> tree_sitter.Parser:
    """
    Create a Tree-sitter parser configured for Java.

    Supports both the modern bindings (Parser() + set_language) and
    older releases that expect the language in the constructor.
    """

    language = tree_sitter.Language(tree_sitter_java.language())
    try:
        parser = tree_sitter.Parser()
        set_language = getattr(parser, "set_language", None)
        if set_language is None:
            parser = tree_sitter.Parser(language)
        else:
            set_language(language)
    except TypeError:
        parser = tree_sitter.Parser(language)
    return parser


def node_text(node: tree_sitter.Node, source_bytes: bytes) -> str:
    """Decode the bytes that correspond to a node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def iter_nodes(root: tree_sitter.Node) -> Iterator[tree_sitter.Node]:
    """Iterative preorder traversal of the syntax tree."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))
