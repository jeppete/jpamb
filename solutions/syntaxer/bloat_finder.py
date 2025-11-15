"""Coordinator that runs all syntaxer checks."""

from __future__ import annotations

import logging

import tree_sitter

from .checks import CHECKS
from .context import AnalysisContext
from .issues import Issue

log = logging.getLogger(__name__)


class BloatFinder:
    """Wraps the analysis context and executes the registered checks."""

    def __init__(self, tree: tree_sitter.Tree, source_bytes: bytes):
        self.context = AnalysisContext(tree, source_bytes)
        self.issues: list[Issue] = []
        self._run_checks()

    def _run_checks(self):
        for check in CHECKS:
            new_issues = check(self.context)
            for issue in new_issues:
                log.debug("bloat: %s", issue)
            self.issues.extend(new_issues)
