"""Registry of analysis checks."""

from __future__ import annotations

from typing import Callable, List

from ..context import AnalysisContext
from ..issues import Issue

from . import (
    blocks,
    dead_branches,
    fields,
    imports,
    locals_usage,
    logging_checks,
    wrappers,
)

Check = Callable[[AnalysisContext], List[Issue]]

CHECKS: list[Check] = [
    imports.run,
    dead_branches.run,
    wrappers.run_trivial_wrappers,
    wrappers.run_wrapper_chains,
    blocks.run_empty_blocks,
    blocks.run_unreachable_code,
    fields.run_unused_fields,
    locals_usage.run_unused_params_and_dead_stores,
    logging_checks.run_logging_patterns,
]

__all__ = ["CHECKS"]
