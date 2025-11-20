#!/usr/bin/env python3
"""Entry point for the syntaxer syntactic debloating analysis."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import jpamb

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from solutions.syntaxer import BloatFinder, Issue  # noqa: E402
from solutions.syntaxer.utils import create_java_parser  # noqa: E402

log = logging.getLogger(__name__)

ANALYSIS_NAME = "syntaxer"
ANALYSIS_VERSION = "1.0"
ANALYSIS_GROUP = "Group 21"
ANALYSIS_TAGS = ["syntactic", "python"]


def resolve_source_path(methodid: jpamb.jvm.AbsMethodID) -> Path:
    """Return an absolute path to the Java source file for the method."""
    srcpath = jpamb.sourcefile(methodid)
    if not srcpath.is_absolute():
        srcpath = Path.cwd() / srcpath
    return srcpath


def run_analysis(methodid: jpamb.jvm.AbsMethodID) -> tuple[list[Issue], str]:
    """Parse the source file and run the bloat finder."""
    parser = create_java_parser()
    srcpath = resolve_source_path(methodid)
    log.debug("parse sourcefile %s", srcpath)

    source_bytes = srcpath.read_bytes()
    tree = parser.parse(source_bytes)
    BloatFinder(tree, source_bytes)


def main():
    logging.basicConfig(level=logging.DEBUG)

    methodid = jpamb.getmethodid(
        ANALYSIS_NAME,
        ANALYSIS_VERSION,
        ANALYSIS_GROUP,
        ANALYSIS_TAGS,
        for_science=True,
    )

    run_analysis(methodid)

if __name__ == "__main__":
    main()
