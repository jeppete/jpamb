# my_analyzer.py
from __future__ import annotations

import sys

import jpamb
from jpamb import jvm

from solutions.components.abstract_interpreter import AbstractInterpreter


def find_method(suite: jpamb.Suite, method_str: str) -> jvm.AbsMethodID:
    for mid, _tags in suite.case_methods():
        if str(mid) == method_str:
            return mid

    # If it's not a case method, we can scan all classfiles/methods here if needed.
    # For now, fail loudly so it's obvious what's wrong.
    raise SystemExit(f"Unknown method: {method_str!r}")


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: my_analyzer.py <AbsMethodID>", file=sys.stderr)
        sys.exit(1)

    method_str = sys.argv[1]

    # Construct suite from the current repo (note: no Suite.from_env())
    suite = jpamb.Suite()

    # Look up the actual AbsMethodID object
    method = find_method(suite, method_str)

    # Run your abstract interpreter
    ai = AbstractInterpreter(suite, max_steps=200)
    finals = ai.analyze(method, init_locals={})  # or None

    # For now just print possible outcomes
    print(f"AI outcomes for {method_str}: {sorted(finals)}")


if __name__ == "__main__":
    main()
