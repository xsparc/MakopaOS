#!/usr/bin/env python3
"""Verify the stable-only x86_64 dependency feature contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REQUIRED = (
    'x86_64 feature "instructions"',
    "x86_64 v0.15.5",
)
FORBIDDEN = (
    'x86_64 feature "default"',
    'x86_64 feature "nightly"',
    'x86_64 feature "abi_x86_interrupt"',
    'x86_64 feature "step_trait"',
)


def feature_violations(tree: str) -> list[str]:
    """Return violations in one `cargo tree -e features` transcript."""
    errors = [f"missing dependency evidence: {item}" for item in REQUIRED if item not in tree]
    errors.extend(
        f"forbidden x86_64 feature enabled: {item}"
        for item in FORBIDDEN
        if item in tree
    )
    if tree.count('x86_64 feature "instructions"') != 1:
        errors.append("expected exactly one x86_64 instructions feature edge")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", help="captured cargo feature tree, or - for stdin")
    args = parser.parse_args()
    tree = (
        sys.stdin.read()
        if args.tree == "-"
        else Path(args.tree).read_text(encoding="utf-8")
    )
    errors = feature_violations(tree)
    if errors:
        for error in errors:
            print(f"verify-dependency-features: {error}")
        return 1
    print("verify-dependency-features: stable x86_64 0.15.5 instructions-only edge")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
