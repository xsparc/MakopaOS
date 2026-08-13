#!/usr/bin/env python3
"""Verify the stable-only x86_64 dependency feature contract."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


REQUIRED = (
    "makopa-task-runtime v0.1.0",
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


def task_runtime_dependency_violations(manifest: str) -> list[str]:
    """Return violations of the dependency-free task-runtime boundary."""
    parsed = tomllib.loads(manifest)
    errors: list[str] = []
    if parsed.get("package", {}).get("name") != "makopa-task-runtime":
        errors.append("task-runtime manifest has the wrong package name")
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        if parsed.get(table):
            errors.append(f"task-runtime manifest has forbidden {table}")
    if parsed.get("target"):
        errors.append("task-runtime manifest has forbidden target dependencies")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", help="captured cargo feature tree, or - for stdin")
    parser.add_argument("--task-manifest", required=True, type=Path)
    args = parser.parse_args()
    tree = (
        sys.stdin.read()
        if args.tree == "-"
        else Path(args.tree).read_text(encoding="utf-8")
    )
    errors = feature_violations(tree)
    errors.extend(
        task_runtime_dependency_violations(
            args.task_manifest.read_text(encoding="utf-8")
        )
    )
    if errors:
        for error in errors:
            print(f"verify-dependency-features: {error}")
        return 1
    print(
        "verify-dependency-features: stable x86_64 0.15.5 instructions-only "
        "edge and dependency-free task runtime"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
