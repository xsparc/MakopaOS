from __future__ import annotations

import contextlib
import io
import shutil
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scripts.check_project_evidence import check_project_evidence, main


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = Path("docs/governance/project-evidence.toml")


class ProjectEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name) / "repository"
        shutil.copytree(
            ROOT,
            self.repository,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "boot.bin"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def registry_path(self) -> Path:
        return self.repository / REGISTRY

    def replace_registry(self, old: str, new: str, *, count: int = 1) -> None:
        text = self.registry_path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.registry_path.write_text(text.replace(old, new, count), encoding="utf-8")

    def finding_codes(self, *, as_of: date | None = None) -> set[str]:
        result = check_project_evidence(self.repository, as_of=as_of)
        return {finding.code for finding in result.findings}

    def test_repository_registry_passes(self) -> None:
        result = check_project_evidence(self.repository, as_of=date(2026, 8, 10))
        self.assertEqual("pass", result.status)
        self.assertEqual(0, result.counts["findings"])

    def test_rejects_missing_reference(self) -> None:
        self.replace_registry('"boot.asm"', '"missing/boot.asm"')
        self.assertIn("reference.missing", self.finding_codes())

    def test_rejects_unsafe_reference(self) -> None:
        self.replace_registry('"boot.asm"', '"../boot.asm"')
        self.assertIn("reference.unsafe", self.finding_codes())

    def test_rejects_hidden_local_reference(self) -> None:
        self.replace_registry('"boot.asm"', '".local/boot.asm"')
        self.assertIn("reference.unsafe", self.finding_codes())

    def test_rejects_unknown_objective_id(self) -> None:
        self.replace_registry(
            'objective_ids = ["OBJ-TRACEABLE-CHANGE"]',
            'objective_ids = ["OBJ-NOT-REGISTERED"]',
        )
        self.assertIn("traceability.unknown-objective", self.finding_codes())

    def test_rejects_unknown_requirement_id(self) -> None:
        self.replace_registry(
            'requirement_ids = ["REQ-PROJECT-EVIDENCE"]',
            'requirement_ids = ["REQ-NOT-REGISTERED"]',
        )
        self.assertIn("traceability.unknown-requirement", self.finding_codes())

    def test_rejects_unindexed_accepted_decision(self) -> None:
        decision = (
            self.repository
            / "docs"
            / "architecture"
            / "decisions"
            / "0099-test-decision.md"
        )
        decision.parent.mkdir(parents=True, exist_ok=True)
        decision.write_text(
            "# Test decision\n\n- **Status:** Accepted\n",
            encoding="utf-8",
        )
        self.assertIn("traceability.unindexed-decision", self.finding_codes())

    def test_reports_stale_review(self) -> None:
        result = check_project_evidence(self.repository, as_of=date(2026, 9, 11))
        self.assertEqual("warn", result.status)
        self.assertIn("review.overdue", self.finding_codes(as_of=date(2026, 9, 11)))

    def test_strict_mode_rejects_stale_review(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "--repository-root",
                    str(self.repository),
                    "--as-of",
                    "2026-09-11",
                    "--strict",
                ]
            )
        self.assertEqual(2, exit_code)
        self.assertIn('"status": "warn"', stdout.getvalue())

    def test_rejects_implemented_requirement_without_verification(self) -> None:
        self.replace_registry(
            'verification_refs = ["tests/test_verify_boot.py"]',
            "verification_refs = []",
        )
        self.assertIn("traceability.missing", self.finding_codes())

    def test_rejects_missing_markdown_anchor(self) -> None:
        self.replace_registry(
            "docs/architecture/overview.md#boot-boundary",
            "docs/architecture/overview.md#missing-boundary",
        )
        self.assertIn("reference.missing-anchor", self.finding_codes())


if __name__ == "__main__":
    unittest.main()
