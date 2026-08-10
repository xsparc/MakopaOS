#!/usr/bin/env python3
"""Validate MakopaOS project evidence and repository-local traceability."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence


REGISTRY_PATH = Path("docs/governance/project-evidence.toml")
SCHEMA_VERSION = 1
PROJECT_ID = "makopa-os"

_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
_CONVERSATION_APPROVAL = re.compile(
    r"^conversation:\d{4}-\d{2}-\d{2}-[a-z0-9-]+$"
)
_GITHUB_APPROVAL = re.compile(
    r"^https://github\.com/xsparc/MakopaOS/"
    r"(?:issues|pull)/[1-9][0-9]*"
    r"(?:#(?:issuecomment-[1-9][0-9]*|discussion_r[1-9][0-9]*|"
    r"pullrequestreview-[1-9][0-9]*))?$"
)
_INLINE_ACCEPTED_STATUS = re.compile(
    r"(?im)^\s*(?:-\s*)?(?:\*\*)?Status:(?:\*\*)?\s*accepted\s*$"
)
_STATUS_HEADING = re.compile(r"(?i)^\s*#{1,6}\s+Status(?:\s+#+)?\s*$")
_ACCEPTED_STATUS_VALUE = re.compile(r"(?i)^\s*(?:\*\*|__)?Accepted(?:\*\*|__)?\s*$")

_TOP_LEVEL_FIELDS = {
    "schema_version",
    "project",
    "authority",
    "review",
    "objectives",
    "requirements",
    "work_items",
    "research_decisions",
}
_AUTHORITY_FIELDS = {"source_priority", "evidence_is_authoritative"}
_REVIEW_FIELDS = {"last_reviewed", "review_due"}
_OBJECTIVE_FIELDS = {"id", "statement", "status", "source_refs", "validation_refs"}
_REQUIREMENT_FIELDS = {
    "id",
    "statement",
    "status",
    "objective_ids",
    "roadmap_refs",
    "design_refs",
    "implementation_refs",
    "verification_refs",
    "validation_refs",
    "risk_refs",
    "deferral_reason",
    "reconsideration_trigger",
}
_WORK_ITEM_FIELDS = {
    "id",
    "title",
    "status",
    "requirement_ids",
    "roadmap_refs",
    "approval_ref",
    "acceptance_refs",
    "evidence_refs",
}
_RESEARCH_FIELDS = {
    "id",
    "finding",
    "disposition",
    "source_urls",
    "observed_on",
    "reviewed_on",
    "review_due",
    "decision_ref",
}


@dataclass(frozen=True, order=True)
class EvidenceFindingV1:
    """One stable, operator-safe evidence finding."""

    code: str
    severity: str
    record_id: str
    reference: str
    message: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "record_id": self.record_id,
            "reference": self.reference,
            "message": self.message,
        }


@dataclass(frozen=True)
class EvidenceCheckV1:
    """Deterministic summary of one repository evidence check."""

    status: str
    counts: Mapping[str, int]
    findings: tuple[EvidenceFindingV1, ...]

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "counts": dict(sorted(self.counts.items())),
            "findings": [finding.to_mapping() for finding in self.findings],
        }


class ProjectEvidenceChecker:
    """Validate MakopaOS's derived evidence index without side effects."""

    def __init__(self, repository_root: Path, *, as_of: date | None = None) -> None:
        self.root = repository_root.resolve()
        self.as_of = as_of
        self.findings: list[EvidenceFindingV1] = []
        self.ids: set[str] = set()
        self.objective_ids: set[str] = set()
        self.requirement_ids: set[str] = set()
        self.design_paths: set[str] = set()
        self.tracked_paths: set[str] | None = None

    def check(self) -> EvidenceCheckV1:
        payload = self._load_registry()
        if payload is None:
            return self._result({})

        self.tracked_paths = self._load_tracked_paths()

        self._unknown_fields(payload, _TOP_LEVEL_FIELDS, "registry", "registry")
        if payload.get("schema_version") != SCHEMA_VERSION:
            self._add(
                "schema.version",
                "error",
                "registry",
                "schema_version",
                f"schema_version must be {SCHEMA_VERSION}",
            )
        if payload.get("project") != PROJECT_ID:
            self._add(
                "project.identity",
                "error",
                "registry",
                "project",
                f"project must be {PROJECT_ID}",
            )

        self._check_authority(payload.get("authority"))
        self._check_review(payload.get("review"))
        objectives = self._records(payload, "objectives")
        requirements = self._records(payload, "requirements")
        work_items = self._records(payload, "work_items")
        research = self._records(payload, "research_decisions")

        for record in objectives:
            self._check_objective(record)
        for record in requirements:
            self._check_requirement(record)
        for record in work_items:
            self._check_work_item(record)
        for record in research:
            self._check_research_decision(record)
        self._check_accepted_decision_coverage()

        return self._result(
            {
                "objectives": len(objectives),
                "requirements": len(requirements),
                "work_items": len(work_items),
                "research_decisions": len(research),
            }
        )

    def _load_registry(self) -> Mapping[str, object] | None:
        path = self.root / REGISTRY_PATH
        try:
            with path.open("rb") as stream:
                payload = tomllib.load(stream)
        except FileNotFoundError:
            self._add(
                "registry.unreadable",
                "error",
                "registry",
                REGISTRY_PATH.as_posix(),
                "project evidence registry is missing",
            )
            return None
        except OSError:
            self._add(
                "registry.unreadable",
                "error",
                "registry",
                REGISTRY_PATH.as_posix(),
                "project evidence registry could not be read",
            )
            return None
        except tomllib.TOMLDecodeError as exc:
            self._add(
                "registry.unreadable",
                "error",
                "registry",
                REGISTRY_PATH.as_posix(),
                f"project evidence registry is malformed TOML: {exc}",
            )
            return None
        if not isinstance(payload, dict):
            self._add("schema.type", "error", "registry", "registry", "root must be a table")
            return None
        return payload

    def _load_tracked_paths(self) -> set[str] | None:
        try:
            completed = subprocess.run(
                ["git", "-C", str(self.root), "ls-files", "-z"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            completed = None
        if completed is None or completed.returncode != 0:
            self._add(
                "repository.tracking-unavailable",
                "error",
                "registry",
                "repository",
                "Git tracking information is unavailable",
            )
            return None
        return {
            item.decode("utf-8", errors="surrogateescape")
            for item in completed.stdout.split(b"\0")
            if item
        }

    def _result(self, counts: Mapping[str, int]) -> EvidenceCheckV1:
        findings = tuple(sorted(self.findings))
        if any(item.severity == "error" for item in findings):
            status = "fail"
        elif findings:
            status = "warn"
        else:
            status = "pass"
        complete_counts = dict(counts)
        complete_counts["findings"] = len(findings)
        return EvidenceCheckV1(status, complete_counts, findings)

    def _add(
        self,
        code: str,
        severity: str,
        record_id: str,
        reference: str,
        message: str,
    ) -> None:
        self.findings.append(
            EvidenceFindingV1(code, severity, record_id, reference, message)
        )

    def _unknown_fields(
        self,
        value: Mapping[str, object],
        allowed: set[str],
        record_id: str,
        reference: str,
    ) -> None:
        for field in sorted(set(value) - allowed):
            self._add(
                "schema.unknown-field",
                "error",
                record_id,
                f"{reference}.{field}",
                f"unknown field: {field}",
            )

    def _records(
        self, payload: Mapping[str, object], field: str
    ) -> list[Mapping[str, object]]:
        value = payload.get(field)
        if not isinstance(value, list):
            self._add("schema.type", "error", "registry", field, f"{field} must be an array")
            return []
        records: list[Mapping[str, object]] = []
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                self._add(
                    "schema.type",
                    "error",
                    "registry",
                    f"{field}[{index}]",
                    "record must be a table",
                )
            else:
                records.append(item)
        return records

    def _record_id(self, record: Mapping[str, object], kind: str) -> str:
        value = record.get("id")
        if not isinstance(value, str) or not _ID.fullmatch(value):
            self._add("record.id", "error", kind, f"{kind}.id", "id has an invalid format")
            return kind
        if value in self.ids:
            self._add("record.duplicate-id", "error", value, f"{kind}.id", "id is duplicated")
        self.ids.add(value)
        return value

    def _string(
        self, record: Mapping[str, object], field: str, record_id: str
    ) -> str | None:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            self._add(
                "schema.type",
                "error",
                record_id,
                field,
                f"{field} must be a non-empty string",
            )
            return None
        return value

    def _string_list(
        self,
        record: Mapping[str, object],
        field: str,
        record_id: str,
        *,
        required: bool = True,
    ) -> list[str]:
        value = record.get(field)
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            self._add(
                "schema.type",
                "error",
                record_id,
                field,
                f"{field} must be an array of non-empty strings",
            )
            return []
        if required and not value:
            self._add(
                "traceability.missing",
                "error",
                record_id,
                field,
                f"{field} must not be empty",
            )
        if len(value) != len(set(value)):
            self._add(
                "traceability.duplicate-reference",
                "error",
                record_id,
                field,
                f"{field} contains duplicate values",
            )
        return list(value)

    def _check_authority(self, value: object) -> None:
        if not isinstance(value, dict):
            self._add("schema.type", "error", "authority", "authority", "authority must be a table")
            return
        self._unknown_fields(value, _AUTHORITY_FIELDS, "authority", "authority")
        expected = [
            "docs/architecture/overview.md",
            "docs/roadmap/implementation-roadmap.md",
            "docs/architecture/decisions/",
            "code-and-tests",
            "supporting-documentation",
        ]
        if value.get("source_priority") != expected:
            self._add(
                "authority.priority",
                "error",
                "authority",
                "authority.source_priority",
                "source priority must match CONTRIBUTING.md",
            )
        if value.get("evidence_is_authoritative") is not False:
            self._add(
                "authority.evidence",
                "error",
                "authority",
                "authority.evidence_is_authoritative",
                "project evidence must remain a derived index",
            )

    def _check_review(self, value: object) -> None:
        if not isinstance(value, dict):
            self._add("schema.type", "error", "review", "review", "review must be a table")
            return
        self._unknown_fields(value, _REVIEW_FIELDS, "review", "review")
        last_reviewed = self._date(value.get("last_reviewed"), "review", "last_reviewed")
        review_due = self._date(value.get("review_due"), "review", "review_due")
        if last_reviewed and review_due and review_due < last_reviewed:
            self._add(
                "review.order",
                "error",
                "review",
                "review_due",
                "review_due precedes last_reviewed",
            )
        if self.as_of and review_due and self.as_of > review_due:
            self._add(
                "review.overdue",
                "warning",
                "review",
                "review_due",
                "project evidence review is overdue",
            )

    def _date(self, value: object, record_id: str, field: str) -> date | None:
        if not isinstance(value, str):
            self._add("schema.type", "error", record_id, field, f"{field} must be an ISO date string")
            return None
        try:
            return date.fromisoformat(value)
        except ValueError:
            self._add("schema.date", "error", record_id, field, f"{field} must be YYYY-MM-DD")
            return None

    def _check_objective(self, record: Mapping[str, object]) -> None:
        record_id = self._record_id(record, "objective")
        self.objective_ids.add(record_id)
        self._unknown_fields(record, _OBJECTIVE_FIELDS, record_id, "objective")
        self._string(record, "statement", record_id)
        if record.get("status") not in {"active", "superseded"}:
            self._add("objective.status", "error", record_id, "status", "unsupported objective status")
        for field in ("source_refs", "validation_refs"):
            for reference in self._string_list(record, field, record_id):
                self._check_local_reference(reference, record_id, field)

    def _check_requirement(self, record: Mapping[str, object]) -> None:
        record_id = self._record_id(record, "requirement")
        self.requirement_ids.add(record_id)
        self._unknown_fields(record, _REQUIREMENT_FIELDS, record_id, "requirement")
        self._string(record, "statement", record_id)
        status = record.get("status")
        if status not in {"planned", "implemented", "deferred", "retired"}:
            self._add("requirement.status", "error", record_id, "status", "unsupported requirement status")
        for objective_id in self._string_list(record, "objective_ids", record_id):
            if objective_id not in self.objective_ids:
                self._add(
                    "traceability.unknown-objective",
                    "error",
                    record_id,
                    "objective_ids",
                    f"unknown objective: {objective_id}",
                )

        required_fields = ("roadmap_refs", "design_refs")
        if status == "implemented":
            required_fields += (
                "implementation_refs",
                "verification_refs",
                "validation_refs",
                "risk_refs",
            )
        for field in (
            "roadmap_refs",
            "design_refs",
            "implementation_refs",
            "verification_refs",
            "validation_refs",
            "risk_refs",
        ):
            references = self._string_list(
                record, field, record_id, required=field in required_fields
            )
            for reference in references:
                self._check_local_reference(reference, record_id, field)
                if field == "design_refs":
                    self.design_paths.add(self._reference_path(reference))

        if status == "deferred":
            self._string(record, "deferral_reason", record_id)
            self._string(record, "reconsideration_trigger", record_id)
        elif "deferral_reason" in record or "reconsideration_trigger" in record:
            self._add(
                "requirement.deferral-fields",
                "error",
                record_id,
                "status",
                "deferral fields are allowed only for deferred requirements",
            )

    def _check_work_item(self, record: Mapping[str, object]) -> None:
        record_id = self._record_id(record, "work-item")
        self._unknown_fields(record, _WORK_ITEM_FIELDS, record_id, "work-item")
        self._string(record, "title", record_id)
        status = record.get("status")
        allowed = {"proposed", "approved", "in-progress", "verified", "closed", "blocked"}
        if status not in allowed:
            self._add("work-item.status", "error", record_id, "status", "unsupported work-item status")
        for requirement_id in self._string_list(record, "requirement_ids", record_id):
            if requirement_id not in self.requirement_ids:
                self._add(
                    "traceability.unknown-requirement",
                    "error",
                    record_id,
                    "requirement_ids",
                    f"unknown requirement: {requirement_id}",
                )
        for field in ("roadmap_refs", "acceptance_refs"):
            for reference in self._string_list(record, field, record_id):
                self._check_local_reference(reference, record_id, field)
        for reference in self._string_list(
            record,
            "evidence_refs",
            record_id,
            required=status in {"verified", "closed"},
        ):
            self._check_local_reference(reference, record_id, "evidence_refs")

        approval_ref = record.get("approval_ref")
        if status in {"approved", "in-progress", "verified", "closed"}:
            if not isinstance(approval_ref, str) or not (
                _CONVERSATION_APPROVAL.fullmatch(approval_ref)
                or _GITHUB_APPROVAL.fullmatch(approval_ref)
            ):
                self._add(
                    "work-item.approval",
                    "error",
                    record_id,
                    "approval_ref",
                    "approved work requires a dated conversation or MakopaOS GitHub reference",
                )
        elif approval_ref is not None:
            self._add(
                "work-item.approval",
                "error",
                record_id,
                "approval_ref",
                "unapproved work cannot carry an approval reference",
            )

    def _check_research_decision(self, record: Mapping[str, object]) -> None:
        record_id = self._record_id(record, "research-decision")
        self._unknown_fields(record, _RESEARCH_FIELDS, record_id, "research-decision")
        self._string(record, "finding", record_id)
        if record.get("disposition") not in {"adopted", "monitoring", "rejected"}:
            self._add(
                "research.disposition",
                "error",
                record_id,
                "disposition",
                "unsupported research disposition",
            )
        for url in self._string_list(record, "source_urls", record_id):
            if not url.startswith("https://"):
                self._add(
                    "research.source-url",
                    "error",
                    record_id,
                    "source_urls",
                    "research sources must use https",
                )
        observed = self._date(record.get("observed_on"), record_id, "observed_on")
        reviewed = self._date(record.get("reviewed_on"), record_id, "reviewed_on")
        due = self._date(record.get("review_due"), record_id, "review_due")
        if observed and reviewed and reviewed < observed:
            self._add(
                "research.review-order",
                "error",
                record_id,
                "reviewed_on",
                "reviewed_on precedes observed_on",
            )
        if reviewed and due and due < reviewed:
            self._add(
                "research.review-order",
                "error",
                record_id,
                "review_due",
                "review_due precedes reviewed_on",
            )
        if self.as_of and due and self.as_of > due:
            self._add(
                "research.review-overdue",
                "warning",
                record_id,
                "review_due",
                "research decision is due for review",
            )
        decision_ref = self._string(record, "decision_ref", record_id)
        if decision_ref:
            self._check_local_reference(decision_ref, record_id, "decision_ref")

    def _check_local_reference(self, reference: str, record_id: str, field: str) -> None:
        path_text = self._reference_path(reference)
        posix = PurePosixPath(path_text)
        if (
            not path_text
            or "\\" in path_text
            or posix.is_absolute()
            or ":" in path_text
            or any(part in {"", ".", ".."} for part in posix.parts)
            or any(
                part.startswith(".") and (index != 0 or part != ".github")
                for index, part in enumerate(posix.parts)
            )
        ):
            self._add(
                "reference.unsafe",
                "error",
                record_id,
                field,
                f"unsafe repository reference: {reference}",
            )
            return
        resolved = (self.root / Path(*posix.parts)).resolve()
        if self.root not in resolved.parents or not resolved.is_file():
            self._add(
                "reference.missing",
                "error",
                record_id,
                field,
                f"referenced file does not exist: {path_text}",
            )
            return
        if self.tracked_paths is not None and path_text not in self.tracked_paths:
            self._add(
                "reference.untracked",
                "error",
                record_id,
                field,
                f"referenced file is not tracked: {path_text}",
            )
            return
        if "::" in reference:
            symbol = reference.split("::", 1)[1]
            if not self._python_symbol_exists(resolved, symbol):
                self._add(
                    "reference.missing-symbol",
                    "error",
                    record_id,
                    field,
                    f"referenced Python symbol does not exist: {reference}",
                )
        elif "#" in reference:
            anchor = reference.split("#", 1)[1]
            if not self._markdown_anchor_exists(resolved, anchor):
                self._add(
                    "reference.missing-anchor",
                    "error",
                    record_id,
                    field,
                    f"referenced Markdown anchor does not exist: {reference}",
                )

    @staticmethod
    def _reference_path(reference: str) -> str:
        return reference.split("::", 1)[0].split("#", 1)[0]

    @staticmethod
    def _python_symbol_exists(path: Path, symbol: str) -> bool:
        if path.suffix != ".py" or not symbol:
            return False
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError):
            return False
        parts = symbol.split("::")
        body: Sequence[ast.stmt] = tree.body
        for part in parts:
            match = next(
                (
                    node
                    for node in body
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == part
                ),
                None,
            )
            if match is None:
                return False
            body = match.body if isinstance(match, ast.ClassDef) else ()
        return True

    @staticmethod
    def _markdown_anchor_exists(path: Path, anchor: str) -> bool:
        if path.suffix.lower() != ".md" or not anchor:
            return False
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return False
        anchors: set[str] = set()
        duplicates: dict[str, int] = {}
        for line in lines:
            match = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
            if not match:
                continue
            base = re.sub(r"[^\w\- ]", "", match.group(1).casefold(), flags=re.UNICODE)
            base = re.sub(r"[\s-]+", "-", base).strip("-")
            count = duplicates.get(base, 0)
            duplicates[base] = count + 1
            anchors.add(base if count == 0 else f"{base}-{count}")
        return anchor in anchors

    def _check_accepted_decision_coverage(self) -> None:
        decision_root = self.root / "docs" / "architecture" / "decisions"
        try:
            paths = sorted(decision_root.rglob("*.md"))
        except OSError:
            paths = []
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if self._decision_is_accepted(text):
                relative = path.relative_to(self.root).as_posix()
                if relative not in self.design_paths:
                    self._add(
                        "traceability.unindexed-decision",
                        "error",
                        "registry",
                        relative,
                        "accepted decision is not referenced by a requirement",
                    )

    @staticmethod
    def _decision_is_accepted(text: str) -> bool:
        if _INLINE_ACCEPTED_STATUS.search(text):
            return True
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if not _STATUS_HEADING.fullmatch(line):
                continue
            for candidate in lines[index + 1 :]:
                if not candidate.strip():
                    continue
                if _ACCEPTED_STATUS_VALUE.fullmatch(candidate):
                    return True
                break
        return False


def check_project_evidence(
    repository_root: Path, *, as_of: date | None = None
) -> EvidenceCheckV1:
    """Check one repository and return a deterministic evidence result."""
    return ProjectEvidenceChecker(repository_root, as_of=as_of).check()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="check-project-evidence")
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="MakopaOS repository root",
    )
    parser.add_argument("--as-of", help="ISO date used for freshness warnings")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as a failed closure gate",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        as_of = None if args.as_of is None else date.fromisoformat(args.as_of)
    except ValueError:
        print("check-project-evidence: --as-of must be YYYY-MM-DD", file=sys.stderr)
        return 2
    result = check_project_evidence(args.repository_root, as_of=as_of)
    print(json.dumps(result.to_mapping(), indent=2, sort_keys=True))
    if result.status == "fail" or (args.strict and result.status == "warn"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
