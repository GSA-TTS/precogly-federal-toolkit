#!/usr/bin/env python3
"""Validate owner-authorized CUI/provenance sidecars for docx-derived content."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO / "schemas-local" / "cui-provenance.schema.json"
SYSTEMS_DIR = REPO / "data" / "systems"


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_CUI_CATEGORY_RE = re.compile(r"^(not_cui|[A-Z][A-Z0-9_-]*)$")
_REVIEW_CADENCES = {"quarterly", "semiannual", "annual", "per-source-update"}
_SOURCE_TYPES = {"ssp-docx", "poam-xlsx", "control-workbook", "manual-source", "other"}


@dataclass(frozen=True)
class CoverageRow:
    system_slug: str
    requires_sidecar: bool
    has_sidecar: bool
    cui_category: str
    source_types: list[str]
    downstream_artifacts: int
    status: str


def _candidate_system_dirs(root: Path) -> list[Path]:
    return sorted(
        p for p in root.iterdir() if p.is_dir() and (p / "system.yaml").exists()
    )


def _requires_contract(system_dir: Path) -> bool:
    markers = [
        system_dir / "responses.yaml",
        system_dir / "sidecar.yaml",
        system_dir / "frr.yaml",
        system_dir / "ksi.yaml",
    ]
    return any(path.exists() for path in markers)


def _required_mapping(
    data: dict[str, Any], key: str, errors: list[str], path: Path
) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        errors.append(f"{path}: {key}: required mapping missing")
        return {}
    return value


def _required_list(
    data: dict[str, Any], key: str, errors: list[str], path: Path
) -> list[Any]:
    value = data.get(key)
    if not isinstance(value, list) or not value:
        errors.append(f"{path}: {key}: required non-empty list missing")
        return []
    return value


def _redaction_policy_errors(system_dir: Path, category: str, path: Path) -> list[str]:
    if category == "not_cui":
        return []
    redaction = system_dir / "redaction.yaml"
    if not redaction.exists():
        return [f"{path}: classified sidecar requires {redaction}"]
    data = _load_yaml(redaction)
    patterns = data.get("forbidden_patterns")
    if not isinstance(patterns, list) or not patterns:
        return [
            f"{path}: classified sidecar requires non-empty redaction.yaml forbidden_patterns"
        ]
    return []


def validate_sidecar(path: Path) -> list[str]:
    data = _load_yaml(path)
    errors: list[str] = []
    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version: must be 1")
    slug = data.get("system_slug")
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        errors.append(f"{path}: system_slug: invalid slug")
    elif slug != path.parent.name:
        errors.append(
            f"{path}: system_slug must match directory name {path.parent.name!r}"
        )

    classification = _required_mapping(data, "classification", errors, path)
    category = classification.get("cui_category")
    if not isinstance(category, str) or not _CUI_CATEGORY_RE.match(category):
        errors.append(f"{path}: classification/cui_category: invalid category")
    for key in ("cui_marking", "authority"):
        if not isinstance(classification.get(key), str) or len(classification[key]) < 3:
            errors.append(f"{path}: classification/{key}: required string too short")
    if classification.get("review_cadence") not in _REVIEW_CADENCES:
        errors.append(f"{path}: classification/review_cadence: invalid cadence")
    if isinstance(category, str):
        errors.extend(_redaction_policy_errors(path.parent, category, path))

    approval = _required_mapping(data, "ingestion_approval", errors, path)
    for key in ("approved_by_role", "approval_ref"):
        if not isinstance(approval.get(key), str) or len(approval[key]) < 3:
            errors.append(
                f"{path}: ingestion_approval/{key}: required string too short"
            )
    try:
        date.fromisoformat(str(approval.get("approval_date")))
    except ValueError:
        errors.append(f"{path}: ingestion_approval/approval_date: invalid date")

    approved_by_role = approval.get("approved_by_role")
    if isinstance(approved_by_role, str) and not re.search(
        r"(?:^|[-_ ])(?:system[-_ ]?owner|owner)(?:$|[-_ ])", approved_by_role, re.IGNORECASE
    ):
        errors.append(
            f"{path}: ingestion_approval/approved_by_role must identify the owning system role"
        )

    for idx, source in enumerate(
        _required_list(data, "source_documents", errors, path)
    ):
        if not isinstance(source, dict):
            errors.append(f"{path}: source_documents/{idx}: required mapping missing")
            continue
        if (
            not isinstance(source.get("source_doc_ref"), str)
            or len(source["source_doc_ref"]) < 3
        ):
            errors.append(
                f"{path}: source_documents/{idx}/source_doc_ref: required string too short"
            )
        if not isinstance(source.get("sha256"), str) or not _SHA256_RE.match(
            source["sha256"]
        ):
            errors.append(f"{path}: source_documents/{idx}/sha256: invalid sha256")
        if source.get("source_type") not in _SOURCE_TYPES:
            errors.append(
                f"{path}: source_documents/{idx}/source_type: invalid source type"
            )

    for artifact in _required_list(data, "downstream_artifacts", errors, path):
        if not isinstance(artifact, str) or len(artifact) < 3:
            errors.append(f"{path}: downstream_artifacts: invalid artifact path")
            continue
        if Path(artifact).is_absolute() or ".." in Path(artifact).parts:
            errors.append(
                f"{path}: downstream artifact must be a repo-relative path: {artifact}"
            )

    retention = _required_mapping(data, "retention", errors, path)
    for key in ("retention_period", "decontrol_condition"):
        if not isinstance(retention.get(key), str) or len(retention[key]) < 3:
            errors.append(f"{path}: retention/{key}: required string too short")
    return errors


def validate_systems(root: Path, require_all: bool) -> list[str]:
    errors: list[str] = []
    for system_dir in _candidate_system_dirs(root):
        sidecar = system_dir / "cui.yaml"
        if not sidecar.exists():
            if require_all and _requires_contract(system_dir):
                errors.append(f"{sidecar}: missing CUI/provenance sidecar")
            continue
        errors.extend(validate_sidecar(sidecar))
    return errors


def coverage_rows(root: Path) -> list[CoverageRow]:
    rows: list[CoverageRow] = []
    for system_dir in _candidate_system_dirs(root):
        sidecar = system_dir / "cui.yaml"
        requires = _requires_contract(system_dir)
        if not sidecar.exists():
            rows.append(
                CoverageRow(
                    system_slug=system_dir.name,
                    requires_sidecar=requires,
                    has_sidecar=False,
                    cui_category="",
                    source_types=[],
                    downstream_artifacts=0,
                    status="missing" if requires else "not-required",
                )
            )
            continue
        data = _load_yaml(sidecar)
        classification = data.get("classification") or {}
        sources = data.get("source_documents") or []
        status = "invalid" if validate_sidecar(sidecar) else "ok"
        rows.append(
            CoverageRow(
                system_slug=system_dir.name,
                requires_sidecar=requires,
                has_sidecar=True,
                cui_category=str(classification.get("cui_category", "")),
                source_types=sorted(
                    {
                        str(source.get("source_type", ""))
                        for source in sources
                        if source.get("source_type")
                    }
                ),
                downstream_artifacts=len(data.get("downstream_artifacts") or []),
                status=status,
            )
        )
    return rows


def render_coverage_markdown(rows: list[CoverageRow]) -> str:
    lines = [
        "# CUI Sidecar Coverage Report",
        "",
        "| System | Requires sidecar | Has sidecar | CUI category | Source types | Downstream artifacts | Status |",
        "| --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for row in rows:
        lines.append(
            f"| `{row.system_slug}` | {'yes' if row.requires_sidecar else 'no'} | {'yes' if row.has_sidecar else 'no'} | "
            f"{row.cui_category or '-'} | {', '.join(row.source_types) or '-'} | {row.downstream_artifacts} | {row.status} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Specific cui.yaml files to validate")
    parser.add_argument("--systems-root", default=str(SYSTEMS_DIR))
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="Require every system with response/sidecar evidence files to have data/systems/<slug>/cui.yaml",
    )
    parser.add_argument(
        "--coverage", action="store_true", help="Print CUI sidecar coverage as Markdown"
    )
    parser.add_argument("--out", help="Write coverage report to this path")
    args = parser.parse_args()

    if args.coverage:
        report = render_coverage_markdown(coverage_rows(Path(args.systems_root)))
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(report)
            print(f"Wrote {out}")
        else:
            print(report, end="")
        return 0

    errors: list[str] = []
    if args.paths:
        for path in args.paths:
            errors.extend(validate_sidecar(Path(path)))
    else:
        errors.extend(validate_systems(Path(args.systems_root), args.require_all))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("OK - CUI/provenance sidecars valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
