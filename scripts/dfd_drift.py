#!/usr/bin/env python3
"""Emit an advisory drift report for a Precogly editor DFD export.

This compares a proposed editor export against the checked-in
``data/systems/<slug>/model/base-dfd.cdx.json`` before authors overwrite the
baseline. Findings are warnings by design: the report should make DFD changes
reviewable without blocking experimentation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from systems.loader import DEFAULT_SYSTEM, load_system  # noqa: E402

SECTION_FIELDS = {
    "zones": ("name", "type", "trustLevel", "parentZone"),
    "assets": ("name", "type", "zone"),
    "flows": ("name", "source", "destination"),
}


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def first_blueprint(doc: dict[str, Any]) -> dict[str, Any]:
    blueprints = doc.get("blueprints") or []
    if not blueprints:
        return {}
    return blueprints[0]


def _index(items: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for item in items:
        ref = item.get("bom-ref")
        if not ref:
            duplicates.append("<missing bom-ref>")
            continue
        if ref in indexed:
            duplicates.append(ref)
        indexed[ref] = item
    return indexed, duplicates


def _finding(section: str, kind: str, message: str, **extra: Any) -> dict[str, Any]:
    out = {"severity": "warning", "section": section, "kind": kind, "message": message}
    out.update(extra)
    return out


def _diff_section(
    section: str,
    base_items: list[dict[str, Any]],
    export_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base, base_dupes = _index(base_items)
    export, export_dupes = _index(export_items)
    for ref in base_dupes:
        findings.append(
            _finding(
                section,
                "duplicate-base-ref",
                f"base DFD duplicates {section} ref {ref}",
                ref=ref,
            )
        )
    for ref in export_dupes:
        findings.append(
            _finding(
                section,
                "duplicate-export-ref",
                f"editor export duplicates {section} ref {ref}",
                ref=ref,
            )
        )

    for ref in sorted(set(base) - set(export)):
        findings.append(
            _finding(
                section,
                "removed",
                f"editor export removed {section} ref {ref}",
                ref=ref,
            )
        )
    for ref in sorted(set(export) - set(base)):
        findings.append(
            _finding(
                section, "added", f"editor export added {section} ref {ref}", ref=ref
            )
        )

    for ref in sorted(set(base) & set(export)):
        changed = {}
        for field in SECTION_FIELDS[section]:
            if base[ref].get(field) != export[ref].get(field):
                changed[field] = {
                    "base": base[ref].get(field),
                    "export": export[ref].get(field),
                }
        if changed:
            findings.append(
                _finding(
                    section,
                    "modified",
                    f"editor export modified {section} ref {ref}",
                    ref=ref,
                    fields=changed,
                )
            )
    return findings


def _endpoint_findings(export_bp: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    asset_refs = {
        item.get("bom-ref")
        for item in export_bp.get("assets", [])
        if item.get("bom-ref")
    }
    zone_refs = {
        item.get("bom-ref")
        for item in export_bp.get("zones", [])
        if item.get("bom-ref")
    }
    endpoints = asset_refs | zone_refs
    for flow in export_bp.get("flows", []) or []:
        ref = flow.get("bom-ref", "<missing bom-ref>")
        for field in ("source", "destination"):
            target = flow.get(field)
            if target not in endpoints:
                findings.append(
                    _finding(
                        "flows",
                        "bad-endpoint",
                        f"editor export flow {ref} {field} references unknown DFD node {target}",
                        ref=ref,
                        field=field,
                        target=target,
                    )
                )
    return findings


def build_report(system: str, base_path: Path, export_path: Path) -> dict[str, Any]:
    base = load_json(base_path)
    export = load_json(export_path)
    base_bp = first_blueprint(base)
    export_bp = first_blueprint(export)

    findings: list[dict[str, Any]] = []
    if (export.get("metadata") or {}).get("authors"):
        findings.append(
            _finding(
                "metadata",
                "editor-authors",
                "editor export includes metadata.authors; strip before replacing the base DFD",
                field="metadata.authors",
            )
        )

    for section in ("zones", "assets", "flows"):
        findings.extend(
            _diff_section(
                section,
                base_bp.get(section, []) or [],
                export_bp.get(section, []) or [],
            )
        )
    findings.extend(_endpoint_findings(export_bp))

    by_kind = Counter(finding["kind"] for finding in findings)
    return {
        "system": system,
        "status": "drift" if findings else "clean",
        "generated_at": datetime.now(UTC).isoformat(),
        "base_dfd": _rel(base_path),
        "editor_export": _rel(export_path),
        "summary": {
            "findings": len(findings),
            "by_kind": dict(sorted(by_kind.items())),
            "base_counts": {
                section: len(base_bp.get(section, []) or [])
                for section in ("zones", "assets", "flows")
            },
            "export_counts": {
                section: len(export_bp.get(section, []) or [])
                for section in ("zones", "assets", "flows")
            },
        },
        "findings": findings,
    }


def write_report(report: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(report, f, sort_keys=False, allow_unicode=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", default=DEFAULT_SYSTEM)
    parser.add_argument(
        "--export",
        required=True,
        help="Precogly editor-exported CycloneDX DFD file to compare",
    )
    parser.add_argument(
        "--out", help="Report path (default: build/<system>-dfd-drift.yaml)"
    )
    args = parser.parse_args(argv)

    paths = load_system(args.system)
    if not paths.model_dfd:
        print(f"FAIL: {args.system} has no model/base-dfd.cdx.json", file=sys.stderr)
        return 1

    export_path = Path(args.export)
    if not export_path.is_absolute():
        export_path = ROOT / export_path
    out_path = (
        Path(args.out) if args.out else ROOT / "build" / f"{args.system}-dfd-drift.yaml"
    )
    if not out_path.is_absolute():
        out_path = ROOT / out_path

    report = build_report(args.system, paths.model_dfd, export_path)
    write_report(report, out_path)
    print(
        f"Wrote {_rel(out_path)} with {report['summary']['findings']} advisory DFD drift finding(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
