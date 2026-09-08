#!/usr/bin/env python3
"""Emit a drift report for a Precogly editor DFD export.

This compares a proposed editor export against the checked-in
``data/systems/<slug>/model/base-dfd.cdx.json`` before authors overwrite the
baseline. By default findings are a failing drift gate; use ``--advisory`` when
the report should make DFD changes reviewable without blocking experimentation.
"""

from __future__ import annotations

import argparse
import copy
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
from systems.rehydrate_dfd import (  # noqa: E402
    DEFAULT_MERGE_TYPES,
    rehydrate_dfd,
)

SECTION_FIELDS = {
    "zones": ("name", "type", "trustLevel", "parentZone"),
    "assets": ("name", "type", "zone"),
    "flows": ("name", "source", "destination"),
    "boundaries": ("name", "zones"),
    "dataStores": ("name", "zone"),
}
DFD_SECTIONS = tuple(SECTION_FIELDS)


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _counts(blueprint: dict[str, Any]) -> dict[str, int]:
    return {section: len(blueprint.get(section, []) or []) for section in DFD_SECTIONS}


def first_blueprint(doc: dict[str, Any]) -> dict[str, Any]:
    blueprints = doc.get("blueprints") or []
    if not blueprints:
        return {}
    return blueprints[0]


def _item_ref(section: str, item: dict[str, Any]) -> str | None:
    ref = item.get("bom-ref")
    if ref:
        return str(ref)
    if section == "boundaries" and item.get("zones"):
        return "zones:" + ",".join(sorted(str(zone) for zone in item["zones"]))
    return None


def _index(
    section: str, items: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for item in items:
        ref = _item_ref(section, item)
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
    base, base_dupes = _index(section, base_items)
    export, export_dupes = _index(section, export_items)
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


def build_report(
    system: str,
    base_path: Path,
    export_path: Path,
    *,
    redaction_path: Path | None = None,
) -> dict[str, Any]:
    base = load_json(base_path)
    raw_export = load_json(export_path)
    export, normalization = rehydrate_dfd(
        copy.deepcopy(raw_export),
        redaction_path=redaction_path,
        merge_types=set(DEFAULT_MERGE_TYPES),
    )
    base_bp = first_blueprint(base)
    export_bp = first_blueprint(export)
    raw_export_bp = first_blueprint(raw_export)

    findings: list[dict[str, Any]] = []
    if (raw_export.get("metadata") or {}).get("authors"):
        findings.append(
            _finding(
                "metadata",
                "editor-authors",
                "editor export includes metadata.authors; strip before replacing the base DFD",
                field="metadata.authors",
            )
        )

    for section in DFD_SECTIONS:
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
            "base_counts": _counts(base_bp),
            "export_counts": _counts(export_bp),
            "raw_export_counts": _counts(raw_export_bp),
            "normalization": normalization["summary"],
        },
        "findings": findings,
    }


def _format_counts(counts: dict[str, int]) -> str:
    labels = {
        "zones": "zones",
        "assets": "assets",
        "flows": "flows",
        "boundaries": "boundaries",
        "dataStores": "data stores",
    }
    return " / ".join(
        f"{counts[section]} {labels[section]}" for section in DFD_SECTIONS
    )


def exit_code(report: dict[str, Any], *, advisory: bool) -> int:
    if advisory:
        return 0
    return 1 if report["summary"]["findings"] else 0


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
    parser.add_argument(
        "--advisory",
        action="store_true",
        help="Write the report but exit zero even when drift is detected",
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

    report = build_report(
        args.system, paths.model_dfd, export_path, redaction_path=paths.redaction
    )
    write_report(report, out_path)
    base_counts = _format_counts(report["summary"]["base_counts"])
    export_counts = _format_counts(report["summary"]["export_counts"])
    print(
        f"Wrote {_rel(out_path)} with {report['summary']['findings']} DFD drift finding(s)."
    )
    if report["summary"]["findings"]:
        mode = "advisory" if args.advisory else "failing"
        print(
            "DFD drift detected "
            f"({mode}): base has {base_counts}; editor export has {export_counts}.",
            file=sys.stderr,
        )
    else:
        print(
            "OK: no DFD drift after rehydrating editor export; "
            f"base and normalized export both have {base_counts}."
        )
    return exit_code(report, advisory=args.advisory)


if __name__ == "__main__":
    raise SystemExit(main())
