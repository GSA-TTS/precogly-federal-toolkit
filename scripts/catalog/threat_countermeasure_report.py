#!/usr/bin/env python3
"""
Portfolio threat-countermeasure report.

Walks every build/systems/<slug>/*.cdx.json file, joins threats to their
mitigating controls, and emits a flat CSV and/or Markdown table.

Usage:
  python3 scripts/catalog/threat_countermeasure_report.py
  python3 scripts/catalog/threat_countermeasure_report.py --format csv
  python3 scripts/catalog/threat_countermeasure_report.py --format md
  python3 scripts/catalog/threat_countermeasure_report.py --format both --out build/
  python3 scripts/catalog/threat_countermeasure_report.py --slug example-system
  python3 scripts/catalog/threat_countermeasure_report.py --status gap,recommended
  python3 scripts/catalog/threat_countermeasure_report.py --full
  python3 scripts/catalog/threat_countermeasure_report.py --per-system build/reports/

Columns added after the original ten (appended, so positional readers keep
working): control_type, providing_system, inheritance_mode,
implementation_statement, responsibility_writeup. Text is cut at 300 characters
unless --full is given. --per-system writes one Markdown document per system
with the full control statement and tenant guidance for each row.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SYSTEMS_DIR = REPO_ROOT / "build" / "systems"

# Also include stand-alone CRM artifacts (not under build/systems/)
EXTRA_CDX = [
    REPO_ROOT / "build" / "example-system-crm-threat-model.cdx.json",
]


_PLACEHOLDER_RE = re.compile(r"\[Add Implementation[^\]]*\]", re.IGNORECASE)
_TRUNCATE = 300


def _clean(text: str) -> str:
    """Drop template placeholders such as "[Add Implementation ...]" and tidy blank lines."""
    text = _PLACEHOLDER_RE.sub("", text or "")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _cut(text: str, full: bool) -> str:
    return text if full else text[:_TRUNCATE]


# ── CDX helpers ──────────────────────────────────────────────────────────────


def _props(node: dict) -> dict[str, str]:
    return {p["name"]: p.get("value", "") for p in (node.get("properties") or [])}


def _ext_ref(node: dict, ref_type: str) -> str:
    for ref in node.get("externalReferences") or []:
        if ref.get("type") == ref_type:
            return ref.get("url", "")
    return ""


def _threat_list(cdx: dict) -> list[dict]:
    block = cdx.get("threats", {})
    if isinstance(block, list):
        return block
    if isinstance(block, dict):
        return block.get("threats", [])
    return []


# ── Row builder ──────────────────────────────────────────────────────────────


def _slug_from_path(cdx_path: Path) -> str:
    # build/systems/<slug>/<slug>.cdx.json  or  build/<name>.cdx.json
    parts = cdx_path.parts
    try:
        idx = parts.index("systems")
        return parts[idx + 1]
    except ValueError:
        return cdx_path.stem.replace(".cdx", "")


def extract_rows(cdx_path: Path, *, full: bool = False) -> list[dict]:
    data = json.loads(cdx_path.read_text(encoding="utf-8"))
    slug = _slug_from_path(cdx_path)

    controls_by_ref: dict[str, dict] = {
        c["bom-ref"]: c for c in data.get("controls", [])
    }
    threats = _threat_list(data)

    # metadata stub flag
    meta_props = {
        p["name"]: p.get("value", "")
        for p in (data.get("metadata", {}).get("properties") or [])
    }
    is_stub = meta_props.get("resp:stub", "") == "no-threat-model"

    rows: list[dict] = []
    for threat in threats:
        tp = _props(threat)
        nist_id = tp.get("ctrl:id") or tp.get("resp:ctrl-ref") or ""
        impl_status = (
            tp.get("vault:implementation-status") or tp.get("resp:status") or ""
        )
        origination = tp.get("vault:origination") or ""
        responsibility_writeup = _clean(tp.get("resp:writeup") or "")
        providing_system = tp.get("vault:providing-system") or ""
        inheritance_mode = tp.get("vault:inheritance-mode") or ""

        mitigation_refs = threat.get("mitigations") or []
        if not mitigation_refs:
            # Emit one row per threat even when no controls are linked
            rows.append(
                {
                    "system": slug,
                    "threat_ref": threat.get("bom-ref", ""),
                    "threat_name": threat.get("name", ""),
                    "ctrl_id": nist_id,
                    "implementation_status": impl_status,
                    "origination": origination,
                    "control_ref": "",
                    "control_name": "",
                    "control_status": "",
                    "control_description": "",
                    "evidence_url": "",
                    "responsibility_writeup": _cut(responsibility_writeup, full),
                    "stub": str(is_stub).lower(),
                    "control_type": "",
                    "providing_system": providing_system,
                    "inheritance_mode": inheritance_mode,
                    "implementation_statement": "",
                }
            )
        else:
            for ctrl_ref in mitigation_refs:
                ctrl = controls_by_ref.get(ctrl_ref, {})
                cp = _props(ctrl)
                ctrl_nist = cp.get("ctrl:id") or nist_id
                description = _clean(ctrl.get("description") or "")
                rows.append(
                    {
                        "system": slug,
                        "threat_ref": threat.get("bom-ref", ""),
                        "threat_name": threat.get("name", ""),
                        "ctrl_id": ctrl_nist or nist_id,
                        "implementation_status": impl_status,
                        "origination": origination,
                        "control_ref": ctrl_ref,
                        "control_name": ctrl.get("name", ctrl_ref),
                        "control_status": ctrl.get("status", ""),
                        "control_description": _cut(description, full),
                        "evidence_url": _ext_ref(ctrl, "evidence"),
                        "responsibility_writeup": _cut(responsibility_writeup, full),
                        "stub": str(is_stub).lower(),
                        "control_type": cp.get("vault:control-type", ""),
                        "providing_system": cp.get("vault:providing-system")
                        or providing_system,
                        "inheritance_mode": cp.get("vault:inheritance-mode")
                        or inheritance_mode,
                        "implementation_statement": _cut(
                            _clean(cp.get("resp:statement", "")), full
                        ),
                    }
                )
    return rows


# ── Format writers ───────────────────────────────────────────────────────────

COLUMNS = [
    "system",
    "ctrl_id",
    "threat_name",
    "implementation_status",
    "origination",
    "control_name",
    "control_status",
    "evidence_url",
    "control_description",
    "stub",
    "control_type",
    "providing_system",
    "inheritance_mode",
    "implementation_statement",
    "responsibility_writeup",
]


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def to_markdown(rows: list[dict]) -> str:
    lines: list[str] = []
    current_system = None

    for row in sorted(
        rows, key=lambda r: (r["system"], r["ctrl_id"], r["threat_name"])
    ):
        if row["system"] != current_system:
            current_system = row["system"]
            lines.append(f"\n## {current_system}\n")
            lines.append(
                "| NIST ID | Threat | Impl Status | Origination | Control | Ctrl Status | Evidence |"
            )
            lines.append(
                "|---------|--------|-------------|-------------|---------|-------------|----------|"
            )

        ev = f"[link]({row['evidence_url']})" if row["evidence_url"] else ""
        ctrl_status = row["control_status"]
        # Highlight gaps
        if ctrl_status in ("recommended", "gap"):
            ctrl_status = f"**{ctrl_status}**"
        lines.append(
            f"| {row['ctrl_id']} "
            f"| {row['threat_name'][:60]} "
            f"| {row['implementation_status']} "
            f"| {row['origination']} "
            f"| {row['control_name'][:50]} "
            f"| {ctrl_status} "
            f"| {ev} |"
        )
    return "\n".join(lines)


_STATUS_BADGE = {
    "implemented": "implemented",
    "verified": "verified",
    "in-progress": "in-progress",
    "planned": "planned",
    "recommended": "**recommended**",
    "gap": "**gap**",
    "not-implemented": "**not-implemented**",
}


def to_system_markdown(system: str, rows: list[dict]) -> str:
    """One document for one system: full control statement and tenant guidance per row."""
    lines = [f"# Threat and countermeasure report: {system}", ""]
    for row in sorted(rows, key=lambda r: (r["ctrl_id"], r["threat_name"])):
        lines.append(
            f"## {row['ctrl_id'] or '(no control id)'}: {row['control_name'] or row['threat_name']}"
        )
        lines.append("")
        status = row["control_status"] or row["implementation_status"]
        meta = [
            f"Status: {_STATUS_BADGE.get(status, status) or 'n/a'}",
            f"Origination: {row['origination'] or 'n/a'}",
        ]
        if row["providing_system"]:
            meta.append(
                f"Provider: {row['providing_system']} ({row['inheritance_mode'] or 'n/a'})"
            )
        if row["control_type"]:
            meta.append(f"Type: {row['control_type']}")
        if row["evidence_url"]:
            meta.append(f"[evidence]({row['evidence_url']})")
        lines.append(" | ".join(meta))
        lines.append("")
        if row["control_description"]:
            lines += ["**Control statement**", "", row["control_description"], ""]
        guidance = row["implementation_statement"] or row["responsibility_writeup"]
        if guidance:
            lines += ["**Implementation / tenant guidance**", "", guidance, ""]
        lines += ["---", ""]
    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--format", choices=["csv", "md", "both"], default="both")
    ap.add_argument("--out", default="build", help="Output directory (default: build/)")
    ap.add_argument(
        "--slug", help="Comma-separated system slugs to include (default: all)"
    )
    ap.add_argument(
        "--status",
        help="Comma-separated control statuses to include, e.g. gap,recommended (default: all)",
    )
    ap.add_argument(
        "--stdout", action="store_true", help="Print to stdout instead of files"
    )
    ap.add_argument(
        "--full",
        action="store_true",
        help="Do not cut control and tenant text at 300 characters",
    )
    ap.add_argument(
        "--per-system",
        metavar="DIR",
        help="Also write one full-text Markdown document per system into DIR",
    )
    args = ap.parse_args()

    slugs = {s.strip() for s in args.slug.split(",")} if args.slug else None
    statuses = {s.strip() for s in args.status.split(",")} if args.status else None

    # Collect CDX paths
    cdx_paths: list[Path] = []
    for system_dir in sorted(SYSTEMS_DIR.iterdir()):
        if not system_dir.is_dir():
            continue
        if slugs and system_dir.name not in slugs:
            continue
        for cdx in system_dir.glob("*.cdx.json"):
            cdx_paths.append(cdx)
    for p in EXTRA_CDX:
        if p.exists():
            stem = p.stem.replace(".cdx", "")
            if not slugs or stem in slugs:
                cdx_paths.append(p)

    if not cdx_paths:
        print("No CDX files found.", file=sys.stderr)
        sys.exit(1)

    # Build rows
    all_rows: list[dict] = []
    for path in cdx_paths:
        try:
            rows = extract_rows(path, full=args.full or bool(args.per_system))
        except Exception as exc:
            print(f"WARN: {path.name}: {exc}", file=sys.stderr)
            continue
        if statuses:
            rows = [
                r
                for r in rows
                if r["control_status"] in statuses
                or r["implementation_status"] in statuses
            ]
        all_rows.extend(rows)

    print(
        f"Collected {len(all_rows)} rows from {len(cdx_paths)} CDX files.",
        file=sys.stderr,
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ("csv", "both"):
        content = to_csv(all_rows)
        if args.stdout:
            print(content)
        else:
            out = out_dir / "threat-countermeasure-report.csv"
            out.write_text(content, encoding="utf-8")
            print(f"Wrote {out}", file=sys.stderr)

    if args.per_system:
        per_dir = Path(args.per_system)
        per_dir.mkdir(parents=True, exist_ok=True)
        by_system: dict[str, list[dict]] = {}
        for row in all_rows:
            by_system.setdefault(row["system"], []).append(row)
        for system, system_rows in sorted(by_system.items()):
            target = per_dir / f"{system}.md"
            target.write_text(to_system_markdown(system, system_rows), encoding="utf-8")
        print(
            f"Wrote {len(by_system)} per-system documents to {per_dir}", file=sys.stderr
        )

    if args.format in ("md", "both"):
        content = to_markdown(all_rows)
        if args.stdout:
            print(content)
        else:
            out = out_dir / "threat-countermeasure-report.md"
            out.write_text(content, encoding="utf-8")
            print(f"Wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
