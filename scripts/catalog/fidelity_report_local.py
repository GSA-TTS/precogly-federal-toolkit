#!/usr/bin/env python3
"""
Offline per-system fidelity report from local CDX files.

Usage:
  python3 scripts/catalog/fidelity_report_local.py [--out build/fidelity-report.yaml]
  python3 scripts/catalog/fidelity_report_local.py --ci  # exits non-zero on breaches
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SYSTEMS_DIR = REPO_ROOT / "build" / "systems"

# Minimum fill-rate thresholds (enforced by --ci)
THRESHOLDS = {
    "nist_pct": 100,
    "prose_pct": 80,
    "evidence_link_pct": 0,  # not yet enforced (N1 evidence work ongoing)
}


def _props(control: dict) -> dict[str, str]:
    return {p["name"]: p.get("value", "") for p in (control.get("properties") or [])}


def analyze(cdx_path: Path) -> dict:
    data = json.loads(cdx_path.read_text(encoding="utf-8"))
    controls = data.get("controls", [])

    threats_block = data.get("threats", {})
    if isinstance(threats_block, dict):
        threats = threats_block.get("threats", [])
        scenarios = threats_block.get("scenarios", [])
    else:
        threats = list(threats_block)
        scenarios = []

    n = len(controls)
    nist = prose = evidence_link = 0
    # origination tier counts: inherited / shared / system-specific / unknown
    orig_counts: dict[str, int] = {}
    for c in controls:
        p = _props(c)
        if p.get("ctrl:id"):
            nist += 1
        if (c.get("description") or "").strip():
            prose += 1
        if p.get("resp:evidence-link"):
            evidence_link += 1
        tier = p.get("vault:origination", "").lower() or "unset"
        orig_counts[tier] = orig_counts.get(tier, 0) + 1

    inherited = orig_counts.get("inherited", 0)

    def pct(x: int) -> int | None:
        return (100 * x // n) if n else None

    return {
        "system": cdx_path.parent.name,
        "controls": n,
        "nist_pct": pct(nist),
        "prose_pct": pct(prose),
        "evidence_link_pct": pct(evidence_link),
        "inherited_pct": pct(inherited),
        # per-tier breakdown (system-specific / shared / inherited / unset)
        "origination": dict(sorted(orig_counts.items())),
        "threats": len(threats),
        "scenarios": len(scenarios),
        "gaps": {
            "nist_missing": n - nist,
            "prose_missing": n - prose,
            "evidence_link_missing": n - evidence_link,
        },
    }


def print_table(rows: list[dict]) -> None:
    header = (
        f"{'System':<42} {'Ctrl':>5} {'NIST%':>6} {'Prose%':>7} "
        f"{'EvidURL%':>9} {'Inh%':>5} {'Threats':>7} {'Scen':>5}"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)
    for r in rows:

        def fmt(v):
            return f"{v}%" if v is not None else " n/a"

        print(
            f"{r['system']:<42} {r['controls']:>5} "
            f"{fmt(r['nist_pct']):>6} {fmt(r['prose_pct']):>7} "
            f"{fmt(r['evidence_link_pct']):>9} {fmt(r['inherited_pct']):>5} "
            f"{r['threats']:>7} {r['scenarios']:>5}"
        )

    total_ctrl = sum(r["controls"] for r in rows)
    total_threats = sum(r["threats"] for r in rows)
    total_scen = sum(r["scenarios"] for r in rows)

    def total_pct(field: str) -> str:
        num = sum(r["controls"] * (r[field] or 0) // 100 for r in rows if r["controls"])
        return f"{100 * num // total_ctrl}%" if total_ctrl else "n/a"

    print(sep)
    print(
        f"{'TOTAL':<42} {total_ctrl:>5} "
        f"{total_pct('nist_pct'):>6} {total_pct('prose_pct'):>7} "
        f"{total_pct('evidence_link_pct'):>9} {total_pct('inherited_pct'):>5} "
        f"{total_threats:>7} {total_scen:>5}"
    )


def check_thresholds(rows: list[dict]) -> list[str]:
    violations = []
    for r in rows:
        if r["controls"] == 0:
            continue
        for field, minimum in THRESHOLDS.items():
            if minimum == 0:
                continue
            val = r.get(field)
            if val is not None and val < minimum:
                violations.append(f"{r['system']}: {field} {val}% < {minimum}%")
    return violations


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Offline fidelity report from local CDX files"
    )
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "build" / "fidelity-report.yaml"),
        help="Write YAML report to this path",
    )
    parser.add_argument(
        "--ci", action="store_true", help="Exit non-zero on threshold violations"
    )
    parser.add_argument("--no-output-file", action="store_true")
    args = parser.parse_args()

    rows: list[dict] = []
    if SYSTEMS_DIR.exists():
        for d in sorted(SYSTEMS_DIR.iterdir()):
            cdx_path = d / (d.name + ".cdx.json")
            if not cdx_path.exists():
                continue
            rows.append(analyze(cdx_path))

    if not rows:
        message = (
            f"No CDX files found under {SYSTEMS_DIR} — run make vault-import-all first."
        )
        print(message)
        if not args.no_output_file:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                yaml.dump(
                    {
                        "generated_date": date.today().isoformat(),
                        "import_coverage": {
                            "total_systems": 0,
                            "total_controls": 0,
                            "ctrl_id_pct": None,
                            "evidence_link_pct": None,
                            "prose_pct": None,
                        },
                        "systems": [],
                        "thresholds": THRESHOLDS,
                        "violations": [],
                        "status": "no-cdx-files",
                        "message": message,
                    },
                    sort_keys=False,
                    allow_unicode=True,
                ),
                encoding="utf-8",
            )
        return

    print()
    print_table(rows)
    print()

    violations = check_thresholds(rows)
    if violations:
        print("Threshold violations:")
        for v in violations:
            print(f"  FAIL: {v}")
        print()

    # lowest evidence coverage — highlight the 5 worst
    lowest = sorted(
        (r for r in rows if r["controls"] > 0),
        key=lambda r: r["evidence_link_pct"] or 0,
    )[:5]
    print("Lowest evidence_link fill rates:")
    for r in lowest:
        print(
            f"  {r['system']}: {r['evidence_link_pct']}%  ({r['gaps']['evidence_link_missing']} controls without evidence link)"
        )
    print()

    # zero-threat systems worth investigating
    zero_threat = [r for r in rows if r["threats"] == 0 and r["controls"] > 5]
    if zero_threat:
        print("Systems with 0 threats (possible stubs):")
        for r in zero_threat:
            print(f"  {r['system']}: {r['controls']} controls, 0 threats")
        print()

    if not args.no_output_file:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "generated_date": date.today().isoformat(),
            "import_coverage": {
                "total_systems": len(rows),
                "total_controls": sum(r["controls"] for r in rows),
                "ctrl_id_pct": (
                    100
                    * sum(r["controls"] * (r["nist_pct"] or 0) // 100 for r in rows)
                    // sum(r["controls"] for r in rows)
                    if any(r["controls"] for r in rows)
                    else None
                ),
                "evidence_link_pct": (
                    100
                    * sum(
                        r["controls"] * (r["evidence_link_pct"] or 0) // 100
                        for r in rows
                    )
                    // sum(r["controls"] for r in rows)
                    if any(r["controls"] for r in rows)
                    else None
                ),
                "prose_pct": (
                    100
                    * sum(r["controls"] * (r["prose_pct"] or 0) // 100 for r in rows)
                    // sum(r["controls"] for r in rows)
                    if any(r["controls"] for r in rows)
                    else None
                ),
            },
            "systems": rows,
            "thresholds": THRESHOLDS,
            "violations": violations,
        }
        out_path.write_text(
            yaml.dump(report, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        try:
            display = out_path.relative_to(REPO_ROOT)
        except ValueError:
            display = out_path
        print(f"Report written to {display}")

    if args.ci and violations:
        sys.exit(1)


if __name__ == "__main__":
    main()
