#!/usr/bin/env python3
"""
portfolio_drift.py — compare two fidelity-report.yaml snapshots and emit a
Markdown diff report showing added/removed/changed systems and control counts.

Usage:
    # Compare HEAD^ vs HEAD (default):
    python3 scripts/catalog/portfolio_drift.py

    # Compare specific git refs:
    python3 scripts/catalog/portfolio_drift.py --from bdd85d6 --to HEAD

    # Compare two files on disk:
    python3 scripts/catalog/portfolio_drift.py --from-file old.yaml --to-file new.yaml

    # Write report to file:
    python3 scripts/catalog/portfolio_drift.py --out build/drift-report.md
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_REPORT = REPO_ROOT / "build" / "fidelity-report.yaml"
REPORT_GIT_PATH = "build/fidelity-report.yaml"
INHERITANCE_GIT_PATH = "catalog/inheritance.yaml"


def _git_show(ref: str, git_path: str = REPORT_GIT_PATH) -> str:
    result = subprocess.run(
        ["git", "show", f"{ref}:{git_path}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(f"git show {ref}:{git_path} failed:\n{result.stderr}")
    return result.stdout


def _load_from_git(ref: str) -> dict:
    return yaml.safe_load(_git_show(ref))


def _load_inheritance_from_git(ref: str) -> dict | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{INHERITANCE_GIT_PATH}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return yaml.safe_load(result.stdout) or {}


def _load_from_file(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _systems_map(report: dict) -> dict[str, dict]:
    return {row["system"]: row for row in report.get("systems", [])}


def _coverage_map(report: dict) -> dict:
    return report.get("import_coverage", {})


def _dependency_counts(inh: dict | None) -> Counter[tuple[str, str]]:
    counts: Counter[tuple[str, str]] = Counter()
    if not inh:
        return counts
    entries = (inh.get("inheritance") or inh).get("entries") or []
    for entry in entries:
        consumer = str(entry.get("consumer") or "").strip()
        provider = str(entry.get("provider") or "").strip()
        if consumer and provider:
            counts[(consumer, provider)] += 1
    return counts


def _pct(v) -> str:
    return f"{v}%" if v is not None else "n/a"


def render_report(
    old: dict,
    new: dict,
    from_label: str,
    to_label: str,
    old_inheritance: dict | None = None,
    new_inheritance: dict | None = None,
) -> str:
    old_sys = _systems_map(old)
    new_sys = _systems_map(new)

    added = sorted(set(new_sys) - set(old_sys))
    removed = sorted(set(old_sys) - set(new_sys))
    common = sorted(set(old_sys) & set(new_sys))

    old_cov = _coverage_map(old)
    new_cov = _coverage_map(new)

    lines: list[str] = []
    lines.append("# Portfolio Drift Report")
    lines.append("")
    lines.append(f"**From:** `{from_label}` ({old.get('generated_date', '?')})")
    lines.append(f"**To:** `{to_label}` ({new.get('generated_date', '?')})")
    lines.append("")

    # Portfolio-level summary
    lines.append("## Portfolio summary")
    lines.append("")
    lines.append("| Metric | Before | After | Δ |")
    lines.append("|--------|--------|-------|---|")

    def delta(k: str) -> str:
        a, b = old_cov.get(k), new_cov.get(k)
        if a is None or b is None:
            return "—"
        diff = b - a
        return f"+{diff}" if diff > 0 else str(diff)

    for label, key in [
        ("Systems", "total_systems"),
        ("Controls", "total_controls"),
        ("ctrl_id %", "ctrl_id_pct"),
        ("evidence_link %", "evidence_link_pct"),
        ("prose %", "prose_pct"),
    ]:
        a = old_cov.get(key, "—")
        b = new_cov.get(key, "—")
        d = delta(key)
        suffix = "%" if "pct" in key else ""
        a_str = f"{a}{suffix}" if a != "—" else "—"
        b_str = f"{b}{suffix}" if b != "—" else "—"
        lines.append(f"| {label} | {a_str} | {b_str} | {d} |")

    lines.append("")

    # Added systems
    if added:
        lines.append(f"## Added systems ({len(added)})")
        lines.append("")
        for s in added:
            r = new_sys[s]
            lines.append(
                f"- **{s}**: {r['controls']} controls, "
                f"NIST={_pct(r.get('nist_pct'))}, "
                f"evidence={_pct(r.get('evidence_link_pct'))}"
            )
        lines.append("")

    # Removed systems
    if removed:
        lines.append(f"## Removed systems ({len(removed)})")
        lines.append("")
        for s in removed:
            r = old_sys[s]
            lines.append(f"- **{s}**: was {r['controls']} controls")
        lines.append("")

    # Changed systems
    TRACKED = [
        "controls",
        "nist_pct",
        "prose_pct",
        "evidence_link_pct",
        "inherited_pct",
        "threats",
        "scenarios",
    ]
    changes: list[tuple[str, list[str]]] = []
    for s in common:
        o, n = old_sys[s], new_sys[s]
        diffs = []
        for k in TRACKED:
            ov, nv = o.get(k), n.get(k)
            if ov != nv:
                suffix = "%" if "pct" in k else ""
                diffs.append(f"`{k}`: {ov}{suffix} → {nv}{suffix}")
        if diffs:
            changes.append((s, diffs))

    if changes:
        lines.append(f"## Changed systems ({len(changes)})")
        lines.append("")
        for s, diffs in changes:
            lines.append(f"- **{s}**: " + ", ".join(diffs))
        lines.append("")

    dep_lines: list[str] = []
    if old_inheritance is not None or new_inheritance is not None:
        old_deps = _dependency_counts(old_inheritance)
        new_deps = _dependency_counts(new_inheritance)
        for pair in sorted(set(old_deps) | set(new_deps)):
            before_c = old_deps.get(pair, 0)
            after_c = new_deps.get(pair, 0)
            if before_c == after_c:
                continue
            consumer, provider = pair
            if before_c == 0:
                dep_lines.append(
                    f"- **+ {consumer} → {provider}** ({after_c} inherited control(s))"
                )
            elif after_c == 0:
                dep_lines.append(
                    f"- **- {consumer} → {provider}** (was {before_c} inherited control(s))"
                )
            else:
                dep_lines.append(
                    f"- **~ {consumer} → {provider}**: {before_c} → {after_c} inherited control(s)"
                )

    if dep_lines:
        lines.append(f"## Provider dependency changes ({len(dep_lines)})")
        lines.append("")
        lines.extend(dep_lines)
        lines.append("")

    if not added and not removed and not changes and not dep_lines:
        lines.append("*No changes detected between snapshots.*")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compare two fidelity-report.yaml snapshots"
    )
    source = ap.add_mutually_exclusive_group()
    source.add_argument(
        "--from",
        dest="from_ref",
        default=None,
        help="Git ref for 'before' snapshot (default: previous commit touching the file)",
    )
    ap.add_argument(
        "--to",
        dest="to_ref",
        default="HEAD",
        help="Git ref for 'after' snapshot (default: HEAD)",
    )
    source.add_argument("--from-file", help="'Before' snapshot from disk")
    ap.add_argument(
        "--to-file",
        help="'After' snapshot from disk (default: current build/fidelity-report.yaml)",
    )
    ap.add_argument(
        "--from-inheritance",
        help="'Before' catalog/inheritance.yaml snapshot from disk",
    )
    ap.add_argument(
        "--to-inheritance",
        help="'After' catalog/inheritance.yaml snapshot from disk",
    )
    ap.add_argument(
        "--out", help="Write Markdown report to this path (default: stdout)"
    )
    args = ap.parse_args()

    # Load "after"
    if args.to_file:
        new = _load_from_file(args.to_file)
        to_label = args.to_file
        new_inh = _load_from_file(args.to_inheritance) if args.to_inheritance else None
    else:
        new = _load_from_git(args.to_ref)
        to_label = args.to_ref
        new_inh = (
            _load_from_file(args.to_inheritance)
            if args.to_inheritance
            else _load_inheritance_from_git(args.to_ref)
        )

    # Load "before"
    if args.from_file:
        old = _load_from_file(args.from_file)
        from_label = args.from_file
        old_inh = (
            _load_from_file(args.from_inheritance) if args.from_inheritance else None
        )
    elif args.from_ref:
        old = _load_from_git(args.from_ref)
        from_label = args.from_ref
        old_inh = (
            _load_from_file(args.from_inheritance)
            if args.from_inheritance
            else _load_inheritance_from_git(args.from_ref)
        )
    else:
        # default: find the previous commit touching the report file
        result = subprocess.run(
            ["git", "log", "--oneline", "-2", "--", REPORT_GIT_PATH],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        commits = [line.split()[0] for line in result.stdout.strip().splitlines()]
        if len(commits) < 2:
            sys.exit(
                "Only one commit in fidelity-report.yaml history; use --from to specify a ref."
            )
        from_label = commits[1]
        old = _load_from_git(commits[1])
        old_inh = (
            _load_from_file(args.from_inheritance)
            if args.from_inheritance
            else _load_inheritance_from_git(commits[1])
        )

    report = render_report(old, new, from_label, to_label, old_inh, new_inh)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Wrote {args.out}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
