#!/usr/bin/env python3
"""Render a human-readable catalog page from catalog/index.yaml
(ADR-SSPP-004 Layer 3, B3). Writes docs/catalog/index.md.
"""

from __future__ import annotations

import argparse
import os
import sys

import yaml


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_CATALOG = os.path.join(ROOT, "catalog", "index.yaml")
DEFAULT_OUT = os.path.join(ROOT, "docs", "catalog", "index.md")


HEADER = """---
title: "System Catalog"
description: "Portfolio-level index of vault-projected GSA/TTS systems"
status: "generated"
tier: 1
generated_by: "scripts/catalog/render_catalog.py"
---

# System Catalog

Auto-generated from `catalog/index.yaml`. Do not edit by hand; rerun
`make catalog-page` after updating vault inputs.
"""


def _fmt(value) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def render(catalog: dict) -> str:
    systems = catalog["catalog"]["systems"]
    skipped = catalog["catalog"].get("skipped", [])
    lines: list[str] = [HEADER, ""]
    lines.append(f"- **Systems imported:** {len(systems)}")
    lines.append(f"- **Systems skipped:** {len(skipped)}")
    lines.append(f"- **Generated at:** {catalog['catalog'].get('generated_at', '-')}")
    lines.append("")
    lines.append("## Systems")
    lines.append("")
    lines.append("| Slug | Name | FIPS-199 | Status | Threats | Controls | Inheritance | Artifacts |")
    lines.append("|---|---|---|---|---:|---:|---:|---|")

    for s in sorted(systems, key=lambda e: e["slug"]):
        stats = s.get("stats") or {}
        art = s.get("artifacts") or {}
        cdx = art.get("cdx")
        pack = art.get("pack")
        art_cell_parts: list[str] = []
        if cdx:
            art_cell_parts.append(f"[cdx]({cdx})")
        if pack:
            art_cell_parts.append(f"[pack]({pack})")
        art_cell = " / ".join(art_cell_parts) or "-"
        lines.append("| {slug} | {name} | {fips} | {status} | {threats} | {controls} | {inh} | {art} |".format(
            slug=s["slug"],
            name=_fmt(s.get("name")),
            fips=_fmt(s.get("fips_199")),
            status=_fmt(s.get("status")),
            threats=_fmt(stats.get("threats")),
            controls=_fmt(stats.get("countermeasures")),
            inh=_fmt(stats.get("inheritance_entries")),
            art=art_cell,
        ))

    lines.append("")
    if skipped:
        lines.append("## Skipped")
        lines.append("")
        lines.append("| Slug | Reason | Vault path |")
        lines.append("|---|---|---|")
        for entry in skipped:
            lines.append("| {s} | {r} | `{p}` |".format(
                s=entry.get("system", "-"),
                r=entry.get("reason", "-"),
                p=entry.get("vault_path", "-"),
            ))
        lines.append("")

    lines.append("## Cross-system inheritance")
    lines.append("")
    lines.append("| Consumer | Provider (as declared) | Mode |")
    lines.append("|---|---|---|")
    for s in sorted(systems, key=lambda e: e["slug"]):
        for rel in s.get("relationships", []) or []:
            if rel.get("type") != "depends_on":
                continue
            lines.append("| {c} | {p} | {m} |".format(
                c=s["slug"], p=_fmt(rel.get("target")), m=_fmt(rel.get("mode"))
            ))
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--catalog", default=DEFAULT_CATALOG)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    if not os.path.isfile(args.catalog):
        print(f"FAIL: catalog not found: {args.catalog}", file=sys.stderr)
        return 2

    with open(args.catalog, encoding="utf-8") as f:
        catalog = yaml.safe_load(f) or {}

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render(catalog))
        f.write("\n")
    print(f"Wrote {os.path.relpath(args.out, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
