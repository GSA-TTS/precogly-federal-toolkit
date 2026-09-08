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
title: 'System Catalog'
description: 'Portfolio-level index of vault-projected GSA/TTS systems'
status: 'generated'
tier: 1
generated_by: 'scripts/catalog/render_catalog.py'
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
    lines.append(
        "| Slug | Name | Sensitivity | Owner | ISSO | AO | Status | Threats | Controls | Inh. | Providers | Artifacts |"
    )
    lines.append("|---|---|---|---|---|---|---|---:|---:|---:|---|---|")

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
        # Count unique providers for this system
        edges = s.get("inheritance") or []
        unique_providers = sorted(
            {e.get("provider", "") for e in edges if e.get("provider")}
        )
        prov_cell = ", ".join(unique_providers) if unique_providers else "-"
        inh_count = len(edges)
        lines.append(
            "| {slug} | {name} | {fips} | {owner} | {isso} | {ao} | {status} | {threats} | {controls} | {inh} | {prov} | {art} |".format(
                slug=s["slug"],
                name=_fmt(s.get("name")),
                fips=_fmt(s.get("data_sensitivity")),
                owner=_fmt(s.get("owner")),
                isso=_fmt(s.get("isso")),
                ao=_fmt(s.get("ao")),
                status=_fmt(s.get("status")),
                threats=_fmt(stats.get("threats")),
                controls=_fmt(stats.get("countermeasures")),
                inh=inh_count if inh_count else "-",
                prov=prov_cell,
                art=art_cell,
            )
        )

    lines.append("")
    if skipped:
        lines.append("## Skipped")
        lines.append("")
        lines.append("| Slug | Class | Reason | Vault path |")
        lines.append("|---|---|---|---|")
        for entry in skipped:
            lines.append(
                "| {s} | {cls} | {r} | `{p}` |".format(
                    s=entry.get("system", "-"),
                    cls=_fmt(entry.get("skip_class")),
                    r=entry.get("reason", "-"),
                    p=entry.get("vault_path", "-"),
                )
            )
        lines.append("")

    lines.append("## Cross-system inheritance")
    lines.append("")
    # Build per-provider dependency counts from first-class inheritance tuples
    import collections

    provider_consumers: dict[str, set] = collections.defaultdict(set)
    provider_controls: dict[str, int] = collections.Counter()
    for s in systems:
        for e in s.get("inheritance", []) or []:
            prov = e.get("provider", "")
            provider_consumers[prov].add(s["slug"])
            provider_controls[prov] += 1

    lines.append("### Provider dependency summary")
    lines.append("")
    lines.append("| Provider | Consumer systems | Controls inherited |")
    lines.append("|---|---:|---:|")
    for prov, consumers in sorted(provider_consumers.items(), key=lambda x: -len(x[1])):
        lines.append(f"| {prov} | {len(consumers)} | {provider_controls[prov]} |")
    lines.append("")

    lines.append("### Per-system inheritance")
    lines.append("")
    lines.append("| Consumer | Provider | Mode | Controls |")
    lines.append("|---|---|---|---:|")
    for s in sorted(systems, key=lambda e: e["slug"]):
        by_provider: dict[tuple, int] = collections.Counter()
        for e in s.get("inheritance", []) or []:
            by_provider[(e.get("provider", ""), e.get("mode", ""))] += 1
        for (prov, mode), count in sorted(by_provider.items()):
            lines.append(f"| {s['slug']} | {prov} | {_fmt(mode)} | {count} |")
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

    import shutil
    import subprocess

    dprint_cmd = shutil.which("dprint")
    if dprint_cmd:
        subprocess.run([dprint_cmd, "fmt", args.out], capture_output=True)
    elif shutil.which("mise"):
        subprocess.run(
            ["mise", "x", "--", "dprint", "fmt", args.out], capture_output=True
        )

    print(f"Wrote {os.path.relpath(args.out, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
