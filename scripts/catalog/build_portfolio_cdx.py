#!/usr/bin/env python3
"""Emit a portfolio-level CycloneDX BOM referencing every per-system CDX
(ADR-SSPP-004 Layer 3, B2).

Reads catalog/index.yaml. Writes build/catalog.cdx.json:
  * one top-level blueprint per system, referencing its per-system CDX via
    externalReferences[].url
  * dependencies[] mirroring inheritance edges (depends_on)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import UTC, datetime

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_CATALOG = os.path.join(ROOT, "catalog", "index.yaml")
DEFAULT_OUT = os.path.join(ROOT, "build", "catalog.cdx.json")


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s or "unknown"


def _target_slug(
    target: str, known_slugs: set[str], source_slug: str = ""
) -> str:
    """Map an inheritance provider name onto a system slug when possible."""
    candidate = slugify(target)
    if candidate in known_slugs and candidate != source_slug:
        return candidate
    if len(candidate) >= 4:
        ordered = sorted(
            known_slugs,
            key=lambda s: ("-hosting-" in s or "-composite-" in s, s),
        )
        for slug in ordered:
            if slug != source_slug and (candidate in slug or slug in candidate):
                return slug
    return f"external:{candidate}"


def build_portfolio_cdx(catalog: dict) -> dict:
    systems = catalog["catalog"]["systems"]
    known_slugs = {s["slug"] for s in systems}

    blueprints: list[dict] = []
    dependencies: list[dict] = []
    external_refs: list[dict] = []

    for entry in systems:
        slug = entry["slug"]
        bp_ref = f"system:{slug}"
        cdx_path = entry.get("artifacts", {}).get("cdx")
        stats = entry.get("stats") or {}
        properties = [
            {"name": "catalog:slug", "value": slug},
            {"name": "catalog:name", "value": entry.get("name") or slug},
            {
                "name": "vault:data-sensitivity",
                "value": entry.get("data_sensitivity")
                or entry.get("fips_199")
                or "unknown",
            },
            {"name": "vault:status", "value": entry.get("status") or "unknown"},
            {"name": "vault:organization", "value": entry.get("organization") or ""},
            {"name": "vault:system-id", "value": entry.get("system_id") or ""},
            {"name": "stats:threats", "value": str(stats.get("threats", 0))},
            {"name": "stats:controls", "value": str(stats.get("countermeasures", 0))},
            {
                "name": "stats:inheritance",
                "value": str(stats.get("inheritance_entries", 0)),
            },
        ]

        refs = []
        if cdx_path:
            refs.append(
                {"type": "other", "url": cdx_path, "comment": "per-system Precogly CDX"}
            )
            refs.append(
                {
                    "type": "other",
                    "url": entry["artifacts"]["pack"],
                    "comment": "per-system Precogly pack",
                }
            )

        blueprints.append(
            {
                "bom-ref": bp_ref,
                "name": entry.get("name") or slug,
                "modelTypes": ["system"],
                "properties": properties,
                "externalReferences": refs,
            }
        )

        deps_targets: list[str] = []
        for rel in entry.get("relationships", []):
            if rel.get("type") != "depends_on":
                continue
            target = rel.get("target")
            if not target:
                continue
            deps_targets.append(_target_slug(target, known_slugs, source_slug=slug))

        if deps_targets:
            dependencies.append(
                {
                    "ref": bp_ref,
                    "dependsOn": sorted(
                        {
                            f"system:{t}" if not t.startswith("external:") else t
                            for t in deps_targets
                        }
                    ),
                }
            )

    for entry in catalog["catalog"].get("skipped", []):
        external_refs.append(
            {
                "type": "issue-tracker",
                "url": entry.get("vault_path", ""),
                "comment": f"skipped: {entry.get('system')} ({entry.get('reason')})",
            }
        )

    return {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "properties": [
                {"name": "catalog:kind", "value": "system-of-systems"},
                {"name": "adr", "value": "ADR-SSPP-004"},
                {
                    "name": "catalog:vault-root",
                    "value": catalog["catalog"].get("vault_root") or "",
                },
                {"name": "catalog:system-count", "value": str(len(blueprints))},
                {
                    "name": "catalog:skipped-count",
                    "value": str(len(catalog["catalog"].get("skipped", []))),
                },
            ],
            "externalReferences": external_refs,
        },
        "blueprints": blueprints,
        "dependencies": dependencies,
    }


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
    bom = build_portfolio_cdx(catalog)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(
        f"Wrote {os.path.relpath(args.out, ROOT)} "
        f"({len(bom['blueprints'])} blueprints, "
        f"{len(bom['dependencies'])} dependency edges)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
