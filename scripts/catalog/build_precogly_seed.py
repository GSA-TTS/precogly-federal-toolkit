#!/usr/bin/env python3
"""Emit a portable Precogly seed manifest from catalog/index.yaml
(ADR-SSPP-004 M4, D1).

Output: build/precogly-seed.yaml with three top-level lists:
  - orgsystems:          one row per catalog system
  - threat_models:       one row per catalog system, linked to library packs
  - relationships:       depends_on / subsystem_of edges

Downstream (D2) tooling loads this into a running Precogly via
`python manage.py seed --catalog build/precogly-seed.yaml`
(the management command is out of scope here; the manifest is the interface).
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_CATALOG = os.path.join(ROOT, "catalog", "index.yaml")
DEFAULT_OUT = os.path.join(ROOT, "build", "precogly-seed.yaml")

SHARED_PACKS = [
    "libraries/packs/standards/nist-800-53-r5",
    "libraries/packs/threat-libraries/gsa-crm",
]


def _criticality(fips: str | None) -> str:
    mapping = {"low": "low", "moderate": "medium", "high": "high"}
    return mapping.get((fips or "").lower(), "medium")


def _resolve_target_slug(
    target: str, source_slug: str, known_slugs: set[str] | list[str]
) -> str | None:
    """Resolve a relationship target to a catalog system slug deterministically.

    Prefers an exact slug match, never resolves a system to itself, requires at
    least 4 characters before attempting substring matching (so short agency
    acronyms like ``GSA`` or ``OMA`` stay external unless they match a slug
    exactly), and orders primary system slugs ahead of ``-hosting-`` /
    ``-composite-`` variants.
    """
    simplified = target.lower().replace(".", "-").replace(" ", "-")
    ordered = sorted(
        known_slugs,
        key=lambda s: ("-hosting-" in s or "-composite-" in s, s),
    )
    if simplified in known_slugs and simplified != source_slug:
        return simplified
    if len(simplified) < 4:
        return None
    for candidate in ordered:
        if candidate == source_slug:
            continue
        if simplified in candidate or candidate in simplified:
            return candidate
    return None


def build_manifest(catalog: dict) -> dict:
    systems = catalog["catalog"]["systems"]
    known_slugs = {s["slug"] for s in systems}

    orgsystems: list[dict] = []
    threat_models: list[dict] = []
    relationships: list[dict] = []

    for entry in systems:
        slug = entry["slug"]
        orgsystems.append(
            {
                "slug": slug,
                "name": entry.get("name") or slug,
                "acronym": entry.get("acronym"),
                "criticality": _criticality(
                    entry.get("data_sensitivity") or entry.get("fips_199")
                ),
                "lifecycle_state": entry.get("status") or "unknown",
                "organization": entry.get("organization") or "gsa",
                "system_id": entry.get("system_id"),
                "tags": entry.get("tags") or [],
            }
        )

        artifacts = entry.get("artifacts") or {}
        threat_models.append(
            {
                "slug": f"{slug}-tm",
                "name": f"{entry.get('name') or slug} - Threat Model",
                "orgsystems": [slug],
                "library_packs": [f"packs/{slug}-crm"] + SHARED_PACKS,
                "compliance_frameworks": entry.get("compliance_frameworks", []),
                "artifacts": {
                    "cdx": artifacts.get("cdx"),
                    "pack": artifacts.get("pack"),
                },
            }
        )

        for rel in entry.get("relationships", []) or []:
            target = rel.get("target")
            if not target:
                continue
            slug_target = _resolve_target_slug(target, slug, known_slugs)
            relationships.append(
                {
                    "type": rel.get("type", "depends_on"),
                    "source": slug,
                    "target": slug_target or f"external:{target}",
                    "mode": rel.get("mode"),
                    "resolved": bool(slug_target),
                }
            )

    return {
        "manifest_version": 1,
        "generated_by": "scripts/catalog/build_precogly_seed.py",
        "generated_at": datetime.now(UTC).isoformat(),
        "shared_library_packs": SHARED_PACKS,
        "orgsystems": orgsystems,
        "threat_models": threat_models,
        "relationships": relationships,
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

    manifest = build_manifest(catalog)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        yaml.safe_dump(manifest, f, sort_keys=False, allow_unicode=True, width=100)

    unresolved = [r for r in manifest["relationships"] if not r["resolved"]]
    print(
        f"Wrote {os.path.relpath(args.out, ROOT)} "
        f"(orgsystems={len(manifest['orgsystems'])}, "
        f"threat_models={len(manifest['threat_models'])}, "
        f"relationships={len(manifest['relationships'])}, "
        f"unresolved-targets={len(unresolved)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
