#!/usr/bin/env python3
"""Build a portfolio-level catalog/index.yaml from build/systems/* outputs
and vault Systems/*.md metadata (ADR-SSPP-004 Layer 3, B1).

Reads:
  - build/systems/index.yaml         (from vault_to_precogly.py --all)
  - build/systems/skipped.yaml       (optional)
  - build/systems/<slug>/pack/joins/inheritance.yaml
  - build/systems/<slug>/<slug>.cdx.json (for asset/threat/control counts)
  - <vault>/examples/vault/<slug>/Systems/*.md (frontmatter for owner, FIPS)

Writes:
  - catalog/index.yaml
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from datetime import UTC, datetime

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_SYSTEMS = os.path.join(ROOT, "build", "systems")
DEFAULT_VAULT = os.path.abspath(os.path.join(ROOT, "..", "oscal-vault"))
DEFAULT_OUT = os.path.join(ROOT, "catalog", "index.yaml")


def load_yaml(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def split_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    try:
        data = yaml.safe_load(text[3:end]) or {}
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _wiki_target(value) -> str | None:
    if not value:
        return None
    m = re.search(r"\[\[[^\]|]*?/([^\]|/]+)(?:\|[^\]]+)?\]\]", str(value))
    if m:
        return m.group(1)
    m = re.search(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", str(value))
    return m.group(1) if m else str(value)


def harvest_system_metadata(vault_root: str, slug: str) -> dict:
    sys_dir = os.path.join(vault_root, "examples", "vault", slug, "Systems")
    if not os.path.isdir(sys_dir):
        return {}
    for name in sorted(os.listdir(sys_dir)):
        if not name.endswith(".md"):
            continue
        with open(os.path.join(sys_dir, name), encoding="utf-8") as f:
            fm = split_frontmatter(f.read())
        if fm.get("note_type") == "system":
            return {
                "name": fm.get("name"),
                "acronym": fm.get("acronym"),
                "status": fm.get("status"),
                "owner": fm.get("owner"),
                "system_id": fm.get("system_id"),
                "fips_199": fm.get("fips_199"),
                "impact_level": fm.get("impact_level"),
                "organization": _wiki_target(fm.get("organization")),
                "last_updated": str(fm.get("last_updated") or ""),
                "tags": list(fm.get("tags") or []),
            }
    return {}


def summarize_cdx(cdx_path: str) -> dict:
    if not os.path.isfile(cdx_path):
        return {}
    with open(cdx_path, encoding="utf-8") as f:
        d = json.load(f)
    bp = (d.get("blueprints") or [{}])[0]
    return {
        "assets": len(bp.get("assets", [])),
        "flows": len(bp.get("flows", [])),
        "zones": len(bp.get("zones", [])),
        "threats": len(d.get("threats", {}).get("threats", [])),
        "scenarios": len(d.get("threats", {}).get("scenarios", [])),
        "controls": len(d.get("controls", [])),
    }


def inheritance_edges(system_dir: str) -> list[dict]:
    inh = load_yaml(os.path.join(system_dir, "pack", "joins", "inheritance.yaml"))
    edges: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for entry in inh.get("entries", []):
        provider = entry.get("provider_system")
        mode = entry.get("mode")
        if not provider:
            continue
        key = (provider, mode or "")
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            {
                "type": "depends_on",
                "target": provider,
                "mode": mode,
            }
        )
    return edges


def build_catalog(systems_root: str, vault_root: str) -> dict:
    idx = load_yaml(os.path.join(systems_root, "index.yaml"))
    skipped = load_yaml(os.path.join(systems_root, "skipped.yaml"))
    systems_out: list[dict] = []

    listed_slugs = {entry["system"] for entry in idx.get("systems", [])}
    for name in sorted(os.listdir(systems_root)):
        system_dir = os.path.join(systems_root, name)
        if not os.path.isdir(system_dir):
            continue
        if name in listed_slugs:
            continue
        summary = load_yaml(os.path.join(system_dir, "import-summary.yaml"))
        stats = summary.get("stats") or {}
        idx.setdefault("systems", []).append(
            {
                "system": name,
                "controls_parsed": stats.get("controls")
                or stats.get("countermeasures"),
                "threats": stats.get("threats"),
                "countermeasures": stats.get("controls")
                or stats.get("countermeasures"),
                "inheritance_entries": 0,
            }
        )

    for entry in idx.get("systems", []):
        slug = entry["system"]
        system_dir = os.path.join(systems_root, slug)
        cdx_files = glob.glob(os.path.join(system_dir, "*.cdx.json"))
        cdx_stats = summarize_cdx(cdx_files[0]) if cdx_files else {}
        meta = harvest_system_metadata(vault_root, slug)
        edges = inheritance_edges(system_dir)

        systems_out.append(
            {
                "slug": slug,
                "name": meta.get("name") or slug.replace("-", " ").title(),
                "acronym": meta.get("acronym"),
                "status": meta.get("status"),
                "owner": meta.get("owner"),
                "system_id": meta.get("system_id"),
                "fips_199": meta.get("fips_199"),
                "impact_level": meta.get("impact_level"),
                "organization": meta.get("organization"),
                "last_updated": meta.get("last_updated"),
                "tags": meta.get("tags") or [],
                "artifacts": {
                    "cdx": os.path.relpath(cdx_files[0], ROOT) if cdx_files else None,
                    "pack": os.path.relpath(os.path.join(system_dir, "pack"), ROOT),
                    "summary": os.path.relpath(
                        os.path.join(system_dir, "import-summary.yaml"), ROOT
                    ),
                },
                "stats": {
                    "controls_parsed": entry.get("controls_parsed"),
                    "threats": cdx_stats.get("threats", entry.get("threats")),
                    "countermeasures": entry.get("countermeasures"),
                    "scenarios": cdx_stats.get("scenarios"),
                    "assets": cdx_stats.get("assets"),
                    "flows": cdx_stats.get("flows"),
                    "zones": cdx_stats.get("zones"),
                    "inheritance_entries": entry.get("inheritance_entries"),
                },
                "compliance_frameworks": ["nist-800-53-r5"],
                "relationships": edges,
            }
        )

    return {
        "catalog": {
            "version": "1.0",
            "generated_by": "scripts/catalog/build_catalog_index.py",
            "generated_at": datetime.now(UTC).isoformat(),
            "vault_root": idx.get("vault_root"),
            "systems": systems_out,
            "skipped": skipped.get("skipped", []),
        }
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--systems-root", default=DEFAULT_SYSTEMS)
    ap.add_argument("--vault-root", default=DEFAULT_VAULT)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    if not os.path.isdir(args.systems_root):
        print(f"FAIL: systems root missing: {args.systems_root}", file=sys.stderr)
        return 2

    catalog = build_catalog(args.systems_root, args.vault_root)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        yaml.safe_dump(catalog, f, sort_keys=False, allow_unicode=True, width=100)
    print(
        f"Wrote {os.path.relpath(args.out, ROOT)} "
        f"({len(catalog['catalog']['systems'])} systems, "
        f"{len(catalog['catalog']['skipped'])} skipped)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
