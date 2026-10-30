#!/usr/bin/env python3
"""Build a portfolio-level catalog/index.yaml from build/systems/* outputs
and vault Systems/*.md metadata (ADR-SSPP-004 Layer 3, B1).

Reads:
  - build/systems/index.yaml         (from vault_to_precogly.py --all)
  - build/systems/skipped.yaml       (optional)
  - build/systems/<slug>/pack/joins/inheritance.yaml
  - build/systems/<slug>/<slug>.cdx.json (for asset/threat/control counts)
  - <vault>/examples/vault/<slug>/Systems/*.md (frontmatter for owner, FIPS)
  - data/catalog/ownership.yaml      (fallback/override for owner, isso, ao, source_doc)

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
_private_vault = os.path.abspath(os.path.join(ROOT, "..", "oscal-vault"))
_vendor_vault = os.path.join(ROOT, "vendor", "oscal-vault")
DEFAULT_VAULT = _private_vault if os.path.isdir(_private_vault) else _vendor_vault
DEFAULT_OUT = os.path.join(ROOT, "catalog", "index.yaml")
DEFAULT_INH_OUT = os.path.join(ROOT, "catalog", "inheritance.yaml")
OWNERSHIP_SIDECAR = os.path.join(ROOT, "data", "catalog", "ownership.yaml")
_BUILD_SYSTEMS_MARKER = f"{os.sep}build{os.sep}systems{os.sep}"


def _artifact_ref(path: str) -> str:
    """Return a stable repository-relative build artifact reference.

    Catalog generation may read build artifacts from another checkout or a
    temporary worktree. ``os.path.relpath(path, ROOT)`` would serialize that
    machine-specific absolute path as a long ``../../..`` traversal. Every
    catalog artifact belongs under ``build/systems/``; retain that stable suffix
    instead of the invocation-specific filesystem prefix.
    """
    normalized = os.path.abspath(path)
    marker_at = normalized.find(_BUILD_SYSTEMS_MARKER)
    if marker_at >= 0:
        return normalized[marker_at + 1 :].replace(os.sep, "/")
    return os.path.relpath(normalized, ROOT).replace(os.sep, "/")


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
            owner_raw = fm.get("owner")
            isso_raw = fm.get("isso")
            return {
                "name": fm.get("name"),
                "acronym": fm.get("acronym"),
                "status": fm.get("status"),
                "owner": _wiki_target(owner_raw) if owner_raw else None,
                "isso": _wiki_target(isso_raw) if isso_raw else None,
                "system_id": fm.get("system_id"),
                "data_sensitivity": fm.get("fips_199") or fm.get("impact_level"),
                "impact_level": fm.get("impact_level"),
                "organization": _wiki_target(fm.get("organization")),
                # This is the source system record's review date, not the date
                # this repository projected artifacts from that record.
                "source_last_updated": str(fm.get("last_updated") or ""),
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
    consumer = inh.get("consumer_system", "")
    edges: list[dict] = []
    for entry in inh.get("entries", []):
        provider = entry.get("provider_system")
        if not provider:
            continue
        edges.append(
            {
                "consumer": consumer,
                "provider": provider,
                "provider_owner": entry.get("provider_owner"),
                "control_id": entry["control_id"],
                "mode": entry.get("mode"),
                "direction": entry.get("direction"),
            }
        )
    return edges


def _relationships(edges: list[dict]) -> list[dict]:
    """Deduplicated depends_on tuples for the catalog relationships field."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for e in edges:
        key = (e["provider"], e.get("mode") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {"type": "depends_on", "target": e["provider"], "mode": e.get("mode")}
        )
    return out


def build_catalog(systems_root: str, vault_root: str) -> dict:
    idx = load_yaml(os.path.join(systems_root, "index.yaml"))
    skipped = load_yaml(os.path.join(systems_root, "skipped.yaml"))
    ownership_overrides: dict[str, dict] = (
        load_yaml(OWNERSHIP_SIDECAR).get("systems") or {}
    )
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
        # ownership.yaml provides fallback/override for fields vault leaves null
        own = ownership_overrides.get(slug) or {}

        systems_out.append(
            {
                "slug": slug,
                "name": meta.get("name") or slug.replace("-", " ").title(),
                "acronym": meta.get("acronym"),
                "status": meta.get("status"),
                "owner": meta.get("owner") or own.get("owner"),
                "isso": meta.get("isso") or own.get("isso"),
                "ao": own.get("ao"),
                "system_id": meta.get("system_id"),
                "data_sensitivity": (
                    meta.get("fips_199")
                    or meta.get("fips_level")
                    or meta.get("data_sensitivity")
                    or own.get("data_sensitivity")
                ),
                "impact_level": meta.get("impact_level") or own.get("impact_level"),
                "organization": meta.get("organization"),
                # Keep the upstream review date distinct from catalog
                # regeneration time so consumers do not treat a fresh build as
                # stale source material.
                "source_last_updated": meta.get("source_last_updated"),
                "tags": meta.get("tags") or [],
                "source_doc": own.get("source_doc"),
                "artifacts": {
                    "cdx": _artifact_ref(cdx_files[0]) if cdx_files else None,
                    "pack": _artifact_ref(os.path.join(system_dir, "pack")),
                    "summary": _artifact_ref(
                        os.path.join(system_dir, "import-summary.yaml")
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
                "relationships": _relationships(edges),
                "inheritance": edges,
            }
        )

    return {
        "catalog": {
            "version": "1.0",
            "generated_by": "scripts/catalog/build_catalog_index.py",
            "catalog_generated_at": datetime.now(UTC).isoformat(),
            # Stable submodule path; never serialize an absolute checkout path
            # or a worktree-relative traversal into a committed catalog.
            "vault_root": "vendor/oscal-vault",
            "systems": systems_out,
            "skipped": skipped.get("skipped", []),
        }
    }


def build_inheritance_index(systems_out: list[dict]) -> dict:
    """Flatten all per-system inheritance edges into a portfolio-level index."""
    all_edges: list[dict] = []
    for s in systems_out:
        all_edges.extend(s.get("inheritance", []))
    return {
        "inheritance": {
            "generated_by": "scripts/catalog/build_catalog_index.py",
            "description": "Queryable consumer/provider/mode tuples across all vault systems",
            "entries": all_edges,
        }
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--systems-root", default=DEFAULT_SYSTEMS)
    ap.add_argument("--vault-root", default=DEFAULT_VAULT)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--inheritance-out", default=DEFAULT_INH_OUT)
    args = ap.parse_args()

    if not os.path.isdir(args.systems_root):
        print(f"FAIL: systems root missing: {args.systems_root}", file=sys.stderr)
        return 2

    catalog = build_catalog(args.systems_root, args.vault_root)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        yaml.safe_dump(catalog, f, sort_keys=False, allow_unicode=True, width=100)

    inh_index = build_inheritance_index(catalog["catalog"]["systems"])
    with open(args.inheritance_out, "w", encoding="utf-8") as f:
        yaml.safe_dump(inh_index, f, sort_keys=False, allow_unicode=True, width=100)

    import shutil
    import subprocess

    dprint_cmd = shutil.which("dprint")
    if dprint_cmd:
        subprocess.run(
            [dprint_cmd, "fmt", args.out, args.inheritance_out], capture_output=True
        )
    elif shutil.which("mise"):
        subprocess.run(
            ["mise", "x", "--", "dprint", "fmt", args.out, args.inheritance_out],
            capture_output=True,
        )

    total_edges = len(inh_index["inheritance"]["entries"])
    print(
        f"Wrote {os.path.relpath(args.out, ROOT)} "
        f"({len(catalog['catalog']['systems'])} systems, "
        f"{len(catalog['catalog']['skipped'])} skipped)"
    )
    print(
        f"Wrote {os.path.relpath(args.inheritance_out, ROOT)} "
        f"({total_edges} inheritance entries)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
