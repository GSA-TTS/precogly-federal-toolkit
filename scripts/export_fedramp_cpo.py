#!/usr/bin/env python3
"""Export a FedRAMP CR26 Certification Package Overview (FRC-CSO-PKG) for one
system. Requires a `data/systems/<slug>.yaml` sidecar because every required
CPO field is hand-authored — no CDX / catalog source exists for them today.

Usage:
    uv run python scripts/export_fedramp_cpo.py --system example-system
    uv run python scripts/export_fedramp_cpo.py --all
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML not installed — run via `uv run`")

REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEMS_DIR = REPO_ROOT / "data" / "systems"
BUILD_SYSTEMS = REPO_ROOT / "build" / "systems"
CATALOG_INDEX = REPO_ROOT / "catalog" / "index.yaml"


def load_catalog() -> dict[str, dict]:
    with CATALOG_INDEX.open() as fh:
        data = yaml.safe_load(fh)
    return {s["slug"]: s for s in data["catalog"]["systems"]}


def load_sidecar(slug: str) -> dict:
    path = SYSTEMS_DIR / f"{slug}.yaml"
    if not path.exists():
        raise SystemExit(
            f"cpo: no sidecar at {path.relative_to(REPO_ROOT)} — see data/systems/README.md"
        )
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def build_cpo(slug: str, catalog_entry: dict, sidecar: dict) -> dict:
    cpo = sidecar.get("cpo") or {}
    contacts = sidecar.get("contacts") or []
    missing = [k for k in (
        "provider_name", "service_name", "service_acronym", "service_description",
        "certification_type", "fed_ramp_package_id", "website", "logo",
        "service_type", "deployment_model",
    ) if not cpo.get(k)]
    if missing:
        raise SystemExit(f"cpo({slug}): sidecar missing required cpo.* fields: {missing}")

    types = {c.get("contactType") for c in contacts}
    for required_type in ("Security", "Sales"):
        if required_type not in types:
            raise SystemExit(
                f"cpo({slug}): sidecar contacts[] must contain at least one '{required_type}' entry"
            )

    doc = {
        "serviceIdentification": {
            "providerName": cpo["provider_name"],
            "serviceName": cpo["service_name"],
            "serviceAcronym": cpo["service_acronym"],
            "serviceDescription": cpo["service_description"].rstrip(),
            "certificationType": cpo["certification_type"],
            "fedRampPackageId": cpo["fed_ramp_package_id"],
            "website": cpo["website"],
            "logo": cpo["logo"],
        },
        "serviceProperties": {
            "serviceType": list(cpo["service_type"]),
            "deploymentModel": cpo["deployment_model"],
        },
        "contactInformation": [
            {k: v for k, v in c.items() if v is not None} for c in contacts
        ],
    }
    if cpo.get("business_category"):
        doc["serviceProperties"]["businessCategory"] = list(cpo["business_category"])
    if cpo.get("uei_number"):
        doc["serviceIdentification"]["ueiNumber"] = cpo["uei_number"]
    return doc


def export_one(slug: str, catalog: dict[str, dict]) -> Path:
    if slug not in catalog:
        raise SystemExit(f"cpo({slug}): slug not present in catalog/index.yaml")
    sidecar = load_sidecar(slug)
    if sidecar.get("system") not in (None, slug):
        raise SystemExit(f"cpo({slug}): sidecar 'system' key mismatch: {sidecar.get('system')!r}")
    doc = build_cpo(slug, catalog[slug], sidecar)
    out_dir = BUILD_SYSTEMS / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "fedramp-cpo.json"
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    return out_path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--system", help="single system slug (e.g. example-system)")
    group.add_argument("--all", action="store_true", help="export every system with a sidecar")
    args = p.parse_args()

    catalog = load_catalog()
    if args.system:
        out = export_one(args.system, catalog)
        print(f"wrote {out.relative_to(REPO_ROOT)}")
        return 0
    exported = 0
    for slug in sorted(catalog.keys()):
        try:
            out = export_one(slug, catalog)
        except SystemExit as e:
            print(f"skip {slug}: {e}", file=sys.stderr)
            continue
        print(f"wrote {out.relative_to(REPO_ROOT)}")
        exported += 1
    if exported == 0:
        print("no CPOs exported", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
