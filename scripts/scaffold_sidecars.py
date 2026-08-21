#!/usr/bin/env python3
"""Scaffold `data/systems/<slug>.yaml` FedRAMP CPO/SDR sidecars for every system
in `catalog/index.yaml` that does not already have one.

Idempotent: never overwrites an existing sidecar. Emit values follow the
convention documented in `data/systems/README.md`:

- Real values are pulled from the catalog where they exist (service_name,
  service_acronym, provider_name when derivable).
- Fields with no upstream source get sentinel values (`TBD ...` strings,
  `https://tbd.example.gov/<slug>...` URLs). Sentinels are schema-valid so
  `make fedramp-validate` passes, but `--strict` mode rejects them.

Usage:
    uv run python scripts/scaffold_sidecars.py --all
    uv run python scripts/scaffold_sidecars.py --system challenge-gov-2022
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML not installed — run via `uv run`")

REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEMS_DIR = REPO_ROOT / "data" / "systems"
CATALOG_INDEX = REPO_ROOT / "catalog" / "index.yaml"

# vault_reader lives in scripts/catalog/; make it importable from here.
sys.path.insert(0, str(REPO_ROOT / "scripts" / "catalog"))
try:
    from vault_reader import OrgParty, parse_org_parties

    _VAULT_READER_AVAILABLE = True
except ImportError:
    _VAULT_READER_AVAILABLE = False

ORG_TO_PROVIDER = {
    "cloud-service-provider": "General Services Administration",
    "agency": "General Services Administration",
}


def load_catalog() -> dict[str, dict]:
    with CATALOG_INDEX.open() as fh:
        data = yaml.safe_load(fh)
    return {s["slug"]: s for s in data["catalog"]["systems"]}


def derive_acronym(entry: dict) -> str:
    if entry.get("acronym"):
        return str(entry["acronym"])
    slug = entry["slug"]
    tokens = [t for t in re.split(r"[^a-z0-9]", slug) if t and not t.isdigit()]
    initials = "".join(t[0] for t in tokens[:4]).upper()
    return initials or slug.upper()[:6]


def _contacts_from_vault(vault_system_dir: str, slug: str) -> list[dict]:
    """Return CPO contacts pre-populated from vault Organizations/*.md, falling back to TBD sentinels."""
    if not _VAULT_READER_AVAILABLE:
        parties: list[OrgParty] = []
    else:
        parties = parse_org_parties(vault_system_dir)

    seen_types: set[str] = set()
    contacts: list[dict] = []
    for p in parties:
        if p.contact_type in seen_types:
            continue
        seen_types.add(p.contact_type)
        contacts.append(
            {
                "contactType": p.contact_type,
                "contactName": p.name,
                "contactEmail": f"tbd-{p.contact_type.lower()}-{slug}@example.gov",
                "contactPhone": "555-555-5555",
            }
        )

    # Ensure both Security and Sales slots are always present
    for contact_type in ("Security", "Sales"):
        if contact_type not in seen_types:
            contacts.append(
                {
                    "contactType": contact_type,
                    "contactName": f"TBD {contact_type} Contact",
                    "contactEmail": f"tbd-{contact_type.lower()}-{slug}@example.gov",
                    "contactPhone": "555-555-5555",
                }
            )
    return contacts


def scaffold(entry: dict, vault_root: str | None = None) -> dict:
    slug = entry["slug"]
    name = entry.get("name") or slug
    provider = ORG_TO_PROVIDER.get(entry.get("organization") or "", "TBD provider name")
    acronym = derive_acronym(entry)
    vault_system_dir = (
        str(Path(vault_root) / "examples" / "vault" / slug) if vault_root else ""
    )
    contacts = _contacts_from_vault(vault_system_dir, slug)
    return {
        "system": slug,
        "cpo": {
            "provider_name": provider,
            "service_name": name,
            "service_acronym": acronym,
            "service_description": (
                f"TBD — replace with a 2-5 sentence description of {name} for FedRAMP CPO. "
                "Include service model, primary users, and hosting environment."
            ),
            "certification_type": "Rev5",
            "fed_ramp_package_id": f"TBD-{slug.upper()}",
            "website": f"https://tbd.example.gov/{slug}",
            "logo": f"https://tbd.example.gov/{slug}/logo.png",
            "service_type": ["PaaS"],
            "deployment_model": "Government Community Cloud",
            "business_category": [],
        },
        "contacts": contacts,
        "sdr": {
            "certification_package_overview_uri": f"https://tbd.example.gov/{slug}/cpo.json",
            "parameter_values": {},
        },
    }


def write_sidecar(
    slug: str, entry: dict, vault_root: str | None = None
) -> tuple[Path, bool]:
    SYSTEMS_DIR.mkdir(parents=True, exist_ok=True)
    path = SYSTEMS_DIR / f"{slug}.yaml"
    if path.exists():
        return path, False
    doc = scaffold(entry, vault_root=vault_root)
    payload = yaml.safe_dump(doc, sort_keys=False, width=100, default_flow_style=False)
    banner = (
        "# SCAFFOLDED SIDECAR — replace every `TBD ...` value and\n"
        "# `https://tbd.example.gov/...` URL before FedRAMP submission.\n"
        "# See data/systems/README.md for authoring guidance.\n"
    )
    path.write_text(banner + payload)
    return path, True


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--vault-root",
        default=None,
        help="path to oscal-vault checkout (to pre-populate contacts from Organizations/*.md)",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--system", help="single system slug")
    g.add_argument("--all", action="store_true", help="scaffold every missing sidecar")
    args = p.parse_args()

    catalog = load_catalog()
    if args.system:
        if args.system not in catalog:
            sys.exit(f"slug not in catalog: {args.system}")
        path, wrote = write_sidecar(
            args.system, catalog[args.system], vault_root=args.vault_root
        )
        print(f"{'wrote' if wrote else 'exists'}: {path.relative_to(REPO_ROOT)}")
        return 0

    wrote_count = 0
    exists_count = 0
    for slug in sorted(catalog.keys()):
        path, wrote = write_sidecar(slug, catalog[slug], vault_root=args.vault_root)
        if wrote:
            wrote_count += 1
            print(f"wrote  {path.relative_to(REPO_ROOT)}")
        else:
            exists_count += 1
    print(f"\nscaffolded={wrote_count} already_present={exists_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
