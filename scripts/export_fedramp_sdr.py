#!/usr/bin/env python3
"""Export a FedRAMP CR26 Security Decision Record (SDR-CSO-FRR) for one system.

Ingests the Precogly-native CycloneDX artifact at either
`build/example-system-crm-threat-model.cdx.json` (for `--system example-system`) or
`build/systems/<slug>/<slug>.cdx.json`, and emits a schema-valid SDR at
`build/systems/<slug>/fedramp-sdr.json`.

Scope (2026-08-13): only `securityControls[]` is populated from the CDX. FRRs,
KSIs, ODP `parameterValues[]` and `portsAndProtocols` remain empty and are
tracked in `docs/IMPLEMENTATION_PLAN_fedramp_cr26_schemas.md`.

Usage:
    uv run python scripts/export_fedramp_sdr.py --system example-system
    uv run python scripts/export_fedramp_sdr.py --all
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML not installed — run via `uv run`")

REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEMS_DIR = REPO_ROOT / "data" / "systems"
BUILD_SYSTEMS = REPO_ROOT / "build" / "systems"
CATALOG_INDEX = REPO_ROOT / "catalog" / "index.yaml"
Example System_CDX = REPO_ROOT / "build" / "example-system-crm-threat-model.cdx.json"

DEFAULT_CPO_URI_TEMPLATE = "https://fedramp.gov/schemas/tbd/{slug}/cpo.json"
STATUS_MAP = {
    "implemented": "Implemented",
    "verified": "Implemented",
    "recommended": "Not Implemented",
    "rejected": "Not Implemented",
}
NIST_CONTROL_ID_RE = re.compile(r"^[A-Z]{2}-\d+(\(\d+\))?$")


def load_catalog() -> dict[str, dict]:
    with CATALOG_INDEX.open() as fh:
        data = yaml.safe_load(fh)
    return {s["slug"]: s for s in data["catalog"]["systems"]}


def load_sidecar(slug: str) -> dict:
    path = SYSTEMS_DIR / f"{slug}.yaml"
    if not path.exists():
        return {}
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def cdx_path_for(slug: str, catalog_entry: dict) -> Path:
    if slug == "example-system" and Example System_CDX.exists():
        return Example System_CDX
    artifacts = catalog_entry.get("artifacts") or {}
    if "cdx" in artifacts:
        return REPO_ROOT / artifacts["cdx"]
    return BUILD_SYSTEMS / slug / f"{slug}.cdx.json"


def get_property(properties: list, name: str) -> str | None:
    for p in properties or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def canonical_control_id(properties: list) -> str | None:
    for key in ("nist:control-id", "crm:control-id"):
        val = get_property(properties, key)
        if val and NIST_CONTROL_ID_RE.match(val):
            return val
    return None


def collapse_status(statuses: set[str]) -> str:
    mapped = {STATUS_MAP.get(s, "Not Implemented") for s in statuses}
    if mapped == {"Implemented"}:
        return "Implemented"
    if mapped == {"Not Implemented"}:
        return "Not Implemented"
    return "Partially Implemented"


def _get_property(properties: list, name: str) -> str | None:
    for p in properties:
        if p.get("name") == name:
            return p.get("value")
    return None


def build_security_controls(cdx: dict, parameter_values: dict) -> list[dict]:
    by_control: dict[str, dict] = defaultdict(lambda: {
        "statuses": set(), "descriptions": [], "names": [],
        "cdx_params": {}, "origination": None, "providing_system": None,
    })
    for c in cdx.get("controls") or []:
        props = c.get("properties") or []
        cid = canonical_control_id(props)
        if not cid:
            continue
        entry = by_control[cid]
        entry["statuses"].add((c.get("status") or "recommended").lower())
        desc = (c.get("description") or "").strip()
        if desc and desc not in entry["descriptions"]:
            entry["descriptions"].append(desc)
        nm = (c.get("name") or "").strip()
        if nm and nm not in entry["names"]:
            entry["names"].append(nm)
        # N2: collect vault:param:* properties as CDX-derived parameter values
        for p in props:
            pname = p.get("name") or ""
            if pname.startswith("vault:param:"):
                param_id = pname[len("vault:param:"):]
                # sidecar takes precedence; only set if not already present
                entry["cdx_params"].setdefault(param_id, p.get("value") or "")
        # N3: capture origination and providing-system for description header
        orig = _get_property(props, "vault:origination")
        if orig and not entry["origination"]:
            entry["origination"] = orig
        prov = _get_property(props, "vault:providing-system")
        if prov and not entry["providing_system"]:
            entry["providing_system"] = prov

    out = []
    for cid in sorted(by_control.keys(), key=_control_sort_key):
        entry = by_control[cid]
        header = "\n\n".join(f"**{n}**" for n in entry["names"])
        body = "\n\n---\n\n".join(entry["descriptions"])
        implementation = f"{header}\n\n{body}".strip() if header else body
        # N3: prepend origination/inheritance header when present
        orig = entry.get("origination")
        prov = entry.get("providing_system")
        if orig and prov:
            orig_header = f"**Origination:** {orig} (inherited from {prov})\n\n"
        elif orig and orig != "system-specific":
            orig_header = f"**Origination:** {orig}\n\n"
        else:
            orig_header = ""
        if orig_header:
            implementation = orig_header + implementation if implementation else orig_header.strip()
        sc = {
            "controlId": cid,
            "controlImplementationStatus": collapse_status(entry["statuses"]),
            "controlImplementationDescription": implementation or "TBD",
        }
        # N2: sidecar parameterValues take precedence; CDX-derived are fallback
        pv = parameter_values.get(cid) or {}
        cdx_pv = entry.get("cdx_params") or {}
        merged = {**cdx_pv, **pv}  # sidecar overwrites CDX-derived for same key
        if merged:
            sc["parameterValues"] = [
                {"parameterId": pid, "parameterValue": str(pval)}
                for pid, pval in sorted(merged.items())
            ]
        out.append(sc)
    return out


def _control_sort_key(cid: str) -> tuple:
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", cid)
    if not m:
        return (cid, 0, 0)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0))


def build_ports_and_protocols(sdr_side: dict) -> list[dict]:
    raw = sdr_side.get("ports_and_protocols") or []
    out = []
    for entry in raw:
        item: dict = {}
        if entry.get("service_name"):
            item["serviceName"] = entry["service_name"]
        if entry.get("port_number") is not None:
            item["portNumber"] = str(entry["port_number"])
        if entry.get("transport_protocol"):
            item["transportProtocol"] = entry["transport_protocol"]
        if entry.get("encryption"):
            item["encryption"] = entry["encryption"]
        if entry.get("purpose"):
            item["purpose"] = entry["purpose"]
        out.append(item)
    return out


def build_sdr(slug: str, catalog_entry: dict, sidecar: dict) -> dict:
    cdx_path = cdx_path_for(slug, catalog_entry)
    if not cdx_path.exists():
        raise SystemExit(f"sdr({slug}): CDX artifact not found at {cdx_path.relative_to(REPO_ROOT)}")
    with cdx_path.open() as fh:
        cdx = json.load(fh)

    sdr_side = sidecar.get("sdr") or {}
    cpo_uri = sdr_side.get("certification_package_overview_uri") or DEFAULT_CPO_URI_TEMPLATE.format(slug=slug)
    parameter_values = sdr_side.get("parameter_values") or {}

    return {
        "certificationPackageOverviewUri": cpo_uri,
        "securityControls": build_security_controls(cdx, parameter_values),
        "fedRampRequirements": [],       # TBD — see IMPLEMENTATION_PLAN P2
        "keySecurityIndicators": [],     # TBD — see IMPLEMENTATION_PLAN P3
        "portsAndProtocols": build_ports_and_protocols(sdr_side),
    }


def export_one(slug: str, catalog: dict[str, dict]) -> Path:
    if slug not in catalog and slug != "example-system":
        raise SystemExit(f"sdr({slug}): slug not present in catalog/index.yaml")
    entry = catalog.get(slug) or {}
    sidecar = load_sidecar(slug)
    doc = build_sdr(slug, entry, sidecar)
    out_dir = BUILD_SYSTEMS / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "fedramp-sdr.json"
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    return out_path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--system", help="single system slug (e.g. example-system)")
    group.add_argument("--all", action="store_true", help="export SDR for every system with a CDX")
    args = p.parse_args()

    catalog = load_catalog()
    if args.system:
        out = export_one(args.system, catalog)
        print(f"wrote {out.relative_to(REPO_ROOT)}")
        return 0
    exported, skipped = 0, 0
    for slug in sorted(catalog.keys()):
        try:
            out = export_one(slug, catalog)
        except SystemExit as e:
            print(f"skip {slug}: {e}", file=sys.stderr)
            skipped += 1
            continue
        print(f"wrote {out.relative_to(REPO_ROOT)}")
        exported += 1
    print(f"exported={exported} skipped={skipped}")
    return 0 if exported else 1


if __name__ == "__main__":
    raise SystemExit(main())
