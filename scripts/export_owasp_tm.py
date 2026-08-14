#!/usr/bin/env python3
"""Export Precogly-native CycloneDX to an OWASP threat-model JSON projection.

This is a one-way compatibility/export layer for ADR-005. The Precogly CDX file
remains the source of truth; this script owns the camelCase -> snake_case
mapping used by the OWASP TM-library proposal alignment:

  authMechanism -> auth_mechanism
  parentZone -> parent_trust_zone
  affectedFlows -> data_flows_affected
"""

from __future__ import annotations

import argparse
import json
import os


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_IN = os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")
DEFAULT_OUT = os.path.join(ROOT, "build", "owasp-threat-model.json")
DEFAULT_SCHEMA = "https://raw.githubusercontent.com/OWASP/www-project-threat-model-library/main/schemas/threat-model.schema.json"


def clean(obj):
    """Drop empty optional fields recursively while preserving falsey scalars."""
    if isinstance(obj, dict):
        cleaned = {k: clean(v) for k, v in obj.items()}
        return {k: v for k, v in cleaned.items() if v not in (None, [], {})}
    if isinstance(obj, list):
        cleaned = []
        for value in obj:
            item = clean(value)
            if item not in (None, [], {}):
                cleaned.append(item)
        return cleaned
    return obj


def property_map(items):
    return {p.get("name"): p.get("value") for p in items or [] if p.get("name")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default=DEFAULT_IN)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    args = ap.parse_args()

    with open(args.in_path, encoding="utf-8") as f:
        cdx = json.load(f)

    bp = cdx["blueprints"][0]
    threats_doc = cdx.get("threats", {})

    asset_by_ref = {a["bom-ref"]: a for a in bp.get("assets", [])}
    zones = [
        clean(
            {
                "id": z["bom-ref"],
                "name": z.get("name"),
                "type": z.get("type"),
                "trust_level": z.get("trustLevel"),
                "parent_trust_zone": z.get("parentZone"),
                "properties": property_map(z.get("properties", [])),
            }
        )
        for z in bp.get("zones", [])
    ]

    components = [
        clean(
            {
                "id": a["bom-ref"],
                "name": a.get("name"),
                "type": a.get("type"),
                "trust_zone": a.get("zone"),
                "description": a.get("description"),
            }
        )
        for a in bp.get("assets", [])
    ]

    data_flows = []
    for f in bp.get("flows", []):
        src = asset_by_ref.get(f.get("source"), {})
        dst = asset_by_ref.get(f.get("destination"), {})
        data_flows.append(
            clean(
                {
                    "id": f["bom-ref"],
                    "name": f.get("name") or f["bom-ref"],
                    "source": f.get("source"),
                    "destination": f.get("destination"),
                    "type": f.get("type"),
                    "protocols": f.get("protocols"),
                    "auth_mechanism": f.get("authMechanism"),
                    "source_trust_zone": src.get("zone"),
                    "destination_trust_zone": dst.get("zone"),
                    "properties": property_map(f.get("properties", [])),
                }
            )
        )

    threats = [
        clean(
            {
                "id": t["bom-ref"],
                "name": t.get("name"),
                "description": t.get("description"),
                "components_affected": t.get("affectedAssets"),
                "data_flows_affected": t.get("affectedFlows"),
                "mitigations": t.get("mitigations"),
                "properties": property_map(t.get("properties", [])),
            }
        )
        for t in threats_doc.get("threats", [])
    ]

    mitigations = [
        clean(
            {
                "id": c["bom-ref"],
                "name": c.get("name"),
                "description": c.get("description"),
                "status": c.get("status"),
                "category": c.get("category"),
                "threats_mitigated": c.get("mitigations"),
                "properties": property_map(c.get("properties", [])),
            }
        )
        for c in cdx.get("controls", [])
    ]

    model = clean(
        {
            "$schema": args.schema,
            "name": bp.get("name", "Example System CRM Threat Model"),
            "version": str(cdx.get("version", 1)),
            "source": "Precogly CycloneDX",
            "source_serial_number": cdx.get("serialNumber"),
            "trust_zones": zones,
            "components": components,
            "data_flows": data_flows,
            "threats": threats,
            "mitigations": mitigations,
        }
    )

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote {os.path.relpath(args.out, ROOT)}")


if __name__ == "__main__":
    main()
