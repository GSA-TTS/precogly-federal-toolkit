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
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_IN = os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")
DEFAULT_OUT = os.path.join(ROOT, "build", "owasp-threat-model.json")
DEFAULT_SCHEMA = "https://raw.githubusercontent.com/OWASP/www-project-threat-model-library/main/schemas/threat-model.schema.json"
DEFAULT_SCHEMA_CONFIG = os.path.join(
    ROOT, "templates", "generic-crm-system", "owasp-export.yaml"
)


def load_export_config(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


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


def effective_trust_level(zone_ref, zones_by_ref, seen=None):
    """Return the most restrictive trustLevel across a zone and its parents."""
    seen = seen or set()
    zone = zones_by_ref.get(zone_ref) or {}
    trust = zone.get("trustLevel")
    parent = zone.get("parentZone")
    if not parent or parent in seen:
        return trust
    parent_trust = effective_trust_level(parent, zones_by_ref, seen | {zone_ref})
    if trust is None:
        return parent_trust
    if parent_trust is None:
        return trust
    return min(trust, parent_trust)


def project_owasp_model(cdx, schema=DEFAULT_SCHEMA):
    bp = cdx["blueprints"][0]
    threats_doc = cdx.get("threats", {})

    asset_by_ref = {a["bom-ref"]: a for a in bp.get("assets", [])}
    zones_by_ref = {z["bom-ref"]: z for z in bp.get("zones", [])}
    zones = [
        clean(
            {
                "id": z["bom-ref"],
                "name": z.get("name"),
                "type": z.get("type"),
                "trust_level": z.get("trustLevel"),
                "effective_trust_level": effective_trust_level(
                    z["bom-ref"], zones_by_ref
                ),
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
            "$schema": schema,
            "name": bp.get("name", "Example System CRM Threat Model"),
            "version": str(cdx.get("version", 1)),
            "source": "Precogly CycloneDX",
            "source_serial_number": cdx.get("serialNumber"),
        }
    )
    model.update(
        {
            "trust_zones": zones,
            "components": components,
            "data_flows": data_flows,
            "threats": threats,
            "mitigations": mitigations,
        }
    )
    return model


def validate_owasp_projection(model):
    """Local structural validator for the OWASP projection.

    This is intentionally schema-light and network-free. It catches broken
    mappings before optional external JSON Schema validation runs.
    """
    errors = []
    for field in (
        "$schema",
        "name",
        "version",
        "trust_zones",
        "components",
        "data_flows",
        "threats",
        "mitigations",
    ):
        if field not in model:
            errors.append(f"missing top-level field: {field}")
    zones = {z.get("id") for z in model.get("trust_zones", [])}
    components = {c.get("id") for c in model.get("components", [])}
    flows = {f.get("id") for f in model.get("data_flows", [])}
    threats = {t.get("id") for t in model.get("threats", [])}
    mitigations = {m.get("id") for m in model.get("mitigations", [])}

    for zone in model.get("trust_zones", []):
        if not zone.get("id"):
            errors.append("trust_zones[] entry missing id")
        parent = zone.get("parent_trust_zone")
        if parent and parent not in zones:
            errors.append(
                f"zone {zone.get('id')} parent_trust_zone references missing zone {parent}"
            )
    for component in model.get("components", []):
        if not component.get("id"):
            errors.append("components[] entry missing id")
        trust_zone = component.get("trust_zone")
        if trust_zone and trust_zone not in zones:
            errors.append(
                f"component {component.get('id')} trust_zone references missing zone {trust_zone}"
            )
    for flow in model.get("data_flows", []):
        if not flow.get("id"):
            errors.append("data_flows[] entry missing id")
        for endpoint in ("source", "destination"):
            ref = flow.get(endpoint)
            if ref and ref not in components:
                errors.append(
                    f"flow {flow.get('id')} {endpoint} references missing component {ref}"
                )
    for threat in model.get("threats", []):
        if not threat.get("id"):
            errors.append("threats[] entry missing id")
        for ref in threat.get("components_affected", []) or []:
            if ref not in components and ref not in flows:
                errors.append(
                    f"threat {threat.get('id')} components_affected references missing component/flow {ref}"
                )
        for ref in threat.get("data_flows_affected", []) or []:
            if ref not in flows:
                errors.append(
                    f"threat {threat.get('id')} data_flows_affected references missing flow {ref}"
                )
        for ref in threat.get("mitigations", []) or []:
            if ref not in mitigations:
                errors.append(
                    f"threat {threat.get('id')} mitigation references missing mitigation {ref}"
                )
    for mitigation in model.get("mitigations", []):
        if not mitigation.get("id"):
            errors.append("mitigations[] entry missing id")
        for ref in mitigation.get("threats_mitigated", []) or []:
            if ref not in threats:
                errors.append(
                    f"mitigation {mitigation.get('id')} threats_mitigated references missing threat {ref}"
                )
    return errors


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default=DEFAULT_IN)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument(
        "--schema-config",
        default=DEFAULT_SCHEMA_CONFIG,
        help="YAML config containing schema_uri and strict_local_validation",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Validate output against OWASP TM JSON schema (M4)",
    )
    args = ap.parse_args()

    config = load_export_config(args.schema_config)
    schema = args.schema
    if schema == DEFAULT_SCHEMA and config.get("schema_uri"):
        schema = str(config["schema_uri"])
    strict = bool(args.strict or config.get("strict_local_validation", False))

    with open(args.in_path, encoding="utf-8") as f:
        cdx = json.load(f)

    model = project_owasp_model(cdx, schema=schema)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote {os.path.relpath(args.out, ROOT)}")

    if strict:
        errors = validate_owasp_projection(model)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            raise SystemExit(1)
        print("Local OWASP projection validation passed.")

        # Optional external schema validation. Network/schema availability is not
        # required for local strict mode because CI should remain deterministic.
        try:
            import urllib.request

            import jsonschema

            print(f"Fetching schema: {schema}")
            with urllib.request.urlopen(schema, timeout=10) as resp:
                schema = json.load(resp)
            jsonschema.validate(instance=model, schema=schema)
            print("External schema validation passed.")
        except ImportError:
            print(
                "WARNING: jsonschema not installed; skipping external schema validation",
                file=sys.stderr,
            )
        except jsonschema.ValidationError as exc:
            print(
                f"ERROR: OWASP schema validation failed: {exc.message}", file=sys.stderr
            )
            raise SystemExit(1) from None
        except Exception as exc:
            print(
                f"WARNING: External schema fetch/validate error (non-fatal): {exc}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
