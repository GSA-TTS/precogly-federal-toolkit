#!/usr/bin/env python3
"""Build a Precogly-native CycloneDX shell JSON from generated pack YAMLs.

This script takes the structured, sorted library pack definitions from
the ``pack/`` folder and rolls them onto the generic DFD template, emitting
a single valid CycloneDX JSON. This matches the user's requirement to
produce a shell cdx.json with all CRM threats loaded.
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

# Standard paths
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACK_DIR = os.path.join(ROOT, "pack")
DFD_PATH = os.path.join(ROOT, "data", "model", "generic-dfd.cdx.json")
OUT_PATH = os.path.join(ROOT, "build", "generic-crm-shell.cdx.json")


def load_yaml(path: str) -> dict | list:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:40]


def extract_nist_id(threat_name: str) -> str:
    """Extract something like AC-2 or AC-6(5) from 'CRM: AC-2 Responsibility Gap'."""
    m = re.search(r"CRM:\s*([A-Z]{2}-\d+(?:\(\d+\))?)", threat_name)
    return m.group(1) if m else ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT_PATH, help="Output CycloneDX JSON path")
    args = ap.parse_args()

    # Verify input exists
    if not os.path.exists(DFD_PATH):
        raise SystemExit(f"FAIL: generic DFD baseline not found: {DFD_PATH}")

    with open(DFD_PATH, encoding="utf-8") as f:
        cdx = json.load(f)

    # Load Pack definitions
    comp_data = load_yaml(os.path.join(PACK_DIR, "components.yaml"))
    threat_data = load_yaml(os.path.join(PACK_DIR, "threats.yaml"))
    cm_data = load_yaml(os.path.join(PACK_DIR, "countermeasures.yaml"))
    ct_data = load_yaml(os.path.join(PACK_DIR, "joins", "components-threats.yaml"))
    tc_data = load_yaml(os.path.join(PACK_DIR, "joins", "threats-countermeasures.yaml"))

    components = comp_data.get("components", [])
    threats = threat_data.get("threats", [])
    countermeasures = cm_data.get("countermeasures", [])
    ct_mappings = ct_data.get("mappings", [])
    tc_mappings = tc_data.get("mappings", [])

    # Map threat_id -> list of control_ids
    threat_to_cms: dict[str, list[str]] = {}
    for mapping in tc_mappings:
        tid = mapping.get("threat")
        cms = mapping.get("countermeasures", [])
        if tid:
            threat_to_cms[tid] = cms

    # Map component_id -> list of threat_ids
    comp_to_threats: dict[str, list[str]] = {}
    for mapping in ct_mappings:
        cid = mapping.get("component")
        thrs = [t.get("threat") for t in mapping.get("threats", []) if t.get("threat")]
        if cid:
            comp_to_threats[cid] = thrs

    # Map threat_id -> component asset ref
    threat_to_asset: dict[str, str] = {}
    bp = cdx["blueprints"][0]

    # Inject CRM components into the DFD's assets
    for comp in components:
        asset_ref = f"asset-{comp['id']}-1"
        bp["assets"].append(
            {
                "bom-ref": asset_ref,
                "name": comp["name"],
                "type": "system",
            }
        )
        # Link threats mapped to this component
        for tid in comp_to_threats.get(comp["id"], []):
            threat_to_asset[tid] = asset_ref

    # Base Core asset ref fallback
    core_asset_ref = bp["assets"][0]["bom-ref"]

    # We want a clean numbering sequence past existing templates
    seq = 100
    cdx_threats: list[dict] = []
    cdx_scenarios: list[dict] = []
    cdx_controls: list[dict] = []

    # Map countermeasure_id -> control bom-ref
    cm_to_ref: dict[str, str] = {}
    for cm in countermeasures:
        seq += 1
        cm_ref = f"control-{slugify(cm['name'])}-{seq}"
        cm_to_ref[cm["id"]] = cm_ref

        cdx_controls.append(
            {
                "bom-ref": cm_ref,
                "name": cm["name"],
                "status": "implemented",
                "description": cm["description"],
                "category": cm.get("control_type", "preventive"),
                "mitigations": [],  # Filled below
            }
        )

    # Re-map cdx_controls for fast retrieval
    ctrls_by_ref = {c["bom-ref"]: c for c in cdx_controls}

    for threat in threats:
        seq += 1
        t_ref = f"threat-{slugify(threat['name'])}-{seq}"
        s_ref = f"scenario-{slugify(threat['name'])}-{seq}"

        nist_id = extract_nist_id(threat["name"])
        affected = [threat_to_asset.get(threat["id"], core_asset_ref)]

        # Find mitigations mapped to this threat
        linked_cms = threat_to_cms.get(threat["id"], [])
        mitigations: list[str] = []
        for cm_id in linked_cms:
            cref = cm_to_ref.get(cm_id)
            if cref:
                mitigations.append(cref)
                # Link bidirectionally
                if cref in ctrls_by_ref:
                    ctrls_by_ref[cref]["mitigations"].append(t_ref)

        cdx_threats.append(
            {
                "bom-ref": t_ref,
                "name": threat["name"],
                "description": threat["description"],
                "affectedAssets": affected,
                "properties": [
                    {"name": "nist:control-id", "value": nist_id},
                    {"name": "crm:threat-id", "value": threat["id"]},
                ],
                "mitigations": mitigations,
            }
        )

        cdx_scenarios.append(
            {
                "bom-ref": s_ref,
                "threat": t_ref,
                "affectedAssets": affected,
                "riskScore": {"level": "medium"},
            }
        )

    cdx["threats"] = {"threats": cdx_threats, "scenarios": cdx_scenarios}
    cdx["controls"] = cdx_controls

    # Doc version update
    cdx["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    cdx["version"] = int(cdx.get("version", 1)) + 1
    meta = cdx.setdefault("metadata", {})
    meta["timestamp"] = (
        datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )

    # Repository Root (two levels up from templates/generic-crm-system/)
    REPO_ROOT = os.path.abspath(os.path.join(ROOT, "..", ".."))
    outputs = [args.out]
    # Mirror into the host repository only when running in place; a copied
    # template (the quick-start) must not write outside its own directory.
    in_place = os.path.realpath(ROOT) == os.path.realpath(
        os.path.join(REPO_ROOT, "templates", "generic-crm-system")
    )
    if in_place:
        outputs += [
            os.path.join(REPO_ROOT, "build", "generic-crm-shell.cdx.json"),
            os.path.join(REPO_ROOT, "build", "cdx.json"),
            os.path.join(REPO_ROOT, "cdx.json"),
        ]

    for out_path in outputs:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(cdx, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(
            f"Wrote {len(cdx_threats)} threats into shell DFD at {os.path.relpath(out_path, REPO_ROOT if in_place else ROOT)}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
