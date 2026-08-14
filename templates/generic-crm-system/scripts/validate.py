#!/usr/bin/env python3
"""Validate the generated generic CRM library packs and CycloneDX shell JSON.

Checks:
  - Pack types and metadata are present.
  - Component categories, cost levels, and applies_to enums are correct.
  - All relationship references across components, threats, and countermeasures
    resolve cleanly (no dangling keys).
  - Bidirectional mitigations link properly in the CycloneDX file.
  - Strict Redaction Gate: no URLs or emails leak.
"""

from __future__ import annotations

import json
import os
import re
import sys

import yaml

# Standard paths
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACK_DIR = os.path.join(ROOT, "pack")
COMPLIANCE_DIR = os.path.join(ROOT, "pack-oscal-800-53r5")
SHELL_CDX = os.path.join(ROOT, "build", "generic-crm-shell.cdx.json")

# Enums based on Precogly core loader rules
VALID_PACK_TYPES = {"technology", "threat", "countermeasure", "compliance", "template", "full", "taxonomy"}
VALID_CATEGORIES = {"process", "datastore", "external_human_actor", "external_system_actor"}
VALID_CONTROL_TYPES = {"preventive", "detective", "corrective", "deterrent", "recovery", "compensating", "procedural"}
VALID_COSTS = {"low", "medium", "high"}
VALID_APPLIES_TO = {"component", "flow", "both"}

# Redaction rules to fail on
FORBIDDEN = [
    (re.compile(r"https?://(?!localhost|127\.0\.0\.1)", re.IGNORECASE), "URL/URI"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "Email address"),
]


def load_yaml(path: str) -> dict | list:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def validate_pack_metadata(dir_path: str, expected_type: str) -> None:
    pack_file = os.path.join(dir_path, "pack.yaml")
    if not os.path.exists(pack_file):
        fail(f"Missing pack.yaml in {dir_path}")
    data = load_yaml(pack_file)
    pack_meta = data.get("pack", {})
    if not pack_meta:
        fail(f"Malformed pack.yaml (missing 'pack' block) in {dir_path}")

    slug = pack_meta.get("slug")
    name = pack_meta.get("name")
    ptype = pack_meta.get("pack_type")

    if not slug or not name:
        fail(f"Missing slug or name in pack.yaml under {dir_path}")
    if ptype != expected_type:
        fail(f"Expected pack_type '{expected_type}', got '{ptype}' in {dir_path}")
    if ptype not in VALID_PACK_TYPES:
        fail(f"Invalid pack_type '{ptype}' in {dir_path}")


def validate_library_pack() -> None:
    # 1. Metadata
    validate_pack_metadata(PACK_DIR, "full")

    # 2. Components
    comp_file = os.path.join(PACK_DIR, "components.yaml")
    if not os.path.exists(comp_file):
        fail("Missing components.yaml")
    components = load_yaml(comp_file).get("components", [])
    comp_ids = set()
    for i, c in enumerate(components):
        cid = c.get("id")
        if not cid:
            fail(f"Component [{i}] missing id")
        comp_ids.add(cid)
        cat = c.get("category")
        if cat not in VALID_CATEGORIES:
            fail(f"Component '{cid}' has invalid category: '{cat}'")

    # 3. Threats
    threat_file = os.path.join(PACK_DIR, "threats.yaml")
    if not os.path.exists(threat_file):
        fail("Missing threats.yaml")
    threats = load_yaml(threat_file).get("threats", [])
    threat_ids = set()
    for i, t in enumerate(threats):
        tid = t.get("id")
        if not tid:
            fail(f"Threat [{i}] missing id")
        threat_ids.add(tid)

    # 4. Countermeasures
    cm_file = os.path.join(PACK_DIR, "countermeasures.yaml")
    if not os.path.exists(cm_file):
        fail("Missing countermeasures.yaml")
    countermeasures = load_yaml(cm_file).get("countermeasures", [])
    cm_ids = set()
    for i, cm in enumerate(countermeasures):
        cm_id = cm.get("id")
        if not cm_id:
            fail(f"Countermeasure [{i}] missing id")
        cm_ids.add(cm_id)
        ctype = cm.get("control_type")
        if ctype not in VALID_CONTROL_TYPES:
            fail(f"Countermeasure '{cm_id}' has invalid control_type: '{ctype}'")
        cost = cm.get("cost")
        if cost not in VALID_COSTS:
            fail(f"Countermeasure '{cm_id}' has invalid cost: '{cost}'")

    # 5. Relationship joins
    ct_file = os.path.join(PACK_DIR, "joins", "components-threats.yaml")
    if not os.path.exists(ct_file):
        fail("Missing joins/components-threats.yaml")
    ct_mappings = load_yaml(ct_file).get("mappings", [])
    for m in ct_mappings:
        comp_ref = m.get("component")
        if comp_ref not in comp_ids:
            fail(f"joins/components-threats.yaml refers to unknown component: {comp_ref}")
        for t_entry in m.get("threats", []):
            t_ref = t_entry.get("threat")
            if t_ref not in threat_ids:
                fail(f"joins/components-threats.yaml refers to unknown threat: {t_ref}")
            app = t_entry.get("applies_to", "component")
            if app not in VALID_APPLIES_TO:
                fail(f"Invalid applies_to '{app}' for threat '{t_ref}' in component-threat joins")

    tc_file = os.path.join(PACK_DIR, "joins", "threats-countermeasures.yaml")
    if not os.path.exists(tc_file):
        fail("Missing joins/threats-countermeasures.yaml")
    tc_mappings = load_yaml(tc_file).get("mappings", [])
    for m in tc_mappings:
        t_ref = m.get("threat")
        if t_ref not in threat_ids:
            fail(f"joins/threats-countermeasures.yaml refers to unknown threat: {t_ref}")
        for cm_ref in m.get("countermeasures", []):
            if cm_ref not in cm_ids:
                fail(f"joins/threats-countermeasures.yaml refers to unknown countermeasure: {cm_ref}")


def validate_shell_cdx() -> None:
    if not os.path.exists(SHELL_CDX):
        fail(f"Shell CDX file not found at: {SHELL_CDX}")

    with open(SHELL_CDX, encoding="utf-8") as f:
        cdx = json.load(f)

    threats = cdx.get("threats", {}).get("threats", [])
    scenarios = cdx.get("threats", {}).get("scenarios", [])
    controls = cdx.get("controls", [])

    t_set = {t["bom-ref"] for t in threats}
    c_set = {c["bom-ref"] for c in controls}

    # Ensure scenarios reference real threats
    for s in scenarios:
        s_threat = s.get("threat")
        if s_threat not in t_set:
            fail(f"Scenario refers to unknown threat: {s_threat}")

    # Ensure bidirectional linkage
    for t in threats:
        t_ref = t["bom-ref"]
        mits = t.get("mitigations", [])
        if not mits:
            fail(f"Threat has no mitigations: {t_ref}")
        for cref in mits:
            if cref not in c_set:
                fail(f"Threat '{t_ref}' links to unknown control: {cref}")

    for c in controls:
        c_ref = c["bom-ref"]
        mits = c.get("mitigations", [])
        for tref in mits:
            if tref not in t_set:
                fail(f"Control '{c_ref}' links to unknown threat: {tref}")


def validate_redaction_gate() -> None:
    # Scan all yaml files and the generated json for forbidden patterns
    for root, _, files in os.walk(ROOT):
        for f in files:
            if not f.endswith((".yaml", ".json")):
                continue
            path = os.path.join(root, f)
            with open(path, encoding="utf-8") as file_stream:
                content = file_stream.read()
            for pattern, label in FORBIDDEN:
                m = pattern.search(content)
                if m:
                    fail(
                        f"Unredacted {label} found in file '{os.path.relpath(path, ROOT)}': "
                        f"'{m.group(0)}'. All public/tracked template artifacts must pass the redaction gate."
                    )


def main() -> None:
    print("Validating library pack metadata and files...", file=sys.stderr)
    validate_library_pack()

    print("Validating companion compliance pack metadata...", file=sys.stderr)
    validate_pack_metadata(COMPLIANCE_DIR, "compliance")

    print("Validating shell CycloneDX diagram linkage...", file=sys.stderr)
    validate_shell_cdx()

    print("Enforcing privacy/redaction gate across all artifacts...", file=sys.stderr)
    validate_redaction_gate()

    print("OK - Generic CRM system template fully validated! Packs and CDX are correct and redactor-clean.")


if __name__ == "__main__":
    main()
