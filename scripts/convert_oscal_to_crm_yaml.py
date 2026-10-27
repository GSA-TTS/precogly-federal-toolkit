#!/usr/bin/env python3
"""
Convert OSCAL component-definition.json files into CRM tier YAML formats.

Transforms:
  - ../gsa-pages/component-definitions/gsa-pages/component-definition.json
  - ../gsa-pages/component-definitions/cloud_gov/component-definition.json
  - ../gsa-pages/component-definitions/gsa_common_controls/component-definition.json

Into:
  - data/tiers/gsa-pages.yaml
  - data/tiers/cloud-gov.yaml
  - data/tiers/gsa-common-controls.yaml
"""

import json
import os
import re
import sys
from pathlib import Path

import yaml

try:
    from scripts.control_identity import canonical_control_id
except ModuleNotFoundError:  # Support direct invocation as a script.
    from control_identity import canonical_control_id

# Standard paths
HERE = Path(__file__).parent
ROOT = HERE.parent
DATA_CRM_TIERS = ROOT / "data" / "tiers"
# Resolved at runtime: sibling repo or NAMES_JSON env override
NAMES_JSON = Path(
    os.environ.get(
        "NAMES_JSON",
        str(
            HERE.resolve().parents[1]
            / "fedramp-automation-parser"
            / "compliance"
            / "data"
            / "nist_sp800-53_rev5_control_names.json"
        ),
    )
)


def clean_text(text: str) -> str:
    """Clean text: normalize whitespace, strip."""
    if not text:
        return ""
    return text.strip()


def redact(text: str) -> str:
    """Apply standard redaction rules (URLs, emails, etc.)."""
    if not text:
        return ""
    # Google Docs URLs
    text = re.sub(
        r"https?://docs\.google\.com/[^\s\"'>,)]*", "<INTERNAL_GOOGLE_DOC>", text
    )
    # Generic URLs
    text = re.sub(r"https?://(?!localhost)[^\s\"'>,)]+", "<REDACTED_URL>", text)
    # Email addresses
    text = re.sub(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "<REDACTED_EMAIL>", text
    )
    return text


def normalize_control_id(raw: str) -> str:
    """Return the shared canonical representation for a control ID."""
    return canonical_control_id(raw) if raw and raw.strip() else ""


def reject_duplicate_controls(controls: list[dict]) -> None:
    """Fail before writing a tier when canonical IDs collide."""
    seen: set[str] = set()
    for control in controls:
        cid = control["control_id"]
        if cid in seen:
            raise ValueError(f"duplicate canonical control ID: {cid}")
        seen.add(cid)


class LiteralStr(str):
    """String that should be rendered as a literal block scalar."""


def literal_str_representer(dumper, data):
    """Represent LiteralStr as a literal block scalar."""
    if "\n" in data or len(data) > 80:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(LiteralStr, literal_str_representer)


def convert_to_literal_strs(obj):
    """Convert long strings to LiteralStr for block scalar output, stripping trailing spaces first."""
    if isinstance(obj, dict):
        return {k: convert_to_literal_strs(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_literal_strs(item) for item in obj]
    elif isinstance(obj, str):
        # Strip trailing whitespace from all lines first to satisfy formatting constraints
        cleaned = "\n".join(line.rstrip() for line in obj.splitlines())
        if "\n" in cleaned or len(cleaned) > 80:
            return LiteralStr(cleaned)
        return cleaned
    return obj


def load_nist_names() -> dict:
    """Load official NIST control titles."""
    if NAMES_JSON.exists():
        with open(NAMES_JSON, encoding="utf-8") as f:
            return json.load(f)
    print("Warning: NIST control names lookup file not found, titles will be blank.")
    return {}


def _component_rule_index(comp: dict) -> dict[str, str]:
    """Index rules to descriptions."""
    rules: dict[str, str] = {}
    props = comp.get("props") or []
    descriptions: dict[str, str] = {}
    for p in props:
        name = p.get("name")
        val = p.get("value")
        remarks = p.get("remarks")
        if name == "Rule_Id" and val and remarks:
            rules[remarks] = val
        elif name == "Rule_Description" and val and remarks:
            descriptions[remarks] = val
    mapped: dict[str, str] = {}
    for remarks, rid in rules.items():
        if remarks in descriptions:
            mapped[rid] = descriptions[remarks]
    return mapped


def _get_prop_values(props: list[dict], name: str) -> list[str]:
    """Extract all values for a given property name."""
    if not props:
        return []
    return [p.get("value") for p in props if p.get("name") == name and p.get("value")]


def _render_responsibility(ir: dict, rules: dict[str, str]) -> str:
    """Render customer responsibility from implemented requirement description and statements."""
    blocks: list[str] = []
    if ir.get("description"):
        blocks.append(clean_text(ir["description"]))
    stmts = ir.get("statements") or []
    if stmts:
        lines: list[str] = []
        for st in stmts:
            sid = st.get("statement-id", "").strip()
            desc = clean_text(st.get("description"))
            rule_ids = _get_prop_values(st.get("props") or [], "Rule_Id")
            rule_notes = [
                f"[{rid}] {clean_text(rules.get(rid, ''))}".strip()
                for rid in rule_ids
                if rid in rules
            ]
            head = f"- {sid}:" if sid else "-"
            body = desc or ""
            trailer = f" ({'; '.join(rule_notes)})" if rule_notes else ""
            lines.append(f"{head} {body}{trailer}".strip())
        if lines:
            blocks.append("Statements:\n" + "\n".join(lines))
    return redact("\n\n".join(b for b in blocks if b))


def normalize_status(raw_status: str) -> str:
    """Normalize OSCAL implementation status to standard CRM values."""
    if not raw_status:
        return "Implemented"
    status_lower = raw_status.lower().strip()
    if "partially" in status_lower:
        return "Partially Implemented"
    elif "planned" in status_lower:
        return "Planned"
    elif "alternative" in status_lower:
        return "Alternative Implementation"
    elif "not-applicable" in status_lower or "n/a" in status_lower:
        return "N/A"
    elif "not-implemented" in status_lower or "gap" in status_lower:
        return "Not Implemented"
    elif "implemented" in status_lower:
        return "Implemented"
    return raw_status.title()


def map_origination(raw_origins: list[str]) -> list[str]:
    """Map raw origination keywords to standard human-readable CRM origination terms."""
    if not raw_origins:
        return ["Service Provider System Specific (cloud.gov)"]
    mapped = []
    for orig in raw_origins:
        orig_lower = orig.lower().strip()
        if "inherited" in orig_lower:
            mapped.append("Service Provider Corporate (GSA/18F)")
        elif "shared" in orig_lower or "hybrid" in orig_lower:
            mapped.append("Shared (Service Provider and Customer Responsibility)")
        elif "configured" in orig_lower:
            mapped.append("Configured by Customer (Customer System Specific)")
        elif "customer-provided" in orig_lower or "provided" in orig_lower:
            mapped.append("Provided by Customer (Customer System Specific)")
        else:
            mapped.append("Service Provider System Specific (cloud.gov)")
    return list(set(mapped))


def convert_file(src_path: Path, nist_names: dict):
    """Convert a single OSCAL component-definition file to a CRM tier YAML."""
    print(f"Parsing {src_path}...")
    with open(src_path, encoding="utf-8") as f:
        data = json.load(f)

    cd = data.get("component-definition", {})
    meta_title = cd.get("metadata", {}).get("title", "")
    components = cd.get("components", []) or []
    if not components:
        print(f"No components found in {src_path}")
        return

    comp = components[0]
    rules = _component_rule_index(comp)
    title = comp.get("title", meta_title)
    description = clean_text(comp.get("description", ""))

    # Slugify component name
    parent_dir_name = src_path.parent.name
    slug = parent_dir_name.replace("_", "-")

    controls = []
    for ci in comp.get("control-implementations", []) or []:
        for ir in ci.get("implemented-requirements", []) or []:
            raw_cid = ir.get("control-id", "")
            cid = normalize_control_id(raw_cid)
            if not cid:
                continue

            name = nist_names.get(cid.lower(), "")

            # Get props from requirement
            props = ir.get("props") or []
            status_vals = _get_prop_values(props, "implementation-status")
            status = normalize_status(status_vals[0] if status_vals else "")

            orig_vals = _get_prop_values(
                props, "control-origination"
            ) or _get_prop_values(props, "origination")
            origination = map_origination(orig_vals)

            can_inherit = "No"
            for o in orig_vals:
                if "inherited" in o.lower():
                    can_inherit = "Yes"
                elif "shared" in o.lower() or "hybrid" in o.lower():
                    can_inherit = "Partial"

            resp_text = _render_responsibility(ir, rules)

            ctrl = {
                "control_id": cid,
                "name": name or cid,
                "can_be_inherited": can_inherit,
                "customer_responsibility": resp_text,
                "implementation_status": status,
                "control_origination": origination,
            }
            controls.append(ctrl)

    # Sort controls deterministically
    def sort_key(c):
        cid = c["control_id"]
        m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", cid)
        if not m:
            return (cid, 10000, 10000)
        return (m.group(1), int(m.group(2)), int(m.group(3) or 0))

    controls.sort(key=sort_key)
    reject_duplicate_controls(controls)

    tier_data = {
        "tier": slug,
        "name": title,
        "description": description,
        "source_sheet": f"OSCAL: {src_path.name}",
        "control_count": len(controls),
        "controls": controls,
    }

    # Format long strings using literal block scalars
    tier_data_formatted = convert_to_literal_strs(tier_data)

    output_path = DATA_CRM_TIERS / f"{slug}.yaml"
    DATA_CRM_TIERS.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as out_f:
        yaml.dump(
            tier_data_formatted,
            out_f,
            default_flow_style=False,
            allow_unicode=True,
            width=120,
            sort_keys=False,
        )
    print(f"Success! Wrote {len(controls)} controls to {output_path}")


def main():
    nist_names = load_nist_names()

    # Locate component definitions in sibling repository gsa-pages (or GSA_PAGES_COMP_DEF_DIR env override)
    gsa_pages_comp_def_dir = Path(
        os.environ.get(
            "GSA_PAGES_COMP_DEF_DIR",
            str(
                Path(__file__).resolve().parents[2]
                / "gsa-pages"
                / "component-definitions"
            ),
        )
    )

    if not gsa_pages_comp_def_dir.exists():
        print(
            "Error: Could not locate component-definitions directory under gsa-pages sibling",
            file=sys.stderr,
        )
        sys.exit(1)

    # Find component-definition.json files recursively
    files = list(gsa_pages_comp_def_dir.glob("**/component-definition.json"))
    if not files:
        print(
            f"No component-definition.json files found in {gsa_pages_comp_def_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"Found {len(files)} component-definition.json files in {gsa_pages_comp_def_dir}."
    )
    for f in files:
        convert_file(f, nist_names)


if __name__ == "__main__":
    main()
