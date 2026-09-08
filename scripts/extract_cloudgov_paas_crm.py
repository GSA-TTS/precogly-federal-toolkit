#!/usr/bin/env python3
"""
Extract Cloud.gov PaaS CRM from tmp/cloud.gov-CIS-Worksheet.ods into data/tiers/cloud-gov-paas.yaml.

Combines columns from both 'PaaS CRM' and 'CIS Worksheet' sheets, matching them 1-to-1 by Control ID:
  - 'PaaS CRM' supplies: Can Be Inherited, cloud.gov PaaS Specific Inheritance writeup.
  - 'CIS Worksheet' supplies: Implementation Status, Control Origination.
  - Sourced NIST SP 800-53 rev5 titles mapped programmatically from compliance registry.
"""

import json
import os
import re
import sys
from pathlib import Path

import yaml
from odf.opendocument import load
from odf.table import Table, TableCell, TableRow
from odf.text import P

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


def get_cell_text(cell) -> str:
    """Extract text from an ODF table cell."""
    ps = cell.getElementsByType(P)
    parts = []
    for p in ps:
        for child in p.childNodes:
            if hasattr(child, "data"):
                parts.append(child.data)
            elif hasattr(child, "childNodes"):
                for gc in child.childNodes:
                    if hasattr(gc, "data"):
                        parts.append(gc.data)
    return " ".join(parts).strip()


def expand_row(row, max_cols=30) -> list[str]:
    """Expand a row's cells, handling column repeats."""
    cells = row.getElementsByType(TableCell)
    vals = []
    for c in cells:
        repeat = int(c.getAttribute("numbercolumnsrepeated") or 1)
        txt = get_cell_text(c)
        vals.extend([txt] * min(repeat, max_cols - len(vals)))
        if len(vals) >= max_cols:
            break
    return vals


def clean_text(text: str) -> str:
    """Clean text: normalize whitespace, strip."""
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def redact(text: str) -> str:
    """Apply redaction rules (URLs, emails, etc.)."""
    if not text:
        return ""
    # Google Docs URLs
    text = re.sub(r"https?://docs\.google\.com/[^\s]+", "<INTERNAL_GOOGLE_DOC>", text)
    # Google Sheets URLs
    text = re.sub(
        r"https?://[^\s]*google\.com/spreadsheets[^\s]*", "<INTERNAL_GOOGLE_DOC>", text
    )
    # Generic URLs (except localhost)
    text = re.sub(r"https?://(?!localhost)[^\s]+", "<REDACTED_URL>", text)
    # Email addresses
    text = re.sub(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "<REDACTED_EMAIL>", text
    )
    return text


def normalize_for_lookup(cid: str) -> str:
    """Normalize control ID: AC-01 (a) -> ac-1, AC-02 (1) -> ac-2.1."""
    cid = cid.lower().strip()
    m = re.match(r"([a-z]{2})-0*(\d+)(?:\s*\((.*?)\))?", cid)
    if m:
        family, num, suffix = m.groups()
        if suffix:
            if suffix.isdigit():
                return f"{family}-{num}.{suffix}"
            else:
                return f"{family}-{num}"
        return f"{family}-{num}"
    return cid


class LiteralStr(str):
    """String that should be rendered as a literal block scalar."""


def literal_str_representer(dumper, data):
    """Represent LiteralStr as a literal block scalar."""
    if "\n" in data or len(data) > 80:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(LiteralStr, literal_str_representer)


def convert_to_literal_strs(obj):
    """Convert long strings to LiteralStr for block scalar output."""
    if isinstance(obj, dict):
        return {k: convert_to_literal_strs(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_literal_strs(item) for item in obj]
    elif isinstance(obj, str) and ("\n" in obj or len(obj) > 100):
        return LiteralStr(obj)
    return obj


def load_nist_names() -> dict:
    """Load official NIST control titles."""
    if NAMES_JSON.exists():
        with open(NAMES_JSON, encoding="utf-8") as f:
            return json.load(f)
    print("Warning: NIST control names lookup file not found, titles will be blank.")
    return {}


def write_tier_yaml(tier_data: dict, output_dir: Path):
    """Write tier data to YAML file."""
    if not tier_data or "tier" not in tier_data:
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{tier_data['tier']}.yaml"

    # Convert long strings to literal block scalars
    tier_data = convert_to_literal_strs(tier_data)

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(
            tier_data,
            f,
            default_flow_style=False,
            allow_unicode=True,
            width=120,
            sort_keys=False,
        )


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract Cloud.gov PaaS CRM from ODS file"
    )
    parser.add_argument("input_file", help="Path to cloud.gov-CIS-Worksheet.ods")
    parser.add_argument(
        "--output-dir", "-o", default=str(DATA_CRM_TIERS), help="Output directory"
    )
    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {input_path}...")
    doc = load(str(input_path))
    sheets = doc.spreadsheet.getElementsByType(Table)

    # 1. Parse CIS Worksheet sheet
    s_cis = next(s for s in sheets if s.getAttribute("name") == "CIS Worksheet")
    rows_cis = s_cis.getElementsByType(TableRow)

    status_headers = [
        "Implemented",
        "Partially Implemented",
        "Planned",
        "Alternative Implementation",
        "N/A",
    ]
    orig_headers = [
        "Service Provider Corporate (GSA/18F)",
        "Service Provider System Specific (cloud.gov)",
        "Service Provider Hybrid (Service Provider Corporate and Service Provider System Specific)",
        "Configured by Customer (Customer System Specific)",
        "Provided by Customer (Customer System Specific)",
        "Shared (Service Provider and Customer Responsibility)",
        "Inherited from Pre-Existing Provisional Authorization (AWS GovCloud)",
    ]

    cis_data = {}
    for row in rows_cis[3:]:  # Data starts at row 3
        vals = expand_row(row, 25)
        if not vals or not vals[0]:
            continue

        control_id = vals[0].strip()

        # Determine status
        status = ""
        for i, h in enumerate(status_headers):
            val = vals[i + 1] if len(vals) > i + 1 else ""
            if "X" in val.upper():
                status = h
                break

        # Determine origination
        origination = []
        for i, h in enumerate(orig_headers):
            val = vals[i + 6] if len(vals) > i + 6 else ""
            if "X" in val.upper():
                origination.append(h)

        cis_data[control_id] = {
            "implementation_status": status,
            "control_origination": origination,
        }

    # 2. Parse PaaS CRM sheet
    s_crm = next(s for s in sheets if s.getAttribute("name") == "PaaS CRM")
    rows_crm = s_crm.getElementsByType(TableRow)

    nist_names = load_nist_names()
    controls = []

    for row in rows_crm[3:]:  # Data starts at row 3
        vals = expand_row(row, 10)
        if not vals or not vals[0]:
            continue

        control_id = vals[0].strip()
        can_inherit = clean_text(vals[1]) if len(vals) > 1 else ""
        resp_text = redact(clean_text(vals[2])) if len(vals) > 2 else ""

        # Retrieve name/title
        lookup_key = normalize_for_lookup(control_id)
        name = nist_names.get(lookup_key, "")

        # Get CIS data
        cis = cis_data.get(control_id, {})

        ctrl = {
            "control_id": control_id,
            "name": name,
            "can_be_inherited": can_inherit,
            "customer_responsibility": resp_text,
            "implementation_status": cis.get("implementation_status", ""),
            "control_origination": cis.get("control_origination", []),
        }
        controls.append(ctrl)

    tier_data = {
        "tier": "cloud-gov-paas",
        "name": "Cloud.gov PaaS",
        "description": "Cloud.gov Platform as a Service (PaaS) Customer Responsibility Matrix (CRM) and Control Implementation Summary (CIS)",
        "source_sheet": "PaaS CRM + CIS Worksheet",
        "control_count": len(controls),
        "controls": controls,
    }

    # Write to YAML
    write_tier_yaml(tier_data, output_dir)
    print(f"\nDone. Cloud.gov PaaS CRM written to {output_dir}/cloud-gov-paas.yaml")


if __name__ == "__main__":
    main()
