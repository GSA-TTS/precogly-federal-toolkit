#!/usr/bin/env python3
"""
Extract CRM service tiers from Example System_CRM_V1_20251020.xlsx.ods into separate YAML files.

Service tiers extracted:
  - GSA Moderate Baseline (from sheet "3 - GSA Moderate Baseline")
  - FCS Core (from sheet "FCS Core")
  - VPCaaS (100% system specific, per the CRM Overview metrics)
  - managed cloud service (extracted from sheet "4 - FCS Inheritance Model" managed cloud service columns)
  - EBTA (shares identical inheritance profile as managed cloud service, per the CRM Overview metrics)
  - CaaS (shares identical inheritance profile as managed cloud service, per the CRM Overview metrics)
  - Data (shares identical inheritance profile as managed cloud service, per the CRM Overview metrics)

Output: data/crm/tiers/<tier-slug>.yaml
"""

import os
import re
import sys
from pathlib import Path

import yaml
from odf.opendocument import load
from odf.table import Table, TableRow, TableCell
from odf.text import P

HERE = Path(__file__).parent
ROOT = HERE.parent
DATA_CRM = ROOT / "data" / "crm"
TIERS_DIR = DATA_CRM / "tiers"


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


def expand_row(row, max_cols=100) -> list[str]:
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


def normalize_control_id(raw: str) -> str:
    """Normalize control ID: AC-02-00 -> AC-2, AC-02-01 -> AC-2(1)."""
    if not raw:
        return ""
    # Remove leading zeros in family number: AC-02 -> AC-2
    m = re.match(r"([A-Z]{2})-0*(\d+)(?:-0*(\d+))?", raw.upper())
    if not m:
        return raw.upper()
    family, num, enh = m.groups()
    if enh and int(enh) > 0:
        return f"{family}-{int(num)}({int(enh)})"
    return f"{family}-{int(num)}"


def clean_text(text: str) -> str:
    """Clean text: normalize whitespace, strip."""
    if not text:
        return ""
    # Collapse multiple spaces/newlines
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def redact(text: str) -> str:
    """Apply redaction rules (URLs, emails, etc.)."""
    if not text:
        return ""
    # Google Docs URLs
    text = re.sub(r"https?://docs\.google\.com/[^\s]+", "<INTERNAL_GOOGLE_DOC>", text)
    # Google Sheets URLs
    text = re.sub(r"https?://[^\s]*google\.com/spreadsheets[^\s]*", "<INTERNAL_GOOGLE_DOC>", text)
    # Generic URLs (except localhost)
    text = re.sub(r"https?://(?!localhost)[^\s]+", "<REDACTED_URL>", text)
    # Email addresses
    text = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "<REDACTED_EMAIL>", text)
    return text


def extract_gsa_moderate_baseline(doc) -> dict:
    """Extract GSA Moderate Baseline from sheet '3 - GSA Moderate Baseline'."""
    sheets = doc.spreadsheet.getElementsByType(Table)
    for s in sheets:
        if s.getAttribute("name") == "3 - GSA Moderate Baseline":
            rows = s.getElementsByType(TableRow)
            
            controls = []
            for row in rows[1:]:
                vals = expand_row(row, 20)
                if not vals or not vals[0]:
                    continue
                
                control_id = normalize_control_id(vals[2] if len(vals) > 2 else "")
                if not control_id:
                    continue
                
                ctrl = {
                    "control_id": control_id,
                    "name": clean_text(vals[3]) if len(vals) > 3 else "",
                    "description": redact(clean_text(vals[4])) if len(vals) > 4 else "",
                    "discussion": redact(clean_text(vals[5])) if len(vals) > 5 else "",
                    "privacy_related": "X" in (vals[6] if len(vals) > 6 else ""),
                    "baseline_low": "X" in (vals[7] if len(vals) > 7 else "") or bool(vals[7] if len(vals) > 7 else ""),
                    "baseline_moderate": "X" in (vals[8] if len(vals) > 8 else "") or bool(vals[8] if len(vals) > 8 else ""),
                    "fedramp_low_params": redact(clean_text(vals[9])) if len(vals) > 9 else "",
                    "fedramp_moderate_params": redact(clean_text(vals[10])) if len(vals) > 10 else "",
                    "fedramp_high_params": redact(clean_text(vals[11])) if len(vals) > 11 else "",
                    "assessment_procedures": redact(clean_text(vals[12])) if len(vals) > 12 else "",
                    "inheritance_type": clean_text(vals[13]) if len(vals) > 13 else "",
                    "responsible_program": clean_text(vals[14]) if len(vals) > 14 else "",
                }
                controls.append(ctrl)
            
            return {
                "tier": "gsa-moderate-baseline",
                "name": "GSA Moderate Baseline",
                "description": "NIST 800-53 Rev 5 controls at GSA Moderate baseline with FedRAMP parameters",
                "source_sheet": "3 - GSA Moderate Baseline",
                "control_count": len(controls),
                "controls": controls,
            }
    return {}


def extract_fcs_core(doc) -> dict:
    """Extract FCS Core from sheet 'FCS Core'."""
    sheets = doc.spreadsheet.getElementsByType(Table)
    for s in sheets:
        if s.getAttribute("name") == "FCS Core":
            rows = s.getElementsByType(TableRow)
            
            controls = []
            for row in rows[1:]:
                vals = expand_row(row, 15)
                if not vals or not vals[0]:
                    continue
                
                control_id = normalize_control_id(vals[2] if len(vals) > 2 else "")
                if not control_id:
                    continue
                
                ctrl = {
                    "control_id": control_id,
                    "name": clean_text(vals[3]) if len(vals) > 3 else "",
                    "description": redact(clean_text(vals[4])) if len(vals) > 4 else "",
                    "discussion": redact(clean_text(vals[5])) if len(vals) > 5 else "",
                    "inheritance_type": clean_text(vals[6]) if len(vals) > 6 else "",
                    "responsible_program": clean_text(vals[7]) if len(vals) > 7 else "",
                    "fcs_core_responsibility": redact(clean_text(vals[8])) if len(vals) > 8 else "",
                    "fcs_core_tenant_responsibility": redact(clean_text(vals[9])) if len(vals) > 9 else "",
                }
                controls.append(ctrl)
            
            return {
                "tier": "fcs-core",
                "name": "FCS Core",
                "description": "FCS Core platform controls with program and tenant responsibilities",
                "source_sheet": "FCS Core",
                "control_count": len(controls),
                "controls": controls,
            }
    return {}


def extract_inheritance_model_controls(doc) -> tuple[list[dict], dict]:
    """Extract raw control rows and column header map from '4 - FCS Inheritance Model'."""
    sheets = doc.spreadsheet.getElementsByType(Table)
    for s in sheets:
        if s.getAttribute("name") == "4 - FCS Inheritance Model":
            rows = s.getElementsByType(TableRow)
            if len(rows) < 7:
                return [], {}
            headers = expand_row(rows[6], 30)
            col_idx = {h: i for i, h in enumerate(headers) if h}
            
            controls = []
            for row in rows[7:]:
                vals = expand_row(row, 30)
                if not vals or not vals[0]:
                    continue
                control_id = normalize_control_id(vals[0])
                if not control_id:
                    continue
                controls.append((control_id, vals))
            return controls, col_idx
    return [], {}


def extract_managed-cloud-service_tier(controls, col_idx) -> dict:
    """Build managed cloud service tier from raw inheritance controls."""
    managed-cloud-service_controls = []
    for cid, vals in controls:
        managed-cloud-service_service = clean_text(vals[col_idx["managed cloud service Service"]]) if "managed cloud service Service" in col_idx and len(vals) > col_idx["managed cloud service Service"] else ""
        managed-cloud-service_tenant = clean_text(vals[col_idx["managed cloud service Tenant"]]) if "managed cloud service Tenant" in col_idx and len(vals) > col_idx["managed cloud service Tenant"] else ""
        managed-cloud-service_inheritance = clean_text(vals[col_idx["managed cloud service Inhertience Source"]]) if "managed cloud service Inhertience Source" in col_idx and len(vals) > col_idx["managed cloud service Inhertience Source"] else ""
        managed-cloud-service_tenant_inh = clean_text(vals[col_idx["managed cloud service Tenant Inheritence Source"]]) if "managed cloud service Tenant Inheritence Source" in col_idx and len(vals) > col_idx["managed cloud service Tenant Inheritence Source"] else ""
        
        if managed-cloud-service_service or managed-cloud-service_tenant:
            ctrl = {
                "control_id": cid,
                "name": clean_text(vals[1]) if len(vals) > 1 else "",
                "baseline": clean_text(vals[2]) if len(vals) > 2 else "",
                "fcs_cloud_control_type": clean_text(vals[5]) if len(vals) > 5 else "",
                "implementation_status": clean_text(vals[6]) if len(vals) > 6 else "",
                "managed-cloud-service_service": managed-cloud-service_service,
                "managed-cloud-service_inheritance_source": managed-cloud-service_inheritance,
                "managed-cloud-service_tenant": managed-cloud-service_tenant,
                "managed-cloud-service_tenant_inheritance_source": managed-cloud-service_tenant_inh,
            }
            managed-cloud-service_controls.append(ctrl)
            
    return {
        "tier": "managed-cloud-service",
        "name": "managed cloud service (Managed Cloud as a Service)",
        "description": "managed cloud service service and tenant control responsibilities",
        "source_sheet": "4 - FCS Inheritance Model (managed cloud service columns)",
        "control_count": len(managed-cloud-service_controls),
        "controls": managed-cloud-service_controls,
    }


def extract_cloned_tier(managed-cloud-service_data: dict, slug_name: str, display_name: str, description: str) -> dict:
    """Clone managed cloud service tier data but update names/keys to map to the new tier."""
    cloned_controls = []
    for c in managed-cloud-service_data["controls"]:
        cc = dict(c)
        # Re-key managed cloud service columns to the specific tier's name
        s_val = cc.pop("managed-cloud-service_service", "")
        s_inh = cc.pop("managed-cloud-service_inheritance_source", "")
        t_val = cc.pop("managed-cloud-service_tenant", "")
        t_inh = cc.pop("managed-cloud-service_tenant_inheritance_source", "")
        
        cc[f"{slug_name}_service"] = s_val
        cc[f"{slug_name}_inheritance_source"] = s_inh
        cc[f"{slug_name}_tenant"] = t_val
        cc[f"{slug_name}_tenant_inheritance_source"] = t_inh
        cloned_controls.append(cc)
        
    return {
        "tier": slug_name,
        "name": display_name,
        "description": description,
        "source_sheet": "4 - FCS Inheritance Model (derived from managed cloud service columns per CRM Overview equivalence)",
        "control_count": len(cloned_controls),
        "controls": cloned_controls,
    }


def build_vpcaas_tier(controls, col_idx) -> dict:
    """Build VPCaaS tier (100% system specific, per the CRM Overview metrics)."""
    vpcaas_controls = []
    for cid, vals in controls:
        ctrl = {
            "control_id": cid,
            "name": clean_text(vals[1]) if len(vals) > 1 else "",
            "baseline": clean_text(vals[2]) if len(vals) > 2 else "",
            "fcs_cloud_control_type": "System Specific",
            "implementation_status": "System Specific",
            "vpcaas_service": "",
            "vpcaas_inheritance_source": "",
            "vpcaas_tenant": clean_text(vals[9]) if len(vals) > 9 else cid,  # full tenant responsibility
            "vpcaas_tenant_inheritance_source": "System Specific",
        }
        vpcaas_controls.append(ctrl)
        
    return {
        "tier": "vpcaas",
        "name": "VPCaaS (VPC as a Service)",
        "description": "VPCaaS 100% system-specific platform controls",
        "source_sheet": "4 - FCS Inheritance Model (VPCaaS mapping)",
        "control_count": len(vpcaas_controls),
        "controls": vpcaas_controls,
    }


class LiteralStr(str):
    """String that should be rendered as a literal block scalar."""
    pass


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


def write_tier_yaml(tier_data: dict, output_dir: Path):
    """Write tier data to YAML file."""
    if not tier_data or "tier" not in tier_data:
        return
    
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{tier_data['tier']}.yaml"
    
    # Convert long strings to literal block scalars
    tier_data = convert_to_literal_strs(tier_data)
    
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(tier_data, f, default_flow_style=False, allow_unicode=True, width=120, sort_keys=False)
    
    print(f"Wrote {tier_data['control_count']} controls to {output_path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Extract CRM service tiers from ODS file")
    parser.add_argument("input_file", help="Path to Example System_CRM_V1_20251020.xlsx.ods")
    parser.add_argument("--output-dir", "-o", default=str(TIERS_DIR), help="Output directory for tier YAML files")
    args = parser.parse_args()
    
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    
    output_dir = Path(args.output_dir)
    
    print(f"Loading {input_path}...")
    doc = load(str(input_path))
    
    # Extract each tier
    print("\nExtracting tiers...")
    
    # GSA Moderate Baseline
    gsa_moderate = extract_gsa_moderate_baseline(doc)
    write_tier_yaml(gsa_moderate, output_dir)
    
    # FCS Core
    fcs_core = extract_fcs_core(doc)
    write_tier_yaml(fcs_core, output_dir)
    
    # Get raw inheritance controls
    raw_controls, col_idx = extract_inheritance_model_controls(doc)
    
    # managed cloud service (extracted from inheritance model)
    managed-cloud-service = extract_managed-cloud-service_tier(raw_controls, col_idx)
    write_tier_yaml(managed-cloud-service, output_dir)
    
    # EBTA (cloned from managed cloud service per CRM Overview equivalence)
    ebta = extract_cloned_tier(
        managed-cloud-service, 
        "ebta", 
        "EBTA (Emerging Business Technology Application)",
        "EBTA service and tenant control responsibilities"
    )
    write_tier_yaml(ebta, output_dir)
    
    # CaaS (cloned from managed cloud service per CRM Overview equivalence)
    caas = extract_cloned_tier(
        managed-cloud-service, 
        "caas", 
        "CaaS (Container as a Service)",
        "CaaS service and tenant control responsibilities"
    )
    write_tier_yaml(caas, output_dir)
    
    # Data (cloned from managed cloud service per CRM Overview equivalence)
    data = extract_cloned_tier(
        managed-cloud-service, 
        "data", 
        "Data (Data as a Service)",
        "Data service and tenant control responsibilities"
    )
    write_tier_yaml(data, output_dir)
    
    # VPCaaS (100% system specific)
    vpcaas = build_vpcaas_tier(raw_controls, col_idx)
    write_tier_yaml(vpcaas, output_dir)
    
    print(f"\nDone. All 7 requested service tiers written to {output_dir}/")


if __name__ == "__main__":
    main()
