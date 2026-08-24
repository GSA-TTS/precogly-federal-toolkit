#!/usr/bin/env python3
"""Convert OSCAL Component Definition JSON files into a generic Precogly Pack.

Given one or more OSCAL Component Definition files (published under
``gsa-pages/component-definitions/<component>/component-definition.json``),
this script produces:

  1. A standard Precogly Technology Pack (pack_type: full) under pack/
     containing:
       - pack.yaml
       - components.yaml (one component per CRM source)
       - threats.yaml (each responsibility control becomes a threat)
       - countermeasures.yaml (procedural controls to satisfy the responsibilities)
       - joins/components-threats.yaml
       - joins/threats-countermeasures.yaml
       - joins/countermeasures-nist-800-53-r5.yaml (compliance mappings)

  2. A companion Precogly Compliance Pack (pack_type: compliance) under
     pack-oscal-800-53r5/ containing:
       - pack.yaml (populates the nist-800-53-r5 framework with the exact
         requirements observed across the parsed files, enriched with NIST catalog titles).

This represents a clean separation of concerns and uses native Precogly library patterns.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterable

import yaml

# Standard paths relative to root of this template
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACK_DIR = os.path.join(ROOT, "pack")
COMPLIANCE_DIR = os.path.join(ROOT, "pack-oscal-800-53r5")


# ---------------------------------------------------------------------------
# Redaction Policy (identical to pipeline scripts to ensure privacy compliance)
# ---------------------------------------------------------------------------
REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"https?://docs\.google\.com/[^\s\"'>,)]*", re.IGNORECASE),
        "<INTERNAL_GOOGLE_DOC>",
    ),
    (
        re.compile(
            r"https?://[A-Za-z0-9.-]*\.cloud\.data-platform\.com[^\s\"'>,)]*",
            re.IGNORECASE,
        ),
        "<DATA-PLATFORM_WORKSPACE_URL>",
    ),
    (
        re.compile(r"\b[A-Za-z0-9-]+\.cloud\.data-platform\.com\b", re.IGNORECASE),
        "<DATA-PLATFORM_WORKSPACE_HOST>",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "<POC_EMAIL>",
    ),
    (
        re.compile(r"\bhttps?://[^\s\"'>,)]+", re.IGNORECASE),
        "<REDACTED_URL>",
    ),
]


def redact(text: str | None) -> str:
    if not text:
        return ""
    for pattern, token in REDACTIONS:
        text = pattern.sub(token, text)
    return text


def clean(v: str | None) -> str:
    if not v:
        return ""
    # Strip trailing whitespace per line to ensure PyYAML uses block scalars (|)
    lines = [line.rstrip() for line in v.splitlines()]
    joined = "\n".join(lines)
    return redact(joined).strip()


# ---------------------------------------------------------------------------
# Control-ID Normalization (collapses dotted and lowercase variations)
# ---------------------------------------------------------------------------
_ID_RE = re.compile(
    r"^\s*([A-Za-z]{2})-?0*(\d+)"  # family + base number
    r"(?:\s*[.(]\s*0*(\d+)\s*\)?)?"  # optional .N or (N) enhancement
    r"(?:\s*_?smt\.?[a-z0-9.]*)?\s*$",  # tolerate statement-id suffix
    re.IGNORECASE,
)


def normalize_control_id(raw: str) -> str:
    """Return the canonical NIST rendering of an OSCAL control id.

    ``ac-2``   -> ``AC-2``
    ``ac-6.5`` -> ``AC-6(5)``
    """
    if not raw:
        return ""
    m = _ID_RE.match(raw)
    if not m:
        return raw.strip()
    fam, num, enh = m.group(1).upper(), int(m.group(2)), m.group(3)
    cid = f"{fam}-{num}"
    if enh is not None:
        cid = f"{cid}({int(enh)})"
    return cid


def slugify(text: str) -> str:
    """Return a clean slug (lowercase alphanumeric with hyphens)."""
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:40]


def sort_key(cid: str) -> tuple[str, int, int]:
    """Sort family-then-numeric so AC-2 precedes AC-10."""
    m = re.match(r"^([A-Za-z]{2})-(\d+)(?:\((\d+)\))?$", cid)
    if not m:
        return (cid, 10_000, 10_000)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0))


# ---------------------------------------------------------------------------
# OSCAL Parsing Helper Functions
# ---------------------------------------------------------------------------
def _props(items: Iterable[dict] | None, name: str) -> list[str]:
    return [p.get("value", "") for p in (items or []) if p.get("name") == name]


def _component_rule_index(component: dict) -> dict[str, str]:
    by_remark: dict[str, dict[str, str]] = {}
    for p in component.get("props", []) or []:
        remark = p.get("remarks")
        if not remark or p.get("name") not in ("Rule_Id", "Rule_Description"):
            continue
        key = "id" if p["name"] == "Rule_Id" else "desc"
        by_remark.setdefault(remark, {})[key] = p.get("value", "")
    return {v["id"]: v.get("desc", "") for v in by_remark.values() if "id" in v}


def _render_responsibility(ir: dict, rules: dict[str, str]) -> str:
    blocks: list[str] = []
    if ir.get("description"):
        blocks.append(clean(ir["description"]))
    stmts = ir.get("statements") or []
    if stmts:
        lines: list[str] = []
        for st in stmts:
            sid = st.get("statement-id", "").strip()
            desc = clean(st.get("description"))
            rule_ids = _props(st.get("props"), "Rule_Id")
            rule_notes = [
                f"[{rid}] {clean(rules.get(rid, ''))}".strip()
                for rid in rule_ids
                if rid in rules
            ]
            head = f"- {sid}:" if sid else "-"
            body = desc or ""
            trailer = f" ({'; '.join(rule_notes)})" if rule_notes else ""
            lines.append(f"{head} {body}{trailer}".strip())
        if lines:
            blocks.append("Statements:\n" + "\n".join(lines))
    return "\n\n".join(b for b in blocks if b)


# ---------------------------------------------------------------------------
# NIST Catalog Lookup (optional -- populates human titles/descriptions)
# ---------------------------------------------------------------------------
def load_catalog(path: str | None) -> tuple[dict[str, str], dict[str, str]]:
    titles: dict[str, str] = {}
    descs: dict[str, str] = {}
    if not path or not os.path.exists(path):
        return titles, descs
    with open(path, encoding="utf-8") as f:
        cat = json.load(f).get("catalog", {})

    def walk(controls: list[dict]) -> None:
        for c in controls or []:
            cid = normalize_control_id(c.get("id", ""))
            title = c.get("title") or ""
            desc = ""
            for p in c.get("parts", []) or []:
                if p.get("name") == "guidance" or p.get("prose"):
                    desc = clean(p.get("prose") or "")
                    break
            if cid:
                if title:
                    titles[cid] = title
                if desc:
                    descs[cid] = desc
            walk(c.get("controls") or [])

    for group in cat.get("groups", []) or []:
        walk(group.get("controls") or [])
    return titles, descs


# ---------------------------------------------------------------------------
# YAML Serialization Configuration
# ---------------------------------------------------------------------------
class _IndentDumper(yaml.Dumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow, False)


def _str_presenter(dumper, data):
    """Force multi-line strings to render as literal block scalars (using |)."""
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, _str_presenter, Dumper=_IndentDumper)


def dump_yaml(obj: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(
            obj,
            f,
            Dumper=_IndentDumper,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
            width=100,
        )


# ---------------------------------------------------------------------------
# Core Conversion Logic
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("sources", nargs="+", help="OSCAL component-definition.json files")
    ap.add_argument("--catalog", help="Path to NIST 800-53 catalog JSON")
    args = ap.parse_args()

    titles, descs = load_catalog(args.catalog)

    # Accumulators for generated entities
    components_list: list[dict] = []
    threats_dict: dict[str, dict] = {}
    countermeasures_dict: dict[str, dict] = {}
    ct_mappings: list[dict] = []
    tc_mappings: list[dict] = []
    fw_mappings: list[dict] = []

    framework_requirements: dict[str, str] = {}

    sources = []
    for src in args.sources:
        if "=" in src:
            explicit_name, path = src.split("=", 1)
            sources.append((explicit_name or None, path))
        else:
            sources.append((None, src))

    for explicit_name, src_path in sources:
        with open(src_path, encoding="utf-8") as f:
            data = json.load(f)
        cd = data["component-definition"]
        meta_title = cd.get("metadata", {}).get("title", "")
        slug = slugify(
            explicit_name or meta_title or os.path.basename(os.path.dirname(src_path))
        )

        components = cd.get("components", []) or []
        if not components:
            continue

        comp = components[0]
        rules = _component_rule_index(comp)

        # 1. Create technology component representing this CRM source
        components_list.append(
            {
                "id": slug,
                "name": comp.get("title", meta_title or slug),
                "category": "external_system_actor",
                "type": comp.get("type", "SaaS"),
                "provider": "gsa",
                "description": clean(comp.get("description", "")),
            }
        )

        component_threat_refs: list[str] = []

        # 2. Iterate control implementations to extract threats & countermeasures
        for ci in comp.get("control-implementations", []) or []:
            for ir in ci.get("implemented-requirements", []) or []:
                raw_cid = ir.get("control-id", "")
                cid = normalize_control_id(raw_cid)
                if not cid:
                    continue

                # Add this requirement to our compliance framework index
                framework_requirements[cid] = titles.get(cid, cid)

                # Threat representing the risk of customer failing to address this CRM
                threat_id = f"{slug}-crm-{slugify(cid)}"
                threat_name = f"CRM: {cid} Responsibility Gap - {comp.get('title')}"
                threat_desc = clean(
                    f"A customer responsibility gap exists for {cid} on {comp.get('title')}.\n"
                    f"Unfulfilled requirements:\n\n"
                    f"{_render_responsibility(ir, rules)}"
                )

                threats_dict[threat_id] = {
                    "id": threat_id,
                    "name": threat_name,
                    "description": threat_desc,
                }
                component_threat_refs.append(threat_id)

                # Countermeasure to fulfill this specific responsibility
                cm_id = f"crm-fulfill-{slugify(cid)}-on-{slug}"
                cm_name = f"Fulfill CRM responsibility for {cid} on {comp.get('title')}"
                cm_desc = clean(
                    f"Implement, document, and monitor the tenant-side obligations\n"
                    f"asserted in the CRM for {cid}. Factual actions mapped:\n\n"
                    f"{_render_responsibility(ir, rules)}"
                )

                countermeasures_dict[cm_id] = {
                    "id": cm_id,
                    "name": cm_name,
                    "description": cm_desc,
                    "control_type": "procedural",
                    "cost": "medium",
                    "default_status": "gap",
                }

                # Threat -> Countermeasure join mapping
                tc_mappings.append(
                    {
                        "threat": threat_id,
                        "countermeasures": [cm_id],
                    }
                )

                # Countermeasure -> Compliance framework join mapping
                fw_mappings.append(
                    {
                        "countermeasure": cm_id,
                        "requirements": [cid],
                        "sufficiency": "full",
                    }
                )

        # Component -> Threats mapping
        ct_mappings.append(
            {
                "component": slug,
                "threats": [
                    {"threat": tid, "applies_to": "component"}
                    for tid in component_threat_refs
                ],
            }
        )

    # Sort everything deterministically by ID to stay versioning-safe
    threats_list = [threats_dict[k] for k in sorted(threats_dict)]
    countermeasures_list = [
        countermeasures_dict[k] for k in sorted(countermeasures_dict)
    ]
    tc_mappings = sorted(tc_mappings, key=lambda m: m["threat"])
    fw_mappings = sorted(fw_mappings, key=lambda m: m["countermeasure"])
    ct_mappings = sorted(ct_mappings, key=lambda m: m["component"])

    # Write Technology Pack
    dump_yaml(
        {
            "pack": {
                "schema_version": 1,
                "slug": "generic-crm-technology",
                "name": "Generic CRM Technology Pack",
                "version": "1.0.0",
                "pack_type": "full",
                "description": "Standard threat library representing shared-responsibility boundaries.",
                "author": "GSA TTSE",
                "depends_on": ["standards/nist-800-53-r5"],
                "tags": ["gsa", "crm", "compliance", "government"],
            }
        },
        os.path.join(PACK_DIR, "pack.yaml"),
    )
    dump_yaml(
        {"components": components_list}, os.path.join(PACK_DIR, "components.yaml")
    )
    dump_yaml({"threats": threats_list}, os.path.join(PACK_DIR, "threats.yaml"))
    dump_yaml(
        {"countermeasures": countermeasures_list},
        os.path.join(PACK_DIR, "countermeasures.yaml"),
    )
    dump_yaml(
        {"mappings": ct_mappings},
        os.path.join(PACK_DIR, "joins", "components-threats.yaml"),
    )
    dump_yaml(
        {"mappings": tc_mappings},
        os.path.join(PACK_DIR, "joins", "threats-countermeasures.yaml"),
    )
    dump_yaml(
        {
            "framework": "nist-800-53-r5",
            "mappings": fw_mappings,
        },
        os.path.join(PACK_DIR, "joins", "countermeasures-nist-800-53-r5.yaml"),
    )

    # Write Compliance Pack (NIST 800-53 r5 framework requirement definitions)
    compliance_reqs = [
        {
            "section_code": cid,
            "description": f"{titles.get(cid, cid)}: {descs.get(cid, 'Obligations to meet for this control.')}",
        }
        for cid in sorted(framework_requirements, key=sort_key)
    ]

    dump_yaml(
        {
            "pack": {
                "schema_version": 1,
                "slug": "nist-800-53-r5",
                "name": "NIST SP 800-53 Rev. 5",
                "version": "5.0.0",
                "pack_type": "compliance",
                "description": "NIST 800-53 Rev 5 compliance requirements generated from parsed OSCAL files.",
                "author": "NIST",
                "tags": ["compliance", "security", "government"],
            },
            "frameworks": [
                {
                    "slug": "nist-800-53-r5",
                    "name": "NIST SP 800-53 Rev. 5",
                    "version": "5",
                    "issuer": "NIST",
                    "description": "Security and Privacy Controls for Information Systems and Organizations",
                    "requirements": compliance_reqs,
                }
            ],
        },
        os.path.join(COMPLIANCE_DIR, "pack.yaml"),
    )

    print(
        f"Generated Technology Pack with {len(components_list)} components, "
        f"{len(threats_list)} threats, and {len(countermeasures_list)} countermeasures.\n"
        f"Generated Compliance Pack with {len(compliance_reqs)} requirements.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
