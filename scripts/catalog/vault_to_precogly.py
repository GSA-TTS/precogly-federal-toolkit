#!/usr/bin/env python3
"""Convert an oscal-vault system into Precogly pack YAML + CycloneDX threats.

Implements ADR-SSPP-006 Phases 1-3 (and Phase 5 batch driver via CLI).
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

from vault_reader import (
    ControlRecord,
    InheritanceEntry,
    parse_control,
    parse_inheritance,
    load_status_and_origination,
)
from heuristics import (
    ORIGINATION_TO_CONTROL_TYPE,
    STATUS_RISK,
    STATUS_TO_CDX,
    classify_control_type,
)


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_VAULT = os.path.abspath(os.path.join(ROOT, "..", "oscal-vault"))


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:40]


REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"https?://[^\s\"'>,)\]]+", re.IGNORECASE), "<REDACTED_URL>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<REDACTED_EMAIL>"),
]

# IPv4 requires each octet 0-255 and negative context to avoid clobbering NIST
# section refs like "Section 5.1.1.1". Handled separately from REDACTIONS.
_IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}"
    r"(?:/\d{1,2})?"
    r"(?![\w.])"
)
_SECTION_CTX_RE = re.compile(r"(?i)(?:section|sections|§|para\.?|paragraph)\s+$")


def _redact_ipv4(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        preceding = text[max(0, match.start() - 40): match.start()]
        if _SECTION_CTX_RE.search(preceding):
            return match.group(0)
        return "<REDACTED_IP>"

    return _IPV4_RE.sub(replace, text)


def redact(text: str | None, *, internal: bool = False) -> str:
    """Redact PII/sensitive tokens. internal=True keeps URLs/emails (build-only CDX)."""
    if not text:
        return ""
    if internal:
        # IPs still redacted even in internal-only artifacts; URLs/emails preserved
        return _redact_ipv4(text)
    out = text
    for pattern, token in REDACTIONS:
        out = pattern.sub(token, out)
    out = _redact_ipv4(out)
    return out


class _IndentDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def _str_presenter(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, _str_presenter, Dumper=_IndentDumper)


_EVIDENCE_LINK_RE = re.compile(r"\[\[(?:[^\]|]+\/)?([^\]|]+?)(?:\|[^\]]+)?\]\]")
_EVIDENCE_EMPTY_RE = re.compile(r"no evidence references recorded", re.IGNORECASE)
_EVIDENCE_KEY_MAX = 96
_URL_RE = re.compile(r"https?://[^\s\"'>,)\]]+", re.IGNORECASE)


def extract_evidence(body_evidence: str, *, internal: bool = False) -> list[dict]:
    """Return structured evidence rows from a raw Evidence markdown block.

    When internal=True, raw URLs are preserved in links[] so the build-only
    CDX can carry evidence_url for Precogly import.
    """
    if not body_evidence or _EVIDENCE_EMPTY_RE.search(body_evidence):
        return []
    rows: list[dict] = []
    for raw_line in body_evidence.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        cleaned = re.sub(r"^[-*+]\s*", "", line).strip()
        if not cleaned:
            continue
        wiki_targets = _EVIDENCE_LINK_RE.findall(cleaned)
        bare_urls = _URL_RE.findall(cleaned) if internal else []
        display_text = redact(
            _EVIDENCE_LINK_RE.sub(lambda m: m.group(1), cleaned),
            internal=internal,
        ).strip()
        if not display_text:
            continue
        key = re.sub(r"[^a-z0-9]+", "-", display_text.lower()).strip("-")[:_EVIDENCE_KEY_MAX]
        row = {"key": key or "evidence", "artifact": display_text}
        links: list[str] = []
        if wiki_targets:
            links.extend(redact(t, internal=internal) for t in wiki_targets)
        if internal and bare_urls:
            links.extend(u for u in bare_urls if u not in links)
        if links:
            row["links"] = links
        rows.append(row)
    return rows


def dump_yaml(obj: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=_IndentDumper, sort_keys=False,
                  allow_unicode=True, default_flow_style=False, width=100)


def interpolate_parameters(text: str, parameters: list[dict]) -> str:
    if not text or not parameters:
        return text
    out = text
    for param in parameters:
        pid = param.get("param_id")
        value = param.get("value")
        if not pid or value is None:
            continue
        pattern = re.compile(rf"\{{\{{\s*insert:\s*param,\s*{re.escape(pid)}\s*\}}\}}",
                             re.IGNORECASE)
        out = pattern.sub(str(value), out)
        alt = re.compile(rf"\[{re.escape(pid)}\]")
        out = alt.sub(str(value), out)
    return out


def _sort_control_key(cid: str) -> tuple[str, int, int]:
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", cid)
    if not m:
        return (cid, 10_000, 10_000)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0))


def iter_control_records(vault_root: str, system_slug: str, status_map, orig_map):
    controls_dir = os.path.join(vault_root, "examples", "vault", system_slug, "Controls")
    if not os.path.isdir(controls_dir):
        raise FileNotFoundError(f"vault system missing: {controls_dir}")
    for name in sorted(os.listdir(controls_dir)):
        if not name.endswith(".md"):
            continue
        record = parse_control(os.path.join(controls_dir, name))
        if record is None:
            continue
        target_status, status_remark = status_map.lookup(record.implementation_status)
        target_origin, origin_remark, raw_origins = orig_map.lookup(record.origination)
        record.normalized_status = record.normalized_status or target_status
        record.normalized_origination = record.normalized_origination or target_origin
        yield record, {
            "status_remark": status_remark,
            "origination_remark": origin_remark,
            "raw_origination": raw_origins,
        }


def _providing_system(entries: list[InheritanceEntry], control_id: str) -> InheritanceEntry | None:
    for entry in entries:
        if entry.control_id == control_id and entry.direction.lower() != "receives":
            return entry
    return None


def build_pack(system_slug: str,
               records: list[tuple[ControlRecord, dict]],
               inheritance: list[InheritanceEntry],
               vault_root: str) -> dict:
    component_id = slugify(system_slug)
    component_name = system_slug.replace("-", " ").title()
    components = [{
        "id": component_id,
        "name": component_name,
        "category": "external_system_actor",
        "type": "service",
        "provider": "gsa",
        "description": f"Vault-projected system {system_slug} from oscal-vault.",
    }]
    threats: list[dict] = []
    countermeasures: list[dict] = []
    ct_threats: list[dict] = []
    tc_mappings: list[dict] = []
    fw_mappings: list[dict] = []

    for record, meta in records:
        cid = record.control_id
        prose = redact(interpolate_parameters(record.combined_prose, record.parameters))
        origination = record.normalized_origination or "system-specific"
        status = record.normalized_status or "not-implemented"
        provider = _providing_system(inheritance, cid)
        threat_id = f"{component_id}-crm-{slugify(cid)}"
        cm_id = f"{component_id}-cm-{slugify(cid)}"

        parameters_block = "\n".join(
            f"- `{p.get('param_id')}` = {redact(str(p.get('value', '')))}" for p in record.parameters
            if p.get("param_id")
        )
        evidence_block = redact(record.body_sections.get("Evidence", ""))

        threat_desc_parts = [
            f"CRM responsibility for {cid} ({record.title}) on {component_name}.",
            f"Implementation status: {status}. Origination: {origination}.",
        ]
        if provider:
            threat_desc_parts.append(
                f"Provider: {provider.provider} ({provider.mode}). See inheritance table."
            )
        if prose:
            threat_desc_parts.append(prose)

        threats.append({
            "id": threat_id,
            "name": f"CRM: {cid} - {component_name}",
            "description": "\n\n".join(p for p in threat_desc_parts if p).strip(),
        })
        ct_threats.append({"threat": threat_id, "applies_to": "component"})

        control_type = ORIGINATION_TO_CONTROL_TYPE.get(origination)
        if control_type is None:
            classified = classify_control_type(origination, prose)
            control_type = "procedural" if classified in {"detective", "corrective"} else "procedural"
        cm_desc = [f"Fulfill CRM responsibility for {cid} on {component_name}."]
        if parameters_block:
            cm_desc.append("Parameters:\n" + parameters_block)
        if prose:
            cm_desc.append(prose)
        if evidence_block:
            cm_desc.append("Evidence:\n" + evidence_block)
        countermeasures.append({
            "id": cm_id,
            "name": f"Fulfill {cid} on {component_name}",
            "description": "\n\n".join(cm_desc),
            "control_type": control_type,
            "cost": "medium",
            "default_status": "gap" if status != "operational" else "implemented",
        })
        tc_mappings.append({"threat": threat_id, "countermeasures": [cm_id]})
        fw_mappings.append({"countermeasure": cm_id, "requirements": [cid], "sufficiency": "full"})

    ct_mappings = [{"component": component_id, "threats": ct_threats}]

    pack_meta = {
        "pack": {
            "schema_version": 1,
            "slug": f"{component_id}-crm",
            "name": f"{component_name} CRM Pack (vault)",
            "version": "1.0.0",
            "pack_type": "full",
            "description": f"CRM projection of oscal-vault system '{system_slug}'.",
            "author": "GSA TTSE",
            "depends_on": ["standards/nist-800-53-r5"],
            "tags": ["gsa", "crm", "vault", system_slug],
        }
    }

    return {
        "pack": pack_meta,
        "components": {"components": components},
        "threats": {"threats": threats},
        "countermeasures": {"countermeasures": countermeasures},
        "joins/components-threats": {"mappings": ct_mappings},
        "joins/threats-countermeasures": {"mappings": tc_mappings},
        "joins/countermeasures-nist-800-53-r5": {
            "framework": "nist-800-53-r5",
            "mappings": fw_mappings,
        },
        "joins/inheritance": {
            "consumer_system": system_slug,
            "entries": [
                {
                    "control_id": entry.control_id,
                    "provider_system": entry.provider,
                    "provider_owner": entry.owner or None,
                    "mode": entry.mode,
                    "direction": entry.direction,
                }
                for entry in inheritance
            ],
        },
    }


def emit_cdx(system_slug: str,
             records: list[tuple[ControlRecord, dict]],
             inheritance: list[InheritanceEntry],
             out_path: str,
             *,
             internal: bool = False) -> dict:
    component_id = slugify(system_slug)
    component_name = system_slug.replace("-", " ").title()
    asset_ref = f"asset-{component_id}"
    zone_ref = f"zone-{component_id}"

    # Build external zones/assets/flows from inheritance table.
    # Each unique provider becomes its own lower-trust zone + asset.
    # Each inherited/hybrid control link becomes a directed flow.
    provider_slugs: dict[str, str] = {}  # provider name -> bom-ref prefix
    ext_zones: list[dict] = []
    ext_assets: list[dict] = []
    dfd_flows: list[dict] = []

    # DFD canvas nodes and edges (built alongside the blueprint data)
    _dfd_nodes: list[dict] = []
    _dfd_edges: list[dict] = []
    for entry in inheritance:
        pslug = slugify(entry.provider)
        if pslug not in provider_slugs:
            provider_slugs[pslug] = pslug
            ext_zones.append({
                "bom-ref": f"zone-ext-{pslug}",
                "name": entry.provider,
                "type": "trust",
                "trustLevel": 10,
            })
            ext_assets.append({
                "bom-ref": f"asset-ext-{pslug}",
                "name": entry.provider,
                "type": "service",
                "zone": f"zone-ext-{pslug}",
            })
        mode = entry.mode.lower() if entry.mode else "inherited"
        dfd_flows.append({
            "bom-ref": f"flow-{pslug}-{slugify(entry.control_id)}",
            "name": f"{entry.control_id} ({mode})",
            "source": f"asset-ext-{pslug}",
            "destination": asset_ref,
            "crosses_trust_zone": True,  # P2-C: provider zones are always lower-trust
            "authenticated": mode in ("hybrid", "shared"),
            "properties": [
                {"name": "nist:control-id", "value": entry.control_id},
                {"name": "vault:inheritance-mode", "value": mode},
            ],
        })

    blueprint = {
        "bom-ref": f"blueprint-{component_id}",
        "name": component_name,
        "modelTypes": ["data-flow"],
        "zones": [{
            "bom-ref": zone_ref,
            "name": component_name,
            "type": "trust",
            "trustLevel": 40,
        }] + ext_zones,
        "assets": [{
            "bom-ref": asset_ref,
            "name": component_name,
            "type": "system",
            "zone": zone_ref,
        }] + ext_assets,
        "flows": dfd_flows,
        "visualizations": [{
            "type": "precogly-dfd",
            "name": f"{component_name} Data Flow Diagram",
            "diagramType": "level1",
            "data": {"nodes": _dfd_nodes, "edges": _dfd_edges},
        }],
    }
    threats: list[dict] = []
    scenarios: list[dict] = []
    controls: list[dict] = []
    seq = 0

    # System scope wrapper
    _dfd_nodes.append({
        "id": f"scope-{component_id}",
        "type": "systemScope",
        "data": {"label": component_name, "orgsystem_id": None},  # id resolved at import
        "style": {"width": max(600, 200 + 250 * len(ext_assets)), "height": 400},
        "position": {"x": 50, "y": 50},
    })

    # Internal system node (process type represents the boundary system)
    _dfd_nodes.append({
        "id": f"process-{component_id}",
        "type": "process",
        "data": {"label": component_name, "component_id": None},
        "parentId": f"scope-{component_id}",
        "position": {"x": 60 + 250 * len(ext_assets) // 2, "y": 160},
    })

    # External provider nodes — anchored inside their own external scope node (P1-B)
    x_step = 220
    for idx, (pslug, _) in enumerate(provider_slugs.items()):
        ext_name = next(e.provider for e in inheritance if slugify(e.provider) == pslug)
        ext_scope_id = f"scope-ext-{pslug}"
        _dfd_nodes.append({
            "id": ext_scope_id,
            "type": "systemScope",
            "data": {"label": ext_name, "orgsystem_id": None},
            "style": {"width": 180, "height": 120},
            "position": {"x": 50 + idx * x_step, "y": 30},
        })
        _dfd_nodes.append({
            "id": f"actor-ext-{pslug}",
            "type": "systemActor",
            "data": {"label": ext_name, "systemType": "service", "component_id": None},
            "parentId": ext_scope_id,
            "position": {"x": 20, "y": 40},
        })

    # One edge per provider per NIST family (P2-B: semantic grouping)
    from collections import defaultdict
    family_flows: dict[tuple[str, str], list] = defaultdict(list)
    for entry in inheritance:
        pslug = slugify(entry.provider)
        family = entry.control_id.split("-")[0].upper()
        family_flows[(pslug, family)].append(entry)

    for (pslug, family), entries in sorted(family_flows.items()):
        modes = sorted({e.mode.lower() for e in entries if e.mode})
        mode_label = "/".join(modes) if modes else "inherited"
        is_authenticated = any(e.mode.lower() in ("hybrid", "shared") for e in entries if e.mode)
        _dfd_edges.append({
            "id": f"edge-{pslug}-{family.lower()}-to-{component_id}",
            "type": "dataFlow",
            "source": f"actor-ext-{pslug}",
            "target": f"process-{component_id}",
            "data": {
                "label": f"{family} ({mode_label}, {len(entries)})",
                "encrypted": False,
                "authenticated": is_authenticated,
            },
        })

    for record, meta in records:
        seq += 1
        cid = record.control_id
        status = record.normalized_status or "not-implemented"
        origination = record.normalized_origination or "system-specific"
        prose = redact(interpolate_parameters(record.combined_prose, record.parameters))
        cdx_status = STATUS_TO_CDX.get(status, "recommended")
        risk = STATUS_RISK.get(status, "medium")

        # Skip not-applicable controls (no threat, no countermeasure).
        if status == "not-applicable":
            continue

        # Normalize NIST enhancement notation "AC-2(1)" -> "AC-2-1" before
        # slugifying, so enhancements don't collide with base controls that
        # share the same digits (e.g. "AC-2(1)" and "AC-21" both slugify to
        # "ac-21" without this normalization).
        cid_slug = cid.replace("(", "-").replace(")", "")
        # Also normalize the display form used in threat names so that
        # Django's slugify on the threat name produces distinct slugs.
        cid_display = cid.replace("(", "-").replace(")", "")
        t_ref = f"threat-{slugify(cid_slug)}-{seq}"
        s_ref = f"scenario-{slugify(cid_slug)}-{seq}"
        c_ref = f"control-{slugify(cid_slug)}-{seq}"

        provider = _providing_system(inheritance, cid)
        properties = [
            {"name": "nist:control-id", "value": cid},
            {"name": "vault:implementation-status", "value": status},
            {"name": "vault:origination", "value": origination},
        ]
        for param in record.parameters:
            pid = param.get("param_id")
            if pid:
                properties.append({
                    "name": f"vault:param:{pid}",
                    "value": redact(str(param.get("value", ""))),
                })
        if meta.get("raw_origination"):
            properties.append({
                "name": "vault:origination-raw",
                "value": ",".join(meta["raw_origination"]),
            })
        if provider:
            properties.append({"name": "vault:providing-system", "value": provider.provider})
            properties.append({"name": "vault:inheritance-mode", "value": provider.mode})

        threat_desc = [
            f"CRM responsibility for {cid} ({record.title}) on {component_name}.",
            f"Implementation status: {status}. Origination: {origination}.",
        ]
        if provider:
            threat_desc.append(
                f"Provider: {provider.provider} ({provider.mode})."
            )
        if prose:
            threat_desc.append(prose)
        # Only emit a threat if there is residual risk (status != operational
        # implies open exposure). Operational controls still get a countermeasure
        # linked to the base risk to record evidence.
        emit_threat = status != "operational"
        if emit_threat:
            threats.append({
                "bom-ref": t_ref,
                "name": f"CRM: {cid_display} residual risk - {component_name}",
                "description": "\n\n".join(threat_desc),
                "affectedAssets": [asset_ref],
                "properties": properties,
                "mitigations": [c_ref],
            })
            # One scenario per threat; list non-empty parts as properties to avoid
            # violating the unique(component_id, threat_library_id) DB constraint.
            emitted_parts = [p for p in record.parts if p.prose.strip()]
            scenario_entry: dict = {
                "bom-ref": s_ref,
                "threat": t_ref,
                "affectedAssets": [asset_ref],
                "riskScore": {"level": risk},
            }
            if emitted_parts:
                scenario_entry["properties"] = [
                    {"name": "vault:statement-part", "value": p.part}
                    for p in emitted_parts
                ]
            scenarios.append(scenario_entry)

        control_category = classify_control_type(origination, prose)
        control_type = ORIGINATION_TO_CONTROL_TYPE.get(origination) or "procedural"
        control_desc = [
            f"Fulfills CRM responsibility for {cid} on {component_name}.",
        ]
        parameters_block = "\n".join(
            f"- {p.get('param_id')} = {redact(str(p.get('value', '')))}"
            for p in record.parameters if p.get("param_id")
        )
        if parameters_block:
            control_desc.append("Parameters:\n" + parameters_block)
        if prose:
            control_desc.append(prose)
        evidence_block = redact(record.body_sections.get("Evidence", ""), internal=internal)
        evidence_rows = extract_evidence(record.body_sections.get("Evidence", ""), internal=internal)
        if evidence_block:
            control_desc.append("Evidence:\n" + evidence_block)

        control_properties = [
            {"name": "vault:control-type", "value": control_type},
            {"name": "nist:control-id", "value": cid},
            {"name": "vault:implementation-status", "value": status},
            {"name": "vault:origination", "value": origination},
        ]
        if provider:
            control_properties.append({"name": "vault:providing-system", "value": provider.provider})
            control_properties.append({"name": "vault:inheritance-mode", "value": provider.mode})
        for param in record.parameters:
            pid = param.get("param_id")
            if pid:
                control_properties.append({
                    "name": f"vault:param:{pid}",
                    "value": redact(str(param.get("value", ""))),
                })
        for idx, row in enumerate(evidence_rows):
            control_properties.append({"name": "crm:evidence-key", "value": row["key"]})
            control_properties.append({"name": "crm:evidence-artifact", "value": row["artifact"]})
            for link in row.get("links", []):
                control_properties.append({"name": "crm:evidence-link", "value": link})

        # P2-A: first HTTP evidence link as externalReference for evidence_url import
        first_evidence_url = next(
            (lnk for row in evidence_rows for lnk in row.get("links", []) if lnk.startswith("http")),
            None,
        )

        control_entry: dict = {
            "bom-ref": c_ref,
            "name": f"{cid} implementation - {component_name}",
            "status": cdx_status,
            "description": "\n\n".join(control_desc),
            "category": control_category,
            "properties": control_properties,
            "appliesTo": [asset_ref],
            "mitigations": [t_ref] if emit_threat else [],
            # P3-A: NIST 800-53 compliance linkage
            "satisfies": [{"reference": cid, "framework": "nist-800-53-r5"}],
        }
        if first_evidence_url:
            control_entry["externalReferences"] = [{"type": "evidence", "url": first_evidence_url}]
        controls.append(control_entry)

    cdx = {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "properties": [
                {"name": "vault:system-slug", "value": system_slug},
                {"name": "vault:source", "value": "oscal-vault"},
                {"name": "adr", "value": "ADR-SSPP-006"},
            ],
        },
        "blueprints": [blueprint],
        "threats": {"threats": threats, "scenarios": scenarios},
        "controls": controls,
    }

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return {
        "threats": len(threats),
        "controls": len(controls),
        "scenarios": len(scenarios),
    }


def write_pack(system_slug: str, pack: dict, out_dir: str) -> None:
    slug = slugify(system_slug)
    base = os.path.join(out_dir, "pack")
    dump_yaml(pack["pack"], os.path.join(base, "pack.yaml"))
    dump_yaml(pack["components"], os.path.join(base, "components.yaml"))
    dump_yaml(pack["threats"], os.path.join(base, "threats.yaml"))
    dump_yaml(pack["countermeasures"], os.path.join(base, "countermeasures.yaml"))
    for key in ("joins/components-threats", "joins/threats-countermeasures",
                "joins/countermeasures-nist-800-53-r5", "joins/inheritance"):
        dump_yaml(pack[key], os.path.join(base, f"{key}.yaml"))


def convert_system(vault_root: str, system_slug: str, out_dir: str,
                   status_map, orig_map, *, internal: bool = False) -> dict:
    records = list(iter_control_records(vault_root, system_slug, status_map, orig_map))
    inheritance_dir = os.path.join(vault_root, "examples", "vault", system_slug, "Inheritance")
    inheritance: list[InheritanceEntry] = []
    if os.path.isdir(inheritance_dir):
        for name in sorted(os.listdir(inheritance_dir)):
            if name.endswith(".md"):
                inheritance.extend(parse_inheritance(os.path.join(inheritance_dir, name)))
    pack = build_pack(system_slug, records, inheritance, vault_root)
    write_pack(system_slug, pack, out_dir)
    cdx_stats = emit_cdx(system_slug, records, inheritance,
                          os.path.join(out_dir, f"{slugify(system_slug)}.cdx.json"),
                          internal=internal)
    stats = {
        "controls_parsed": len(records),
        "threats": cdx_stats["threats"],
        "countermeasures": cdx_stats["controls"],
        "inheritance_entries": len(inheritance),
    }
    with open(os.path.join(out_dir, "import-summary.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump({"system": system_slug, "stats": stats}, f, sort_keys=False)
    return stats


def enumerate_systems(vault_root: str) -> list[str]:
    root = os.path.join(vault_root, "examples", "vault")
    return sorted(
        name for name in os.listdir(root)
        if os.path.isdir(os.path.join(root, name, "Controls"))
    )


def enumerate_skipped_systems(vault_root: str) -> list[dict]:
    root = os.path.join(vault_root, "examples", "vault")
    skipped: list[dict] = []
    for name in sorted(os.listdir(root)):
        system_dir = os.path.join(root, name)
        if not os.path.isdir(system_dir):
            continue
        if os.path.isdir(os.path.join(system_dir, "Controls")):
            continue
        skipped.append({
            "system": name,
            "reason": "no Controls/ directory in vault",
            "vault_path": os.path.relpath(system_dir, ROOT) if system_dir.startswith(ROOT) else system_dir,
        })
    return skipped


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vault-root", default=DEFAULT_VAULT,
                    help="Path to the sibling oscal-vault checkout.")
    ap.add_argument("--system", action="append",
                    help="Vault system slug (repeatable). Use --all for all systems.")
    ap.add_argument("--all", action="store_true", help="Convert every vault system.")
    ap.add_argument("--internal", action="store_true",
                    help="Preserve URLs/emails in build/ CDX (internal artifacts only).")
    ap.add_argument("--out-root", default=os.path.join(ROOT, "build", "systems"),
                    help="Output root directory (build/systems by default).")
    args = ap.parse_args()

    vault_root = os.path.abspath(args.vault_root)
    if not os.path.isdir(vault_root):
        print(f"FAIL: vault_root not a directory: {vault_root}", file=sys.stderr)
        sys.exit(2)

    status_map, orig_map = load_status_and_origination(vault_root)

    systems = list(args.system or [])
    if args.all:
        systems.extend(enumerate_systems(vault_root))
    systems = sorted(dict.fromkeys(systems))
    if not systems:
        print("FAIL: no systems requested; pass --system SLUG or --all", file=sys.stderr)
        sys.exit(2)

    summary = []
    for system in systems:
        out_dir = os.path.join(args.out_root, slugify(system))
        try:
            stats = convert_system(vault_root, system, out_dir, status_map, orig_map,
                                   internal=args.internal)
        except FileNotFoundError as exc:
            print(f"SKIP {system}: {exc}", file=sys.stderr)
            continue
        summary.append({"system": system, **stats})
        print(f"{system}: controls={stats['controls_parsed']} "
              f"threats={stats['threats']} countermeasures={stats['countermeasures']} "
              f"inheritance={stats['inheritance_entries']}",
              file=sys.stderr)

    os.makedirs(args.out_root, exist_ok=True)
    index_path = os.path.join(args.out_root, "index.yaml")
    with open(index_path, "w", encoding="utf-8") as f:
        yaml.safe_dump({
            "vault_root": os.path.relpath(vault_root, ROOT) if vault_root.startswith(ROOT) else vault_root,
            "generated_at": datetime.now(UTC).isoformat(),
            "systems": summary,
        }, f, sort_keys=False)
    print(f"Wrote {os.path.relpath(index_path, ROOT)}", file=sys.stderr)

    skipped = enumerate_skipped_systems(vault_root) if args.all else []
    if args.all:
        skipped_path = os.path.join(args.out_root, "skipped.yaml")
        with open(skipped_path, "w", encoding="utf-8") as f:
            yaml.safe_dump({
                "vault_root": os.path.relpath(vault_root, ROOT) if vault_root.startswith(ROOT) else vault_root,
                "generated_at": datetime.now(UTC).isoformat(),
                "skipped": skipped,
            }, f, sort_keys=False)
        print(f"Wrote {os.path.relpath(skipped_path, ROOT)} ({len(skipped)} skipped)", file=sys.stderr)


if __name__ == "__main__":
    main()
