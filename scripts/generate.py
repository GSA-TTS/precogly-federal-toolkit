#!/usr/bin/env python3
"""Generate the Example System CRM threat-model CycloneDX (Precogly-native) JSON.

Emits top-level controls[] linked bidirectionally to threats by bom-ref so
countermeasures survive a Precogly editor round-trip.  One control per evidence
MECHANISM, reused many-to-many.

Output: build/example-system-crm-threat-model.cdx.json (default; --out to override).
"""

import argparse
import json
import os
import re
import sys
import uuid
from pathlib import Path

import yaml

try:
    from scripts.control_identity import canonical_control_id
    from scripts.tmbom_standards import project_nist_standard
    from scripts.tmbom_topology import project_tmbom_topology
except ModuleNotFoundError:  # Support direct invocation as a script.
    from control_identity import canonical_control_id
    from tmbom_standards import project_nist_standard
    from tmbom_topology import project_tmbom_topology

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")

# scripts/systems is not on PYTHONPATH when running via ``uv run python
# scripts/generate.py``; prepend HERE so ``from systems.loader import ...``
# resolves without requiring callers to set PYTHONPATH.
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from flow_auth import auth_mechanism_properties, load_auth_catalog, load_auth_metadata  # noqa: E402
from flow_refs import resolve_flow_bindings, resolve_flow_overrides  # noqa: E402
from systems.hosting import (  # noqa: E402
    compose_hosting_overlay,
    load_hosting_overlay,
)
from systems.loader import DEFAULT_SYSTEM, SystemPaths, load_system  # noqa: E402

_CDX_UUID_NS = uuid.UUID("f9d1dea1-0000-4000-8000-000000000002")
_STABLE_TIMESTAMP = "1970-01-01T00:00:00.000Z"

# Precogly slug rule (derived empirically from an editor export):
#   lowercase -> non-alphanumeric collapsed to '-' -> truncate to 40 chars
#   (trailing '-' kept) -> prefixed 'threat-'/'control-' -> suffix '-<seq>'.
SLUG_CAP = 40

STRATEGY_TO_CATEGORY = {
    "PREVENTIVE": "preventive",
    "DETECTIVE": "detective",
    "CORRECTIVE": "corrective",
}

# Map CRM inheritance string → ADR-015 responsibility_source enum.
_INHERIT_TENANT_KEYWORDS = ("tenant", "system specific")


def _responsibility_source(inheritance: str) -> str:
    """Classify CRM inheritance string into the ADR-015 responsibility_source enum."""
    s = (inheritance or "").lower()
    if not s:
        return "tenant"
    if s == "tenant" or s == "system specific":
        return "tenant"
    if "fedramp" in s:
        return "fedramp-inherited"
    # Any hybrid that mentions tenant is shared; pure platform = platform-inherited
    if "tenant" in s:
        return "shared"
    return "platform-inherited"


def load_yaml(*parts):
    with open(os.path.join(DATA, *parts), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_yaml_path(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def slug(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:SLUG_CAP]


def family(cid):
    return cid.split("-", 1)[0]


def by_id(doc):
    result = {}
    for control in doc.get("controls", []):
        cid = canonical_control_id(control["control_id"])
        if cid in result:
            raise ValueError(f"duplicate canonical control ID: {cid}")
        control["control_id"] = cid
        result[cid] = control
    return result


def merge_properties(existing, additions):
    """Merge CycloneDX-style name/value properties by name."""
    merged = list(existing or [])
    by_name = {p.get("name"): p for p in merged if p.get("name")}
    for prop in additions or []:
        name = prop.get("name")
        if not name:
            continue
        if name in by_name:
            by_name[name]["value"] = prop.get("value", "")
        else:
            new_prop = {"name": name, "value": prop.get("value", "")}
            merged.append(new_prop)
            by_name[name] = new_prop
    return merged


def apply_architecture_overrides(cdx, arch):
    """Apply ADR-005 DFD enrichments managed outside the editor export."""
    allowed_auth, warning_auth = load_auth_catalog(arch=arch)
    auth_metadata = load_auth_metadata(arch=arch)
    known_auth = allowed_auth | set(warning_auth)
    bp = cdx["blueprints"][0]
    zones = {z["bom-ref"]: z for z in bp.get("zones", [])}
    for zref, override in arch.get("zone_overrides", {}).items():
        if zref not in zones:
            raise KeyError(f"zone override references unknown zone: {zref}")
        zone = zones[zref]
        if override.get("parentZone"):
            parent = override["parentZone"]
            if parent not in zones:
                raise KeyError(f"zone {zref} parentZone references unknown zone: {parent}")
            zone["parentZone"] = parent
        if override.get("properties"):
            zone["properties"] = merge_properties(zone.get("properties", []), override["properties"])
    assets = {a["bom-ref"]: a for a in bp.get("assets", [])}
    for aref, override in arch.get("asset_overrides", {}).items():
        if aref not in assets:
            raise KeyError(f"asset override references unknown asset: {aref}")
        asset = assets[aref]
        if override.get("zone"):
            zref = override["zone"]
            if zref not in zones:
                raise KeyError(f"asset {aref} zone references unknown zone: {zref}")
            asset["zone"] = zref
        if override.get("properties"):
            asset["properties"] = merge_properties(asset.get("properties", []), override["properties"])
    flows = {f["bom-ref"]: f for f in bp.get("flows", [])}
    flow_overrides, flow_errors = resolve_flow_overrides(arch, bp)
    if flow_errors:
        raise KeyError("; ".join(flow_errors))
    for fref, override in flow_overrides.items():
        if fref not in flows:
            raise KeyError(f"flow override references unknown flow: {fref}")
        flow = flows[fref]
        if override.get("protocols"):
            flow["protocols"] = list(override["protocols"])
        auth = override.get("authMechanism")
        if auth:
            if auth not in known_auth:
                raise ValueError(f"flow {fref} uses unsupported authMechanism: {auth}")
            flow["authMechanism"] = auth
            flow["properties"] = merge_properties(
                flow.get("properties", []),
                auth_mechanism_properties(auth, metadata=auth_metadata),
            )
        for field in ("encrypted", "crosses_trust_zone", "data_classification"):
            val = override.get(field)
            if val is None:
                continue
            flow[field] = val
            prop_name = f"resp:{field.replace('_', '-')}"
            flow["properties"] = merge_properties(
                flow.get("properties", []),
                [
                    {
                        "name": prop_name,
                        "value": str(val).lower() if isinstance(val, bool) else val,
                    }
                ],
            )


def build_mitigation_text(cid, mc, db):
    blocks = []
    if mc and mc.get("responsibility"):
        blocks.append("== managed cloud service Tenant Responsibility ==\n" + mc["responsibility"])
    if db:
        five_w = [
            f"{l}: {db[k]}"
            for l, k in (
                ("WHO", "who"),
                ("WHAT", "what"),
                ("HOW", "how"),
                ("WHEN", "when"),
                ("WHERE (evidence source)", "where"),
            )
            if db.get(k)
        ]
        if five_w:
            blocks.append("== data platform Tenant Implementation ==\n" + "\n".join(five_w))
        if db.get("assessment_objective"):
            ao = re.split(r"\.\s*Additionally", db["assessment_objective"])[0].strip()
            blocks.append(f"== Assessment Objective ==\n{ao}")
        if db.get("assessment_method"):
            am = re.split(r"\.\s*Additionally", db["assessment_method"])[0].strip()
            blocks.append(f"== Assessment Method ==\n{am}")
        if db.get("evidence"):
            blocks.append(f"== Evidence Artifacts ==\n{db['evidence']}")
    return "\n\n".join(blocks).strip()


def build_threat_desc(cid, mc, db):
    parts = []
    if db and db.get("impact_if_unaddressed"):
        impact = re.split(r"\.\s*Additionally", db["impact_if_unaddressed"])[0].strip()
        parts.append(f"Risk if unaddressed: {impact}.")
    parts.append(
        "Customer/tenant responsibility control - failure to fully implement "
        "the tenant-side obligations for this NIST 800-53 Rev.5 control leaves "
        "the shared-responsibility gap unmitigated within the Example System/data platform "
        "tenant boundary."
    )
    return " ".join(parts)


class ControlRegistry:
    """Deduplicates evidence-mechanism controls with monotonic bom-ref sequences."""

    def __init__(
        self,
        start_seq,
        evidence_links=None,
        evidence_artifacts=None,
        evidence_ids=None,
        evidence_roles=None,
    ):
        self.seq = start_seq
        self.by_key = {}  # evidence-key -> control dict (shared)
        self.controls = []  # ordered list of all control dicts
        self._evidence_links = evidence_links or {}
        self._evidence_artifacts = evidence_artifacts or {}
        # Per-system overrides layer over the built-in Example System-derived map.
        self._evidence_ids = {**EVIDENCE_NIST_IDS, **(evidence_ids or {})}
        self._evidence_roles = evidence_roles or {}

    def _new_ref(self, name):
        self.seq += 1
        return f"control-{slug(name)}-{self.seq}"

    def shared_evidence(self, key, name, description, category):
        """Reusable control for an evidence key; created once, linked N times."""
        ctrl = self.by_key.get(key)
        if ctrl is None:
            props = [{"name": "resp:evidence-key", "value": key}]
            evidence_role = self._evidence_roles.get(key, "implementation")
            props.append({"name": "resp:evidence-role", "value": evidence_role})
            if key in self._evidence_ids:
                props.append({"name": "ctrl:id", "value": self._evidence_ids[key]})
            nist_id = self._evidence_ids.get(key)
            ctrl = {
                "bom-ref": self._new_ref(name),
                "name": name,
                "status": "recommended" if evidence_role == "observation" else "verified",
                "description": description,
                "category": category,
                "properties": props,
                "mitigations": [],
            }
            if nist_id:
                ctrl["satisfies"] = [{"reference": nist_id, "framework": "nist-800-53-r5"}]
            url = self._evidence_links.get(key)
            if url:
                ctrl["externalReferences"] = [{"type": "evidence", "url": url}]
            artifact = self._evidence_artifacts.get(key)
            if artifact:
                for field in (
                    "artifact_type",
                    "is_continuous",
                    "captured_at",
                    "expires_at",
                    "title",
                ):
                    val = artifact.get(field)
                    if val is not None:
                        ctrl["properties"] = merge_properties(
                            ctrl.get("properties", []),
                            [
                                {
                                    "name": f"resp:evidence-{field.replace('_', '-')}",
                                    "value": str(val).lower() if isinstance(val, bool) else str(val),
                                }
                            ],
                        )
            self.by_key[key] = ctrl
            self.controls.append(ctrl)
        return ctrl

    def one_off(
        self,
        name,
        description,
        category,
        status,
        properties=None,
        evidence_url=None,
        implementation_statement=None,
        responsibility_source=None,
        test_steps=None,
        nist_id=None,
    ):
        ctrl = {
            "bom-ref": self._new_ref(name),
            "name": name,
            "status": status,
            "description": description,
            "category": category,
            "mitigations": [],
        }
        if nist_id:
            ctrl["satisfies"] = [{"reference": nist_id, "framework": "nist-800-53-r5"}]
        props = list(properties or [])
        if implementation_statement:
            props.append(
                {
                    "name": "resp:statement",
                    "value": implementation_statement,
                }
            )
        if responsibility_source:
            props.append({"name": "resp:source", "value": responsibility_source})
        if test_steps:
            props.append({"name": "resp:test-steps", "value": json.dumps(test_steps)})
        if props:
            ctrl["properties"] = props
        if evidence_url:
            ctrl["externalReferences"] = [{"type": "evidence", "url": evidence_url}]
        self.controls.append(ctrl)
        return ctrl


# Primary authoritative NIST control for each reusable evidence key.
EVIDENCE_NIST_IDS = {
    "identity_chain": "IA-8(1)",
    "dev_oauth": "AC-6(2)",
    "ci_sp_token": "SA-10",
    "deployer_sp": "AC-6(5)",
    "uc_rbac": "AC-6",
    "catalog_iso": "AC-4",
    "serverless": "CM-7(1)",
    "delta_integrity": "CP-10(2)",
    "dq_quarantine": "AU-6",
    "log_sanitize": "AU-3(3)",
    "delta_share": "CA-3(5)",
    "cicd_gate": "SA-11",
    "iea_ext": "CA-3(3)",
    "no_ingress": "CA-3(5)",
    "test_schema_governance": "AC-6",
    "pr_secret_isolation": "SA-10",
    "oauth_m2m_deployer": "AC-6(5)",
    "fouo_gap": "AC-3",
    "no_kms": "SC-28",
    "supply_chain": "SR-3",  # upgraded: supply_chain evidence now maps to SR-3
}

# Human-friendly names for reusable evidence-key controls.
EVIDENCE_CONTROL_NAMES = {
    "identity_chain": "Federated identity: GSA SSO/Okta -> login.gov PIV/CAC + email-MFA",
    "dev_oauth": "Developer OAuth sessions to stg_developer sandbox only",
    "ci_sp_token": "CI service-principal tokens, PR-secret isolation + peer review",
    "deployer_sp": "OAuth m2m deployer service principal",
    "uc_rbac": "Unity Catalog schema-level RBAC (declared as code, CI-tested)",
    "catalog_iso": "Catalog-per-environment isolation (example-system_stg/ivv/example-system)",
    "serverless": "100% data platform serverless compute (inherited hardening)",
    "delta_integrity": "Delta ACID + Change Data Feed + row tracking",
    "dq_quarantine": "Data-quality metrics + quarantine framework",
    "log_sanitize": "Log sanitization (redact URLs/paths/emails/tokens/PII)",
    "delta_share": "Delta Sharing egress boundary (GSA-only, 3 metric views)",
    "cicd_gate": "Gated CI/CD deploy (SHA-pinned, peer-reviewed, promotion)",
    "supply_chain": "Supply-chain scanning (uv audit, gitleaks, zizmor, Renovate)",
    "iea_ext": "ISA/IEA/MOU-governed external interconnections",
    "no_ingress": "No direct Internet ingress; Zscaler CIDR + FCS firewall",
    "fouo_gap": "GAP: fine-grained masking/ABAC for FOUO/PII (not codified)",
    "no_kms": "GAP: KMS/CMK, audit-log delivery, IP-allowlist evidence",
    "test_schema_governance": "CI-tested RBAC contract (test_schema_governance.py)",
    "pr_secret_isolation": "ADR-0001 PR secret isolation (pr-static-check vs main-live-validate)",
    "oauth_m2m_deployer": "OAuth m2m deployer SP (DATA-PLATFORM_AUTH_TYPE=oauth-m2m)",
}


_STATUS_RANK = {
    "verified": 4,
    "implemented": 3,
    "in-progress": 2,
    "planned": 1,
    "recommended": 0,
}


def _max_seq(items):
    m = 0
    for it in items:
        mm = re.search(r"-(\d+)$", it.get("bom-ref", ""))
        if mm:
            m = max(m, int(mm.group(1)))
    return m


def _assets_for(cid, fam_map, default_assets, alias):
    aliases = fam_map.get(family(cid), default_assets)
    return [alias[a] for a in aliases]


def _primary_asset(cid, fam_map, default_assets, alias):
    """Primary asset only (avoids Precogly duplicate rows; full set in props)."""
    all_assets = _assets_for(cid, fam_map, default_assets, alias)
    return [all_assets[0]] if all_assets else []


def _index_references_source(index, source: str) -> bool:
    """True if any control in a CRM index lists ``source`` (legacy ``sources`` or baseline ``crm_sources``)."""
    for row in (index or {}).get("controls") or []:
        if not isinstance(row, dict):
            continue
        for key in ("sources", "crm_sources"):
            listed = row.get(key)
            if isinstance(listed, list) and source in listed:
                return True
    return False


def _load_data(cdx, paths: SystemPaths, architecture=None):
    """Load all YAML data sources; apply architecture overrides; return dict."""
    arch = architecture or _load_yaml_path(paths.model_architecture)
    apply_architecture_overrides(cdx, arch)
    # Evidence snippets are optional, and so is the data platform CRM, but only for
    # a system whose CRM index never references data platform (for example
    # Example System-Sync). If the index lists data platform as a source, crm/data-platform.yaml
    # is required, so dropping it fails instead of silently producing a model
    # with no data platform responsibilities. A countermeasure that references a
    # missing evidence key still fails with a clear KeyError.
    ev = _load_yaml_path(paths.model_evidence) if paths.model_evidence else {}
    managed_cloud_service = paths.crm_source("managed-cloud-service")
    dbx = paths.crm_source("data-platform")
    needs_dbx = bool(paths.crm_index) and _index_references_source(_load_yaml_path(paths.crm_index), "data-platform")
    if not (paths.crm_index and managed_cloud_service and paths.countermeasures and (dbx or not needs_dbx)):
        missing = [
            name
            for name, p in (
                ("crm_index", paths.crm_index),
                ("crm/managed-cloud-service.yaml", managed_cloud_service),
                ("crm/data-platform.yaml (referenced by the CRM index)", dbx if needs_dbx else True),
                ("countermeasures", paths.countermeasures),
            )
            if not p
        ]
        raise FileNotFoundError(f"system '{paths.slug}' is missing required CRM data: {missing}")
    return {
        "arch": arch,
        "evidence": ev.get("evidence") or {},
        "evidence_links": ev.get("evidence_links") or {},
        "evidence_artifacts": ev.get("evidence_artifacts") or {},
        "evidence_ids": ev.get("evidence_ids") or {},
        "evidence_roles": ev.get("evidence_roles") or {},
        "index": _load_yaml_path(paths.crm_index),
        "managed-cloud-service": by_id(_load_yaml_path(managed_cloud_service)),
        "dbx": by_id(_load_yaml_path(dbx)) if dbx else {},
        "cms": {
            canonical_control_id(c["control_id"]): c for c in _load_yaml_path(paths.countermeasures)["countermeasures"]
        },
    }


def _build_threat_properties(cid, mc, db, all_affected, sources):
    props = [{"name": "ctrl:id", "value": cid}]
    if len(all_affected) > 1:
        props.append({"name": "resp:affected-assets", "value": " ".join(all_affected)})
    if mc:
        if mc.get("baseline_low"):
            props.append({"name": "gsa:baseline-low", "value": "included"})
        if mc.get("baseline_moderate"):
            props.append({"name": "gsa:baseline-moderate", "value": "included"})
        pr = (mc.get("privacy_related") or "").strip()
        if pr and pr.upper() != "NA":
            props.append({"name": "privacy:related", "value": pr})
    if db:
        if db.get("implementation_status"):
            props.append(
                {
                    "name": "resp:status",
                    "value": db["implementation_status"],
                }
            )
        if db.get("inheritance"):
            props.append({"name": "resp:inheritance", "value": db["inheritance"]})
        if db.get("evidence_link") and db["evidence_link"].upper() != "N/A":
            props.append({"name": "resp:evidence-link", "value": db["evidence_link"]})
    props.append({"name": "resp:source", "value": "+".join(sources)})
    return props


def _build_controls_for_threat(
    cid,
    cm,
    db,
    mc,
    registry,
    cdx_ctrl_status,
    inline_evidence_url,
    t_ref,
    resp_src,
    evidence,
):
    """Build all controls for a control-id; return linked bom-ref list."""
    category = STRATEGY_TO_CATEGORY.get(cm["strategy"], "preventive")
    cm_test_steps = cm.get("test_procedures")
    has_text_mech = any("text" in m for m in cm.get("mechanisms", []))

    linked = []
    for mech in cm["mechanisms"]:
        if "ref" in mech:
            key = mech["ref"]
            if key not in evidence:
                raise KeyError(f"{cid}: evidence key '{key}' not found")
            ctrl = registry.shared_evidence(
                key,
                EVIDENCE_CONTROL_NAMES.get(key, key),
                evidence[key].strip(),
                category,
            )
        elif "text" in mech:
            impl_stmt = None
            if db:
                writeup = build_mitigation_text(cid, mc, db)
                if writeup:
                    impl_stmt = writeup[:2000]
            ctrl = registry.one_off(
                f"{cid} specific control",
                mech["text"].strip(),
                category,
                cdx_ctrl_status,
                properties=[
                    {"name": "ctrl:id", "value": cid},
                ],
                evidence_url=inline_evidence_url,
                implementation_statement=impl_stmt,
                responsibility_source=resp_src,
                test_steps=cm_test_steps,
                nist_id=cid,
            )
        else:
            raise ValueError(f"{cid}: mechanism needs ref or text: {mech}")
        ctrl["mitigations"].append(t_ref)
        linked.append(ctrl["bom-ref"])

    if cm_test_steps and not has_text_mech and linked:
        last_ctrl = next((c for c in registry.controls if c["bom-ref"] == linked[-1]), None)
        if last_ctrl and not any(p["name"] == "resp:test-steps" for p in last_ctrl.get("properties", [])):
            last_ctrl.setdefault("properties", []).append(
                {"name": "resp:test-steps", "value": json.dumps(cm_test_steps)}
            )

    for gap in cm.get("residual_actions", []):
        ctrl = registry.one_off(
            f"{cid} residual action",
            gap.strip(),
            category,
            "recommended",
            properties=[
                {"name": "ctrl:id", "value": cid},
                {"name": "resp:residual", "value": "true"},
            ],
            responsibility_source=resp_src,
            nist_id=cid,
        )
        ctrl["mitigations"].append(t_ref)
        linked.append(ctrl["bom-ref"])

    return linked


def _build_scenario(s_ref, t_ref, affected, flows, impl_status, status_risk, db, resp_src):
    level = status_risk.get(impl_status, status_risk.get("", "medium"))
    inherent = "high" if level in {"high", "critical"} else "medium"
    scenario_props = [{"name": "resp:source", "value": resp_src}]
    if db and db.get("impact_if_unaddressed"):
        narrative = re.split(r"\.\s*Additionally", db["impact_if_unaddressed"])[0].strip()
        scenario_props.append({"name": "resp:residual-narrative", "value": narrative})
    return {
        "bom-ref": s_ref,
        "threat": t_ref,
        "affectedAssets": affected + flows,
        **({"affectedFlows": flows} if flows else {}),
        "riskScore": {"level": level},
        "inherentSeverity": inherent,
        "residualSeverity": level,
        "properties": scenario_props,
    }


def _process_control_id(
    cid,
    seq,
    managed_cloud_service,
    dbx,
    cms,
    evidence,
    registry,
    fam_map,
    default_assets,
    alias,
    flow_bindings,
    status_risk,
):
    """Process one control-id; return (threat, scenario, new_seq)."""
    mc, db = managed_cloud_service.get(cid), dbx.get(cid)
    sources = [s for s, present in (("managed cloud service", mc), ("data platform", db)) if present]
    name = (db and db.get("name")) or (mc and mc.get("name")) or cid
    all_affected = _assets_for(cid, fam_map, default_assets, alias)
    affected = _primary_asset(cid, fam_map, default_assets, alias)
    seq += 1
    t_ref = f"threat-{slug(f'{cid} {name}')}-{seq}"
    s_ref = f"scenario-{slug(f'{cid} {name}')}-{seq}"

    props = _build_threat_properties(cid, mc, db, all_affected, sources)
    mitig_text = build_mitigation_text(cid, mc, db)
    threat_desc = mitig_text if mitig_text else build_threat_desc(cid, mc, db)
    flows = flow_bindings.get(cid, [])
    threat = {
        "bom-ref": t_ref,
        "name": f"{cid} {name}",
        "description": threat_desc,
        "affectedAssets": affected + flows,
        "properties": props,
        "mitigations": [],
    }
    if flows:
        threat["affectedFlows"] = flows

    cm = cms.get(cid)
    if not cm:
        raise KeyError(f"no countermeasure for {cid} in countermeasures.yaml")
    impl_status = (db and db.get("implementation_status", "").lower()) or ""
    cdx_ctrl_status = {
        "fully implemented": "implemented",
        "partially implemented": "in-progress",
        "planned": "planned",
        "not implemented": "recommended",
    }.get(impl_status, "recommended")
    inline_evidence_url = db.get("evidence_link") if db else None
    if inline_evidence_url and inline_evidence_url.upper() == "N/A":
        inline_evidence_url = None
    resp_src = _responsibility_source(db.get("inheritance") if db else None)

    linked = _build_controls_for_threat(
        cid,
        cm,
        db,
        mc,
        registry,
        cdx_ctrl_status,
        inline_evidence_url,
        t_ref,
        resp_src,
        evidence,
    )
    threat["mitigations"] = linked
    if mitig_text:
        threat["properties"].append({"name": "resp:writeup", "value": mitig_text})
    return (
        threat,
        _build_scenario(s_ref, t_ref, affected, flows, impl_status, status_risk, db, resp_src),
        seq,
    )


def _link_object_poisoning(threats, all_controls):
    """Link Object Poisoning threat ↔ SR-3 control (#43)."""
    op_ref = "threat-object-poisoning-1"
    op_threat = next((t for t in threats if t.get("bom-ref") == op_ref), None)
    if op_threat is None:
        return
    sc_ctrl = next(
        (
            c
            for c in all_controls
            if any(p.get("name") == "ctrl:id" and p.get("value") == "SR-3" for p in (c.get("properties") or []))
        ),
        None,
    )
    if sc_ctrl is None:
        return
    op_threat.setdefault("mitigations", [])
    if sc_ctrl["bom-ref"] not in op_threat["mitigations"]:
        op_threat["mitigations"].append(sc_ctrl["bom-ref"])
    sc_ctrl.setdefault("mitigations", [])
    if op_ref not in sc_ctrl["mitigations"]:
        sc_ctrl["mitigations"].append(op_ref)


def _aggregate_status(statuses):
    """Return the weakest required countermeasure status for a NIST control."""
    if not statuses:
        raise ValueError("cannot aggregate an empty status list")
    required = [status for status in statuses if status != "rejected"]
    if not required:
        return "rejected"
    unknown = sorted(set(required) - set(_STATUS_RANK))
    if unknown:
        raise ValueError(f"unknown control statuses: {unknown}")
    return min(required, key=_STATUS_RANK.__getitem__)


def _compute_control_rollup(all_controls):
    """ADR-012: per-NIST-control aggregate status rollup."""
    rollup: dict[str, list[str]] = {}
    for ctrl in all_controls:
        props = {p["name"]: p["value"] for p in ctrl.get("properties", [])}
        nid = props.get("ctrl:id")
        if not nid:
            continue
        rollup.setdefault(nid, []).append(ctrl["status"])
    return [
        {
            "control_id": nid,
            "aggregate_status": _aggregate_status(statuses),
            "cm_count": len(statuses),
        }
        for nid, statuses in sorted(rollup.items())
    ]


def _emit_metadata(cdx, controls_list, rollup_entries):
    """Stamp deterministic metadata so source-only regeneration is stable."""
    stable_payload = {
        "blueprints": cdx.get("blueprints", []),
        "threats": cdx.get("threats", {}),
        "controls": cdx.get("controls", []),
    }
    cdx["serialNumber"] = f"urn:uuid:{uuid.uuid5(_CDX_UUID_NS, json.dumps(stable_payload, sort_keys=True))}"
    cdx["version"] = int(cdx.get("version", 1)) + 1
    meta = cdx.setdefault("metadata", {})
    meta["timestamp"] = _STABLE_TIMESTAMP
    meta.setdefault("properties", []).extend(
        [
            {
                "name": "resp:generated-by",
                "value": "docs/threat-model/scripts/generate.py (YAML->Precogly CDX)",
            },
            {
                "name": "resp:sources",
                "value": "data/crm/*.yaml + data/countermeasures + data/model",
            },
            {"name": "resp:control-count", "value": str(len(controls_list))},
            {
                "name": "resp:countermeasures",
                "value": "Precogly controls[] (one per mechanism, reused m:n); "
                "Example System data platform codebase + GSA SSO/Okta -> login.gov PIV/CAC + email-MFA identity chain",
            },
            {
                "name": "resp:control-rollup",
                "value": json.dumps(rollup_entries, separators=(",", ":")),
            },
        ]
    )


def _write_output(cdx, out_path, controls_list, managed_cloud_service, dbx, threats, scenarios, registry):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2, ensure_ascii=False)
        f.write("\n")
    both = sum(1 for c in controls_list if c in managed_cloud_service and c in dbx)
    reusable, one_off = (
        len(registry.by_key),
        len(registry.controls) - len(registry.by_key),
    )
    print(f"Wrote {os.path.relpath(out_path, ROOT)}", file=sys.stderr)
    print(
        f"Controls (NIST): {len(controls_list)} (both: {both}, "
        f"managed cloud service-only: {len(managed_cloud_service) - both}, data platform-only: {len(dbx) - both})",
        file=sys.stderr,
    )
    print(
        f"Threats: {len(threats)}, Scenarios: {len(scenarios)}, "
        f"controls[] (Precogly countermeasures): {len(cdx['controls'])} "
        f"({reusable} reusable evidence controls + {one_off} one-off)",
        file=sys.stderr,
    )


def _write_hosting_summary(cdx, out_path, overlay):
    blueprint = cdx["blueprints"][0]
    threats = cdx.get("threats") or {}
    summary = {
        "system": overlay.slug,
        "parent_system": overlay.parent_system,
        "hosting_overlay": overlay.name,
        "lifecycle": overlay.lifecycle,
        "authorization_state": overlay.authorization_state,
        "feasibility_status": overlay.feasibility["status"],
        "artifact": Path(out_path).name,
        "statistics": {
            "zones": len(blueprint.get("zones") or []),
            "assets": len(blueprint.get("assets") or []),
            "flows": len(blueprint.get("flows") or []),
            "threats": len(threats.get("threats") or []),
            "scenarios": len(threats.get("scenarios") or []),
            "controls": len(cdx.get("controls") or []),
            "visualizations": len(blueprint.get("visualizations") or []),
        },
    }
    summary_path = Path(out_path).with_name("import-summary.yaml")
    summary_path.write_text(yaml.safe_dump(summary, sort_keys=False), encoding="utf-8")


def _resolve_flow_bindings(flow_bindings, arch, cdx):
    resolved, errors = resolve_flow_bindings(flow_bindings, arch, cdx["blueprints"][0])
    if errors:
        raise KeyError("; ".join(errors))
    return resolved


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--system",
        default=DEFAULT_SYSTEM,
        help="System slug to build; defaults to the Example System sources under data/systems/<slug>/ + legacy fallbacks (Phase A).",
    )
    ap.add_argument(
        "--out",
        default=None,
    )
    ap.add_argument(
        "--hosting",
        help="Explicit hosting overlay name under data/systems/<system>/hosting/.",
    )
    args = ap.parse_args()

    paths = load_system(args.system)

    with open(paths.model_dfd, encoding="utf-8") as f:
        cdx = json.load(f)

    architecture = _load_yaml_path(paths.model_architecture)
    hosting_overlay = None
    if args.hosting:
        hosting_overlay = load_hosting_overlay(paths, args.hosting)
        composed = compose_hosting_overlay(cdx, hosting_overlay, architecture)
        cdx = composed.dfd
        architecture = composed.architecture or architecture
        cdx["blueprints"][0]["name"] = hosting_overlay.title or hosting_overlay.slug
        cdx.setdefault("metadata", {}).setdefault("properties", []).extend(
            [
                {"name": "resp:parent-system", "value": paths.slug},
                {"name": "resp:hosting-overlay", "value": hosting_overlay.name},
                {"name": "resp:lifecycle", "value": hosting_overlay.lifecycle},
                {
                    "name": "resp:authorization-state",
                    "value": hosting_overlay.authorization_state,
                },
                {
                    "name": "resp:feasibility-status",
                    "value": str(hosting_overlay.feasibility["status"]),
                },
            ]
        )
    out_path = args.out
    if out_path is None:
        out_path = (
            os.path.join(
                ROOT,
                "build",
                "systems",
                hosting_overlay.slug,
                f"{hosting_overlay.slug}.cdx.json",
            )
            if hosting_overlay
            else os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")
        )

    data = _load_data(cdx, paths, architecture)
    arch = data["arch"]
    fam_map = arch["family_asset_map"]
    default_assets = arch["default_assets"]
    alias = arch["assets"]
    flow_bindings = arch.get("flow_bindings", {})
    gwt_bindings = arch.get("gwt_bindings", {})
    flow_bindings = _resolve_flow_bindings(flow_bindings, arch, cdx)

    existing_threats = cdx.get("threats", {}).get("threats", [])
    existing_scenarios = cdx.get("threats", {}).get("scenarios", [])
    existing_controls = cdx.get("controls", [])

    seq = _max_seq(existing_threats + existing_scenarios)
    threats = list(existing_threats)
    scenarios = list(existing_scenarios)
    registry = ControlRegistry(
        _max_seq(existing_controls),
        evidence_links=data["evidence_links"],
        evidence_artifacts=data["evidence_artifacts"],
        evidence_ids=data["evidence_ids"],
        evidence_roles=data["evidence_roles"],
    )
    controls_list = [c["control_id"] for c in data["index"]["controls"]]

    for cid in controls_list:
        threat, scenario, seq = _process_control_id(
            cid,
            seq,
            data["managed-cloud-service"],
            data["dbx"],
            data["cms"],
            data["evidence"],
            registry,
            fam_map,
            default_assets,
            alias,
            flow_bindings,
            arch["status_risk"],
        )
        threats.append(threat)
        scenarios.append(scenario)

    # M5 prototype: apply GWT properties to matching threats
    for t in threats:
        cid = next(
            (p["value"] for p in t.get("properties", []) if p["name"] == "ctrl:id"),
            None,
        )
        if cid and cid in gwt_bindings:
            gwt = gwt_bindings[cid]
            for key in ("given", "when", "then"):
                if gwt.get(key):
                    t.setdefault("properties", []).append({"name": f"gwt.{key}", "value": gwt[key]})

    cdx["threats"] = {"threats": threats, "scenarios": scenarios}
    all_controls = existing_controls + registry.controls
    _link_object_poisoning(threats, all_controls)
    cdx["controls"] = all_controls

    project_nist_standard(cdx)
    project_tmbom_topology(cdx)

    _emit_metadata(cdx, controls_list, _compute_control_rollup(all_controls))
    _write_output(
        cdx,
        out_path,
        controls_list,
        data["managed-cloud-service"],
        data["dbx"],
        threats,
        scenarios,
        registry,
    )
    if hosting_overlay:
        _write_hosting_summary(cdx, out_path, hosting_overlay)


if __name__ == "__main__":
    main()
