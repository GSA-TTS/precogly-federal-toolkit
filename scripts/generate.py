#!/usr/bin/env python3
"""Generate the Example System CRM threat-model CycloneDX (Precogly-native) JSON from
YAML data sources.

IMPORTANT (round-trip): Precogly stores countermeasures as TOP-LEVEL
`controls[]` objects linked bidirectionally to threats by bom-ref
(control.mitigations -> [threat-ref], threat.mitigations -> [control-ref]).
Our earlier schema embedded `countermeasures`/`responses`/`properties` inside
each threat, which the Precogly editor silently DROPS on import/export. This
generator emits the native schema so countermeasures survive an editor
round-trip.

Granularity (per user decision): ONE control per evidence MECHANISM, reused
many-to-many. Each reusable evidence snippet in model/evidence.yaml becomes one
control linked to every threat that references it. Control-specific inline
mechanisms and residual actions become their own controls linked to just that
threat.

Inputs (under docs/threat-model/data/):
  model/base-dfd.cdx.json          - Precogly DFD + base (non-CRM) threats
  model/architecture.yaml          - assets, family->asset map, risk scoring
  model/evidence.yaml              - reusable evidence snippets (by key)
  crm/index.yaml, crm/managed-cloud-service.yaml, crm/data-platform.yaml
  countermeasures/countermeasures.yaml

Output: build/example-system-crm-threat-model.cdx.json (default; --out to override).

Deterministic. Read-only against inputs; writes only --out.
Requires PyYAML (run via `uv run`).
"""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import UTC, datetime

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")

# Precogly slug rule (derived empirically from an editor export):
#   lowercase -> non-alphanumeric collapsed to '-' -> truncate to 40 chars
#   (trailing '-' kept) -> prefixed 'threat-'/'control-' -> suffix '-<seq>'.
SLUG_CAP = 40

STRATEGY_TO_CATEGORY = {
    "PREVENTIVE": "preventive",
    "DETECTIVE": "detective",
    "CORRECTIVE": "corrective",
}

FLOW_AUTH_MECHANISMS = {
    "OAuth 2.0",
    "mTLS",
    "JWT",
    "API key",
    "SSH key",
    "HMAC",
    "AWS IAM role",
}


def load_yaml(*parts):
    with open(os.path.join(DATA, *parts), encoding="utf-8") as f:
        return yaml.safe_load(f)


def slug(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:SLUG_CAP]


def family(cid):
    return cid.split("-", 1)[0]


def by_id(doc):
    return {c["control_id"]: c for c in doc.get("controls", [])}


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
            zone["properties"] = merge_properties(
                zone.get("properties", []), override["properties"]
            )

    flows = {f["bom-ref"]: f for f in bp.get("flows", [])}
    for fref, override in arch.get("flow_overrides", {}).items():
        if fref not in flows:
            raise KeyError(f"flow override references unknown flow: {fref}")
        flow = flows[fref]
        if override.get("protocols"):
            flow["protocols"] = list(override["protocols"])
        auth = override.get("authMechanism")
        if auth:
            if auth not in FLOW_AUTH_MECHANISMS:
                raise ValueError(f"flow {fref} uses unsupported authMechanism: {auth}")
            flow["authMechanism"] = auth
            flow["properties"] = merge_properties(
                flow.get("properties", []),
                [{"name": "owasp:auth_mechanism", "value": auth}],
            )


def build_mitigation_text(cid, mc, db):
    blocks = []
    if mc and mc.get("responsibility"):
        blocks.append("== managed cloud service Tenant Responsibility ==\n" + mc["responsibility"])
    if db:
        five_w = []
        for label, key in (
            ("WHO", "who"),
            ("WHAT", "what"),
            ("HOW", "how"),
            ("WHEN", "when"),
            ("WHERE (evidence source)", "where"),
        ):
            if db.get(key):
                five_w.append(f"{label}: {db[key]}")
        if five_w:
            blocks.append(
                "== data platform Tenant Implementation ==\n" + "\n".join(five_w)
            )
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
    """Deduplicates evidence-mechanism controls (many-to-many) and assigns
    stable, Precogly-style control bom-refs with a monotonic sequence."""

    def __init__(self, start_seq, evidence_links=None):
        self.seq = start_seq
        self.by_key = {}  # evidence-key -> control dict (shared)
        self.controls = []  # ordered list of all control dicts
        self._evidence_links = evidence_links or {}

    def _new_ref(self, name):
        self.seq += 1
        return f"control-{slug(name)}-{self.seq}"

    def shared_evidence(self, key, name, description, category):
        """Reusable control for an evidence key; created once, linked N times."""
        ctrl = self.by_key.get(key)
        if ctrl is None:
            props = [{"name": "crm:evidence-key", "value": key}]
            if key in EVIDENCE_NIST_IDS:
                props.append({"name": "nist:control-id", "value": EVIDENCE_NIST_IDS[key]})
            ctrl = {
                "bom-ref": self._new_ref(name),
                "name": name,
                # Precogly backend accepts `implemented`, but the current
                # Threat Analysis frontend only defines a status color for
                # completed controls under `verified`.
                "status": "verified",
                "description": description,
                "category": category,
                "properties": props,
                "mitigations": [],
            }
            url = self._evidence_links.get(key)
            if url:
                ctrl["externalReferences"] = [{"type": "evidence", "url": url}]
            self.by_key[key] = ctrl
            self.controls.append(ctrl)
        return ctrl

    def one_off(self, name, description, category, status, properties=None):
        ctrl = {
            "bom-ref": self._new_ref(name),
            "name": name,
            "status": status,
            "description": description,
            "category": category,
            "mitigations": [],
        }
        if properties:
            ctrl["properties"] = properties
        self.controls.append(ctrl)
        return ctrl


# Primary authoritative NIST control for each reusable evidence key.
EVIDENCE_NIST_IDS = {
    "identity_chain":   "IA-8(1)",
    "dev_oauth":        "AC-6(2)",
    "ci_sp_token":      "SA-10",
    "deployer_sp":      "AC-6(5)",
    "uc_rbac":          "AC-6",
    "catalog_iso":      "AC-4",
    "serverless":       "CM-7(1)",
    "delta_integrity":  "CP-10(2)",
    "dq_quarantine":    "AU-6",
    "log_sanitize":     "AU-3(3)",
    "delta_share":      "CA-3(5)",
    "cicd_gate":        "SA-11",
    "supply_chain":     "RA-5",
    "iea_ext":          "CA-3(3)",
    "no_ingress":       "CA-3(5)",
    "test_schema_governance": "AC-6",
    "pr_secret_isolation":    "SA-10",
    "oauth_m2m_deployer":     "AC-6(5)",
    # Gap controls: no full implementation yet; track under closest NIST families
    "fouo_gap":         "AC-3",
    "no_kms":           "SC-28",
    "supply_chain":     "SR-3",   # upgraded: supply_chain evidence now maps to SR-3
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
    "pr_secret_isolation":    "ADR-0001 PR secret isolation (pr-static-check vs main-live-validate)",
    "oauth_m2m_deployer":     "OAuth m2m deployer SP (DATA-PLATFORM_AUTH_TYPE=oauth-m2m)",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out", default=os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")
    )
    args = ap.parse_args()

    with open(os.path.join(DATA, "model", "base-dfd.cdx.json"), encoding="utf-8") as f:
        cdx = json.load(f)

    arch = load_yaml("model", "architecture.yaml")
    apply_architecture_overrides(cdx, arch)
    _ev_yaml = load_yaml("model", "evidence.yaml")
    evidence = _ev_yaml["evidence"]
    evidence_links = _ev_yaml.get("evidence_links") or {}
    index = load_yaml("crm", "index.yaml")
    managed-cloud-service = by_id(load_yaml("crm", "managed-cloud-service.yaml"))
    dbx = by_id(load_yaml("crm", "data-platform.yaml"))
    cms = {
        c["control_id"]: c
        for c in load_yaml("countermeasures", "countermeasures.yaml")["countermeasures"]
    }

    alias = arch["assets"]
    fam_map = arch["family_asset_map"]
    default_assets = arch["default_assets"]
    status_risk = arch["status_risk"]
    flow_bindings = arch.get("flow_bindings", {})
    flow_refs = {f["bom-ref"] for f in cdx["blueprints"][0].get("flows", [])}

    for cid, refs in flow_bindings.items():
        unknown = sorted(set(refs) - flow_refs)
        if unknown:
            raise KeyError(f"{cid}: flow_bindings references unknown flows: {unknown}")

    def assets_for(cid):
        aliases = fam_map.get(family(cid), default_assets)
        return [alias[a] for a in aliases]

    existing_threats = cdx.get("threats", {}).get("threats", [])
    existing_scenarios = cdx.get("threats", {}).get("scenarios", [])
    existing_controls = cdx.get("controls", [])

    # Sequence continues after the highest existing threat/control suffix so
    # bom-refs never collide with the base DFD's.
    def max_seq(items):
        m = 0
        for it in items:
            mm = re.search(r"-(\d+)$", it.get("bom-ref", ""))
            if mm:
                m = max(m, int(mm.group(1)))
        return m

    seq = max_seq(existing_threats + existing_scenarios)
    threats = list(existing_threats)
    scenarios = list(existing_scenarios)
    controls_seq_start = max_seq(existing_controls)
    registry = ControlRegistry(controls_seq_start, evidence_links=evidence_links)

    controls_list = [c["control_id"] for c in index["controls"]]

    for cid in controls_list:
        mc = managed-cloud-service.get(cid)
        db = dbx.get(cid)
        sources = [s for s, present in (("managed cloud service", mc), ("data platform", db)) if present]
        name = (db and db.get("name")) or (mc and mc.get("name")) or cid
        affected = assets_for(cid)

        seq += 1
        t_ref = f"threat-{slug(f'{cid} {name}')}-{seq}"
        s_ref = f"scenario-{slug(f'{cid} {name}')}-{seq}"

        # ---- threat properties (kept; Precogly preserves unknown props) ----
        props = [{"name": "nist:control-id", "value": cid}]
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
                        "name": "crm:implementation-status",
                        "value": db["implementation_status"],
                    }
                )
            if db.get("inheritance"):
                props.append({"name": "crm:inheritance", "value": db["inheritance"]})
            if db.get("evidence_link") and db["evidence_link"].upper() != "N/A":
                props.append(
                    {"name": "crm:evidence-link", "value": db["evidence_link"]}
                )
        props.append({"name": "crm:source", "value": "+".join(sources)})

        threat = {
            "bom-ref": t_ref,
            "name": f"{cid} {name}",
            "description": build_threat_desc(cid, mc, db),
            "affectedAssets": affected,
            "properties": props,
            "mitigations": [],  # filled below with control bom-refs
        }
        if cid in flow_bindings:
            threat["affectedFlows"] = flow_bindings[cid]

        # ---- controls: one per mechanism, reusing evidence-key controls ----
        cm = cms.get(cid)
        if not cm:
            raise KeyError(f"no countermeasure for {cid} in countermeasures.yaml")
        category = STRATEGY_TO_CATEGORY.get(cm["strategy"], "preventive")

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
                    # shared controls keep their own category by first use;
                    # default to the threat's category on creation.
                    category,
                )
            elif "text" in mech:
                ctrl = registry.one_off(
                    f"{cid} specific control",
                    mech["text"].strip(),
                    category,
                    "verified",
                    properties=[
                        {"name": "crm:control-id", "value": cid},
                        {"name": "nist:control-id", "value": cid},
                    ],
                )
            else:
                raise ValueError(f"{cid}: mechanism needs ref or text: {mech}")
            ctrl["mitigations"].append(t_ref)
            linked.append(ctrl["bom-ref"])

        # residual/tenant actions -> recommended controls (status: recommended)
        for gap in cm.get("residual_actions", []):
            ctrl = registry.one_off(
                f"{cid} residual action",
                gap.strip(),
                category,
                "recommended",
                properties=[
                    {"name": "crm:control-id", "value": cid},
                    {"name": "crm:residual", "value": "true"},
                ],
            )
            ctrl["mitigations"].append(t_ref)
            linked.append(ctrl["bom-ref"])

        threat["mitigations"] = linked
        # keep the human-readable mitigation write-up as a threat property too
        mitig = build_mitigation_text(cid, mc, db)
        if mitig:
            threat["properties"].append(
                {"name": "crm:responsibility-writeup", "value": mitig}
            )

        threats.append(threat)

        status = (db and db.get("implementation_status", "").lower()) or ""
        level = status_risk.get(status, status_risk.get("", "medium"))
        # inherent severity is pre-mitigation; residual reflects current impl status
        inherent = "high" if level in {"high", "critical"} else "medium"
        scenarios.append(
            {
                "bom-ref": s_ref,
                "threat": t_ref,
                "affectedAssets": affected,
                **({"affectedFlows": flow_bindings[cid]} if cid in flow_bindings else {}),
                "riskScore": {"level": level},
                "inherentSeverity": inherent,
                "residualSeverity": level,
            }
        )

    cdx["threats"] = {"threats": threats, "scenarios": scenarios}

    all_controls = existing_controls + registry.controls

    # #43: link Object Poisoning threat to the supply_chain control (SR-3)
    op_ref = "threat-object-poisoning-1"
    op_threat = next((t for t in threats if t.get("bom-ref") == op_ref), None)
    if op_threat is not None:
        sc_ctrl = next(
            (c for c in all_controls
             if any(p.get("name") == "nist:control-id" and p.get("value") == "SR-3"
                    for p in (c.get("properties") or []))),
            None,
        )
        if sc_ctrl is not None:
            op_threat.setdefault("mitigations", [])
            if sc_ctrl["bom-ref"] not in op_threat["mitigations"]:
                op_threat["mitigations"].append(sc_ctrl["bom-ref"])
            sc_ctrl.setdefault("mitigations", [])
            if op_ref not in sc_ctrl["mitigations"]:
                sc_ctrl["mitigations"].append(op_ref)

    cdx["controls"] = all_controls

    cdx["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    cdx["version"] = int(cdx.get("version", 1)) + 1
    meta = cdx.setdefault("metadata", {})
    meta["timestamp"] = (
        datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    meta.setdefault("properties", []).extend(
        [
            {
                "name": "crm:generated-by",
                "value": "docs/threat-model/scripts/generate.py (YAML->Precogly CDX)",
            },
            {
                "name": "crm:sources",
                "value": "data/crm/*.yaml + data/countermeasures + data/model",
            },
            {"name": "crm:control-count", "value": str(len(controls_list))},
            {
                "name": "crm:countermeasures",
                "value": "Precogly controls[] (one per mechanism, reused m:n); "
                "Example System data platform codebase + GSA SSO/Okta -> login.gov "
                "PIV/CAC + email-MFA identity chain",
            },
        ]
    )

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote {os.path.relpath(args.out, ROOT)}", file=sys.stderr)
    both = sum(1 for c in controls_list if c in managed-cloud-service and c in dbx)
    print(
        f"Controls (NIST): {len(controls_list)} (both: {both}, "
        f"managed cloud service-only: {len(managed-cloud-service) - both}, data platform-only: {len(dbx) - both})",
        file=sys.stderr,
    )
    print(
        f"Threats: {len(threats)}, Scenarios: {len(scenarios)}, "
        f"controls[] (Precogly countermeasures): {len(cdx['controls'])} "
        f"({len(registry.by_key)} reusable evidence controls + "
        f"{len(registry.controls) - len(registry.by_key)} one-off)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
