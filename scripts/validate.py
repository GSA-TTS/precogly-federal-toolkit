#!/usr/bin/env python3
"""Validate the generated CRM threat-model CycloneDX JSON (Precogly-native
schema) against the invariants the editor and downstream consumers rely on.

Exit non-zero on any violation. Run via `uv run` after generate.py.
"""

import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
DEFAULT = os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")

CATEGORIES = {"preventive", "detective", "corrective"}
STATUSES = {
    "verified",
    "recommended",
    "rejected",
    "implemented",
    "in-progress",
    "planned",
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
TRANSPORT_THREAT_RE = re.compile(
    r"\b(mitm|man[- ]in[- ]the[- ]middle|eavesdropp?ing|replay|downgrade|cleartext|transport)\b",
    re.IGNORECASE,
)

# Recon-useful patterns that MUST NOT appear in any tracked build artifact
# (see docs/redaction-guide.md). These would aid endpoint recon/DDoS or
# spearphishing of credential holders.
# Exception: public github.com URLs in externalReferences are intentional
# evidence links (issue #46) and are not recon-useful.
FORBIDDEN = [
    (
        re.compile(r"https?://(?!localhost|127\.0\.0\.1|github\.com)", re.IGNORECASE),
        "URL/URI",
    ),
    (
        re.compile(r"\.cloud\.data-platform\.com", re.IGNORECASE),
        "data platform workspace host",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "email / POC identifier",
    ),
    (re.compile(r"itplaybook\.gsa\.gov", re.IGNORECASE), "internal DocOps host"),
    (re.compile(r"\bexample-sp-id-a|example-sp-id-b\b"), "service-principal id"),
    (re.compile(r"\bgsaext[_-]example-system[_-]uat\b", re.IGNORECASE), "UAT share recipient"),
]


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print(f"WARN: {msg}", file=sys.stderr)


def same_boundary(source_zone, destination_zone):
    return source_zone == destination_zone and source_zone is not None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    with open(path, encoding="utf-8") as f:
        d = json.load(f)

    with open(os.path.join(DATA, "model", "base-dfd.cdx.json"), encoding="utf-8") as f:
        base = json.load(f)

    # --- DFD preserved from base ---
    bp, base_bp = d["blueprints"][0], base["blueprints"][0]
    if len(bp["assets"]) != len(base_bp["assets"]):
        fail("asset count changed vs base DFD")
    if len(bp["flows"]) != len(base_bp["flows"]):
        fail("flow count changed vs base DFD")
    if len(bp.get("visualizations", [])) != len(base_bp.get("visualizations", [])):
        fail("visualization changed vs base DFD")

    threats = d["threats"]["threats"]
    scenarios = d["threats"]["scenarios"]
    controls = d.get("controls", [])
    tset = {t["bom-ref"] for t in threats}
    cset = {c["bom-ref"] for c in controls}
    aset = {a["bom-ref"] for a in bp["assets"]}
    zset = {z["bom-ref"] for z in bp.get("zones", [])}
    flows = bp.get("flows", [])
    fset = {f["bom-ref"] for f in flows}
    asset_by_ref = {a["bom-ref"]: a for a in bp["assets"]}

    # --- ADR-005 M1/M3: enriched DFD metadata is well-formed ---
    for z in bp.get("zones", []):
        parent = z.get("parentZone")
        if parent and parent not in zset:
            fail(f"zone {z['bom-ref']} parentZone references missing zone {parent}")
        if parent == z["bom-ref"]:
            fail(f"zone {z['bom-ref']} parentZone cannot reference itself")

    for f in flows:
        src = asset_by_ref.get(f.get("source"))
        dst = asset_by_ref.get(f.get("destination"))
        source_zone = (
            src.get("zone")
            if src
            else f.get("source")
            if f.get("source") in zset
            else None
        )
        destination_zone = (
            dst.get("zone")
            if dst
            else f.get("destination")
            if f.get("destination") in zset
            else None
        )
        boundary_crossing = not same_boundary(source_zone, destination_zone)
        if boundary_crossing:
            if not f.get("protocols"):
                fail(f"boundary-crossing flow {f['bom-ref']} missing protocols[]")
            if not f.get("authMechanism"):
                fail(f"boundary-crossing flow {f['bom-ref']} missing authMechanism")
        auth = f.get("authMechanism")
        if auth and auth not in FLOW_AUTH_MECHANISMS:
            fail(f"flow {f['bom-ref']} unsupported authMechanism {auth}")

    # --- base threats preserved ---
    for bt in base.get("threats", {}).get("threats", []):
        if bt["bom-ref"] not in tset:
            fail(f"base threat lost: {bt['bom-ref']}")

    # --- scenarios reference real threats + assets (flow refs allowed in affectedAssets) ---
    for s in scenarios:
        if s["threat"] not in tset:
            fail(f"dangling scenario -> {s['threat']}")
        for a in s.get("affectedAssets", []):
            if a not in aset and a not in fset:
                fail(f"scenario {s['bom-ref']} bad asset {a}")
        for flow_ref in s.get("affectedFlows", []):
            if flow_ref not in fset:
                fail(f"scenario {s['bom-ref']} bad affectedFlow {flow_ref}")

    # --- controls well-formed + bidirectionally linked ---
    if not controls:
        fail("no controls[] (Precogly countermeasures) emitted")
    for c in controls:
        if c.get("category") not in CATEGORIES:
            fail(f"control {c['bom-ref']} bad category {c.get('category')}")
        if c.get("status") not in STATUSES:
            fail(f"control {c['bom-ref']} bad status {c.get('status')}")
        for tref in c.get("mitigations", []):
            if tref not in tset:
                fail(f"control {c['bom-ref']} links missing threat {tref}")

    # --- CRM threats: match YAML control set + link back to controls ---
    with open(os.path.join(DATA, "crm", "index.yaml"), encoding="utf-8") as f:
        idx = yaml.safe_load(f)
    expected = {c["control_id"] for c in idx["controls"]}
    seen = set()
    for t in threats:
        cid = next(
            (
                p["value"]
                for p in t.get("properties", [])
                if p["name"] == "nist:control-id"
            ),
            None,
        )
        if not cid:
            continue  # base threat (no NIST control)
        seen.add(cid)
        mits = t.get("mitigations", [])
        if not mits:
            fail(f"{cid}: threat has no linked controls (mitigations[])")
        for cref in mits:
            if cref not in cset:
                fail(f"{cid}: threat links missing control {cref}")
            # bidirectional: the control must link back to this threat
            ctrl = next(c for c in controls if c["bom-ref"] == cref)
            if t["bom-ref"] not in ctrl.get("mitigations", []):
                fail(f"{cid}: control {cref} not linked back to threat {t['bom-ref']}")
        for a in t.get("affectedAssets", []):
            if a not in aset and a not in fset:
                fail(f"{cid}: bad asset ref {a}")
        for flow_ref in t.get("affectedFlows", []):
            if flow_ref not in fset:
                fail(f"{cid}: bad affectedFlow ref {flow_ref}")
        text = " ".join([t.get("name", ""), t.get("description", "")])
        if TRANSPORT_THREAT_RE.search(text) and not t.get("affectedFlows"):
            warn(
                f"{cid or t['bom-ref']}: transport-oriented threat SHOULD populate affectedFlows[]"
            )

    missing = expected - seen
    extra = seen - expected
    if missing:
        fail(f"controls in index.yaml missing from output: {sorted(missing)}")
    if extra:
        fail(f"controls in output not in index.yaml: {sorted(extra)}")

    # --- redaction gate: no recon-useful values in the tracked artifact ---
    if "risks" in d:
        fail("gap CDX must not contain a top-level 'risks' key (ideal-state only)")
    raw = json.dumps(d)
    for pattern, label in FORBIDDEN:
        m = pattern.search(raw)
        if m:
            fail(
                f"unredacted {label} found in output: '{m.group(0)}' "
                "(see docs/redaction-guide.md)"
            )

    reusable = sum(
        1
        for c in controls
        if any(p.get("name") == "crm:evidence-key" for p in c.get("properties", []))
    )
    print(
        f"OK - DFD intact, {len(seen)} CRM threats fully formed, "
        f"{len(scenarios)} scenarios valid, {len(controls)} controls "
        f"({reusable} reusable) bidirectionally linked."
    )


if __name__ == "__main__":
    main()
