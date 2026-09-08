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

# scripts/systems is not on PYTHONPATH when running via ``uv run python
# scripts/validate.py``; prepend HERE so ``from systems.loader import ...``
# resolves without requiring callers to set PYTHONPATH.
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from flow_auth import load_auth_catalog  # noqa: E402
from systems.loader import DEFAULT_SYSTEM, load_system  # noqa: E402

CATEGORIES = {"preventive", "detective", "corrective"}
STATUSES = {
    "verified",
    "recommended",
    "rejected",
    "implemented",
    "in-progress",
    "planned",
}
TRANSPORT_THREAT_RE = re.compile(
    r"\b(mitm|man[- ]in[- ]the[- ]middle|eavesdropp?ing|replay|downgrade|cleartext|transport)\b",
    re.IGNORECASE,
)

# Universal recon-useful patterns that MUST NOT appear in any tracked build
# artifact (see docs/redaction-guide.md). System-specific patterns (e.g. Example System's
# data platform workspace host, service-principal ids, UAT share recipients) live
# in ``data/systems/<slug>/redaction.yaml`` and are merged in at runtime by
# ``_load_forbidden``.
FORBIDDEN = [
    (
        re.compile(r"https?://(?!localhost|127\.0\.0\.1|github\.com)", re.IGNORECASE),
        "URL/URI",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "email / POC identifier",
    ),
    (re.compile(r"itplaybook\.gsa\.gov", re.IGNORECASE), "internal DocOps host"),
]


_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


def _load_forbidden(redaction_path):
    """Merge universal + per-system forbidden patterns."""
    patterns = list(FORBIDDEN)
    if not redaction_path:
        return patterns
    with open(redaction_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    for entry in cfg.get("forbidden_patterns", []) or []:
        pat = entry.get("pattern")
        label = entry.get("label", "system-specific redaction")
        if not pat:
            continue
        flags = 0
        for flag_name in entry.get("flags", []) or []:
            flags |= _FLAG_MAP.get(flag_name.upper(), 0)
        patterns.append((re.compile(pat, flags), label))
    return patterns


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print(f"WARN: {msg}", file=sys.stderr)


def same_boundary(source_zone, destination_zone):
    return source_zone == destination_zone and source_zone is not None


def main():
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "artifact",
        nargs="?",
        default=DEFAULT,
        help="CDX artifact to validate (default: %(default)s).",
    )
    ap.add_argument(
        "--system",
        default=DEFAULT_SYSTEM,
        help="System slug for base-DFD / CRM index resolution (default: %(default)s).",
    )
    args = ap.parse_args()

    paths = load_system(args.system)
    path = args.artifact
    with open(path, encoding="utf-8") as f:
        d = json.load(f)

    with open(paths.model_dfd, encoding="utf-8") as f:
        base = json.load(f)
    with open(paths.model_architecture, encoding="utf-8") as f:
        arch = yaml.safe_load(f) or {}
    allowed_auth, warning_auth = load_auth_catalog(arch=arch)
    known_auth = allowed_auth | set(warning_auth)

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
        if auth and auth not in known_auth:
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
    with open(paths.crm_index, encoding="utf-8") as f:
        idx = yaml.safe_load(f)
    expected = {c["control_id"] for c in idx["controls"]}
    seen = set()
    base_threat_refs = {
        bt["bom-ref"] for bt in base.get("threats", {}).get("threats", [])
    }
    for t in threats:
        if t.get("bom-ref") in base_threat_refs:
            continue  # base threat (from base DFD, not CRM generated)
        cid = next(
            (p["value"] for p in t.get("properties", []) if p["name"] == "ctrl:id"),
            None,
        )
        if not cid:
            continue  # non-CRM threat (no NIST control)
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
    forbidden = _load_forbidden(paths.redaction)
    for pattern, label in forbidden:
        m = pattern.search(raw)
        if m:
            fail(
                f"unredacted {label} found in output: '{m.group(0)}' "
                "(see docs/redaction-guide.md)"
            )

    reusable = sum(
        1
        for c in controls
        if any(p.get("name") == "resp:evidence-key" for p in c.get("properties", []))
    )
    print(
        f"OK - DFD intact, {len(seen)} CRM threats fully formed, "
        f"{len(scenarios)} scenarios valid, {len(controls)} controls "
        f"({reusable} reusable) bidirectionally linked."
    )


if __name__ == "__main__":
    main()
