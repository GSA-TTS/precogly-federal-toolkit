#!/usr/bin/env python3
"""Generate the Example System CRM threat model in its IDEAL / DESIRED post-remediation
state as an isolated CycloneDX artifact suitable for direct import into
Precogly as a separate threat model.

WHAT THIS DOES
--------------
1. Loads the current gap-tracking CDX
   `build/example-system-crm-threat-model.cdx.json` (produced by `scripts/generate.py`).
2. Applies the overlay in `data/ideal-state/overlay.yaml`:
   - Promotes every `recommended` control to `verified`.
   - Emits `ctrl:id` on every control.
   - Adds mock evidence URLs (localhost placeholders that satisfy the
     redaction gate) as CDX `externalReferences[]` and a duplicate
     `evidence:url` property so Precogly picks them up regardless of adapter
     version.
   - Adds every scenario an `inherentSeverity` and `residualSeverity` derived
     from the priority cluster.
   - Populates `risks[]` — one Risk per priority cluster (Finding F.5).
   - Adds a synthetic P8 countermeasure covering the `Object Poisoning`
     custom threat (Finding F.1).
   - Renames the top-level threat model to distinguish it from the
     gap-tracking model in Precogly.

Output: `build/example-system-crm-threat-model-ideal.cdx.json` (deterministic).

This artifact is intentionally MOCKED. Nothing in it asserts that Example System is in
this state today; every evidence URL is a `https://localhost:8443/...`
placeholder. See `data/ideal-state/overlay.yaml` for the mock scheme.
"""

import argparse
import copy
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
DEFAULT_IN = os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")
DEFAULT_OUT = os.path.join(ROOT, "build", "example-system-crm-threat-model-ideal.cdx.json")

if HERE not in sys.path:
    sys.path.insert(0, HERE)

from systems.loader import DEFAULT_SYSTEM, load_system  # noqa: E402

SEVERITY_LEVELS = {"info", "low", "medium", "high", "critical"}

# Stable UUID namespace so re-runs produce the same serialNumber.
_IDEAL_UUID_NS = uuid.UUID("f9d1dea1-0000-4000-8000-000000000001")


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_prop(props, name):
    return next((p.get("value") for p in props or [] if p.get("name") == name), None)


def upsert_prop(props, name, value):
    """Insert or replace a CycloneDX-style {name, value} property."""
    for p in props:
        if p.get("name") == name:
            p["value"] = value
            return
    props.append({"name": name, "value": value})


def control_id_for(ctrl):
    """Return the control id for a control. Prefers ctrl:id; shared-evidence
    controls carry ctrl:id mapped to their primary id in scripts/generate.py."""
    props = ctrl.get("properties", [])
    return get_prop(props, "ctrl:id")


def is_residual(ctrl):
    return get_prop(ctrl.get("properties", []), "resp:residual") == "true"


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def add_evidence(ctrl, url, description=None, key=None):
    """Attach evidence to a control in two shapes: CDX-standard
    externalReferences[] and a duplicate evidence:url property. Precogly
    versions vary in which one they surface as `evidence_url`."""
    ext = ctrl.setdefault("externalReferences", [])
    ref = {"type": "documentation", "url": url}
    if description:
        ref["comment"] = description
    ext.append(ref)
    props = ctrl.setdefault("properties", [])
    upsert_prop(props, "evidence:url", url)
    if key:
        upsert_prop(props, "evidence:key", key)


def promote_and_evidence(controls, overlay):
    """Promote all `recommended` controls to `verified` and attach mock
    evidence per the overlay. Also ensure every control carries ctrl:id."""
    root = overlay["evidence_root"].rstrip("/")
    target_status = overlay.get("default_target_status", "verified")
    priorities = overlay["priorities"]
    control_priority_map = overlay["control_priority_map"]
    extra_evidence = overlay.get("extra_evidence", {})
    control_overrides = overlay.get("control_evidence_overrides", {})

    promoted = 0
    for ctrl in controls:
        cid = control_id_for(ctrl) or ""
        props = ctrl.setdefault("properties", [])

        # (a) Normalize ctrl:id so downstream queries work.
        norm = get_prop(props, "ctrl:id")
        if norm:
            upsert_prop(props, "ctrl:id", norm)

        # (b) Promote status if this is a residual / recommended entry.
        old_status = ctrl.get("status")
        if old_status in ("recommended", "in-progress"):
            ctrl["status"] = target_status
            promoted += 1
            upsert_prop(props, "mock:promotion", "true")
            upsert_prop(props, "mock:previous-status", old_status)

        # (c) Attach mock evidence.
        pri = control_priority_map.get(cid)
        if pri is None:
            # Already-implemented control with no overlay entry; still attach
            # a "baseline" evidence pointer so every control has an
            # evidence_url after import.
            pri = "P0"
        pri_meta = priorities[pri]
        pri_slug = pri_meta["slug"]
        control_slug = slug(cid) if cid else slug(ctrl.get("name", ""))
        url = f"{root}/{pri_slug}/{control_slug or ctrl['bom-ref']}.pdf"
        add_evidence(
            ctrl,
            url,
            description=f"Mock evidence bundle for {pri} — {pri_meta['title']}",
        )

        # (d) Attach per-control extra evidence snippets as properties so the
        # imported CM description references the ideal narrative.
        for k in control_overrides.get(cid, []):
            snippet = extra_evidence.get(k)
            if snippet:
                upsert_prop(props, f"evidence:{k}", snippet.strip())

        upsert_prop(props, "mock:priority", pri)
        upsert_prop(props, "mock:priority-title", pri_meta["title"])

    return promoted


def score_scenarios(scenarios, controls, overlay):
    """Assign inherent + residual severities to every scenario. The inherent
    level is the pre-remediation risk carried in the base CDX (`riskScore.level`
    when set) or `high` by default for residual controls. The residual level
    is `low` because every gap has been treated as implemented + evidenced."""
    {c["bom-ref"]: c for c in controls}
    scored = 0
    for s in scenarios:
        # Base CDX already stores an approximate level under riskScore.level;
        # promote it to inherentSeverity, then set residual to `low`.
        rs = s.get("riskScore", {}) or {}
        inherent = (rs.get("level") or "medium").lower()
        if inherent not in SEVERITY_LEVELS:
            inherent = "medium"
        s["inherentSeverity"] = inherent
        s["residualSeverity"] = "low"
        # Also stamp the priority (helpful for filtering in Precogly).
        scenario_threats = s.get("threats") or (
            [s["threat"]] if s.get("threat") else []
        )
        linked = [
            c
            for c in controls
            if any(ref in c.get("mitigations", []) for ref in scenario_threats)
        ]
        pri = None
        for c in linked:
            pri = get_prop(c.get("properties", []), "mock:priority")
            if pri:
                break
        if pri:
            s.setdefault("properties", []).append(
                {"name": "mock:priority", "value": pri}
            )
        scored += 1
    return scored


def build_risks(controls, overlay):
    """Emit one Risk per priority cluster in the Precogly-native shape:
    ``risks: {risks: [...]}`` with per-rating ``{riskScore: {level, score}}``
    blocks. Confirmed by reading `apps/threat_models/adapters/cyclonedx.py`
    (`_import_risk`, `_extract_risk_score`) inside the local precogly-backend
    container."""
    level_to_score = {"info": 10, "low": 20, "medium": 45, "high": 70, "critical": 90}
    ctrl_by_pri = {}
    for c in controls:
        p = get_prop(c.get("properties", []), "mock:priority")
        if p:
            ctrl_by_pri.setdefault(p, []).append(c["bom-ref"])
    risks = []
    for r in overlay["risks"]:
        risk = {
            "bom-ref": r["id"],
            "name": r["name"],
            "statement": r["description"].strip(),
            "inherentRisk": {
                "riskScore": {
                    "level": r["inherent_level"],
                    "score": level_to_score[r["inherent_level"]],
                }
            },
            "residualRisk": {
                "riskScore": {
                    "level": r["residual_level"],
                    "score": level_to_score[r["residual_level"]],
                }
            },
            "targetRisk": {
                "riskScore": {
                    "level": r["target_level"],
                    "score": level_to_score[r["target_level"]],
                }
            },
            "domains": r.get("domains", []),
            "properties": [
                {"name": "mock:priority", "value": r["priority"]},
                {
                    "name": "mock:mitigating-controls",
                    "value": ",".join(ctrl_by_pri.get(r["priority"], [])),
                },
            ],
        }
        risks.append(risk)
    return {"risks": risks}


def add_object_poisoning_countermeasure(cdx, overlay, next_seq):
    """Add a synthetic P8 control mitigating the `Object Poisoning` threat.
    That threat is present in the base DFD but has no dedicated
    countermeasure entry today."""
    threats = cdx.get("threats", {}).get("threats", [])
    op_threats = [
        t
        for t in threats
        if (t.get("name") or "").strip().lower() == "object poisoning"
    ]
    if not op_threats:
        return None
    op_meta = overlay["object_poisoning_countermeasure"]
    root = overlay["evidence_root"].rstrip("/")
    pri_slug = overlay["priorities"]["P8"]["slug"]
    ctrl = {
        "bom-ref": f"control-p8-object-poisoning-{next_seq}",
        "name": op_meta["name"],
        "status": "verified",
        "description": op_meta["description"].strip(),
        "category": op_meta.get("category", "preventive"),
        "properties": [
            {"name": "ctrl:id", "value": "SI-10"},
            {"name": "mock:priority", "value": "P8"},
            {
                "name": "mock:priority-title",
                "value": overlay["priorities"]["P8"]["title"],
            },
            {"name": "mock:synthetic", "value": "true"},
        ],
        "mitigations": [t["bom-ref"] for t in op_threats],
    }
    for k in op_meta.get("evidence_keys", []):
        snippet = overlay["extra_evidence"].get(k, "")
        if snippet:
            upsert_prop(ctrl["properties"], f"evidence:{k}", snippet.strip())
    add_evidence(
        ctrl,
        f"{root}/{pri_slug}/object-poisoning.pdf",
        description="Mock evidence bundle for P8 — Data-supply-chain integrity",
    )
    # Link the threats back to this control.
    for t in op_threats:
        t.setdefault("mitigations", []).append(ctrl["bom-ref"])
    return ctrl


def bump_metadata(cdx):
    cdx["serialNumber"] = (
        f"urn:uuid:{uuid.uuid5(_IDEAL_UUID_NS, json.dumps(cdx.get('controls', []), sort_keys=True))}"
    )
    cdx["version"] = (
        int(cdx.get("version", 1)) + 100
    )  # separate from gap-tracking versioning
    bp = cdx["blueprints"][0]
    # Force a recognizable, deterministic blueprint name so Precogly imports
    # this as "Example System CRM Threat Model (Ideal State)" regardless of what the
    # editor called the source diagram.
    bp["name"] = "Example System CRM Threat Model (Ideal State)"
    meta = cdx.setdefault("metadata", {})
    meta["timestamp"] = (
        datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    props = meta.setdefault("properties", [])
    upsert_prop(props, "resp:profile", "ideal-state")
    upsert_prop(props, "resp:generated-by", "scripts/generate_ideal.py")
    upsert_prop(
        props,
        "resp:notice",
        "MOCK ARTIFACT — every evidence URL is a localhost placeholder. "
        "This TM represents the desired post-remediation state, not Example System's "
        "current implementation posture.",
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument(
        "--system",
        default=os.environ.get("SYSTEM", DEFAULT_SYSTEM),
        help="System slug under data/systems/ (default: %(default)s)",
    )
    ap.add_argument(
        "--overlay",
        default=None,
        help="Override ideal-state overlay YAML (defaults to the resolved "
        "per-system path from the loader).",
    )
    args = ap.parse_args()

    paths = load_system(args.system)
    overlay_path = args.overlay or (
        str(paths.ideal_overlay)
        if paths.ideal_overlay
        else os.path.join(DATA, "ideal-state", "overlay.yaml")
    )

    if not os.path.exists(args.inp):
        sys.exit(
            f"missing input CDX: {args.inp}\n"
            "run `make generate` first (this script post-processes the base "
            "gap-tracking CDX)."
        )

    with open(args.inp, encoding="utf-8") as f:
        cdx = json.load(f)
    overlay = load_yaml(overlay_path)

    # Deep copy so we never mutate the source artifact.
    cdx = copy.deepcopy(cdx)

    controls = cdx.get("controls", [])
    scenarios = cdx.get("threats", {}).get("scenarios", [])

    promoted = promote_and_evidence(controls, overlay)
    target_status = overlay.get("default_target_status", "verified")
    scored = score_scenarios(scenarios, controls, overlay)

    # Synthetic P8 control for Object Poisoning.
    next_seq = 1000
    op_ctrl = add_object_poisoning_countermeasure(cdx, overlay, next_seq)
    if op_ctrl is not None:
        controls.append(op_ctrl)

    cdx["risks"] = build_risks(controls, overlay)

    bump_metadata(cdx)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2, ensure_ascii=False)
        f.write("\n")

    implemented = sum(1 for c in controls if c.get("status") == "implemented")
    with_evidence = sum(
        1
        for c in controls
        if c.get("externalReferences")
        or get_prop(c.get("properties", []), "evidence:url")
    )
    print(
        f"Wrote {os.path.relpath(args.out, ROOT)}",
        file=sys.stderr,
    )
    print(
        f"Controls: {len(controls)}  implemented: {implemented}  with evidence: {with_evidence}",
        file=sys.stderr,
    )
    print(f"Promoted recommended -> {target_status}: {promoted}", file=sys.stderr)
    print(f"Scenarios scored: {scored}", file=sys.stderr)
    print(f"Risks emitted: {len(cdx['risks'])}", file=sys.stderr)
    if op_ctrl is not None:
        print(
            f"Object Poisoning covered by synthetic control: {op_ctrl['bom-ref']}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
