#!/usr/bin/env python3
"""Diff the gap-tracking Example System CDX against the IDEAL CDX to make it easy to
review what changes between the two.

Categories reported:
- Controls: count by status (before -> after), controls promoted, controls
  gaining evidence, controls gaining nist:control-id parity.
- Scenarios: count with residualSeverity populated (before -> after).
- Risks: count of Risk objects (before -> after).
- Object Poisoning: mitigations count (before -> after).

Optional flags:
  --json    Machine-readable summary to stdout.
  --full    Also print every control that changed status or gained evidence.
"""

import argparse
import json
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_A = os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")
DEFAULT_B = os.path.join(ROOT, "build", "example-system-crm-threat-model-ideal.cdx.json")


def prop(props, name):
    return next((p.get("value") for p in props or [] if p.get("name") == name), None)


def has_evidence(c):
    if c.get("externalReferences"):
        return True
    return prop(c.get("properties", []), "evidence:url") is not None


def summary(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    controls = d.get("controls", [])
    scenarios = d.get("threats", {}).get("scenarios", [])
    threats = d.get("threats", {}).get("threats", [])
    _risks_block = d.get("risks", {})
    risks = (
        _risks_block.get("risks", [])
        if isinstance(_risks_block, dict)
        else _risks_block
    )
    status = Counter(c.get("status") for c in controls)
    with_nist = sum(
        1 for c in controls if prop(c.get("properties", []), "nist:control-id")
    )
    with_crm = sum(
        1 for c in controls if prop(c.get("properties", []), "crm:control-id")
    )
    with_both = sum(
        1
        for c in controls
        if prop(c.get("properties", []), "nist:control-id")
        and prop(c.get("properties", []), "crm:control-id")
    )
    with_evi = sum(1 for c in controls if has_evidence(c))
    scen_scored = sum(
        1 for s in scenarios if s.get("inherentSeverity") and s.get("residualSeverity")
    )
    op_threats = [
        t
        for t in threats
        if (t.get("name") or "").strip().lower() == "object poisoning"
    ]
    op_mit = sum(len(t.get("mitigations", [])) for t in op_threats)
    return {
        "path": path,
        "controls_total": len(controls),
        "controls_by_status": dict(status),
        "controls_with_nist_control_id": with_nist,
        "controls_with_crm_control_id": with_crm,
        "controls_with_both_ids": with_both,
        "controls_with_evidence": with_evi,
        "scenarios_total": len(scenarios),
        "scenarios_scored": scen_scored,
        "risks_total": len(risks),
        "object_poisoning_threats": len(op_threats),
        "object_poisoning_mitigations": op_mit,
    }


def diff_controls(a_path, b_path):
    """Return the list of controls whose status changed or which gained evidence."""
    with open(a_path, encoding="utf-8") as f:
        a = json.load(f)
    with open(b_path, encoding="utf-8") as f:
        b = json.load(f)
    a_by_ref = {c["bom-ref"]: c for c in a.get("controls", [])}
    changes = []
    for c in b.get("controls", []):
        ref = c["bom-ref"]
        prev = a_by_ref.get(ref)
        if prev is None:
            changes.append({"bom_ref": ref, "kind": "added", "name": c.get("name")})
            continue
        row = {"bom_ref": ref, "name": c.get("name")}
        if prev.get("status") != c.get("status"):
            row["status_change"] = f"{prev.get('status')} -> {c.get('status')}"
        if has_evidence(c) and not has_evidence(prev):
            row["gained_evidence"] = True
        if len(row) > 2:
            changes.append(row)
    return changes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", default=DEFAULT_A, help="baseline gap-tracking CDX")
    ap.add_argument("--b", default=DEFAULT_B, help="ideal-state CDX")
    ap.add_argument("--json", action="store_true", help="emit JSON summary")
    ap.add_argument("--full", action="store_true", help="also list per-control changes")
    args = ap.parse_args()

    a = summary(args.a)
    b = summary(args.b)

    if args.json:
        out = {"baseline": a, "ideal": b}
        if args.full:
            out["control_changes"] = diff_controls(args.a, args.b)
        print(json.dumps(out, indent=2))
        return

    def line(label, av, bv):
        print(f"  {label:40s} {av!s:>12}  ->  {bv!s:<12}")

    print(f"Baseline: {os.path.relpath(args.a, ROOT)}")
    print(f"Ideal:    {os.path.relpath(args.b, ROOT)}")
    print()
    line("controls total", a["controls_total"], b["controls_total"])
    line(
        "  implemented",
        a["controls_by_status"].get("implemented", 0),
        b["controls_by_status"].get("implemented", 0),
    )
    line(
        "  recommended (gap)",
        a["controls_by_status"].get("recommended", 0),
        b["controls_by_status"].get("recommended", 0),
    )
    line(
        "  verified",
        a["controls_by_status"].get("verified", 0),
        b["controls_by_status"].get("verified", 0),
    )
    line(
        "controls w/ nist:control-id",
        a["controls_with_nist_control_id"],
        b["controls_with_nist_control_id"],
    )
    line(
        "controls w/ crm:control-id",
        a["controls_with_crm_control_id"],
        b["controls_with_crm_control_id"],
    )
    line(
        "controls w/ BOTH id props",
        a["controls_with_both_ids"],
        b["controls_with_both_ids"],
    )
    line(
        "controls w/ evidence", a["controls_with_evidence"], b["controls_with_evidence"]
    )
    print()
    line("scenarios total", a["scenarios_total"], b["scenarios_total"])
    line("scenarios scored (both sev)", a["scenarios_scored"], b["scenarios_scored"])
    print()
    line("risks[]", a["risks_total"], b["risks_total"])
    print()
    line(
        "Object Poisoning threats",
        a["object_poisoning_threats"],
        b["object_poisoning_threats"],
    )
    line(
        "Object Poisoning mitigations",
        a["object_poisoning_mitigations"],
        b["object_poisoning_mitigations"],
    )

    if args.full:
        changes = diff_controls(args.a, args.b)
        print(f"\nControl-level changes: {len(changes)}")
        for row in changes:
            bits = []
            if row.get("kind") == "added":
                bits.append("ADDED")
            if "status_change" in row:
                bits.append(row["status_change"])
            if row.get("gained_evidence"):
                bits.append("+evidence")
            print(
                f"  {row['bom_ref']:60s} {' '.join(bits):40s} {(row.get('name') or '')[:60]}"
            )


if __name__ == "__main__":
    main()
