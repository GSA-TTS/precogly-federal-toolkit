#!/usr/bin/env python3
"""Validate the IDEAL / DESIRED Example System CRM threat model produced by
scripts/generate_ideal.py.

Invariants checked (fail = non-zero exit):
- Every control is `implemented` or `verified` (no `gap` / `recommended`).
- Every control carries `ctrl:id` property.
- Every control has evidence: either an `externalReferences[]` entry OR a
  `properties[].name: evidence:url` property.
- Every scenario has `inherentSeverity` and `residualSeverity` in the
  allowed set.
- `risks[]` has at least 7 entries (one per priority cluster P1..P7 minimum).
- The `Object Poisoning` custom threat has at least one control linked.
- Same redaction gate as `scripts/validate.py` (regex list is authoritative).
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT = os.path.join(ROOT, "build", "example-system-crm-threat-model-ideal.cdx.json")

if HERE not in sys.path:
    sys.path.insert(0, HERE)

from systems.loader import DEFAULT_SYSTEM, load_system  # noqa: E402
from validate import _load_forbidden  # noqa: E402

ALLOWED_STATUS = {"verified", "implemented"}
SEVERITY_LEVELS = {"info", "low", "medium", "high", "critical"}


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def get_prop(props, name):
    return next((p.get("value") for p in props or [] if p.get("name") == name), None)


def has_evidence(ctrl):
    if ctrl.get("externalReferences"):
        return True
    return get_prop(ctrl.get("properties", []), "evidence:url") is not None


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=DEFAULT)
    parser.add_argument(
        "--system",
        default=os.environ.get("SYSTEM", DEFAULT_SYSTEM),
        help="System slug under data/systems/ (default: %(default)s)",
    )
    args = parser.parse_args()
    path = args.path
    paths = load_system(args.system)
    if not os.path.exists(path):
        fail(f"missing ideal artifact: {path} — run `make generate-ideal` first")
    with open(path, encoding="utf-8") as f:
        d = json.load(f)

    controls = d.get("controls", [])
    scenarios = d.get("threats", {}).get("scenarios", [])
    threats = d.get("threats", {}).get("threats", [])
    risks_block = d.get("risks", {})
    risks = (
        risks_block.get("risks", []) if isinstance(risks_block, dict) else risks_block
    )

    if not controls:
        fail("no controls[] emitted")

    control_refs = {
        str(control["bom-ref"]) for control in controls if control.get("bom-ref")
    }
    bad_status = [
        c["bom-ref"] for c in controls if c.get("status") not in ALLOWED_STATUS
    ]
    if bad_status:
        fail(
            f"{len(bad_status)} control(s) not in {sorted(ALLOWED_STATUS)}: "
            f"e.g. {bad_status[:3]}"
        )

    missing_props = []
    missing_evidence = []
    for c in controls:
        props = c.get("properties", [])
        ctrl_id = get_prop(props, "ctrl:id")
        if not ctrl_id:
            missing_props.append(c["bom-ref"])
        if not has_evidence(c):
            missing_evidence.append(c["bom-ref"])

    if missing_props:
        fail(
            f"{len(missing_props)} control(s) missing ctrl:id "
            f"property: e.g. {missing_props[:3]}"
        )
    if missing_evidence:
        fail(
            f"{len(missing_evidence)} control(s) missing evidence "
            f"(externalReferences or evidence:url property): e.g. "
            f"{missing_evidence[:3]}"
        )

    bad_scen = []
    for s in scenarios:
        i = (s.get("inherentSeverity") or "").lower()
        r = (s.get("residualSeverity") or "").lower()
        if i not in SEVERITY_LEVELS or r not in SEVERITY_LEVELS:
            bad_scen.append(s.get("bom-ref"))
    if bad_scen:
        fail(f"{len(bad_scen)} scenario(s) missing / bad severity: e.g. {bad_scen[:3]}")

    if len(risks) < 7:
        fail(f"expected >= 7 risks (one per priority cluster), got {len(risks)}")

    op = [
        t
        for t in threats
        if (t.get("name") or "").strip().lower() == "object poisoning"
    ]
    if op:
        for t in op:
            if not t.get("mitigations"):
                fail(f"Object Poisoning threat {t['bom-ref']} has no linked controls")
            unknown_mitigations = sorted(set(t["mitigations"]) - control_refs)
            if unknown_mitigations:
                fail(
                    f"Object Poisoning threat {t['bom-ref']} references unknown "
                    f"control(s): {unknown_mitigations[:3]}"
                )

    raw = json.dumps(d)
    forbidden = _load_forbidden(paths.redaction)
    for pattern, label in forbidden:
        m = pattern.search(raw)
        if m:
            fail(f"unredacted {label}: {m.group(0)}")

    print(
        f"OK - {len(controls)} controls (all implemented/verified), "
        f"{len(scenarios)} scenarios scored, {len(risks)} risks, "
        f"redaction clean."
    )


if __name__ == "__main__":
    main()
