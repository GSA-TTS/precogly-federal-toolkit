#!/usr/bin/env python3
"""Validate the IDEAL / DESIRED Example System CRM threat model produced by
scripts/generate_ideal.py.

Invariants checked (fail = non-zero exit):
- Every control is `implemented` or `verified` (no `gap` / `recommended`).
- Every control carries BOTH `nist:control-id` and `crm:control-id`
  properties (Finding G).
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
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT = os.path.join(ROOT, "build", "example-system-crm-threat-model-ideal.cdx.json")

ALLOWED_STATUS = {"verified"}
SEVERITY_LEVELS = {"info", "low", "medium", "high", "critical"}

FORBIDDEN = [
    (re.compile(r"https?://(?!localhost|127\.0\.0\.1)", re.IGNORECASE), "URL/URI"),
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


def get_prop(props, name):
    return next((p.get("value") for p in props or [] if p.get("name") == name), None)


def has_evidence(ctrl):
    if ctrl.get("externalReferences"):
        return True
    return get_prop(ctrl.get("properties", []), "evidence:url") is not None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
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
        nist = get_prop(props, "nist:control-id")
        crm = get_prop(props, "crm:control-id")
        if not nist or not crm:
            missing_props.append(c["bom-ref"])
        if not has_evidence(c):
            missing_evidence.append(c["bom-ref"])

    if missing_props:
        fail(
            f"{len(missing_props)} control(s) missing both nist:control-id and "
            f"crm:control-id properties: e.g. {missing_props[:3]}"
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

    raw = json.dumps(d)
    for pattern, label in FORBIDDEN:
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
