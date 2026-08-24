---
id: skill-countermeasure-audit
type: Skill
name: countermeasure-audit
description: "Devil's-advocate audit playbook for Example System-style CRM remediation plans. Cross-checks plan documents against countermeasures.yaml, generated CycloneDX, and live Precogly state to flag extraneous controls, silently omitted controls, status misalignment, cross-priority double-billing, PT-* dual-thread traps, and CDX property defects. Use when reviewing any docs/IMPLEMENTATION_PLAN_*.md that proposes remediation for tracked NIST controls."
status: stable
tier: 1
last_updated: '2026-08-13'
keywords: ['audit', 'countermeasure', 'crm', 'gap-analysis', 'precogly', 'cyclonedx', 'residual-action', 'devils-advocate']
related_files:
  - 'docs/IMPLEMENTATION_PLAN_example-system_remediation_countermeasures.md'
  - 'docs/AUDIT_IMPLEMENTATION_PLAN_example-system_remediation_countermeasures.md'
  - 'data/countermeasures/countermeasures.yaml'
  - 'data/model/evidence.yaml'
  - 'build/example-system-crm-threat-model.cdx.json'
  - 'skills/precogly-api/SKILL.md'
  - 'skills/sspp-threat-modeling/SKILL.md'
---

# Countermeasure Audit Skill

Use this skill when a stakeholder asks you to independently review any Example System /
CRM remediation plan (files matching `docs/IMPLEMENTATION_PLAN_*.md`). It
captures the concrete cross-check procedure used to produce
[docs/AUDIT_IMPLEMENTATION_PLAN_example-system_remediation_countermeasures.md](../../docs/AUDIT_IMPLEMENTATION_PLAN_example-system_remediation_countermeasures.md).

## When to use

- Reviewing a remediation / countermeasure implementation plan before it goes
  to ISSO/ISSM/AO.
- Reconciling a CDX artifact in `tmp/` against `data/countermeasures/countermeasures.yaml`.
- Confirming that a plan's promotion of `gap → proposed implemented` actually
  matches the artifact and the live Precogly state.
- Preparing an ADR that consolidates control-family closure procedures.

## Load first

- [docs/IMPLEMENTATION_PLAN_example-system_remediation_countermeasures.md](../../docs/IMPLEMENTATION_PLAN_example-system_remediation_countermeasures.md)
- [data/countermeasures/countermeasures.yaml](../../data/countermeasures/countermeasures.yaml)
- [data/model/evidence.yaml](../../data/model/evidence.yaml)
- [build/example-system-crm-threat-model.cdx.json](../../build/example-system-crm-threat-model.cdx.json)
- [skills/precogly-api/SKILL.md](../precogly-api/SKILL.md) (§ CycloneDX 2.0 Adapter, § Common Shell Queries)
- [skills/sspp-threat-modeling/SKILL.md](../sspp-threat-modeling/SKILL.md) (§ Precogly Round Trip, § Redaction Gate)

## Ten findings taxonomy

Every plan review should look for these ten defect classes and report by
severity (High / Medium / Low).

| # | Class                                | What to look for                                                                                                                                                                                                              |
| - | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A | **Extraneous controls**              | Plan lists a `control_id` not present in `countermeasures.yaml` and not in the CDX threat catalog.                                                                                                                            |
| B | **Silently omitted controls**        | `countermeasures.yaml` entry exists (typically `implemented`) but the plan never mentions it. Especially critical when the plan's P1/P2 changes could re-open the implemented posture (e.g., SA-3(2), CM-12(1)).              |
| C | **Status misalignment**              | Plan proposes remediation work on a control whose current CRM status is already `implemented` (no `residual_actions`).                                                                                                        |
| D | **Cross-priority double-billing**    | Same `control_id` claimed under multiple priorities without an owning-priority table. Blocks clean `residual_action` retirement.                                                                                              |
| E | **PT-\* dual-thread trap**           | Any PT-family control with **two** entries in its YAML `residual_actions[]` produces **two** CDX controls. Any retirement must remove both.                                                                                   |
| F | **Missing risk areas**               | Threats or scenarios present in the CDX threat catalog that the plan does not address (e.g., `Object Poisoning`, `SA-3(2)` live-data use, non-OAuth secret rotation, Delta Sharing recurring recipient review, risk scoring). |
| G | **CDX property defect**              | Controls in the CDX carrying NIST identifiers only in the free-text `name` field, missing `properties[].name: nist:control-id` or `crm:control-id`. This breaks Precogly's join between CMs and NIST families.                |
| H | **Duplicated closure procedure**     | The "regenerate + reimport + attach evidence" checklist is repeated inside every priority instead of consolidated into a single appendix.                                                                                     |
| I | **Build vs evidence conflation**     | Task described as "capture evidence" but is actually a new-build (no existing CI/config/runbook to capture). Tag each task explicitly.                                                                                        |
| J | **Sprint → residual mapping absent** | Sprint plan does not enumerate the concrete `residual_action[]` entries each sprint will close, so `make drift` cannot be a sprint exit criterion.                                                                            |

## Reproducible audit procedure

Run these six queries in order and record the outputs. Total wall time ≈ 1–2
minutes on a warm laptop.

### Step 1 — Ground-truth control counts from the source CDX

```bash
python3 - <<'PY'
import json
from collections import Counter
with open('tmp/Example Systemv2026-08-13-patched.json') as f: d = json.load(f)
controls = d.get('controls', [])
status = Counter(c.get('status') for c in controls)
print('Total controls:', len(controls))
print('Status:', dict(status))
print('Threats:', len(d.get('threats',{}).get('threats',[])))
print('Scenarios:', len(d.get('threats',{}).get('scenarios',[])))
print('Risks:', len(d.get('risks',[])))
PY
```

Expected: `Total controls: 83`, `implemented: 25`, `recommended: 58` (matches
current Example System baseline). Anything else, stop and reconcile before continuing.

### Step 2 — Extract the plan's referenced controls

Parse the "Affected controls:" line under every priority in the plan and
build one Python list `plan_ids = [...]`.

### Step 3 — Compute A and B set differences

```bash
python3 - <<'PY'
import yaml
with open('data/countermeasures/countermeasures.yaml') as f: d = yaml.safe_load(f)
yaml_ids = {c['control_id'] for c in d['countermeasures']}
plan_ids = {...}  # from Step 2
print('A - in plan, not in YAML:', sorted(plan_ids - yaml_ids))
print('B - in YAML, not in plan:', sorted(yaml_ids - plan_ids))
PY
```

- **A** = Finding A candidates (extraneous). Verify each against the CDX
  threat catalog before flagging.
- **B** = Finding B candidates (silently omitted). Check the YAML entry's
  `residual_actions` — if empty, note as "confirmed implemented, not
  acknowledged"; if not empty, escalate to High.

### Step 4 — Status misalignment (Finding C)

For every control in `plan_ids ∩ yaml_ids`, check if its YAML
`residual_actions` list is empty. If it is, the plan is proposing work on an
implemented control.

```bash
python3 - <<'PY'
import yaml
with open('data/countermeasures/countermeasures.yaml') as f: d = yaml.safe_load(f)
cms = {c['control_id']: c for c in d['countermeasures']}
plan_ids = {...}
for cid in sorted(plan_ids & set(cms)):
    if not (cms[cid].get('residual_actions') or []):
        print(f'{cid}: already implemented, plan lists as needing work')
PY
```

### Step 5 — Double-billing (Finding D)

Grep every priority's "Affected controls:" line, count occurrences per
`control_id`. Anything appearing in >1 priority is a Finding D candidate.

### Step 6 — Live Precogly cross-check (Finding G)

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@precogly.dev","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")

TMID=175  # Example System CRM Threat Model; verify with a search first
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/countermeasures/?threat_model=$TMID&page_size=200" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
r = d.get('results', d)
have_nist = sum(1 for c in r if c.get('format_metadata',{}).get('cyclonedx',{}).get('nist_control_id'))
have_evi  = sum(1 for c in r if c.get('evidence_url'))
print(f'CMs: {len(r)}  with_nist_id: {have_nist}  with_evidence_url: {have_evi}')
"
```

If `with_nist_id == 0`, escalate Finding G. If `with_evidence_url == 0`,
Finding G's corollary: no plan should promote to `implemented` before evidence
URLs land.

## Property nuance to remember

The generator (`scripts/generate.py`) writes NIST identifiers on controls in
two different property names depending on origin:

| Control origin                                                              | Property emitted                          |
| --------------------------------------------------------------------------- | ----------------------------------------- |
| Shared evidence control (from `EVIDENCE_NIST_IDS` mapping in `generate.py`) | `nist:control-id`                         |
| One-off inline `text:` mechanism                                            | `crm:control-id`                          |
| Residual-action control                                                     | `crm:control-id` + `crm:residual: "true"` |

Precogly's adapter accepts **either** and maps to
`format_metadata.cyclonedx.nist_control_id` — see
[skills/precogly-api/SKILL.md § Vault-specific CDX properties parsed during
step 10](../precogly-api/SKILL.md).

**Trap.** Precogly re-exports (files in `tmp/`) may drop these properties on
round-trip. Always audit against the **freshly generated `build/*.cdx.json`**,
not against a Precogly export.

## PT-family dual-thread quirk

Every `PT-*` countermeasure in `countermeasures.yaml` has **two** entries in
its `residual_actions[]` list:

1. FOUO / mask GAP (identical wording to the AC-2(1) family GAP).
2. `Complete PTA/PIA and SORN determinations for PII-bearing tenant data before processing.`

`generate.py` emits one CDX control per `residual_action`, so PT-2 produces
`control-55` and `control-56`, PT-3 produces `control-57`/`control-58`, etc.
Any remediation plan **must** address both threads (typically P1 handles the
mask thread; P7 handles the privacy thread) and closure must remove **both**
list entries from the YAML.

## Redaction gate

Any evidence URL, screenshot path, or attestation snippet added during
remediation must pass the redaction gate documented in
[skills/sspp-threat-modeling/SKILL.md § Redaction Gate](../sspp-threat-modeling/SKILL.md).
Reject any evidence URL that:

- points to a non-localhost host,
- contains a data platform workspace hostname,
- reveals a POC email or service-principal ID,
- names a Delta Share recipient or share.

`scripts/validate.py`'s `FORBIDDEN` regex list is authoritative.

## Deliverable format

An audit produces a single Markdown file at
`docs/AUDIT_IMPLEMENTATION_PLAN_<slug>.md` with:

- **Sources used** — enumerate every file, artifact, and API call.
- **Ground truth** — table of counts (controls / implemented / gap /
  `nist:control-id` populated / `evidence_url` populated / risks).
- **One finding section per class A–J** — even if empty, state so.
- **Summary scorecard** — count and severity per finding.
- **Recommended minimum edits to the plan** — numbered list, actionable.

Do not modify the plan in place. The plan is the ISSO's document; the audit
is the reviewer's counterpoint.

## Anti-patterns

- **Don't** grade a plan by counting priorities. The Example System plan has 7
  priorities and still misses the `Object Poisoning` custom threat entirely.
- **Don't** rely on the CDX `name` field for NIST identity — always read
  `properties[]`.
- **Don't** treat `tmp/*.json` Precogly exports as authoritative. Regenerate
  and validate against `build/*.cdx.json`.
- **Don't** promote `gap → implemented` in Precogly without an
  `evidence_url`. The countermeasure-audit signal is the count of CMs with
  populated evidence.
- **Don't** silently strengthen an already-implemented control by listing it
  in a remediation priority. Move it to a separate "runbook artifacts"
  section (Finding C).
