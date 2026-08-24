---
id: skill-sspp-threat-modeling
type: Skill
name: sspp-threat-modeling
description: 'Example System data platform SSPP / ATO support threat-modeling workflow: Precogly CycloneDX CRM artifacts, redacted CRM YAML/CSV sources, drift/reinject validation, system-scope zone rollup, and standalone repository handoff. Use when editing docs/threat-model, TTSE-petrified-forest-sspp, Precogly exports, CRM controls, or SSPP threat-model ADRs.'
status: stable
tier: 2
last_updated: '2026-08-06'
keywords: ['sspp', 'ato', 'threat-model', 'precogly', 'cyclonedx', 'crm', 'data-platform', 'redaction']
related_files:
  - 'docs/threat-model/AGENT_HANDOFF.md'
  - 'docs/threat-model/README.md'
  - 'docs/adrs/ADR-SSPP-001-versioned-precogly-crm-threat-model.md'
  - 'docs/adrs/ADR-SSPP-002-system-scope-crm-zone-rollup.md'
  - 'docs/adrs/ADR-SSPP-003-standalone-sspp-repository.md'
---

# SSPP Threat Modeling Skill

Use this skill when working on the Example System data platform SSPP threat-modeling package, including the in-pipeline `docs/threat-model/` copy and the standalone `TTSE-petrified-forest-sspp` repository.

## Load First

Before editing, read:

- `docs/threat-model/AGENT_HANDOFF.md`
- `docs/threat-model/README.md`
- `docs/adrs/ADR-SSPP-001-versioned-precogly-crm-threat-model.md`
- `docs/adrs/ADR-SSPP-002-system-scope-crm-zone-rollup.md`
- `docs/adrs/ADR-SSPP-003-standalone-sspp-repository.md`

If working in the standalone repository, the former `docs/threat-model/` paths are rooted at repository root.

## Core Rules

- Treat `build/example-system-crm-threat-model.cdx.json` as intentionally version-controlled.
- Do not directly edit generated CRM threats, scenarios, or controls in the Precogly export; update YAML sources and reinject.
- Treat the DFD as user/editor-owned and preserve it in `data/model/base-dfd.cdx.json`.
- Model CRM obligations as system-scope responsibilities by rolling declared zones up to member assets.
- Add component-specific or zone-specific threats separately; do not overload CRM controls to represent every architectural risk.
- Keep raw CSVs manually redacted and preserve them as provenance.
- Never commit secrets, PII, internal hostnames, internal URLs, data platform workspace hosts, service-principal IDs, or Delta Share recipient/share names.

## Required Commands

Run these before declaring changes complete:

```bash
make validate
make drift
```

If dependencies are missing in the standalone repository, use the checked-in `pyproject.toml`/`uv.lock` and run through `uv` via the Makefile.

If the artifact drift is intentional because YAML or base DFD changed, run:

```bash
make reinject
make validate
make drift
```

## Redaction Gate

The artifact must not contain:

- Non-localhost URLs or URIs.
- data platform workspace hostnames.
- Email addresses or POC identifiers.
- Service-principal IDs.
- Delta Share recipient or share names.

Use placeholders such as `<DATA-PLATFORM_WORKSPACE_HOST>`, `<POC_EMAIL>`, and `<REDACTED_URL>`.

## Precogly Round Trip

1. Import `build/example-system-crm-threat-model.cdx.json` into Precogly.
2. Edit DFD assets, flows, zones, boundaries, or visualizations.
3. Export the diagram.
4. Extract/preserve the editor-owned DFD in `data/model/base-dfd.cdx.json`.
5. Keep CRM entities generated from YAML.
6. Run `make reinject validate drift`.

## Known Modeling Decision

`flow-flow-22` currently targets `zone-example-system-gov-3` as a flow destination in the editor export. The reconciled standalone validator permits flow endpoints to reference either assets or zones. If stakeholders decide every flow must target concrete assets, retarget that flow and rerun reinjection/validation.

## Repository Split

The standalone repository should be treated as the canonical implementation target once pushed:

```text
https://github.com/GSA-TTS/TTSE-petrified-forest-sspp.git
```

Until the split is fully completed, confirm with the user before making functional edits to both the pipeline copy and the standalone copy.
