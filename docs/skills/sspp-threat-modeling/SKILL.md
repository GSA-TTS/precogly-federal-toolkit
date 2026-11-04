---
id: skill-sspp-threat-modeling
type: Skill
name: sspp-threat-modeling
description: 'Generic SSPP threat-modeling workflow: Precogly CycloneDX CRM artifacts, redacted YAML/CSV sources, drift/reinject validation, and system-scope zone rollup. Use for a private system repository that consumes this toolkit.'
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

Use this skill when working on an SSPP threat-modeling package in a private system repository that consumes this toolkit.

## Load First

Before editing, read:

- the consuming repository's threat-model README and architecture decision records;
- its redaction policy and system-specific source-of-truth documentation;
- its generated-artifact and drift-validation instructions.

## Core Rules

- Treat `build/<system>-crm-threat-model.cdx.json` as intentionally version-controlled.
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

1. Import `build/<system>-crm-threat-model.cdx.json` into Precogly.
2. Edit DFD assets, flows, zones, boundaries, or visualizations.
3. Export the diagram.
4. Extract/preserve the editor-owned DFD in `data/model/base-dfd.cdx.json`.
5. Keep CRM entities generated from YAML.
6. Run `make reinject validate drift`.

## Known Modeling Decision

A consuming repository may model a flow endpoint as either an asset or a zone when its editor/export contract permits it. Document any such decision locally and rerun reinjection and validation after changing it.

## Repository boundary

This toolkit contains reusable tooling and sanitized examples. Keep system-specific DFDs, CRM content, evidence, and authorization artifacts in the consuming private repository.
