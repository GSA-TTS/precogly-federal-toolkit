---
id: skill-sspp-threat-modeling
type: Skill
name: sspp-threat-modeling
description: 'SSPP / ATO support threat-modeling workflow: Precogly CycloneDX CRM artifacts, redacted YAML/CSV sources, drift/reinject validation, editor-DFD round trip, and system-scope zone rollup. Use when editing data/systems/<slug>/ sources, Precogly exports, CRM controls, or SSPP threat-model ADRs.'
status: stable
tier: 2
last_updated: '2026-11-05'
keywords: ['sspp', 'ato', 'threat-model', 'precogly', 'cyclonedx', 'crm', 'data-platform', 'redaction']
related_files:
  - 'docs/threat-model-authoring-guide.md'
  - 'docs/redaction-guide.md'
---

# SSPP Threat Modeling Skill

Use this skill when working on an SSPP threat-modeling package: the per-system YAML sources under `data/systems/<slug>/`, the generated Precogly CycloneDX artifact, and the editor-owned DFD.

## Load First

Before editing, read:

- `docs/threat-model-authoring-guide.md` (source layout and authoring rules);
- `docs/redaction-guide.md` (what must never be committed, and the CUI/provenance gates);
- the system's own README and architecture decision records, including the system-scope CRM zone rollup decision (ADR-SSPP-002) and the standalone-repository decision (ADR-SSPP-003).

## Core Rules

- Treat `build/<system>-crm-threat-model.cdx.json` as a generated, intentionally version-controlled artifact. Never edit it by hand.
- Do not directly edit generated CRM threats, scenarios, or controls in the Precogly export; update the YAML sources and reinject.
- Treat the DFD as user/editor-owned and preserve it in `data/systems/<slug>/model/base-dfd.cdx.json`.
- Model CRM obligations as system-scope responsibilities by rolling declared zones up to member assets.
- Add component-specific or zone-specific threats separately; do not overload CRM controls to represent every architectural risk.
- Keep raw CSVs manually redacted and preserve them as provenance.
- Never commit secrets, PII, internal hostnames, internal URLs, data platform workspace hosts, service-principal IDs, or Delta Share recipient/share names.

## Required Commands

Run these before declaring changes complete (`SYSTEM=<slug>` selects the system; the default is set in the Makefile):

```bash
make validate-sources
make validate
make drift
make test
```

Dependencies are resolved from the checked-in `pyproject.toml`/`uv.lock` through `uv` via the Makefile.

If the artifact drift is intentional because YAML or the base DFD changed, run:

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
4. Run `make rehydrate-dfd DFD_EXPORT=<path>` to dedupe and scrub the export into `data/systems/<slug>/model/base-dfd.cdx.json`. Editor exports carry author emails in `metadata.authors[]`; `make scrub-check` must pass before committing.
5. Keep CRM entities generated from YAML.
6. Run `make reinject validate drift`.

`make dfd-drift DFD_EXPORT=<path>` compares an export against the checked-in DFD without changing it.

## Known Modeling Decision

A flow endpoint (`source` or `destination`) may reference either an asset or a zone; `scripts/validate_sources.py` accepts both. If stakeholders decide every flow must target concrete assets, retarget the flow in the DFD and rerun reinjection and validation. Document any such decision with the system's sources.

## Repository boundary

Reusable tooling, packs, and templates are shared through the community toolkit (`make oss-sync` projects them from an allowlist). Keep system-specific DFDs, CRM content, evidence, and authorization artifacts under `data/systems/<slug>/` in the system's private repository; they are never part of the projection.
