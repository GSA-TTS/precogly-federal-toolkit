---
id: threat-model-authoring-guide
type: Guide
title: 'Threat Model Authoring, Export, and Library Workflow'
status: draft
last_updated: '2026-08-13'
keywords: ['threat modeling', 'Precogly', 'CycloneDX', 'libraries', 'OSCAL vault', 'SSPP']
related_files:
  - README.md
  - Makefile
  - data/packs/
  - build/systems/
  - catalog/index.yaml
---

# Threat Model Authoring, Export, and Library Workflow

This guide explains how to develop a threat model in this repository without
losing generated CRM content, leaking sensitive data, or bypassing the reusable
GSA technology libraries.

## Mental model

The repository has three layers:

1. **Source data**: YAML and redacted source exports under `data/`.
2. **Generated artifacts**: Precogly-native CycloneDX files under `build/`.
3. **Editor workflow**: Precogly imports and exports the CycloneDX files for DFD
   authoring and library-assisted modeling.

Prefer editing source YAML for generated controls and threats. Use Precogly for
DFD layout, assets, flows, zones, and library selection.

## Choose the right starting point

| Goal                                      | Start with                               | Result                                                           |
| ----------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| Update the Example System CRM model                 | `build/example-system-crm-threat-model.cdx.json`   | Revised Example System artifact plus source YAML changes                   |
| Model a vault-projected GSA system        | `build/systems/<slug>/<slug>.cdx.json`   | Revised per-system artifact or pack proposal                     |
| Create a new model from reusable services | Installed Precogly packs                 | New Precogly model using approved components                     |
| Refresh the whole portfolio catalog       | `vendor/oscal-vault` or `../oscal-vault` | Updated `build/systems/`, `catalog/index.yaml`, and docs catalog |

## Install and use the libraries

Start Precogly and install all packs:

```bash
make precogly-up
make pack-install-all
```

The pack library includes:

- `gsa-fedramp` for GSA-operated FedRAMP platforms.
- `fcs-managed-cloud-service` for managed cloud service service tiers.
- `cloudgov-paas` for cloud.gov PaaS managed services.
- `gsa-overlay-aws`, `gsa-overlay-azure`, and `gsa-overlay-gcp` for GSA OCISO
  cloud service approval overlays.

In Precogly, use packs as building blocks instead of hand-copying controls:

1. Create or open a threat model.
2. Add components from the installed libraries for platforms, cloud services,
   identity providers, CI/CD, hosting layers, and managed databases.
3. Review imported threats and countermeasures for applicability.
4. Keep tenant-specific residual actions separate from provider-managed controls.
5. Export the model and commit the changed artifact only after validation.

## What to edit

| Change                                                     | Edit                                                            | Command                                                 |
| ---------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------- |
| CRM responsibility text or mappings from spreadsheets      | `data/crm/*.yaml`                                               | `make generate validate`                                |
| Countermeasure wording, mechanism, gap, or residual action | `data/countermeasures/countermeasures.yaml`                     | `make generate validate`                                |
| Shared evidence text reused across many controls           | `data/model/evidence.yaml`                                      | `make generate validate`                                |
| Asset mappings, flow bindings, zones, risk scores          | `data/model/architecture.yaml`                                  | `make validate-sources generate validate`               |
| Example System DFD structure and layout                              | Edit in Precogly, then compare export before replacing baseline | `make dfd-drift DFD_EXPORT=tmp/export.cdx.json`         |
| Pack component, threat, or countermeasure library content  | `data/packs/<pack>/`                                            | `make pack-install-all` and test in Precogly            |
| Vault-projected system content                             | Source OSCAL vault, not generated `build/systems/` files        | `make vault-import-all VAULT_ROOT=./vendor/oscal-vault` |

Avoid hand-editing generated `controls[]` or generated CRM threats directly in
`build/example-system-crm-threat-model.cdx.json`; those edits are overwritten by
`make generate` or `make reinject`.

## Update the Example System CRM model

1. Edit the YAML source file that owns the change.
2. Regenerate and validate:

   ```bash
   make generate validate
   make drift
   ```

3. If `make drift` fails because the artifact has stale generated content, run:

   ```bash
   make reinject
   make validate drift
   ```

4. Review the diff for both source YAML and the generated CycloneDX artifact.

## Edit the DFD in Precogly

Use this workflow for assets, flows, trust zones, and diagram layout:

1. Start Precogly with `make precogly-up`.
2. Import `build/example-system-crm-threat-model.cdx.json`.
3. Edit only DFD-owned content in the UI.
4. Export the model.
5. Run `make dfd-drift DFD_EXPORT=<exported-cdx.json>` and review
   `build/<system>-dfd-drift.yaml`; a non-zero exit means the export differs
   from the checked-in DFD and needs review before promotion.
6. Save the exported DFD baseline over `data/model/base-dfd.cdx.json`.
7. Run `make scrub-dfd SYSTEM=<slug>` to remove editor-injected authors and
   redact configured DFD text fields.
8. If asset, zone, or flow references changed, update `data/model/architecture.yaml`.
9. Run `make validate-sources reinject validate drift`.

`make validate-sources` runs `make scrub-check` first and fails before generation
when the source DFD still contains editor-injected `metadata.authors` or other
configured redaction hits, when architecture bindings reference missing assets,
zones, or flows, or when a flow declares an unknown `authMechanism`. Use
`architecture.yaml` `flows:` aliases with `source_asset` and `destination_asset`
selectors for `flow_overrides` and `flow_bindings`; raw DFD flow `bom-ref`s are
still accepted as a compatibility fallback. Shared mechanisms live in
`data/catalog/flow-auth-mechanisms.yaml`; system-specific additions can be
declared in `auth_mechanisms` inside `architecture.yaml`. Add local NIST mappings
under `auth_mechanisms.metadata.<mechanism>.nist` when a system-specific
mechanism should emit `resp:auth-mechanism-nist` in generated flows.

`make dfd-drift` rehydrates editor exports before comparison, then calls out
added, removed, or modified zones, assets, flows, boundaries, and data stores,
plus editor authors and broken flow endpoints. Use it to decide whether an export
is safe to promote into `base-dfd.cdx.json`. For a report-only pass, run
`make dfd-drift DFD_DRIFT_ADVISORY=1`. In repositories without this Makefile, run
the same check directly with:
`uv run python scripts/dfd_drift.py --system <slug> --export <exported-cdx.json>`.

For cloud.gov-hosted browser SSO, model the default GSA employee path as
`GSAuth via cloud.gov UAA`. Use `login.gov application-managed authorization`
when the application or an identity broker owns authorization and can match the
login.gov email claim to the application's username or account record.

Precogly preserves countermeasures when they are top-level `controls[]` linked
bidirectionally to threats. The generator already emits that native schema.

## Refresh the vault catalog

The CI workflow uses the pinned submodule at `vendor/oscal-vault`. To refresh
from that source:

```bash
git submodule update --init --recursive
make vault-import-all VAULT_ROOT=./vendor/oscal-vault
make example-system-backfill
make vault-validate
make catalog-all VAULT_ROOT=./vendor/oscal-vault
make precogly-seed
make vault-drift VAULT_ROOT=./vendor/oscal-vault
```

If you intentionally update the vault source, advance the submodule, regenerate
the catalog artifacts, and include both changes in the same pull request.

## Export formats

Use Precogly-native CycloneDX as the source of truth. For OWASP-compatible
downstream checks, generate the one-way projection:

```bash
make export-owasp
```

The export writes `build/owasp-threat-model.json`. Do not edit the OWASP export
as source; regenerate it from the CycloneDX model.

## Publication Diagram Pilot

The Example System publication diagrams are deterministic, offline HTML/SVG projections of
the governed DFD and composite hosting models. They complement the editable
Precogly canvas; they do not replace the canvas or the existing Archify figures
used by the SSPP.

```bash
make publication-diagram
make publication-diagram-check
```

The renderer reads `data/systems/example-system/model/base-dfd.cdx.json` and
`data/systems/example-system/model/architecture.yaml`, then writes:

- `build/diagrams/example-system-data-platform-core.html`
- `build/diagrams/example-system-data-platform-core.svg`
- `build/diagrams/example-system-data-platform-core.manifest.json`
- `build/diagrams/example-system-publication-{auth-sequence,access-lanes,authorization-boundary,data-flow,it-current-state,architecture-delta}.{html,svg,manifest.json}`
- `build/diagrams/example-system-publication-axonometric-{core,pages,managed-cloud-service}.{html,svg,manifest.json}`

The manifest and figure embed source digests. Do not hand-edit these outputs:
change the governed DFD, architecture binding, or composite hosting model, rerun
`make publication-diagram`, and review the resulting figure together with the
source change. The IT current-state and architecture-delta views compare the GSA
Pages baseline with the managed cloud service Kubernetes candidate. These views have their own
filenames and do not change the Pillow-rendered DOCX figure paths.

## Redaction and review checklist

Before committing:

- Run `make validate` for the Example System model.
- Run `make validate-sources` after any DFD export or architecture binding edit.
- Run `make vault-validate` and `make vault-drift VAULT_ROOT=./vendor/oscal-vault`
  when catalog artifacts change.
- Confirm no secrets, PII, internal hostnames, private URLs, or unredacted IPs
  appear in YAML, CycloneDX, screenshots, or docs.
- Keep generated files and their source edits together in one commit.
- Explain whether a countermeasure is implemented, recommended, verified,
  rejected, planned, or in-progress.
- Document tenant-responsible residual actions separately from inherited
  provider controls.

## Pull request checklist

- Source YAML changed when generated CRM content changed.
- Generated CycloneDX artifacts are refreshed.
- Pack changes were installed and smoke-tested in Precogly.
- Catalog changes pass the drift gate.
- README or catalog docs are updated when user-facing workflow changes.
- ISSO/ISSM review is requested before compliance use.
