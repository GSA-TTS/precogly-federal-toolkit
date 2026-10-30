# Precogly Federal Toolkit

Reusable Precogly/CycloneDX scaffolding, packs, scripts, and guides for federal
system security plans. Extracted from the TTSE Petrified Forest SSPP repository.

## Navigation

| Start here                                                                       | For                                                           |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [docs/threat-model-authoring-guide.md](docs/threat-model-authoring-guide.md)     | Authoring, exporting, and using pack libraries                |
| [docs/pipeline-diagrams.md](docs/pipeline-diagrams.md)                           | Vault-projection flow diagrams                                |
| [docs/redaction-guide.md](docs/redaction-guide.md)                               | What the redaction gate blocks, and which placeholders to use |
| [docs/SYNTHETIC_RECONCILIATION_PROOF.md](docs/SYNTHETIC_RECONCILIATION_PROOF.md) | The synthetic end-to-end publication/reconciliation proof     |
| [templates/generic-crm-system/](templates/generic-crm-system/)                   | Starter CRM pack template                                     |
| [templates/private-system-repository/](templates/private-system-repository/)     | Layout for a repository that holds real system content        |
| [docs/skills/](docs/skills/)                                                     | Agent skill playbooks (authoring, API, countermeasure audit)  |
| [SUBMODULE.md](SUBMODULE.md)                                                     | Converting this directory into a pinned submodule             |

## The toolkit boundary, as a grammar

This matters more than it looks: everything here is a **library** tool. It
requires a private system repository to supply control data, a catalog, and
authorized system records. The grammar makes explicit which inputs are
system-owned, and therefore deliberately absent from this toolkit.

```mermaid
railroad-abnf-beta
title "Toolkit pipeline - system-owned inputs are required"

run = system-inputs toolkit-stage gate artifact ;

; Supplied by the private system repository, never by this toolkit.
system-inputs = control-data catalog [ sidecars ] ;
control-data = "data/systems/<slug>/crm/*.yaml" ;
catalog = "OSCAL catalog or component-definition JSON" ;
sidecars = "authorized system records" ;

toolkit-stage = emit [ overlay ] ;
emit = "scripts/generate.py" ;
overlay = "scripts/generate_ideal.py" ;

; Not optional: redaction runs before any artifact is publishable.
gate = redaction [ drift ] ;
redaction = "scripts/validate.py" ;
drift = "scripts/drift.py" ;

artifact = cdx [ fedramp ] ;
cdx = "build/threat-model.cdx.json" ;
fedramp = "scripts/export_fedramp_cpo.py" / "scripts/export_fedramp_sdr.py" ;
```

Two consequences worth stating plainly:

- `system-inputs` has **no default**. Running `scripts/generate.py` against
  this toolkit alone produces nothing useful, because the toolkit intentionally
  contains no system-specific source data.
- `gate` is not skippable. FedRAMP export defaults are schema-oriented
  scaffolding; a submission-ready SDR needs system-owned sidecars with real,
  authorized values and must pass the strict validator. Placeholder values are
  rejected by design.

## Quick-start — new generic CRM pack

```bash
# 1. Copy the starter template
cp -r templates/generic-crm-system my-system
cd my-system

# 2. Generate and validate the generic CRM shell.
# CATALOG: NIST 800-53 r5 catalog.json; OSCAL_SOURCES: one or more
#   component-definition.json files (see templates/generic-crm-system/README.md).
make all CATALOG=/path/to/catalog.json OSCAL_SOURCES='/path/to/component-definition.json'
```

The root `scripts/generate.py` and FedRAMP exporters are library tools for a
private system repository that supplies its own `data/systems/<system-slug>/`,
catalog, and authorized system records. They are not runnable against this
public toolkit alone, which intentionally contains no system-specific source
data. Use `templates/private-system-repository/README.md` to establish that
boundary before invoking those tools.

FedRAMP export defaults are schema-oriented scaffolding. A submission-ready
SDR requires system-owned sidecars with real, authorized values and must pass
the strict FedRAMP validator; placeholder values are intentionally rejected.

## Contents

| Path                            | Purpose                                                                     |
| ------------------------------- | --------------------------------------------------------------------------- |
| `packs/`                        | Reusable Precogly technology packs (cloud.gov, FCS managed cloud service, FedRAMP overlays) |
| `templates/generic-crm-system/` | Starter system template with Makefile + data/ scaffold                      |
| `scripts/generate.py`           | CRM YAML → Precogly-native CycloneDX 2.0 emitter                            |
| `scripts/generate_ideal.py`     | Promotes gap CDX to all-verified ideal-state CDX with mock evidence         |
| `scripts/validate.py`           | Redaction gate + structural validator for generated CDX                     |
| `scripts/validate_ideal.py`     | Validates ideal-state CDX invariants                                        |
| `scripts/diff_ideal.py`         | Human-readable diff between gap and ideal CDX                               |
| `scripts/drift.py`              | CI gate: fails if generated CDX diverges from checked-in artifact           |
| `scripts/export_fedramp_cpo.py` | Generate FedRAMP CR26 CPO JSON                                              |
| `scripts/export_fedramp_sdr.py` | Generate FedRAMP CR26 SDR JSON                                              |
| `scripts/validate_fedramp.py`   | Validate CPO/SDR against CR26 schemas                                       |
| `scripts/scaffold_sidecars.py`  | Scaffold FedRAMP sidecar YAML stubs for each system                         |
| `scripts/catalog/`              | OSCAL-vault ingestion, portfolio CDX, catalog builder                       |
| `docs/`                         | Threat-model authoring guides and agent skills                              |

## Submodule usage

This directory is designed to be replaced by a git submodule at the same path
once the standalone repository exists. See `SUBMODULE.md` for the conversion
workflow.

## License

Scripts and docs: Apache 2.0 (`LICENSE.APACHE`)
Pack YAML data: CC0 1.0 (`LICENSE.CC0`)
