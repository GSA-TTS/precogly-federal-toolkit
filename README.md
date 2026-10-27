# Precogly Federal Toolkit

Reusable Precogly/CycloneDX scaffolding, packs, scripts, and guides for federal
system security plans. Extracted from the TTSE Petrified Forest SSPP repository.

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
