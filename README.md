# Precogly Federal Toolkit

Reusable Precogly/CycloneDX scaffolding, packs, scripts, and guides for federal
system security plans. Extracted from the TTSE Petrified Forest SSPP repository.

## Quick-start — new system threat model

```bash
# 1. Copy the starter template
cp -r templates/generic-crm-system my-system
cd my-system

# 2. Fill in your control data
#    Edit: data/crm/index.yaml, data/crm/platform.yaml, data/countermeasures/countermeasures.yaml
#    Edit: data/model/architecture.yaml, data/model/evidence.yaml

# 3. Generate the CycloneDX threat model
uv run python scripts/generate.py --out build/threat-model.cdx.json

# 4. Validate (redaction gate + structure)
uv run python scripts/validate.py build/threat-model.cdx.json

# 5. Import into local Precogly
uv run python scripts/bulk_import_to_precogly.py
```

## Contents

| Path | Purpose |
|---|---|
| `packs/` | Reusable Precogly technology packs (cloud.gov, FCS managed cloud service, FedRAMP overlays) |
| `templates/generic-crm-system/` | Starter system template with Makefile + data/ scaffold |
| `scripts/generate.py` | CRM YAML → Precogly-native CycloneDX 2.0 emitter |
| `scripts/generate_ideal.py` | Promotes gap CDX to all-verified ideal-state CDX with mock evidence |
| `scripts/validate.py` | Redaction gate + structural validator for generated CDX |
| `scripts/validate_ideal.py` | Validates ideal-state CDX invariants |
| `scripts/diff_ideal.py` | Human-readable diff between gap and ideal CDX |
| `scripts/drift.py` | CI gate: fails if generated CDX diverges from checked-in artifact |
| `scripts/export_fedramp_cpo.py` | Generate FedRAMP CR26 CPO JSON |
| `scripts/export_fedramp_sdr.py` | Generate FedRAMP CR26 SDR JSON |
| `scripts/validate_fedramp.py` | Validate CPO/SDR against CR26 schemas |
| `scripts/scaffold_sidecars.py` | Scaffold FedRAMP sidecar YAML stubs for each system |
| `scripts/catalog/` | OSCAL-vault ingestion, portfolio CDX, catalog builder |
| `docs/` | Threat-model authoring guides and agent skills |

## Submodule usage

This directory is designed to be replaced by a git submodule at the same path
once the standalone repository exists. See `SUBMODULE.md` for the conversion
workflow.

## License

Scripts and docs: Apache 2.0 (`LICENSE.APACHE`)
Pack YAML data: CC0 1.0 (`LICENSE.CC0`)
