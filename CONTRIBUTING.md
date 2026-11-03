# Contributing to precogly-federal-toolkit

Contributions are welcome. This repository publishes reusable, non-system-specific
packs, schemas, templates, and validation tooling for federal threat modeling and
SSP reconciliation.

[← README](README.md) · [Submodule guide](SUBMODULE.md) · [Security policy](SECURITY.md)

## Boundary & Redaction Invariants

- **Never commit system-specific or CUI artifacts:** Do not include customer SSP
  DOCX files, internal hostnames, non-localhost URLs, email addresses, service
  principal UUIDs, or production evidence in any commit, issue, or pull request.
- **Vendor into private system repositories:** System-specific threat models,
  CRM YAML sources, and reconciliation evidence belong in a separate private
  system repository that consumes this toolkit as a submodule (`vendor/precogly-federal-toolkit`).
  See [`SUBMODULE.md`](SUBMODULE.md) and [`templates/private-system-repository/`](templates/private-system-repository/).

## Running Local Validation Gates

From a system repository that vendors both `vendor/oscal-vault-core` and
`vendor/precogly-federal-toolkit`:

```bash
# Validate private system repository layout
uv run python vendor/precogly-federal-toolkit/scripts/bootstrap_private_system_repository.py <system-slug> --repository .

# Run publication, CUI, and reconciliation contract gates (fails closed on missing core)
uv run python vendor/precogly-federal-toolkit/scripts/reconciliation_check.py --repository . --core vendor/oscal-vault-core

# Validate fenced Mermaid and C4 diagrams
uv run python vendor/precogly-federal-toolkit/scripts/validate_mermaid_blocks.py
```

## Licensing

As a work of the United States Government, this project is in the public domain
within the United States, and copyright and related rights in the work worldwide
are waived through the [CC0 1.0 Universal public domain](https://creativecommons.org/publicdomain/zero/1.0/)
dedication (see [`LICENSE.md`](LICENSE.md), [`LICENSE.CC0`](LICENSE.CC0), and
[`LICENSE.APACHE`](LICENSE.APACHE)). By submitting a pull request, you agree to
comply with these licensing terms.
