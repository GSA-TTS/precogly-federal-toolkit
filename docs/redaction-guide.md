---
title: 'CRM Threat-Model — Redaction Guide'
description: 'Policy and mechanism for redacting recon-useful identifiers (URIs/URLs, endpoint hostnames, resource IDs, and POC identifiers) from the tracked threat-model artifacts to mitigate reconnaissance, endpoint DoS/DDoS, and spearphishing'
status: draft
tier: 2
last_updated: '2026-11-09'
nist_controls: ['AC-3', 'AU-3', 'SC-7', 'SI-12', 'PT-3', 'RA-5', 'SR-3', 'PL-2']
frameworks: ['NIST SP 800-53 Rev 5.2', 'OWASP Top 10 LLM 2025']
audience: 'security'
keywords: ['redaction', 'reconnaissance', 'ddos', 'spearphishing', 'pii', 'endpoint', 'uri', 'poc', 'opsec', 'cui']
related_files:
  - 'threat-model/scripts/convert_crm_to_yaml.py'
  - 'threat-model/scripts/validate.py'
  - 'threat-model/data/model/evidence.yaml'
  - '../scripts/validate_cui_contracts.py'
  - '../schemas/cui-provenance.schema.json'
  - 'docs/adrs/ADR-SSPP-020-cui-classification-sidecar.md'
  - 'cui-guidance-summary.md'
  - '.betterleaks.toml'
---

<!-- AI-GENERATED DRAFT — requires ISSO / ISSM review. -->

# CRM Threat-Model — Redaction Guide

## Why redact

A threat model is itself a **reconnaissance target**. If concrete endpoints and
named people are committed to a repository, an attacker who reads the artifact
gains a ready-made target list. We redact three classes of value to reduce that
attack surface:

| Class                                                                                                  | Attacker benefit if leaked                                                           | Mitigation intent                                        |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| **URIs / URLs / endpoint hostnames** (e.g. `*.cloud.data-platform.com`, internal DocOps/Google-Doc links) | Map reachable endpoints; target them for recon and **DoS/DDoS**; harvest linked docs | Remove the concrete endpoint; keep only a labelled token |
| **Resource / account identifiers** (service-principal IDs, share recipients, metastore/account IDs)    | Pivot, impersonate, or scope attacks to real cloud resources                         | Replace with a role-descriptive token                    |
| **POC identifiers** (individual emails / names)                                                        | **Spearphish** the specific individuals who hold credentials to the systems          | Replace with `<POC_EMAIL>` / role reference              |

> **Source of record.** The real values remain only in the source CRM
> spreadsheet / Google Sheet (access-controlled). This repo tracks the
> _structure_ of the model, not the live target data.

## CUI classification (policy layer, tracked separately from tokenization)

The tokenization mechanism below (URL/email/IP/resource-ID redaction) is an
OPSEC/recon-hygiene control. It is **not** a CUI marking or handling
determination, and until now this guide did not distinguish the two.

A live check of the NARA CUI Registry (2026-09-18, see issue #230 and
[ADR-SSPP-020](adrs/ADR-SSPP-020-cui-classification-sidecar.md)) found that
**Information Systems Vulnerability Information (ISVI)** — banner marking
`CUI` / `CUI//ISVI`, authority 44 U.S.C. §3554 (per OMB M-24-04) and
§3555(f) — is a generally-applicable FISMA category, **not** limited to
DHS, whose scope (information whose disclosure could adversely affect an
information system: infrastructure inventories, interconnections,
enterprise architecture models) plausibly covers SSPP infrastructure and
vulnerability content of the kind this pipeline extracts.

This means:

- **Tokenizing a value in a generated artifact does not resolve a CUI
  determination for the source `.docx`.** The source document may still
  require a CUI marking and handling controls even where every downstream
  derivative is fully redacted.
- Every system with `.docx`-derived content (parsed controls,
  countermeasures, DFD/architecture model) should have a
  `data/systems/<slug>/cui.yaml` classification sidecar
  (schema: [schemas/cui-provenance.schema.json](../schemas/cui-provenance.schema.json)),
  recording the candidate `cui_category`, citing `authority`, and pointing
  to the system owner's determination through `approved_by_role` and
  `approval_ref` (a role-based reference, not a personal name) — not just a
  redaction pass. Classification and transfer authorization are system-owner
  decisions; this repository must not infer a final classification from
  content alone.
  In the parent SSPP repository, run `make cui-contracts` to check sidecar
  schema compliance and `make cui-coverage` to list systems that have
  `.docx`-derived content but no sidecar yet. In a private system repository
  that vendors the toolkit, run
  `uv run --with jsonschema --with pyyaml python vendor/precogly-federal-toolkit/scripts/validate_cui_contracts.py --systems-root data/systems --require-all`
  (add `--coverage` to list systems with no sidecar yet).
- This redaction gate remains the mitigation for the classes of value it
  already covers (URLs, POC emails, resource IDs). It is not, by itself, a
  substitute for the CUI classification/approval sidecar, and a
  `cui_category` of `ISVI` on a system does **not** automatically mean this
  gate's existing token list is sufficient handling — see the CUI redaction
  policy work tracked in issue #231, which reviews `.betterleaks.toml`
  against actual NARA CUI guidance rather than only recon-hygiene patterns.

## What gets redacted

The source CSVs under `data/raw/` are **manually redacted before commit** (they
are the tracked provenance copy). The converter (`redact()` in
`scripts/convert_crm_to_yaml.py`) also strips the same classes as a
belt-and-suspenders pass so the generated YAML is clean even if a raw value
slips through. Patterns run specific-first, generic catch-all last:

| Pattern                                       | Token                         |
| --------------------------------------------- | ----------------------------- |
| `https://docs.google.com/...`                 | `<INTERNAL_GOOGLE_DOC>`       |
| `https://docops.myfcs.itplaybook.gsa.gov/...` | `<INTERNAL_DOCOPS_URL>`       |
| `https://<sub>.cloud.data-platform.com/...`      | `<DATA-PLATFORM_WORKSPACE_URL>`  |
| bare `<sub>.cloud.data-platform.com` (no scheme) | `<DATA-PLATFORM_WORKSPACE_HOST>` |
| any email address                             | `<POC_EMAIL>`                 |
| any other `http(s)://...` URI                 | `<REDACTED_URL>`              |

Authored (non-CSV-derived) files are redacted by hand and use descriptive
tokens so the prose still reads clearly:

| Real value                                 | Token                   | Files                                    |
| ------------------------------------------ | ----------------------- | ---------------------------------------- |
| deployer / GraphQL service-principal UUIDs | `<DEPLOYER_SP_ID>`      | `evidence.yaml`, `recommendations.md`    |
| Delta Share name `example-system_uat_share`          | `<UAT_SHARE_NAME>`      | `evidence.yaml`                          |
| Delta Share recipient `gsaext_example-system_uat`    | `<UAT_SHARE_RECIPIENT>` | `evidence.yaml`, `recommendations.md`    |
| data platform SQL Warehouse identifier        | `<SQL_WAREHOUSE_ID>`    | `analyses/58-example-system-software-inventory.md` |

### Vault-projected systems (`build/systems/**`)

The vault converter (`scripts/catalog/vault_to_precogly.py`) adds three
additional passes on top of the Example System policy above:

| Class                                            | Token              | Notes                                       |
| ------------------------------------------------ | ------------------ | ------------------------------------------- |
| Any `https?://…`                                 | `<REDACTED_URL>`   | Generic catch-all (matches raw vault prose) |
| Emails                                           | `<REDACTED_EMAIL>` | Generic catch-all                           |
| IPv4 addresses (octet-bounded, optional `/mask`) | `<REDACTED_IP>`    | See exemption below                         |

**IPv4 exemption.** NIST publications contain section numbers like
`Section 5.1.1.1` that match the same shape as an IP address. The converter
and validator use a negative-context match — an IPv4-looking token immediately
preceded by `Section`, `Sections`, `§`, or `Paragraph` (case-insensitive,
followed by whitespace) is preserved as text. See `_SECTION_CTX_RE` in
[scripts/catalog/vault_to_precogly.py](../scripts/catalog/vault_to_precogly.py)
and the shared helper `find_ipv4_leak` in
[scripts/catalog/validators_common.py](../scripts/catalog/validators_common.py).

## How it is enforced

1. **At conversion** — `convert_crm_to_yaml.py` runs `redact()` on all CRM
   values, so re-running `make crm` re-strips automatically. The function is
   idempotent (running it on already-tokenized text is a no-op).
2. **Before generation** — `make scrub-check SYSTEM=<slug>` runs before
   `validate-sources` and fails if `model/base-dfd.cdx.json` still has
   editor-injected `metadata.authors` or forbidden values in configured DFD text
   fields. Run `make scrub-dfd SYSTEM=<slug>` to remove authors and redact those
   fields in place.
3. **At validation** — `scripts/validate.py` fails closed (non-zero exit) if the
   generated `build/*.cdx.json` contains any URL/URI, `*.cloud.data-platform.com`
   host, email, internal DocOps host, CUI banner marking (`CUI//<CATEGORY>`),
   ISVI cloud resource identifier (`arn:aws:...`, `vpc-...`, `subnet-...`,
   `sg-...`, `i-...`), known service-principal ID, or the UAT share recipient.
   It also consults `data/systems/<slug>/cui.yaml`: if the sidecar is `pending`
   or classified (`cui_category != not_cui`), `redaction.yaml` must exist with a
   non-empty `forbidden_patterns` list, and any declared `cui_marking` is added
   to the forbidden list automatically. This is the regression gate (covered by
   `tests/fixtures/example-system-with-leak.yaml` and
   `tests/fixtures/example-system-with-cui-leak.yaml`).
4. **At CUI contract validation** — `scripts/validate_cui_contracts.py` (`make
   cui-check`) scans every existing text and `.docx` (`word/*.xml`) file listed
   in `cui.yaml` `downstream_artifacts` against the merged universal,
   CUI-sidecar, and per-system `redaction.yaml` patterns.

`localhost` / `127.0.0.1` (Precogly local URLs in the README) are explicitly
allowed — they are not sensitive endpoints.

## CUI provenance coupling

Any system that ingests SSP/docx-derived or otherwise classified source material
must record provenance in `data/systems/<slug>/cui.yaml`. Validate sidecars with:

```bash
# Parent SSPP repository
make cui-contracts

# Private system repository that vendors the toolkit
uv run --with jsonschema --with pyyaml python \
   vendor/precogly-federal-toolkit/scripts/validate_cui_contracts.py \
   --systems-root data/systems --require-all
```

The CUI sidecar records classification, approval, source document hashes,
downstream artifacts, and retention/decontrol expectations. It is intentionally
metadata-only: do not commit the source document itself.

If `determination_status` is `pending` or `classification.cui_category` is
anything other than `not_cui`, the system must also define a non-empty
`data/systems/<slug>/redaction.yaml` `forbidden_patterns` list, and all existing
files in `downstream_artifacts` (including `.docx` `word/*.xml` streams) are
scanned against the merged redaction gate. This makes the redaction policy
explicit before any classified source material is projected into generated
artifacts.

## Adding a new redaction

1. Add a `(regex, token)` pair to `REDACTIONS` in `convert_crm_to_yaml.py`
   (specific patterns before the generic URL catch-all).
2. If the value also appears in an authored file, replace it there by hand with
   the same token.
3. Add a matching entry to `FORBIDDEN` in `validate.py` so the gate catches
   regressions.
4. For DFD export fields, add optional `scrub.fields` and `scrub.patterns`
   entries to `data/systems/<slug>/redaction.yaml` when the default fields or
   forbidden patterns need local extensions.
5. If the system has a CUI sidecar with a category other than `not_cui`, confirm
   `redaction.yaml` has non-empty `forbidden_patterns` and run `make
   cui-contracts`.
6. Re-run `make validate` and confirm validation passes.

## Reviewer guidance

- Tokens are intentional and MUST NOT be "resolved" back to real values in the
  repo. Anyone needing the real endpoint/POC consults the source CRM.
- If you spot a concrete endpoint, resource ID, or personal name in a tracked
  artifact that is not tokenized, treat it as a finding and extend the
  redaction (steps above) before merge.

## Betterleaks baseline governance (draft)

The `.betterleaks-baseline.json` file is an exception register for findings
that are understood and intentionally retained. It is not an approval to
publish sensitive content and it must not be used to make a failing redaction
gate green without review.

Until the policy work in issue #231 is approved, apply these minimum rules:

1. Do not baseline CUI banner markings, credentials, tokens, private URLs,
   email addresses, account identifiers, service-principal identifiers, or
   sensitive diagrams. Remove or redact the content instead.
2. A baseline entry must correspond to a deterministic, non-sensitive fixture
   or an independently reviewed false positive. Include the rule, path, and
   reason in the pull request description or review record; do not paste the
   matched sensitive value into that record.
3. Baseline changes require security-reviewer approval and must be kept in the
   same pull request as the content or rule change that necessitates them.
4. Review baseline entries whenever the matching rule, path, or generated
   artifact changes, and remove entries that no longer reproduce.
5. A baseline entry does not waive the generated-artifact validator,
   `make scrub-check`, CUI sidecar validation, or any system-specific
   redaction gate.

This is process guidance, not a final CUI handling determination. Under the
owner decision recorded 2026-11-04, the system owner determines classification
and authorizes transfer for controlled engineering use, and no third-party gate
is required for that use. The boundary that remains is provenance plus owner
authorization plus redaction for repository handling, and a **separate release
review before any public dissemination**; redaction success is never
publication authorization.

> **Control Mapping:** SC-7 (Boundary Protection), AU-3 (Content of Audit
> Records — no sensitive data in records), SI-12 (Information Management),
> PT-3 (PII Processing), AC-3 (Access Enforcement), SR-3 (Supply Chain).
