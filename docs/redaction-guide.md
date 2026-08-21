---
title: 'CRM Threat-Model — Redaction Guide'
description: 'Policy and mechanism for redacting recon-useful identifiers (URIs/URLs, endpoint hostnames, resource IDs, and POC identifiers) from the tracked threat-model artifacts to mitigate reconnaissance, endpoint DoS/DDoS, and spearphishing'
status: draft
tier: 2
last_updated: '2026-08-06'
nist_controls: ['AC-3', 'AU-3', 'SC-7', 'SI-12', 'PT-3', 'RA-5', 'SR-3']
frameworks: ['NIST SP 800-53 Rev 5.2', 'OWASP Top 10 LLM 2025']
audience: 'security'
keywords: ['redaction', 'reconnaissance', 'ddos', 'spearphishing', 'pii', 'endpoint', 'uri', 'poc', 'opsec']
related_files:
  - 'threat-model/scripts/convert_crm_to_yaml.py'
  - 'threat-model/scripts/validate.py'
  - 'threat-model/data/model/evidence.yaml'
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

| Real value                                 | Token                   | Files                                 |
| ------------------------------------------ | ----------------------- | ------------------------------------- |
| deployer / GraphQL service-principal UUIDs | `<DEPLOYER_SP_ID>`      | `evidence.yaml`, `recommendations.md` |
| Delta Share name `example-system_uat_share`          | `<UAT_SHARE_NAME>`      | `evidence.yaml`                       |
| Delta Share recipient `gsaext_example-system_uat`    | `<UAT_SHARE_RECIPIENT>` | `evidence.yaml`, `recommendations.md` |

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
2. **At validation** — `scripts/validate.py` fails closed (non-zero exit) if the
   generated `build/*.cdx.json` contains any URL/URI, `*.cloud.data-platform.com`
   host, email, internal DocOps host, known service-principal ID, or the UAT
   share recipient. This is the regression gate.

`localhost` / `127.0.0.1` (Precogly local URLs in the README) are explicitly
allowed — they are not sensitive endpoints.

## Adding a new redaction

1. Add a `(regex, token)` pair to `REDACTIONS` in `convert_crm_to_yaml.py`
   (specific patterns before the generic URL catch-all).
2. If the value also appears in an authored file, replace it there by hand with
   the same token.
3. Add a matching entry to `FORBIDDEN` in `validate.py` so the gate catches
   regressions.
4. Re-run `make -C docs/threat-model all` and confirm validation passes.

## Reviewer guidance

- Tokens are intentional and MUST NOT be "resolved" back to real values in the
  repo. Anyone needing the real endpoint/POC consults the source CRM.
- If you spot a concrete endpoint, resource ID, or personal name in a tracked
  artifact that is not tokenized, treat it as a finding and extend the
  redaction (steps above) before merge.

> **Control Mapping:** SC-7 (Boundary Protection), AU-3 (Content of Audit
> Records — no sensitive data in records), SI-12 (Information Management),
> PT-3 (PII Processing), AC-3 (Access Enforcement), SR-3 (Supply Chain).
