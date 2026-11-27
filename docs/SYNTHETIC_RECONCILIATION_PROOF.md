---
title: 'Synthetic Reconciliation Proof'
description: 'Defines the local-only synthetic proof for Data Contract-gated publication and reconciliation.'
status: 'active'
tier: 2
last_updated: '2026-10-07'
related_files:
  - 'data/systems/example-system/cui.yaml'
  - 'data/systems/example-system/publication.yaml'
  - 'data/systems/example-system/reconciliation-proposal.yaml'
  - 'data/systems/example-system/reconciliation-evidence/example-system-internal-publication.yaml'
  - 'scripts/validate_reconciliation_chain.py'
  - 'vendor/oscal-vault/README.md'
---

# Synthetic Reconciliation Proof

This proof uses `example-system` only. It contains no live system content,
source DOCX, CUI, credentials, repository URLs, or identities.

## Scope

`oscal-vault` owns the DOCX-to-vault-to-canonical conversion. A private system
repository supplies its authorized DOCX locally, generates vault and canonical
artifacts with that pinned toolkit, and records their SHA-256 digests. This
repository proves the gate that begins after those artifacts exist; it does not
copy the source DOCX or reimplement the converter.

## Proof Chain

1. `cui.yaml` records source classification, source digest, and ingestion approval.
2. `publication.yaml` binds source/canonical digests, passed redaction, internal
   publication scope, owner/reviewer concurrence, and revalidation date.
3. `reconciliation-proposal.yaml` binds the publication manifest to a portable
   GitHub Enterprise PR or Workshop GitLab MR target kind without a URL or write
   instruction.
4. `reconciliation-evidence/*.yaml` records an explicit decision, conflict
   disposition, and break-glass back-port state against the same digests.

Run `make reconciliation-chain` to verify the complete chain. It fails closed
when any stage is invalid, when proposal and evidence digests disagree, when an
approved decision has an unresolved conflict, or when a proposal has no decision
evidence. A passing result does not open, merge, or publish a pull/merge request.

## Remaining Live Proof

The next proof must run in an authorized private system repository with synthetic
DOCX content: generate a vault through `oscal-vault`, generate canonical JSON,
create both portable proposal directions, and have humans create and review the
owning-forge PR/MR. That work remains blocked on #230, #231, and the configured
system-owner repositories.

The repository test suite also creates a temporary, non-sensitive DOCX and runs
the pinned `oscal-vault` coverage CLI. Its SHA-256 is bound into temporary copies
of the CUI, publication, proposal, and evidence records before the local chain is
validated. The DOCX and coverage report remain in the test directory and are not
committed.
