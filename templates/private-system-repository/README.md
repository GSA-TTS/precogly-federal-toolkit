# Private System Repository Template

[← Repository README](../../README.md) · [Documentation index](../../docs/index.md) ·
[Open Work Tracker](../../docs/OPEN_WORK.md) (Workstream 6) ·
[Redaction guide](../../docs/redaction-guide.md) ·
[Generic CRM template](../generic-crm-system/README.md)

Use this template for a system owner repository that contains source documents,
vault notes, canonical sidecars, evidence, and publication approvals. The
repository consumes a pinned community toolkit but remains the system-content
source of record.

## Required Layout

```text
data/systems/<system-slug>/
  cui.yaml
  publication.yaml
  reconciliation-proposal.yaml
vault/
evidence/
vendor/precogly-federal-toolkit/
```

Keep source DOCX files outside Git unless an authorized policy explicitly says
otherwise. Store source and canonical digests in `publication.yaml`, not source
content. Store no forge URL, token, credential, person name, or email address in
the portable proposal manifest.

`publication.yaml` must name a canonical JSON sidecar under `vault/`. Its
`canonical_sha256` is verified against that local file before a proposal is
accepted. The DOCX source digest is recorded but the source document remains
outside Git.

## Workflow

1. Validate CUI/provenance and redact the proposed derivative.
2. Obtain role-based system-owner and reviewer concurrence in `publication.yaml`.
3. Create `reconciliation-proposal.yaml` with matching source and canonical
   digests and one portable target kind.
4. Run `python scripts/bootstrap_private_system_repository.py <system-slug>`
   before invoking the community toolkit validators locally.
   Then run `python vendor/precogly-federal-toolkit/scripts/reconciliation_check.py
   --repository .` so system content is read from this private repository while
   schemas and validators remain pinned to the community toolkit.
5. A human opens the owning-forge PR or MR. The proposal never performs a remote
   write and does not authorize merge.

## Non-Goals

- This template does not configure GitHub Enterprise or Workshop GitLab.
- This template does not create a repository, credential, or network connection.
- A passing validator result does not authorize public release or automatic merge.
