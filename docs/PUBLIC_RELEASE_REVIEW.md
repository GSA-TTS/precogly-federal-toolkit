# Public release review

This checklist is required before changing this repository's visibility or
publishing a public release. Passing automated checks does **not** grant
authorization to publish.

## Required owner decisions

- [ ] A designated content owner has approved the reusable platform
      descriptions, component mappings, threats, and countermeasures in `packs/`.
- [ ] The reviewer confirmed that no pack claim is copied from a nonpublic SSP,
      CRM, ATO package, internal playbook, or system-specific evidence artifact.
- [ ] Draft-pack maturity labels and non-authoritative guidance wording remain
      accurate for the intended audience.
- [ ] A steward has approved licensing, repository governance, and the intended
      public support model.

## Required technical evidence

- [ ] CI redaction/private-marker gate passes.
- [ ] Template cold-start check passes.
- [ ] Gitleaks or an equivalent secret scan passes for the proposed release
      commit and Git history.
- [ ] The release review confirms there are no tracked source documents,
      generated system artifacts, internal URLs, credentials, account identifiers,
      or personal information.

## Release receipt

Record the approving role, decision reference, release commit/tag, and date in
the release PR or release notes. Do not record personal email addresses,
credentials, or sensitive source content in this file.
