---
id: skill-ssp-architecture-review
type: Skill
name: ssp-architecture-review
description: 'Independently review the architecture content of an SSP, or of a reusable pack/module that feeds one, against the GSA SSP reviewer checklist (sections 1-11): boundaries, diagrams, connections (port/protocol/direction/encryption/authentication), data nature and protection, environments, DevSecOps, containers, AWS, and interconnections. Use when reviewing an SSP draft, a Precogly pack under packs/, a DFD template, or any architecture narrative before ISSO or AO submission.'
status: stable
tier: 1
last_updated: '2026-11-12'
keywords: ['architecture-review', 'ssp', 'sspp', 'checklist', 'boundary', 'dfd', 'ports-protocols', 'encryption', 'pack', 'toolkit', 'third-party-review']
related_files:
  - 'skills/control-response-review/SKILL.md'
  - 'skills/platform-right-sizing/SKILL.md'
  - 'skills/sspp-diagram-generation/SKILL.md'
  - 'skills/ssp-architecture-review/pack_inventory.py'
  - 'docs/reviews/architecture/README.md'
  - 'vendor/oscal-vault/examples/vault/moderate-sspp-template-2024/Systems/moderate-sspp-template.md'
---

# SSP Architecture Review

Act as an independent reviewer who is new to the system. The checklist's own
rule applies to every row: **make no assumptions; if you were brand new to this,
could you understand it?** Do not modify the artifact under review. Report
findings only.

## Two review targets

| Target                                                                          | Mode       | Notes                                                                                                                              |
| ------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| A system SSP or SSPP source (`data/systems/<slug>/`, DOCX, vault `Systems/*.md`) | **system** | Every checklist row is assessable. A row with no content is a finding, not a pass.                                                |
| A reusable pack under `packs/<slug>/` (components, threats, countermeasures, joins, `dfd-templates/`, `offerings.yaml`) | **pack**   | A pack is a library, not a system. Rows are classed A, C or N below. A pack is judged on whether it lets a consuming SSP pass. |

## Row classes (pack mode)

- **A, assessable:** the pack contains the artifact the row asks about (a diagram, a component description, an offering). Score it PASS, PARTIAL or FAIL.
- **C, consumer obligation:** the row needs system facts a pack cannot hold (URLs, user tables, asset versions, pipelines). Score `N/A (consumer)` and, if the pack gives a hook, say so. If the pack makes a claim that would mislead the consumer, that is a finding.
- **N, not applicable:** the row cannot apply to this pack type. State why. Never leave a row blank (checklist rule 6: "if it is N/A, clearly note so").

| Checklist rows                                                       | Class       | What to inspect in a pack                                                                                   |
| -------------------------------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------- |
| 1-7 General, points of contact                                       | C           | `pack.yaml` author and maintainer present and resolvable. No individual contact details in a public pack.   |
| 8.2 Systems receiving controls                                       | **A**       | `offerings.yaml` `provides[].origination`, inheritance prose, CRM/CIS named with a version or date.        |
| 9 General description                                                | **A**       | `pack.yaml` description: what it is, who uses it, why it matters, what it does not claim.                   |
| 9.1 Locations                                                        | **A**       | Cloud, region or "unspecified" stated.                                                                      |
| 9.2 Components and boundaries                                        | **A**       | `components.yaml` grouped at a useful level. Providers shown. Each component placed in or out of a boundary. |
| 9.3 URLs                                                             | C           | `documentation_url` and `repository_url` are pack metadata only. Do not accept them as system URLs.        |
| 9.4 Users, service accounts, MFA                                     | **A** / C   | Actor nodes and machine-identity components. MFA tool and method named, not just "MFA".                     |
| 9.5 Network architecture (boundary, components, direction, port/protocol, encryption marking, integrations, authentication points) | **A** | Every DFD template. Measured by `pack_inventory.py`. |
| 10 Environments (what runs where, data per environment, identical?)  | **A** / C   | Any dev/test/prod separation modelled or stated.                                                            |
| 10.1 Asset inventory, 10.3 Software inventory (versions, GEAR)       | C           | Component fields. Flag when the schema offers no version field. GEAR is checked by the consumer.            |
| 10.2 External services                                               | **A**       | Non-persistent outside services (SaaS, APIs, registries) identified as external, not drawn inside.          |
| 10.4 Data flow                                                       | **A**       | The DFD is the data flow. Check it matches the component and join content.                                  |
| 10.5 System data nature (what, protection method, algorithms/FIPS, key location) | **A** | Component and countermeasure prose.                                                                         |
| 10.6 Ports, protocols, services                                      | **A**       | Edge `protocol` and `port`. Admin and management paths present.                                            |
| 10.7.1-10.7.10 DevSecOps                                             | **A** / C   | Which sub-sections the pack's countermeasures give a hook for. The rest are consumer obligations.           |
| 10.8 Containers                                                      | **A** / C   | As 10.7. If the platform hides it, the pack must say which duties are inherited.                            |
| 10.9 AWS management                                                  | **A** / N   | A real review only for packs that model AWS. Otherwise N, with the reason.                                  |
| 11 Interconnections (ISA/MOU)                                        | **A** / C   | Persistent or agreement-backed connections are drawn and flagged as needing an ISA or MOU.                  |

> **Numbering note.** The reviewer checklist numbers containers 10.8 and AWS
> 10.9. The vendored moderate template's DevOps instruction text says
> 10.8 DevOps, 10.9 containers and 10.10 AWS. Use the checklist numbering in
> reports. When reviewing a DOCX, confirm the numbering against that file.

## Required source check

For system mode, state the template commit you reviewed against:

```bash
git -C vendor/oscal-vault rev-parse --short HEAD
```

For pack mode, state the toolkit commit and whether the working tree is clean:

```bash
git -C vendor/precogly-federal-toolkit rev-parse --short HEAD
git -C vendor/precogly-federal-toolkit status --short
git ls-tree HEAD vendor/precogly-federal-toolkit
```

If the working tree is dirty or `HEAD` differs from the parent pin, say so in
the report header. Do not stop.

## Procedure (pack mode)

1. Run the fact collector. It is read-only and needs only PyYAML.

   ```bash
   uv run --no-project --with pyyaml python skills/ssp-architecture-review/pack_inventory.py \
     vendor/precogly-federal-toolkit/packs/<slug>
   ```

   It reports component, threat and countermeasure counts, join integrity,
   components absent from every DFD, per-DFD boundaries and zones, external
   actors and whether each sits outside the boundary, third-party components
   drawn inside a boundary, edges missing `protocol`, `encrypted`, `port` or
   `authentication`, edges marked encrypted whose protocol names no transport
   cryptography, stray edge keys, and claim and crypto term counts.

2. Read `pack.yaml`, then `components.yaml`, `offerings.yaml` (if any) and every
   DFD in full. The collector finds structure. It does not judge meaning.
3. Score each applicable row from the table above. Cite `file:line` for every
   finding. Never cite a count without the file it came from.
4. Check cross-pack consistency. Search the other packs for the same component
   id, countermeasure id, or service name, and compare claims. Contradictions
   between packs are findings on both packs.
5. Write the report. Put findings first, then the row ledger, then the consumer
   obligations.

## Procedure (system mode)

Score every row. Open the DOCX or vault `Systems/*.md` section, the
`architecture.yaml` and `base-dfd.cdx.json` for diagrams, and cross-check:

- 9.4 users against 10.6 admin ports and 9.5 authentication points.
- 9.5 diagram connections against the 10.6 table, in both directions.
- 10.1 assets and 10.3 software against 9.2 components.
- 10.2 external services against 9.5 integrations and 11 interconnections.
- 10.5 protection claims against the evidence in `evidence.yaml`.

Use `skills/control-response-review` for per-control narrative review. This
skill does not score control responses.

## Findings

| ID | Finding                                                                                                                  | Rows         | Severity |
| -- | ------------------------------------------------------------------------------------------------------------------------ | ------------ | -------- |
| B1 | Third-party or external service drawn inside the boundary, or boundary membership unclear.                              | 9.5, 10.2    | Medium   |
| B2 | Component or authentication point missing from the diagram, or a node with no connections.                              | 9.2, 9.5     | Medium   |
| F1 | Connection has no destination port.                                                                                      | 9.5, 10.6    | Medium   |
| F2 | Connection has no structured authentication, so the authentication point appears only in label text.                    | 9.5          | Medium   |
| F3 | Connection marked encrypted but the mechanism, protocol or version is not traceable.                                    | 9.5, 10.5    | Medium   |
| F4 | Direction or initiator not stated (push, pull, bi-directional).                                                          | 9.5          | Low      |
| F5 | Diagram label or attribute defect (for example a YAML parse that truncates a label).                                    | 9.5          | Medium   |
| A1 | MFA or authentication tool and method not named (for example "MFA" with no product, factor or protocol).                | 9.4, 9.5     | Medium   |
| D1 | Nature of the data stored or processed is not stated, or provider handling of plaintext is not stated.                  | 10.5         | Medium   |
| D2 | Algorithms, FIPS status, or key storage location not stated.                                                             | 10.5         | Medium   |
| I1 | Inheritance or provided-control claim unsupported, contradicted, or not tied to a named and versioned CIS/CRM.          | 8.2          | High     |
| I2 | Authorization level or approval status asserted without a source and date.                                              | 8.2, 9       | Medium   |
| X1 | Cross-pack contradiction, id collision, orphaned join, undeclared dependency, or description that does not match content. | all          | Medium   |
| E1 | No environment separation modelled or stated.                                                                            | 10           | Medium   |
| V1 | No version or inventory field available for components, so 10.1 and 10.3 cannot be populated.                           | 10.1, 10.3   | Medium   |
| C1 | Consumer obligation not stated where the pack gives the consumer a reason to assume coverage.                           | any          | Low      |
| N1 | Not-applicable row not stated as such.                                                                                   | any          | Low      |
| M1 | Metadata placeholder or non-specific reference (documentation or repository URL).                                       | 1-7, 9.3     | Low      |
| S1 | Source is dated or stale and the pack does not say how current it is.                                                   | 9            | Medium   |

### Systemic findings

When the same gap appears in every pack because the shared DFD template shape
or schema causes it (for example no edge carries `port`), report it **once** in
`docs/reviews/architecture/README.md` with a `T` ID (T1, T2, ...) and cite it
from each pack ledger. Do not repeat it as a pack-specific Medium, and do not
let it set a pack's verdict. A pack still earns its own finding if it is
materially worse than the baseline.

**Severities in the table are defaults.** Raise or lower one only with a stated one-line reason in the report. B2 does not apply to components of a catalog-style pack (for example a cloud-provider approval overlay) that no single DFD could show. Judge B2 by whether the DFD's own story needs the component. A High finding is a
statement that would cause a consuming SSP to assert something false (a
contradicted inheritance or location claim, or an approval that another pack
denies). High findings block promotion out of Draft. Medium findings need an
owner before AO submission. A pack gets **FAIL** with any High, **CONDITIONAL**
with Medium only, **PASS** otherwise.

## Report format

```markdown
| row  | class | verdict | findings | evidence (file:line)                       | note                    |
| ---- | ----- | ------- | -------- | ------------------------------------------ | ----------------------- |
| 8.2  | A     | FAIL    | I1       | components.yaml:11, data/tiers/vpcaas.yaml | contradicts tier model  |
| 9.3  | C     | N/A     |          |                                            | consumer lists all URLs |
```

Verdicts: `PASS`, `PARTIAL`, `FAIL`, `N/A`, `N/A (consumer)`. `BLOCKED` when the
artifact cannot be read, never a silent pass.

## Review boundaries

- Treat all narrative as assertions needing evidence. A mechanism named in prose is not evidenced until it is traced to a diagram, config or evidence file.
- Do not assume a boundary. If a node is inside a `systemScope`, it is inside.
- Do not reproduce emails, hostnames, account or principal IDs, or non-GitHub URLs in a report. Use the placeholders in `docs/redaction-guide.md`.
- Do not claim to have verified an external fact (an authorization date, a GEAR listing, a service approval). Say it is unverified and name the register the consumer must check.
- Include in every report: the commit reviewed, files read, the collector command, and findings by severity.
- Reports are read-only deliverables. Fixes happen on a separate branch after the owner triages the findings.

## Consumer obligations (shared checklist for pack reports)

A pack cannot satisfy these. A consuming SSP must supply them, so each pack
report links here instead of repeating them.

| Rows       | The consuming SSP must provide                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------------------ |
| 1-7        | Complete general sections with correct points of contact.                                                          |
| 8.2        | The named, versioned CIS/CRM from each providing system, attached or referenced.                                  |
| 9, 9.1     | A plain-language description of the real system, who uses it, and every physical or cloud location.               |
| 9.3        | Every URL, internal and external.                                                                                  |
| 9.4        | Every user type, service account and MFA tool and method, plus the login narrative from workstation to system.    |
| 10         | Each environment, what data it holds, and whether environments are identical.                                      |
| 10.1, 10.3 | Complete asset and software tables with versions. GEAR approval for GSA systems.                                  |
| 10.5       | Exact algorithms, FIPS status and key storage location for each data store and transport.                         |
| 10.6       | A complete ports table that matches the diagram, including admin access.                                          |
| 10.7-10.9  | The sub-sections that apply, or an explicit "not applicable" for each that does not.                              |
| 11         | An ISA or MOU row for each agreement-backed connection.                                                           |
