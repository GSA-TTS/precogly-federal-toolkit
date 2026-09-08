# Vault → Precogly Pipeline Diagrams

## 1. Source Data Model (Vault Obsidian Note)

```mermaid
classDiagram
    class ControlNote {
        +String control_id
        +String title
        +String family
        +String normalized_status
        +String normalized_origination
        +List~String~ origination
        +List~ParamRecord~ parameters
        +String source_ssp
        +String last_updated
    }
    class PartRecord {
        +String part
        +String prose
        +String inheritance_mode
        +String implementation_status
    }
    class InheritanceEntry {
        +String control_id
        +String provider
        +String mode
        +String direction
    }
    class EvidenceRef {
        +String key
        +String artifact
        +List~String~ links
    }
    ControlNote "1" --> "1..*" PartRecord : Statement Parts
    ControlNote "0..*" --> "0..1" InheritanceEntry : Inheritance/
    ControlNote "0..*" --> "0..*" EvidenceRef : Evidence section
```

**CA-2(1) example values:**

- `control_id`: `CA-02(01)`
- `normalized_status`: `not-implemented`
- `normalized_origination`: `system-specific`
- `PartRecord.part a prose`: _"GSA OCISO: None, if the assessment is performed by GSA OCISO contracted assessors…"_

---

## 2. CDX Generation Pipeline (vault_to_precogly.py)

```mermaid
flowchart TD
    subgraph vault_reader["vault_reader.py — parse_control()"]
        A[Control Markdown Note\nfrontmatter + body] -->|split_frontmatter| B[ControlRecord]
        B --> C[combined_prose\nall Part prose joined]
        B --> D[body_sections dict\nEvidence / CRM Guidance]
        B --> E[parameters list]
    end

    subgraph heuristics["heuristics.py"]
        F[normalized_status] -->|STATUS_TO_CDX| G[cdx_status\nimplemented / planned / in-progress / recommended / rejected]
        H[origination] -->|ORIGINATION_TO_CONTROL_TYPE| I[control_type]
    end

    subgraph generator["vault_to_precogly.py — build_cdx_for_system()"]
        B --> heuristics
        C --> J[control.description\n= header + params + prose + evidence]
        G --> K[control.status]
        I --> L[control.category]
        B --> M[control.properties\nnist:control-id\nvault:implementation-status\nvault:origination\nvault:providing-system]
        B --> N[appliesTo → asset_ref]

        J & K & L & M & N --> O[CDX Control Object\nbom-ref / name / status\ndescription / category\nproperties / appliesTo]

        B --> P{emit_threat?\nstatus != operational}
        P -->|yes| Q[CDX Threat Object\nname: CRM residual risk\ndesc: status + origination + prose\naffectedAssets / mitigations]
        P -->|yes| R[CDX Scenario Object\nthreat ref / riskScore.level]
    end

    O --> S[.cdx.json file\nbuild/systems/system-slug/]
    Q --> S
    R --> S
```

**CA-2(1) trace:**

- `cdx_status` = `recommended` → because `normalized_status=not-implemented`
- `emit_threat = True` → because status ≠ operational
- threat name = `"CRM: CA-2-1 residual risk - Gsa Pages Ssp 2026"`
- control description = _"Fulfills CRM responsibility for CA-2(1)… GSA OCISO: None…"_

---

## 3. CycloneDX Import → Precogly DB (cyclonedx.py adapter)

> **Fix applied (jjediny/precogly@32de8e7):** `_import_scenario()` now uses `get_or_create()` instead of `create()`. Multiple CDX scenarios referencing the same (threat, asset) pair collapse to one `ComponentInstanceThreat` row; all scenario bom-refs are accumulated in `format_metadata.cyclonedx.scenarios[]` and severity is escalated to the highest value across scenarios. Fixes vault-style CDX imports where a single NIST control has multiple attack scenarios (e.g. SR-12 with 74 scenarios).

```mermaid
flowchart TD
    subgraph cdx_file["CDX JSON File"]
        A1[blueprints: assets + zones + flows]
        A2[controls array]
        A3[threats.threats array]
        A4[threats.scenarios array]
    end

    subgraph adapter["CycloneDXAdapter.import_data()"]
        A1 -->|_import_threat_model| B1[ThreatModel]
        A1 -->|_import_orgsystem| B2[OrgSystem]
        A1 -->|_import_asset| B3[OrgsystemComponent]
        A2 -->|_import_control| B4[InstanceCountermeasure]
        A3 -->|_import_threat| B5[ThreatLibrary]
        A4 -->|_import_scenario\nget_or_create| B6[ComponentInstanceThreat]
        B6 -->|_merge_scenario_metadata| B7[Accumulate scenarios list\nEscalate severity to max]
        B5 -.->|_resolve_control_threat_links| B4
        B6 -.->|CountermeasureThreatLink| B4
    end

    subgraph ic["InstanceCountermeasure fields on import"]
        C1[countermeasure_name from control.name]
        C2[countermeasure_description from control.description]
        C3[status: recommended to gap\nimplemented stays implemented]
        C4[control_type from control.category]
        C5[is_inherited from vault:origination]
        C6[inherited_from_component_name from vault:providing-system]
        C7[format_metadata.cyclonedx.bomRef]
    end

    subgraph ic_sync["InstanceCountermeasure fields after sync_cdx_to_precogly.py"]
        D1[format_metadata.cyclonedx.ctrlId from nist:control-id]
        D2[format_metadata.cyclonedx.responsibilitySource from vault:origination]
        D3[format_metadata.cyclonedx.implementationStatement from control.description]
    end

    subgraph cit["ComponentInstanceThreat fields"]
        E1[threat_library FK to ThreatLibrary]
        E2[component FK to OrgsystemComponent]
        E3[inherent_severity = max riskScore.level across all scenarios]
        E4[format_metadata.cyclonedx.scenarios = all scenario bom-refs]
    end

    B4 --> ic
    B4 -.->|post-import sync| ic_sync
    B6 --> cit
```

**CA-2(1) result in DB (after import + sync):**

| Field                                               | Value                                             |
| --------------------------------------------------- | ------------------------------------------------- |
| `countermeasure_name`                               | `CA-2(1) implementation - Gsa Pages Ssp 2026`     |
| `status`                                            | `gap` (recommended → gap)                         |
| `countermeasure_description`                        | Full prose including statement parts + parameters |
| `is_inherited`                                      | False                                             |
| `format_metadata.cyclonedx.ctrlId`                  | `CA-2(1)`                                         |
| `format_metadata.cyclonedx.responsibilitySource`    | `system-specific`                                 |
| `format_metadata.cyclonedx.implementationStatement` | Full prose                                        |

**SR-12 result (74 scenarios → 1 CIT):**

| Field                                 | Value                                           |
| ------------------------------------- | ----------------------------------------------- |
| `inherent_severity`                   | `high` (escalated from max across 74 scenarios) |
| `format_metadata.cyclonedx.scenarios` | Array of 74 `{scenario_bom_ref: ...}` entries   |

---

## 4. Precogly Data Model (stored concepts)

```mermaid
erDiagram
    ThreatModel {
        int id PK
        string name
        string description
        json format_metadata
    }
    OrgSystem {
        int id PK
        string name
    }
    OrgsystemComponent {
        int id PK
        string name
        string category
        json format_metadata
    }
    ThreatLibrary {
        int id PK
        string name
        string description
        string slug
    }
    ComponentInstanceThreat {
        int id PK
        string threat_name
        string threat_description
        string inherent_severity
        string status
        json format_metadata
    }
    InstanceCountermeasure {
        int id PK
        string countermeasure_name
        string countermeasure_description
        string status
        string control_type
        bool is_inherited
        string inherited_from_component_name
        string evidence_url
        json format_metadata
    }
    CountermeasureThreatLink {
        int id PK
    }

    ThreatModel ||--o{ OrgSystem : contains
    OrgSystem ||--o{ OrgsystemComponent : has
    ThreatModel ||--o{ ThreatLibrary : owns
    ThreatModel ||--o{ InstanceCountermeasure : owns
    ThreatLibrary ||--o{ ComponentInstanceThreat : instantiates
    OrgsystemComponent ||--o{ ComponentInstanceThreat : hosts
    ComponentInstanceThreat ||--o{ CountermeasureThreatLink : linked_via
    InstanceCountermeasure ||--o{ CountermeasureThreatLink : linked_via
```

**Key constraint:** `ComponentInstanceThreat` has `unique_together = ["component", "threat_library"]`. One CIT per (component, threat) pair — multiple scenarios for the same pair collapse via `_merge_scenario_metadata()`.

---

## 5. Content Coverage Gap Analysis

```mermaid
flowchart LR
    subgraph vault_source["Vault Source Fields"]
        V1[control_id OK]
        V2[title OK]
        V3[normalized_status OK]
        V4[origination OK]
        V5[parameters list OK in description]
        V6[Part a/b/c prose OK in description]
        V7[inheritance provider OK via vault:providing-system]
        V8[evidence keys OK in description]
        V9[statement part labels a/b/c partial merged not structured]
        V10[parameter param_id / value partial text only]
        V11[NIST taxonomy link missing not linked]
        V12[evidence URLs missing not in evidence_url field]
    end

    subgraph precogly_db["Precogly DB Fields (after import + sync)"]
        P1[ctrlId in format_metadata OK via sync]
        P2[countermeasure_name OK]
        P3[status OK]
        P4[control_type OK]
        P5[is_inherited OK]
        P6[inherited_from_component_name OK]
        P7[countermeasure_description OK full prose]
        P8[responsibilitySource OK via sync]
        P9[implementationStatement OK via sync]
        P10[ComponentInstanceThreat OK via get_or_create fix]
        P11[evidence_url missing vault has no artifact links]
        P12[InstanceCountermeasureStandard missing not created]
    end

    V1 --> P1
    V2 --> P2
    V3 --> P3
    V4 --> P4
    V4 --> P5
    V7 --> P6
    V5 & V6 & V8 --> P7
    V4 --> P8
    V5 & V6 --> P9
    V3 --> P10
    V12 -.->|gap| P11
    V11 -.->|gap| P12
```

**Legend:** OK = mapped and populated · partial = partially mapped (text only) · missing = not populated (tracked issues #136–#138)

---

## 6. Post-Import Sync Pipeline (sync_cdx_to_precogly.py)

```mermaid
sequenceDiagram
    participant Script as sync_cdx_to_precogly.py
    participant CDX as build/systems/{slug}.cdx.json
    participant API as Precogly API
    participant DB as PostgreSQL

    Script->>API: GET /api/threat-models/
    API-->>Script: 33 ThreatModels (prefer highest ID per name)

    loop for each TM
        Script->>CDX: load controls array
        CDX-->>Script: {name_prefix: {ctrlId, responsibilitySource, implementationStatement}}

        Script->>API: GET /api/countermeasures/?threat_model={id}&page_size=200
        API-->>Script: ICs list (camelCase keys in response)

        loop for each IC
            Script->>Script: match IC by name[:60].lower() to CDX index
            alt needs patch
                Script->>API: PATCH /api/countermeasures/{id}/ {formatMetadata: {cyclonedx: {...}}}
                API->>DB: UPDATE format_metadata JSONB
            end
        end
    end

    Note over Script,DB: API convention: query params snake_case (?threat_model=)<br/>JSON body/response camelCase (ctrlId, responsibilitySource)
```

**Result after sync:**

- 100% NIST coverage (`ctrlId` on all ICs)
- 100% prose coverage (`implementationStatement` on all ICs)
- Inheritance metadata (`responsibilitySource`) on all ICs

---

## 7. Why "CA-2-1 residual risk" shows only a control ID

```mermaid
sequenceDiagram
    participant UI as Precogly UI
    participant CIT as ComponentInstanceThreat
    participant IC as InstanceCountermeasure
    participant Meta as format_metadata

    UI->>CIT: display threat card "CRM: CA-2-1 residual risk"
    CIT-->>UI: threat_name + threat_description (status/origination text)
    note over UI,CIT: UI surfaces ComponentInstanceThreat.threat_name prominently

    UI->>IC: (linked via CountermeasureThreatLink)
    IC-->>UI: countermeasure_description (full prose)
    IC-->>Meta: ctrlId = CA-2(1), responsibilitySource = system-specific
    note over UI,IC: Full prose IS stored in IC.countermeasure_description
```

The prose is present in the DB. The gap is that the Precogly **threat card view** shows `ComponentInstanceThreat.threat_name` (which contains the threat library name) rather than surfacing the linked `InstanceCountermeasure.countermeasure_description` inline. See [docs/DATA_PIPELINE.md](DATA_PIPELINE.md) for the full field mapping.
