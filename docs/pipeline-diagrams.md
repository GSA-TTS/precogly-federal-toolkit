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
- `PartRecord.part a prose`: *"GSA OCISO: None, if the assessment is performed by GSA OCISO contracted assessors…"*

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
- control description = *"Fulfills CRM responsibility for CA-2(1)… GSA OCISO: None…"*

---

## 3. CycloneDX Import → Precogly DB (cyclonedx.py adapter)

```mermaid
flowchart TD
    subgraph cdx_file["CDX JSON File"]
        A1[blueprints → ThreatModel + OrgSystem]
        A2[controls array]
        A3[threats.threats array]
        A4[threats.scenarios array]
    end

    subgraph adapter["CycloneDXAdapter.import_data()"]
        A1 -->|_import_threat_model| B1[ThreatModel\nname / description]
        A1 -->|_import_orgsystem| B2[OrgSystem\ncomponent boundary]
        A1 -->|_import_asset| B3[OrgsystemComponent\nasset-{slug}]

        A2 -->|_import_control| B4[InstanceCountermeasure]
        A3 -->|_import_threat| B5[ThreatLibrary\nqualified_slug unique]
        A4 -->|_import_scenario| B6[InstanceScenario\nrisk score]

        B5 -.->|_resolve_control_threat_links\nmitigations field| B4
    end

    subgraph ic["InstanceCountermeasure fields populated"]
        C1[countermeasure_name ← control.name]
        C2[countermeasure_description ← control.description]
        C3[status ← CDX_STATUS_TO_CONTROL\nrecommended→gap / implemented→implemented\nplanned→planned / in-progress→in_progress]
        C4[control_type ← control.category]
        C5[is_inherited ← vault:origination in inherited/shared]
        C6[inherited_from_component_name ← vault:providing-system]
        C7[format_metadata.cyclonedx.nist_control_id ← nist:control-id OR crm:control-id]
        C8[format_metadata.cyclonedx.bom_ref]
    end

    B4 --> ic

    subgraph NOT_POPULATED["⚠ Not currently populated"]
        D1[evidence_url]
        D2[InstanceCountermeasureStandard\nNIST taxonomy link]
        D3[appliesTo → OrgsystemComponent link\ndeferred but never resolved]
        D4[statement parts a/b/c as separate objects]
        D5[parameter values as structured fields]
    end
```

**CA-2(1) result in DB:**
| Field | Value |
|---|---|
| `countermeasure_name` | `CA-2(1) implementation - Gsa Pages Ssp 2026` |
| `status` | `gap` (recommended → gap) |
| `countermeasure_description` | 415 chars of prose including statement part a |
| `is_inherited` | False |
| `format_metadata.cyclonedx.nist_control_id` | `CA-2(1)` |
| `format_metadata.cyclonedx.bom_ref` | `control-ca-2-1-…` |

The **threat** object (`CRM: CA-2-1 residual risk`) is a `ThreatLibrary` entry with its own description. The Precogly UI currently surfaces the threat name prominently but the countermeasure (with the full prose) is a separate linked record.

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
        string component_type
    }
    ThreatLibrary {
        int id PK
        string name
        string description
        string qualified_slug
        json properties
    }
    InstanceScenario {
        int id PK
        string risk_level
    }
    InstanceCountermeasure {
        int id PK
        string countermeasure_name
        string countermeasure_description
        string status
        string control_type
        bool is_inherited
        string inherited_from_component_name
        string inherited_from_zone_name
        string evidence_url
        json format_metadata
    }
    InstanceCountermeasureStandard {
        int id PK
        string control_id
    }

    ThreatModel ||--o{ OrgSystem : contains
    OrgSystem ||--o{ OrgsystemComponent : has
    ThreatModel ||--o{ ThreatLibrary : owns
    ThreatModel ||--o{ InstanceCountermeasure : owns
    ThreatLibrary ||--o{ InstanceScenario : triggers
    InstanceCountermeasure }o--o{ ThreatLibrary : mitigates
    InstanceCountermeasure ||--o{ InstanceCountermeasureStandard : maps_to
```

---

## 5. Content Coverage Gap Analysis

```mermaid
flowchart LR
    subgraph vault_source["Vault Source Fields"]
        V1[control_id ✅]
        V2[title ✅]
        V3[normalized_status ✅]
        V4[origination ✅]
        V5[parameters list ✅ in description]
        V6[Part a/b/c prose ✅ in description]
        V7[inheritance provider ✅ via vault:providing-system]
        V8[evidence keys ✅ in description]
        V9[statement part labels a/b/c ⚠ merged not structured]
        V10[parameter param_id / value ⚠ text only]
        V11[NIST taxonomy link ❌ not linked]
        V12[evidence URLs ❌ not in evidence_url field]
    end

    subgraph precogly_db["Precogly DB Fields"]
        P1[nist_control_id in format_metadata ✅]
        P2[countermeasure_name ✅]
        P3[status ✅]
        P4[control_type ✅]
        P5[is_inherited ✅]
        P6[inherited_from_component_name ✅]
        P7[countermeasure_description ✅ full prose]
        P8[evidence_url ❌ not populated]
        P9[InstanceCountermeasureStandard ❌ not created]
        P10[appliesTo OrgsystemComponent ❌ deferred never resolved]
    end

    V1 --> P1
    V2 --> P2
    V3 --> P3
    V4 --> P4
    V4 --> P5
    V7 --> P6
    V5 & V6 & V8 --> P7
    V12 -.->|gap| P8
    V11 -.->|gap| P9
    V9 -.->|gap| P10

    style V9 fill:#ffe4b5
    style V10 fill:#ffe4b5
    style V11 fill:#ffcccc
    style V12 fill:#ffcccc
    style P8 fill:#ffcccc
    style P9 fill:#ffcccc
    style P10 fill:#ffcccc
```

**Legend:** ✅ mapped · ⚠ partially (text only) · ❌ not populated

---

## 6. Why "CA-2-1 residual risk" shows only a control ID

```mermaid
sequenceDiagram
    participant UI as Precogly UI
    participant T as ThreatLibrary
    participant CM as InstanceCountermeasure
    participant Meta as format_metadata

    UI->>T: display threat card "CRM: CA-2-1 residual risk"
    T-->>UI: name + description (status/origination text only)
    note over UI,T: UI surfaces ThreatLibrary.name prominently
    note over UI,CM: Countermeasure is a linked record, not shown inline

    UI->>CM: (linked via mitigations) CA-2(1) implementation - Gsa Pages Ssp 2026
    CM-->>UI: countermeasure_description (415 chars of statement prose)
    CM-->>Meta: nist_control_id = CA-2(1)
    note over UI,CM: Full prose IS stored — it lives in the countermeasure,\nnot in the threat card the UI shows first
```

The prose is present in the DB. The gap is that the Precogly **threat card view** shows `ThreatLibrary.description` (which only contains status/origination metadata) rather than surfacing the linked `InstanceCountermeasure.countermeasure_description` inline.
