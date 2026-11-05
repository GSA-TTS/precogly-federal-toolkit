---
id: skill-precogly-api
type: Skill
name: precogly-api
description: 'Precogly Django REST API reference: all endpoints, data models, authentication, and CycloneDX 2.0 import/export adapter. Use when querying Precogly programmatically, writing scripts that call the API, importing/exporting CDX artifacts, or understanding the database model for threat models, countermeasures, components, and DFDs.'
status: stable
tier: 1
last_updated: '2026-11-05'
keywords: ['precogly', 'api', 'cyclonedx', 'threat-model', 'django', 'rest', 'data-model', 'dfd', 'countermeasure', 'import', 'export']
related_files:
  - 'scripts/bulk_import_to_precogly.py'
  - 'scripts/catalog/vault_to_precogly.py'
  - 'build/systems/'
---

# Precogly API & Data Model

Reference for the Precogly Django backend deployed locally at `http://localhost:8000`.

**API docs (live):**

- OpenAPI schema: `GET /api/schema/`
- Swagger UI: `GET /api/docs/`
- ReDoc: `GET /api/redoc/`

---

## Authentication

All endpoints require `Authorization: Bearer <token>` except public magic-link routes.

**Get a token:**

> **Local development only:** set `LOCAL_PRECOGLY_EMAIL` and `LOCAL_PRECOGLY_PASSWORD` for a disposable localhost Precogly instance. Do not reuse, commit, or deploy these values.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$LOCAL_PRECOGLY_EMAIL\",\"password\":\"$LOCAL_PRECOGLY_PASSWORD\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")
```

| Method  | Path                         | Purpose                             |
| ------- | ---------------------------- | ----------------------------------- |
| POST    | `/api/auth/login/`           | JWT login → `{"access": "<token>"}` |
| POST    | `/api/auth/logout/`          | Logout                              |
| GET/PUT | `/api/auth/user/`            | Current user profile                |
| POST    | `/api/auth/registration/`    | Register new user                   |
| POST    | `/api/auth/password/change/` | Change password                     |

**Permission classes:** `IsAuthenticated` (all endpoints), `CanWrite` (mutating ops), `IsSecurityTeam` (library management). Security team members see all org threat models; regular members see only their team's.

---

## API Endpoints

### Health & Dashboard

| Method | Path                    | Purpose                   |
| ------ | ----------------------- | ------------------------- |
| GET    | `/api/health/`          | Liveness probe            |
| GET    | `/api/dashboard/stats/` | Org-level aggregate stats |

---

### Threat Models `/api/threat-models/`

Standard CRUD ViewSet plus extra actions:

| Method | Path                                      | Purpose                                                                                           |
| ------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------- |
| GET    | `/api/threat-models/`                     | List (filter: `organization`; search: `name,description`; order: `name,created_at,updated_at`)    |
| POST   | `/api/threat-models/`                     | Create                                                                                            |
| GET    | `/api/threat-models/{id}/`                | Retrieve                                                                                          |
| PATCH  | `/api/threat-models/{id}/`                | Update                                                                                            |
| DELETE | `/api/threat-models/{id}/`                | Delete                                                                                            |
| GET    | `/api/threat-models/{id}/delete_preview/` | Cascade delete summary                                                                            |
| POST   | `/api/threat-models/{id}/add_system/`     | Link an `Orgsystem`                                                                               |
| POST   | `/api/threat-models/{id}/remove_system/`  | Unlink an `Orgsystem`                                                                             |
| GET    | `/api/threat-models/{id}/export/`         | Export as CycloneDX 2.0 JSON                                                                      |
| POST   | `/api/threat-models/import/cyclonedx/`    | Import CDX 2.0 file (multipart `file` field) → `{"threatModel": {"id": "..."}, "summary": {...}}` |

**Import summary fields:** `threatModel`, `orgsystems`, `zones`, `components`, `flows`, `controls`, `threats`, `scenarios`

**Reference images (nested):**

| Method           | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| GET/POST         | `/api/threat-models/{threat_model_pk}/reference-images/`      |
| GET/PATCH/DELETE | `/api/threat-models/{threat_model_pk}/reference-images/{id}/` |

**Out-of-scope items (nested):**

| Method   | Path                                                       |
| -------- | ---------------------------------------------------------- |
| GET/POST | `/api/threat-models/{threat_model_pk}/out-of-scope-items/` |

---

### Threats & Countermeasures

| Path prefix                                             | ViewSet                                 | Notes                                                      |
| ------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------- |
| `/api/threat-library/`                                  | `ThreatLibraryViewSet`                  | `IsSecurityTeam`; filter by `component_id`, `threat_model` |
| `/api/countermeasure-library/`                          | `CountermeasureLibraryViewSet`          | `IsSecurityTeam`                                           |
| `/api/component-library-threats/`                       | `ComponentLibraryThreatViewSet`         | component template ↔ threat template                       |
| `/api/component-threats/`                               | `ComponentInstanceThreatViewSet`        | threat instances on components                             |
| `/api/flow-threats/`                                    | `DataFlowInstanceThreatViewSet`         | threat instances on data flows                             |
| `/api/countermeasures/`                                 | `InstanceCountermeasureViewSet`         | per-TM countermeasure instances                            |
| `/api/verification-tests/`                              | `VerificationTestViewSet`               |                                                            |
| `/api/pentest-findings/`                                | `PentestFindingViewSet`                 |                                                            |
| `/api/countermeasure-standards/`                        | `InstanceCountermeasureStandardViewSet` | compliance mappings                                        |
| `/api/countermeasure-comments/`                         | `CountermeasureCommentViewSet`          |                                                            |
| `/api/taxonomies/`                                      | `ExternalTaxonomyViewSet`               | STRIDE, CAPEC, CWE, etc.                                   |
| `/api/taxonomy-entries/`                                | `TaxonomyEntryViewSet`                  |                                                            |
| `/api/threat-sources/`                                  | `ThreatSourceViewSet`                   |                                                            |
| `/api/threat-models/{threat_model_pk}/risks/`           | `RiskViewSet`                           | nested                                                     |
| `/api/threat-models/{threat_model_pk}/threat-personas/` | `ThreatPersonaViewSet`                  | nested                                                     |
| GET `/api/scoring-methods/`                             | `ScoringMethodsView`                    | available risk scoring methods                             |

---

### Systems / Components / Data Flows

| Path prefix                   | Notes                                                                      |
| ----------------------------- | -------------------------------------------------------------------------- |
| `/api/systems/`               | `Orgsystem` CRUD; filter: `criticality`, `lifecycle_state`, `organization` |
| `/api/trust-zones/`           | `TrustZone`; filter: `threat_model`                                        |
| `/api/trust-boundaries/`      | `TrustBoundary`; filter: `zone_a`, `zone_b`                                |
| `/api/component-library/`     | `ComponentLibrary` templates; `IsSecurityTeam`                             |
| `/api/components/`            | `OrgsystemComponent` instances                                             |
| `/api/data-assets/`           | `DataAsset`                                                                |
| `/api/data-flows/`            | `DataFlow`                                                                 |
| `/api/integrations/`          | `IntegrationSource`                                                        |
| `/api/component-data-assets/` | `ComponentDataAsset` join table                                            |
| `/api/data-flow-assets/`      | `DataFlowAsset` join table                                                 |

---

### Diagrams (DFD)

| Method           | Path                                     | Purpose                   |
| ---------------- | ---------------------------------------- | ------------------------- |
| GET/POST         | `/api/diagrams/`                         | List/create DFD records   |
| GET/PATCH/DELETE | `/api/diagrams/{id}/`                    | CRUD                      |
| POST             | `/api/diagrams/create_for_threat_model/` | Create DFD scoped to a TM |
| GET              | `/api/diagrams/{id}/delete_preview/`     | Cascade summary           |
| GET/POST         | `/api/dfd-templates/`                    | `DFDTemplatesLibrary`     |

`PATCH /api/diagrams/{id}/` on the primary DFD triggers `sync_dfd_nodes_to_components()` — React Flow canvas nodes are synced back to `OrgsystemComponent` records.

---

### Compliance

| Path prefix                      | Notes                           |
| -------------------------------- | ------------------------------- |
| `/api/frameworks/`               | `StandardFramework`             |
| `/api/requirements/`             | `StandardRequirement`           |
| `/api/countermeasure-standards/` | `CountermeasureLibraryStandard` |

---

### Packs

| Path prefix   | Notes                               |
| ------------- | ----------------------------------- |
| `/api/packs/` | `LibraryPack` CRUD and installation |

---

### Organizations

| Path                           | Notes                                      |
| ------------------------------ | ------------------------------------------ |
| `/api/organizations/`          | Tenant management                          |
| `/api/memberships/`            | `OrganizationMember`                       |
| `/api/business-units/`         | `BusinessUnit` (hierarchical via `parent`) |
| `/api/teams/`                  | `Team`                                     |
| `/api/magic-links/`            | Read-only share tokens                     |
| `/api/team-invitations/`       | Invite flow                                |
| `/api/shared-with-me/`         | TMs shared via magic link                  |
| GET/POST `/api/share/<token>/` | Access a magic-link shared TM              |
| POST `/api/invite/<token>/`    | Accept team invitation                     |

---

### AI

| Path                         | Notes                                                     |
| ---------------------------- | --------------------------------------------------------- |
| `/api/ai-providers/`         | `AIProviderConfig`; per-org OpenAI-compat endpoint config |
| GET `/api/ai-usage/summary/` | Token usage summary                                       |

---

## Data Model

### `ThreatModel`

Central aggregate. All other records are scoped by FK or M2M through this.

| Field                 | Type               | Notes                                       |
| --------------------- | ------------------ | ------------------------------------------- |
| `id`                  | int PK             |                                             |
| `organization`        | FK Organization    | tenant                                      |
| `owning_team`         | FK Team (nullable) |                                             |
| `created_by`          | FK User            |                                             |
| `name`                | str                |                                             |
| `description`         | text               |                                             |
| `criticality`         | enum               | low/medium/high/critical                    |
| `risk_scoring_method` | enum               | tm_library/fair/owasp_rr/mozilla_rra/custom |
| `format_metadata`     | JSON               | CDX passthrough fields stored here          |
| `workspace_data`      | JSON               | UI state                                    |
| `assumptions`         | JSON array         |                                             |
| `scope_locked`        | bool               |                                             |

---

### `Orgsystem` (System Boundary)

| Field                            | Type      |
| -------------------------------- | --------- |
| `organization`                   | FK        |
| `name`, `owner`                  | str       |
| `criticality`, `lifecycle_state` | enum      |
| `description`, `format_metadata` | text/JSON |

Linked to `ThreatModel` via `ThreatModelOrgsystem` M2M join.

---

### `OrgsystemComponent`

| Field                                             | Type                    | Notes                                                        |
| ------------------------------------------------- | ----------------------- | ------------------------------------------------------------ |
| `orgsystem`                                       | FK (nullable)           |                                                              |
| `component_library`                               | FK (nullable)           | template source                                              |
| `trust_zone`                                      | FK TrustZone (nullable) |                                                              |
| `threat_model`                                    | FK (nullable)           | analysis-only components                                     |
| `name`, `description`                             | str/text                |                                                              |
| `category`                                        | enum                    | process/datastore/external_human_actor/external_system_actor |
| `component_type`, `actor_type`, `data_store_type` | str                     |                                                              |
| `data_sensitivity_level`                          | str                     |                                                              |
| `format_metadata`                                 | JSON                    | `{"cyclonedx": {"bom_ref": "...", "asset_type": "..."}}`     |

---

### `TrustZone`

| Field                            | Type               | Notes |
| -------------------------------- | ------------------ | ----- |
| `name`                           | str                |       |
| `trust_level`                    | int 0–100          |       |
| `description`, `format_metadata` | text/JSON          |       |
| `parent`                         | FK self (nullable) |       |

---

### `DataFlow`

| Field                                      | Type                  | Notes                               |
| ------------------------------------------ | --------------------- | ----------------------------------- |
| `source_component`                         | FK OrgsystemComponent |                                     |
| `dest_component`                           | FK OrgsystemComponent |                                     |
| `label`, `edge_id`                         | str                   |                                     |
| `protocol`, `port`                         | str                   |                                     |
| `encrypted`, `authenticated`               | bool                  |                                     |
| `crosses_trust_zone`, `has_sensitive_data` | bool                  |                                     |
| `data_classification`                      | JSON                  |                                     |
| `format_metadata`                          | JSON                  | `{"cyclonedx": {"bom_ref": "..."}}` |

---

### `DFD`

| Field          | Type | Notes                                     |
| -------------- | ---- | ----------------------------------------- |
| `threat_model` | FK   |                                           |
| `name`         | str  |                                           |
| `diagram_type` | str  | context/level1/level2                     |
| `is_primary`   | bool | unique per TM                             |
| `canvas_data`  | JSON | React Flow `{nodes: [...], edges: [...]}` |

**Node types in `canvas_data.nodes`:** `systemScope`, `trustZone`, `process`, `datastore`, `humanActor`, `systemActor`

**Node data fields:**

- `systemScope`: `{label, orgsystem_id}`
- `trustZone`: `{label, zoneType, trust_zone_id}`
- `process/datastore`: `{label, technology, description, component_id, component_ref}`
- `humanActor/systemActor`: `{label, actorType/systemType, description, component_id}`

**Edge type:** `dataFlow` — `{id, source, target, data: {label, encrypted, authenticated, dataflow_id}}`

---

### `InstanceCountermeasure`

| Field                           | Type          | Notes                                                                       |
| ------------------------------- | ------------- | --------------------------------------------------------------------------- |
| `threat_model`                  | FK            |                                                                             |
| `countermeasure_library`        | FK (nullable) |                                                                             |
| `countermeasure_name`           | str           | denormalized                                                                |
| `countermeasure_description`    | text          | full prose from vault/import                                                |
| `status`                        | enum          | gap/planned/in_progress/implemented/verified/waived/platform/decommissioned |
| `control_type`                  | str           |                                                                             |
| `is_inherited`                  | bool          | True when `vault:origination` is inherited/shared                           |
| `inherited_from_component_name` | str           | providing system name                                                       |
| `inherited_from_zone_name`      | str           |                                                                             |
| `evidence_url`                  | str           |                                                                             |
| `effectiveness`                 | float 0–1     |                                                                             |
| `format_metadata`               | JSON          | `{"cyclonedx": {"bom_ref": "...", "ctrl_id": "AC-2(1)"}}`                   |

**Status → CDX mapping (import):**

| CDX `status`  | `InstanceCountermeasure.status` |
| ------------- | ------------------------------- |
| `implemented` | `implemented`                   |
| `recommended` | `gap`                           |
| `planned`     | `planned`                       |
| `in-progress` | `in_progress`                   |
| `rejected`    | `waived`                        |

---

### `ThreatLibrary`

| Field                    | Type          | Notes |
| ------------------------ | ------------- | ----- |
| `name`, `description`    | str/text      |       |
| `slug`, `qualified_slug` | str (unique)  |       |
| `source_pack`            | FK (nullable) |       |
| `customization_status`   | str           |       |
| `aliases`                | ArrayField    |       |

---

### `ComponentInstanceThreat` / `DataFlowInstanceThreat`

Threat instance on a component or flow:

| Field                                    | Type                                |
| ---------------------------------------- | ----------------------------------- |
| `component` / `data_flow`                | FK                                  |
| `threat_library`                         | FK ThreatLibrary (nullable)         |
| `inherent_severity`, `residual_severity` | str                                 |
| `status`                                 | enum: exposed/addressable/mitigated |
| `is_dismissed`, `dismissal_reason`       | bool/text                           |
| `threat_name`, `threat_description`      | str (denormalized)                  |
| `taxonomy_snapshot`                      | JSON                                |

---

### `Risk`

| Field                                              | Type        |
| -------------------------------------------------- | ----------- |
| `threat_model`                                     | FK          |
| `name`, `description`                              | str/text    |
| `inherent_score`, `residual_score`, `target_score` | float 0–100 |
| `inherent_level`, `residual_level`, `target_level` | str         |
| `scoring_metadata`, `domains`                      | JSON        |

---

## CycloneDX 2.0 Adapter

**Class:** `CycloneDxAdapter` in `apps/threat_models/adapters/cyclonedx.py`

### Import: `import_data(json_data, organization, created_by) → (ThreatModel, summary_dict)`

Called by `POST /api/threat-models/import/cyclonedx/`. Runs in a single DB transaction with 14 ordered steps:

| Step | CDX element                                               | Created model                                             |
| ---- | --------------------------------------------------------- | --------------------------------------------------------- |
| 1    | `blueprints[0].name`                                      | `ThreatModel`                                             |
| 2    | `blueprints[0]`                                           | `Orgsystem` + `ThreatModelOrgsystem`                      |
| 3    | `blueprint.zones[]`                                       | `TrustZone` (parent resolved via bom-ref)                 |
| 4    | `blueprint.boundaries[]`                                  | `TrustBoundary`                                           |
| 5    | `blueprint.assets[]`                                      | `OrgsystemComponent`                                      |
| 6    | `blueprint.dataStores[]`                                  | merged into existing component by name                    |
| 7    | `blueprint.dataSets[]`                                    | `DataAsset`                                               |
| 8    | `blueprint.flows[]`                                       | `DataFlow` (`source`/`destination` keys, not `from`/`to`) |
| 9    | `definitions.useCases[]`                                  | `UseCase`                                                 |
| 10   | `controls[]`                                              | `InstanceCountermeasure`                                  |
| 11   | `threats.threats[]`                                       | `ThreatLibrary` (get_or_create by name)                   |
| 12   | `threats.scenarios[]`                                     | `ComponentInstanceThreat` or `DataFlowInstanceThreat`     |
| 13   | `risks[]`                                                 | `Risk`                                                    |
| 14   | `blueprint.visualizations[]` where `type=="precogly-dfd"` | `DFD` with remapped `component_id`/`dataflow_id`          |

**Vault-specific CDX properties parsed during step 10:**

| Property                                  | Mapped to                           |
| ----------------------------------------- | ----------------------------------- |
| `ctrl:id`                                 | `format_metadata.cyclonedx.ctrl_id` |
| `vault:origination` ∈ {inherited, shared} | `is_inherited = True`               |
| `vault:providing-system`                  | `inherited_from_component_name`     |
| `vault:implementation-status`             | stored in metadata                  |

### Export: `export_data(threat_model) → dict`

Called by `GET /api/threat-models/{id}/export/`. Builds full CDX 2.0 document:

```
blueprints[0]:
  zones       ← TrustZone
  assets      ← OrgsystemComponent (non-datastore)
  dataStores  ← OrgsystemComponent (category==datastore)
  dataSets    ← DataAsset
  boundaries  ← TrustBoundary
  flows       ← DataFlow
  visualizations ← DFD.canvas_data (type: "precogly-dfd")
controls[]    ← InstanceCountermeasure
threats.threats[]  ← ThreatLibrary
threats.scenarios[] ← ComponentInstanceThreat / DataFlowInstanceThreat
risks[]       ← Risk
```

### CDX format quirks

- **Flow keys:** adapter reads `source`/`destination` (NOT `from`/`to`)
- **DFD visualization:** `blueprint.visualizations[].type == "precogly-dfd"` triggers `DFD` creation; `data.nodes[].data.component_id` is remapped to new component IDs post-import
- **bom-ref resolver:** all cross-references between zones, assets, flows, threats, controls resolved via a `BomRefResolver` keyed on the CDX `bom-ref` string
- **Tier-3 passthrough:** unhandled CDX fields stored/restored from `ThreatModel.format_metadata["cyclonedx"]`

---

## Common Shell Queries

```python
# Django shell: docker exec precogly-backend python manage.py shell -c "..."

# Get TM by name fragment
from apps.threat_models.models import ThreatModel

tm = ThreatModel.objects.filter(name__icontains="gsa-pages").last()

# List countermeasures with NIST ID
from apps.threats.models import InstanceCountermeasure

cms = InstanceCountermeasure.objects.filter(threat_model=tm)
for cm in cms:
    nist = cm.format_metadata.get("cyclonedx", {}).get("ctrl_id", "")
    print(nist, cm.status, cm.countermeasure_name[:60])

# Check DFDs
from apps.diagrams.models import DFD

dfds = DFD.objects.filter(threat_model=tm)
for d in dfds:
    cd = d.canvas_data or {}
    print(d.id, len(cd.get("nodes", [])), "nodes", len(cd.get("edges", [])), "edges")

# Fidelity report: coverage across all vault TMs
for tm in ThreatModel.objects.filter(id__gte=96).order_by("id"):
    cms = InstanceCountermeasure.objects.filter(threat_model=tm)
    with_id = sum(
        1 for c in cms if c.format_metadata.get("cyclonedx", {}).get("ctrl_id")
    )
    print(f"{tm.id} {tm.name}: {cms.count()} CMs, {with_id} with ctrl_id")
```

---

## Bulk Import Script

`scripts/bulk_import_to_precogly.py` — imports all `build/systems/*/` CDX artifacts.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$LOCAL_PRECOGLY_EMAIL\",\"password\":\"$LOCAL_PRECOGLY_PASSWORD\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")

PRECOGLY_TOKEN="$TOKEN" python3 scripts/bulk_import_to_precogly.py \
  --api-url http://localhost:8000
```

Systems named in `KNOWN_IMPORTS` dict (see the script; by default it names the long-lived systems already imported, e.g. `example-system`, `login-gov-2017`) are **skipped** — import those manually:

```bash
curl -s -X POST http://localhost:8000/api/threat-models/import/cyclonedx/ \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@build/systems/example-system/example-system.cdx.json"
```
