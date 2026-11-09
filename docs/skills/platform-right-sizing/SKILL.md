---
id: skill-platform-right-sizing
type: Skill
name: platform-right-sizing
description: 'Evaluates platform siting and right-sizing decisions on Pull Requests and architecture changes. Compares hosting platforms (cloud.gov PaaS, cloud.gov Workshop, FCS managed cloud service, FCS CaaS, Brokered Sandboxes) across compliance inheritance, developer velocity, operational ticket friction, cognitive load, and workload fit to ensure teams choose the smallest responsible platform boundary.'
status: stable
tier: 1
last_updated: '2026-11-05'
keywords: ['platform-siting', 'right-sizing', 'cloudgov', 'fcs', 'managed-cloud-service', 'caas', 'ato', 'crm', 'residual-controls', 'pr-review', 'cognitive-load']
related_files:
  - 'docs/analyses/README.md'
  - 'docs/analyses/00-example-systemgov-hosting-control-delta-summary.md'
  - 'docs/analyses/26-residual-controls-by-inheritance-model.md'
  - 'docs/analyses/40-k8s-operational-burden-assessment.md'
  - 'docs/presentations/cloudgov-platforming-right-sizing-marp.md'
  - 'scripts/analysis/residual_controls_by_tier.py'
  - 'data/tiers/cloud-gov-paas.yaml'
  - 'data/tiers/managed-cloud-service.yaml'
  - 'data/tiers/caas.yaml'
  - 'data/tiers/gsa-pages.yaml'
  - 'data/systems/'
---

# Platform Right-Sizing & Siting Skill

Use this skill when evaluating a Pull Request, architecture proposal, or system manifest in `TTSE-petrified-forest-sspp` that introduces, migrates, or selects a hosting platform.

The core guiding principle is:

> **Choose the smallest responsible platform boundary that meets the system's mission and compliance requirements.**

Every layer of unneeded infrastructure ownership translates directly into residual NIST controls, Jira ticket friction, CVE patching obligations, and required DevSecOps headcount.

---

## When to Use

1. **Pull Request Review:**
   - Any PR adding or modifying `data/systems/<slug>/system.yaml` or `data/systems/<slug>/model/architecture.yaml`.
   - Any PR modifying `inherits_from:` or `tier:` references.
   - Any PR introducing a new cloud hosting boundary or migrating an existing component.
2. **Interactive Architectural Siting:**
   - When an engineer or team lead asks: _"Should we deploy this on cloud.gov, cloud.gov Workshop, FCS, or a sandbox account?"_
   - When evaluating new initiatives (e.g., CRSP, SAM.gov modernization, FedRAMP dashboards).
3. **ATO Scoping & Compliance Reviews:**
   - Quantifying residual controls before committing to an ATO pathway.
   - Justifying why a dedicated VPC/cluster is or is not required for an ISSO, ISSM, or Authorizing Official (AO).

---

## The 5-Pillar Decision Framework

When evaluating a workload, score it across five core dimensions:

```
+------------------------------------------------------------------------------------+
|                         THE 5-PILLAR DECISION FRAMEWORK                            |
+--------------------------+---------------------------------------------------------+
| 1. Compliance Lift       | FedRAMP JAB / boundary inheritance vs. tenant-owned    |
|    (Weight: 25%)         | residual NIST 800-53 controls (0 vs. 134 vs. 192).      |
+--------------------------+---------------------------------------------------------+
| 2. Developer Velocity    | Self-service CLI/API (`cf push`) vs. GSA IT ticket-     |
|    & Agility (25%)       | driven change requests (minutes vs. weeks).             |
+--------------------------+---------------------------------------------------------+
| 3. Cognitive Load & SRE  | Container OS/CVE patching, IRSA, ingress routing,       |
|    Burden (20%)          | and required full-time DevSecOps headcount (0.2 vs 2.0).|
+--------------------------+---------------------------------------------------------+
| 4. Workload Fit (15%)    | Architectural alignment (12-Factor web vs. specialized  |
|                          | AWS primitives vs. data analytics / GPU compute).       |
+--------------------------+---------------------------------------------------------+
| 5. Cost & Portability    | Shared platform cost envelope vs. dedicated tenancy     |
|    (15%)                 | and proprietary cloud lock-in.                          |
+--------------------------+---------------------------------------------------------+
```

---

## Step-by-Step PR Review Protocol

When an agent or reviewer executes a platform right-sizing analysis on a PR, follow this 5-step sequence:

### Step 1: Detect Workload Archetype and Data Sensitivity

Inspect the PR files (e.g. `system.yaml`, `architecture.yaml`, `system-profile.md`) to determine:

- **Workload Type:**
  - _Static content / Documentation / Jamstack_ $\rightarrow$ **Candidate: GSA Pages**
  - _Twelve-Factor Web App / REST API / Admin Portal_ $\rightarrow$ **Candidate: cloud.gov PaaS**
  - _Containerized microservice with custom ingress or sidecars_ $\rightarrow$ **Candidate: cloud.gov Workshop**
  - _Specialized AWS GovCloud primitives / Data Lakes / GPU_ $\rightarrow$ **Candidate: FCS managed cloud service**
  - _Custom Kubernetes cluster / Bare-metal node control_ $\rightarrow$ **Candidate: FCS CaaS**
  - _Disposable R&D / Hackathon / Pre-ATO experiment_ $\rightarrow$ **Candidate: cloud-sandbox**
- **Data Classification:** Public (Low), CUI / PII (Moderate), or High.
- **Backing Services:** Managed PostgreSQL/Redis/S3 vs. custom-installed persistent daemons.

### Step 2: Compute Residual NIST 800-53 Control Count

Run the tier residual analysis against the candidate platform:

```bash
uv run python scripts/analysis/residual_controls_by_tier.py
```

Compare residual burdens across the baseline tiers:

| Platform Tier            | NIST Controls Inherited | Residual Controls Owned by Tenant | % Inherited | DevSecOps FTE Needed |
| :----------------------- | :---------------------- | :-------------------------------- | :---------- | :------------------- |
| **GSA Pages**            | 89 / 89                 | **0**                             | 100%        | 0.0 FTE              |
| **cloud.gov Core App**   | 13 / 13                 | **0**                             | 100%        | 0.0 FTE              |
| **cloud.gov PaaS Stack** | 325 / 616               | **291** (mostly app-level)        | 52.8%       | ~0.2 FTE             |
| **FCS managed cloud service**            | 58 / 192                | **134** (125 hybrid + 9 tenant)   | 30.2%       | ~1.0–1.5 FTE         |
| **FCS CaaS (EKS)**       | 0 / 192                 | **192** (100% tenant owned)       | 0.0%        | ~2.0–3.0 FTE         |

Use the `cloud.gov Core App` row when evaluating the platform-provided runtime controls directly inherited from cloud.gov. Use the broader `cloud.gov PaaS Stack` row when evaluating a full application SSPP boundary that includes application-layer controls still owned by the tenant.

For the Example System.gov static-site component swap specifically, run the focused delta script in addition to the cross-tier residual report:

```bash
uv run python scripts/analysis/control_delta_gsa_pages_vs_managed-cloud-service.py
```

> **Critical Rule:** Remember the **20 irreducible tenant controls** (AC-4, AC-5, AC-7, AC-8, AC-11, AC-14, AC-22, CM-9, CM-12, MP-3..5, PE-10, PE-17, SA-10, SA-15, SC-32, SI-11, SI-18, SI-19). No platform relieves a system owner from these.

### Step 3: Assess Operational Ticket Friction vs. Self-Service

Examine whether the PR introduces infrastructure components requiring GSA IT Jira tickets:

- **Routes / Domains / TLS:** Automated via cloud.gov domain broker (instant) vs. GSA IT DNS/Cert ticket (2–10 business days).
- **IAM / Auth:** Built-in cloud.gov UAA / IdP bindings vs. custom AWS IAM roles, IAM Identity Center, and IRSA mapping.
- **Egress / Firewall:** Self-service network egress vs. NetOps firewall exception requests.
- **Zero-Day Remediation:** Platform stemcell updates (zero tenant effort) vs. rebuilding, scanning, and redeploying base container images within 48 hours.

### Step 4: Validate "Smallest Responsible Platform Boundary"

Apply the **Golden Rule of Right-Sizing**:

- If a workload _can_ run on cloud.gov PaaS or Workshop, deploying it to FCS CaaS or managed cloud service represents **over-provisioning** and introduces an unjustifiable operational tax on TTS.
- If the PR selects FCS CaaS/managed cloud service, verify that it documents a strict **Technical Impossibility Justification** (e.g., requires AWS GPU nodes, direct VPC peering with agency backend, or non-HTTP protocols unsupported by cloud.gov Gorouter).

---

## PR Review Comment Template

When reviewing a PR, generate a structured markdown comment using the following format:

```markdown
## ⚖️ Platform Right-Sizing & Siting Analysis

### Executive Recommendation

- **Target Workload:** `<Workload Name or Component>`
- **Proposed Platform:** `<Proposed Platform in PR>`
- **Recommended Platform:** `<cloud.gov PaaS | cloud.gov Workshop | FCS managed cloud service | FCS CaaS | cloud-sandbox>`
- **Siting Verdict:** `[ ✅ OPTIMAL | ⚠️ OVER-PROVISIONED | ❌ INAPPROPRIATE BURDEN ]`

---

### Key Comparison Metrics

| Evaluation Dimension        | Proposed Platform           | Recommended Alternative     | Delta / Impact               |
| :-------------------------- | :-------------------------- | :-------------------------- | :--------------------------- |
| **Residual NIST Controls**  | `XX` controls               | `YY` controls               | `±ZZ` controls owned by team |
| **Provisioning Lead Time**  | `<Lead Time>`               | `<Lead Time>`               | `<Self-service vs. Ticket>`  |
| **DevSecOps Headcount**     | `~X.X FTE`                  | `~Y.Y FTE`                  | `±N FTE staffing demand`     |
| **Container & OS Burden**   | `<Full container CVE duty>` | `<Zero / Managed stemcell>` | `<Impact on maintenance>`    |
| **Change-Request Friction** | `<Jira tickets required>`   | `<100% self-service CLI>`   | `<Operational agility>`      |

---

### Analysis & Justification

- **Workload Alignment:** `<Explanation of whether workload characteristics match the platform boundary.>`
- **Compliance Inheritance:** `<Specific NIST families most impacted (e.g. SC, SI, CM).>`
- **Operational Reality:** `<Discussion of lead times, certificate renewal, and CVE patching.>`

### Actionable Next Steps

1. `[ ]` <Specific change to system.yaml, tier configuration, or documentation>
2. `[ ]` Run `make residuals-report` to refresh residual control outputs.
3. `[ ]` Update `docs/analyses/` or ADR if a technical exception is justified.
```

---

## Quick Reference Commands

```bash
# Calculate residual controls across all baseline tiers
uv run python scripts/analysis/residual_controls_by_tier.py

# Calculate the Example System.gov GSA Pages vs FCS managed cloud service/CaaS hosting-component delta
uv run python scripts/analysis/control_delta_gsa_pages_vs_managed-cloud-service.py

# Run the Example System composite overlay comparison
uv run python scripts/analysis/composite_control_overlay.py

# Validate all system manifests and architecture schemas
make validate-sources
make test
```
