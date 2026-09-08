"""Configuration overrides for ADR-006 vault-to-Precogly conversion.

Kept in-repo so ISSO reviewers can tune the technical/procedural heuristic
without editing code (see issue #22 open question).
"""

TECHNICAL_STATEMENT_KEYWORDS = (
    "encrypt",
    "tls",
    "mtls",
    "certificate",
    "firewall",
    "network",
    "vpn",
    "iam",
    "rbac",
    "mfa",
    "sso",
    "logging",
    "audit log",
    "scan",
    "vulnerability",
    "patch",
    "backup",
    "hash",
    "signing",
    "hsm",
    "kms",
    "cryptograph",
    "container",
    "kubernetes",
    "pipeline",
    "ci/cd",
    "sast",
    "dast",
)

PROCEDURAL_STATEMENT_KEYWORDS = (
    "policy",
    "procedure",
    "training",
    "awareness",
    "annual",
    "quarterly",
    "review",
    "approval",
    "governance",
    "committee",
    "recert",
    "personnel",
    "sign",
    "acknowledg",
    "notification",
)

STATUS_TO_CDX = {
    "operational": "implemented",
    "under-development": "planned",
    "under-testing": "in-progress",
    "planned": "planned",
    "not-applicable": "rejected",
    "not-implemented": "recommended",
}

ORIGINATION_TO_CONTROL_TYPE = {
    "inherited": "procedural",
    "shared": "procedural",
    "hybrid": "procedural",
    "system-specific": None,
    "customer-configured": "corrective",
    "customer-provided": "procedural",
}

CRM_ORIGINATION_MAP = {
    "system-specific": "tenant",
    "customer-configured": "tenant",
    "customer-provided": "tenant",
    "shared": "shared",
    "hybrid": "shared",
    "inherited": "platform-inherited",
}

STATUS_RISK = {
    "operational": "low",
    "under-development": "medium",
    "under-testing": "medium",
    "planned": "high",
    "not-implemented": "high",
    "not-applicable": "low",
}


def classify_control_type(origination: str, prose: str) -> str:
    """Return preventive/detective/corrective for CycloneDX category field.

    Uses a keyword heuristic on the prose; falls back to procedural default.
    See issue #22 for the accuracy question.
    """
    text = (prose or "").lower()
    if origination in {"inherited", "shared", "customer-provided"}:
        return "preventive"
    if origination == "customer-configured":
        return "corrective"
    for kw in TECHNICAL_STATEMENT_KEYWORDS:
        if kw in text:
            return "preventive"
    for kw in PROCEDURAL_STATEMENT_KEYWORDS:
        if kw in text:
            return "detective"
    return "preventive"
