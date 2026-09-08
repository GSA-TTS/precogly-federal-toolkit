"""Shared validation primitives for the Example System and vault-projected artifacts.

Extracted from scripts/validate.py and scripts/catalog/validate_vault.py so
that both entrypoints agree on redaction, enum sets, and cross-ref lint
behavior. New callers should import from here rather than duplicating.
"""

from __future__ import annotations

import re

CATEGORIES = frozenset({"preventive", "detective", "corrective"})
STATUSES = frozenset(
    {"implemented", "recommended", "verified", "rejected", "planned", "in-progress"}
)
RISK_LEVELS = frozenset({"low", "medium", "high", "critical", "info"})


FORBIDDEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"https?://[^\s\"'>,)\]]+", re.IGNORECASE), "URL"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "email"),
]

_IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}"
    r"(?:/\d{1,2})?"
    r"(?![\w.])"
)
_SECTION_CTX_RE = re.compile(r"(?i)(?:section|sections|§|para\.?|paragraph)\s+$")


def find_ipv4_leak(text: str) -> re.Match[str] | None:
    """Return the first non-NIST-section-cited IPv4 in ``text`` (or None)."""
    for m in _IPV4_RE.finditer(text):
        preceding = text[max(0, m.start() - 40) : m.start()]
        if _SECTION_CTX_RE.search(preceding):
            continue
        return m
    return None


def find_leaks(text: str) -> list[tuple[str, str]]:
    """Return (label, matched_substring) for every recon-useful leak."""
    findings: list[tuple[str, str]] = []
    for pattern, label in FORBIDDEN_PATTERNS:
        m = pattern.search(text)
        if m:
            findings.append((label, m.group(0)))
    m = find_ipv4_leak(text)
    if m:
        findings.append(("IPv4", m.group(0)))
    return findings


def bidirectional_control_threat_errors(
    threats: list[dict], controls: list[dict]
) -> list[str]:
    """Return a list of human-readable messages for broken threat<->control links."""
    control_by_ref = {c["bom-ref"]: c for c in controls}
    errors: list[str] = []
    for t in threats:
        for cref in t.get("mitigations", []) or []:
            ctrl = control_by_ref.get(cref)
            if ctrl is None:
                continue
            if t["bom-ref"] not in (ctrl.get("mitigations") or []):
                errors.append(
                    f"bidirectional link broken: control {cref} does not link back to threat {t['bom-ref']}"
                )
    return errors
