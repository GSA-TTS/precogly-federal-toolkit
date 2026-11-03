"""Project canonical NIST control mappings into CycloneDX 2.0 TM-BOM."""

from __future__ import annotations

import re
from typing import Any

try:
    from scripts.control_identity import canonical_control_id
except ModuleNotFoundError:  # Support direct invocation as a script.
    from control_identity import canonical_control_id


NIST_FRAMEWORK = "nist-800-53-r5"
NIST_STANDARD_REF = f"standard-{NIST_FRAMEWORK}"
_NIST_ALIASES = {
    NIST_FRAMEWORK,
    "NIST 800-53 Rev 5",
    "NIST SP 800-53",
    "NIST SP 800-53 Rev. 5",
}


def requirement_ref(control_id: str) -> str:
    """Return a stable bom-ref for a canonical NIST requirement identifier."""

    canonical = canonical_control_id(control_id)
    suffix = re.sub(r"[^a-z0-9]+", "-", canonical.lower()).strip("-")
    return f"requirement-{NIST_FRAMEWORK}-{suffix}"


def project_nist_standard(document: dict[str, Any]) -> None:
    """Emit native standard requirements and make controls reference them.

    Legacy object-form mappings are accepted only as source input. Unrelated
    standards and non-NIST satisfies entries are preserved.
    """

    requirement_ids: set[str] = set()
    for control in document.get("controls") or []:
        properties = {
            item.get("name"): item.get("value")
            for item in control.get("properties") or []
            if isinstance(item, dict) and item.get("name")
        }
        raw_id = properties.get("ctrl:id")
        canonical = canonical_control_id(str(raw_id)) if raw_id else None
        satisfies = []
        for item in control.get("satisfies") or []:
            if isinstance(item, dict) and item.get("framework") in _NIST_ALIASES:
                mapped = canonical_control_id(str(item.get("reference") or raw_id))
                requirement_ids.add(mapped)
                ref = requirement_ref(mapped)
                if ref not in satisfies:
                    satisfies.append(ref)
            elif item not in satisfies:
                satisfies.append(item)
        if canonical:
            requirement_ids.add(canonical)
            ref = requirement_ref(canonical)
            satisfies = [
                item
                for item in satisfies
                if not (
                    isinstance(item, str)
                    and item.startswith(f"requirement-{NIST_FRAMEWORK}-")
                )
            ]
            satisfies.append(ref)
        if satisfies:
            control["satisfies"] = satisfies

    definitions = document.setdefault("definitions", {})
    standards = definitions.setdefault("standards", [])
    existing = next(
        (
            standard
            for standard in standards
            if standard.get("bom-ref") == NIST_STANDARD_REF
            or standard.get("name") in _NIST_ALIASES
        ),
        None,
    )
    standard = existing or {
        "bom-ref": NIST_STANDARD_REF,
        "name": NIST_FRAMEWORK,
        "version": "5",
    }
    existing_requirements = {
        requirement.get("identifier"): requirement
        for requirement in standard.get("requirements") or []
        if isinstance(requirement, dict) and requirement.get("identifier")
    }
    standard["requirements"] = [
        existing_requirements.get(control_id)
        or {
            "bom-ref": requirement_ref(control_id),
            "identifier": control_id,
            "title": control_id,
        }
        for control_id in sorted(requirement_ids)
    ]
    if existing is None:
        standards.append(standard)
