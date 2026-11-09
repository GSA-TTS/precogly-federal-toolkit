"""Validate semantic readiness of a CycloneDX control projection.

This gate complements ``scripts/validate.py``. Structural validation proves
that references point somewhere; this validator proves that each control keeps
its identity, destination, type, and provenance through an adapter boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from scripts.control_identity import canonical_control_id
except ModuleNotFoundError:  # Support direct invocation as a script.
    from control_identity import canonical_control_id


REQUIRED_PROVENANCE = {"resp:source", "resp:evidence-key", "response_source"}
ALLOWED_CATEGORIES = {"preventive", "detective", "corrective"}
SEMANTIC_PROPERTY_PREFIXES = (
    "evidence:",
    "parameter:",
    "stable:",
    "resp:",
    "vault:param:",
    "odp:",
)
FRAMEWORK_ALIASES = {
    "NIST SP 800-53": "nist-800-53-r5",
    "NIST SP 800-53 Rev. 5": "nist-800-53-r5",
}


def _properties(item: dict[str, Any]) -> dict[str, Any]:
    return {
        prop.get("name"): prop.get("value")
        for prop in item.get("properties", []) or []
        if prop.get("name")
    }


def _destination_refs(
    control: dict[str, Any],
    threats: dict[str, dict[str, Any]],
    labels: dict[str, str] | None = None,
) -> list[str]:
    destinations = list(control.get("appliesTo") or [])
    for mitigation in control.get("mitigations") or []:
        destinations.extend(threats.get(mitigation, {}).get("affectedAssets") or [])
    control_ref = control.get("bom-ref")
    for threat in threats.values():
        if control_ref in (threat.get("mitigations") or []):
            destinations.extend(threat.get("affectedAssets") or [])
    labels = labels or {}
    return sorted(
        {labels.get(destination, destination) for destination in destinations}
    )


def _semantic_properties(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        name: properties[name]
        for name in sorted(properties)
        if name.startswith(SEMANTIC_PROPERTY_PREFIXES)
    }


def _requirement_index(document: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Index native CycloneDX requirement refs as compact framework identities."""
    index = {}
    definitions = document.get("definitions") or {}
    for standard in definitions.get("standards") or []:
        framework = standard.get("bom-ref") or standard.get("name")
        if isinstance(framework, str) and framework.startswith("standard-"):
            framework = framework.removeprefix("standard-")
        framework = FRAMEWORK_ALIASES.get(framework, framework)
        for requirement in standard.get("requirements") or []:
            bom_ref = requirement.get("bom-ref")
            if bom_ref:
                reference = requirement.get("identifier") or requirement.get("title")
                index[bom_ref] = (framework, reference)
    # Retain the pre-2.0 draft shape for semantic migration comparisons only.
    for requirement in definitions.get("requirements") or []:
        bom_ref = requirement.get("bom-ref")
        if bom_ref:
            source = requirement.get("source") or {}
            framework = source.get("bom-ref") or source.get("name")
            framework = FRAMEWORK_ALIASES.get(framework, framework)
            reference = requirement.get("identifier") or requirement.get("title")
            index[bom_ref] = (framework, reference)
    return index


def _satisfies(
    control: dict[str, Any],
    requirements: dict[str, tuple[Any, Any]],
) -> list[tuple[Any, Any]]:
    """Normalize compact objects and native requirement bom-ref strings."""
    resolved = set()
    for item in control.get("satisfies") or []:
        if isinstance(item, dict):
            resolved.add((item.get("framework"), item.get("reference")))
        elif isinstance(item, str):
            resolved.add(requirements.get(item, ("unresolved-bom-ref", item)))
    return sorted(resolved)


def build_manifest(document: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic semantic manifest from a CDX document."""

    threats = {
        threat.get("bom-ref"): threat
        for threat in (document.get("threats") or {}).get("threats", []) or []
    }
    labels = {
        asset.get("bom-ref"): asset.get("name") or asset.get("bom-ref")
        for blueprint in document.get("blueprints", []) or []
        for asset in [
            *(blueprint.get("assets", []) or []),
            *(blueprint.get("dataStores", []) or []),
        ]
        if asset.get("bom-ref")
    }
    labels.update(
        {
            flow.get("bom-ref"): flow.get("name") or flow.get("bom-ref")
            for blueprint in document.get("blueprints", []) or []
            for flow in blueprint.get("flows", []) or []
            if flow.get("bom-ref")
        }
    )
    threat_labels = {
        threat.get("bom-ref"): threat.get("name") or threat.get("bom-ref")
        for threat in threats.values()
        if threat.get("bom-ref")
    }
    requirements = _requirement_index(document)
    records: list[dict[str, Any]] = []
    for control in document.get("controls") or []:
        props = _properties(control)
        raw_id = props.get("ctrl:id")
        if not raw_id:
            continue
        try:
            control_id = canonical_control_id(str(raw_id))
        except ValueError:
            continue
        records.append(
            {
                "bom_ref": control.get("bom-ref"),
                "control_id": control_id,
                "category": control.get("category"),
                "status": control.get("status"),
                "destination_refs": _destination_refs(control, threats, labels),
                "satisfies": _satisfies(control, requirements),
                "semantic_properties": _semantic_properties(props),
                "placeholder": props.get("sspp:is-placeholder", "false") == "true",
            }
        )
    records.sort(key=lambda item: (item["control_id"], item["bom_ref"] or ""))
    scenarios = []
    for scenario in (document.get("threats") or {}).get("scenarios", []) or []:
        threat_refs = scenario.get("threats") or [scenario.get("threat")]
        threat_ref = threat_refs[0] if threat_refs else None
        properties = _properties(scenario)
        scenarios.append(
            {
                "scenario": scenario.get("name") or scenario.get("bom-ref"),
                "threat": threat_labels.get(threat_ref, threat_ref),
                "inherent_severity": scenario.get("inherentSeverity")
                or properties.get("resp:inherent-severity"),
                "residual_severity": scenario.get("residualSeverity")
                or properties.get("resp:residual-severity"),
                "affected_assets": sorted(
                    labels.get(ref, ref) for ref in scenario.get("affectedAssets", [])
                ),
                "affected_flows": sorted(
                    labels.get(ref, ref) for ref in scenario.get("affectedFlows", [])
                ),
            }
        )
    scenarios.sort(key=lambda item: (item["threat"] or "", item["scenario"] or ""))
    payload = {"manifest_version": 1, "controls": records, "scenarios": scenarios}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        **payload,
        "control_count": len(records),
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def compare_manifests(
    expected: dict[str, Any], actual: dict[str, Any]
) -> dict[str, Any]:
    """Compare semantic records while ignoring unstable ``bom_ref`` values."""

    def semantic_key(record: dict[str, Any]) -> str:
        comparable = {key: value for key, value in record.items() if key != "bom_ref"}
        return json.dumps(comparable, sort_keys=True, separators=(",", ":"))

    def difference(field: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        expected_counts: dict[str, int] = {}
        actual_counts: dict[str, int] = {}
        for record in expected.get(field, []):
            key = semantic_key(record)
            expected_counts[key] = expected_counts.get(key, 0) + 1
        for record in actual.get(field, []):
            key = semantic_key(record)
            actual_counts[key] = actual_counts.get(key, 0) + 1
        missing: list[dict[str, Any]] = []
        extra: list[dict[str, Any]] = []
        for key in sorted(set(expected_counts) | set(actual_counts)):
            delta = expected_counts.get(key, 0) - actual_counts.get(key, 0)
            record = json.loads(key)
            if delta > 0:
                missing.extend([record] * delta)
            elif delta < 0:
                extra.extend([record] * -delta)
        return missing, extra

    missing, extra = difference("controls")
    scenario_missing, scenario_extra = difference("scenarios")
    missing.extend({"scenario": item} for item in scenario_missing)
    extra.extend({"scenario": item} for item in scenario_extra)
    return {
        "equal": not missing and not extra,
        "expected_count": len(expected.get("controls", [])),
        "actual_count": len(actual.get("controls", [])),
        "expected_scenario_count": len(expected.get("scenarios", [])),
        "actual_scenario_count": len(actual.get("scenarios", [])),
        "missing_count": len(missing),
        "extra_count": len(extra),
        "missing": missing,
        "extra": extra,
    }


def validate_cdx(document: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic readiness report for one CDX document."""

    controls = document.get("controls") or []
    threats = {
        threat.get("bom-ref"): threat
        for threat in (document.get("threats") or {}).get("threats", []) or []
    }
    assets = {
        asset.get("bom-ref")
        for blueprint in document.get("blueprints", []) or []
        for asset in blueprint.get("assets", []) or []
        if asset.get("bom-ref")
    }
    flows = {
        flow.get("bom-ref")
        for blueprint in document.get("blueprints", []) or []
        for flow in blueprint.get("flows", []) or []
        if flow.get("bom-ref")
    }
    failures: list[dict[str, str]] = []
    seen: dict[str, str] = {}
    requirements = _requirement_index(document)

    for control in controls:
        ref = str(control.get("bom-ref") or "<missing-bom-ref>")
        props = _properties(control)
        raw_id = props.get("ctrl:id")
        if not raw_id:
            failures.append({"bom_ref": ref, "code": "missing-control-id"})
            continue
        try:
            control_id = canonical_control_id(str(raw_id))
        except ValueError:
            failures.append({"bom_ref": ref, "code": "invalid-control-id"})
            continue
        # Multiple countermeasures may intentionally share one NIST control ID;
        # each remains distinct by bom-ref and mechanism-level provenance.
        seen.setdefault(control_id, ref)

        references = _satisfies(control, requirements)
        if not any(reference == control_id for _, reference in references):
            failures.append({"bom_ref": ref, "code": "identity-not-preserved"})

        destinations = control.get("appliesTo") or []
        if not destinations:
            for mitigation in control.get("mitigations") or []:
                destinations.extend(
                    threats.get(mitigation, {}).get("affectedAssets") or []
                )
        if not destinations:
            for threat in threats.values():
                if ref in (threat.get("mitigations") or []):
                    destinations.extend(threat.get("affectedAssets") or [])
        if not destinations:
            failures.append({"bom_ref": ref, "code": "missing-destination"})
        elif assets and any(
            destination not in assets and destination not in flows
            for destination in destinations
        ):
            failures.append({"bom_ref": ref, "code": "unknown-destination"})

        if control.get("category") not in ALLOWED_CATEGORIES:
            failures.append({"bom_ref": ref, "code": "missing-or-invalid-type"})

        has_external_provenance = bool(control.get("externalReferences"))
        if not has_external_provenance and not any(
            props.get(name) for name in REQUIRED_PROVENANCE
        ):
            failures.append({"bom_ref": ref, "code": "missing-provenance"})

        if props.get("sspp:is-placeholder", "false") == "true":
            failures.append({"bom_ref": ref, "code": "placeholder-control"})

    report = {
        "ready": bool(controls) and not failures,
        "control_count": len(controls),
        "canonical_control_count": len(seen),
        "failure_count": len(failures),
        "failures": failures,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cdx", type=Path)
    parser.add_argument(
        "--report", type=Path, help="Write the readiness report as JSON"
    )
    parser.add_argument(
        "--manifest", type=Path, help="Write the semantic manifest as JSON"
    )
    parser.add_argument(
        "--compare", type=Path, help="Compare this manifest with another manifest"
    )
    args = parser.parse_args(argv)
    document = json.loads(args.cdx.read_text(encoding="utf-8"))
    if args.compare:
        comparison = compare_manifests(
            document, json.loads(args.compare.read_text(encoding="utf-8"))
        )
        rendered = json.dumps(comparison, indent=2, sort_keys=True) + "\n"
        if args.report:
            args.report.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0 if comparison["equal"] else 1
    report = validate_cdx(document)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.write_text(rendered, encoding="utf-8")
    if args.manifest:
        args.manifest.write_text(
            json.dumps(build_manifest(document), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(rendered, end="")
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
