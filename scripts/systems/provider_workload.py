"""Build one workload system from exactly one independent provider CRM."""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path
from typing import Any

import jsonschema
import yaml

try:
    from scripts.control_identity import canonical_control_id
    from scripts.tmbom_standards import project_nist_standard
    from scripts.tmbom_topology import project_tmbom_topology
except ModuleNotFoundError:  # Support imports from direct script invocation.
    from control_identity import canonical_control_id
    from tmbom_standards import project_nist_standard
    from tmbom_topology import project_tmbom_topology

from .loader import ROOT, load_manifest, load_system

WORKLOAD_SCHEMA = ROOT / "schemas" / "provider-workload.schema.json"
OPTIONS_SCHEMA = ROOT / "schemas" / "example-system-options.schema.json"
TIERS = ROOT / "data" / "tiers"
BUILT_SYSTEMS = ROOT / "build" / "systems"
IDENTITY_NAMESPACE = uuid.UUID("8f247e65-96ae-4539-ad77-8aa3e8792394")
CRM_PACKAGES = {
    "gsa-pages": ("gsa-pages-ssp-2026", "gsa-pages-ssp-2026-crm"),
    "cloud-gov-paas": ("cloud-gov-v1-33", "cloud-gov-v1-33-crm"),
}
DETECTIVE_CONTROL_FAMILIES = {"AU", "CA", "IR", "RA", "SI"}


class ProviderWorkloadError(ValueError):
    """The independent workload or its sole CRM package is invalid."""


def workload_control_status(
    provider_status: str,
    lifecycle: str,
    authorization_state: str,
    proposal_statuses: list[str] | None = None,
) -> str:
    """Keep provider posture separate and fail closed for non-current workloads."""

    proposals = proposal_statuses or []
    if "recommended" in proposals:
        return "recommended"
    if lifecycle not in {"as-built"} or authorization_state not in {
        "approved",
        "current",
    }:
        return "planned"
    return provider_status


def control_category(control_id: str) -> str:
    family = canonical_control_id(control_id).split("-", 1)[0]
    return "detective" if family in DETECTIVE_CONTROL_FAMILIES else "preventive"


def _remember_original_targets(item: dict[str, Any], field: str) -> None:
    targets = item.get(field) or []
    if targets:
        item.setdefault("properties", []).append(
            {
                "name": f"resp:original-{field}",
                "value": json.dumps(targets, separators=(",", ":")),
            }
        )


def _set_property(document: dict[str, Any], name: str, value: str) -> None:
    properties = document.setdefault("metadata", {}).setdefault("properties", [])
    existing = next((item for item in properties if item.get("name") == name), None)
    if existing:
        existing["value"] = value
    else:
        properties.append({"name": name, "value": value})


def _validate_topology_refs(workload: dict[str, Any], *, source: Path) -> None:
    seen: dict[str, str] = {}
    for section in ("zones", "boundaries", "assets", "flows"):
        for index, item in enumerate(workload["topology"][section]):
            ref = item["bom-ref"]
            location = f"topology.{section}[{index}]"
            previous = seen.get(ref)
            if previous:
                raise ProviderWorkloadError(
                    f"{source}: duplicate topology bom-ref {ref!r} at {previous} "
                    f"and {location}"
                )
            seen[ref] = location


def load_provider_workload(
    slug: str,
) -> tuple[dict[str, Any], dict[str, Any], str, str, str]:
    paths = load_system(slug)
    manifest = load_manifest(slug)
    tiers = manifest.get("inherits_from") or []
    if len(tiers) != 1:
        raise ProviderWorkloadError(
            f"{slug}: independent workload must inherit exactly one CRM tier, found {tiers}"
        )
    tier = tiers[0]
    if not (TIERS / f"{tier}.yaml").is_file():
        raise ProviderWorkloadError(f"{slug}: CRM tier {tier!r} does not exist")
    package_system, package_slug = CRM_PACKAGES.get(
        tier, (f"tier-{tier}", f"{tier}-crm")
    )
    if tier in CRM_PACKAGES:
        pack_path = BUILT_SYSTEMS / package_system / "pack" / "pack.yaml"
        package_path = BUILT_SYSTEMS / package_system / f"{package_system}.cdx.json"
        if not pack_path.is_file() or not package_path.is_file():
            raise ProviderWorkloadError(
                f"{slug}: canonical CRM artifacts missing for {package_system}"
            )
        pack = yaml.safe_load(pack_path.read_text(encoding="utf-8")) or {}
        if (pack.get("pack") or {}).get("slug") != package_slug:
            raise ProviderWorkloadError(f"{slug}: canonical CRM pack slug mismatch")
    workload_path = paths.root / "workload.yaml"
    workload = yaml.safe_load(workload_path.read_text(encoding="utf-8")) or {}
    schema = json.loads(WORKLOAD_SCHEMA.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(workload, schema)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ProviderWorkloadError(
            f"{workload_path}: schema error at {location}: {exc.message}"
        ) from exc
    _validate_topology_refs(workload, source=workload_path)
    if workload["system"] != slug:
        raise ProviderWorkloadError(f"{slug}: workload system does not match directory")
    return manifest, workload, tier, package_system, package_slug


def validate_example_system_options() -> list[str]:
    path = ROOT / "data" / "systems" / "example-system" / "options.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    schema = json.loads(OPTIONS_SCHEMA.read_text(encoding="utf-8"))
    errors = [
        f"{path}: {error.message}"
        for error in jsonschema.Draft202012Validator(schema).iter_errors(data)
    ]
    if errors:
        return errors
    expected = {
        supplement: option
        for option, detail in data["options"].items()
        for supplement in detail["supplements"]
    }
    for supplement, option in expected.items():
        try:
            _, workload, _, _, _ = load_provider_workload(supplement)
        except ProviderWorkloadError as exc:
            errors.append(str(exc))
            continue
        if workload.get("option_membership") != [option]:
            errors.append(
                f"{supplement}: option_membership must be exactly [{option!r}]"
            )
        if workload.get("depends_on_system") != data["core_system"]:
            errors.append(
                f"{supplement}: depends_on_system must be {data['core_system']!r}"
            )
    return errors


def _tier_crm_document(tier: str, package_slug: str, title: str) -> dict[str, Any]:
    source_path = (
        ROOT / "data" / "systems" / "example-system" / "crm" / "data-platform.yaml"
        if tier == "data-platform"
        else TIERS / f"{tier}.yaml"
    )
    source = yaml.safe_load(source_path.read_text(encoding="utf-8")) or {}
    controls = []
    for index, row in enumerate(source.get("controls") or [], start=1):
        raw_id = row.get("managed-cloud-service_tenant") or row.get("control_id")
        control_id = canonical_control_id(raw_id)
        inheritance = str(
            row.get("managed-cloud-service_tenant_inheritance_source") or row.get("inheritance") or ""
        )
        responsibility = str(
            row.get("managed-cloud-service_tenant_responsibility")
            or row.get("what")
            or row.get("how")
            or "No tenant responsibility prose is present in the CRM source."
        )
        inherited = inheritance.lower().startswith("fully inherited")
        origination = (
            "inherited"
            if inherited
            else "hybrid"
            if inheritance.lower().startswith("hybrid")
            else "system-specific"
        )
        source_status = str(row.get("implementation_status") or "").lower()
        implementation_status = (
            "implemented"
            if inherited or source_status == "fully implemented"
            else "in-progress"
            if source_status == "partially implemented"
            else "recommended"
            if source_status in {"not implemented", "gap"}
            else "planned"
        )
        controls.append(
            {
                "bom-ref": f"ctrl-{tier}-{index:04d}",
                "name": f"{control_id} - {row.get('name') or control_id}",
                "description": responsibility,
                "category": control_category(control_id),
                "status": implementation_status,
                "properties": [
                    {"name": "ctrl:id", "value": control_id},
                    {"name": "crm:responsibility-source", "value": package_slug},
                    {"name": "vault:inheritance-source", "value": inheritance},
                    {
                        "name": "vault:implementation-status",
                        "value": implementation_status,
                    },
                    {"name": "vault:origination", "value": origination},
                    {"name": "resp:source", "value": f"crm-package:{package_slug}"},
                ],
                "satisfies": [{"framework": "nist-800-53-r5", "reference": control_id}],
            }
        )
    return {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": title},
            "properties": [],
        },
        "definitions": {},
        "blueprints": [
            {
                "bom-ref": f"blueprint-{tier}",
                "name": title,
                "modelTypes": ["data-flow"],
                "zones": [],
                "boundaries": [],
                "assets": [],
                "dataStores": [],
                "flows": [],
            }
        ],
        "threats": {"threats": [], "scenarios": []},
        "controls": controls,
    }


def build_provider_workload(slug: str) -> dict[str, Any]:
    manifest, workload, tier, package_system, package_slug = load_provider_workload(
        slug
    )
    if tier in CRM_PACKAGES:
        package_path = BUILT_SYSTEMS / package_system / f"{package_system}.cdx.json"
        document = copy.deepcopy(json.loads(package_path.read_text(encoding="utf-8")))
    else:
        document = _tier_crm_document(tier, package_slug, manifest["name"])
    blueprint = document["blueprints"][0]
    blueprint["zones"] = []
    blueprint["boundaries"] = []
    blueprint["assets"] = []
    blueprint["dataStores"] = []
    blueprint["flows"] = []
    blueprint.pop("visualizations", None)
    topology = workload["topology"]
    shared = {section: [] for section in ("zones", "boundaries", "assets", "flows")}
    sections = ("zones", "boundaries", "assets", "flows")
    existing = {
        item["bom-ref"] for section in sections for item in blueprint.get(section) or []
    }
    additions = {
        item["bom-ref"]
        for section in sections
        for item in [*shared[section], *topology[section]]
    }
    collisions = sorted(existing & additions)
    if collisions:
        raise ProviderWorkloadError(f"{slug}: duplicate topology refs: {collisions}")
    for section in sections:
        blueprint.setdefault(section, []).extend(copy.deepcopy(shared[section]))
        blueprint[section].extend(copy.deepcopy(topology[section]))
    for boundary in blueprint.get("boundaries") or []:
        name = str(boundary.get("name") or "").strip()
        if name and "boundary" not in name.lower():
            boundary["name"] = f"{name} Boundary"
    entities = {
        item["bom-ref"]: item.get("name") or item["bom-ref"]
        for section in ("zones", "assets", "dataStores")
        for item in blueprint.get(section) or []
    }
    for flow in blueprint.get("flows") or []:
        source = entities.get(flow.get("source"), flow.get("source"))
        destination = entities.get(flow.get("destination"), flow.get("destination"))
        linked_name = f"{source} to {destination}"
        original_name = flow.get("name")
        flow["name"] = (
            original_name
            if original_name and original_name.startswith(linked_name)
            else f"{linked_name} - {original_name}"
            if original_name
            else linked_name
        )
        flow.setdefault("type", "data")
        authenticated = flow.pop("authenticated", None)
        if authenticated is not None:
            flow.setdefault("properties", []).append(
                {"name": "resp:authenticated", "value": str(authenticated).lower()}
            )
    blueprint["bom-ref"] = f"blueprint-{slug}"
    blueprint["name"] = workload.get("title") or manifest["name"]
    metadata_component = document.setdefault("metadata", {}).setdefault("component", {})
    metadata_component["name"] = workload.get("title") or manifest["name"]
    metadata_component.setdefault("type", "application")
    if workload.get("scope"):
        blueprint["scope"] = copy.deepcopy(workload["scope"])
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(IDENTITY_NAMESPACE, slug)}"
    document["version"] = 1
    _set_property(document, "vault:system-slug", slug)
    _set_property(document, "resp:crm-tier", tier)
    _set_property(document, "resp:crm-package-system", package_system)
    _set_property(document, "resp:crm-package-slug", package_slug)
    _set_property(document, "resp:lifecycle", workload["lifecycle"])
    _set_property(document, "resp:authorization-state", workload["authorization_state"])
    _set_property(document, "resp:feasibility-status", workload["feasibility_status"])
    _set_property(document, "resp:model-role", workload["model_role"])
    for option in workload.get("option_membership") or []:
        document.setdefault("metadata", {}).setdefault("properties", []).append(
            {"name": "resp:option-membership", "value": option}
        )
    proposals: dict[str, list[dict[str, Any]]] = {}
    for proposal in workload.get("proposed_controls") or []:
        control_id = canonical_control_id(proposal["control_id"])
        proposals.setdefault(control_id, []).append(proposal)
    for control in document.get("controls") or []:
        properties = control.setdefault("properties", [])
        if not any(item.get("name") == "resp:source" for item in properties):
            properties.append(
                {
                    "name": "resp:source",
                    "value": f"crm-package:{package_slug}",
                }
            )
        control_id = next(
            (item["value"] for item in properties if item.get("name") == "ctrl:id"),
            None,
        )
        provider_status = control.get("status", "planned")
        properties.append({"name": "resp:provider-status", "value": provider_status})
        control_proposals = proposals.get(control_id, [])
        for proposal in control_proposals:
            properties.extend(
                [
                    {"name": "resp:proposal-status", "value": proposal["status"]},
                    {"name": "resp:proposal-source", "value": proposal["source"]},
                    {
                        "name": "resp:proposal-mechanism",
                        "value": proposal["mechanism"],
                    },
                ]
            )
            for criterion in proposal["acceptance_criteria"]:
                properties.append(
                    {"name": "resp:proposal-acceptance", "value": criterion}
                )
        control["status"] = workload_control_status(
            provider_status,
            workload["lifecycle"],
            workload["authorization_state"],
            [proposal["status"] for proposal in control_proposals],
        )
        properties.append({"name": "resp:workload-status", "value": control["status"]})
    target_ref = workload.get("crm_target_asset")
    if target_ref:
        if target_ref not in {
            item["bom-ref"] for item in blueprint.get("assets") or []
        }:
            raise ProviderWorkloadError(
                f"{slug}: crm_target_asset {target_ref!r} is not a workload asset"
            )
        for control in document.get("controls") or []:
            _remember_original_targets(control, "appliesTo")
            control["appliesTo"] = [target_ref]
            control["category"] = control_category(
                next(
                    item["value"]
                    for item in control["properties"]
                    if item.get("name") == "ctrl:id"
                )
            )
        for threat in (document.get("threats") or {}).get("threats") or []:
            _remember_original_targets(threat, "affectedAssets")
            _remember_original_targets(threat, "affectedFlows")
            threat["affectedAssets"] = [target_ref]
            threat.pop("affectedFlows", None)
        for scenario in (document.get("threats") or {}).get("scenarios") or []:
            _remember_original_targets(scenario, "affectedAssets")
            _remember_original_targets(scenario, "affectedFlows")
            scenario["affectedAssets"] = [target_ref]
            scenario.pop("affectedFlows", None)
    project_nist_standard(document)
    project_tmbom_topology(document)
    try:
        from scripts.precogly.add_dfd_visualization import add_visualization
    except ModuleNotFoundError:
        from precogly.add_dfd_visualization import add_visualization
    document, _ = add_visualization(document)
    blueprint = document["blueprints"][0]
    depends_on = workload.get("depends_on_system")
    if depends_on:
        target_serial = uuid.uuid5(IDENTITY_NAMESPACE, depends_on)
        blueprint["assets"].append(
            {
                "bom-ref": f"related-model-{depends_on}",
                "name": "Example System data platform Core",
                "type": "system",
                "externalReferences": [
                    {
                        "type": "threat-model",
                        "url": f"urn:cdx:{target_serial}/1",
                    }
                ],
                "properties": [
                    {"name": "precogly:relationship", "value": "depends_on"}
                ],
            }
        )
    return document


def write_provider_workload(slug: str, out: Path | None = None) -> Path:
    document = build_provider_workload(slug)
    path = out or BUILT_SYSTEMS / slug / f"{slug}.cdx.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    blueprint = document["blueprints"][0]
    properties = {
        item["name"]: item["value"]
        for item in document.get("metadata", {}).get("properties", [])
    }
    summary = {
        "system": slug,
        "crm": {
            "tier": properties["resp:crm-tier"],
            "package_system": properties["resp:crm-package-system"],
            "package_slug": properties["resp:crm-package-slug"],
        },
        "statistics": {
            "zones": len(blueprint.get("zones") or []),
            "assets": len(blueprint.get("assets") or []),
            "boundaries": len(blueprint.get("boundaries") or []),
            "flows": len(blueprint.get("flows") or []),
            "threats": len((document.get("threats") or {}).get("threats") or []),
            "scenarios": len((document.get("threats") or {}).get("scenarios") or []),
            "controls": len(document.get("controls") or []),
        },
    }
    path.with_name("import-summary.yaml").write_text(
        yaml.safe_dump(summary, sort_keys=False), encoding="utf-8"
    )
    return path
