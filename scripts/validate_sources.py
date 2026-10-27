#!/usr/bin/env python3
"""Validate source DFD and architecture bindings before generation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCHEMAS = ROOT / "schemas"
RISK_LEVELS = frozenset({"info", "low", "medium", "high", "critical"})

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from flow_auth import load_auth_catalog  # noqa: E402
from flow_refs import (  # noqa: E402
    build_flow_alias_map,
    first_blueprint,
    resolve_flow_ref,
)
from systems.hosting import (  # noqa: E402
    HostingOverlayError,
    compose_hosting_overlay,
    discover_hosting_overlays,
    load_hosting_overlay,
)
from systems.loader import DEFAULT_SYSTEM, SystemPaths, load_system  # noqa: E402
from systems.provider_workload import (  # noqa: E402
    ProviderWorkloadError,
    build_provider_workload,
    load_provider_workload,
    validate_example_system_options,
)
from validate import _load_forbidden  # noqa: E402


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _schema_errors(payload: dict[str, Any], schema_name: str, source: Path) -> list[str]:
    schema_path = SCHEMAS / schema_name
    if not schema_path.is_file():
        return []
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return []

    with schema_path.open(encoding="utf-8") as f:
        schema = json.load(f)
    validator = jsonschema.Draft202012Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        at = "/".join(str(part) for part in error.path) or "<root>"
        errors.append(f"{_rel(source)}:{at}: {error.message}")
    return errors


def validate_dfd(dfd: dict[str, Any], *, source: Path) -> tuple[set[str], set[str], set[str], list[str]]:
    errors: list[str] = []
    metadata = dfd.get("metadata") or {}
    if isinstance(metadata, dict) and metadata.get("authors"):
        errors.append(f"{_rel(source)}: metadata.authors must be stripped before generation")

    blueprints = dfd.get("blueprints") or []
    asset_refs: set[str] = set()
    zone_refs: set[str] = set()
    flow_refs: set[str] = set()
    data_store_refs: set[str] = set()
    if len(blueprints) != 1:
        errors.append(
            f"{_rel(source)}: expected exactly one blueprint, found {len(blueprints)}"
        )

    for index, blueprint in enumerate(blueprints):
        prefix = f"{_rel(source)}:blueprints[{index}]"
        assets = blueprint.get("assets") or []
        zones = blueprint.get("zones") or []
        boundaries = blueprint.get("boundaries") or []
        data_stores = blueprint.get("dataStores") or []
        flows = blueprint.get("flows") or []
        blueprint_zone_refs = {
            zone["bom-ref"] for zone in zones if zone.get("bom-ref")
        }

        for zone in zones:
            ref = zone.get("bom-ref")
            if ref in zone_refs:
                errors.append(f"{prefix}: duplicate zone bom-ref {ref}")
            elif ref in asset_refs:
                errors.append(
                    f"{prefix}: bom-ref {ref} is used by both a zone and an asset"
                )
            elif ref:
                zone_refs.add(ref)

        for asset in assets:
            ref = asset.get("bom-ref")
            if ref in asset_refs:
                errors.append(f"{prefix}: duplicate asset bom-ref {ref}")
            elif ref in zone_refs:
                errors.append(
                    f"{prefix}: bom-ref {ref} is used by both a zone and an asset"
                )
            elif ref:
                asset_refs.add(ref)
            zone = asset.get("zone")
            if zone and zone not in zone_refs:
                errors.append(f"{prefix}: asset {ref} references unknown zone {zone}")

        for boundary_index, boundary in enumerate(boundaries):
            if not isinstance(boundary, dict):
                errors.append(
                    f"{prefix}: boundaries[{boundary_index}] must be an object"
                )
                continue
            ref = boundary.get("bom-ref")
            for zone_ref in boundary.get("zones") or []:
                if zone_ref not in blueprint_zone_refs:
                    errors.append(
                        f"{prefix}: boundary {ref} references unknown zone {zone_ref}"
                    )

        for data_store_index, data_store in enumerate(data_stores):
            if not isinstance(data_store, dict):
                errors.append(
                    f"{prefix}: dataStores[{data_store_index}] must be an object"
                )
                continue
            ref = data_store.get("bom-ref")
            zone_ref = data_store.get("zone")
            if zone_ref and zone_ref not in blueprint_zone_refs:
                errors.append(
                    f"{prefix}: data store {ref} zone references unknown zone {zone_ref}"
                )

            if ref in data_store_refs:
                errors.append(f"{prefix}: duplicate data store bom-ref {ref}")
            elif ref:
                data_store_refs.add(ref)

        endpoints = asset_refs | zone_refs
        for flow in flows:
            ref = flow.get("bom-ref")
            if ref in flow_refs:
                errors.append(f"{prefix}: duplicate flow bom-ref {ref}")
            elif ref:
                flow_refs.add(ref)
            for field in ("source", "destination"):
                target = flow.get(field)
                if target not in endpoints:
                    errors.append(f"{prefix}: flow {ref} {field} references unknown DFD node {target}")

    for ref in sorted(asset_refs & flow_refs):
        errors.append(f"{_rel(source)}: bom-ref {ref} is used by both an asset and a flow")
    for ref in sorted(zone_refs & flow_refs):
        errors.append(f"{_rel(source)}: bom-ref {ref} is used by both a zone and a flow")

    return asset_refs, zone_refs, flow_refs, errors


def _check_aliases(errors: list[str], source: Path, field: str, aliases: Any, known_aliases: set[str]) -> None:
    if not isinstance(aliases, list):
        errors.append(f"{_rel(source)}:{field}: expected a list of asset aliases")
        return
    for alias in aliases:
        if alias not in known_aliases:
            errors.append(f"{_rel(source)}:{field}: unknown asset alias {alias}")


def validate_architecture(
    arch: dict[str, Any],
    *,
    source: Path,
    dfd: dict[str, Any] | None = None,
    asset_refs: set[str],
    zone_refs: set[str],
    flow_refs: set[str],
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    aliases = arch.get("assets") or {}
    known_aliases = set(aliases)

    for alias, asset_ref in aliases.items():
        if asset_ref not in asset_refs:
            errors.append(f"{_rel(source)}:assets.{alias} references unknown asset {asset_ref}")

    parent_zones: dict[str, str] = {}

    status_risk = arch.get("status_risk")
    if not isinstance(status_risk, dict):
        errors.append(f"{_rel(source)}:status_risk: expected a mapping of risk levels")
    else:
        for status, risk_level in status_risk.items():
            if risk_level not in RISK_LEVELS:
                errors.append(
                    f"{_rel(source)}:status_risk.{status} unsupported risk level {risk_level!r}"
                )

    for zone_ref, override in (arch.get("zone_overrides") or {}).items():
        if zone_ref not in zone_refs:
            errors.append(f"{_rel(source)}:zone_overrides.{zone_ref} references unknown zone")
        parent = (override or {}).get("parentZone")
        if parent and parent not in zone_refs:
            errors.append(f"{_rel(source)}:zone_overrides.{zone_ref}.parentZone references unknown zone {parent}")
        if parent == zone_ref:
            errors.append(f"{_rel(source)}:zone_overrides.{zone_ref}.parentZone cannot reference itself")
        elif parent and parent in zone_refs and zone_ref in zone_refs:
            parent_zones[zone_ref] = parent

    checked_zones: set[str] = set()
    for zone_ref in sorted(parent_zones):
        if zone_ref in checked_zones:
            continue
        ancestry: list[str] = []
        current = zone_ref
        while current in parent_zones:
            if current in ancestry:
                cycle = ancestry[ancestry.index(current) :] + [current]
                errors.append(
                    f"{_rel(source)}:zone_overrides: parentZone cycle detected: "
                    f"{' -> '.join(cycle)}"
                )
                break
            ancestry.append(current)
            current = parent_zones[current]
            checked_zones.update(ancestry)

    for asset_ref, override in (arch.get("asset_overrides") or {}).items():
        if asset_ref not in asset_refs:
            errors.append(f"{_rel(source)}:asset_overrides.{asset_ref} references unknown asset")
        zone_ref = (override or {}).get("zone")
        if zone_ref and zone_ref not in zone_refs:
            errors.append(f"{_rel(source)}:asset_overrides.{asset_ref}.zone references unknown zone {zone_ref}")

    flow_aliases: dict[str, str] = {}
    if dfd is not None:
        flow_aliases, flow_alias_errors = build_flow_alias_map(arch, first_blueprint(dfd))
        errors.extend(f"{_rel(source)}:{error}" for error in flow_alias_errors)

    allowed_auth, warning_auth = load_auth_catalog(arch=arch)
    known_auth = allowed_auth | set(warning_auth)
    resolved_flow_overrides: set[str] = set()
    for flow_ref, override in (arch.get("flow_overrides") or {}).items():
        resolved_flow_ref = resolve_flow_ref(flow_ref, flow_refs, flow_aliases)
        if not resolved_flow_ref:
            errors.append(f"{_rel(source)}:flow_overrides.{flow_ref} references unknown flow")
        elif resolved_flow_ref in resolved_flow_overrides:
            errors.append(
                f"{_rel(source)}:flow_overrides.{flow_ref} resolves to duplicate "
                f"flow override {resolved_flow_ref}"
            )
        else:
            resolved_flow_overrides.add(resolved_flow_ref)
        auth = (override or {}).get("authMechanism")
        if auth and auth not in known_auth:
            errors.append(f"{_rel(source)}:flow_overrides.{flow_ref}.authMechanism unsupported value {auth}")
        elif auth in warning_auth:
            warnings.append(f"{_rel(source)}:flow_overrides.{flow_ref}.authMechanism {auth}: {warning_auth[auth]}")

    for control_id, refs in (arch.get("flow_bindings") or {}).items():
        if not isinstance(refs, list):
            errors.append(f"{_rel(source)}:flow_bindings.{control_id}: expected a list of flow refs")
            continue
        resolved_refs: set[str] = set()
        unknown: list[str] = []
        for value in refs:
            resolved_flow_ref = resolve_flow_ref(value, flow_refs, flow_aliases)
            if not resolved_flow_ref:
                unknown.append(value)
            elif resolved_flow_ref in resolved_refs:
                errors.append(
                    f"{_rel(source)}:flow_bindings.{control_id} contains duplicate "
                    f"resolved flow {resolved_flow_ref}"
                )
            else:
                resolved_refs.add(resolved_flow_ref)
        unknown.sort()
        if unknown:
            errors.append(f"{_rel(source)}:flow_bindings.{control_id} references unknown flows {unknown}")

    for group, group_aliases in (arch.get("asset_groups") or {}).items():
        _check_aliases(errors, source, f"asset_groups.{group}", group_aliases, known_aliases)
    for family, family_aliases in (arch.get("family_asset_map") or {}).items():
        _check_aliases(errors, source, f"family_asset_map.{family}", family_aliases, known_aliases)
    _check_aliases(errors, source, "default_assets", arch.get("default_assets"), known_aliases)

    return errors, warnings


def validate_sources(paths: SystemPaths) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    workload_source = paths.root / "workload.yaml"
    if workload_source.is_file():
        try:
            load_provider_workload(paths.slug)
            document = build_provider_workload(paths.slug)
        except ProviderWorkloadError as exc:
            return [str(exc)], warnings
        errors.extend(_schema_errors(document, "model-dfd.schema.json", workload_source))
        forbidden = _load_forbidden(paths.redaction)
        for source in (paths.manifest, workload_source):
            text = source.read_text(encoding="utf-8")
            for pattern, label in forbidden:
                match = pattern.search(text)
                if match:
                    errors.append(f"{_rel(source)}: unredacted {label} found before generation: {match.group(0)!r}")
        errors.extend(validate_example_system_options())
        return errors, warnings
    if not paths.model_dfd:
        errors.append(f"{paths.slug}: missing model/base-dfd.cdx.json")
    if not paths.model_architecture:
        errors.append(f"{paths.slug}: missing model/architecture.yaml")
    if errors:
        return errors, warnings

    dfd = _load_json(paths.model_dfd)
    arch = _load_yaml(paths.model_architecture)
    errors.extend(_schema_errors(dfd, "model-dfd.schema.json", paths.model_dfd))
    errors.extend(_schema_errors(arch, "architecture.schema.json", paths.model_architecture))
    if paths.responses:
        responses = _load_yaml(paths.responses)
        errors.extend(_schema_errors(responses, "system-responses.schema.json", paths.responses))
    docx_source = paths.root / "docx.yaml"
    if docx_source.is_file():
        errors.extend(_schema_errors(_load_yaml(docx_source), "system-docx.schema.json", docx_source))

    asset_refs, zone_refs, flow_refs, dfd_errors = validate_dfd(dfd, source=paths.model_dfd)
    errors.extend(dfd_errors)
    arch_errors, arch_warnings = validate_architecture(
        arch,
        source=paths.model_architecture,
        dfd=dfd,
        asset_refs=asset_refs,
        zone_refs=zone_refs,
        flow_refs=flow_refs,
    )
    errors.extend(arch_errors)
    warnings.extend(arch_warnings)

    try:
        overlays = discover_hosting_overlays(paths)
    except HostingOverlayError as exc:
        errors.append(f"{paths.slug}: {exc}")
        overlays = ()
    for overlay_paths in overlays:
        try:
            overlay = load_hosting_overlay(paths, overlay_paths.name)
            composed_sources = compose_hosting_overlay(dfd, overlay, arch)
            composed = composed_sources.dfd
            composed_arch = composed_sources.architecture or arch
        except HostingOverlayError as exc:
            errors.append(f"{paths.slug}/{overlay_paths.name}: {exc}")
            continue
        errors.extend(_schema_errors(composed, "model-dfd.schema.json", overlay.source))
        overlay_assets, overlay_zones, overlay_flows, overlay_dfd_errors = validate_dfd(composed, source=overlay.source)
        errors.extend(overlay_dfd_errors)
        overlay_arch_errors, overlay_arch_warnings = validate_architecture(
            composed_arch,
            source=paths.model_architecture,
            dfd=composed,
            asset_refs=overlay_assets,
            zone_refs=overlay_zones,
            flow_refs=overlay_flows,
        )
        errors.extend(f"{paths.slug}/{overlay_paths.name}: {error}" for error in overlay_arch_errors)
        warnings.extend(f"{paths.slug}/{overlay_paths.name}: {warning}" for warning in overlay_arch_warnings)

    forbidden = _load_forbidden(paths.redaction)
    overlay_sources = tuple(item.overlay for item in overlays)
    for source in (paths.model_dfd, paths.model_architecture, *overlay_sources):
        text = source.read_text(encoding="utf-8")
        for pattern, label in forbidden:
            match = pattern.search(text)
            if match:
                errors.append(f"{_rel(source)}: unredacted {label} found before generation: {match.group(0)!r}")

    return errors, warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", default=DEFAULT_SYSTEM)
    args = parser.parse_args(argv)

    errors, warnings = validate_sources(load_system(args.system))
    for warning in warnings:
        print(f"WARN: {warning}", file=sys.stderr)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"OK - source DFD and architecture bindings valid for {args.system}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
