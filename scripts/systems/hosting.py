"""Load and compose typed hosting topology overlays for a system DFD."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .loader import ROOT, SystemPaths

SCHEMA_PATH = ROOT / "schemas" / "hosting-overlay.schema.json"
_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_OPERATION_NAMES = (
    "remove_flow_refs",
    "remove_asset_refs",
    "remove_zone_refs",
    "replace_zones",
    "replace_assets",
    "replace_flows",
    "add_zones",
    "add_assets",
    "add_flows",
    "architecture_zone_overrides",
    "architecture_asset_overrides",
    "architecture_flow_overrides",
)


class HostingOverlayError(ValueError):
    """The hosting overlay cannot be safely loaded."""


class HostingCompositionError(HostingOverlayError):
    """The hosting overlay cannot be applied to the source DFD."""


@dataclass(frozen=True)
class HostingOverlayPaths:
    name: str
    root: Path
    overlay: Path


@dataclass(frozen=True)
class HostingOverlay:
    schema_version: int
    name: str
    parent_system: str
    slug: str
    title: str | None
    lifecycle: str
    authorization_state: str
    feasibility: Mapping[str, Any]
    operations: Mapping[str, Any]
    source: Path


@dataclass(frozen=True)
class ComposedHostingSources:
    dfd: dict[str, Any]
    architecture: dict[str, Any] | None
    overlay: HostingOverlay


def _safe_name(name: str) -> None:
    if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name):
        raise HostingOverlayError(f"invalid hosting overlay name: {name!r}")


def _contained_file(root: Path, candidate: Path) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HostingOverlayError(f"missing hosting overlay path: {exc.filename}") from exc
    if not resolved_candidate.is_relative_to(resolved_root):
        raise HostingOverlayError(f"{candidate} resolves outside hosting root {root}")
    if not resolved_candidate.is_file():
        raise HostingOverlayError(f"not a file: {candidate}")
    return resolved_candidate


def discover_hosting_overlays(
    system: SystemPaths,
) -> tuple[HostingOverlayPaths, ...]:
    hosting_root = system.root / "hosting"
    if not hosting_root.is_dir():
        return ()
    resolved_system_root = system.root.resolve(strict=True)
    overlays: list[HostingOverlayPaths] = []
    for entry in sorted(hosting_root.iterdir(), key=lambda path: path.name):
        if entry.name == "shared" or not entry.is_dir():
            continue
        _safe_name(entry.name)
        resolved_entry = entry.resolve(strict=True)
        if not resolved_entry.is_relative_to(resolved_system_root):
            raise HostingOverlayError(f"{entry} resolves outside {system.root}")
        overlay_path = entry / "overlay.yaml"
        if not overlay_path.exists():
            continue
        overlays.append(
            HostingOverlayPaths(
                name=entry.name,
                root=resolved_entry,
                overlay=_contained_file(resolved_entry, overlay_path),
            )
        )
    return tuple(overlays)


def load_hosting_overlay(system: SystemPaths, name: str) -> HostingOverlay:
    _safe_name(name)
    overlay_root = system.root / "hosting" / name
    try:
        resolved_system_root = system.root.resolve(strict=True)
        resolved_overlay_root = overlay_root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HostingOverlayError(f"missing hosting overlay path: {exc.filename}") from exc
    if not resolved_overlay_root.is_relative_to(resolved_system_root):
        raise HostingOverlayError(f"{overlay_root} resolves outside {system.root}")
    source = _contained_file(overlay_root, overlay_root / "overlay.yaml")
    document = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(document, schema)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise HostingOverlayError(f"{source}: schema error at {location}: {exc.message}") from exc
    if document["name"] != name:
        raise HostingOverlayError(f"{source}: overlay name {document['name']!r} does not match directory {name!r}")
    if document["parent_system"] != system.slug:
        raise HostingOverlayError(
            f"{source}: parent_system {document['parent_system']!r} does not match loaded system {system.slug!r}"
        )
    operations = {}
    for operation in _OPERATION_NAMES:
        default = {} if operation.startswith("architecture_") else []
        value = copy.deepcopy(document["operations"].get(operation, default))
        operations[operation] = value if isinstance(value, dict) else tuple(value)
    return HostingOverlay(
        schema_version=document["schema_version"],
        name=document["name"],
        parent_system=document["parent_system"],
        slug=document["slug"],
        title=document.get("title"),
        lifecycle=document["lifecycle"],
        authorization_state=document["authorization_state"],
        feasibility=copy.deepcopy(document["feasibility"]),
        operations=operations,
        source=source,
    )


def _index(items: list[dict[str, Any]], kind: str) -> dict[str, int]:
    index: dict[str, int] = {}
    duplicates: set[str] = set()
    for position, item in enumerate(items):
        ref = item.get("bom-ref")
        if not ref:
            raise HostingCompositionError(f"{kind} at index {position} has no bom-ref")
        if ref in index:
            duplicates.add(ref)
        index[ref] = position
    if duplicates:
        raise HostingCompositionError(f"duplicate {kind} refs: {', '.join(sorted(duplicates))}")
    return index


def _remove(items: list[dict[str, Any]], refs: tuple[Any, ...], kind: str) -> None:
    for ref in refs:
        index = _index(items, kind)
        if ref not in index:
            raise HostingCompositionError(f"cannot remove missing {kind} ref {ref!r}")
        items.pop(index[ref])


def _replace(
    items: list[dict[str, Any]],
    replacements: tuple[Any, ...],
    kind: str,
) -> dict[str, str]:
    ref_changes: dict[str, str] = {}
    for replacement in replacements:
        target = replacement["target_ref"]
        index = _index(items, kind)
        if target not in index:
            raise HostingCompositionError(f"cannot replace missing {kind} ref {target!r}")
        value = copy.deepcopy(replacement["value"])
        new_ref = value["bom-ref"]
        if new_ref != target and new_ref in index:
            raise HostingCompositionError(f"replacement {kind} ref {new_ref!r} already exists")
        items[index[target]] = value
        if new_ref != target:
            ref_changes[target] = new_ref
    return ref_changes


def _add(items: list[dict[str, Any]], additions: tuple[Any, ...], kind: str) -> None:
    existing = _index(items, kind)
    pending: set[str] = set()
    copied = []
    for addition in additions:
        value = copy.deepcopy(addition)
        ref = value["bom-ref"]
        if ref in existing or ref in pending:
            raise HostingCompositionError(f"cannot add duplicate {kind} ref {ref!r}")
        pending.add(ref)
        copied.append(value)
    items.extend(sorted(copied, key=lambda item: item["bom-ref"]))


def _rewrite_refs(
    assets: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    zone_changes: Mapping[str, str],
    asset_changes: Mapping[str, str],
) -> None:
    for asset in assets:
        zone = asset.get("zone")
        if zone in zone_changes:
            asset["zone"] = zone_changes[zone]
    for flow in flows:
        endpoint_changes = {**zone_changes, **asset_changes}
        if flow.get("source") in endpoint_changes:
            flow["source"] = endpoint_changes[flow["source"]]
        if flow.get("destination") in endpoint_changes:
            flow["destination"] = endpoint_changes[flow["destination"]]


def _validate_graph(
    zones: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    flows: list[dict[str, Any]],
) -> None:
    zone_refs = set(_index(zones, "zone"))
    asset_refs = set(_index(assets, "asset"))
    _index(flows, "flow")
    bad_zones = sorted(
        f"{asset['bom-ref']}->{asset['zone']}"
        for asset in assets
        if asset.get("zone") and asset["zone"] not in zone_refs
    )
    if bad_zones:
        raise HostingCompositionError(f"assets reference unknown zones: {', '.join(bad_zones)}")
    endpoints = zone_refs | asset_refs
    dangling = sorted(
        f"{flow['bom-ref']}->{endpoint}"
        for flow in flows
        for endpoint in (flow.get("source"), flow.get("destination"))
        if endpoint not in endpoints
    )
    if dangling:
        raise HostingCompositionError(f"flows reference unknown endpoints: {', '.join(dangling)}")


def compose_hosting_overlay(
    base_dfd: Mapping[str, Any],
    overlay: HostingOverlay,
    base_architecture: Mapping[str, Any] | None = None,
) -> ComposedHostingSources:
    document = copy.deepcopy(dict(base_dfd))
    blueprints = document.get("blueprints") or []
    if len(blueprints) != 1:
        raise HostingCompositionError(f"hosting composition requires exactly one blueprint, found {len(blueprints)}")
    blueprint = blueprints[0]
    zones = blueprint.setdefault("zones", [])
    assets = blueprint.setdefault("assets", [])
    flows = blueprint.setdefault("flows", [])
    operations = overlay.operations

    _validate_graph(zones, assets, flows)
    _remove(flows, operations["remove_flow_refs"], "flow")
    _remove(assets, operations["remove_asset_refs"], "asset")
    _remove(zones, operations["remove_zone_refs"], "zone")
    zone_changes = _replace(zones, operations["replace_zones"], "zone")
    asset_changes = _replace(assets, operations["replace_assets"], "asset")
    _rewrite_refs(assets, flows, zone_changes, asset_changes)
    _replace(flows, operations["replace_flows"], "flow")
    _add(zones, operations["add_zones"], "zone")
    _add(assets, operations["add_assets"], "asset")
    _add(flows, operations["add_flows"], "flow")
    _validate_graph(zones, assets, flows)
    architecture = copy.deepcopy(dict(base_architecture)) if base_architecture else None
    if architecture is not None:
        for operation, target in (
            ("architecture_zone_overrides", "zone_overrides"),
            ("architecture_asset_overrides", "asset_overrides"),
            ("architecture_flow_overrides", "flow_overrides"),
        ):
            architecture.setdefault(target, {}).update(copy.deepcopy(operations[operation]))
    return ComposedHostingSources(dfd=document, architecture=architecture, overlay=overlay)
