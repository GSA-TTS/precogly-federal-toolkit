"""Resolve architecture flow aliases against editor-owned DFD flows."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def first_blueprint(cdx: dict[str, Any]) -> dict[str, Any]:
    blueprints = cdx.get("blueprints") or []
    return blueprints[0] if blueprints else {}


def flow_ref_set(blueprint: dict[str, Any]) -> set[str]:
    return {
        flow["bom-ref"]
        for flow in blueprint.get("flows", []) or []
        if flow.get("bom-ref")
    }


def build_flow_alias_map(
    arch: dict[str, Any], blueprint: dict[str, Any]
) -> tuple[dict[str, str], list[str]]:
    declared = arch.get("flows") or {}
    if not isinstance(declared, dict):
        return {}, ["flows: expected an object mapping aliases to flow selectors"]

    asset_aliases = arch.get("assets") or {}
    flows = [flow for flow in blueprint.get("flows", []) or [] if flow.get("bom-ref")]
    by_ref = {flow["bom-ref"]: flow for flow in flows}
    by_endpoints: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        by_endpoints[(flow.get("source"), flow.get("destination"))].append(flow)

    aliases: dict[str, str] = {}
    errors: list[str] = []
    for alias, selector in declared.items():
        if isinstance(selector, str):
            if selector not in by_ref:
                errors.append(f"flows.{alias} references unknown flow {selector}")
                continue
            aliases[alias] = selector
            continue
        if not isinstance(selector, dict):
            errors.append(f"flows.{alias}: expected a string ref or selector object")
            continue

        explicit_ref = selector.get("ref")
        if explicit_ref:
            if explicit_ref not in by_ref:
                errors.append(
                    f"flows.{alias}.ref references unknown flow {explicit_ref}"
                )
                continue
            aliases[alias] = explicit_ref
            continue

        source_alias = selector.get("source_asset")
        destination_alias = selector.get("destination_asset")
        if source_alias not in asset_aliases:
            errors.append(
                f"flows.{alias}.source_asset references unknown asset alias {source_alias}"
            )
            continue
        if destination_alias not in asset_aliases:
            errors.append(
                f"flows.{alias}.destination_asset references unknown asset alias {destination_alias}"
            )
            continue

        candidates = list(
            by_endpoints[
                (asset_aliases[source_alias], asset_aliases[destination_alias])
            ]
        )
        if "name" in selector:
            name = selector.get("name")
            candidates = [
                flow for flow in candidates if (flow.get("name") or "") == name
            ]
        if not candidates:
            errors.append(f"flows.{alias} selector matches no DFD flow")
            continue
        if len(candidates) > 1:
            errors.append(
                f"flows.{alias} selector matches multiple DFD flows; add name or ref"
            )
            continue
        aliases[alias] = candidates[0]["bom-ref"]

    return aliases, errors


def resolve_flow_ref(
    value: str, flow_refs: set[str], aliases: dict[str, str]
) -> str | None:
    if value in flow_refs:
        return value
    return aliases.get(value)


def resolve_flow_overrides(
    arch: dict[str, Any], blueprint: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    flow_refs = flow_ref_set(blueprint)
    aliases, errors = build_flow_alias_map(arch, blueprint)
    resolved: dict[str, Any] = {}
    for value, override in (arch.get("flow_overrides") or {}).items():
        flow_ref = resolve_flow_ref(value, flow_refs, aliases)
        if not flow_ref:
            errors.append(f"flow_overrides.{value} references unknown flow")
            continue
        if flow_ref in resolved:
            errors.append(
                f"flow_overrides.{value} resolves to duplicate flow override {flow_ref}"
            )
            continue
        resolved[flow_ref] = override
    return resolved, errors


def resolve_flow_bindings(
    flow_bindings: dict[str, Any], arch: dict[str, Any], blueprint: dict[str, Any]
) -> tuple[dict[str, list[str]], list[str]]:
    flow_refs = flow_ref_set(blueprint)
    aliases, errors = build_flow_alias_map(arch, blueprint)
    resolved: dict[str, list[str]] = {}
    for control_id, refs in (flow_bindings or {}).items():
        if not isinstance(refs, list):
            errors.append(f"flow_bindings.{control_id}: expected a list of flow refs")
            continue
        control_refs: list[str] = []
        unknown: list[str] = []
        for value in refs:
            flow_ref = resolve_flow_ref(value, flow_refs, aliases)
            if flow_ref:
                control_refs.append(flow_ref)
            else:
                unknown.append(value)
        if unknown:
            errors.append(
                f"flow_bindings.{control_id} references unknown flows {sorted(unknown)}"
            )
            continue
        resolved[control_id] = control_refs
    return resolved, errors
