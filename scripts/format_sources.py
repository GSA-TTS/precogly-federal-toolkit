#!/usr/bin/env python3
# ruff: noqa: E402, I001
"""Canonicalize source DFD JSON before generation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from systems.loader import DEFAULT_SYSTEM, load_system


DFD_KEY_ORDER = {
    "specFormat": 0,
    "specVersion": 1,
    "serialNumber": 2,
    "version": 3,
    "metadata": 4,
    "blueprints": 5,
    "threats": 6,
    "controls": 7,
}
BLUEPRINT_KEY_ORDER = {
    "bom-ref": 0,
    "name": 1,
    "modelTypes": 2,
    "properties": 3,
    "zones": 4,
    "assets": 5,
    "flows": 6,
    "visualizations": 7,
}
ZONE_KEY_ORDER = {
    "bom-ref": 0,
    "name": 1,
    "type": 2,
    "trustLevel": 3,
    "parentZone": 4,
    "properties": 5,
}
ASSET_KEY_ORDER = {
    "bom-ref": 0,
    "name": 1,
    "type": 2,
    "zone": 3,
    "properties": 4,
}
FLOW_KEY_ORDER = {
    "bom-ref": 0,
    "name": 1,
    "source": 2,
    "destination": 3,
    "protocols": 4,
    "authMechanism": 5,
    "encrypted": 6,
    "crosses_trust_zone": 7,
    "data_classification": 8,
    "properties": 9,
}
PROPERTY_KEY_ORDER = {"name": 0, "value": 1}


def _ordered_items(
    payload: dict[str, Any], key_order: dict[str, int]
) -> list[tuple[str, Any]]:
    return sorted(
        payload.items(), key=lambda item: (key_order.get(item[0], 1000), item[0])
    )


def _canonical_properties(properties: Any) -> Any:
    if not isinstance(properties, list):
        return properties
    canonical = [_canonical_object(prop, PROPERTY_KEY_ORDER) for prop in properties]
    if all(isinstance(prop, dict) and "name" in prop for prop in canonical):
        return sorted(
            canonical,
            key=lambda prop: (
                str(prop.get("name", "")),
                str(prop.get("value", "")),
            ),
        )
    return canonical


def _canonical_object(payload: Any, key_order: dict[str, int] | None = None) -> Any:
    if isinstance(payload, list):
        return [_canonical_object(item) for item in payload]
    if not isinstance(payload, dict):
        return payload

    ordered: dict[str, Any] = {}
    for key, value in _ordered_items(payload, key_order or {}):
        if key == "properties":
            ordered[key] = _canonical_properties(value)
        else:
            ordered[key] = _canonical_object(value)
    return ordered


def canonicalize_dfd(dfd: dict[str, Any]) -> dict[str, Any]:
    canonical = _canonical_object(dfd, DFD_KEY_ORDER)
    for blueprint in canonical.get("blueprints", []):
        if not isinstance(blueprint, dict):
            continue
        reordered = _canonical_object(blueprint, BLUEPRINT_KEY_ORDER)
        blueprint.clear()
        blueprint.update(reordered)
        for zone in blueprint.get("zones", []):
            if isinstance(zone, dict):
                reordered_zone = _canonical_object(zone, ZONE_KEY_ORDER)
                zone.clear()
                zone.update(reordered_zone)
        for asset in blueprint.get("assets", []):
            if isinstance(asset, dict):
                reordered_asset = _canonical_object(asset, ASSET_KEY_ORDER)
                asset.clear()
                asset.update(reordered_asset)
        for flow in blueprint.get("flows", []):
            if isinstance(flow, dict):
                reordered_flow = _canonical_object(flow, FLOW_KEY_ORDER)
                flow.clear()
                flow.update(reordered_flow)
    return canonical


def format_json(payload: dict[str, Any]) -> str:
    return json.dumps(canonicalize_dfd(payload), indent=2, ensure_ascii=False) + "\n"


def format_dfd(path: Path, *, check: bool = False) -> bool:
    with path.open(encoding="utf-8") as source:
        payload = json.load(source)
    formatted = format_json(payload)
    current = path.read_text(encoding="utf-8")
    if formatted == current:
        return False
    if check:
        return True
    path.write_text(formatted, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", default=DEFAULT_SYSTEM)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    paths = load_system(args.system)
    if not paths.model_dfd:
        print(f"FAIL: {args.system}: missing model/base-dfd.cdx.json", file=sys.stderr)
        return 1

    changed = format_dfd(paths.model_dfd, check=args.check)
    if args.check and changed:
        print(
            f"FAIL: {paths.model_dfd.relative_to(ROOT)} is not canonically formatted",
            file=sys.stderr,
        )
        return 1
    if changed:
        print(f"Formatted {paths.model_dfd.relative_to(ROOT)}")
    else:
        print(f"OK - {paths.model_dfd.relative_to(ROOT)} already canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
