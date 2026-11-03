#!/usr/bin/env python3
"""Add a deterministic Precogly DFD visualization to a CycloneDX threat model.

Precogly can import a DFD canvas when a blueprint contains a visualization of
``type: precogly-dfd``. Source-driven CDX files generally contain only the
logical graph (zones, assets, flows) and no editor coordinates. This tool turns
that graph into Precogly's React Flow ``canvas_data`` shape before upload.

The visualization intentionally carries source bom-refs, names, and flow
metadata rather than database IDs. Precogly's existing ``_import_dfd`` adapter
remaps nodes and edges to the rows created during the same import.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vault_core

if not vault_core.available("canvas_forms"):
    raise ImportError(
        "vendor/oscal-vault-core is missing or predates canvas_forms; "
        "run: git submodule update --init vendor/oscal-vault-core"
    )

_canvas_forms = vault_core.load("canvas_forms")
MEDIA_TYPE = _canvas_forms.MEDIA_TYPE
canvas_visualization = _canvas_forms.canvas_visualization
normalize_legacy_visualizations = _canvas_forms.normalize_legacy_visualizations
to_legacy_visualizations = _canvas_forms.to_legacy_visualizations

NODE_TYPE_BY_ASSET_TYPE = {
    "actor": "humanActor",
    "system": "systemActor",
    "component": "process",
    "process": "process",
    "data-store": "datastore",
    "datastore": "datastore",
}

NODE_SIZES = {
    "process": {"width": 150, "height": 70},
    "datastore": {"width": 170, "height": 70},
    "humanActor": {"width": 100, "height": 100},
    "systemActor": {"width": 100, "height": 90},
    "trustZone": {"width": 500, "height": 350},
    "systemScope": {"width": 700, "height": 500},
}

CONTAINER_PADDING = 40
CHILD_GAP = 30
ZONE_GAP = 60
LABEL_OFFSET = 30
ACTOR_X = -200


def _ref(item: dict[str, Any]) -> str:
    return str(item.get("bom-ref") or item.get("bomRef") or "")


def _layout_children(children: list[dict[str, Any]]) -> tuple[int, int]:
    if not children:
        return 0, 0
    columns = (
        len(children)
        if len(children) <= 3
        else 3
        if len(children) <= 8
        else math.ceil(math.sqrt(len(children)))
    )
    cursor_x = CONTAINER_PADDING
    cursor_y = CONTAINER_PADDING + LABEL_OFFSET
    row_height = 0
    right_edge = 0
    for index, child in enumerate(children):
        if index and index % columns == 0:
            cursor_x = CONTAINER_PADDING
            cursor_y += row_height + CHILD_GAP
            row_height = 0
        size = child["style"]
        child["position"] = {"x": cursor_x, "y": cursor_y}
        right_edge = max(right_edge, cursor_x + size["width"])
        cursor_x += size["width"] + CHILD_GAP
        row_height = max(row_height, size["height"])
    return right_edge + CONTAINER_PADDING, cursor_y + row_height + CONTAINER_PADDING


def _flow_properties(flow: dict[str, Any]) -> dict[str, str]:
    return {
        str(prop.get("name")): str(prop.get("value"))
        for prop in flow.get("properties", []) or []
        if isinstance(prop, dict) and prop.get("name") and prop.get("value") is not None
    }


def _property_value(item: dict[str, Any], name: str, default: str = "") -> str:
    return _flow_properties(item).get(name, default)


def build_canvas(blueprint: dict[str, Any]) -> dict[str, Any]:
    zones = [
        item for item in blueprint.get("zones", []) or [] if isinstance(item, dict)
    ]
    assets = [
        item for item in blueprint.get("assets", []) or [] if isinstance(item, dict)
    ]
    flows = [
        item for item in blueprint.get("flows", []) or [] if isinstance(item, dict)
    ]

    scope_id = f"scope-{_ref(blueprint) or 'system'}"
    scope_size = dict(NODE_SIZES["systemScope"])
    nodes: list[dict[str, Any]] = [
        {
            "id": scope_id,
            "type": "systemScope",
            "data": {
                "label": blueprint.get("name") or "System",
                "source_ref": _ref(blueprint),
            },
            "position": {"x": 260, "y": 20},
            "style": scope_size,
            "measured": dict(scope_size),
        }
    ]

    zone_node_by_ref: dict[str, dict[str, Any]] = {}
    for zone in zones:
        zone_ref = _ref(zone)
        node_id = f"zone-{zone_ref}"
        size = dict(NODE_SIZES["trustZone"])
        node = {
            "id": node_id,
            "type": "trustZone",
            "data": {
                "label": zone.get("name") or zone_ref,
                "source_ref": zone_ref,
                "zone_type": (
                    "zoneInternal"
                    if int(
                        zone.get("trustLevel")
                        or _property_value(zone, "precogly:trust-level", "50")
                    )
                    >= 50
                    else "zoneInternet"
                ),
            },
            "position": {"x": 0, "y": 0},
            "style": size,
            "measured": dict(size),
            "parentId": scope_id,
        }
        zone_node_by_ref[zone_ref] = node
        nodes.append(node)

    node_id_by_asset: dict[str, str] = {}
    zone_children: dict[str, list[dict[str, Any]]] = {}
    actors: list[dict[str, Any]] = []
    for asset in assets:
        asset_ref = _ref(asset)
        node_type = NODE_TYPE_BY_ASSET_TYPE.get(str(asset.get("type", "")), "process")
        node_id = f"asset-{asset_ref}"
        node_id_by_asset[asset_ref] = node_id
        size = dict(NODE_SIZES[node_type])
        node = {
            "id": node_id,
            "type": node_type,
            "data": {
                "label": asset.get("name") or asset_ref,
                "description": asset.get("description") or "",
                "source_ref": asset_ref,
            },
            "position": {"x": 0, "y": 0},
            "style": size,
            "measured": dict(size),
        }
        zone_ref = str(asset.get("zone") or "")
        parent = zone_node_by_ref.get(zone_ref)
        if node_type in {"humanActor", "systemActor"} and not parent:
            actors.append(node)
        else:
            if parent:
                node["parentId"] = parent["id"]
                zone_children.setdefault(zone_ref, []).append(node)
            else:
                node["parentId"] = scope_id
            nodes.append(node)

    # Size each trust zone around its member components.
    zone_order = list(zone_node_by_ref)
    zone_sizes: list[tuple[int, int]] = []
    for zone_ref in zone_order:
        children = zone_children.get(zone_ref, [])
        width, height = _layout_children(children)
        node = zone_node_by_ref[zone_ref]
        width = max(width, NODE_SIZES["trustZone"]["width"])
        height = max(height, NODE_SIZES["trustZone"]["height"])
        node["style"] = {"width": width, "height": height}
        node["measured"] = {"width": width, "height": height}
        zone_sizes.append((width, height))

    # Place trust zones inside the system scope in a stable three-column grid.
    cursor_x = CONTAINER_PADDING
    cursor_y = CONTAINER_PADDING + LABEL_OFFSET
    row_height = 0
    for index, (zone_ref, (width, height)) in enumerate(
        zip(zone_order, zone_sizes, strict=True)
    ):
        if index and index % 3 == 0:
            cursor_x = CONTAINER_PADDING
            cursor_y += row_height + ZONE_GAP
            row_height = 0
        zone_node_by_ref[zone_ref]["position"] = {"x": cursor_x, "y": cursor_y}
        cursor_x += width + ZONE_GAP
        row_height = max(row_height, height)
    scope_width = max(cursor_x + CONTAINER_PADDING, NODE_SIZES["systemScope"]["width"])
    scope_height = max(
        cursor_y + row_height + CONTAINER_PADDING,
        NODE_SIZES["systemScope"]["height"],
    )
    nodes[0]["style"] = {"width": scope_width, "height": scope_height}
    nodes[0]["measured"] = {"width": scope_width, "height": scope_height}

    # Actors are external to the modeled system scope, matching Precogly's own
    # deterministic post-layout convention.
    actor_y = 20
    for actor in actors:
        actor["position"] = {"x": ACTOR_X, "y": actor_y}
        actor_y += actor["style"]["height"] + CHILD_GAP
        nodes.append(actor)

    edges: list[dict[str, Any]] = []
    for flow in flows:
        source_ref = str(flow.get("source") or "")
        destination_ref = str(flow.get("destination") or "")
        source = node_id_by_asset.get(source_ref)
        target = node_id_by_asset.get(destination_ref)
        if not source or not target:
            continue
        props = _flow_properties(flow)
        protocols = flow.get("protocols") or []
        edges.append(
            {
                "id": f"flow-{_ref(flow)}",
                "type": "dataFlow",
                "source": source,
                "target": target,
                "data": {
                    "label": flow.get("name") or "",
                    "protocol": ", ".join(str(value) for value in protocols),
                    "encrypted": bool(flow.get("encrypted", False)),
                    "authenticated": bool(
                        flow.get("authMechanism") or props.get("owasp:auth_mechanism")
                    ),
                    "source_ref": _ref(flow),
                },
            }
        )

    return {"nodes": nodes, "edges": edges, "notation_style": "owasp-sdt"}


def add_visualization(document: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = copy.deepcopy(document)
    added = 0
    for blueprint in result.get("blueprints", []) or []:
        if not isinstance(blueprint, dict):
            continue
        visualization = canvas_visualization(
            build_canvas(blueprint),
            name=f"{blueprint.get('name') or 'System'} Data Flow Diagram",
            ref=_ref(blueprint) or str(added + 1),
        )
        current = [
            item
            for item in blueprint.get("visualizations", []) or []
            if not (
                isinstance(item, dict)
                and (item.get("attachment") or {}).get("mediaType")
                == "application/vnd.precogly.dfd+json"
            )
        ]
        current.append(visualization)
        blueprint["visualizations"] = current
        added += 1
    return result, added


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    source = json.loads(args.source.read_text(encoding="utf-8"))
    result, added = add_visualization(source)
    output = args.out or args.source
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output} with {added} Precogly DFD visualization(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
