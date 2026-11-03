"""Typed, zoned DFD topology from an SSP's Ports/Protocols/Services table.

PPS parsing, component classification, and CycloneDX blueprint topology generation
are owned by the vendored ``oscal-vault-core`` (``compliance/lib/topology.py`` and
``compliance/lib/topology_cyclonedx.py``; see ADR-SSPP-025 and ADR-SSPP-027).
This module re-exports the core classifier and blueprint builder for existing callers
and provides ``build_canvas`` for Precogly React Flow layout.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vault_core
from vault_reader import PpsFlow

if not vault_core.available("topology") or not vault_core.available("topology_cyclonedx"):
    raise ImportError(
        "vendor/oscal-vault-core is missing or predates topology generators; "
        "run: git submodule update --init vendor/oscal-vault-core"
    )

_core_topo = vault_core.load("topology")
_core_cdx = vault_core.load("topology_cyclonedx")

ZONE_USERS = _core_topo.ZONE_USERS
ZONE_EXTERNAL = _core_topo.ZONE_EXTERNAL
ZONE_PLATFORM = _core_topo.ZONE_PLATFORM
ZONE_APP = _core_topo.ZONE_APP

# (suffix, label template, trust level, placement)
ZONES = {
    key: (
        key,
        _core_topo.ZONE_LABELS[key],
        _core_topo.ZONE_TRUST[key],
        "external" if key in (ZONE_USERS, ZONE_EXTERNAL) else "internal",
    )
    for key in _core_topo.ZONE_LABELS
}

slug = _core_topo.slug
classify = _core_topo.classify
parse_port = _core_topo.parse_port


def build_topology(
    system_id: str, display: str, topology: list[PpsFlow]
) -> dict[str, list[dict[str, Any]]]:
    """Return ``zones``, ``assets``, ``dataStores`` and ``flows`` for a blueprint."""
    rows = [
        _core_topo.PpsRow(
            source=row.source,
            destination=row.destination,
            direction=row.direction,
            boundary_crossing=row.boundary_crossing,
            port=row.port,
            protocol=row.protocol,
            service=row.service,
            purpose=row.purpose,
            encrypted=row.encrypted,
            sensitivity=row.data_sensitivity,
        )
        for row in topology
    ]
    return _core_cdx.to_cyclonedx_blueprint(
        _core_topo.build_topology(system_id, display, rows)
    )


NODE_SIZE = {
    "process": (160, 70),
    "datastore": (170, 80),
    "humanActor": (100, 100),
    "systemActor": (130, 80),
}
PAD, GAP, HEAD = 30, 24, 40
COLUMN_ORDER = (ZONE_USERS, ZONE_EXTERNAL, ZONE_APP, ZONE_PLATFORM)


def _node_type(item: dict[str, Any], is_store: bool) -> str:
    if is_store:
        return "datastore"
    return {"actor": "humanActor", "system": "systemActor"}.get(
        item.get("type"), "process"
    )


def build_canvas(display: str, topo: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """React Flow canvas: a system scope holding one trust-zone node per zone, components inside.

    Zones are laid out left to right (users, external, application, platform); components wrap
    in a grid inside their zone. Nodes carry ``bom_ref`` so the importer maps them to the rows
    it creates, and edges carry the flow's protocol, port and encryption.
    """
    members: dict[str, list[tuple[dict[str, Any], bool]]] = {}
    for item in topo["assets"]:
        members.setdefault(item["zone"], []).append((item, False))
    for item in topo["dataStores"]:
        members.setdefault(item["zone"], []).append((item, True))

    def zone_key(zone: dict[str, Any]) -> int:
        suffix = zone["bom-ref"].rsplit("-", 1)[-1]
        names = [ZONES[k][0] for k in COLUMN_ORDER]
        return names.index(suffix) if suffix in names else len(names)

    scope_id = "scope-system"
    nodes: list[dict[str, Any]] = []
    node_id: dict[str, str] = {}
    x = PAD
    tallest = 0
    for zone in sorted(topo["zones"], key=zone_key):
        items = sorted(
            members.get(zone["bom-ref"], []), key=lambda m: m[0]["name"].lower()
        )
        cols = 1 if len(items) <= 3 else 2 if len(items) <= 8 else 3
        children: list[dict[str, Any]] = []
        col_w = [0] * cols
        row_h: list[int] = []
        for i, (item, is_store) in enumerate(items):
            kind = _node_type(item, is_store)
            w, h = NODE_SIZE[kind]
            r, c = divmod(i, cols)
            if r == len(row_h):
                row_h.append(0)
            row_h[r] = max(row_h[r], h)
            col_w[c] = max(col_w[c], w)
            children.append(
                {"item": item, "kind": kind, "r": r, "c": c, "w": w, "h": h}
            )
        width = max(PAD * 2 + sum(col_w) + GAP * (cols - 1), 240)
        height = max(HEAD + PAD + sum(row_h) + GAP * max(len(row_h) - 1, 0), 140)
        zone_node = f"zone-{zone['bom-ref']}"
        props = {p["name"]: p["value"] for p in zone.get("properties", [])}
        nodes.append(
            {
                "id": zone_node,
                "type": "trustZone",
                "parentId": scope_id,
                "position": {"x": x, "y": HEAD},
                "style": {"width": width, "height": height},
                "measured": {"width": width, "height": height},
                "data": {
                    "label": zone["name"],
                    "zoneType": "trust",
                    "trustLevel": int(props.get("precogly:trust-level", 50)),
                    "bom_ref": zone["bom-ref"],
                },
            }
        )
        for ch in children:
            cx = PAD + sum(col_w[: ch["c"]]) + GAP * ch["c"]
            cy = HEAD + sum(row_h[: ch["r"]]) + GAP * ch["r"] + 10
            nid = f"node-{ch['item']['bom-ref']}"
            node_id[ch["item"]["bom-ref"]] = nid
            nodes.append(
                {
                    "id": nid,
                    "type": ch["kind"],
                    "parentId": zone_node,
                    "position": {"x": cx, "y": cy},
                    "style": {"width": ch["w"], "height": ch["h"]},
                    "measured": {"width": ch["w"], "height": ch["h"]},
                    "data": {
                        "label": ch["item"]["name"],
                        "bom_ref": ch["item"]["bom-ref"],
                    },
                }
            )
        x += width + GAP * 2
        tallest = max(tallest, height)
    scope_w, scope_h = x - GAP * 2 + PAD, tallest + HEAD + PAD
    nodes.insert(
        0,
        {
            "id": scope_id,
            "type": "systemScope",
            "position": {"x": 0, "y": 0},
            "style": {"width": scope_w, "height": scope_h},
            "measured": {"width": scope_w, "height": scope_h},
            "data": {"label": display},
        },
    )
    edges = []
    for flow in topo["flows"]:
        props = {p["name"]: p["value"] for p in flow.get("properties", [])}
        data: dict[str, Any] = {
            "label": flow["name"],
            "protocol": ", ".join(flow.get("protocols", [])),
            "encrypted": bool(flow.get("encrypted")),
            "bom_ref": flow["bom-ref"],
        }
        if "precogly:port" in props:
            data["port"] = int(props["precogly:port"])
        edges.append(
            {
                "id": f"edge-{flow['bom-ref']}",
                "type": "dataFlow",
                "source": node_id[flow["source"]],
                "target": node_id[flow["destination"]],
                "data": data,
            }
        )
    return {"nodes": nodes, "edges": edges}
