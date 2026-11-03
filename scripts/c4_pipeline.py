#!/usr/bin/env python3
"""C4 enrichment, multi-view rendering, and DFD/C4 boundary consistency (#511, #512, #515).

Consumes the neutral ``Topology``, ``to_cyclonedx_blueprint``, ``render_context``,
``render_container``, ``parse_c4``, ``validate_generated_c4``, and ``names_match``
primitives from ``vendor/oscal-vault-core``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

import vault_core  # noqa: E402

SCHEMA_CANDIDATES = (
    REPO / "schemas" / "c4-enrichment.schema.json",
    REPO / "schemas" / "c4-enrichment.schema.json",
)
VALID_STATUS = frozenset({"verified", "assumed", "conflict"})


def _core():
    if not (
        vault_core.available("topology")
        and vault_core.available("topology_c4")
        and vault_core.available("topology_cyclonedx")
        and vault_core.available("topology_eval")
    ):
        raise ImportError(
            "vendor/oscal-vault-core is missing or predates topology modules"
        )
    return (
        vault_core.load("topology"),
        vault_core.load("topology_c4"),
        vault_core.load("topology_cyclonedx"),
        vault_core.load("topology_eval"),
    )


def validate_enrichment(data: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    """Validate an enrichment dictionary and return ``(errors, conflicts)``.

    Fails when any component, relationship, or deployment node lacks a non-empty
    source reference or valid status, and surfaces ``status: conflict`` items
    explicitly rather than hiding them in edge labels (#511).
    """
    errors: list[str] = []
    conflicts: list[dict[str, str]] = []

    if not isinstance(data, dict):
        return ["enrichment payload must be a YAML/JSON mapping"], []
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if not str(data.get("system") or "").strip():
        errors.append("system slug is required")

    schema_path = next((p for p in SCHEMA_CANDIDATES if p.is_file()), None)
    if schema_path is not None:
        try:
            import jsonschema

            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            for err in jsonschema.Draft202012Validator(schema).iter_errors(data):
                loc = ".".join(str(p) for p in err.absolute_path) or "<root>"
                errors.append(f"schema error at {loc}: {err.message}")
        except ImportError:
            pass

    for idx, comp in enumerate(data.get("components") or []):
        if not isinstance(comp, dict):
            errors.append(f"components[{idx}]: must be an object")
            continue
        name = str(comp.get("name") or "").strip()
        if not name:
            errors.append(f"components[{idx}]: missing name")
        status = str(comp.get("status") or "").strip()
        if status not in VALID_STATUS:
            errors.append(f"components[{idx}] ({name or '?'}): invalid status {status!r}")
        source = str(comp.get("source") or "").strip()
        if not source:
            errors.append(f"components[{idx}] ({name or '?'}): missing required source")
        if status == "conflict":
            conflicts.append(
                {
                    "kind": "component",
                    "item": name,
                    "source": source,
                    "note": str(comp.get("note") or ""),
                }
            )

    for idx, rel in enumerate(data.get("relationships") or []):
        if not isinstance(rel, dict):
            errors.append(f"relationships[{idx}]: must be an object")
            continue
        src = str(rel.get("source") or "").strip()
        dst = str(rel.get("destination") or "").strip()
        label = str(rel.get("label") or "").strip()
        ident = f"{src} -> {dst}"
        if not src or not dst or not label:
            errors.append(f"relationships[{idx}] ({ident}): source, destination, and label are required")
        status = str(rel.get("status") or "").strip()
        if status not in VALID_STATUS:
            errors.append(f"relationships[{idx}] ({ident}): invalid status {status!r}")
        source_ref = str(rel.get("source_ref") or "").strip()
        if not source_ref:
            errors.append(f"relationships[{idx}] ({ident}): missing required source_ref")
        if status == "conflict":
            conflicts.append(
                {
                    "kind": "relationship",
                    "item": f"{src} -> {dst} ({label})",
                    "source": source_ref,
                    "note": str(rel.get("note") or ""),
                }
            )

    deployment = data.get("deployment")
    if isinstance(deployment, dict):
        for idx, node in enumerate(deployment.get("nodes") or []):
            if not isinstance(node, dict):
                continue
            label = str(node.get("label") or node.get("alias") or f"node-{idx}")
            status = str(node.get("status") or "").strip()
            source = str(node.get("source") or "").strip()
            if status not in VALID_STATUS:
                errors.append(f"deployment.nodes[{idx}] ({label}): invalid status {status!r}")
            if not source:
                errors.append(f"deployment.nodes[{idx}] ({label}): missing required source")
            if status == "conflict":
                conflicts.append(
                    {
                        "kind": "deployment",
                        "item": label,
                        "source": source,
                        "note": str(node.get("note") or ""),
                    }
                )

    return errors, conflicts


def merge_enrichment(topo: Any, enrichment: dict[str, Any]) -> Any:
    """Return a new ``Topology`` combining PPS-derived and enrichment items (#511).

    Unknown technologies stay blank (never guessed). One merged ``Topology`` feeds
    both CycloneDX and C4 rendering.
    """
    topology_mod, _, _, _ = _core()
    by_key = {c.key: c for c in topo.components}

    for item in enrichment.get("components") or []:
        name = str(item["name"]).strip()
        key = str(item.get("key") or topology_mod.slug(name))
        kind = str(item.get("kind") or topology_mod.classify(name))
        zone = str(item.get("boundary") or topology_mod.zone_for(name, kind))
        stype = (
            str(item.get("store_type") or topology_mod.store_type(name))
            if kind == topology_mod.DATASTORE
            else None
        )
        by_key[key] = topology_mod.Component(
            key=key,
            name=name,
            kind=kind,
            zone=zone,
            store_type=stype,
        )

    flows = list(topo.flows)
    seen_refs = {f.ref for f in flows}
    existing_pairs = {(f.source, f.destination, f.label.lower()) for f in flows}
    by_name = {c.name.lower(): c.key for c in by_key.values()}

    for rel in enrichment.get("relationships") or []:
        src_name = str(rel["source"]).strip()
        dst_name = str(rel["destination"]).strip()
        src_key = (
            src_name
            if src_name in by_key
            else by_name.get(src_name.lower(), topology_mod.slug(src_name))
        )
        dst_key = (
            dst_name
            if dst_name in by_key
            else by_name.get(dst_name.lower(), topology_mod.slug(dst_name))
        )
        if src_key not in by_key:
            kind = topology_mod.classify(src_name)
            by_key[src_key] = topology_mod.Component(
                src_key,
                src_name,
                kind,
                topology_mod.zone_for(src_name, kind),
                topology_mod.store_type(src_name) if kind == topology_mod.DATASTORE else None,
            )
            by_name[src_name.lower()] = src_key
        if dst_key not in by_key:
            kind = topology_mod.classify(dst_name)
            by_key[dst_key] = topology_mod.Component(
                dst_key,
                dst_name,
                kind,
                topology_mod.zone_for(dst_name, kind),
                topology_mod.store_type(dst_name) if kind == topology_mod.DATASTORE else None,
            )
            by_name[dst_name.lower()] = dst_key

        label = str(rel["label"]).strip()
        if (src_key, dst_key, label.lower()) in existing_pairs:
            continue
        existing_pairs.add((src_key, dst_key, label.lower()))
        port = topology_mod.parse_port(str(rel.get("port") or ""))
        base = f"flow-{topo.system_id}-{src_key}-to-{dst_key}" + (f"-{port}" if port else "")
        ref, n = base, 2
        while ref in seen_refs:
            ref, n = f"{base}-{n}", n + 1
        seen_refs.add(ref)
        crosses = bool(
            rel["boundary_crossing"]
            if "boundary_crossing" in rel
            else by_key[src_key].zone != by_key[dst_key].zone
        )
        flows.append(
            topology_mod.Flow(
                ref=ref,
                source=src_key,
                destination=dst_key,
                label=label,
                purpose=str(rel.get("purpose") or label),
                protocol=str(rel.get("protocol") or ""),
                port=port,
                encrypted=bool(rel.get("encrypted", True)),
                crosses_boundary=crosses,
                sensitivity=str(rel.get("sensitivity") or "Low"),
            )
        )

    merged = topology_mod.Topology(
        system_id=topo.system_id,
        display=topo.display,
        components=[by_key[k] for k in sorted(by_key)],
        flows=flows,
    )
    return merged


def _explicit_tech_map(enrichment: dict[str, Any]) -> dict[str, str]:
    topology_mod, _, _, _ = _core()
    out: dict[str, str] = {}
    for item in enrichment.get("components") or []:
        key = str(item.get("key") or topology_mod.slug(str(item["name"])))
        if "technology" in item:
            out[key] = str(item.get("technology") or "")
    return out


def render_subsystem_container(
    topo: Any,
    sub_id: str,
    title: str,
    member_keys: set[str],
    tech_overrides: dict[str, str],
) -> str:
    """Render one readable C4Container view scoped to ``member_keys`` and its direct neighbors (#512)."""
    topology_mod, c4_mod, _, _ = _core()
    by_key = {c.key: c for c in topo.components}
    sub_flows = [
        f
        for f in topo.flows
        if f.source in member_keys or f.destination in member_keys
    ]
    active_keys = {
        k for f in sub_flows for k in (f.source, f.destination) if k in by_key
    } | (member_keys & set(by_key))
    sub_components = [by_key[k] for k in sorted(active_keys)]

    lines = ["C4Container", f"    title {c4_mod._text(title)}", ""]
    by_zone: dict[str, list[Any]] = {}
    for c in sub_components:
        by_zone.setdefault(c.zone, []).append(c)

    for c in sorted(by_zone.get("users", []), key=lambda x: x.name.lower()):
        lines.append(f'    Person({c4_mod._alias(c.key)}, "{c4_mod._text(c.name)}")')
    for c in sorted(by_zone.get("external", []), key=lambda x: x.name.lower()):
        lines.append(
            f'    System_Ext({c4_mod._alias(c.key)}, "{c4_mod._text(c.name)}", "External system")'
        )
    lines.append("")

    for zone, label in (
        (topology_mod.ZONE_APP, f"{c4_mod._text(title)} boundary"),
        (topology_mod.ZONE_PLATFORM, "cloud.gov / AWS platform services"),
    ):
        members = sorted(by_zone.get(zone, []), key=lambda x: x.name.lower())
        if not members:
            continue
        lines.append(f'    System_Boundary({sub_id}_{zone}_boundary, "{label}") {{')
        for c in members:
            alias = c4_mod._alias(c.key)
            name = c4_mod._text(c.name)
            tech = c4_mod._text(
                tech_overrides.get(c.key, c4_mod._tech_from_name(c.name))
            )
            kind = "ContainerDb" if c.kind == topology_mod.DATASTORE else "Container"
            lines.append(f'        {kind}({alias}, "{name}", "{tech}")')
        lines.append("    }")
        lines.append("")

    seen: set[str] = set()
    for f in sub_flows:
        rel = c4_mod._rel(
            c4_mod._alias(f.source),
            c4_mod._alias(f.destination),
            f.purpose or f.label,
            c4_mod._tech(f),
        )
        if rel not in seen:
            seen.add(rel)
            lines.append(f"    {rel}")
    lines += ["", '    UpdateLayoutConfig($c4ShapeInRow="4", $c4BoundaryInRow="1")']
    return "\n".join(lines) + "\n"


def render_deployment(topo: Any, enrichment: dict[str, Any]) -> str:
    """Render a C4Deployment view for hosting relationships (#512)."""
    topology_mod, c4_mod, _, _ = _core()
    deployment = enrichment.get("deployment") or {}
    title = str(deployment.get("title") or f"{topo.display} - Deployment")
    by_key = {c.key: c for c in topo.components}
    tech_overrides = _explicit_tech_map(enrichment)

    lines = ["C4Deployment", f"    title {c4_mod._text(title)}", ""]
    placed: set[str] = set()
    for node in deployment.get("nodes") or []:
        n_alias = c4_mod._alias(str(node["alias"]))
        n_label = c4_mod._text(str(node["label"]))
        n_tech = c4_mod._text(str(node.get("technology") or ""))
        lines.append(f'    Deployment_Node({n_alias}, "{n_label}", "{n_tech}") {{')
        for raw_key in node.get("containers") or []:
            key = raw_key if raw_key in by_key else topology_mod.slug(str(raw_key))
            comp = by_key.get(key)
            if comp is None:
                continue
            placed.add(key)
            c_alias = c4_mod._alias(comp.key)
            c_name = c4_mod._text(comp.name)
            c_tech = c4_mod._text(
                tech_overrides.get(comp.key, c4_mod._tech_from_name(comp.name))
            )
            kind = "ContainerDb" if comp.kind == topology_mod.DATASTORE else "Container"
            lines.append(f'        {kind}({c_alias}, "{c_name}", "{c_tech}")')
        lines.append("    }")
        lines.append("")

    seen: set[str] = set()
    for f in topo.flows:
        if f.source in placed and f.destination in placed:
            rel = c4_mod._rel(
                c4_mod._alias(f.source),
                c4_mod._alias(f.destination),
                f.purpose or f.label,
                c4_mod._tech(f),
            )
            if rel not in seen:
                seen.add(rel)
                lines.append(f"    {rel}")
    lines += ["", '    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")']
    return "\n".join(lines) + "\n"


def render_system_views(topo: Any, enrichment: dict[str, Any] | None = None) -> dict[str, str]:
    """Render Context, per-subsystem Container views, and Deployment view (#512)."""
    topology_mod, c4_mod, _, _ = _core()
    enrichment = enrichment or {}
    tech_overrides = _explicit_tech_map(enrichment)
    views: dict[str, str] = {"c4-context": c4_mod.render_context(topo)}

    subsystems = enrichment.get("subsystems") or {}
    if subsystems:
        for sub_id, spec in subsystems.items():
            members = {
                k if any(c.key == k for c in topo.components) else topology_mod.slug(k)
                for k in (spec.get("components") or [])
            }
            views[f"c4-container-{sub_id}"] = render_subsystem_container(
                topo,
                sub_id,
                str(spec.get("title") or f"{topo.display} - {sub_id}"),
                members,
                tech_overrides,
            )
    else:
        views["c4-container"] = c4_mod.render_container(topo)

    if enrichment.get("deployment"):
        views["c4-deployment"] = render_deployment(topo, enrichment)

    return views


def check_dfd_c4_boundary_consistency(
    blueprint: dict[str, Any], c4_blocks: list[str]
) -> dict[str, list[str]]:
    """Compare DFD trust-zone crossings against C4 cross-boundary relationships (#515).

    Returns ``{"dfd_crossings_missing_in_c4": [...], "c4_crossings_missing_in_dfd": [...], "unexplained_zones": [...]}``.
    """
    _, _, _, eval_mod = _core()
    by_ref: dict[str, dict[str, Any]] = {}
    for key in ("assets", "dataStores"):
        for item in blueprint.get(key) or []:
            if item.get("bom-ref"):
                by_ref[item["bom-ref"]] = item

    dfd_crossings: list[tuple[str, str]] = []
    for flow in blueprint.get("flows") or []:
        props = {
            p.get("name"): str(p.get("value")).lower()
            for p in flow.get("properties") or []
            if isinstance(p, dict)
        }
        crosses = (
            bool(flow.get("crosses_trust_zone"))
            or props.get("resp:crosses-trust-zone") == "true"
        )
        src_item = by_ref.get(flow.get("source"))
        dst_item = by_ref.get(flow.get("destination"))
        if not src_item or not dst_item:
            continue
        if crosses or src_item.get("zone") != dst_item.get("zone"):
            dfd_crossings.append((src_item.get("name", ""), dst_item.get("name", "")))

    c4_crossings: list[tuple[str, str]] = []
    c4_boundaries: set[str] = set()
    has_external_or_person = False
    for block in c4_blocks:
        diagram = eval_mod.parse_c4(block)
        if diagram.level == "C4Context":
            continue
        c4_boundaries.update(diagram.boundaries)
        for el in diagram.elements.values():
            if el.kind in ("person", "external"):
                has_external_or_person = True
        for rel in diagram.rels:
            src_el = diagram.elements.get(rel.source)
            dst_el = diagram.elements.get(rel.destination)
            if not src_el or not dst_el:
                continue
            src_group = src_el.boundary or f"outside:{src_el.kind}"
            dst_group = dst_el.boundary or f"outside:{dst_el.kind}"
            if src_group != dst_group:
                c4_crossings.append((src_el.label, dst_el.label))

    def pair_matches(a: tuple[str, str], b: tuple[str, str]) -> bool:
        return (
            eval_mod.names_match(a[0], b[0]) and eval_mod.names_match(a[1], b[1])
        ) or (
            eval_mod.names_match(a[0], b[1]) and eval_mod.names_match(a[1], b[0])
        )

    missing_in_c4 = sorted(
        {
            f"{src} -> {dst}"
            for src, dst in dfd_crossings
            if not any(pair_matches((src, dst), c4p) for c4p in c4_crossings)
        }
    )
    missing_in_dfd = sorted(
        {
            f"{src} -> {dst}"
            for src, dst in c4_crossings
            if not any(pair_matches((src, dst), dfdp) for dfdp in dfd_crossings)
        }
    )

    unexplained_zones: list[str] = []
    for zone in blueprint.get("zones") or []:
        zname = str(zone.get("name") or "")
        zlow = zname.lower()
        if any(tok in zlow for tok in ("user", "public", "external", "internet")):
            if not has_external_or_person and not c4_boundaries:
                unexplained_zones.append(zname)
        elif not c4_boundaries:
            unexplained_zones.append(zname)

    return {
        "dfd_crossings_missing_in_c4": missing_in_c4,
        "c4_crossings_missing_in_dfd": missing_in_dfd,
        "unexplained_zones": unexplained_zones,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--enrichment",
        type=Path,
        required=True,
        help="Path to data/systems/<slug>/model/c4-enrichment.yaml",
    )
    parser.add_argument(
        "--vault-system",
        type=Path,
        help="Optional vault system directory holding Relationships/*.md",
    )
    args = parser.parse_args(argv)

    data = yaml.safe_load(args.enrichment.read_text(encoding="utf-8")) or {}
    errors, conflicts = validate_enrichment(data)
    for conflict in conflicts:
        print(
            f"CONFLICT [{conflict['kind']}] {conflict['item']} "
            f"(source: {conflict['source']}): {conflict['note']}"
        )
    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        return 1

    if args.vault_system:
        topology_mod, _, cdx_mod, eval_mod = _core()
        rows = topology_mod.load_pps_rows(args.vault_system)
        topo = topology_mod.build_topology(
            data["system"],
            data["system"],
            rows,
            resolve_via=bool(data.get("resolve_via", False)),
        )
        merged = merge_enrichment(topo, data)
        blueprint = cdx_mod.to_cyclonedx_blueprint(merged)
        views = render_system_views(merged, data)
        for name, block in views.items():
            normalized = block.replace("Deployment_Node(", "Boundary(") if name == "c4-deployment" else block
            rep = eval_mod.validate_generated_c4(normalized)
            orphans = [] if name == "c4-deployment" else rep["orphan_elements"]
            if rep["syntax_errors"] or not rep["has_title"] or orphans:
                print(f"FAIL [{name}]: {rep}", file=sys.stderr)
                return 1
            stats = eval_mod.readability(merged, normalized)
            if stats["elements"] > 20 or stats["longest_label"] > 80 or stats["max_degree"] > 8:
                print(f"FAIL readability [{name}]: {stats}", file=sys.stderr)
                return 1
        container_blocks = [
            b for k, b in views.items() if k.startswith("c4-container")
        ]
        consistency = check_dfd_c4_boundary_consistency(blueprint, container_blocks)
        if any(consistency.values()):
            print(f"FAIL boundary consistency: {consistency}", file=sys.stderr)
            return 1

    print(
        f"OK - {args.enrichment} valid ({len(conflicts)} documented conflict item(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
