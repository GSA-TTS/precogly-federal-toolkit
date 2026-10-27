#!/usr/bin/env python3
# isort: skip_file
"""Rehydrate a Precogly editor DFD export into a tracked system base DFD.

The editor can round-trip duplicate zones/assets and inject author metadata.
This script collapses duplicated graph objects, rewrites references through the
remap, scrubs unsafe editor metadata, and writes a reviewer-facing remap report.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
ROOT = SCRIPTS.parent

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from format_sources import canonicalize_dfd  # noqa: E402

from systems.loader import DEFAULT_SYSTEM, load_system  # noqa: E402
from systems.scrub_base_dfd import scrub_dfd  # noqa: E402

DFD_SECTIONS = ("zones", "assets", "flows", "boundaries", "dataStores")
DEFAULT_MERGE_TYPES = ("system", "component")

# Fields the Precogly editor export carries that are NOT part of the tracked
# base-DFD source of truth: top-level `threats`/`controls` are the editor's
# own stale preview of a generated threat model (regenerated fresh by
# scripts/generate.py from the CRM YAML sources on every `make generate`),
# and per-blueprint `visualizations` is React Flow canvas/layout state, not
# model data. Carrying either forward causes `scripts/validate.py` to
# recompute scenarios against dangling/duplicate-numbered asset refs from the
# editor's stale preview (see issue #182) and bloats the tracked DFD with
# canvas coordinates no downstream consumer reads.
TOP_LEVEL_STRIP_KEYS = ("threats", "controls")
BLUEPRINT_STRIP_KEYS = ("visualizations",)


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _norm(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def _ref(item: dict[str, Any]) -> str | None:
    value = item.get("bom-ref")
    return str(value) if value else None


def _record(
    remap: dict[str, dict[str, str]], section: str, old: str | None, new: str | None
) -> None:
    if old and new and old != new:
        remap.setdefault(section, {})[old] = new


def _remap(value: Any, refs: dict[str, str]) -> Any:
    if isinstance(value, str):
        return refs.get(value, value)
    if isinstance(value, list):
        return [_remap(item, refs) for item in value]
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            new_key = refs.get(key, key) if isinstance(key, str) else key
            new_value = _remap(item, refs)
            if new_key in out:
                out[new_key] = _merge(out[new_key], new_value)
            else:
                out[new_key] = new_value
        return out
    return value


def _merge(left: Any, right: Any) -> Any:
    if isinstance(left, dict) and isinstance(right, dict):
        merged = dict(left)
        for key, value in right.items():
            merged[key] = _merge(merged[key], value) if key in merged else value
        return merged
    if isinstance(left, list) and isinstance(right, list):
        merged = list(left)
        for value in right:
            if value not in merged:
                merged.append(value)
        return merged
    return left if left == right else right


def _upsert_property(properties: list[dict[str, Any]], name: str, value: str) -> None:
    for prop in properties:
        if prop.get("name") == name:
            prop["value"] = value
            return
    properties.append({"name": name, "value": value})


def _first_blueprint(dfd: dict[str, Any]) -> dict[str, Any]:
    blueprints = dfd.get("blueprints") or []
    if not blueprints or not isinstance(blueprints[0], dict):
        raise ValueError("DFD export has no first blueprint")
    return blueprints[0]


def _set_dfd3_notation(blueprint: dict[str, Any]) -> bool:
    properties = blueprint.setdefault("properties", [])
    before = copy.deepcopy(properties)
    _upsert_property(properties, "owasp:notationStyle", "dfd3")
    return before != properties


def _dedupe_zones(blueprint: dict[str, Any], remap: dict[str, dict[str, str]]) -> int:
    seen: dict[str, str] = {}
    kept: list[dict[str, Any]] = []
    removed = 0
    for zone in blueprint.get("zones", []) or []:
        if not isinstance(zone, dict):
            kept.append(zone)
            continue
        zone_ref = _ref(zone)
        key = _norm(zone.get("name"))
        if key and zone_ref and key in seen:
            _record(remap, "zones", zone_ref, seen[key])
            removed += 1
            continue
        if key and zone_ref:
            seen[key] = zone_ref
        kept.append(zone)
    zone_refs = remap.get("zones", {})
    for zone in kept:
        if isinstance(zone, dict) and zone.get("parentZone") in zone_refs:
            zone["parentZone"] = zone_refs[zone["parentZone"]]
    blueprint["zones"] = kept
    return removed


def _asset_canonical_refs(
    assets: list[dict[str, Any]], merge_types: set[str]
) -> dict[str, str]:
    ref_by_exact: dict[tuple[str, str], str] = {}
    candidates_by_name: dict[str, list[dict[str, Any]]] = {}
    remap: dict[str, str] = {}

    for asset in assets:
        asset_ref = _ref(asset)
        if not asset_ref:
            continue
        asset_type = str(asset.get("type") or "")
        exact_key = (_norm(asset.get("name")), asset_type)
        if exact_key in ref_by_exact:
            remap[asset_ref] = ref_by_exact[exact_key]
        else:
            ref_by_exact[exact_key] = asset_ref
        candidates_by_name.setdefault(exact_key[0], []).append(asset)

    for same_name in candidates_by_name.values():
        mergeable = [
            asset
            for asset in same_name
            if _ref(asset) and str(asset.get("type") or "") in merge_types
        ]
        if len(mergeable) < 2:
            continue
        canonical = next(
            (asset for asset in mergeable if str(asset.get("type") or "") == "system"),
            mergeable[0],
        )
        canonical_ref = _ref(canonical)
        for asset in mergeable:
            _record_ref = _ref(asset)
            if _record_ref and canonical_ref and _record_ref != canonical_ref:
                remap[_record_ref] = canonical_ref
    return remap


def _dedupe_assets(
    blueprint: dict[str, Any], remap: dict[str, dict[str, str]], merge_types: set[str]
) -> int:
    zone_refs = remap.get("zones", {})
    assets = []
    for asset in blueprint.get("assets", []) or []:
        if isinstance(asset, dict):
            updated_asset = copy.deepcopy(asset)
            if updated_asset.get("zone") in zone_refs:
                updated_asset["zone"] = zone_refs[updated_asset["zone"]]
            assets.append(updated_asset)
        else:
            assets.append(asset)

    asset_remap = _asset_canonical_refs(
        [asset for asset in assets if isinstance(asset, dict)], merge_types
    )
    remap.setdefault("assets", {}).update(asset_remap)
    kept: list[Any] = []
    removed = 0
    for asset in assets:
        asset_ref = _ref(asset) if isinstance(asset, dict) else None
        if (
            asset_ref
            and asset_remap.get(asset_ref) != asset_ref
            and asset_ref in asset_remap
        ):
            removed += 1
            continue
        kept.append(asset)
    blueprint["assets"] = kept
    return removed


def _dedupe_flows(
    blueprint: dict[str, Any],
    remap: dict[str, dict[str, str]],
    conflicts: list[dict[str, Any]],
) -> int:
    refs = remap.get("assets", {})
    seen: dict[tuple[str, str, str], str] = {}
    kept: list[Any] = []
    kept_by_ref: dict[str, dict[str, Any]] = {}
    removed = 0
    for flow in blueprint.get("flows", []) or []:
        if not isinstance(flow, dict):
            kept.append(flow)
            continue
        updated_flow = copy.deepcopy(flow)
        if updated_flow.get("source") in refs:
            updated_flow["source"] = refs[updated_flow["source"]]
        if updated_flow.get("destination") in refs:
            updated_flow["destination"] = refs[updated_flow["destination"]]
        flow_ref = _ref(updated_flow)
        key = (
            _norm(updated_flow.get("name")),
            str(updated_flow.get("source") or ""),
            str(updated_flow.get("destination") or ""),
        )
        if flow_ref and key in seen:
            # A duplicate editor round-trip commonly splits attributes (e.g.
            # `protocols`) unevenly across the two copies of an otherwise
            # identical flow. Merge into the kept flow rather than silently
            # dropping whichever attributes only the discarded copy carried.
            canonical_ref = seen[key]
            canonical = kept_by_ref[canonical_ref]
            for merged_key, merged_value in updated_flow.items():
                if merged_key == "bom-ref":
                    continue
                current_value = canonical.get(merged_key)
                if merged_key not in canonical or current_value in (None, [], ""):
                    canonical[merged_key] = merged_value
                elif (
                    merged_key == "protocols"
                    and isinstance(current_value, list)
                    and isinstance(merged_value, list)
                ):
                    canonical[merged_key] = list(
                        dict.fromkeys([*current_value, *merged_value])
                    )
                elif (
                    merged_value not in (None, [], "") and current_value != merged_value
                ):
                    conflicts.append(
                        {
                            "section": "flows",
                            "canonical_ref": canonical_ref,
                            "duplicate_ref": flow_ref,
                            "field": merged_key,
                            "canonical_value": current_value,
                            "duplicate_value": merged_value,
                        }
                    )
            _record(remap, "flows", flow_ref, canonical_ref)
            removed += 1
            continue
        if flow_ref:
            seen[key] = flow_ref
            kept_by_ref[flow_ref] = updated_flow
        kept.append(updated_flow)
    blueprint["flows"] = kept
    return removed


def _remap_unique(values: Any, refs: dict[str, str]) -> list[Any]:
    out = []
    for value in values or []:
        mapped = refs.get(value, value) if isinstance(value, str) else value
        if mapped not in out:
            out.append(mapped)
    return out


def _dedupe_boundaries(
    blueprint: dict[str, Any], remap: dict[str, dict[str, str]]
) -> int:
    zone_refs = remap.get("zones", {})
    seen: dict[tuple[str, tuple[Any, ...]], str] = {}
    kept: list[Any] = []
    removed = 0
    dropped_incomplete = 0
    for boundary in blueprint.get("boundaries", []) or []:
        if not isinstance(boundary, dict):
            kept.append(boundary)
            continue
        updated_boundary = copy.deepcopy(boundary)
        updated_boundary["zones"] = _remap_unique(
            updated_boundary.get("zones"), zone_refs
        )
        # The editor can export a malformed boundary with a `null` placeholder
        # in its zones list where an unresolved zone reference should have
        # been (observed alongside a complete two-zone AWS VPC/S3 Transfer
        # Family boundary covering the same real zone). Drop entries that
        # still contain a `null` zone after remapping rather than keep an
        # unusable half-formed boundary.
        zones_list = updated_boundary.get("zones") or []
        if any(z is None for z in zones_list):
            _record(
                remap,
                "boundaries",
                _ref(updated_boundary)
                or "zones:" + ",".join(str(z) for z in zones_list),
                None,
            )
            dropped_incomplete += 1
            continue
        key = (
            _norm(updated_boundary.get("name")),
            tuple(sorted(zones_list, key=lambda z: (z is None, z))),
        )
        # Boundaries in Precogly editor exports have no `bom-ref`; identify
        # them by their (name, zones) key so duplicates across editor
        # round-trips are still collapsed instead of silently passing through.
        boundary_ref = _ref(updated_boundary) or "zones:" + ",".join(
            str(z) for z in key[1]
        )
        if key in seen:
            _record(remap, "boundaries", boundary_ref, seen[key])
            removed += 1
            continue
        seen[key] = boundary_ref
        kept.append(updated_boundary)
    if kept:
        blueprint["boundaries"] = kept
    return removed + dropped_incomplete


def _dedupe_data_stores(
    blueprint: dict[str, Any], remap: dict[str, dict[str, str]]
) -> int:
    zone_refs = remap.get("zones", {})
    seen: dict[tuple[str, str], str] = {}
    kept: list[Any] = []
    removed = 0
    for store in blueprint.get("dataStores", []) or []:
        if not isinstance(store, dict):
            kept.append(store)
            continue
        updated_store = copy.deepcopy(store)
        if updated_store.get("zone") in zone_refs:
            updated_store["zone"] = zone_refs[updated_store["zone"]]
        store_ref = _ref(updated_store)
        key = (_norm(updated_store.get("name")), str(updated_store.get("zone") or ""))
        if store_ref and key in seen:
            _record(remap, "dataStores", store_ref, seen[key])
            removed += 1
            continue
        if store_ref:
            seen[key] = store_ref
        kept.append(updated_store)
    if kept:
        blueprint["dataStores"] = kept
    return removed


def _strip_editor_only_fields(dfd: dict[str, Any]) -> list[str]:
    """Remove editor-only preview/canvas fields not part of the DFD source of truth.

    Returns the list of dotted-path keys actually removed, for the remap report.
    """
    stripped: list[str] = []
    for key in TOP_LEVEL_STRIP_KEYS:
        if key in dfd:
            del dfd[key]
            stripped.append(key)
    for blueprint in dfd.get("blueprints") or []:
        if not isinstance(blueprint, dict):
            continue
        for key in BLUEPRINT_STRIP_KEYS:
            if key in blueprint:
                del blueprint[key]
                stripped.append(f"blueprints[].{key}")
    return stripped


def rehydrate_dfd(
    dfd: dict[str, Any], *, redaction_path: Path | None, merge_types: set[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    scrubbed, scrub_findings = scrub_dfd(dfd, redaction_path=redaction_path)
    stripped_fields = _strip_editor_only_fields(scrubbed)
    blueprint = _first_blueprint(scrubbed)
    before_counts = {
        section: len(blueprint.get(section, []) or []) for section in DFD_SECTIONS
    }
    remap: dict[str, dict[str, str]] = {}
    conflicts: list[dict[str, Any]] = []
    removed = {
        "zones": _dedupe_zones(blueprint, remap),
        "assets": _dedupe_assets(blueprint, remap, merge_types),
        "flows": _dedupe_flows(blueprint, remap, conflicts),
        "boundaries": _dedupe_boundaries(blueprint, remap),
        "dataStores": _dedupe_data_stores(blueprint, remap),
    }
    notation_changed = _set_dfd3_notation(blueprint)
    rehydrated = canonicalize_dfd(scrubbed)
    after_bp = _first_blueprint(rehydrated)
    after_counts = {
        section: len(after_bp.get(section, []) or []) for section in DFD_SECTIONS
    }
    report = {
        "summary": {
            "before_counts": before_counts,
            "after_counts": after_counts,
            "removed_counts": removed,
            "remapped_refs": sum(len(values) for values in remap.values()),
            "scrubbed_fields": len(scrub_findings),
            "stripped_editor_fields": len(stripped_fields),
            "notation_style_set": notation_changed,
            "conflicts": len(conflicts),
        },
        "remap": {
            section: dict(sorted(values.items()))
            for section, values in sorted(remap.items())
        },
        "scrubbed": [finding.__dict__ for finding in scrub_findings],
        "stripped": sorted(stripped_fields),
        "conflicts": conflicts,
    }
    return rehydrated, report


def remap_architecture(
    arch: dict[str, Any], remap: dict[str, dict[str, str]]
) -> dict[str, Any]:
    refs: dict[str, str] = {}
    for section in ("zones", "assets", "flows", "boundaries", "dataStores"):
        refs.update(remap.get(section, {}))
    return _remap(arch, refs)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=False, allow_unicode=False)


def _merge_types(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def build_report(
    system: str,
    export_path: Path,
    out_path: Path,
    report: dict[str, Any],
    *,
    arch_changed: bool,
) -> dict[str, Any]:
    by_section = Counter()
    for section, refs in report.get("remap", {}).items():
        by_section[section] = len(refs)
    return {
        "system": system,
        "status": "changed"
        if report["summary"]["remapped_refs"]
        or report["summary"]["scrubbed_fields"]
        or report["summary"]["stripped_editor_fields"]
        or report["summary"]["notation_style_set"]
        or arch_changed
        else "clean",
        "generated_at": datetime.now(UTC).isoformat(),
        "editor_export": _rel(export_path),
        "output_dfd": _rel(out_path),
        "summary": {
            **report["summary"],
            "architecture_changed": arch_changed,
            "remapped_by_section": dict(sorted(by_section.items())),
        },
        "remap": report.get("remap", {}),
        "scrubbed": report.get("scrubbed", []),
        "stripped": report.get("stripped", []),
        "conflicts": report.get("conflicts", []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system", nargs="?", default=DEFAULT_SYSTEM)
    parser.add_argument(
        "--from", dest="source", required=True, help="Precogly editor CycloneDX export"
    )
    parser.add_argument(
        "--out", help="DFD output path (default: system model/base-dfd.cdx.json)"
    )
    parser.add_argument(
        "--report", help="Remap report path (default: build/<system>-dfd-remap.yaml)"
    )
    parser.add_argument(
        "--merge-types",
        default=",".join(DEFAULT_MERGE_TYPES),
        help="Comma-separated asset types to merge by name, preferring system when present",
    )
    parser.add_argument(
        "--strict-conflicts",
        action="store_true",
        help="Fail without updating source files when duplicate fields conflict",
    )
    args = parser.parse_args(argv)

    paths = load_system(args.system)
    if not paths.model_dfd and not args.out:
        print(
            f"FAIL: {args.system} has no model/base-dfd.cdx.json; pass --out",
            file=sys.stderr,
        )
        return 1

    source = Path(args.source)
    if not source.is_absolute():
        source = ROOT / source
    out = Path(args.out) if args.out else paths.model_dfd
    if out is None:
        raise AssertionError("out path must be resolved")
    if not out.is_absolute():
        out = ROOT / out
    report_path = (
        Path(args.report)
        if args.report
        else ROOT / "build" / f"{args.system}-dfd-remap.yaml"
    )
    if not report_path.is_absolute():
        report_path = ROOT / report_path

    rehydrated, details = rehydrate_dfd(
        load_json(source),
        redaction_path=paths.redaction,
        merge_types=_merge_types(args.merge_types),
    )
    if args.strict_conflicts and details["conflicts"]:
        report = build_report(args.system, source, out, details, arch_changed=False)
        write_yaml(report_path, report)
        print(
            f"FAIL: found {len(details['conflicts'])} conflicting duplicate field(s); "
            f"review {_rel(report_path)}.",
            file=sys.stderr,
        )
        return 1
    write_json(out, rehydrated)

    arch_changed = False
    if paths.model_architecture:
        arch = (
            yaml.safe_load(paths.model_architecture.read_text(encoding="utf-8")) or {}
        )
        remapped_arch = remap_architecture(arch, details.get("remap", {}))
        if remapped_arch != arch:
            write_yaml(paths.model_architecture, remapped_arch)
            arch_changed = True

    report = build_report(args.system, source, out, details, arch_changed=arch_changed)
    write_yaml(report_path, report)
    counts = report["summary"]
    print(
        f"Wrote {_rel(out)} and {_rel(report_path)}; "
        f"removed {sum(counts['removed_counts'].values())} duplicate DFD item(s), "
        f"remapped {counts['remapped_refs']} ref(s), scrubbed {counts['scrubbed_fields']} field(s), "
        f"stripped {counts['stripped_editor_fields']} editor-only field(s)."
    )
    if arch_changed:
        print(f"Updated {_rel(paths.model_architecture)} through the same remap.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
