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
SCHEMAS = ROOT / "schemas-local"

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from flow_auth import load_auth_catalog  # noqa: E402
from systems.loader import DEFAULT_SYSTEM, SystemPaths, load_system  # noqa: E402
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


def _schema_errors(
    payload: dict[str, Any], schema_name: str, source: Path
) -> list[str]:
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
    for error in sorted(
        validator.iter_errors(payload), key=lambda item: list(item.path)
    ):
        at = "/".join(str(part) for part in error.path) or "<root>"
        errors.append(f"{_rel(source)}:{at}: {error.message}")
    return errors


def validate_dfd(
    dfd: dict[str, Any], *, source: Path
) -> tuple[set[str], set[str], set[str], list[str]]:
    errors: list[str] = []
    metadata = dfd.get("metadata") or {}
    if isinstance(metadata, dict) and metadata.get("authors"):
        errors.append(
            f"{_rel(source)}: metadata.authors must be stripped before generation"
        )

    blueprints = dfd.get("blueprints") or []
    asset_refs: set[str] = set()
    zone_refs: set[str] = set()
    flow_refs: set[str] = set()

    for index, blueprint in enumerate(blueprints):
        prefix = f"{_rel(source)}:blueprints[{index}]"
        assets = blueprint.get("assets") or []
        zones = blueprint.get("zones") or []
        flows = blueprint.get("flows") or []

        for zone in zones:
            ref = zone.get("bom-ref")
            if ref in zone_refs:
                errors.append(f"{prefix}: duplicate zone bom-ref {ref}")
            elif ref:
                zone_refs.add(ref)

        for asset in assets:
            ref = asset.get("bom-ref")
            if ref in asset_refs:
                errors.append(f"{prefix}: duplicate asset bom-ref {ref}")
            elif ref:
                asset_refs.add(ref)

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
                    errors.append(
                        f"{prefix}: flow {ref} {field} references unknown DFD node {target}"
                    )

    return asset_refs, zone_refs, flow_refs, errors


def _check_aliases(
    errors: list[str], source: Path, field: str, aliases: Any, known_aliases: set[str]
) -> None:
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
            errors.append(
                f"{_rel(source)}:assets.{alias} references unknown asset {asset_ref}"
            )

    for zone_ref, override in (arch.get("zone_overrides") or {}).items():
        if zone_ref not in zone_refs:
            errors.append(
                f"{_rel(source)}:zone_overrides.{zone_ref} references unknown zone"
            )
        parent = (override or {}).get("parentZone")
        if parent and parent not in zone_refs:
            errors.append(
                f"{_rel(source)}:zone_overrides.{zone_ref}.parentZone references unknown zone {parent}"
            )
        if parent == zone_ref:
            errors.append(
                f"{_rel(source)}:zone_overrides.{zone_ref}.parentZone cannot reference itself"
            )

    for asset_ref, override in (arch.get("asset_overrides") or {}).items():
        if asset_ref not in asset_refs:
            errors.append(
                f"{_rel(source)}:asset_overrides.{asset_ref} references unknown asset"
            )
        zone_ref = (override or {}).get("zone")
        if zone_ref and zone_ref not in zone_refs:
            errors.append(
                f"{_rel(source)}:asset_overrides.{asset_ref}.zone references unknown zone {zone_ref}"
            )

    allowed_auth, warning_auth = load_auth_catalog(arch=arch)
    known_auth = allowed_auth | set(warning_auth)
    for flow_ref, override in (arch.get("flow_overrides") or {}).items():
        if flow_ref not in flow_refs:
            errors.append(
                f"{_rel(source)}:flow_overrides.{flow_ref} references unknown flow"
            )
        auth = (override or {}).get("authMechanism")
        if auth and auth not in known_auth:
            errors.append(
                f"{_rel(source)}:flow_overrides.{flow_ref}.authMechanism unsupported value {auth}"
            )
        elif auth in warning_auth:
            warnings.append(
                f"{_rel(source)}:flow_overrides.{flow_ref}.authMechanism {auth}: {warning_auth[auth]}"
            )

    for control_id, refs in (arch.get("flow_bindings") or {}).items():
        if not isinstance(refs, list):
            errors.append(
                f"{_rel(source)}:flow_bindings.{control_id}: expected a list of flow refs"
            )
            continue
        unknown = sorted(set(refs) - flow_refs)
        if unknown:
            errors.append(
                f"{_rel(source)}:flow_bindings.{control_id} references unknown flows {unknown}"
            )

    for group, group_aliases in (arch.get("asset_groups") or {}).items():
        _check_aliases(
            errors, source, f"asset_groups.{group}", group_aliases, known_aliases
        )
    for family, family_aliases in (arch.get("family_asset_map") or {}).items():
        _check_aliases(
            errors, source, f"family_asset_map.{family}", family_aliases, known_aliases
        )
    _check_aliases(
        errors, source, "default_assets", arch.get("default_assets"), known_aliases
    )

    return errors, warnings


def validate_sources(paths: SystemPaths) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not paths.model_dfd:
        errors.append(f"{paths.slug}: missing model/base-dfd.cdx.json")
    if not paths.model_architecture:
        errors.append(f"{paths.slug}: missing model/architecture.yaml")
    if errors:
        return errors, warnings

    dfd = _load_json(paths.model_dfd)
    arch = _load_yaml(paths.model_architecture)
    errors.extend(_schema_errors(dfd, "model-dfd.schema.json", paths.model_dfd))
    errors.extend(
        _schema_errors(arch, "architecture.schema.json", paths.model_architecture)
    )

    asset_refs, zone_refs, flow_refs, dfd_errors = validate_dfd(
        dfd, source=paths.model_dfd
    )
    errors.extend(dfd_errors)
    arch_errors, arch_warnings = validate_architecture(
        arch,
        source=paths.model_architecture,
        asset_refs=asset_refs,
        zone_refs=zone_refs,
        flow_refs=flow_refs,
    )
    errors.extend(arch_errors)
    warnings.extend(arch_warnings)

    forbidden = _load_forbidden(paths.redaction)
    for source in (paths.model_dfd, paths.model_architecture):
        text = source.read_text(encoding="utf-8")
        for pattern, label in forbidden:
            match = pattern.search(text)
            if match:
                errors.append(
                    f"{_rel(source)}: unredacted {label} found before generation: {match.group(0)!r}"
                )

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
