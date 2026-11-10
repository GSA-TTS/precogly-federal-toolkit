#!/usr/bin/env python3
"""Validate Precogly pack metadata and required pack content files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent


def _resolve_pack_schema(name: str) -> Path:
    candidate = ROOT / "data" / "packs" / name
    return candidate if candidate.is_file() else ROOT / "schemas" / name


DEFAULT_SCHEMA = _resolve_pack_schema("pack.schema.json")
SERVICE_SCHEMA = _resolve_pack_schema("service-descriptor.schema.json")
OFFERINGS_SCHEMA = _resolve_pack_schema("offerings.schema.json")
CORE_CONTROL_NAMES = (
    ROOT
    / "vendor"
    / "oscal-vault-core"
    / "compliance"
    / "data"
    / "nist_sp800-53_rev5_control_names.json"
)
PACK_GLOBS = (
    "data/packs/*/pack.yaml",
    "packs/*/pack.yaml",
    "vendor/*/packs/*/pack.yaml",
)
REQUIRED_CONTENT = {
    "components.yaml": "components",
    "threats.yaml": "threats",
    "countermeasures.yaml": "countermeasures",
}


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"expected YAML mapping, got {type(data).__name__}")
    return data


def iter_pack_paths(root: Path, explicit: list[str]) -> list[Path]:
    if explicit:
        return sorted(
            (root / p).resolve() if not Path(p).is_absolute() else Path(p)
            for p in explicit
        )
    found: set[Path] = set()
    for pattern in PACK_GLOBS:
        found.update(path.resolve() for path in root.glob(pattern))
    return sorted(found)


def format_error(path: Path, message: str) -> str:
    try:
        display = path.relative_to(ROOT)
    except ValueError:
        display = path
    return f"{display}: {message}"


def validate_content_file(pack_dir: Path, file_name: str, key: str) -> list[str]:
    path = pack_dir / file_name
    if not path.is_file():
        return [format_error(path, "missing required pack content file")]
    try:
        data = load_yaml(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [format_error(path, f"invalid YAML: {exc}")]
    items = data.get(key)
    if not isinstance(items, list) or not items:
        return [format_error(path, f"expected non-empty '{key}' list")]
    return []


def validate_icon_map(pack_dir: Path, data: dict) -> list[str]:
    icon_map = data.get("pack", {}).get("icon_map", [])
    if not icon_map:
        return []
    components_path = pack_dir / "components.yaml"
    try:
        components = load_yaml(components_path).get("components", [])
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [format_error(components_path, f"invalid YAML: {exc}")]
    component_ids = {
        component.get("id") for component in components if isinstance(component, dict)
    }
    errors: list[str] = []
    seen: set[str] = set()
    for mapping in icon_map:
        if not isinstance(mapping, dict):
            continue
        component = mapping.get("component")
        if component in seen:
            errors.append(
                format_error(
                    pack_dir / "pack.yaml",
                    f"icon_map duplicates component: {component}",
                )
            )
        seen.add(component)
        if component not in component_ids:
            errors.append(
                format_error(
                    pack_dir / "pack.yaml",
                    f"icon_map references unknown component: {component}",
                )
            )
    return errors


def validate_service_descriptors(pack_dir: Path) -> list[str]:
    components_path = pack_dir / "components.yaml"
    try:
        components = load_yaml(components_path).get("components", [])
    except (OSError, ValueError, yaml.YAMLError):
        return []
    described = [c for c in components if isinstance(c, dict) and "service" in c]
    if not described:
        return []
    service_validator = Draft202012Validator(load_yaml(SERVICE_SCHEMA))
    component_ids = {c.get("id") for c in components if isinstance(c, dict)}
    errors: list[str] = []
    for component in described:
        cid = component.get("id")
        service = component["service"]
        for error in sorted(
            service_validator.iter_errors(service), key=lambda e: list(e.path)
        ):
            location = ".".join(str(part) for part in error.path) or "<service>"
            errors.append(
                format_error(
                    components_path, f"{cid}.service.{location}: {error.message}"
                )
            )
        if not isinstance(service, dict):
            continue
        for prerequisite in service.get("prerequisites", []):
            if prerequisite == cid:
                message = "lists itself as a prerequisite"
            elif prerequisite not in component_ids:
                message = f"has unknown prerequisite: {prerequisite}"
            else:
                continue
            errors.append(format_error(components_path, f"{cid}.service {message}"))
    errors.extend(_prerequisite_cycles(components_path, described))
    return errors


def _prerequisite_cycles(components_path: Path, described: list[dict]) -> list[str]:
    graph = {
        c["id"]: [
            p
            for p in c["service"].get("prerequisites", [])
            if isinstance(c.get("service"), dict) and p != c["id"]
        ]
        for c in described
        if isinstance(c.get("service"), dict) and "id" in c
    }
    errors: list[str] = []
    state: dict[str, int] = {}

    def visit(node: str, trail: list[str]) -> None:
        if state.get(node) == 2 or node not in graph:
            return
        if state.get(node) == 1:
            cycle = " -> ".join([*trail[trail.index(node) :], node])
            errors.append(format_error(components_path, f"prerequisite cycle: {cycle}"))
            return
        state[node] = 1
        for nxt in graph[node]:
            visit(nxt, [*trail, node])
        state[node] = 2

    for node in graph:
        visit(node, [])
    return errors


def _known_control_ids() -> set[str] | None:
    """OSCAL control ids from the pinned core, or None when the core is not checked out."""
    try:
        return set(json.loads(CORE_CONTROL_NAMES.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


def validate_offerings(pack_dir: Path) -> list[str]:
    path = pack_dir / "offerings.yaml"
    if not path.is_file():
        return []
    try:
        data = load_yaml(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [format_error(path, f"invalid YAML: {exc}")]
    validator = Draft202012Validator(load_yaml(OFFERINGS_SCHEMA))
    errors = [
        format_error(
            path, f"{'.'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        )
        for e in sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    ]
    if errors:
        return errors

    try:
        components = load_yaml(pack_dir / "components.yaml").get("components", [])
    except (OSError, ValueError, yaml.YAMLError):
        return errors
    component_ids = {c.get("id") for c in components if isinstance(c, dict)}
    known_controls = _known_control_ids()
    seen_offerings: set[str] = set()
    for offering in data["offerings"]:
        if offering["id"] in seen_offerings:
            errors.append(
                format_error(path, f"duplicate offering id: {offering['id']}")
            )
        seen_offerings.add(offering["id"])
        seen_plans: set[str] = set()
        for plan in offering["plans"]:
            where = f"{offering['id']}/{plan['id']}"
            if plan["id"] in seen_plans:
                errors.append(format_error(path, f"{where}: duplicate plan id"))
            seen_plans.add(plan["id"])
            for ref in plan["incorporates"]:
                if ref not in component_ids:
                    errors.append(
                        format_error(path, f"{where}: unknown component: {ref}")
                    )
            controls = [row["control"] for row in plan["provides"]]
            for control in sorted({c for c in controls if controls.count(c) > 1}):
                errors.append(
                    format_error(path, f"{where}: duplicate control: {control}")
                )
            if known_controls is not None:
                for control in controls:
                    if control not in known_controls:
                        errors.append(
                            format_error(path, f"{where}: unknown control: {control}")
                        )
    return errors


def validate_pack(path: Path, validator: Draft202012Validator) -> list[str]:
    errors: list[str] = []
    try:
        data = load_yaml(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [format_error(path, f"invalid YAML: {exc}")]

    for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        location = ".".join(str(part) for part in error.path) or "<root>"
        errors.append(format_error(path, f"{location}: {error.message}"))

    for file_name, key in REQUIRED_CONTENT.items():
        errors.extend(validate_content_file(path.parent, file_name, key))
    errors.extend(validate_icon_map(path.parent, data))
    errors.extend(validate_service_descriptors(path.parent))
    errors.extend(validate_offerings(path.parent))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack", nargs="*", help="Specific pack.yaml paths to validate")
    parser.add_argument(
        "--schema", default=str(DEFAULT_SCHEMA), help="JSON Schema path"
    )
    parser.add_argument("--root", default=str(ROOT), help="Repository root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    schema_path = Path(args.schema).resolve()
    schema = load_yaml(schema_path)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    pack_paths = iter_pack_paths(root, args.pack)
    if not pack_paths:
        print("FAIL: no pack.yaml files found", file=sys.stderr)
        return 1

    errors: list[str] = []
    for pack_path in pack_paths:
        errors.extend(validate_pack(pack_path, validator))

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"OK: validated {len(pack_paths)} packs against {schema_path.relative_to(root)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
