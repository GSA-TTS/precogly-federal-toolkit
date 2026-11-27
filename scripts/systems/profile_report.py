#!/usr/bin/env python3
"""Render system assets and user roles from per-system sources."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
ROOT = SCRIPTS.parent
ASSETS_START = "<!-- system-profile:assets:start -->"
ASSETS_END = "<!-- system-profile:assets:end -->"
ROLES_START = "<!-- system-profile:roles:start -->"
ROLES_END = "<!-- system-profile:roles:end -->"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from systems.loader import DEFAULT_SYSTEM, load_system  # noqa: E402


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source_file:
        return json.load(source_file)


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source_file:
        return yaml.safe_load(source_file) or {}


def _first_blueprint(dfd: dict[str, Any]) -> dict[str, Any]:
    blueprints = dfd.get("blueprints") or []
    if not blueprints or not isinstance(blueprints[0], dict):
        raise ValueError("DFD has no first blueprint")
    return blueprints[0]


def _aliases_by_ref(arch: dict[str, Any]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for alias, asset_ref in (arch.get("assets") or {}).items():
        if isinstance(alias, str) and isinstance(asset_ref, str):
            aliases[asset_ref] = alias
    return aliases


def _families_by_alias(arch: dict[str, Any]) -> dict[str, list[str]]:
    families: dict[str, list[str]] = {}
    for family, aliases in (arch.get("family_asset_map") or {}).items():
        for alias in aliases or []:
            if not isinstance(alias, str):
                continue
            families.setdefault(alias, []).append(str(family))
    return {alias: sorted(values) for alias, values in families.items()}


def _flow_names_by_asset(blueprint: dict[str, Any]) -> dict[str, list[str]]:
    flow_names: dict[str, list[str]] = {}
    for flow in blueprint.get("flows") or []:
        if not isinstance(flow, dict):
            continue
        name = str(flow.get("name") or flow.get("bom-ref") or "")
        for endpoint in (flow.get("source"), flow.get("destination")):
            if (
                isinstance(endpoint, str)
                and name
                and name not in flow_names.setdefault(endpoint, [])
            ):
                flow_names[endpoint].append(name)
    return flow_names


def system_assets(dfd: dict[str, Any], arch: dict[str, Any]) -> list[dict[str, Any]]:
    blueprint = _first_blueprint(dfd)
    aliases = _aliases_by_ref(arch)
    families = _families_by_alias(arch)
    flow_names = _flow_names_by_asset(blueprint)
    zones = {
        zone.get("bom-ref"): zone.get("name")
        for zone in blueprint.get("zones") or []
        if isinstance(zone, dict)
    }
    descriptions = arch.get("asset_descriptions") or {}

    rows: list[dict[str, Any]] = []
    for asset in blueprint.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        asset_ref = str(asset.get("bom-ref") or "")
        alias = aliases.get(asset_ref, "")
        description = ""
        if alias and isinstance(descriptions, dict):
            description = str(descriptions.get(alias) or "")
        if not description:
            description = str(asset.get("description") or "")
        rows.append(
            {
                "asset_ref": asset_ref,
                "alias": alias,
                "name": str(asset.get("name") or asset_ref),
                "type": str(asset.get("type") or ""),
                "zone": str(zones.get(asset.get("zone")) or asset.get("zone") or ""),
                "description": description,
                "connected_flows": flow_names.get(asset_ref, []),
                "control_families": families.get(alias, []),
            }
        )
    return rows


def user_roles(arch: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for role in arch.get("user_roles") or []:
        if isinstance(role, dict):
            rows.append(role)
    return rows


def _cell(value: Any) -> str:
    if isinstance(value, list):
        text = ", ".join(str(item) for item in value)
    else:
        text = str(value or "")
    return text.replace("|", "\\|").replace("\n", "<br>") or "-"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _header in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    return "\n".join(lines)


def render_markdown(
    system: str, assets: list[dict[str, Any]], roles: list[dict[str, Any]]
) -> str:
    asset_rows = [
        [
            asset["name"],
            asset["type"],
            asset["zone"],
            asset["alias"],
            asset["description"],
            asset["connected_flows"],
            asset["control_families"],
        ]
        for asset in assets
    ]
    role_rows = [
        [
            role.get("name"),
            role.get("internal_external"),
            role.get("privilege_level"),
            role.get("sensitivity_level"),
            role.get("authorized_privileges"),
            role.get("functions_performed"),
            role.get("mfa_authentication_method"),
        ]
        for role in roles
    ]
    if not role_rows:
        role_rows = [["No roles defined", "-", "-", "-", "-", "-", "-"]]

    return (
        "\n\n".join(
            [
                f"# {system} System Profile",
                "## System Assets",
                _table(
                    [
                        "Asset",
                        "Type",
                        "Zone",
                        "Alias",
                        "Function or Service Provided",
                        "Connected Flows",
                        "Control Families",
                    ],
                    asset_rows,
                ),
                "## User Roles and Privileges",
                _table(
                    [
                        "Role",
                        "Int/Ext",
                        "P / NP / NLA",
                        "Sensitivity Level",
                        "Authorized Privileges",
                        "Functions Performed",
                        "MFA Authentication Method",
                    ],
                    role_rows,
                ),
            ]
        )
        + "\n"
    )


def build_profile(paths) -> str:
    if not paths.model_dfd:
        raise FileNotFoundError(f"{paths.slug}: missing model/base-dfd.cdx.json")
    if not paths.model_architecture:
        raise FileNotFoundError(f"{paths.slug}: missing model/architecture.yaml")
    dfd = load_json(paths.model_dfd)
    arch = load_yaml(paths.model_architecture)
    return render_markdown(paths.slug, system_assets(dfd, arch), user_roles(arch))


def _replace_section(text: str, start: str, end: str, content: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError(f"document must contain exactly one {start} / {end} pair")
    before, remainder = text.split(start, 1)
    _, after = remainder.split(end, 1)
    return f"{before}{start}\n\n{content}\n\n{end}{after}"


def _section(text: str, start: str, end: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError(f"document must contain exactly one {start} / {end} pair")
    return text.split(start, 1)[1].split(end, 1)[0].strip()


def _normalize_table(table: str) -> list[list[str]]:
    rows = [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in table.splitlines()
        if line.strip().startswith("|")
    ]
    if len(rows) > 1 and all(set(cell) <= {"-", ":"} for cell in rows[1]):
        rows[1] = ["---"] * len(rows[1])
    return rows


def sync_document(text: str, profile: str) -> str:
    assets_and_roles = profile.split("## System Assets\n\n", 1)[1]
    assets, roles = assets_and_roles.split("\n\n## User Roles and Privileges\n\n", 1)
    text = _replace_section(text, ASSETS_START, ASSETS_END, assets)
    return _replace_section(text, ROLES_START, ROLES_END, roles.rstrip())


def document_is_current(text: str, profile: str) -> bool:
    assets_and_roles = profile.split("## System Assets\n\n", 1)[1]
    assets, roles = assets_and_roles.split("\n\n## User Roles and Privileges\n\n", 1)
    return _normalize_table(
        _section(text, ASSETS_START, ASSETS_END)
    ) == _normalize_table(assets) and _normalize_table(
        _section(text, ROLES_START, ROLES_END)
    ) == _normalize_table(roles)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system", nargs="?", default=DEFAULT_SYSTEM)
    parser.add_argument(
        "--out", help="Output path (default: build/<system>-system-profile.md)"
    )
    parser.add_argument(
        "--sync-doc", type=Path, help="Update marked tables in a document"
    )
    parser.add_argument(
        "--check-doc", type=Path, help="Fail when marked tables differ from sources"
    )
    args = parser.parse_args(argv)

    paths = load_system(args.system)
    if args.sync_doc or args.check_doc:
        doc = args.sync_doc or args.check_doc
        if not doc.is_absolute():
            doc = ROOT / doc
        current = doc.read_text(encoding="utf-8")
        profile = build_profile(paths)
        if args.check_doc:
            if not document_is_current(current, profile):
                print(f"FAIL: {_rel(doc)} profile tables are stale", file=sys.stderr)
                return 1
            print(f"OK - {_rel(doc)} profile tables match source data.")
            return 0
        updated = sync_document(current, profile)
        doc.write_text(updated, encoding="utf-8")
        print(f"Updated {_rel(doc)}")
        return 0
    out = (
        Path(args.out)
        if args.out
        else ROOT / "build" / f"{args.system}-system-profile.md"
    )
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_profile(paths), encoding="utf-8")
    print(f"Wrote {_rel(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
