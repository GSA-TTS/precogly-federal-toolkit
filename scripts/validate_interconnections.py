#!/usr/bin/env python3
"""Validate canonical interconnection contracts against system source views."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "data" / "interconnections"
SCHEMA = ROOT / "schemas" / "interconnection-contract.schema.json"


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _schema_errors(data: dict[str, Any], path: Path) -> list[str]:
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return []
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    return [
        f"{path}:{'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
        for error in sorted(
            validator.iter_errors(data), key=lambda item: list(item.path)
        )
    ]


def validate_contract(
    contract_path: Path,
    *,
    sync_architecture_path: Path | None = None,
    example_system_docx_path: Path | None = None,
) -> list[str]:
    data = _load_yaml(contract_path)
    errors = _schema_errors(data, contract_path)
    architecture_path = sync_architecture_path or (
        ROOT / "data/systems/example-system-sync/model/architecture.yaml"
    )
    docx_path = example_system_docx_path or ROOT / "data/systems/example-system/docx.yaml"
    architecture = _load_yaml(architecture_path)
    flows = architecture.get("flows") or {}
    overrides = architecture.get("flow_overrides") or {}

    for exchange_id, exchange in (data.get("exchanges") or {}).items():
        alias = exchange.get("architecture_flow")
        if alias not in flows:
            errors.append(
                f"{contract_path}:exchanges/{exchange_id}: unknown architecture_flow {alias!r}"
            )
            continue
        override = overrides.get(alias) or {}
        if exchange.get("protocol") not in (override.get("protocols") or []):
            errors.append(
                f"{contract_path}:exchanges/{exchange_id}: protocol does not match architecture flow {alias}"
            )
        if str(override.get("port_number") or "") != str(exchange.get("port") or ""):
            errors.append(
                f"{contract_path}:exchanges/{exchange_id}: port does not match architecture flow {alias}"
            )
        if override.get("authMechanism") != exchange.get("authentication"):
            errors.append(
                f"{contract_path}:exchanges/{exchange_id}: authentication does not match architecture flow {alias}"
            )
        if override.get("encrypted") is not exchange.get("encrypted"):
            errors.append(
                f"{contract_path}:exchanges/{exchange_id}: encryption does not match architecture flow {alias}"
            )

    example_system_exchange = (data.get("exchanges") or {}).get("example-system_clean_bucket_read") or {}
    interconnections = (_load_yaml(docx_path).get("chapters") or {}).get(
        "interconnections"
    ) or []
    example_system_row = next(
        (
            row
            for row in interconnections
            if str(row.get("system") or "").casefold().replace("-", " ") == "example-system sync"
        ),
        None,
    )
    if not example_system_row:
        errors.append(f"{docx_path}: missing Example System Sync interconnection row")
        return errors
    expected_direction = (
        "Inbound" if example_system_exchange.get("destination_system") == "example-system" else "Outbound"
    )
    if example_system_row.get("direction") != expected_direction:
        errors.append(
            f"{docx_path}: Example System Sync direction must be {expected_direction} from the Example System viewpoint"
        )
    security = str(example_system_row.get("connection_security") or "")
    for expected in (
        example_system_exchange.get("protocol"),
        example_system_exchange.get("authentication"),
    ):
        if expected and str(expected).casefold() not in security.casefold():
            errors.append(
                f"{docx_path}: Example System Sync connection_security omits canonical {expected}"
            )
    if example_system_row.get("system_type") == "Minor Application":
        errors.append(
            f"{docx_path}: Example System Sync must not be classified as a Minor Application"
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args(argv)
    paths = args.paths or sorted(CONTRACTS.glob("*.yaml"))
    errors = [error for path in paths for error in validate_contract(path)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"OK - {len(paths)} interconnection contract(s) valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
