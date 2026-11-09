#!/usr/bin/env python3
"""Validate committed public CCC inheritance starter profile documents."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[1]
PROFILE_DIR = REPO / "data" / "catalog" / "public-inheritance-profiles"
SCHEMA_PATH = REPO / "schemas" / "public-inheritance-profile.schema.json"
EXPECTED_FILENAMES = {
    "public-ccc-low-starter.yaml",
    "public-ccc-moderate-starter.yaml",
    "public-ccc-high-starter.yaml",
}


def _semantic_errors(data: dict, path: Path) -> list[str]:
    """Validate cross-field invariants that JSON Schema cannot express."""
    errors: list[str] = []
    level = str(data.get("baseline", "")).lower()
    expected_name = f"public-ccc-{level}-starter"
    if path.name != f"{expected_name}.yaml":
        errors.append(f"{path}: filename must be {expected_name}.yaml")
    if data.get("profile") != expected_name:
        errors.append(f"{path}: profile must be {expected_name}")
    if not data.get("source_fedramp_baselines"):
        errors.append(f"{path}: source_fedramp_baselines is required")

    controls = data.get("controls") or []
    control_ids = [control.get("control_id") for control in controls if isinstance(control, dict)]
    if control_ids != sorted(control_ids):
        errors.append(f"{path}: controls must be sorted by control_id")
    if len(control_ids) != len(set(control_ids)):
        errors.append(f"{path}: controls must not contain duplicate control_id values")
    if data.get("control_count") != len(controls):
        errors.append(f"{path}: control_count must equal controls length")
    if data.get("ccc_designated_control_count") != len(controls):
        errors.append(f"{path}: ccc_designated_control_count must equal controls length")

    undesignated = data.get("baseline_controls_without_ccc_designation") or []
    if undesignated != sorted(undesignated):
        errors.append(f"{path}: baseline_controls_without_ccc_designation must be sorted")
    if len(undesignated) != len(set(undesignated)):
        errors.append(f"{path}: baseline_controls_without_ccc_designation must not contain duplicates")
    if set(control_ids) & set(undesignated):
        errors.append(f"{path}: designated and undesignated control sets must be disjoint")
    if data.get("fedramp_baseline_control_count") != len(controls) + len(undesignated):
        errors.append(f"{path}: fedramp_baseline_control_count must equal designated plus undesignated controls")
    return errors


def validate_profile(path: Path, schema: dict) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    validator = Draft202012Validator(schema)
    errors = [
        f"{path}: schema: {error.message}"
        for error in sorted(validator.iter_errors(data), key=lambda error: list(error.path))
    ]
    return errors + _semantic_errors(data, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Specific profile YAML files")
    args = parser.parse_args(argv)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    paths = args.paths or sorted(PROFILE_DIR.glob("*.yaml"))
    errors = [error for path in paths for error in validate_profile(path, schema)]
    if not args.paths:
        actual_filenames = {path.name for path in paths}
        missing = EXPECTED_FILENAMES - actual_filenames
        unexpected = actual_filenames - EXPECTED_FILENAMES
        if missing:
            errors.append(f"{PROFILE_DIR}: missing required profile(s): {', '.join(sorted(missing))}")
        if unexpected:
            errors.append(f"{PROFILE_DIR}: unexpected profile(s): {', '.join(sorted(unexpected))}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"OK - {len(paths)} public inheritance profile(s) conform to schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
