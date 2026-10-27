#!/usr/bin/env python3
"""Validate reconciliation decision evidence against a proposal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.validate_reconciliation_proposals import validate_proposal  # noqa: E402

SYSTEMS_DIR = REPO / "data" / "systems"
SCHEMA_PATH = REPO / "schemas" / "reconciliation-evidence.schema.json"
_DECISIONS = {"approved", "rejected", "blocked"}
_CONFLICTS = {"none", "manual-review-required", "rejected"}
_BREAK_GLASS = {"not-used", "required", "completed"}


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def _schema_errors(data: dict[str, Any], path: Path) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    return [f"{path}: schema: {error.message}" for error in validator.iter_errors(data)]


def validate_evidence(path: Path, repository: Path = REPO) -> list[str]:
    data = _load(path)
    errors = _schema_errors(data, path)
    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    proposal_ref = data.get("proposal")
    expected_ref = (
        f"data/systems/{path.parent.parent.name}/reconciliation-proposal.yaml"
    )
    if not isinstance(proposal_ref, str) or proposal_ref != expected_ref:
        return [f"{path}: proposal must be a repository-relative proposal path"]
    proposal_path = (repository / proposal_ref).resolve()
    if not proposal_path.is_relative_to(repository.resolve()):
        return [f"{path}: proposal must remain within the repository"]
    if not proposal_path.is_file():
        return [f"{path}: referenced proposal is missing"]
    errors.extend(validate_proposal(proposal_path, repository=repository))
    proposal = _load(proposal_path)
    for key in ("proposal_id", "source_sha256", "canonical_sha256"):
        if data.get(key) != proposal.get(key):
            errors.append(f"{path}: {key} must match the proposal")
    if data.get("validation_status") != "passed":
        errors.append(f"{path}: validation_status must be passed")
    if data.get("decision") not in _DECISIONS:
        errors.append(f"{path}: decision is invalid")
    if data.get("conflict_disposition") not in _CONFLICTS:
        errors.append(f"{path}: conflict_disposition is invalid")
    if data.get("break_glass_backport") not in _BREAK_GLASS:
        errors.append(f"{path}: break_glass_backport is invalid")
    if (
        data.get("decision") == "approved"
        and data.get("conflict_disposition") != "none"
    ):
        errors.append(f"{path}: approved evidence cannot carry an unresolved conflict")
    if (
        data.get("break_glass_backport") == "completed"
        and data.get("decision") != "approved"
    ):
        errors.append(f"{path}: completed break-glass backport requires approval")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths", nargs="*", help="Specific reconciliation evidence files"
    )
    args = parser.parse_args()
    paths = [Path(path) for path in args.paths] or sorted(
        SYSTEMS_DIR.glob("*/reconciliation-evidence/*.yaml")
    )
    errors = [error for path in paths for error in validate_evidence(path)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK - reconciliation evidence valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
