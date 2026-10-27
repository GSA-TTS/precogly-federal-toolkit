#!/usr/bin/env python3
"""Validate forge-neutral reconciliation proposals without remote writes."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.validate_publication_contracts import (  # noqa: E402
    REPO,
    SYSTEMS_DIR,
    validate_manifest,
)

SCHEMA_PATH = REPO / "schemas" / "reconciliation-proposal.schema.json"

_PROPOSAL_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_DIRECTIONS = {"outbound-publication", "inbound-improvement"}
_TARGETS = {"github-enterprise-pull-request", "workshop-gitlab-merge-request"}


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def _schema_errors(data: dict[str, Any], path: Path) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    return [f"{path}: schema: {error.message}" for error in validator.iter_errors(data)]


def validate_proposal(path: Path, repository: Path = REPO) -> list[str]:
    data = _load(path)
    errors = _schema_errors(data, path)
    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if not isinstance(data.get("proposal_id"), str) or not _PROPOSAL_ID.match(
        data["proposal_id"]
    ):
        errors.append(f"{path}: proposal_id is invalid")
    if data.get("direction") not in _DIRECTIONS:
        errors.append(f"{path}: direction is invalid")
    if data.get("target_kind") not in _TARGETS:
        errors.append(f"{path}: target_kind is invalid")
    if data.get("status") != "proposed":
        errors.append(f"{path}: status must be proposed")
    manifest_ref = data.get("publication_manifest")
    if (
        not isinstance(manifest_ref, str)
        or manifest_ref != f"data/systems/{path.parent.name}/publication.yaml"
    ):
        errors.append(
            f"{path}: publication_manifest must be a repository-relative manifest path"
        )
        return errors
    manifest_path = (repository / manifest_ref).resolve()
    if not manifest_path.is_relative_to(repository.resolve()):
        return [f"{path}: publication_manifest must remain within the repository"]
    if not manifest_path.is_file():
        errors.append(f"{path}: publication manifest is missing")
        return errors
    errors.extend(validate_manifest(manifest_path, repository=repository))
    manifest = _load(manifest_path)
    for key in ("source_sha256", "canonical_sha256"):
        value = data.get(key)
        if not isinstance(value, str) or not _SHA256.match(value):
            errors.append(f"{path}: {key} must be a SHA-256 digest")
        elif value != manifest.get(key):
            errors.append(f"{path}: {key} must match the publication manifest")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths", nargs="*", help="Specific reconciliation-proposal.yaml files"
    )
    args = parser.parse_args()
    paths = [Path(path) for path in args.paths] or sorted(
        SYSTEMS_DIR.glob("*/reconciliation-proposal.yaml")
    )
    errors = [error for path in paths for error in validate_proposal(path)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK - reconciliation proposals valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
