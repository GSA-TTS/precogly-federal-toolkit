#!/usr/bin/env python3
"""Validate fail-closed publication/concurrence manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from validate import _load_forbidden  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SYSTEMS_DIR = REPO / "data" / "systems"
SCHEMA_PATH = REPO / "schemas" / "publication-concurrence.schema.json"


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def _schema_errors(data: dict[str, Any], path: Path) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    return [f"{path}: schema: {error.message}" for error in validator.iter_errors(data)]


def validate_manifest(
    path: Path, today: date | None = None, repository: Path = REPO
) -> list[str]:
    data = _load(path)
    errors = _schema_errors(data, path)
    today = today or date.today()
    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if data.get("system_slug") != path.parent.name:
        errors.append(f"{path}: system_slug must match directory name")
    for key in ("source_sha256", "canonical_sha256"):
        value = data.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdefABCDEF" for c in value)
        ):
            errors.append(f"{path}: {key} must be a SHA-256 digest")
    artifact = data.get("canonical_artifact")
    if not isinstance(artifact, str) or not artifact.startswith("vault/"):
        errors.append(f"{path}: canonical_artifact must be a vault-relative path")
    else:
        vault_root = (repository / "vault").resolve()
        artifact_path = (repository / artifact).resolve()
        if not artifact_path.is_relative_to(vault_root):
            errors.append(
                f"{path}: canonical_artifact must remain within the vault directory"
            )
            return errors
        if artifact_path.is_file():
            artifact_text = artifact_path.read_text(encoding="utf-8")
            digest = hashlib.sha256(artifact_text.encode()).hexdigest()
            if digest != data.get("canonical_sha256"):
                errors.append(
                    f"{path}: canonical_sha256 does not match canonical_artifact"
                )
            else:
                redaction_path = path.parent / "redaction.yaml"
                if not redaction_path.is_file():
                    redaction_path = None
                for pattern, label in _load_forbidden(redaction_path):
                    if pattern.search(artifact_text):
                        errors.append(
                            f"{path}: canonical_artifact contains forbidden {label}"
                        )
        else:
            errors.append(f"{path}: canonical_artifact is missing")
    expected_sidecar = f"data/systems/{path.parent.name}/cui.yaml"
    if data.get("cui_sidecar") != expected_sidecar:
        errors.append(f"{path}: cui_sidecar must be {expected_sidecar}")
    elif not (repository / expected_sidecar).is_file():
        errors.append(f"{path}: referenced CUI sidecar is missing")
    else:
        sidecar = _load(repository / expected_sidecar)
        sources = sidecar.get("source_documents")
        approved_digests = {
            source.get("sha256")
            for source in sources
            if isinstance(source, dict) and isinstance(source.get("sha256"), str)
        }
        if data.get("source_sha256") not in approved_digests:
            errors.append(f"{path}: source_sha256 is not approved by the CUI sidecar")
    if data.get("redaction_status") != "passed":
        errors.append(f"{path}: redaction_status must be passed")
    if data.get("publication_scope") != "internal-community":
        errors.append(f"{path}: publication_scope must be internal-community")
    concurrence = data.get("concurrence")
    if not isinstance(concurrence, dict):
        errors.append(f"{path}: concurrence mapping is required")
    else:
        for key in ("system_owner_role", "reviewer_role", "decision_ref"):
            if not isinstance(concurrence.get(key), str) or len(concurrence[key]) < 3:
                errors.append(f"{path}: concurrence/{key} is required")
        try:
            date.fromisoformat(str(concurrence.get("decision_date")))
        except ValueError:
            errors.append(f"{path}: concurrence/decision_date is invalid")
    try:
        if date.fromisoformat(str(data.get("revalidate_by"))) < today:
            errors.append(f"{path}: concurrence has expired")
    except ValueError:
        errors.append(f"{path}: revalidate_by is invalid")
    return errors


def validate_provider_workload_publication(
    system_dir: Path, repository: Path = REPO
) -> list[str]:
    """Ensure non-as-built provider workloads cannot enter publication paths."""

    workload_path = system_dir / "workload.yaml"
    if not workload_path.is_file():
        return []
    workload = _load(workload_path)
    eligible = (
        workload.get("lifecycle") == "as-built"
        and workload.get("authorization_state") in {"approved", "current"}
        and workload.get("feasibility_status") == "confirmed"
    )
    errors: list[str] = []
    publication = system_dir / "publication.yaml"
    if publication.exists() and not eligible:
        errors.append(
            f"{publication}: provider workload is not publication eligible "
            f"(lifecycle={workload.get('lifecycle')}, "
            f"authorization_state={workload.get('authorization_state')}, "
            f"feasibility_status={workload.get('feasibility_status')})"
        )
    slug = system_dir.name
    artifact = repository / "build" / "systems" / slug / f"{slug}.cdx.json"
    if artifact.is_file() and not eligible:
        document = json.loads(artifact.read_text(encoding="utf-8"))
        promoted = [
            control.get("bom-ref")
            for control in document.get("controls") or []
            if control.get("status") in {"implemented", "verified"}
        ]
        if promoted:
            errors.append(
                f"{artifact}: non-publishable provider workload contains "
                f"{len(promoted)} implemented/verified control statuses"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Specific publication.yaml files")
    args = parser.parse_args()
    paths = [Path(path) for path in args.paths] or sorted(
        SYSTEMS_DIR.glob("*/publication.yaml")
    )
    errors = [error for path in paths for error in validate_manifest(path)]
    errors.extend(
        error
        for system_dir in sorted(SYSTEMS_DIR.iterdir())
        if system_dir.is_dir()
        for error in validate_provider_workload_publication(system_dir)
    )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK - publication/concurrence manifests valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
