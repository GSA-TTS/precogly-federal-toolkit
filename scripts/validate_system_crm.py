#!/usr/bin/env python3
"""Validate a system's CRM inheritance and control-responsibility baseline.

Reads ``data/systems/<slug>/crm/index.yaml`` and every provider CRM source it
references. The rules fail closed: inheritance can only be accepted from a
provider whose CRM is current and whose authorization identifier is recorded,
and a tenant obligation can only be called confirmed when it appears in a
provider CRM file in the same directory.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    from scripts.control_identity import canonical_control_id
except ModuleNotFoundError:  # Support direct invocation as a script.
    from control_identity import canonical_control_id

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SYSTEM = "example-system-sync"
SCHEMA = ROOT / "schemas/system-crm.schema.json"


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _provider_ready(provider: dict[str, Any]) -> bool:
    return (
        provider.get("crm_status") == "current"
        and bool(provider.get("authorization_id"))
        and bool(provider.get("crm_version"))
        and bool(provider.get("crm_source"))
    )


def is_legacy_canonical_index(data: dict[str, Any]) -> bool:
    """Return True only for a positively identified legacy canonical index.

    Systems that predate the inheritance baseline keep a canonical control index
    where every control carries a ``sources`` list and no baseline fields. That
    shape is what is skipped. Anything else, including a baseline index that has
    lost its ``schema_version``/``providers`` keys, is validated in full so a
    damaged baseline fails instead of silently skipping.
    """
    if "schema_version" in data or "providers" in data:
        return False
    controls = data.get("controls")
    if not isinstance(controls, list) or not controls:
        return False
    return all(
        isinstance(row, dict)
        and isinstance(row.get("sources"), list)
        and "classification" not in row
        for row in controls
    )


def validate_index(index_path: Path) -> list[str]:
    data = _load_yaml(index_path)
    errors: list[str] = []
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        jsonschema = None
    if jsonschema:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors.extend(
            f"{index_path}:{'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in sorted(
                validator.iter_errors(data), key=lambda item: list(item.path)
            )
        )
        if errors:
            return errors

    providers: dict[str, dict[str, Any]] = data.get("providers") or {}
    controls: list[dict[str, Any]] = data.get("controls") or []
    crm_dir = index_path.parent

    if data.get("count") != len(controls):
        errors.append(
            f"{index_path}:count: {data.get('count')} does not match {len(controls)} controls"
        )

    # Provider registry rules.
    source_controls: dict[str, set[str]] = {}
    for name, provider in providers.items():
        status = provider.get("crm_status")
        source = provider.get("crm_source")
        if status == "current" and not _provider_ready(provider):
            errors.append(
                f"{index_path}:providers/{name}: current CRM requires authorization_id, crm_version, and crm_source"
            )
        if status != "not-obtained" and not source:
            errors.append(
                f"{index_path}:providers/{name}: crm_status {status} requires a crm_source file"
            )
        if source:
            source_path = crm_dir / source
            if not source_path.is_file():
                errors.append(
                    f"{index_path}:providers/{name}: crm_source {source} not found"
                )
                continue
            source_data = _load_yaml(source_path)
            ids: set[str] = set()
            for entry in source_data.get("controls") or []:
                try:
                    cid = canonical_control_id(str(entry.get("control_id", "")))
                except ValueError as exc:
                    errors.append(f"{source_path}: {exc}")
                    continue
                if cid in ids:
                    errors.append(f"{source_path}: duplicate control {cid}")
                ids.add(cid)
            if status == "not-obtained" and ids:
                errors.append(
                    f"{source_path}: provider {name} CRM is not obtained but lists controls"
                )
            source_controls[source.removesuffix(".yaml")] = ids

    seen: set[str] = set()
    for row in controls:
        cid = row.get("control_id", "<missing>")
        where = f"{index_path}:controls/{cid}"
        try:
            canonical = canonical_control_id(cid)
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            continue
        if canonical != cid:
            errors.append(f"{where}: control_id is not canonical ({canonical})")
        if cid in seen:
            errors.append(f"{where}: duplicate control_id")
        seen.add(cid)

        classification = row.get("classification")
        obligation = row.get("tenant_obligation")
        inheritance = row.get("provider_inheritance")
        row_providers = row.get("providers") or []
        crm_sources = row.get("crm_sources") or []

        for provider_name in row_providers:
            if provider_name not in providers:
                errors.append(f"{where}: unknown provider {provider_name}")
        for source_name in crm_sources:
            if source_name not in source_controls:
                errors.append(f"{where}: unknown crm_source {source_name}")

        if obligation == "confirmed-by-crm":
            if not crm_sources:
                errors.append(f"{where}: confirmed obligation requires crm_sources")
            for source_name in crm_sources:
                if cid not in source_controls.get(source_name, set()):
                    errors.append(
                        f"{where}: obligation not found in crm source {source_name}"
                    )
        elif crm_sources:
            errors.append(
                f"{where}: crm_sources set but tenant_obligation is {obligation}"
            )

        if classification == "inherited" or inheritance == "accepted":
            if not row_providers:
                errors.append(f"{where}: accepted inheritance requires providers")
            for provider_name in row_providers:
                provider = providers.get(provider_name, {})
                if not _provider_ready(provider):
                    errors.append(
                        f"{where}: inheritance from {provider_name} requires a current CRM and authorization_id"
                    )
            if classification != "inherited" or inheritance != "accepted":
                errors.append(
                    f"{where}: inherited classification and accepted inheritance must be set together"
                )
        if classification in {"hybrid", "system-specific"} and obligation != (
            "confirmed-by-crm"
        ):
            errors.append(
                f"{where}: {classification} requires a tenant obligation confirmed by a provider CRM"
            )
        if classification == "hybrid" and inheritance == "none":
            errors.append(f"{where}: hybrid requires a provider inheritance claim")
        if inheritance == "pending-provider-evidence":
            if not row_providers:
                errors.append(f"{where}: pending inheritance requires providers")
            if any(_provider_ready(providers.get(p, {})) for p in row_providers):
                errors.append(
                    f"{where}: provider CRM is current; accept or reject the inheritance claim"
                )
        needs_action = (
            classification
            in {
                "unresolved",
                "planned",
                "not-implemented",
            }
            and inheritance != "pending-provider-evidence"
        )
        if (obligation == "unresolved" or needs_action) and not str(
            row.get("required_action") or ""
        ).strip():
            errors.append(f"{where}: unresolved ownership requires required_action")
        if row.get("implementation_state") == "implemented" and not row.get(
            "evidence_refs"
        ):
            errors.append(f"{where}: implemented state requires evidence_refs")

    # Every provider CRM entry must be indexed against its source.
    for source_name, ids in source_controls.items():
        indexed = {
            r["control_id"]
            for r in controls
            if source_name in (r.get("crm_sources") or [])
        }
        for cid in sorted(ids - indexed):
            errors.append(
                f"{index_path}: {source_name} lists {cid} but the index does not reference it"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", default=DEFAULT_SYSTEM)
    parser.add_argument("--index", type=Path)
    args = parser.parse_args(argv)
    index = args.index or ROOT / "data/systems" / args.system / "crm/index.yaml"
    if not index.is_file():
        print(f"{index}: not found", file=sys.stderr)
        return 1
    if is_legacy_canonical_index(_load_yaml(index)):
        print(
            f"SKIP - {args.system} uses the legacy canonical control index; it has no inheritance baseline to validate"
        )
        return 0
    errors = validate_index(index)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    data = _load_yaml(index)
    counts: dict[str, int] = {}
    for row in data.get("controls") or []:
        key = str(row.get("classification"))
        counts[key] = counts.get(key, 0) + 1
    summary = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    print(f"OK - {args.system} CRM baseline valid ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
