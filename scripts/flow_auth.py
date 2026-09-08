"""Shared flow authentication mechanism catalog helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_CATALOG = ROOT / "data" / "catalog" / "flow-auth-mechanisms.yaml"


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError("auth mechanism lists must be YAML sequences")
    return [str(item) for item in value]


def _warning_map(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, list):
        return {str(item): "declared warning-only auth mechanism" for item in value}
    if not isinstance(value, dict):
        raise TypeError("warning auth mechanisms must be a YAML mapping or sequence")
    return {str(key): str(msg) for key, msg in value.items()}


def load_auth_catalog(
    *, path: Path | None = None, arch: dict[str, Any] | None = None
) -> tuple[set[str], dict[str, str]]:
    """Return allowed and warning-only auth mechanisms.

    Systems may add local entries under ``auth_mechanisms.allowed`` or
    ``auth_mechanisms.warn`` in architecture.yaml. Unknown values still fail;
    warning-only values are accepted but reported by source validation.
    """

    catalog_path = path or DEFAULT_CATALOG
    with catalog_path.open(encoding="utf-8") as f:
        catalog = yaml.safe_load(f) or {}
    if catalog.get("version") != 1:
        raise ValueError(f"{catalog_path} must declare version: 1")

    allowed = set(_string_list(catalog.get("allowed")))
    warnings = _warning_map(catalog.get("warn"))

    overrides = (arch or {}).get("auth_mechanisms") or {}
    if overrides:
        if not isinstance(overrides, dict):
            raise TypeError("architecture auth_mechanisms must be a mapping")
        allowed.update(_string_list(overrides.get("allowed")))
        warnings.update(_warning_map(overrides.get("warn")))

    return allowed, warnings
