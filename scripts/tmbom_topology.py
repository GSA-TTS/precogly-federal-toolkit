"""Normalize legacy Precogly fields into CycloneDX 2.0 TM-BOM shapes.

Provided by ``compliance/lib/cyclonedx_tmbom.py`` in the vendored ``oscal-vault-core``;
re-exported here so existing callers keep one import path.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vault_core

if not vault_core.available("cyclonedx_tmbom"):
    raise ImportError(
        "vendor/oscal-vault-core is missing or predates cyclonedx_tmbom; "
        "run: git submodule update --init vendor/oscal-vault-core"
    )

_core = vault_core.load("cyclonedx_tmbom")
_property = _core._property
_label = _core._label
normalize_scenario_threats = _core.normalize_scenario_threats
project_tmbom_topology = _core.project_tmbom_topology

__all__ = [
    "_label",
    "_property",
    "normalize_scenario_threats",
    "project_tmbom_topology",
]
