"""Canonical NIST control identity, provided by the vendored oscal-vault-core.

This module used to hold the implementation; it now re-exports the core's
``compliance/lib/control_identity.py`` so every adapter shares one definition. ``make test`` and the CI
workflows initialise the submodule; otherwise run
``git submodule update --init vendor/oscal-vault-core``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vault_core

if not vault_core.available("control_identity"):
    raise ImportError(
        "vendor/oscal-vault-core is missing or predates control_identity; "
        "run: git submodule update --init vendor/oscal-vault-core"
    )

_core = vault_core.load("control_identity")
ControlKey = _core.ControlKey
parse_control_id = _core.parse_control_id
canonical_control_id = _core.canonical_control_id
reject_duplicate_control_ids = _core.reject_duplicate_control_ids

__all__ = [
    "ControlKey",
    "canonical_control_id",
    "parse_control_id",
    "reject_duplicate_control_ids",
]
