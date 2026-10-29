"""Threat-model validation primitives, provided by the vendored oscal-vault-core.

Re-exports ``compliance/lib/threat_model_checks.py`` so ``validate_vault`` and ``validate`` keep
one import path.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vault_core

_checks = vault_core.load("threat_model_checks")
CATEGORIES = _checks.CATEGORIES
STATUSES = _checks.STATUSES
RISK_LEVELS = _checks.RISK_LEVELS
FORBIDDEN_PATTERNS = _checks.FORBIDDEN_PATTERNS
find_ipv4_leak = _checks.find_ipv4_leak
find_leaks = _checks.find_leaks
bidirectional_control_threat_errors = _checks.bidirectional_control_threat_errors
