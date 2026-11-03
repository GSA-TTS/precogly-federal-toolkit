"""Load modules from the vendored oscal-vault-core without clashing with other ``compliance`` trees."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

CORE_LIB = (
    Path(__file__).resolve().parent.parent
    / "vendor"
    / "oscal-vault-core"
    / "compliance"
    / "lib"
)
_PACKAGE = "oscal_vault_core_lib"


def available(module: str) -> bool:
    return (CORE_LIB / f"{module}.py").is_file()


def load(module: str) -> ModuleType:
    """Import ``compliance/lib/<module>.py`` from the core under a private package name."""
    if _PACKAGE not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            _PACKAGE,
            CORE_LIB / "__init__.py",
            submodule_search_locations=[str(CORE_LIB)],
        )
        package = importlib.util.module_from_spec(spec)
        sys.modules[_PACKAGE] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"{_PACKAGE}.{module}")
