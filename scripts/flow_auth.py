"""Legacy catalog path adapter over the installed toolkit engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from precogly_toolkit import flow_auth as _core

DEFAULT_CATALOG = Path(__file__).resolve().parents[1] / "data/catalog/flow-auth-mechanisms.yaml"
auth_mechanism_properties = _core.auth_mechanism_properties


def load_auth_catalog(*, path=None, arch=None):
    return _core.load_auth_catalog(path=path or DEFAULT_CATALOG, arch=arch)


def load_auth_metadata(*, path=None, arch=None):
    return _core.load_auth_metadata(path=path or DEFAULT_CATALOG, arch=arch)
