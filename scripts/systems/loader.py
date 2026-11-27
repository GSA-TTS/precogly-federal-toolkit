"""Legacy repository path bindings for the installed system-directory engine."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from precogly_toolkit import system_directory as _core

SYSTEMS_DIR = ROOT / "data/systems"
SCHEMA_PATH = ROOT / "schemas/system-directory.schema.json"
DEFAULT_SYSTEM = "example-system"
SystemPaths = _core.SystemPaths


def load_system(slug):
    return _core.load_system(slug, systems_dir=SYSTEMS_DIR, default_system=DEFAULT_SYSTEM)


def discover_systems():
    return _core.discover_systems(systems_dir=SYSTEMS_DIR)


def load_manifest(slug):
    return _core.load_manifest(slug, systems_dir=SYSTEMS_DIR, schema_path=SCHEMA_PATH)


def _cli(argv=None):
    return _core.cli(argv, repository=ROOT, systems_dir=SYSTEMS_DIR, schema_path=SCHEMA_PATH, default_system=DEFAULT_SYSTEM)


if __name__ == "__main__":
    raise SystemExit(_cli())
