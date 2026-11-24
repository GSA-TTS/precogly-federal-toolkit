"""Offline flow-binding validation; never contacts a running service."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    flows = commands.add_parser("flow-bindings", help="Validate architecture flow bindings")
    flows.add_argument("--architecture", type=Path, required=True)
    flows.add_argument("--cdx", type=Path, required=True)
    args = parser.parse_args(argv)
    from precogly_toolkit.flow_refs import first_blueprint, resolve_flow_bindings

    try:
        architecture = json.loads(args.architecture.read_text(encoding="utf-8"))
        cdx = json.loads(args.cdx.read_text(encoding="utf-8"))
        if not isinstance(architecture, dict) or not isinstance(cdx, dict):
            raise ValueError("architecture and CDX must be JSON objects")
        bindings, errors = resolve_flow_bindings(
            architecture.get("flow_bindings", {}), architecture, first_blueprint(cdx)
        )
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        print(f"FAIL: invalid input: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"bindings": bindings, "errors": errors}, sort_keys=True))
    return int(bool(errors))
