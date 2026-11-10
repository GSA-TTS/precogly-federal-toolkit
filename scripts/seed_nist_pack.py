#!/usr/bin/env python3
"""
seed_nist_pack.py — deploy the NIST 800-53r5 compliance pack to a Precogly instance.

Supports two backends:
  docker  -- docker exec into a local 'precogly-backend' container (default)
  cf      -- CF run-task against a Cloud Foundry app (e.g. precogly.app.cloud.gov)

Usage:
    # Local Docker
    python3 scripts/seed_nist_pack.py

    # Cloud Foundry
    python3 scripts/seed_nist_pack.py --backend cf [--cf-app precogly]

    # Dry-run: print the Django shell payload without executing
    python3 scripts/seed_nist_pack.py --dry-run
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vault_core

ROOT = Path(__file__).resolve().parent.parent
PACK_YAML = (
    ROOT / "templates" / "generic-crm-system" / "pack-oscal-800-53r5" / "pack.yaml"
)
CONTAINER = os.environ.get("PRECOGLY_CONTAINER", "precogly-backend")
# Cloud Controller limit on `cf run-task --command` (COMMAND_MAX_LENGTH).
CF_COMMAND_MAX_LENGTH = 4096
CF_APP_DEFAULT = os.environ.get("PRECOGLY_CF_APP", "precogly")


def full_catalog_pack_bytes() -> bytes | None:
    """The shipped pack with every NIST 800-53 Rev. 5 control, from the vendored core.

    The checked-in pack lists only the requirements seen in one earlier set of parsed files
    (218 of 1196), so a system citing any other control imports with no framework link. Returns
    None when the core predates ``nist_standard``.
    """
    if not vault_core.available("nist_standard"):
        return None
    import yaml

    nist = vault_core.load("nist_standard")
    pack = yaml.safe_load(PACK_YAML.read_text(encoding="utf-8"))
    pack["frameworks"][0]["requirements"] = [
        {
            "section_code": req["identifier"],
            "description": req.get("text") or req["title"],
        }
        for req in map(nist.requirement, nist.catalog_control_ids())
    ]
    return yaml.safe_dump(pack, sort_keys=False, allow_unicode=True).encode("utf-8")


def _build_django_snippet(pack_b64: str) -> str:
    return f"""
import base64, tempfile, json
from pathlib import Path
PACK_B64 = {json.dumps(pack_b64)}
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp) / "nist-800-53-r5"
    p.mkdir()
    (p / "pack.yaml").write_bytes(base64.b64decode(PACK_B64))
    from apps.packs.services import import_pack_from_path
    result = import_pack_from_path(p, force=True)
    print(json.dumps({{"success": result.success, "message": result.message}}))
""".strip()


def _run_container(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], **kwargs)
    except FileNotFoundError:
        return subprocess.run(["podman", *args], **kwargs)


def app_dir() -> str:
    """Where manage.py lives: /app/backend in current Precogly images, /app in v0.3.0-era ones."""
    probe = _run_container(
        ["exec", CONTAINER, "test", "-f", "/app/backend/manage.py"],
        capture_output=True,
    )
    return "/app/backend" if probe.returncode == 0 else "/app"


def run_docker(snippet: str) -> str:
    """Run the snippet in the backend's Django shell.

    The snippet goes over stdin, not ``-c``: it embeds the whole pack, and one command-line
    argument is limited to 128 KB on Linux (the full catalog pack is about 424 KB).
    """
    cmd = [
        "exec",
        "-i",
        "-w",
        app_dir(),
        CONTAINER,
        "python",
        "manage.py",
        "shell",
    ]
    result = _run_container(cmd, input=snippet, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout.strip()


def run_cf(snippet: str, cf_app: str) -> str:
    import uuid

    task_name = f"seed-nist-pack-{uuid.uuid4().hex[:8]}"
    # `cf run-task --command` is executed by a shell, so a multi-line snippet with
    # quotes/backslashes cannot be passed inline (escaping newlines as a literal
    # backslash-n yields a Python SyntaxError). Base64 contains only [A-Za-z0-9+/=],
    # so it is safe inside the quotes below with no escaping at all. The snippet is
    # zlib-compressed first because CF rejects commands over CF_COMMAND_MAX_LENGTH.
    payload = base64.b64encode(zlib.compress(snippet.encode(), 9)).decode()
    command = (
        'python manage.py shell -c "import base64,zlib;'
        f"exec(zlib.decompress(base64.b64decode('{payload}')).decode(),{{}})\""
    )
    if len(command) > CF_COMMAND_MAX_LENGTH:
        print(
            f"ERROR: CF task command is {len(command)} chars; "
            f"cf run-task allows at most {CF_COMMAND_MAX_LENGTH}.",
            file=sys.stderr,
        )
        sys.exit(1)
    cmd = [
        "cf",
        "run-task",
        cf_app,
        "--command",
        command,
        "--name",
        task_name,
        "--memory",
        "256M",
    ]
    print(f"Submitting CF task: {task_name}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    print(result.stdout)
    print(
        f"Task submitted. To see output: cf logs {cf_app} --recent | grep {task_name}"
    )
    return ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed NIST 800-53r5 pack into Precogly")
    ap.add_argument(
        "--backend",
        choices=["docker", "cf"],
        default="docker",
        help="Runtime backend (default: docker)",
    )
    ap.add_argument(
        "--cf-app",
        default=CF_APP_DEFAULT,
        help=f"CF app name (default: {CF_APP_DEFAULT})",
    )
    ap.add_argument(
        "--catalog",
        choices=["full", "observed"],
        default=None,
        help="'full': every Rev. 5 control from the vendored core (default for docker). "
        "'observed': the checked-in pack (218 requirements; default for cf, whose task command "
        "is limited to 4096 characters).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print Django shell snippet without executing",
    )
    args = ap.parse_args()

    if not PACK_YAML.exists():
        print(f"ERROR: pack.yaml not found at {PACK_YAML}", file=sys.stderr)
        sys.exit(1)

    catalog = args.catalog or ("full" if args.backend == "docker" else "observed")
    if catalog == "full" and args.backend == "cf":
        print(
            "ERROR: the full catalog pack cannot be sent through cf run-task "
            f"(limit {CF_COMMAND_MAX_LENGTH} characters). Use --catalog observed.",
            file=sys.stderr,
        )
        sys.exit(1)
    pack_bytes = full_catalog_pack_bytes() if catalog == "full" else None
    if catalog == "full" and pack_bytes is None:
        print(
            "WARN: vendor/oscal-vault-core has no nist_standard; seeding the checked-in "
            "218-requirement pack (git submodule update --init vendor/oscal-vault-core)",
            file=sys.stderr,
        )
    pack_b64 = base64.b64encode(pack_bytes or PACK_YAML.read_bytes()).decode()
    snippet = _build_django_snippet(pack_b64)

    if args.dry_run:
        print("--- Django shell snippet (dry-run) ---")
        print(snippet)
        return

    print(f"Seeding NIST 800-53r5 pack via {args.backend} backend...")
    if args.backend == "docker":
        output = run_docker(snippet)
        print(output)
        try:
            result = json.loads(output.splitlines()[-1])
            if result.get("success"):
                print("Pack seeded successfully.")
            else:
                print(f"WARNING: {result.get('message')}", file=sys.stderr)
        except (json.JSONDecodeError, IndexError):
            pass
    else:
        run_cf(snippet, args.cf_app)


if __name__ == "__main__":
    main()
