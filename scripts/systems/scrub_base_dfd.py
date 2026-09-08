#!/usr/bin/env python3
"""Scrub editor-injected sensitive fields from a system base DFD."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
ROOT = SCRIPTS.parent

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from validate import _FLAG_MAP, _load_forbidden  # noqa: E402

from systems.loader import DEFAULT_SYSTEM, load_system  # noqa: E402

DEFAULT_FIELDS = [
    "metadata.description",
    "metadata.tools[].name",
    "blueprints[].zones[].name",
    "blueprints[].zones[].description",
    "blueprints[].assets[].name",
    "blueprints[].assets[].description",
    "blueprints[].flows[].name",
    "blueprints[].flows[].description",
]


@dataclass(frozen=True)
class Finding:
    path: str
    label: str
    action: str


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _placeholder(label: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]+", "_", label.upper()).strip("_") or "VALUE"
    return f"<REDACTED_{token}>"


def _redact_text(text: str, pattern: re.Pattern[str], label: str) -> tuple[str, bool]:
    if not pattern.search(text):
        return text, False
    replacement = _placeholder(label)
    if "URL" in label or "URI" in label:
        return re.sub(
            r"https?://[^\s\"'>,)\]]+", replacement, text, flags=re.IGNORECASE
        ), True
    return pattern.sub(replacement, text), True


def _compile_scrub_patterns(
    redaction_path: Path | None,
) -> list[tuple[re.Pattern[str], str]]:
    patterns = _load_forbidden(redaction_path)
    if not redaction_path:
        return patterns
    with redaction_path.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    for entry in (cfg.get("scrub") or {}).get("patterns", []) or []:
        pattern = entry.get("pattern")
        if not pattern:
            continue
        flags = 0
        for flag_name in entry.get("flags", []) or []:
            flags |= _FLAG_MAP.get(str(flag_name).upper(), 0)
        patterns.append(
            (re.compile(pattern, flags), entry.get("label", "scrub pattern"))
        )
    return patterns


def _scrub_fields(redaction_path: Path | None) -> list[str]:
    fields = list(DEFAULT_FIELDS)
    if not redaction_path:
        return fields
    with redaction_path.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    for field in (cfg.get("scrub") or {}).get("fields", []) or []:
        fields.append(str(field))
    return fields


def _walk_string_fields(root: Any, path_expr: str):
    parts = path_expr.split(".")

    def visit(value: Any, index: int, rendered: list[str]):
        if index == len(parts) - 1:
            key = parts[index]
            if isinstance(value, dict) and isinstance(value.get(key), str):
                yield value, key, ".".join([*rendered, key]), value[key]
            return
        part = parts[index]
        is_list = part.endswith("[]")
        key = part[:-2] if is_list else part
        if not isinstance(value, dict) or key not in value:
            return
        child = value[key]
        if is_list:
            if not isinstance(child, list):
                return
            for item_index, item in enumerate(child):
                yield from visit(item, index + 1, [*rendered, f"{key}[{item_index}]"])
        else:
            yield from visit(child, index + 1, [*rendered, key])

    yield from visit(root, 0, [])


def scrub_dfd(
    dfd: dict[str, Any], *, redaction_path: Path | None = None
) -> tuple[dict[str, Any], list[Finding]]:
    scrubbed = json.loads(json.dumps(dfd))
    findings: list[Finding] = []

    metadata = scrubbed.get("metadata")
    if isinstance(metadata, dict) and metadata.get("authors"):
        metadata.pop("authors", None)
        findings.append(Finding("metadata.authors", "metadata.authors", "removed"))

    patterns = _compile_scrub_patterns(redaction_path)
    for field in _scrub_fields(redaction_path):
        for parent, key, rendered_path, value in _walk_string_fields(scrubbed, field):
            redacted = value
            for pattern, label in patterns:
                redacted, changed = _redact_text(redacted, pattern, label)
                if changed:
                    findings.append(Finding(rendered_path, label, "redacted"))
            if redacted != value:
                parent[key] = redacted

    return scrubbed, findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system", nargs="?", default=DEFAULT_SYSTEM)
    parser.add_argument(
        "--check", action="store_true", help="fail if scrubbing would change the file"
    )
    args = parser.parse_args(argv)

    paths = load_system(args.system)
    if not paths.model_dfd:
        print(f"FAIL: {args.system} has no model/base-dfd.cdx.json", file=sys.stderr)
        return 1

    with paths.model_dfd.open(encoding="utf-8") as f:
        dfd = json.load(f)
    scrubbed, findings = scrub_dfd(dfd, redaction_path=paths.redaction)

    if findings:
        for finding in findings:
            print(f"{finding.action}: {finding.path} ({finding.label})")
        if args.check:
            print(
                f"FAIL: {_rel(paths.model_dfd)} needs pre-generation DFD scrubbing",
                file=sys.stderr,
            )
            return 1
        with paths.model_dfd.open("w", encoding="utf-8") as f:
            json.dump(scrubbed, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"Wrote scrubbed {_rel(paths.model_dfd)}")
        return 0

    print(f"OK: {_rel(paths.model_dfd)} needs no DFD scrubbing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
