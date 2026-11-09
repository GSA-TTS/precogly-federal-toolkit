#!/usr/bin/env python3
"""Reject control-response wording that conflates declarations with runtime evidence."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSTEMS = ROOT / "data" / "systems"

PROHIBITED = (
    re.compile(r"declared model is verifiably the deployed model", re.IGNORECASE),
    re.compile(
        r"source(?:-level)? tests? (?:prove|verify) (?:the )?deployed", re.IGNORECASE
    ),
    re.compile(
        r"CI (?:proves|verifies) (?:the )?(?:live|runtime|deployed)", re.IGNORECASE
    ),
)


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _normalized_content(content: str) -> tuple[str, list[int]]:
    """Collapse whitespace and retain each normalized character's source offset."""
    characters: list[str] = []
    source_offsets: list[int] = []
    for word in re.finditer(r"\S+", content):
        if characters:
            characters.append(" ")
            source_offsets.append(word.start())
        characters.extend(word.group())
        source_offsets.extend(range(word.start(), word.end()))
    return "".join(characters), source_offsets


def find_claims(path: Path) -> list[str]:
    content = path.read_text(encoding="utf-8")
    normalized, source_offsets = _normalized_content(content)
    lines = content.splitlines()
    findings: list[str] = []
    for pattern in PROHIBITED:
        for match in pattern.finditer(normalized):
            offset = source_offsets[match.start()]
            number = content.count("\n", 0, offset) + 1
            findings.append(
                f"{_display_path(path)}:{number}: {lines[number - 1].strip()}"
            )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args(argv)
    paths = args.paths or sorted(SYSTEMS.glob("*/responses.yaml"))
    findings = [finding for path in paths for finding in find_claims(path)]
    if findings:
        print("FAIL: unqualified declared-versus-deployed evidence claims:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(f"OK - evidence claim wording valid across {len(paths)} response file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
