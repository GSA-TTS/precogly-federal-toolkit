#!/usr/bin/env python3
"""Validate every fenced ```mermaid block in the repository's Markdown.

Mermaid's newer diagram types (kanban, sankey, railroad, wardley) fail silently
in a Markdown renderer: GitHub shows the raw fence or an error box rather than
refusing the commit.  This parses each block with the real Mermaid parser so a
syntax error is a build failure instead of a broken README.

Requires Node with `mermaid` and `jsdom` resolvable.  The harness is written to
a temporary directory; nothing is installed into the repository.

Usage:
  uv run python scripts/validate_mermaid_blocks.py [path ...]

With no paths, scans tracked Markdown outside generated and vendored trees.
Exits non-zero on the first failing block, naming the file and fence number.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

import vault_core  # noqa: E402

# Generated, vendored, or submodule trees own their own link and diagram
# hygiene; scanning them reports failures this repository cannot fix.
EXCLUDED_PREFIXES = (
    "build/",
    "tmp/",
    "vendor/",
    "oss/",
    "schemas/",
    "node_modules/",
    ".precogly/",
    ".pytest_cache/",
)

FENCE = re.compile(r"^[ \t]*```mermaid[ \t]*$(.*?)^[ \t]*```[ \t]*$", re.M | re.S)

HARNESS = """
import { JSDOM } from 'jsdom';
import fs from 'node:fs';

const dom = new JSDOM('<!doctype html><html><body></body></html>', {
  pretendToBeVisual: true,
});
global.window = dom.window;
global.document = dom.window.document;
global.MutationObserver = dom.window.MutationObserver;
// `navigator` is getter-only on newer Node, so assignment throws.
Object.defineProperty(global, 'navigator', {
  value: dom.window.navigator,
  configurable: true,
});

const mermaid = (await import('mermaid')).default;
mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

const jobs = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const results = [];
for (const job of jobs) {
  try {
    await mermaid.parse(job.text);
    results.push({ id: job.id, ok: true });
  } catch (error) {
    results.push({
      id: job.id,
      ok: false,
      message: String(error?.message ?? error).split('\\n')[0],
    });
  }
}
fs.writeFileSync(process.argv[3], JSON.stringify(results));
"""


def _candidate_files(paths: list[Path]) -> list[Path]:
    if paths:
        return [path for path in paths if path.suffix == ".md" and path.is_file()]
    tracked = subprocess.check_output(
        ["git", "-C", str(REPO), "ls-files", "*.md"], text=True
    ).splitlines()
    return [
        REPO / name
        for name in tracked
        if not name.startswith(EXCLUDED_PREFIXES) and (REPO / name).is_file()
    ]


def collect_blocks(files: list[Path]) -> list[dict[str, str]]:
    """Return one job per fenced mermaid block, labelled by file and index."""
    jobs: list[dict[str, str]] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for index, match in enumerate(FENCE.finditer(text), start=1):
            relative = path.relative_to(REPO) if path.is_relative_to(REPO) else path
            jobs.append(
                {
                    "id": f"{relative}#mermaid-{index}",
                    "text": match.group(1).strip("\n"),
                }
            )
    return jobs


C4_HEADERS = ("C4Context", "C4Container", "C4Component", "C4Dynamic", "C4Deployment")
READABILITY_LIMITS = {
    "elements": 20,
    "longest_label": 80,
    "max_degree": 8,
}


def is_c4_block(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%%"):
            continue
        return stripped.startswith(C4_HEADERS)
    return False


def validate_c4_block(text: str) -> tuple[list[str], list[str]]:
    """Run structural C4 validation and rubric readability checks via oscal-vault-core."""
    if not vault_core.available("topology_eval"):
        return [], []
    topology_eval = vault_core.load("topology_eval")
    report = topology_eval.validate_generated_c4(text)
    errors: list[str] = list(report.get("syntax_errors") or [])
    if not report.get("has_title"):
        errors.append("missing title")
    for orphan in report.get("orphan_elements") or []:
        errors.append(f"orphan element {orphan}")

    stats = topology_eval.readability(None, text)
    warnings: list[str] = []
    if stats["elements"] > READABILITY_LIMITS["elements"]:
        warnings.append(
            f"element count {stats['elements']} exceeds readability limit {READABILITY_LIMITS['elements']}"
        )
    if stats["longest_label"] > READABILITY_LIMITS["longest_label"]:
        warnings.append(
            f"relationship label length {stats['longest_label']} exceeds readability limit {READABILITY_LIMITS['longest_label']}"
        )
    if stats["max_degree"] > READABILITY_LIMITS["max_degree"]:
        warnings.append(
            f"max node degree {stats['max_degree']} exceeds readability limit {READABILITY_LIMITS['max_degree']}"
        )
    return errors, warnings


def validate_c4_blocks(
    jobs: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return ``(failures, warnings)`` across all ``C4*`` jobs."""
    failures: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    for job in jobs:
        if not is_c4_block(job["text"]):
            continue
        errs, warns = validate_c4_block(job["text"])
        for err in errs:
            failures.append({"id": job["id"], "ok": False, "message": err})
        for warn in warns:
            warnings.append({"id": job["id"], "message": warn})
    return failures, warnings


def _node_modules() -> Path | None:
    """A directory containing both `mermaid` and `jsdom`, or None."""
    for base in (REPO, Path.cwd()):
        modules = base / "node_modules"
        if (modules / "mermaid").is_dir() and (modules / "jsdom").is_dir():
            return modules
    return None


def run_parser(jobs: list[dict[str, str]], modules: Path) -> list[dict]:
    with tempfile.TemporaryDirectory() as work_name:
        work = Path(work_name)
        (work / "check.mjs").write_text(HARNESS, encoding="utf-8")
        (work / "jobs.json").write_text(json.dumps(jobs), encoding="utf-8")
        # Symlink rather than copy: the dependency tree is large and this is a
        # read-only use of it.
        (work / "node_modules").symlink_to(modules, target_is_directory=True)
        (work / "package.json").write_text('{"type":"module"}', encoding="utf-8")
        results = work / "results.json"
        completed = subprocess.run(
            ["node", "check.mjs", "jobs.json", "results.json"],
            cwd=work,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0 or not results.is_file():
            raise RuntimeError(
                "mermaid parser harness failed:\n"
                + (completed.stderr or completed.stdout).strip()
            )
        return json.loads(results.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args(argv)

    files = _candidate_files([path.resolve() for path in args.paths])
    jobs = collect_blocks(files)
    if not jobs:
        print("OK - no mermaid blocks found")
        return 0

    c4_failures, c4_warnings = validate_c4_blocks(jobs)
    for warning in c4_warnings:
        print(f"WARN {warning['id']}: {warning['message']}")

    if shutil.which("node") is None:
        for failure in c4_failures:
            print(f"FAIL {failure['id']}: {failure['message']}")
        if c4_failures:
            return 1
        print("SKIP - node is not available; mermaid blocks were not parsed")
        return 0

    modules = _node_modules()
    if modules is None:
        for failure in c4_failures:
            print(f"FAIL {failure['id']}: {failure['message']}")
        if c4_failures:
            return 1
        print(
            "SKIP - mermaid and jsdom are not installed "
            "(npm install mermaid jsdom); blocks were not parsed"
        )
        return 0

    results = run_parser(jobs, modules)
    failures = [result for result in results if not result["ok"]] + c4_failures
    for failure in failures:
        print(f"FAIL {failure['id']}: {failure.get('message', 'parse error')}")
    if failures:
        failed_ids = {failure["id"] for failure in failures}
        print(f"\n{len(failed_ids)} of {len(jobs)} mermaid block(s) failed validation")
        return 1
    print(f"OK - {len(jobs)} mermaid block(s) parsed across {len(files)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
