#!/usr/bin/env python
"""Set the version everywhere it appears, then tag.

The version lives in three places that must agree: pyproject.toml, the
package's __version__, and server.json — which additionally repeats it inside
its `packages` entry, pointing at the PyPI release. The registry treats each
version as its own row and validates that the package exists at exactly that
version, so a manifest a step ahead of PyPI is rejected rather than ignored.

    uv run python scripts/release.py 0.2.0          # edit and show the diff
    uv run python scripts/release.py 0.2.0 --tag    # also commit and tag
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.]+)?$")


def read_current() -> str:
    match = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M)
    if not match:
        raise SystemExit("could not find the version in pyproject.toml")
    return match.group(1)


def set_pyproject(version: str) -> None:
    path = ROOT / "pyproject.toml"
    text, count = re.subn(r'^version = "[^"]+"', f'version = "{version}"',
                          path.read_text(), count=1, flags=re.M)
    if count != 1:
        raise SystemExit("pyproject.toml: version line not found")
    path.write_text(text)


def set_dunder(version: str) -> None:
    path = ROOT / "src" / "mikrotik_mcp" / "server.py"
    text, count = re.subn(r'^__version__ = "[^"]+"', f'__version__ = "{version}"',
                          path.read_text(), count=1, flags=re.M)
    if count != 1:
        raise SystemExit("server.py: __version__ not found")
    path.write_text(text)


def set_manifest(version: str) -> None:
    """Both the server version and the package it points at.

    Missing the nested one is the easy mistake: the manifest validates, and the
    registry then rejects it for naming a PyPI version that does not exist.
    """
    path = ROOT / "server.json"
    doc = json.loads(path.read_text())
    doc["version"] = version
    for package in doc.get("packages") or []:
        package["version"] = version
    path.write_text(json.dumps(doc, indent=2) + "\n")


def verify(version: str) -> list[str]:
    problems = []
    if read_current() != version:
        problems.append("pyproject.toml")
    doc = json.loads((ROOT / "server.json").read_text())
    if doc.get("version") != version:
        problems.append("server.json version")
    for package in doc.get("packages") or []:
        if package.get("version") != version:
            problems.append(f"server.json packages[{package.get('identifier')}]")
    if f'__version__ = "{version}"' not in (ROOT / "src" / "mikrotik_mcp" / "server.py").read_text():
        problems.append("server.py __version__")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", help="New version, e.g. 0.2.0")
    parser.add_argument("--tag", action="store_true", help="Commit and create the v<version> tag")
    args = parser.parse_args()

    if not SEMVER.match(args.version):
        raise SystemExit(f"{args.version!r} does not look like a version")

    current = read_current()
    if current == args.version:
        raise SystemExit(f"already at {current}")
    print(f"{current} -> {args.version}")

    set_pyproject(args.version)
    set_dunder(args.version)
    set_manifest(args.version)

    problems = verify(args.version)
    if problems:
        raise SystemExit("version not applied to: " + ", ".join(problems))
    print("  pyproject.toml, server.py, server.json (including the package entry)")

    subprocess.run(["git", "--no-pager", "diff", "--stat"], cwd=ROOT, check=False)

    if not args.tag:
        print("\nReview, then re-run with --tag, or commit and tag by hand.")
        return 0

    if subprocess.run(["git", "diff", "--quiet", "--cached"], cwd=ROOT).returncode != 0:
        raise SystemExit("there are already staged changes; commit or reset them first")

    subprocess.run(["git", "add", "pyproject.toml", "server.json",
                    "src/mikrotik_mcp/server.py"], cwd=ROOT, check=True)
    subprocess.run(["git", "commit", "-m", f"Release {args.version}"], cwd=ROOT, check=True)
    subprocess.run(["git", "tag", f"v{args.version}"], cwd=ROOT, check=True)
    print(f"\nCommitted and tagged v{args.version}. Push with:")
    print(f"  git push && git push origin v{args.version}")
    print("Then, once PyPI has it:  ./mcp-publisher publish")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
