"""The version appears in four places and they have to agree.

The registry validates that the PyPI package exists at exactly the version the
manifest names, so a manifest one step ahead of a release is rejected outright
rather than quietly ignored. The nested `packages[].version` is the one that
gets missed, because the file still validates against its schema without it.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def version() -> str:
    match = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M)
    assert match, "pyproject.toml has no version"
    return match.group(1)


def test_package_dunder_matches(version):
    source = (ROOT / "src" / "mikrotik_mcp" / "server.py").read_text()
    assert f'__version__ = "{version}"' in source


def test_manifest_version_matches(version):
    assert json.loads((ROOT / "server.json").read_text())["version"] == version


def test_manifest_package_version_matches(version):
    """The easy one to miss: the file validates fine without this agreeing."""
    for package in json.loads((ROOT / "server.json").read_text())["packages"]:
        assert package["version"] == version, (
            f"packages[{package['identifier']}] names {package['version']}, "
            f"but this release is {version} — the registry would reject it"
        )


def test_manifest_names_this_package_and_namespace():
    doc = json.loads((ROOT / "server.json").read_text())
    assert doc["name"] == "io.github.StefanKnol/mikrotik-mcp"
    assert [p["identifier"] for p in doc["packages"]] == ["mikrotik-mcp"]


def test_readme_carries_the_ownership_token():
    """Without it the registry cannot prove we own the PyPI package."""
    readme = (ROOT / "README.md").read_text()
    name = json.loads((ROOT / "server.json").read_text())["name"]
    assert re.search(rf"^mcp-name: {re.escape(name)}\s*$", readme, re.M), (
        "the `mcp-name:` token must be on its own line in the README, which is "
        "the PyPI description the registry validates against"
    )


def test_the_changelog_documents_this_version(version):
    """A version bump with nothing said about it is half a release.

    The changelog is the only place that records *why* a consumer's
    integration might need attention; the four version strings agreeing says
    nothing about what changed between them.
    """
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert re.search(rf"^## {re.escape(version)}\s*$", changelog, re.M), (
        f"CHANGELOG.md has no `## {version}` section — add one before releasing"
    )
