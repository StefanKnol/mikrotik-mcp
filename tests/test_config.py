"""Configuration from the environment, which is how a launched server is set up."""

import pytest

from mikrotik_mcp.config import from_env
from mikrotik_mcp.server import build_server


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ("HOST", "USERNAME", "PASSWORD", "PORT", "TLS", "TLS_FINGERPRINT", "TIMEOUT"):
        monkeypatch.delenv(f"MIKROTIK_{key}", raising=False)


def test_reads_the_environment(monkeypatch):
    monkeypatch.setenv("MIKROTIK_HOST", "192.168.88.1")
    monkeypatch.setenv("MIKROTIK_USERNAME", "mcp-agent")
    monkeypatch.setenv("MIKROTIK_PASSWORD", "s3cret")
    cfg = from_env()
    assert (cfg.host, cfg.username, cfg.password) == ("192.168.88.1", "mcp-agent", "s3cret")
    assert cfg.port == 8729 and cfg.use_tls is True


def test_arguments_win_over_the_environment(monkeypatch):
    monkeypatch.setenv("MIKROTIK_HOST", "from-env")
    monkeypatch.setenv("MIKROTIK_USERNAME", "u")
    assert from_env(host="from-args").host == "from-args"


def test_none_overrides_are_ignored(monkeypatch):
    """argparse hands us None for every flag the user did not pass."""
    monkeypatch.setenv("MIKROTIK_HOST", "192.168.88.1")
    monkeypatch.setenv("MIKROTIK_USERNAME", "u")
    assert from_env(host=None, port=None).host == "192.168.88.1"


def test_missing_settings_are_named(monkeypatch):
    monkeypatch.setenv("MIKROTIK_USERNAME", "u")
    with pytest.raises(SystemExit) as excinfo:
        from_env()
    assert "MIKROTIK_HOST" in str(excinfo.value)
    assert "MIKROTIK_USERNAME" not in str(excinfo.value), "only the missing ones should be listed"


@pytest.mark.parametrize("raw,expected", [("false", False), ("0", False), ("no", False),
                                          ("true", True), ("1", True), ("", True)])
def test_tls_toggle(monkeypatch, raw, expected):
    monkeypatch.setenv("MIKROTIK_HOST", "h")
    monkeypatch.setenv("MIKROTIK_USERNAME", "u")
    if raw:
        monkeypatch.setenv("MIKROTIK_TLS", raw)
    assert from_env().use_tls is expected


def test_password_is_not_stripped(monkeypatch):
    """A password may legitimately begin or end with a space."""
    monkeypatch.setenv("MIKROTIK_HOST", "h")
    monkeypatch.setenv("MIKROTIK_USERNAME", "u")
    monkeypatch.setenv("MIKROTIK_PASSWORD", "  padded  ")
    assert from_env().password == "  padded  "


async def test_build_server_performs_no_io():
    """An unreachable router must still produce a server.

    Otherwise a device that is merely down stops the whole process from
    starting, and the tools never get a chance to report why.
    """
    from mikrotik_mcp.client import RouterConfig

    server = build_server(RouterConfig(host="203.0.113.1", username="u", password="p", timeout=0.1))
    tools = await server.list_tools()
    assert len(tools) == 24
    assert "list_firewall_rules" in {t.name for t in tools}
