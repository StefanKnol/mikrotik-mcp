"""Connection settings, from arguments or the environment."""

from __future__ import annotations

import os

from .client import RouterConfig

ENV_PREFIX = "MIKROTIK_"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"{ENV_PREFIX}{name}", default).strip()


def _truthy(value: str, default: bool) -> bool:
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def from_env(**overrides: object) -> RouterConfig:
    """Build a RouterConfig from MIKROTIK_* variables, with explicit overrides.

    Environment rather than flags is the default because that is how an MCP
    client passes configuration to a server it launches, and it keeps the
    password off the process command line where `ps` would show it.
    """
    values: dict[str, object] = {
        "host": _env("HOST"),
        "username": _env("USERNAME"),
        "password": os.environ.get(f"{ENV_PREFIX}PASSWORD", ""),
        "port": int(_env("PORT") or 8729),
        "use_tls": _truthy(_env("TLS"), True),
        "tls_fingerprint": _env("TLS_FINGERPRINT"),
        "timeout": float(_env("TIMEOUT") or 10),
    }
    values.update({k: v for k, v in overrides.items() if v is not None})

    missing = [k for k in ("host", "username") if not values.get(k)]
    if missing:
        raise SystemExit(
            "mikrotik-mcp: missing required settings: "
            + ", ".join(f"{ENV_PREFIX}{k.upper()}" for k in missing)
            + "\n  Set them in the environment, or pass --host/--username."
        )
    return RouterConfig(**values)  # type: ignore[arg-type]
