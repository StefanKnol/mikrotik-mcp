"""mcphub plugin shim.

Lets mcphub load this package in-process, with typed fields in its settings UI
instead of a command line. Optional: the module imports from `mcphub`, which is
only ever present when mcphub itself is the thing loading the entry point, and
mcphub skips a plugin that fails to import.

The isolated route — mcphub launching `uvx mikrotik-mcp` as a subprocess — is
the better default for most people, because a plugin loaded into the hub can
read every credential the hub holds and this one cannot be made to forget that.
Use this shim when you are building your own image and want the nicer form.

Subclassing `PluginDefaults` rather than starting from nothing is what supplies
`variant()`, which builds the instance for a pinned version. Writing that by
hand means listing `BackendInstance` fields, and a field added to the hub later
would then be dropped — silently, and only at a pinned version, which is the
hardest kind of difference to notice.

This plugin does not ask for a data directory. Everything it reads and writes
lives on the router; there is no local state to keep, and a path the hub names
but nothing uses is clutter on the settings page.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcphub.plugins.base import (
    BackendInstance,
    CheckResult,
    ConfigField,
    FieldError,
    PluginDefaults,
)

from .client import RouterConfig, RouterError, RouterOS
from .server import build_server


def _config(instance: BackendInstance) -> RouterConfig:
    return RouterConfig(
        host=str(instance.get("host", "")).strip(),
        username=str(instance.get("username", "")).strip(),
        password=str(instance.get("password", "")),
        port=int(instance.get("port", 8729) or 8729),
        use_tls=bool(instance.get("use_tls", True)),
        tls_fingerprint=str(instance.get("tls_fingerprint", "") or ""),
        timeout=float(instance.get("timeout", 10) or 10),
    )


class MikroTikPlugin(PluginDefaults):
    id = "mikrotik"
    name = "MikroTik RouterOS"
    description = (
        "Manage a MikroTik router over the RouterOS binary API: interfaces, "
        "addressing, firewall and NAT, DHCP, DNS, routes and logs."
    )

    fields = (
        ConfigField("host", "Host", help="IP address or hostname of the router.", placeholder="192.168.88.1"),
        ConfigField(
            "port", "API port", type="number", default=8729,
            help="8729 for the TLS API (api-ssl), 8728 for plaintext. Enable the service under IP > Services.",
        ),
        ConfigField(
            "use_tls", "Use TLS", type="bool", default=True, required=False,
            help="Strongly recommended. Plaintext on 8728 sends the router password over the network in the clear.",
        ),
        ConfigField(
            "username", "Username", placeholder="mcp-agent",
            help="Use a dedicated RouterOS user, not admin, so its access can be scoped and revoked on its own. "
                 "Its group must carry the `api` policy.",
        ),
        ConfigField("password", "Password", type="password", secret=True),
        ConfigField(
            "tls_fingerprint", "TLS fingerprint", required=False,
            help=(
                "Optional SHA-256 of the router's certificate. MikroTik's API-SSL certificate is "
                "self-signed, so normal CA validation cannot apply; pinning this is what makes the "
                "TLS connection meaningfully authenticated rather than merely encrypted."
            ),
            placeholder="ab:cd:ef:...",
        ),
        ConfigField("timeout", "Timeout (seconds)", type="number", default=10, required=False),
    )

    def validate(self, instance: BackendInstance) -> list[FieldError]:
        """Refuse a configuration that cannot work, field by field.

        Each of these otherwise surfaces as a connection failure at `check`
        time, where the real cause is a typo three fields up.
        """
        errors: list[FieldError] = []

        try:
            port = int(instance.get("port", 8729) or 8729)
        except (TypeError, ValueError):
            errors.append(FieldError("port", "Must be a whole number, e.g. 8729."))
        else:
            if not 1 <= port <= 65535:
                errors.append(FieldError("port", "Must be between 1 and 65535."))

        fingerprint = str(instance.get("tls_fingerprint", "") or "").strip()
        if fingerprint:
            if not instance.get("use_tls", True):
                errors.append(FieldError(
                    "tls_fingerprint",
                    "Not used while TLS is off — there is no certificate to pin.",
                ))
            else:
                digits = fingerprint.replace(":", "").replace(" ", "")
                if len(digits) != 64 or not all(c in "0123456789abcdefABCDEF" for c in digits):
                    errors.append(FieldError(
                        "tls_fingerprint",
                        "A SHA-256 fingerprint is 64 hex characters, with or without colons. "
                        "Read it from the router with `/certificate print detail`.",
                    ))

        try:
            timeout = float(instance.get("timeout", 10) or 10)
        except (TypeError, ValueError):
            errors.append(FieldError("timeout", "Must be a number of seconds."))
        else:
            if timeout <= 0:
                errors.append(FieldError("timeout", "Must be greater than zero."))

        return errors

    def build(self, instance: BackendInstance) -> MCPServer:
        return build_server(_config(instance), title=instance.title, name=f"mikrotik-{instance.slug}")

    async def check(self, instance: BackendInstance) -> CheckResult:
        config = _config(instance)
        if not config.host or not config.username:
            return CheckResult(False, "Host and username are required.")
        router = RouterOS(config)
        try:
            identity = await router.list("system", "identity")
            resource = await router.list("system", "resource")
            name = identity[0].get("name", "?") if identity else "?"
            version = resource[0].get("version", "?") if resource else "?"
            return CheckResult(True, f"Connected to {name} — RouterOS {version}")
        except RouterError as exc:
            return CheckResult(False, str(exc))
        except Exception as exc:  # noqa: BLE001 - surfaced verbatim in the UI
            return CheckResult(False, f"{type(exc).__name__}: {exc}")
        finally:
            await router.close()


PLUGIN = MikroTikPlugin()
