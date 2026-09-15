"""Async RouterOS client over the binary API (port 8728 / 8729 TLS).

Why not SSH: the server this replaces drove `/ip firewall filter print` over an
SSH shell and parsed the text back. That approach cannot see a rule's real
`.id` — the CLI prints *positional* numbers — so its write tools looked rules
up with `where .id=<position>`, which matches nothing, and every write failed
with "not found" on rules that plainly existed.

The binary API returns real `.id` values (`*1`, `*a`, `*1f`) on every read, so
IDs round-trip exactly and the entire class of bug disappears.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from dataclasses import dataclass
from typing import Any

import librouteros
from librouteros.exceptions import LibRouterosError, TrapError

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0


class RouterError(RuntimeError):
    """A RouterOS-side failure worth showing the user verbatim."""


@dataclass(frozen=True)
class RouterConfig:
    host: str
    username: str
    password: str
    port: int = 8729
    use_tls: bool = True
    tls_fingerprint: str = ""
    """Optional SHA-256 of the device certificate, hex, colons optional.

    MikroTik ships a self-signed API-SSL certificate, so ordinary CA validation
    can never succeed against a stock device. Pinning the fingerprint gives
    real protection against interception without requiring you to run a CA.
    """
    timeout: float = DEFAULT_TIMEOUT


def _ssl_context() -> ssl.SSLContext:
    """A context that completes the handshake without asserting CA trust.

    Trust is established by fingerprint pinning after the handshake (see
    `_verify_fingerprint`) when one is configured. RouterOS also offers only a
    narrow cipher set on API-SSL, hence the relaxed security level.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:  # pragma: no cover - depends on the OpenSSL build
        pass
    return ctx


def _normalise_fingerprint(value: str) -> str:
    return value.replace(":", "").replace(" ", "").strip().lower()


class RouterOS:
    """One lazily-established, reused connection to a single device.

    RouterOS drops idle API sessions, so every call is prepared to reconnect
    once. The lock serialises commands: the binary API multiplexes by tag, but
    a single connection object is not safe to drive from several tasks at once.
    """

    def __init__(self, config: RouterConfig) -> None:
        self._cfg = config
        self._api: Any | None = None
        self._lock = asyncio.Lock()

    # ── connection ────────────────────────────────────────────────────────

    async def _connect(self) -> Any:
        cfg = self._cfg
        kwargs: dict[str, Any] = {
            "host": cfg.host,
            "username": cfg.username,
            "password": cfg.password,
            "port": cfg.port,
            "timeout": cfg.timeout,
        }
        if cfg.use_tls:
            kwargs["ssl_wrapper"] = _ssl_context()

        try:
            api = await asyncio.wait_for(librouteros.async_connect(**kwargs), timeout=cfg.timeout + 5)
        except TrapError as exc:
            # RouterOS returns exactly this for a user whose group lacks the
            # `api` policy, as well as for genuinely wrong credentials, so the
            # message has to name both causes or the second one is invisible.
            raise RouterError(
                f"RouterOS rejected the login for {cfg.username!r}: {exc}\n"
                f"  Check the username exists (`/user print`) and that its group has the "
                f"`api` policy (`/user group print`) — a missing policy gives this same error."
            ) from exc
        except asyncio.TimeoutError as exc:
            raise RouterError(
                f"Timed out connecting to {cfg.host}:{cfg.port}. Check that the "
                f"{'api-ssl' if cfg.use_tls else 'api'} service is enabled and reachable."
            ) from exc
        except (OSError, LibRouterosError) as exc:
            raise RouterError(f"Could not connect to {cfg.host}:{cfg.port}: {exc}") from exc

        if cfg.use_tls and cfg.tls_fingerprint:
            self._verify_fingerprint(api)
        return api

    def _verify_fingerprint(self, api: Any) -> None:
        expected = _normalise_fingerprint(self._cfg.tls_fingerprint)
        der = self._peer_cert(api)
        if der is None:
            raise RouterError("A TLS fingerprint is configured but the peer certificate was unavailable.")
        actual = hashlib.sha256(der).hexdigest()
        if actual != expected:
            raise RouterError(
                "TLS fingerprint mismatch — refusing to talk to this device.\n"
                f"  expected: {expected}\n  actual:   {actual}\n"
                "Either the device certificate was regenerated (update the pin) "
                "or the connection is being intercepted."
            )

    @staticmethod
    def _peer_cert(api: Any) -> bytes | None:
        """Dig the peer certificate out of whichever transport the API holds."""
        for attr in ("transport", "_transport"):
            transport = getattr(api, attr, None)
            if transport is None:
                continue
            for sub in ("writer", "_writer", "sock", "_sock"):
                obj = getattr(transport, sub, None)
                if obj is None:
                    continue
                sslobj = obj.get_extra_info("ssl_object") if hasattr(obj, "get_extra_info") else obj
                if sslobj is not None and hasattr(sslobj, "getpeercert"):
                    return sslobj.getpeercert(binary_form=True)
        return None

    async def _api_handle(self) -> Any:
        if self._api is None:
            self._api = await self._connect()
        return self._api

    async def close(self) -> None:
        async with self._lock:
            if self._api is not None:
                try:
                    await self._api.close()
                except Exception:  # noqa: BLE001 - closing must never raise
                    log.debug("error closing RouterOS connection", exc_info=True)
                self._api = None

    async def _call(self, fn_name: str, path: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
        """Run one API operation, reconnecting once if the session went away.

        `fn_name` is either a method on `AsyncPath` to await, or one of three
        modes that have to be *iterated* instead: `librouteros` splits its API
        between coroutines (`add`, `update`, `remove`) and async generator
        functions (`__aiter__`, `__call__`, `rawCmd`). Awaiting a generator
        function raises `TypeError` before a single byte reaches the device,
        so telling the two apart is not a style choice.
        """
        async with self._lock:
            for attempt in (1, 2):
                api = await self._api_handle()
                try:
                    target = api.path(*path)
                    if fn_name == "iter":
                        return [dict(row) async for row in target]
                    if fn_name == "cmd":
                        # `AsyncPath.__call__` is an async *generator* function.
                        # Awaiting it is the bug that made every `move` fail
                        # with a bare "Error executing tool" and no RouterOS
                        # message: the generator body never ran, so nothing was
                        # sent and nothing came back to explain the silence.
                        return [dict(row) async for row in target(*args, **kwargs)]
                    if fn_name == "raw":
                        # Query words (`?list=blocked`) are filtered by the
                        # device. The alternative — pulling every row and
                        # filtering here — is untenable on an address list with
                        # tens of thousands of entries.
                        return [dict(row) async for row in api.rawCmd(*args)]
                    return await getattr(target, fn_name)(*args, **kwargs)
                except TrapError as exc:
                    # A trap is RouterOS saying no — a bad argument, a missing
                    # item. Reconnecting would not change the answer.
                    raise RouterError(str(exc)) from exc
                except (OSError, LibRouterosError, asyncio.IncompleteReadError) as exc:
                    self._api = None
                    if attempt == 2:
                        raise RouterError(f"RouterOS connection failed: {exc}") from exc
                    log.info("RouterOS session dropped, reconnecting (%s)", exc)
        raise AssertionError("unreachable")

    # ── operations ────────────────────────────────────────────────────────

    async def list(self, *path: str) -> list[dict[str, Any]]:
        """Every item at a path, each carrying its real `.id`."""
        return _jsonable(await self._call("iter", path))

    async def get(self, *path: str, item_id: str) -> dict[str, Any] | None:
        for item in await self.list(*path):
            if item.get(".id") == item_id:
                return item
        return None

    async def add(self, *path: str, **fields: Any) -> str:
        """Create an item; returns the new `.id`."""
        return await self._call("add", path, **_ros_values(fields))

    async def update(self, *path: str, item_id: str, **fields: Any) -> None:
        await self._call("update", path, **{".id": item_id, **_ros_values(fields)})

    async def remove(self, *path: str, item_id: str) -> None:
        await self._call("remove", path, item_id)

    async def run(self, *path: str, command: str, **fields: Any) -> list[dict[str, Any]]:
        """Invoke a non-CRUD command such as `move`, `make-static` or `unset`."""
        return _jsonable(await self._call("cmd", path, command, **_ros_values(fields)))

    async def unset(self, *path: str, item_id: str, field: str) -> None:
        """Clear one property, returning it to its RouterOS default.

        RouterOS takes a single `value-name` per call, so clearing several
        fields is several calls. Setting a property to an empty string is not
        the same operation: for `src-address` that is a validation error, and
        for `comment` it leaves an empty comment rather than no comment.
        """
        await self.run(*path, command="unset", **{".id": item_id, "value-name": field})

    async def move(self, *path: str, item_id: str, destination: str | None = None) -> None:
        """Move an item before `destination`, or to the end of the list.

        Both ends are real `.id` values. RouterOS also accepts ordinals here,
        and they are exactly what must not be used: the list shifts under any
        concurrent change, so an ordinal read a moment ago can address a
        different rule by the time it arrives.
        """
        fields: dict[str, Any] = {"numbers": item_id}
        if destination is not None:
            fields["destination"] = destination
        await self.run(*path, command="move", **fields)

    async def query(
        self, *path: str, where: dict[str, str] | None = None, proplist: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        """List items, filtered and projected *by the device*.

        `/ip/firewall/address-list` routinely holds tens of thousands of
        entries. Fetching all of them to keep a handful is slow enough to hit
        the API timeout, so the predicate travels to the router instead.
        """
        cmd = "/" + "/".join((*path, "print"))
        predicates = [f"?{key}={value}" for key, value in (where or {}).items()]
        words: list[str] = []
        if proplist:
            words.append("=.proplist=" + ",".join(proplist))
        words.extend(predicates)
        # RouterOS evaluates query words as a stack. Combining them is left to
        # the caller, so the AND is written out rather than assumed: get this
        # wrong and `list=x` plus `dynamic=no` silently matches either set.
        words.extend(["?#&"] * max(0, len(predicates) - 1))
        return _jsonable(await self._call("raw", path, cmd, *words))

    async def count(self, *path: str, where: dict[str, str] | None = None) -> int:
        """How many items match, without transferring them.

        `.proplist=.id` is the smallest row RouterOS will return; there is no
        server-side count in the binary API.
        """
        return len(await self.query(*path, where=where, proplist=(".id",)))


def _ros_values(fields: dict[str, Any]) -> dict[str, Any]:
    """Translate Python values into what the RouterOS API expects.

    Booleans are the trap: RouterOS wants the strings "yes"/"no", and a bare
    Python True would be sent as something the device silently misreads.
    `None` means "caller did not supply this", so it is dropped rather than
    sent as an empty value that would clear the field.
    """
    out: dict[str, Any] = {}
    for key, value in fields.items():
        if value is None:
            continue
        api_key = key.replace("_", "-") if not key.startswith(".") else key
        if isinstance(value, bool):
            out[api_key] = "yes" if value else "no"
        else:
            out[api_key] = str(value)
    return out


def _jsonable(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v)) for k, v in row.items()} for row in rows]
