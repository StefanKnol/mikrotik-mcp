"""MikroTik tools.

Two rules shape this module:

1. **Writes address rules by `.id`, never by position.** Every read returns the
   device's real `.id`; every write takes one back. If a rule is gone, the
   write fails cleanly instead of silently hitting whatever slid into its
   place. Positional indices are reported for humans and rejected for writes.
2. **Writes read back what they wrote**, so a caller can verify the change
   landed rather than trusting an "ok".
"""

from __future__ import annotations

import functools
import json
import logging
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .client import RouterError, RouterOS

log = logging.getLogger(__name__)

NAT = ("ip", "firewall", "nat")

# IPv4 and IPv6 filtering are separate tables with separate rules. A device can
# read as fully locked down on `ip/firewall/filter` while `ipv6/firewall/filter`
# is empty and therefore accepting everything, so the family is explicit
# wherever it applies rather than assumed.
FAMILIES = {"ipv4": "ip", "ipv6": "ipv6"}
Family = Literal["ipv4", "ipv6"]


def _filter_path(family: str) -> tuple[str, ...]:
    return (FAMILIES[family], "firewall", "filter")


def _address_list_path(family: str) -> tuple[str, ...]:
    return (FAMILIES[family], "firewall", "address-list")


# Actions that are not self-sufficient, mapped to the fields that complete them
# and what they are for. Satisfying *any* one of the listed fields is enough.
#
# RouterOS accepts each of these with its companion missing, stores the rule,
# and reports `invalid: false` — so the rule looks configured, reads as
# configured, and does nothing. Refusing is the kinder failure, and it is safe
# to refuse because no working rule has this shape.
ACTION_REQUIRES = {
    "add-src-to-address-list": (("address_list",), "the list to add the source address to"),
    "add-dst-to-address-list": (("address_list",), "the list to add the destination address to"),
    "jump": (("jump_target",), "the custom chain to jump to"),
}

# The same idea for NAT. Note the pair: `dst-nat` with only `to_ports` is a
# perfectly good rule — it rewrites the port and leaves the address alone — so
# the requirement is one *or* the other, never `to_addresses` specifically.
# `masquerade`, `redirect` and `accept` are complete on their own and are
# absent here on purpose.
NAT_ACTION_REQUIRES = {
    "dst-nat": (("to_addresses", "to_ports"), "an address or a port to send matching traffic to"),
    "src-nat": (("to_addresses", "to_ports"), "an address or a port to rewrite the source to"),
    "netmap": (("to_addresses", "to_ports"), "the address range to map onto"),
}

# Fields `update_firewall_rule` will set or clear, as the tool spells them.
FILTER_EDITABLE = (
    "comment", "protocol", "src_address", "dst_address", "src_port", "dst_port",
    "port", "src_address_type", "dst_address_type", "in_interface",
    "out_interface", "in_interface_list", "out_interface_list",
    "connection_state", "connection_nat_state", "connection_limit",
    "connection_mark", "limit", "psd", "tcp_flags", "src_address_list",
    "dst_address_list", "address_list", "address_list_timeout", "jump_target",
    "reject_with", "log", "log_prefix",
)

# And for `update_nat_rule`.
NAT_EDITABLE = (
    "comment", "protocol", "src_address", "dst_address", "src_port", "dst_port",
    "port", "src_address_type", "dst_address_type", "in_interface",
    "out_interface", "in_interface_list", "out_interface_list",
    "src_address_list", "dst_address_list", "connection_mark",
    "to_addresses", "to_ports", "log", "log_prefix",
)

# Fields worth showing without being asked. The device returns ~30 per rule,
# most of them counters; dumping all of them for every rule costs a great deal
# of context to say very little.
#
# The bar for inclusion is whether leaving the field out changes what the rule
# appears to *do*. Every matcher clears it: a port-scan detector listed without
# its `psd` reads as an unconditional drop on a protocol, which is a far more
# alarming rule than the one actually on the device. Counters do not clear it —
# `bytes` and `packets` say how much traffic hit a rule, never which traffic
# would.
RULE_SUMMARY = (
    ".id", "chain", "action", "comment", "disabled", "dynamic", "invalid",
    "protocol", "src-address", "dst-address", "src-port", "dst-port", "port",
    "in-interface", "out-interface", "in-interface-list", "out-interface-list",
    "src-address-type", "dst-address-type", "connection-state",
    "connection-nat-state", "connection-limit", "connection-mark", "limit",
    "psd", "tcp-flags", "src-address-list", "dst-address-list",
    "address-list", "address-list-timeout", "jump-target", "reject-with",
    "to-addresses", "to-ports", "log", "log-prefix",
)

# Flags RouterOS reports only when they are set, so their absence is a value
# and not a gap. Filling them in costs three keys per rule and removes the
# question of whether a missing `disabled` means enabled or means unreported —
# `invalid` especially, which is the device saying a rule references an
# interface or address list that no longer exists.
RULE_FLAGS = ("disabled", "dynamic", "invalid", "log")

# RouterOS types these by content: a lone `9991` arrives as an integer and
# `"80,443"` as a string, from the same field of the same call. They are port
# *specifications* — ranges and lists are as valid as single ports — so they
# are text, consistently.
PORT_FIELDS = ("src-port", "dst-port", "port", "to-ports")


def _flag(value: Any) -> bool:
    return value in (True, "true", "yes")


def _text_ports(item: dict[str, Any]) -> None:
    for field in PORT_FIELDS:
        if item.get(field) is not None:
            item[field] = str(item[field])


def _summarise(
    rows: list[dict[str, Any]],
    keys: tuple[str, ...],
    verbose: bool,
    *,
    flags: tuple[str, ...] = ("disabled",),
) -> list[dict[str, Any]]:
    out = []
    for position, row in enumerate(rows):
        kept = dict(row) if verbose else {k: v for k, v in row.items() if k in keys}
        kept.pop(".id", None)
        # `position` is display-only. It is what the CLI would print, and it is
        # exactly the thing that must never be used as a write handle.
        item = {"id": row.get(".id"), "position": position, **kept}
        for flag in flags:
            item[flag] = _flag(row.get(flag))
        _text_ports(item)
        out.append(item)
    return out


def _detail(row: dict[str, Any] | None, *, flags: tuple[str, ...] = RULE_FLAGS) -> dict[str, Any] | None:
    """One item, every field, keyed the same way a list result is.

    Reads used to hand back `.id` here and `id` from a list, so a caller that
    took an id from one and passed it to the other had to know which shape it
    was holding. One spelling, everywhere.
    """
    if row is None:
        return None
    item = {"id": row.get(".id"), **{k: v for k, v in row.items() if k != ".id"}}
    for flag in flags:
        item[flag] = _flag(row.get(flag))
    _text_ports(item)
    return item


def _dump(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=False, default=str)


def _require_real_id(rule_id: str, kind: str = "rule") -> str:
    """Reject positional indices at the door.

    This is the single guard that the server this replaces was missing. There,
    `list` printed positions, the docs told you to pass one, and the write path
    looked it up as an `.id` — which cannot match — so every write reported
    "not found". Worse, had it matched, positions shift when rules are added or
    a dynamic rule appears, so the write would have hit the wrong rule.
    """
    value = rule_id.strip()
    if not value.startswith("*"):
        raise ToolError(
            f"{rule_id!r} is not a RouterOS {kind} id. Ids look like '*7' and come "
            f"from the 'id' field of a list result — the 'position' field is a "
            f"display index that shifts whenever rules change, so it is not accepted "
            f"for writes. List the {kind}s and pass the 'id' of the one you mean."
        )
    return value


def _misplaced(item_id: str, target: str | None, order: list[str]) -> str | None:
    """Whether a rule failed to land where a move asked it to.

    A reorder that quietly does nothing is the one outcome this must never
    report as success: the caller goes on believing a rule sits in front of a
    drop when it sits behind it, and the firewall reads correctly while
    behaving otherwise.
    """
    landed = order.index(item_id)
    expected = order.index(target) - 1 if target is not None else len(order) - 1
    if landed == expected:
        return None
    return (
        f"{item_id} was to go "
        + (f"immediately before {target}" if target else "to the end of the list")
        + f", but it sits at index {landed} of {len(order)}."
    )


def _check_action(
    action: str | None,
    supplied: dict[str, Any],
    existing: dict[str, Any] | None = None,
    requires: dict[str, tuple[tuple[str, ...], str]] = ACTION_REQUIRES,
) -> None:
    """Refuse an action whose companion field is missing.

    Any one of the listed fields satisfies the requirement. `existing` is the
    rule as it stands, for an update that changes the action without restating
    a field the rule already carries.
    """
    if action is None or action not in requires:
        return
    fields, purpose = requires[action]
    if any(supplied.get(field) is not None for field in fields):
        return
    if existing is not None and any(existing.get(f.replace("_", "-")) for f in fields):
        return
    named = " or ".join(f"`{f}`" for f in fields)
    raise ToolError(
        f"action {action!r} needs {named} — {purpose}. RouterOS would accept the "
        f"rule without it and report it valid, but the rule would have nothing to "
        f"act on, so it is refused here instead."
    )


def _unset_fields(
    names: list[str], supplied: dict[str, Any], editable: tuple[str, ...] = FILTER_EDITABLE,
) -> list[str]:
    """Validate the `unset` list and return RouterOS field names."""
    out = []
    for name in names:
        key = name.strip().replace("-", "_")
        if key in ("chain", "action"):
            raise ToolError(
                f"{name!r} cannot be cleared: every rule must have a chain and an "
                f"action. Pass a new value for it instead."
            )
        if key not in editable:
            raise ToolError(
                f"{name!r} is not a field this tool can clear. Clearable fields are: "
                + ", ".join(editable)
            )
        if supplied.get(key) is not None:
            raise ToolError(
                f"{name!r} is in `unset` and also given a value. Pass one or the other."
            )
        out.append(key.replace("_", "-"))
    return out


class _Surfaced:
    """Re-raises device failures as `ToolError` so their text reaches the model.

    Anything that is not a `ToolError` is treated by the SDK as a crash and the
    model is told only "Error executing tool X" — which for "the router refused
    this address" or "the credentials are wrong" is precisely the wrong half of
    the message to keep.

    The catch-all is deliberate. A `TypeError` deep in the client once reached
    the caller as "Error executing tool move_firewall_rule" and nothing else,
    which is untriageable from the other side of the protocol: no RouterOS
    message, no failing argument, no way to tell a device refusal from a bug in
    this code. An unexpected exception is still a bug, but it should arrive
    saying what it was.
    """

    def __init__(self, router: RouterOS) -> None:
        self._router = router

    def __getattr__(self, name: str):
        attr = getattr(self._router, name)

        async def wrapper(*args: Any, **kwargs: Any):
            try:
                return await attr(*args, **kwargs)
            except RouterError as exc:
                raise ToolError(str(exc)) from exc
            except ToolError:
                raise
            except Exception as exc:  # noqa: BLE001 - see the class docstring
                log.exception("unexpected failure in RouterOS.%s", name)
                raise ToolError(
                    f"{type(exc).__name__} while calling RouterOS.{name}: {exc}\n"
                    f"  This is a fault in mikrotik-mcp rather than a refusal by the "
                    f"device. The device was most likely not modified."
                ) from exc

        return wrapper


def register(mcp: MCPServer, device: RouterOS, *, title: str) -> None:
    """Attach every tool for one device to its own MCPServer instance."""
    router = _Surfaced(device)

    def tool(**kwargs: Any):
        """`mcp.tool`, with unexpected failures kept legible.

        The SDK withholds the text of anything that is not a `ToolError`, so a
        plain bug in a tool body reaches the caller as "Error executing tool
        <name>" and nothing else — no exception type, no message, no way to
        tell a fault here from a refusal by the router. That is the right
        default for a server exposed to strangers and the wrong one for a
        server an operator points at their own device, where the whole value of
        the failure is being able to act on it.
        """
        decorate = mcp.tool(**kwargs)

        def wrap(fn):
            @functools.wraps(fn)
            async def guarded(*args: Any, **kw: Any):
                try:
                    return await fn(*args, **kw)
                except ToolError:
                    raise
                except Exception as exc:  # noqa: BLE001 - see the docstring
                    log.exception("unexpected failure in %s", fn.__name__)
                    # The SDK already prefixes the tool name; what it drops for
                    # anything but a ToolError is everything after it.
                    raise ToolError(
                        f"{type(exc).__name__}: {exc}\n"
                        f"  This is a fault in mikrotik-mcp rather than a refusal by "
                        f"the device. Check the server log for the traceback."
                    ) from exc

            return decorate(guarded)

        return wrap

    async def _list(*path: str) -> list[dict[str, Any]]:
        return await router.list(*path)

    async def _reorder(path: tuple[str, ...], rule_id: str, before_rule_id: str | None,
                       kind: str) -> dict[str, Any]:
        """Move one rule, verify it landed, and report the affected chain.

        Filter rules and NAT rules are both ordered tables with first-match-wins
        semantics, so they get one implementation rather than two that drift.
        """
        item_id = _require_real_id(rule_id, kind)
        target = _require_real_id(before_rule_id, kind) if before_rule_id else None
        if target == item_id:
            raise ToolError(f"{item_id} cannot be moved before itself.")

        rows = await router.list(*path)
        order_before = [r.get(".id") for r in rows]
        by_id = {r.get(".id"): r for r in rows}
        if item_id not in by_id:
            raise ToolError(
                f"No {kind} with id {item_id!r} exists. It may have been removed. "
                f"Nothing was moved."
            )
        if target is not None and target not in by_id:
            raise ToolError(
                f"Cannot move {item_id} before {target!r}: no such {kind} exists. "
                f"Nothing was moved."
            )

        chain = by_id[item_id].get("chain")
        warning = None
        if target is not None and by_id[target].get("chain") != chain:
            # Legal — the table is one list and chains are labels on it — but
            # a rule sitting among another chain's rules is nearly always a
            # mistake, and silence here would let it pass unnoticed.
            warning = (
                f"{item_id} is in chain {chain!r} but {target} is in "
                f"{by_id[target].get('chain')!r}. The move was performed; a rule "
                f"placed among another chain's rules still only matches its own chain, "
                f"but its position relative to its own chain may not be what you meant."
            )

        await router.move(*path, item_id=item_id, destination=target)

        after = await router.list(*path)
        order_after = [r.get(".id") for r in after]
        problem = _misplaced(item_id, target, order_after)
        if problem:
            raise ToolError(
                f"The move did not take effect as asked. {problem}\n"
                f"  order before: {order_before}\n  order after:  {order_after}\n"
                f"The device accepted the command, so re-read the rules before "
                f"assuming the order is what you intended."
            )

        return {
            "moved": True, "id": item_id, "before_rule_id": target,
            "chain": chain, "warning": warning,
            "position_note": "index across all chains, for ordering only",
            "chain_order": [
                {"id": r["id"], "position": r["position"], "action": r.get("action"),
                 "comment": r.get("comment")}
                for r in _summarise(after, RULE_SUMMARY, False, flags=RULE_FLAGS)
                if r.get("chain") == chain
            ],
        }

    # ── system ────────────────────────────────────────────────────────────

    @tool(name="system_info", annotations=ToolAnnotations(
        title="System Info", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def system_info(ctx: Context) -> str:
        """Identity, RouterOS version, model, uptime, CPU and memory for the device."""
        resource = await _list("system", "resource")
        identity = await _list("system", "identity")
        routerboard = await _list("system", "routerboard")
        return _dump({
            "device": title,
            "identity": identity[0].get("name") if identity else None,
            "resource": resource[0] if resource else {},
            "routerboard": routerboard[0] if routerboard else {},
        })

    @tool(name="ros_list", annotations=ToolAnnotations(
        title="Read Any RouterOS Path", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def ros_list(
        ctx: Context,
        path: Annotated[str, Field(description="RouterOS menu path, slash-separated and without the leading slash, e.g. 'ip/dhcp-server/lease' or 'interface/wireguard/peers'.")],
    ) -> str:
        """Read any RouterOS configuration path.

        The escape hatch for everything without a dedicated tool. Read-only:
        it lists items at a path and cannot modify the device.
        """
        parts = tuple(p for p in path.strip("/").replace(".", "/").split("/") if p)
        if not parts:
            raise ToolError("path must name a RouterOS menu, e.g. 'ip/address'")
        rows = await _list(*parts)
        return _dump({"path": "/".join(parts), "count": len(rows), "items": rows})

    # ── interfaces and addressing ─────────────────────────────────────────

    @tool(name="list_interfaces", annotations=ToolAnnotations(
        title="List Interfaces", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_interfaces(
        ctx: Context,
        type_filter: Annotated[str | None, Field(description="Restrict to a RouterOS interface type, e.g. 'ether', 'bridge', 'vlan', 'wg'.")] = None,
        running_only: bool = False,
    ) -> str:
        """List every interface with its type, MAC, MTU and running state."""
        rows = await _list("interface")
        if type_filter:
            rows = [r for r in rows if r.get("type", "").startswith(type_filter)]
        if running_only:
            rows = [r for r in rows if r.get("running") in (True, "true", "yes")]
        return _dump(_summarise(rows, (".id", "name", "type", "mtu", "mac-address", "running", "disabled", "comment"), False,
                                flags=("disabled", "running")))

    @tool(name="set_interface_enabled", annotations=ToolAnnotations(
        title="Enable/Disable Interface", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def set_interface_enabled(
        ctx: Context,
        interface_id: Annotated[str, Field(description="The interface 'id' from list_interfaces, e.g. '*3'.")],
        enabled: bool,
    ) -> str:
        """Bring an interface up or down.

        Disabling the interface you are reaching the router through will cut
        this connection, and nothing here can undo that remotely.
        """
        item_id = _require_real_id(interface_id, "interface")
        await router.update("interface", item_id=item_id, disabled=not enabled)
        after = await router.get("interface", item_id=item_id)
        return _dump({"changed": True, "interface": _detail(after, flags=("disabled",))})

    @tool(name="list_ip_addresses", annotations=ToolAnnotations(
        title="List IP Addresses", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_ip_addresses(ctx: Context) -> str:
        """List configured IPv4 addresses and the interfaces they sit on."""
        rows = await _list("ip", "address")
        return _dump(_summarise(rows, (".id", "address", "network", "interface", "disabled", "dynamic", "comment"), False,
                                flags=("disabled", "dynamic", "invalid")))

    # ── firewall filter ───────────────────────────────────────────────────

    @tool(name="list_firewall_rules", annotations=ToolAnnotations(
        title="List Firewall Rules", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_firewall_rules(
        ctx: Context,
        chain: Annotated[str | None, Field(description="Restrict to one chain: 'input', 'forward', 'output', or a custom chain name.")] = None,
        family: Annotated[Family, Field(description="'ipv4' reads ip/firewall/filter, 'ipv6' reads ipv6/firewall/filter. They are separate rule sets and one says nothing about the other.")] = "ipv4",
        include_dynamic: Annotated[bool, Field(description="Include rules RouterOS generates itself, which cannot be edited.")] = False,
        verbose: Annotated[bool, Field(description="Add the packet and byte counters, and any remaining field. The matchers that define a rule are in the default view already.")] = False,
    ) -> str:
        """List firewall filter rules in evaluation order.

        Each rule carries both an `id` and a `position`. Use `id` for any
        later change: `position` is only where the rule currently sits, and it
        shifts as soon as anything is added, removed or moved.

        `position` counts every rule in the table, so a result filtered to one
        chain is numbered by its place among *all* rules — the first three
        forward rules might come back as 29, 30, 31. That is the right number
        for reasoning about evaluation order and the wrong number for anything
        else.
        """
        rows = await router.list(*_filter_path(family))
        summarised = _summarise(rows, RULE_SUMMARY, verbose, flags=RULE_FLAGS)
        if chain:
            summarised = [r for r in summarised if r.get("chain") == chain]
        if not include_dynamic:
            summarised = [r for r in summarised if not r["dynamic"]]
        payload: dict[str, Any] = {
            "family": family,
            "count": len(summarised),
            "position_note": "index across all chains, for ordering only — never pass it to a write",
            "rules": summarised,
        }
        if family == "ipv4":
            payload["ipv6"] = await _ipv6_note()
        return _dump(payload)

    async def _ipv6_note() -> dict[str, Any]:
        """What the v4 table cannot tell you about the v6 one.

        An IPv6 filter table with no rules accepts everything, and it is not
        visible from here — which is how a device ends up looking locked down
        while being wide open on the protocol it actually prefers.
        """
        try:
            count = await router.count("ipv6", "firewall", "filter")
        except ToolError as exc:
            return {"readable": False, "reason": str(exc).splitlines()[0]}
        if count == 0:
            return {
                "rule_count": 0,
                "warning": "The IPv6 filter table is empty, so every IPv6 packet is "
                           "accepted regardless of what the IPv4 rules above do. "
                           "Check whether the ipv6 package is enabled before "
                           "concluding this device is firewalled.",
            }
        return {"rule_count": count,
                "note": "IPv6 is filtered separately. List it with family='ipv6'."}

    @tool(name="get_firewall_rule", annotations=ToolAnnotations(
        title="Get Firewall Rule", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def get_firewall_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_firewall_rules, e.g. '*7'.")],
        family: Family = "ipv4",
    ) -> str:
        """Every field of one firewall rule, including counters."""
        path = _filter_path(family)
        item_id = _require_real_id(rule_id)
        rule = await router.get(*path, item_id=item_id)
        if rule is None:
            raise ToolError(f"No {family} firewall rule with id {item_id!r} exists. It may have been removed.")
        return _dump(_detail(rule))

    @tool(name="add_firewall_rule", annotations=ToolAnnotations(
        title="Add Firewall Rule", destructive_hint=False, idempotent_hint=False, open_world_hint=False))
    async def add_firewall_rule(
        ctx: Context,
        chain: Annotated[str, Field(description="'input', 'forward', 'output', or a custom chain.")],
        action: Annotated[Literal["accept", "drop", "reject", "log", "jump", "return", "passthrough", "fasttrack-connection", "add-src-to-address-list", "add-dst-to-address-list"], Field(description="What to do with matching traffic. 'jump' also needs `jump_target`; the two address-list actions also need `address_list`.")],
        comment: Annotated[str | None, Field(description="Strongly recommended — an uncommented rule is very hard to audit later.")] = None,
        family: Family = "ipv4",
        protocol: Annotated[str | None, Field(description="'tcp', 'udp', 'icmp', 'icmpv6', or a protocol number.")] = None,
        src_address: Annotated[str | None, Field(description="Address or CIDR; a leading '!' negates.")] = None,
        dst_address: Annotated[str | None, Field(description="Address or CIDR; a leading '!' negates.")] = None,
        src_port: Annotated[str | None, Field(description="Port, list or range, e.g. '443', '80,443', '1000-2000'. Needs a protocol.")] = None,
        dst_port: Annotated[str | None, Field(description="Port, list or range, e.g. '443', '80,443', '1000-2000'. Needs a protocol.")] = None,
        port: Annotated[str | None, Field(description="Matches either source or destination port.")] = None,
        src_address_type: Annotated[str | None, Field(description="'unicast', 'local', 'broadcast', 'multicast'; '!' negates.")] = None,
        dst_address_type: Annotated[str | None, Field(description="'unicast', 'local', 'broadcast', 'multicast'; '!' negates. '!local' is how a DNS redirect avoids catching traffic aimed at the router itself.")] = None,
        in_interface: str | None = None,
        out_interface: str | None = None,
        in_interface_list: str | None = None,
        out_interface_list: str | None = None,
        connection_state: Annotated[str | None, Field(description="Comma-separated, e.g. 'established,related'. '!' negates.")] = None,
        connection_nat_state: Annotated[str | None, Field(description="'dstnat' or 'srcnat'; '!' negates. A forward-chain rule accepting port-forwarded traffic is written with connection_nat_state='dstnat'.")] = None,
        connection_limit: Annotated[str | None, Field(description="'limit,netmask' — '100,32' caps each single source address at 100 connections.")] = None,
        connection_mark: str | None = None,
        limit: Annotated[str | None, Field(description="Rate limit as 'count[/time],burst:mode', e.g. '10/1m,5:packet'. Matches only while under the rate, so it is how a log rule avoids flooding the log.")] = None,
        psd: Annotated[str | None, Field(description="Port Scan Detect: 'WeightThreshold,DelayThreshold,LowPortWeight,HighPortWeight', e.g. '21,3s,3,1'.")] = None,
        tcp_flags: Annotated[str | None, Field(description="Comma-separated, '!' negates, e.g. 'syn,!ack'. Needs protocol='tcp'.")] = None,
        src_address_list: Annotated[str | None, Field(description="Match when the source is on this address list; '!' negates.")] = None,
        dst_address_list: Annotated[str | None, Field(description="Match when the destination is on this address list; '!' negates.")] = None,
        address_list: Annotated[str | None, Field(description="For 'add-src-to-address-list'/'add-dst-to-address-list': the list to write into. Required for those actions — without it the rule is stored, reports valid, and does nothing.")] = None,
        address_list_timeout: Annotated[str | None, Field(description="How long an entry this rule creates survives, e.g. '1d' or '00:30:00'. Omit for permanent entries, which on an auto-populated list grow without bound.")] = None,
        jump_target: Annotated[str | None, Field(description="The custom chain to jump to. Required when action='jump'.")] = None,
        reject_with: Annotated[str | None, Field(description="What to answer with when action='reject', e.g. 'icmp-port-unreachable' or 'tcp-reset'.")] = None,
        log: bool | None = None,
        log_prefix: str | None = None,
        disabled: Annotated[bool, Field(description="Add the rule disabled, to position it before it takes effect.")] = False,
        place_before: Annotated[str | None, Field(description="Rule 'id' to insert before. Without it the rule lands at the end of the list, which for a chain ending in a drop rule usually means it never matches.")] = None,
    ) -> str:
        """Add a firewall filter rule.

        Order decides everything in a RouterOS firewall: the first matching
        rule wins. A new rule appended after a final `drop` is dead code, so
        set `place_before` unless the end of the chain is genuinely what you
        want.
        """
        path = _filter_path(family)
        fields = dict(
            chain=chain, action=action, comment=comment, protocol=protocol,
            src_address=src_address, dst_address=dst_address,
            src_port=src_port, dst_port=dst_port, port=port,
            src_address_type=src_address_type, dst_address_type=dst_address_type,
            in_interface=in_interface, out_interface=out_interface,
            in_interface_list=in_interface_list, out_interface_list=out_interface_list,
            connection_state=connection_state, connection_nat_state=connection_nat_state,
            connection_limit=connection_limit, connection_mark=connection_mark,
            limit=limit, psd=psd, tcp_flags=tcp_flags,
            src_address_list=src_address_list, dst_address_list=dst_address_list,
            address_list=address_list, address_list_timeout=address_list_timeout,
            jump_target=jump_target, reject_with=reject_with,
            log=log, log_prefix=log_prefix,
        )
        _check_action(action, fields)

        target = _require_real_id(place_before) if place_before else None
        if target is not None and await router.get(*path, item_id=target) is None:
            raise ToolError(
                f"Cannot place the new rule before {target!r}: no such rule exists. "
                f"Nothing was added. Re-list the rules and check the id."
            )

        new_id = await router.add(*path, **fields, disabled=disabled or None)
        if target is not None:
            await router.move(*path, item_id=new_id, destination=target)
            order = [r.get(".id") for r in await router.list(*path)]
            problem = _misplaced(new_id, target, order)
            if problem:
                # The rule exists either way, so reporting only "failed" would
                # leave one behind that nobody knows about. Where it actually
                # sits is the part the caller has to act on.
                raise ToolError(
                    f"The rule was created as {new_id}, but placing it failed: {problem}\n"
                    f"  order now: {order}\n"
                    f"It is most likely at the end of the chain, where a chain ending in "
                    f"a drop will never reach it. Move it with move_firewall_rule, or "
                    f"delete it with remove_firewall_rule({new_id!r})."
                )

        rule = await router.get(*path, item_id=new_id)
        return _dump({"created": True, "id": new_id, "family": family,
                      "placed_before": target, "rule": _detail(rule)})

    @tool(name="update_firewall_rule", annotations=ToolAnnotations(
        title="Update Firewall Rule", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def update_firewall_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_firewall_rules, e.g. '*7'.")],
        family: Family = "ipv4",
        chain: str | None = None,
        action: str | None = None,
        comment: str | None = None,
        protocol: str | None = None,
        src_address: str | None = None,
        dst_address: str | None = None,
        src_port: str | None = None,
        dst_port: str | None = None,
        port: str | None = None,
        src_address_type: str | None = None,
        dst_address_type: Annotated[str | None, Field(description="'unicast', 'local', 'broadcast', 'multicast'; '!' negates.")] = None,
        in_interface: str | None = None,
        out_interface: str | None = None,
        in_interface_list: str | None = None,
        out_interface_list: str | None = None,
        connection_state: str | None = None,
        connection_nat_state: Annotated[str | None, Field(description="'dstnat' or 'srcnat'; '!' negates.")] = None,
        connection_limit: Annotated[str | None, Field(description="'limit,netmask', e.g. '100,32'.")] = None,
        connection_mark: str | None = None,
        limit: Annotated[str | None, Field(description="'count[/time],burst:mode', e.g. '10/1m,5:packet'.")] = None,
        psd: Annotated[str | None, Field(description="'WeightThreshold,DelayThreshold,LowPortWeight,HighPortWeight', e.g. '21,3s,3,1'.")] = None,
        tcp_flags: Annotated[str | None, Field(description="Comma-separated, '!' negates, e.g. 'syn,!ack'.")] = None,
        src_address_list: str | None = None,
        dst_address_list: str | None = None,
        address_list: Annotated[str | None, Field(description="Target list for the 'add-*-to-address-list' actions.")] = None,
        address_list_timeout: Annotated[str | None, Field(description="Lifetime of entries this rule creates, e.g. '1d'.")] = None,
        jump_target: Annotated[str | None, Field(description="Custom chain for action='jump'.")] = None,
        reject_with: Annotated[str | None, Field(description="ICMP or TCP response for action='reject'.")] = None,
        log: bool | None = None,
        log_prefix: str | None = None,
        unset: Annotated[list[str] | None, Field(description="Fields to clear back to their RouterOS default, e.g. ['log_prefix', 'src_address']. Use this rather than an empty string: for some fields an empty string is a value in its own right, and for others the device rejects it. A field cannot be both set and cleared in one call.")] = None,
    ) -> str:
        """Change fields on an existing firewall rule.

        Only the arguments you pass are modified; omitted ones are left alone.
        To remove a field rather than change it, name it in `unset`. Returns
        the rule before and after, so the change can be checked rather than
        taken on trust.
        """
        path = _filter_path(family)
        item_id = _require_real_id(rule_id)
        before = await router.get(*path, item_id=item_id)
        if before is None:
            raise ToolError(f"No firewall rule with id {item_id!r} exists. It may have been removed.")

        fields = dict(
            chain=chain, action=action, comment=comment, protocol=protocol,
            src_address=src_address, dst_address=dst_address,
            src_port=src_port, dst_port=dst_port, port=port,
            src_address_type=src_address_type, dst_address_type=dst_address_type,
            in_interface=in_interface, out_interface=out_interface,
            in_interface_list=in_interface_list, out_interface_list=out_interface_list,
            connection_state=connection_state, connection_nat_state=connection_nat_state,
            connection_limit=connection_limit, connection_mark=connection_mark,
            limit=limit, psd=psd, tcp_flags=tcp_flags,
            src_address_list=src_address_list, dst_address_list=dst_address_list,
            address_list=address_list, address_list_timeout=address_list_timeout,
            jump_target=jump_target, reject_with=reject_with,
            log=log, log_prefix=log_prefix,
        )
        _check_action(action, fields, before)
        clearing = _unset_fields(unset or [], fields)
        # An action that needs a companion field must not have that field
        # cleared out from under it, whether the action is being set now or was
        # already there.
        effective = action or str(before.get("action", ""))
        if effective in ACTION_REQUIRES:
            needed = ACTION_REQUIRES[effective][0][0].replace("_", "-")
            if needed in clearing:
                raise ToolError(
                    f"Cannot clear {needed!r} while the rule's action is {effective!r}: "
                    f"the rule would keep matching and stop doing anything. Change the "
                    f"action in the same call, or remove the rule."
                )

        setting = any(v is not None for v in fields.values())
        if not setting and not clearing:
            raise ToolError(
                "Nothing to change. Pass at least one field to set, or name one in "
                "`unset` to clear it. Reporting a no-op as an update would make the "
                "before/after pair below look like a change that did not happen."
            )
        if setting:
            await router.update(*path, item_id=item_id, **fields)
        for field in clearing:
            await router.unset(*path, item_id=item_id, field=field)

        after = await router.get(*path, item_id=item_id)
        return _dump({"updated": True, "id": item_id, "family": family,
                      "cleared": clearing, "before": _detail(before), "after": _detail(after)})

    @tool(name="set_firewall_rule_enabled", annotations=ToolAnnotations(
        title="Enable/Disable Firewall Rule", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def set_firewall_rule_enabled(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_firewall_rules, e.g. '*7'.")],
        enabled: bool,
        family: Family = "ipv4",
    ) -> str:
        """Enable or disable one firewall rule, leaving its position intact.

        Disabling is the reversible way to test whether a rule is responsible
        for something — prefer it over removing the rule.
        """
        path = _filter_path(family)
        item_id = _require_real_id(rule_id)
        rule = await router.get(*path, item_id=item_id)
        if rule is None:
            raise ToolError(f"No firewall rule with id {item_id!r} exists. It may have been removed.")
        await router.update(*path, item_id=item_id, disabled=not enabled)
        return _dump({"changed": True, "id": item_id, "family": family, "enabled": enabled,
                      "rule": _detail(await router.get(*path, item_id=item_id))})

    @tool(name="remove_firewall_rule", annotations=ToolAnnotations(
        title="Remove Firewall Rule", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def remove_firewall_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_firewall_rules, e.g. '*7'.")],
        confirm_comment: Annotated[str | None, Field(description="If given, the removal only proceeds when the rule's comment matches. Cheap insurance that you are deleting the rule you think you are.")] = None,
        family: Family = "ipv4",
    ) -> str:
        """Delete a firewall rule permanently.

        There is no undo. Disabling a rule (`set_firewall_rule_enabled`) is
        almost always the better first move, and the returned copy of the
        deleted rule is the only record you will have afterwards.
        """
        path = _filter_path(family)
        item_id = _require_real_id(rule_id)
        rule = await router.get(*path, item_id=item_id)
        if rule is None:
            raise ToolError(f"No firewall rule with id {item_id!r} exists. It may already have been removed.")
        if confirm_comment is not None and rule.get("comment", "") != confirm_comment:
            raise ToolError(
                f"Refusing to remove {item_id}: its comment is {rule.get('comment', '')!r}, "
                f"not {confirm_comment!r}. Re-list the rules and check the id."
            )
        await router.remove(*path, item_id=item_id)
        return _dump({"removed": True, "id": item_id, "family": family,
                      "deleted_rule": _detail(rule)})

    @tool(name="move_firewall_rule", annotations=ToolAnnotations(
        title="Move Firewall Rule", destructive_hint=True, idempotent_hint=False, open_world_hint=False))
    async def move_firewall_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The 'id' of the rule to move.")],
        before_rule_id: Annotated[str | None, Field(description="The 'id' of the rule to place it in front of. Omit to move it to the end of the list — which, after a chain's final drop, means it will never match.")] = None,
        family: Family = "ipv4",
    ) -> str:
        """Reorder a firewall rule relative to another rule.

        Both ends are given by `id` rather than position, so the move means the
        same thing even if the list shifted since you last read it.

        The resulting order is read back and checked against what was asked
        for. If the rule did not land where it should have, this fails and
        says so rather than reporting a move that did not happen.
        """
        return _dump({"family": family, **await _reorder(
            _filter_path(family), rule_id, before_rule_id, f"{family} firewall rule")})

    # ── address lists ─────────────────────────────────────────────────────

    @tool(name="list_address_lists", annotations=ToolAnnotations(
        title="List Address Lists", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_address_lists(ctx: Context, family: Family = "ipv4") -> str:
        """The names of every firewall address list, with entry counts.

        Start here rather than with `list_address_list_entries`: a firewall
        built on named lists is unreadable until you know which lists exist,
        and the dynamic entries that rules create with a timeout never appear
        in a configuration export.

        Reads one small row per entry to do the counting, so it is proportional
        to the total number of entries across all lists.
        """
        rows = await router.query(*_address_list_path(family), proplist=("list", "dynamic", "timeout"))
        lists: dict[str, dict[str, Any]] = {}
        for row in rows:
            name = str(row.get("list", ""))
            entry = lists.setdefault(name, {"list": name, "entries": 0, "dynamic": 0, "with_timeout": 0})
            entry["entries"] += 1
            if _flag(row.get("dynamic")):
                entry["dynamic"] += 1
            if row.get("timeout"):
                entry["with_timeout"] += 1
        return _dump({
            "family": family,
            "count": len(lists),
            "total_entries": len(rows),
            "lists": sorted(lists.values(), key=lambda item: -item["entries"]),
        })

    @tool(name="list_address_list_entries", annotations=ToolAnnotations(
        title="List Address List Entries", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_address_list_entries(
        ctx: Context,
        list_name: Annotated[str | None, Field(description="Restrict to one list by name. Filtered by the device, not here.")] = None,
        address: Annotated[str | None, Field(description="Look up one exact address or CIDR — the fastest way to answer 'is this host blocked?'.")] = None,
        family: Family = "ipv4",
        include_dynamic: Annotated[bool, Field(description="Include entries added by rules rather than by configuration. These are the ones with a timeout, and they are invisible in a config export.")] = True,
        count_only: Annotated[bool, Field(description="Return only how many entries match. Use this first: these lists routinely hold tens of thousands of entries.")] = False,
        limit: Annotated[int, Field(description="Most entries to return.", ge=1, le=1000)] = 100,
    ) -> str:
        """List firewall address list entries.

        `count_only` first, then narrow with `list_name` or `address`. A
        dynamically populated block list can hold tens of thousands of entries,
        and asking for all of them is rarely what you want.
        """
        path = _address_list_path(family)
        where: dict[str, str] = {}
        if list_name:
            where["list"] = list_name
        if address:
            where["address"] = address
        if not include_dynamic:
            where["dynamic"] = "false"

        if count_only:
            return _dump({"family": family, "list": list_name, "address": address,
                          "matched": await router.count(*path, where=where)})

        rows = await router.query(*path, where=where)
        entries = _summarise(rows, (".id", "list", "address", "timeout", "creation-time",
                                    "dynamic", "disabled", "comment"), False,
                             flags=("disabled", "dynamic"))
        return _dump({
            "family": family, "list": list_name, "matched": len(entries),
            "returned": len(entries[:limit]),
            "truncated": len(entries) > limit,
            "entries": entries[:limit],
        })

    @tool(name="add_address_list_entry", annotations=ToolAnnotations(
        title="Add Address List Entry", destructive_hint=False, idempotent_hint=False, open_world_hint=False))
    async def add_address_list_entry(
        ctx: Context,
        list_name: Annotated[str, Field(description="The list to add to. Creating a list is the same operation as adding the first entry to it — there is no separate step, so a typo here silently makes a new list that no rule reads.")],
        address: Annotated[str, Field(description="Address, CIDR, range ('10.0.0.1-10.0.0.9') or a resolvable hostname.")],
        timeout: Annotated[str | None, Field(description="How long the entry lives, e.g. '1d' or '00:30:00'. Omit for a permanent entry.")] = None,
        comment: str | None = None,
        family: Family = "ipv4",
    ) -> str:
        """Add one entry to a firewall address list.

        Adding to a list no rule references has no effect; check
        `list_address_lists` for the name, or search the rules for
        `src_address_list`.
        """
        path = _address_list_path(family)
        new_id = await router.add(*path, list=list_name, address=address,
                                  timeout=timeout, comment=comment)
        return _dump({"created": True, "id": new_id, "family": family,
                      "entry": _detail(await router.get(*path, item_id=new_id),
                                       flags=("disabled", "dynamic"))})

    @tool(name="remove_address_list_entry", annotations=ToolAnnotations(
        title="Remove Address List Entry", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def remove_address_list_entry(
        ctx: Context,
        entry_id: Annotated[str, Field(description="The entry 'id' from list_address_list_entries.")],
        confirm_address: Annotated[str | None, Field(description="If given, the removal only proceeds when the entry's address matches.")] = None,
        family: Family = "ipv4",
    ) -> str:
        """Remove one entry from a firewall address list.

        A dynamic entry removed here comes back the moment the rule that
        created it matches again; change the rule if that is not what you want.
        """
        path = _address_list_path(family)
        item_id = _require_real_id(entry_id, "address list entry")
        entry = await router.get(*path, item_id=item_id)
        if entry is None:
            raise ToolError(f"No address list entry with id {item_id!r} exists. It may already have been removed.")
        if confirm_address is not None and str(entry.get("address", "")) != confirm_address:
            raise ToolError(
                f"Refusing to remove {item_id}: its address is {entry.get('address', '')!r}, "
                f"not {confirm_address!r}. Re-list the entries and check the id."
            )
        await router.remove(*path, item_id=item_id)
        return _dump({"removed": True, "id": item_id, "family": family,
                      "deleted_entry": _detail(entry, flags=("disabled", "dynamic"))})
    # ── NAT ───────────────────────────────────────────────────────────────

    @tool(name="list_nat_rules", annotations=ToolAnnotations(
        title="List NAT Rules", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_nat_rules(
        ctx: Context,
        chain: Annotated[str | None, Field(description="'srcnat' or 'dstnat'.")] = None,
        include_dynamic: Annotated[bool, Field(description="Include rules RouterOS generates itself, which cannot be edited.")] = False,
        verbose: Annotated[bool, Field(description="Add the packet and byte counters. The matchers are in the default view already.")] = False,
    ) -> str:
        """List NAT rules, including port forwards, in evaluation order.

        NAT is an ordered table with first-match-wins semantics, exactly like
        the filter chains, so `position` and `id` mean the same things here —
        `id` for writes, `position` for reading order, counted across both
        chains rather than within one.
        """
        rows = _summarise(await _list(*NAT), RULE_SUMMARY, verbose, flags=RULE_FLAGS)
        if chain:
            rows = [r for r in rows if r.get("chain") == chain]
        if not include_dynamic:
            rows = [r for r in rows if not r["dynamic"]]
        return _dump({"count": len(rows),
                      "position_note": "index across all chains, for ordering only — never pass it to a write",
                      "rules": rows})

    @tool(name="get_nat_rule", annotations=ToolAnnotations(
        title="Get NAT Rule", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def get_nat_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_nat_rules, e.g. '*7'.")],
    ) -> str:
        """Every field of one NAT rule, including counters."""
        item_id = _require_real_id(rule_id, "NAT rule")
        rule = await router.get(*NAT, item_id=item_id)
        if rule is None:
            raise ToolError(f"No NAT rule with id {item_id!r} exists. It may have been removed.")
        return _dump(_detail(rule))

    @tool(name="add_nat_rule", annotations=ToolAnnotations(
        title="Add NAT Rule", destructive_hint=False, idempotent_hint=False, open_world_hint=False))
    async def add_nat_rule(
        ctx: Context,
        chain: Annotated[Literal["srcnat", "dstnat"], Field(description="'dstnat' for a port forward or redirect, 'srcnat' for masquerade.")],
        action: Annotated[Literal["masquerade", "dst-nat", "src-nat", "redirect", "accept", "netmap"], Field(description="'dst-nat' for port forwards, 'masquerade' for outbound NAT, 'redirect' to send traffic to the router itself. 'dst-nat', 'src-nat' and 'netmap' also need `to_addresses` or `to_ports`.")],
        comment: Annotated[str | None, Field(description="Strongly recommended — an uncommented NAT rule is very hard to audit later.")] = None,
        protocol: Annotated[str | None, Field(description="'tcp', 'udp', 'icmp', or a protocol number. Required before any port matcher.")] = None,
        src_address: str | None = None,
        dst_address: str | None = None,
        src_port: str | None = None,
        dst_port: Annotated[str | None, Field(description="Port, list or range, e.g. '443', '80,443', '1000-2000'. Needs a protocol.")] = None,
        port: Annotated[str | None, Field(description="Matches either source or destination port.")] = None,
        src_address_type: Annotated[str | None, Field(description="'unicast', 'local', 'broadcast', 'multicast'; '!' negates.")] = None,
        dst_address_type: Annotated[str | None, Field(description="'unicast', 'local', 'broadcast', 'multicast'; '!' negates. A DNS redirect is written with dst_address_type='!local', which is what stops it catching queries already addressed to the router and NATting them to themselves.")] = None,
        in_interface: str | None = None,
        in_interface_list: str | None = None,
        out_interface: str | None = None,
        out_interface_list: str | None = None,
        src_address_list: Annotated[str | None, Field(description="Match when the source is on this address list; '!' negates.")] = None,
        dst_address_list: Annotated[str | None, Field(description="Match when the destination is on this address list; '!' negates.")] = None,
        connection_mark: str | None = None,
        to_addresses: Annotated[str | None, Field(description="Address to send matching traffic to, e.g. '192.168.88.50'. Required for dst-nat/src-nat/netmap unless `to_ports` is given.")] = None,
        to_ports: Annotated[str | None, Field(description="Port to send matching traffic to, e.g. '8080'. On its own it rewrites the port and leaves the address alone.")] = None,
        log: bool | None = None,
        log_prefix: str | None = None,
        disabled: Annotated[bool, Field(description="Add the rule disabled, to position it before it takes effect.")] = False,
        place_before: Annotated[str | None, Field(description="Rule 'id' to insert before. Without it the rule lands at the end of the table.")] = None,
    ) -> str:
        """Add a NAT rule, such as a port forward.

        A port forward also needs the forward chain to permit the traffic;
        check `list_firewall_rules(chain='forward')` for a rule accepting
        `connection_nat_state='dstnat'` before concluding it is broken.
        """
        fields = dict(
            chain=chain, action=action, comment=comment, protocol=protocol,
            src_address=src_address, dst_address=dst_address,
            src_port=src_port, dst_port=dst_port, port=port,
            src_address_type=src_address_type, dst_address_type=dst_address_type,
            in_interface=in_interface, in_interface_list=in_interface_list,
            out_interface=out_interface, out_interface_list=out_interface_list,
            src_address_list=src_address_list, dst_address_list=dst_address_list,
            connection_mark=connection_mark,
            to_addresses=to_addresses, to_ports=to_ports,
            log=log, log_prefix=log_prefix,
        )
        _check_action(action, fields, requires=NAT_ACTION_REQUIRES)

        target = _require_real_id(place_before, "NAT rule") if place_before else None
        if target is not None and await router.get(*NAT, item_id=target) is None:
            raise ToolError(
                f"Cannot place the new rule before {target!r}: no such NAT rule exists. "
                f"Nothing was added. Re-list the rules and check the id."
            )

        new_id = await router.add(*NAT, **fields, disabled=disabled or None)
        if target is not None:
            await router.move(*NAT, item_id=new_id, destination=target)
            order = [r.get(".id") for r in await router.list(*NAT)]
            problem = _misplaced(new_id, target, order)
            if problem:
                raise ToolError(
                    f"The rule was created as {new_id}, but placing it failed: {problem}\n"
                    f"  order now: {order}\n"
                    f"Move it with move_nat_rule, or delete it with "
                    f"remove_nat_rule({new_id!r})."
                )

        return _dump({"created": True, "id": new_id, "placed_before": target,
                      "rule": _detail(await router.get(*NAT, item_id=new_id))})

    @tool(name="update_nat_rule", annotations=ToolAnnotations(
        title="Update NAT Rule", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def update_nat_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_nat_rules, e.g. '*7'.")],
        chain: str | None = None,
        action: str | None = None,
        comment: str | None = None,
        protocol: str | None = None,
        src_address: str | None = None,
        dst_address: str | None = None,
        src_port: str | None = None,
        dst_port: str | None = None,
        port: str | None = None,
        src_address_type: str | None = None,
        dst_address_type: Annotated[str | None, Field(description="'unicast', 'local', 'broadcast', 'multicast'; '!' negates.")] = None,
        in_interface: str | None = None,
        in_interface_list: str | None = None,
        out_interface: str | None = None,
        out_interface_list: str | None = None,
        src_address_list: str | None = None,
        dst_address_list: str | None = None,
        connection_mark: str | None = None,
        to_addresses: Annotated[str | None, Field(description="Address to send matching traffic to.")] = None,
        to_ports: Annotated[str | None, Field(description="Port to send matching traffic to.")] = None,
        log: bool | None = None,
        log_prefix: str | None = None,
        unset: Annotated[list[str] | None, Field(description="Fields to clear back to their RouterOS default, e.g. ['src_address']. A field cannot be both set and cleared in one call.")] = None,
    ) -> str:
        """Change fields on an existing NAT rule.

        Only the arguments you pass are modified; omitted ones are left alone.
        Editing in place keeps the rule's id and its position — removing and
        re-adding a port forward loses both, and the replacement lands at the
        end of the table.
        """
        item_id = _require_real_id(rule_id, "NAT rule")
        before = await router.get(*NAT, item_id=item_id)
        if before is None:
            raise ToolError(f"No NAT rule with id {item_id!r} exists. It may have been removed.")

        fields = dict(
            chain=chain, action=action, comment=comment, protocol=protocol,
            src_address=src_address, dst_address=dst_address,
            src_port=src_port, dst_port=dst_port, port=port,
            src_address_type=src_address_type, dst_address_type=dst_address_type,
            in_interface=in_interface, in_interface_list=in_interface_list,
            out_interface=out_interface, out_interface_list=out_interface_list,
            src_address_list=src_address_list, dst_address_list=dst_address_list,
            connection_mark=connection_mark,
            to_addresses=to_addresses, to_ports=to_ports,
            log=log, log_prefix=log_prefix,
        )
        _check_action(action, fields, before, requires=NAT_ACTION_REQUIRES)
        clearing = _unset_fields(unset or [], fields, NAT_EDITABLE)

        # Clearing the last of `to-addresses`/`to-ports` leaves a dst-nat with
        # nothing to rewrite to — the same broken rule the add path refuses.
        effective = action or str(before.get("action", ""))
        if effective in NAT_ACTION_REQUIRES:
            needed = NAT_ACTION_REQUIRES[effective][0]
            remaining = [
                f for f in needed
                if f.replace("_", "-") not in clearing
                and (fields.get(f) is not None or before.get(f.replace("_", "-")))
            ]
            if not remaining:
                raise ToolError(
                    f"That would leave a {effective!r} rule with neither "
                    + " nor ".join(f"`{f}`" for f in needed)
                    + ", which matches traffic and then has nothing to send it to. "
                    f"Set one in the same call, change the action, or remove the rule."
                )

        setting = any(v is not None for v in fields.values())
        if not setting and not clearing:
            raise ToolError(
                "Nothing to change. Pass at least one field to set, or name one in "
                "`unset` to clear it."
            )
        if setting:
            await router.update(*NAT, item_id=item_id, **fields)
        for field in clearing:
            await router.unset(*NAT, item_id=item_id, field=field)

        after = await router.get(*NAT, item_id=item_id)
        return _dump({"updated": True, "id": item_id, "cleared": clearing,
                      "before": _detail(before), "after": _detail(after)})

    @tool(name="move_nat_rule", annotations=ToolAnnotations(
        title="Move NAT Rule", destructive_hint=True, idempotent_hint=False, open_world_hint=False))
    async def move_nat_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The 'id' of the rule to move.")],
        before_rule_id: Annotated[str | None, Field(description="The 'id' of the rule to place it in front of. Omit to move it to the end of the table.")] = None,
    ) -> str:
        """Reorder a NAT rule relative to another rule.

        NAT is first-match-wins within a chain, so a broad `masquerade` ahead of
        a specific `src-nat` means the specific one never runs. Both ends are
        given by `id`, and the resulting order is read back and checked.
        """
        return _dump(await _reorder(NAT, rule_id, before_rule_id, "NAT rule"))

    @tool(name="set_nat_rule_enabled", annotations=ToolAnnotations(
        title="Enable/Disable NAT Rule", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def set_nat_rule_enabled(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_nat_rules, e.g. '*7'.")],
        enabled: bool,
    ) -> str:
        """Enable or disable one NAT rule, leaving its position intact.

        Disabling is the reversible way to test whether a port forward is
        responsible for something — prefer it over removing the rule.
        """
        item_id = _require_real_id(rule_id, "NAT rule")
        rule = await router.get(*NAT, item_id=item_id)
        if rule is None:
            raise ToolError(f"No NAT rule with id {item_id!r} exists. It may have been removed.")
        await router.update(*NAT, item_id=item_id, disabled=not enabled)
        return _dump({"changed": True, "id": item_id, "enabled": enabled,
                      "rule": _detail(await router.get(*NAT, item_id=item_id))})

    @tool(name="remove_nat_rule", annotations=ToolAnnotations(
        title="Remove NAT Rule", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def remove_nat_rule(
        ctx: Context,
        rule_id: Annotated[str, Field(description="The rule 'id' from list_nat_rules, e.g. '*7'.")],
        confirm_comment: Annotated[str | None, Field(description="If given, the removal only proceeds when the rule's comment matches. Cheap insurance that you are deleting the rule you think you are.")] = None,
    ) -> str:
        """Delete a NAT rule permanently.

        There is no undo, and the returned copy is the only record you will
        have afterwards. To change a rule rather than replace it, use
        `update_nat_rule` — it keeps the id and the position.
        """
        item_id = _require_real_id(rule_id, "NAT rule")
        rule = await router.get(*NAT, item_id=item_id)
        if rule is None:
            raise ToolError(f"No NAT rule with id {item_id!r} exists. It may already have been removed.")
        if confirm_comment is not None and rule.get("comment", "") != confirm_comment:
            raise ToolError(
                f"Refusing to remove {item_id}: its comment is {rule.get('comment', '')!r}, "
                f"not {confirm_comment!r}. Re-list the rules and check the id."
            )
        await router.remove(*NAT, item_id=item_id)
        return _dump({"removed": True, "id": item_id, "deleted_rule": _detail(rule)})
    # ── DHCP, DNS, routing ────────────────────────────────────────────────

    @tool(name="list_dhcp_leases", annotations=ToolAnnotations(
        title="List DHCP Leases", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_dhcp_leases(
        ctx: Context,
        active_only: bool = False,
        search: Annotated[str | None, Field(description="Case-insensitive match against hostname, MAC or address.")] = None,
    ) -> str:
        """List DHCP leases — effectively the inventory of what is on the network."""
        rows = await _list("ip", "dhcp-server", "lease")
        if active_only:
            rows = [r for r in rows if r.get("status") == "bound"]
        if search:
            needle = search.lower()
            rows = [r for r in rows if any(needle in str(r.get(k, "")).lower()
                                           for k in ("host-name", "mac-address", "address", "comment"))]
        return _dump(_summarise(rows, (".id", "address", "mac-address", "host-name", "status",
                                       "expires-after", "dynamic", "disabled", "server", "comment"), False,
                                flags=("disabled", "dynamic")))

    @tool(name="make_lease_static", annotations=ToolAnnotations(
        title="Make DHCP Lease Static", destructive_hint=False, idempotent_hint=True, open_world_hint=False))
    async def make_lease_static(
        ctx: Context,
        lease_id: Annotated[str, Field(description="The lease 'id' from list_dhcp_leases.")],
        comment: str | None = None,
    ) -> str:
        """Pin a dynamic DHCP lease so the device keeps its address."""
        item_id = _require_real_id(lease_id, "lease")
        await router.run("ip", "dhcp-server", "lease", command="make-static", numbers=item_id)
        if comment:
            await router.update("ip", "dhcp-server", "lease", item_id=item_id, comment=comment)
        return _dump({"changed": True, "lease": _detail(
            await router.get("ip", "dhcp-server", "lease", item_id=item_id),
            flags=("disabled", "dynamic"))})

    @tool(name="list_dns_static", annotations=ToolAnnotations(
        title="List Static DNS", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_dns_static(ctx: Context) -> str:
        """List static DNS entries and regex overrides."""
        rows = await _list("ip", "dns", "static")
        return _dump({"count": len(rows), "entries": _summarise(
            rows, (".id", "name", "regexp", "address", "cname", "type", "ttl",
                   "match-subdomain", "disabled", "comment"), False,
            flags=("disabled", "dynamic"))})

    @tool(name="add_dns_static", annotations=ToolAnnotations(
        title="Add Static DNS Entry", destructive_hint=False, idempotent_hint=False, open_world_hint=False))
    async def add_dns_static(
        ctx: Context,
        name: Annotated[str | None, Field(description="Hostname to answer for, e.g. 'nas.lan'.")] = None,
        address: Annotated[str | None, Field(description="IPv4 address to return.")] = None,
        cname: Annotated[str | None, Field(description="Return a CNAME instead of an address.")] = None,
        regexp: Annotated[str | None, Field(description="Match hostnames by regex instead of an exact name.")] = None,
        match_subdomain: Annotated[bool | None, Field(description="Also answer for anything under `name`, so 'lan' covers 'nas.lan'.")] = None,
        ttl: str = "1d",
        comment: str | None = None,
    ) -> str:
        """Add a static DNS entry."""
        if not name and not regexp:
            raise ToolError("Provide either `name` (an exact hostname) or `regexp` (a pattern).")
        if not address and not cname:
            raise ToolError("Provide either `address` or `cname` for the answer.")
        new_id = await router.add("ip", "dns", "static", name=name, address=address,
                                  cname=cname, regexp=regexp, ttl=ttl, comment=comment,
                                  match_subdomain=match_subdomain)
        return _dump({"created": True, "id": new_id,
                      "entry": _detail(await router.get("ip", "dns", "static", item_id=new_id),
                                       flags=("disabled",))})

    @tool(name="update_dns_static", annotations=ToolAnnotations(
        title="Update Static DNS Entry", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def update_dns_static(
        ctx: Context,
        entry_id: Annotated[str, Field(description="The entry 'id' from list_dns_static, e.g. '*3'.")],
        name: Annotated[str | None, Field(description="Hostname to answer for, e.g. 'nas.lan'.")] = None,
        address: Annotated[str | None, Field(description="IPv4 address to return.")] = None,
        cname: Annotated[str | None, Field(description="Return a CNAME instead of an address.")] = None,
        regexp: Annotated[str | None, Field(description="Match hostnames by regex instead of an exact name.")] = None,
        match_subdomain: Annotated[bool | None, Field(description="Also answer for anything under `name`.")] = None,
        ttl: str | None = None,
        comment: str | None = None,
        disabled: Annotated[bool | None, Field(description="Disable the entry without deleting it.")] = None,
    ) -> str:
        """Change fields on an existing static DNS entry.

        Only the arguments you pass are modified. Repointing a name at a new
        address belongs here rather than in remove-then-add: editing keeps the
        entry's id, so anything holding a reference to it stays valid.
        """
        item_id = _require_real_id(entry_id, "DNS entry")
        before = await router.get("ip", "dns", "static", item_id=item_id)
        if before is None:
            raise ToolError(f"No static DNS entry with id {item_id!r} exists. It may have been removed.")

        fields = dict(name=name, address=address, cname=cname, regexp=regexp,
                      match_subdomain=match_subdomain, ttl=ttl, comment=comment,
                      disabled=disabled)
        if all(v is None for v in fields.values()):
            raise ToolError("Nothing to change. Pass at least one field to set.")

        await router.update("ip", "dns", "static", item_id=item_id, **fields)
        after = await router.get("ip", "dns", "static", item_id=item_id)
        return _dump({"updated": True, "id": item_id,
                      "before": _detail(before, flags=("disabled",)),
                      "after": _detail(after, flags=("disabled",))})

    @tool(name="remove_dns_static", annotations=ToolAnnotations(
        title="Remove Static DNS Entry", destructive_hint=True, idempotent_hint=True, open_world_hint=False))
    async def remove_dns_static(ctx: Context, entry_id: str) -> str:
        """Delete a static DNS entry."""
        item_id = _require_real_id(entry_id, "DNS entry")
        entry = await router.get("ip", "dns", "static", item_id=item_id)
        if entry is None:
            raise ToolError(f"No static DNS entry with id {item_id!r} exists.")
        await router.remove("ip", "dns", "static", item_id=item_id)
        return _dump({"removed": True, "id": item_id,
                      "deleted_entry": _detail(entry, flags=("disabled",))})

    @tool(name="get_dns_settings", annotations=ToolAnnotations(
        title="Get DNS Settings", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def get_dns_settings(ctx: Context) -> str:
        """Resolver configuration: upstream servers, cache, and who may query it.

        `allow-remote-requests` is the field to look at first. With it set, the
        router answers DNS for anything that can reach port 53, so whether the
        firewall restricts that reaching is the difference between a LAN
        resolver and an open one that can be used to amplify traffic at someone
        else.
        """
        rows = await _list("ip", "dns")
        settings = rows[0] if rows else {}
        flags = {k: _flag(settings.get(k)) for k in ("allow-remote-requests", "use-doh-server-verify-certificate")}
        return _dump({"settings": {**settings, **flags},
                      "static_entries": len(await _list("ip", "dns", "static"))})

    @tool(name="list_dns_adlist", annotations=ToolAnnotations(
        title="List DNS Adlists", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_dns_adlist(ctx: Context) -> str:
        """Blocklist files the DNS server loads (RouterOS 7.15 and later).

        Reports a `match-count` per list, which is how you tell a list that is
        doing work from one that failed to download.
        """
        try:
            rows = await _list("ip", "dns", "adlist")
        except ToolError as exc:
            raise ToolError(
                f"Could not read ip/dns/adlist: {exc}\n"
                f"  Adlists were added in RouterOS 7.15; on an older release the menu "
                f"does not exist. Check the version with system_info."
            ) from exc
        return _dump({"count": len(rows), "adlists": _summarise(
            rows, (".id", "url", "file", "ssl-verify", "match-count", "name-count",
                   "disabled", "comment"), False, flags=("disabled",))})

    @tool(name="list_routes", annotations=ToolAnnotations(
        title="List Routes", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def list_routes(ctx: Context, active_only: bool = False) -> str:
        """List the IPv4 routing table."""
        rows = await _list("ip", "route")
        if active_only:
            rows = [r for r in rows if r.get("active") in (True, "true", "yes")]
        return _dump(_summarise(rows, (".id", "dst-address", "gateway", "distance", "active",
                                       "static", "dynamic", "disabled", "routing-table", "comment"), False,
                                flags=("disabled", "dynamic", "active", "inactive")))

    # ── observability ─────────────────────────────────────────────────────

    @tool(name="get_logs", annotations=ToolAnnotations(
        title="Get Logs", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def get_logs(
        ctx: Context,
        limit: Annotated[int, Field(description="Most recent N entries.", ge=1, le=500)] = 50,
        topic: Annotated[str | None, Field(description="Filter by RouterOS log topic, e.g. 'firewall', 'dhcp', 'system', 'error'.")] = None,
        search: Annotated[str | None, Field(description="Case-insensitive substring match on the message.")] = None,
    ) -> str:
        """Read the device log, most recent last."""
        rows = await _list("log")
        if topic:
            rows = [r for r in rows if topic in str(r.get("topics", ""))]
        if search:
            needle = search.lower()
            rows = [r for r in rows if needle in str(r.get("message", "")).lower()]
        return _dump({"count": len(rows[-limit:]), "entries": [
            {k: r.get(k) for k in ("time", "topics", "message")} for r in rows[-limit:]
        ]})

    @tool(name="connectivity_check", annotations=ToolAnnotations(
        title="Connectivity Check", read_only_hint=True, idempotent_hint=True, open_world_hint=False))
    async def connectivity_check(ctx: Context) -> str:
        """Confirm the hub can reach and authenticate to this device."""
        try:
            rows = await device.list("system", "identity")
        except RouterError as exc:
            return _dump({"reachable": False, "error": str(exc)})
        return _dump({"reachable": True, "identity": rows[0].get("name") if rows else None})
