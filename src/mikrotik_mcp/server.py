"""Builds the MCP server for one MikroTik device."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .client import RouterConfig, RouterOS
from .tools import register

__version__ = "0.3.0"

INSTRUCTIONS = (
    "Tools for one MikroTik RouterOS device, over the RouterOS binary API.\n\n"
    "Every item the device holds has an `id` that looks like `*7`. Reads return "
    "it; writes require it. List results also carry a `position`, which is where "
    "the item currently sits in evaluation order — it is for reading, and it "
    "shifts whenever anything is added, removed or moved, so it is never a valid "
    "way to address a write. `position` is an index across the whole table, not "
    "within the chain you filtered to: the first three rules of the forward "
    "chain may well come back numbered 29, 30, 31.\n\n"
    "Firewall rules are evaluated in order and the first match wins, so when "
    "adding a rule, place it deliberately rather than letting it land at the end "
    "of a chain that terminates in a drop.\n\n"
    "IPv4 and IPv6 are filtered by separate rule sets. The firewall tools take a "
    "`family` and default to `ipv4`, so a device that looks locked down may have "
    "an empty — and therefore fully permissive — IPv6 table. Check both before "
    "concluding anything about what the device blocks.\n\n"
    "Address lists are how RouterOS firewalls express most of their state, and "
    "the entries a rule adds with a timeout exist only at runtime: no "
    "configuration export will show them. Read them with the address list tools, "
    "and ask for a count before asking for entries — a populated block list can "
    "hold tens of thousands."
)


def build_server(config: RouterConfig, *, title: str = "MikroTik", name: str = "mikrotik") -> MCPServer:
    """Return a server bound to one device.

    Performs no I/O: an unreachable router still has to produce a server, so
    the tools can report the failure themselves rather than the process
    refusing to start.
    """
    mcp = MCPServer(name=name, title=title, instructions=INSTRUCTIONS, version=__version__)
    register(mcp, RouterOS(config), title=title)
    return mcp
