"""The annotations mcphub enforces levels from.

The hub does not ask this server to check anything. It reads `readOnlyHint` and
`destructiveHint` off `tools/list` and decides from those alone:

    viewer  only readOnlyHint: true
    user    everything except destructiveHint: true
    admin   everything

So an annotation is not documentation here, it is the access control. A tool
that is annotated wrongly is either withheld from someone who should have it or
handed to someone who should not, and nothing downstream will catch it.

Every tool is named in `EXPECTED` below. A new tool fails this test until
someone classifies it, which is the point: the default for an unannotated tool
is "withheld from a viewer, allowed for a user", and that should be a decision
rather than an oversight.
"""

import pytest
from mcp.server.mcpserver import MCPServer

from mikrotik_mcp.client import RouterConfig, RouterOS
from mikrotik_mcp.tools import register

# Reading only. Safe for an account that may look but not touch.
VIEWER = {
    "connectivity_check",
    "get_dns_settings",
    "get_firewall_rule",
    "get_logs",
    "get_nat_rule",
    "list_address_list_entries",
    "list_address_lists",
    "list_dhcp_leases",
    "list_dns_adlist",
    "list_dns_static",
    "list_firewall_rules",
    "list_interfaces",
    "list_ip_addresses",
    "list_nat_rules",
    "list_routes",
    "ros_list",
    "system_info",
}

# Changes the device, but takes nothing away. Adding a rule is a write and not
# a destruction; so is pinning a lease, or flipping a rule off and on again.
USER = {
    "add_address_list_entry",
    "add_dns_static",
    "add_firewall_rule",
    "add_nat_rule",
    "make_lease_static",
    "set_firewall_rule_enabled",
    "set_nat_rule_enabled",
}

# Destroys or overwrites something a person would mind losing: deletions,
# in-place edits that discard the previous value, reorderings that cannot be
# undone from what the call returns, and the one toggle that can cut off the
# only route back to the device.
ADMIN = {
    "move_firewall_rule",
    "move_nat_rule",
    "remove_address_list_entry",
    "remove_dns_static",
    "remove_firewall_rule",
    "remove_nat_rule",
    "set_interface_enabled",
    "update_dns_static",
    "update_firewall_rule",
    "update_nat_rule",
}

EXPECTED = {name: "viewer" for name in VIEWER} | {name: "user" for name in USER} \
    | {name: "admin" for name in ADMIN}


def level_of(annotations) -> str:
    """The level the hub will file a tool under, by the hub's own rule."""
    if annotations is None:
        return "user"  # withheld from a viewer, allowed for a user
    if annotations.get("readOnlyHint"):
        return "viewer"
    if annotations.get("destructiveHint"):
        return "admin"
    return "user"


@pytest.fixture(scope="module")
def tools():
    mcp = MCPServer("annotations")
    register(mcp, RouterOS(RouterConfig(host="h", username="u", password="p")), title="T")
    return mcp


async def wire(mcp) -> dict[str, dict]:
    """Annotations exactly as they go over the protocol."""
    return {
        t.name: (t.annotations.model_dump(by_alias=True, exclude_none=True)
                 if t.annotations else None)
        for t in await mcp.list_tools()
    }


async def test_every_tool_is_classified(tools):
    """A tool nobody classified is a tool whose access level was an accident."""
    listed = set(await wire(tools))
    assert listed - set(EXPECTED) == set(), "new tool: add it to VIEWER, USER or ADMIN"
    assert set(EXPECTED) - listed == set(), "tool in EXPECTED no longer exists"


async def test_every_tool_lands_in_the_expected_level(tools):
    got = {name: level_of(a) for name, a in (await wire(tools)).items()}
    assert got == EXPECTED


async def test_no_tool_relies_on_the_unannotated_default(tools):
    """`user` should be a claim the tool makes, not one it fell into."""
    bare = [name for name, a in (await wire(tools)).items()
            if a is None or ("readOnlyHint" not in a and "destructiveHint" not in a)]
    assert bare == []


async def test_hints_reach_the_wire_in_the_spelling_the_hub_reads(tools):
    """The SDK takes `read_only_hint` and must emit `readOnlyHint`.

    If that aliasing ever changed, every tool would read as unannotated and a
    viewer would silently get nothing — with no error anywhere to say so.
    """
    annotations = await wire(tools)
    assert annotations["list_firewall_rules"]["readOnlyHint"] is True
    assert annotations["remove_firewall_rule"]["destructiveHint"] is True
    assert annotations["add_firewall_rule"]["destructiveHint"] is False
    for name, payload in annotations.items():
        assert "read_only_hint" not in payload, f"{name} emitted snake_case"
        assert "destructive_hint" not in payload, f"{name} emitted snake_case"


async def test_a_viewer_is_offered_a_useful_server(tools):
    """The read-only surface has to stand on its own to be worth granting."""
    viewer = {n for n, a in (await wire(tools)).items() if level_of(a) == "viewer"}
    assert {"list_firewall_rules", "list_nat_rules", "list_address_lists",
            "system_info", "get_logs"} <= viewer


async def test_nothing_read_only_is_also_destructive(tools):
    for name, payload in (await wire(tools)).items():
        if payload and payload.get("readOnlyHint"):
            assert not payload.get("destructiveHint"), f"{name} claims both"


async def test_every_delete_is_destructive(tools):
    """The one mistake with real consequences: deletion below admin."""
    annotations = await wire(tools)
    for name, payload in annotations.items():
        if name.startswith("remove_"):
            assert payload and payload.get("destructiveHint") is True, name
