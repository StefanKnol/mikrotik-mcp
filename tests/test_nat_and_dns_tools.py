"""NAT and DNS: the same guarantees the filter tools give.

NAT is an ordered, first-match-wins table exactly like the filter chains, so it
gets the same treatment — reorder by id with the result verified, edit in place
rather than remove-and-re-add, and a refusal rather than a rule that matches
traffic and then has nothing to do with it.
"""

import json

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mikrotik_mcp.tools import register

from test_firewall_tools import FakeRouter, ToolFailed, call

NAT = ("ip", "firewall", "nat")
DNS = ("ip", "dns", "static")

NAT_RULES = [
    {".id": "*20", "chain": "srcnat", "action": "masquerade", "out-interface": "ether1",
     "comment": "outbound"},
    {".id": "*21", "chain": "dstnat", "action": "dst-nat", "protocol": "tcp",
     "dst-port": 443, "to-addresses": "192.168.88.50", "to-ports": 8443,
     "comment": "https to the nas"},
    {".id": "*22", "chain": "dstnat", "action": "redirect", "protocol": "udp",
     "dst-port": 53, "dst-address-type": "!local", "comment": "dns redirect"},
]

DNS_ENTRIES = [
    {".id": "*30", "name": "nas.lan", "address": "192.168.88.50", "ttl": "1d"},
    {".id": "*31", "name": "old.lan", "address": "192.168.88.9", "ttl": "1d"},
]


@pytest.fixture
def server():
    router = FakeRouter([])
    router._items[NAT] = [dict(r) for r in NAT_RULES]
    router._items[DNS] = [dict(r) for r in DNS_ENTRIES]
    mcp = MCPServer("test-router")
    register(mcp, router, title="Test Router")
    return mcp, router


# ── NAT reads ─────────────────────────────────────────────────────────────

async def test_nat_rules_list_with_ids_and_normalised_fields(server):
    mcp, _ = server
    out = await call(mcp, "list_nat_rules")
    rules = {r["id"]: r for r in out["rules"]}
    assert list(rules) == ["*20", "*21", "*22"]
    # Same normalisation the filter tools give: ports are text, flags are real
    # booleans and always present.
    assert rules["*21"]["dst-port"] == "443"
    assert rules["*21"]["to-ports"] == "8443"
    assert rules["*20"]["disabled"] is False
    assert rules["*20"]["invalid"] is False


async def test_a_nat_rule_can_be_read_on_its_own(server):
    mcp, _ = server
    out = await call(mcp, "get_nat_rule", rule_id="*21")
    assert out["id"] == "*21"
    assert out["to-addresses"] == "192.168.88.50"


async def test_getting_a_missing_nat_rule_says_so(server):
    mcp, _ = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "get_nat_rule", rule_id="*ZZ99")
    assert "*ZZ99" in str(excinfo.value)


# ── the guard ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("action", ["dst-nat", "src-nat", "netmap"])
async def test_a_rewrite_action_with_nothing_to_rewrite_to_is_refused(server, action):
    """Matches traffic, then has nowhere to send it. Never a working rule."""
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "add_nat_rule", chain="dstnat", action=action,
                   protocol="tcp", dst_port="8080")
    assert "to_addresses" in str(excinfo.value)
    assert "to_ports" in str(excinfo.value)
    assert len(router._items[NAT]) == 3, "nothing should have been created"


async def test_dst_nat_with_only_a_port_is_allowed(server):
    """The reason the guard is on the pair: this rewrites the port only."""
    mcp, _ = server
    out = await call(mcp, "add_nat_rule", chain="dstnat", action="dst-nat",
                     protocol="tcp", dst_port="8080", to_ports="80",
                     comment="port shift, same host")
    assert out["created"] is True
    assert out["rule"]["to-ports"] == "80"


async def test_dst_nat_with_only_an_address_is_allowed(server):
    mcp, _ = server
    out = await call(mcp, "add_nat_rule", chain="dstnat", action="dst-nat",
                     protocol="tcp", dst_port="25", to_addresses="192.168.88.7")
    assert out["rule"]["to-addresses"] == "192.168.88.7"


@pytest.mark.parametrize("action", ["masquerade", "redirect", "accept"])
async def test_self_sufficient_actions_are_not_guarded(server, action):
    """These do not rewrite to anywhere, so requiring a target would be wrong."""
    mcp, _ = server
    out = await call(mcp, "add_nat_rule", chain="srcnat", action=action,
                     out_interface="ether1")
    assert out["created"] is True


async def test_clearing_the_last_rewrite_target_is_refused(server):
    mcp, _ = server
    # One of the pair may go while the other remains.
    out = await call(mcp, "update_nat_rule", rule_id="*21", unset=["to_ports"])
    assert out["cleared"] == ["to-ports"]
    # The last one may not.
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_nat_rule", rule_id="*21", unset=["to_addresses"])
    assert "nothing to send it to" in str(excinfo.value)


async def test_clearing_both_at_once_is_refused(server):
    mcp, _ = server
    with pytest.raises(ToolFailed):
        await call(mcp, "update_nat_rule", rule_id="*21",
                   unset=["to_addresses", "to_ports"])


async def test_clearing_a_target_is_fine_when_the_action_stops_needing_it(server):
    mcp, _ = server
    out = await call(mcp, "update_nat_rule", rule_id="*21", action="accept",
                     unset=["to_addresses", "to_ports"])
    assert out["after"]["action"] == "accept"


# ── the DNS redirect matcher that was missing ─────────────────────────────

async def test_dst_address_type_is_settable_on_a_nat_rule(server):
    """`dst-address-type=!local` is what stops a DNS redirect self-NATting."""
    mcp, _ = server
    out = await call(mcp, "add_nat_rule", chain="dstnat", action="redirect",
                     protocol="udp", dst_port="53", dst_address_type="!local",
                     comment="dns redirect")
    assert out["rule"]["dst-address-type"] == "!local"


async def test_the_existing_redirect_survives_a_read_modify_write(server):
    """The round trip that used to drop the matcher and widen the rule."""
    mcp, _ = server
    before = await call(mcp, "get_nat_rule", rule_id="*22")
    assert before["dst-address-type"] == "!local"
    out = await call(mcp, "update_nat_rule", rule_id="*22", comment="dns redirect v2")
    assert out["after"]["dst-address-type"] == "!local"


# ── NAT ordering ──────────────────────────────────────────────────────────

async def test_a_nat_rule_can_be_moved_by_id(server):
    mcp, router = server
    out = await call(mcp, "move_nat_rule", rule_id="*22", before_rule_id="*21")
    assert out["moved"] is True
    assert router.order(NAT) == ["*20", "*22", "*21"]


async def test_moving_a_nat_rule_to_the_end(server):
    mcp, router = server
    await call(mcp, "move_nat_rule", rule_id="*20")
    assert router.order(NAT) == ["*21", "*22", "*20"]


async def test_a_nat_move_rejects_a_position(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_nat_rule", rule_id="1", before_rule_id="*21")
    assert "position" in str(excinfo.value).lower()
    assert router.order(NAT) == ["*20", "*21", "*22"]


async def test_a_nat_move_that_did_not_happen_is_a_failure(server):
    mcp, router = server

    async def refuse(*path, item_id, destination=None):
        pass

    router.move = refuse
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_nat_rule", rule_id="*22", before_rule_id="*21")
    assert "did not take effect" in str(excinfo.value)


async def test_place_before_puts_a_new_nat_rule_ahead_of_an_existing_one(server):
    mcp, router = server
    out = await call(mcp, "add_nat_rule", chain="dstnat", action="dst-nat",
                     protocol="tcp", dst_port="22", to_addresses="192.168.88.4",
                     place_before="*21")
    assert router.order(NAT) == ["*20", out["id"], "*21", "*22"]


# ── NAT edits keep id and position ────────────────────────────────────────

async def test_editing_a_port_forward_keeps_its_id_and_place(server):
    """The reason update exists: remove-and-re-add loses both."""
    mcp, router = server
    out = await call(mcp, "update_nat_rule", rule_id="*21", to_addresses="192.168.88.60")
    assert out["id"] == "*21"
    assert out["before"]["to-addresses"] == "192.168.88.50"
    assert out["after"]["to-addresses"] == "192.168.88.60"
    assert router.order(NAT) == ["*20", "*21", "*22"]


async def test_a_nat_update_that_changes_nothing_is_refused(server):
    mcp, _ = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_nat_rule", rule_id="*21")
    assert "Nothing to change" in str(excinfo.value)


async def test_removing_a_nat_rule_honours_the_comment_guard(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "remove_nat_rule", rule_id="*21", confirm_comment="outbound")
    assert "refusing" in str(excinfo.value).lower()
    assert len(router._items[NAT]) == 3

    out = await call(mcp, "remove_nat_rule", rule_id="*21",
                     confirm_comment="https to the nas")
    assert out["deleted_rule"]["id"] == "*21"
    assert len(router._items[NAT]) == 2


# ── DNS ───────────────────────────────────────────────────────────────────

async def test_a_dns_entry_can_be_repointed_in_place(server):
    mcp, _ = server
    out = await call(mcp, "update_dns_static", entry_id="*30", address="192.168.88.60")
    assert out["id"] == "*30"
    assert out["before"]["address"] == "192.168.88.50"
    assert out["after"]["address"] == "192.168.88.60"


async def test_a_dns_entry_can_be_disabled_rather_than_deleted(server):
    mcp, _ = server
    out = await call(mcp, "update_dns_static", entry_id="*31", disabled=True)
    assert out["after"]["disabled"] is True


async def test_updating_a_missing_dns_entry_fails_cleanly(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_dns_static", entry_id="*ZZ99", address="10.0.0.1")
    assert "*ZZ99" in str(excinfo.value)
    assert router.calls == []


async def test_a_dns_update_that_changes_nothing_is_refused(server):
    mcp, _ = server
    with pytest.raises(ToolFailed):
        await call(mcp, "update_dns_static", entry_id="*30")


async def test_dns_static_listing_reports_ids_and_flags(server):
    mcp, _ = server
    out = await call(mcp, "list_dns_static")
    assert out["count"] == 2
    assert out["entries"][0]["id"] == "*30"
    assert out["entries"][0]["disabled"] is False
