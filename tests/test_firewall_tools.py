"""End-to-end tool behaviour against a stand-in RouterOS.

Exercises the tools the way a client does — through the MCP server's dispatch —
so the argument schemas and the id handling are both covered.

The stand-in models *order*, because order is the entire semantics of a
RouterOS firewall and a move that returns without error is not the same thing
as a move that happened. What actually goes over the wire is covered a layer
down, in `test_client_commands.py`.
"""

import copy
import json

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mikrotik_mcp.client import _ros_values
from mikrotik_mcp.tools import register

FILTER = ("ip", "firewall", "filter")
FILTER6 = ("ipv6", "firewall", "filter")
ADDRESS_LIST = ("ip", "firewall", "address-list")


class FakeRouter:
    """Mimics the parts of RouterOS the client layer exposes.

    Crucially it behaves like the *binary API*: every item carries a real `.id`,
    and writes address items by that id alone. A positional index reaching this
    layer simply finds nothing, which is what makes the tests meaningful.
    """

    def __init__(self, rules, ipv6_rules=(), address_list=()):
        # Deep copy: a shallow one shares the rule dicts with the module-level
        # fixture, so an update in one test leaks into every later test.
        self._items = {
            FILTER: copy.deepcopy(list(rules)),
            FILTER6: copy.deepcopy(list(ipv6_rules)),
            ADDRESS_LIST: copy.deepcopy(list(address_list)),
        }
        self.calls = []

    async def list(self, *path):
        return [dict(r) for r in self._items.get(path, [])]

    async def get(self, *path, item_id):
        return next((dict(r) for r in self._items.get(path, []) if r[".id"] == item_id), None)

    async def add(self, *path, **fields):
        items = self._items.setdefault(path, [])
        new_id = f"*{len(items) + 100:x}"
        items.append({".id": new_id, **_ros_values(fields)})
        return new_id

    async def update(self, *path, item_id, **fields):
        self.calls.append(("update", item_id))
        for row in self._items.get(path, []):
            if row[".id"] == item_id:
                # Same translation the real client applies, so the stored shape
                # matches the device's (booleans become "yes"/"no").
                row.update(_ros_values(fields))
                return
        raise AssertionError(f"update targeted {item_id!r}, which does not exist")

    async def remove(self, *path, item_id):
        self.calls.append(("remove", item_id))
        items = self._items.get(path, [])
        before = len(items)
        self._items[path] = [r for r in items if r[".id"] != item_id]
        if len(self._items[path]) == before:
            raise AssertionError(f"remove targeted {item_id!r}, which does not exist")

    async def unset(self, *path, item_id, field):
        self.calls.append(("unset", item_id, field))
        for row in self._items.get(path, []):
            if row[".id"] == item_id:
                row.pop(field, None)
                return
        raise AssertionError(f"unset targeted {item_id!r}, which does not exist")

    async def move(self, *path, item_id, destination=None):
        self.calls.append(("move", item_id, destination))
        items = self._items[path]
        row = next(r for r in items if r[".id"] == item_id)
        items.remove(row)
        if destination is None:
            items.append(row)
        else:
            # "Before this one", resolved after the removal so the index means
            # the same thing it will mean on the device.
            items.insert(next(i for i, r in enumerate(items) if r[".id"] == destination), row)

    async def query(self, *path, where=None, proplist=()):
        rows = [dict(r) for r in self._items.get(path, [])]
        for key, value in (where or {}).items():
            rows = [r for r in rows if _matches(r, key, value)]
        if proplist:
            rows = [{k: v for k, v in r.items() if k in proplist} for r in rows]
        return rows

    async def count(self, *path, where=None):
        return len(await self.query(*path, where=where))

    async def run(self, *path, command, **fields):
        self.calls.append((command, fields))
        return []

    def order(self, path=FILTER):
        return [r[".id"] for r in self._items[path]]


def _matches(row, key, value):
    actual = row.get(key)
    if value in ("true", "false", "yes", "no"):
        return (actual in (True, "true", "yes")) == (value in ("true", "yes"))
    return str(actual) == value


RULES = [
    {".id": "*0", "chain": "input", "action": "accept", "comment": "back-to-home-vpn", "dynamic": "true"},
    {".id": "*7", "chain": "input", "action": "drop", "src-address": "156.147.69.32"},
    {".id": "*a", "chain": "forward", "action": "accept", "comment": "Accept Port Forwards"},
    {".id": "*1f", "chain": "input", "action": "accept", "comment": "Accept Existing Connections (CRITICAL)"},
]

IPV6_RULES = [{".id": "*b1", "chain": "input", "action": "drop", "comment": "v6 drop"}]

ADDRESS_ENTRIES = [
    {".id": "*c1", "list": "blocked", "address": "203.0.113.5", "dynamic": "true", "timeout": "23h59m"},
    {".id": "*c2", "list": "blocked", "address": "203.0.113.6", "dynamic": "true", "timeout": "23h59m"},
    {".id": "*c3", "list": "trusted", "address": "192.168.88.0/24"},
]


@pytest.fixture
def server():
    router = FakeRouter(RULES, IPV6_RULES, ADDRESS_ENTRIES)
    mcp = MCPServer("test-router")
    register(mcp, router, title="Test Router")
    return mcp, router


async def call(mcp, name, **args):
    """Call a tool the way a client does, turning any failure into ToolFailed."""
    try:
        result = await mcp.call_tool(name, args)
    except ToolError as exc:
        raise ToolFailed(str(exc)) from exc
    if result.is_error:
        raise ToolFailed(result.content[0].text)
    return json.loads(result.content[0].text)


class ToolFailed(Exception):
    """A tool that reported is_error, so tests can assert on the message."""


# ── reading ───────────────────────────────────────────────────────────────

async def test_list_reports_ids_and_positions(server):
    mcp, _ = server
    out = await call(mcp, "list_firewall_rules")
    ids = [r["id"] for r in out["rules"]]
    assert ids == ["*7", "*a", "*1f"], "dynamic rules are excluded by default"
    # Positions stay the device's real evaluation positions: the dynamic rule
    # filtered out of this view still occupies position 0 on the router, and
    # renumbering the visible rules 0,1,2 would misreport where they sit.
    assert [r["position"] for r in out["rules"]] == [1, 2, 3]


async def test_list_can_include_dynamic_rules(server):
    mcp, _ = server
    out = await call(mcp, "list_firewall_rules", include_dynamic=True)
    assert [r["id"] for r in out["rules"]] == ["*0", "*7", "*a", "*1f"]


async def test_flags_are_always_present_and_default_to_false(server):
    """A missing `disabled` is the device saying "no", not saying nothing."""
    mcp, _ = server
    rule = (await call(mcp, "list_firewall_rules"))["rules"][0]
    assert rule["disabled"] is False
    assert rule["log"] is False
    assert rule["dynamic"] is False
    # `invalid` is the highest-value thing a listing can report — a rule naming
    # an interface or address list that no longer exists — so it is not hidden
    # behind verbose.
    assert rule["invalid"] is False


async def test_matchers_that_define_a_rule_are_in_the_default_view(server):
    """Without these a scan detector reads as an unconditional drop."""
    mcp, _ = server
    out = await call(mcp, "add_firewall_rule", chain="input", action="drop",
                     protocol="tcp", psd="21,3s,3,1", connection_limit="100,32",
                     comment="port scan")
    listed = next(r for r in (await call(mcp, "list_firewall_rules"))["rules"]
                  if r["id"] == out["id"])
    assert listed["psd"] == "21,3s,3,1"
    assert listed["connection-limit"] == "100,32"


async def test_ports_are_always_text_whatever_the_device_sent(server):
    """RouterOS types this field by content; the tool should not."""
    mcp, router = server
    router._items[FILTER].append({".id": "*d1", "chain": "input", "action": "drop", "dst-port": 9991})
    router._items[FILTER].append({".id": "*d2", "chain": "input", "action": "drop", "dst-port": "80,443"})
    listed = {r["id"]: r for r in (await call(mcp, "list_firewall_rules"))["rules"]}
    assert listed["*d1"]["dst-port"] == "9991"
    assert listed["*d2"]["dst-port"] == "80,443"
    assert (await call(mcp, "get_firewall_rule", rule_id="*d1"))["dst-port"] == "9991"


async def test_every_shape_spells_the_identifier_the_same_way(server):
    """List, get, add, update and remove all return `id`, never `.id`."""
    mcp, _ = server
    listed = (await call(mcp, "list_firewall_rules"))["rules"][0]
    got = await call(mcp, "get_firewall_rule", rule_id="*7")
    added = await call(mcp, "add_firewall_rule", chain="input", action="drop")
    updated = await call(mcp, "update_firewall_rule", rule_id="*7", comment="x")
    removed = await call(mcp, "remove_firewall_rule", rule_id="*7")
    for shape in (listed, got, added["rule"], updated["before"], updated["after"],
                  removed["deleted_rule"]):
        assert "id" in shape and ".id" not in shape


async def test_listing_ipv4_reports_that_ipv6_is_filtered_separately(server):
    mcp, _ = server
    out = await call(mcp, "list_firewall_rules")
    assert out["ipv6"]["rule_count"] == 1


async def test_an_empty_ipv6_table_is_called_out_as_permissive(server):
    """The failure mode: v4 reads locked down, v6 accepts everything."""
    mcp, router = server
    router._items[FILTER6] = []
    out = await call(mcp, "list_firewall_rules")
    assert out["ipv6"]["rule_count"] == 0
    assert "accepted" in out["ipv6"]["warning"]


async def test_ipv6_rules_are_reachable_by_family(server):
    mcp, _ = server
    out = await call(mcp, "list_firewall_rules", family="ipv6")
    assert [r["id"] for r in out["rules"]] == ["*b1"]


# ── writing by id ─────────────────────────────────────────────────────────

async def test_update_by_real_id_succeeds_and_reads_back(server):
    """The exact operation that failed on the server this replaces."""
    mcp, router = server
    out = await call(mcp, "update_firewall_rule", rule_id="*a", comment="renamed")
    assert out["updated"] is True
    assert out["before"]["comment"] == "Accept Port Forwards"
    assert out["after"]["comment"] == "renamed"
    assert ("update", "*a") in router.calls


async def test_update_by_position_is_refused_before_touching_the_device(server):
    mcp, router = server
    # "1" is the position of *a in the listing above — the value a caller would
    # copy from CLI-style output.
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_firewall_rule", rule_id="1", comment="oops")
    assert "position" in str(excinfo.value).lower()
    assert router.calls == [], "nothing should have been sent to the device"


async def test_update_of_a_removed_rule_fails_cleanly(server):
    mcp, router = server
    await call(mcp, "remove_firewall_rule", rule_id="*7")
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_firewall_rule", rule_id="*7", comment="x")
    assert "*7" in str(excinfo.value)
    # It failed by name rather than silently editing whatever took that slot.
    assert ("update", "*7") not in router.calls


async def test_remove_returns_the_deleted_rule(server):
    mcp, _ = server
    out = await call(mcp, "remove_firewall_rule", rule_id="*a")
    assert out["removed"] is True
    assert out["deleted_rule"]["comment"] == "Accept Port Forwards"
    remaining = await call(mcp, "list_firewall_rules")
    assert "*a" not in [r["id"] for r in remaining["rules"]]


async def test_remove_honours_the_comment_guard(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "remove_firewall_rule", rule_id="*1f", confirm_comment="Accept Port Forwards")
    assert "refusing" in str(excinfo.value).lower()
    assert router.calls == []
    still_there = await call(mcp, "get_firewall_rule", rule_id="*1f")
    assert still_there["comment"] == "Accept Existing Connections (CRITICAL)"


async def test_disable_keeps_the_rule_in_place(server):
    mcp, router = server
    out = await call(mcp, "set_firewall_rule_enabled", rule_id="*7", enabled=False)
    assert out["enabled"] is False
    assert out["rule"]["disabled"] is True
    assert router.order() == ["*0", "*7", "*a", "*1f"]


async def test_add_returns_the_created_rule(server):
    mcp, _ = server
    out = await call(mcp, "add_firewall_rule", chain="forward", action="drop",
                     comment="block thing", dst_port="853", protocol="udp")
    assert out["created"] is True
    assert out["id"].startswith("*")
    assert out["rule"]["comment"] == "block thing"
    assert out["rule"]["dst-port"] == "853"


# ── ordering ──────────────────────────────────────────────────────────────

async def test_move_puts_the_rule_immediately_before_the_target(server):
    mcp, router = server
    out = await call(mcp, "move_firewall_rule", rule_id="*1f", before_rule_id="*7")
    assert out["moved"] is True
    assert router.order() == ["*0", "*1f", "*7", "*a"]


async def test_move_backwards_lands_where_it_was_asked_to(server):
    mcp, router = server
    await call(mcp, "move_firewall_rule", rule_id="*0", before_rule_id="*1f")
    assert router.order() == ["*7", "*a", "*0", "*1f"]


async def test_move_without_a_destination_goes_to_the_end(server):
    mcp, router = server
    out = await call(mcp, "move_firewall_rule", rule_id="*7")
    assert router.order() == ["*0", "*a", "*1f", "*7"]
    assert out["before_rule_id"] is None


async def test_move_reports_the_resulting_chain_order(server):
    mcp, _ = server
    out = await call(mcp, "move_firewall_rule", rule_id="*1f", before_rule_id="*7")
    assert out["chain"] == "input"
    assert [r["id"] for r in out["chain_order"]] == ["*0", "*1f", "*7"]


async def test_move_to_a_missing_target_changes_nothing(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_firewall_rule", rule_id="*7", before_rule_id="*ZZ99")
    assert "*ZZ99" in str(excinfo.value)
    assert "Nothing was moved" in str(excinfo.value)
    assert router.order() == ["*0", "*7", "*a", "*1f"]


async def test_moving_a_missing_rule_says_which_one(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_firewall_rule", rule_id="*ZZ99", before_rule_id="*7")
    assert "*ZZ99" in str(excinfo.value)
    assert router.order() == ["*0", "*7", "*a", "*1f"]


async def test_move_rejects_a_position_at_either_end(server):
    mcp, router = server
    for args in ({"rule_id": "1", "before_rule_id": "*7"},
                 {"rule_id": "*7", "before_rule_id": "2"}):
        with pytest.raises(ToolFailed) as excinfo:
            await call(mcp, "move_firewall_rule", **args)
        assert "position" in str(excinfo.value).lower()
    assert not any(c[0] == "move" for c in router.calls)


async def test_a_rule_cannot_be_moved_before_itself(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_firewall_rule", rule_id="*7", before_rule_id="*7")
    assert "itself" in str(excinfo.value)
    assert not any(c[0] == "move" for c in router.calls)


async def test_moving_across_chains_works_but_says_so(server):
    mcp, router = server
    out = await call(mcp, "move_firewall_rule", rule_id="*a", before_rule_id="*7")
    assert router.order() == ["*0", "*a", "*7", "*1f"]
    assert "forward" in out["warning"] and "input" in out["warning"]


async def test_a_move_the_device_did_not_honour_is_reported_as_a_failure(server):
    """A silent no-op is the one outcome a reorder tool must never report as ok."""
    mcp, router = server

    async def refuse(*path, item_id, destination=None):
        router.calls.append(("move", item_id, destination))

    router.move = refuse
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_firewall_rule", rule_id="*1f", before_rule_id="*7")
    assert "did not take effect" in str(excinfo.value)
    assert "order after" in str(excinfo.value)


async def test_add_with_place_before_lands_in_the_right_place(server):
    mcp, router = server
    out = await call(mcp, "add_firewall_rule", chain="input", action="drop", place_before="*1f")
    assert out["placed_before"] == "*1f"
    assert router.order() == ["*0", "*7", "*a", out["id"], "*1f"]


async def test_place_before_rejects_a_position(server):
    mcp, router = server
    with pytest.raises(ToolFailed):
        await call(mcp, "add_firewall_rule", chain="input", action="drop", place_before="2")
    assert not any(c[0] == "move" for c in router.calls)


async def test_place_before_a_missing_rule_adds_nothing(server):
    """Otherwise the rule lands at the end of the chain — after the drop."""
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "add_firewall_rule", chain="input", action="drop", place_before="*ZZ99")
    assert "Nothing was added" in str(excinfo.value)
    assert router.order() == ["*0", "*7", "*a", "*1f"]


# ── actions that need a companion field ───────────────────────────────────

@pytest.mark.parametrize("action", ["add-src-to-address-list", "add-dst-to-address-list"])
async def test_an_address_list_action_without_a_list_is_refused(server, action):
    """RouterOS would accept this, report it valid, and do nothing with it."""
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "add_firewall_rule", chain="input", action=action,
                   protocol="tcp", dst_port="9993")
    assert "address_list" in str(excinfo.value)
    assert router.order() == ["*0", "*7", "*a", "*1f"], "nothing should have been created"


async def test_an_address_list_action_with_a_list_configures_the_rule(server):
    mcp, _ = server
    out = await call(mcp, "add_firewall_rule", chain="input", action="add-src-to-address-list",
                     address_list="scanners", address_list_timeout="1d",
                     protocol="tcp", dst_port="9993", comment="honeypot")
    assert out["rule"]["address-list"] == "scanners"
    assert out["rule"]["address-list-timeout"] == "1d"


async def test_jump_without_a_target_is_refused(server):
    mcp, _ = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "add_firewall_rule", chain="input", action="jump")
    assert "jump_target" in str(excinfo.value)


async def test_switching_to_an_address_list_action_needs_the_list_too(server):
    mcp, _ = server
    with pytest.raises(ToolFailed):
        await call(mcp, "update_firewall_rule", rule_id="*7", action="add-src-to-address-list")
    out = await call(mcp, "update_firewall_rule", rule_id="*7",
                     action="add-src-to-address-list", address_list="scanners")
    assert out["after"]["action"] == "add-src-to-address-list"


async def test_a_rule_that_already_names_a_list_can_change_action_alone(server):
    mcp, router = server
    router._items[FILTER].append(
        {".id": "*e1", "chain": "input", "action": "add-src-to-address-list", "address-list": "scanners"})
    out = await call(mcp, "update_firewall_rule", rule_id="*e1", action="add-dst-to-address-list")
    assert out["after"]["action"] == "add-dst-to-address-list"


# ── clearing fields ───────────────────────────────────────────────────────

async def test_unset_clears_a_field_that_no_value_could_clear(server):
    mcp, router = server
    await call(mcp, "update_firewall_rule", rule_id="*7", log_prefix="SCAN")
    out = await call(mcp, "update_firewall_rule", rule_id="*7", unset=["log_prefix"])
    assert out["cleared"] == ["log-prefix"]
    assert "log-prefix" not in out["after"]
    assert ("unset", "*7", "log-prefix") in router.calls


async def test_unset_accepts_either_spelling(server):
    mcp, _ = server
    out = await call(mcp, "update_firewall_rule", rule_id="*7", unset=["src-address"])
    assert out["cleared"] == ["src-address"]
    assert "src-address" not in out["after"]


async def test_setting_and_clearing_the_same_field_is_refused(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_firewall_rule", rule_id="*7",
                   log_prefix="SCAN", unset=["log_prefix"])
    assert "one or the other" in str(excinfo.value)
    assert router.calls == []


async def test_chain_and_action_cannot_be_cleared(server):
    mcp, _ = server
    for field in ("chain", "action"):
        with pytest.raises(ToolFailed) as excinfo:
            await call(mcp, "update_firewall_rule", rule_id="*7", unset=[field])
        assert "cannot be cleared" in str(excinfo.value)


async def test_an_unknown_field_is_refused_with_the_list_of_real_ones(server):
    mcp, _ = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_firewall_rule", rule_id="*7", unset=["nonsense"])
    assert "log_prefix" in str(excinfo.value)


async def test_clearing_the_field_an_action_depends_on_is_refused(server):
    mcp, router = server
    router._items[FILTER].append(
        {".id": "*e2", "chain": "input", "action": "add-src-to-address-list", "address-list": "scanners"})
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_firewall_rule", rule_id="*e2", unset=["address_list"])
    assert "stop doing anything" in str(excinfo.value)


# ── address lists ─────────────────────────────────────────────────────────

async def test_address_lists_are_summarised_by_name(server):
    mcp, _ = server
    out = await call(mcp, "list_address_lists")
    by_name = {item["list"]: item for item in out["lists"]}
    assert by_name["blocked"]["entries"] == 2
    assert by_name["blocked"]["dynamic"] == 2
    assert by_name["trusted"]["entries"] == 1


async def test_entries_can_be_counted_without_being_returned(server):
    """The first call to make against a list with fifty thousand entries."""
    mcp, _ = server
    out = await call(mcp, "list_address_list_entries", list_name="blocked", count_only=True)
    assert out["matched"] == 2
    assert "entries" not in out


async def test_entries_can_be_filtered_to_one_list(server):
    mcp, _ = server
    out = await call(mcp, "list_address_list_entries", list_name="trusted")
    assert [e["address"] for e in out["entries"]] == ["192.168.88.0/24"]


async def test_one_address_can_be_looked_up_directly(server):
    mcp, _ = server
    out = await call(mcp, "list_address_list_entries", address="203.0.113.5")
    assert out["matched"] == 1
    assert out["entries"][0]["list"] == "blocked"


async def test_dynamic_entries_can_be_excluded(server):
    mcp, _ = server
    out = await call(mcp, "list_address_list_entries", include_dynamic=False)
    assert [e["address"] for e in out["entries"]] == ["192.168.88.0/24"]


async def test_a_truncated_listing_says_so(server):
    mcp, _ = server
    out = await call(mcp, "list_address_list_entries", list_name="blocked", limit=1)
    assert out["matched"] == 2
    assert out["returned"] == 1
    assert out["truncated"] is True


async def test_an_entry_can_be_added_with_a_timeout(server):
    mcp, _ = server
    out = await call(mcp, "add_address_list_entry", list_name="blocked",
                     address="198.51.100.9", timeout="1d", comment="manual")
    assert out["entry"]["address"] == "198.51.100.9"
    assert out["entry"]["timeout"] == "1d"


async def test_removing_an_entry_honours_the_address_guard(server):
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "remove_address_list_entry", entry_id="*c1", confirm_address="203.0.113.99")
    assert "refusing" in str(excinfo.value).lower()
    assert len(router._items[ADDRESS_LIST]) == 3

    out = await call(mcp, "remove_address_list_entry", entry_id="*c1", confirm_address="203.0.113.5")
    assert out["deleted_entry"]["address"] == "203.0.113.5"
    assert len(router._items[ADDRESS_LIST]) == 2


# ── failures stay legible ─────────────────────────────────────────────────

async def test_an_unexpected_client_failure_names_itself(server):
    """The shape of the original bug: a TypeError inside the client layer.

    It reached the caller as "Error executing tool move_firewall_rule" and
    nothing more — no exception, no RouterOS message, no failing argument.
    """
    mcp, router = server

    async def broken(*path, item_id, destination=None):
        raise TypeError("'async_generator' object can't be awaited")

    router.move = broken
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_firewall_rule", rule_id="*7", before_rule_id="*1f")
    assert "TypeError" in str(excinfo.value)
    assert "async_generator" in str(excinfo.value)
    assert "fault in mikrotik-mcp" in str(excinfo.value)


async def test_an_unexpected_failure_in_a_tool_body_names_itself_too(server):
    mcp, router = server

    async def malformed(*path):
        return ["not a row"]

    router.list = malformed
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "list_firewall_rules")
    # The SDK's own prefix is always there. What matters is that something
    # follows it: bare "Error executing tool list_firewall_rules" is the
    # failure mode this guards against.
    message = str(excinfo.value)
    assert "AttributeError" in message
    assert message.rstrip() != "Error executing tool list_firewall_rules"


async def test_a_device_refusal_is_reported_as_the_device_worded_it(server):
    """A RouterOS trap is not a bug here, and must not be dressed up as one."""
    from mikrotik_mcp.client import RouterError

    mcp, router = server

    async def refusing(*path, item_id, destination=None):
        raise RouterError("no such item (4)")

    router.move = refusing
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "move_firewall_rule", rule_id="*7", before_rule_id="*1f")
    assert "no such item (4)" in str(excinfo.value)
    assert "fault in mikrotik-mcp" not in str(excinfo.value)


async def test_an_update_that_changes_nothing_is_refused(server):
    """`updated: true` with an identical before/after pair reads as a change."""
    mcp, router = server
    with pytest.raises(ToolFailed) as excinfo:
        await call(mcp, "update_firewall_rule", rule_id="*7")
    assert "Nothing to change" in str(excinfo.value)
    assert router.calls == []


async def test_turning_logging_off_is_a_change_not_an_omission(server):
    """`log=False` must reach the device; only `None` means "not supplied"."""
    mcp, router = server
    out = await call(mcp, "update_firewall_rule", rule_id="*7", log=False)
    assert ("update", "*7") in router.calls
    assert out["after"]["log"] is False
