"""What actually reaches the wire.

These tests drive the *real* `librouteros.AsyncApi` over a stand-in protocol
rather than a stand-in API. That is the whole point: librouteros splits its
surface between coroutines (`add`, `update`, `remove`) and async generator
functions (`__aiter__`, `__call__`, `rawCmd`), and awaiting one of the latter
raises `TypeError` *before* the generator body runs — so no bytes are sent, no
RouterOS reply comes back, and the caller sees a bare "Error executing tool"
with nothing to go on.

Mocking one level higher, at `RouterOS`, cannot see any of that. It is why
`move_firewall_rule` shipped broken with a green suite.
"""

import pytest
from librouteros.api import AsyncApi
from librouteros.exceptions import TrapError

from mikrotik_mcp.client import RouterConfig, RouterError, RouterOS


class FakeProtocol:
    """Enough of librouteros' protocol to satisfy a real `AsyncApi`.

    Records every sentence written so a test can assert on the words the
    device would have received, which is the only level at which "did this
    command happen at all" is a real question.
    """

    def __init__(self, replies: dict[str, list[tuple[str, dict]]] | None = None) -> None:
        self.sent: list[tuple[str, tuple[str, ...]]] = []
        self._replies = replies or {}
        self._pending: list[tuple[str, dict]] = []

    async def writeSentence(self, cmd: str, *words: str) -> None:  # noqa: N802
        self.sent.append((cmd, words))
        self._pending = list(self._replies.get(cmd, [("!done", {})]))

    async def readSentence(self):  # noqa: N802
        # The protocol layer hands `AsyncApi` *raw* words; parsing them back
        # into a dict is the API's job, and letting it do that here keeps the
        # value casting (`yes` to True, digits to int) in the test path too.
        reply, values = self._pending.pop(0)
        return reply, [f"={key}={value}" for key, value in values.items()]

    async def close(self) -> None:
        pass


def router(replies=None) -> tuple[RouterOS, FakeProtocol]:
    proto = FakeProtocol(replies)
    device = RouterOS(RouterConfig(host="192.0.2.1", username="u", password="p"))
    # Skip the connection: these tests are about the command layer above it.
    device._api = AsyncApi(proto)
    return device, proto


def words_for(proto: FakeProtocol, cmd: str) -> tuple[str, ...]:
    return next(w for c, w in proto.sent if c == cmd)


async def test_move_reaches_the_device():
    """The regression. This command previously never left the process."""
    device, proto = router()
    await device.move("ip", "firewall", "filter", item_id="*35", destination="*33")
    assert proto.sent == [("/ip/firewall/filter/move", ("=numbers=*35", "=destination=*33"))]


async def test_move_to_the_end_sends_no_destination():
    device, proto = router()
    await device.move("ip", "firewall", "filter", item_id="*34")
    cmd, words = proto.sent[0]
    assert cmd == "/ip/firewall/filter/move"
    assert words == ("=numbers=*34",)


async def test_run_returns_the_rows_the_device_sent():
    device, proto = router({"/ip/dhcp-server/lease/make-static": [("!re", {".id": "*5"}), ("!done", {})]})
    rows = await device.run("ip", "dhcp-server", "lease", command="make-static", numbers="*5")
    assert rows == [{".id": "*5"}]


async def test_unset_clears_one_named_field():
    device, proto = router()
    await device.unset("ip", "firewall", "filter", item_id="*7", field="log-prefix")
    cmd, words = proto.sent[0]
    assert cmd == "/ip/firewall/filter/unset"
    assert set(words) == {"=.id=*7", "=value-name=log-prefix"}


async def test_query_filters_on_the_device_with_an_explicit_and():
    device, proto = router({"/ip/firewall/address-list/print": [("!done", {})]})
    await device.query("ip", "firewall", "address-list",
                       where={"list": "blocked", "dynamic": "false"})
    words = words_for(proto, "/ip/firewall/address-list/print")
    assert "?list=blocked" in words
    assert "?dynamic=false" in words
    # Two predicates, one AND. Without it RouterOS unions them and the answer
    # is every entry in either set.
    assert words.count("?#&") == 1


async def test_a_single_predicate_needs_no_operator():
    device, proto = router({"/ip/firewall/address-list/print": [("!done", {})]})
    await device.query("ip", "firewall", "address-list", where={"list": "blocked"})
    assert "?#&" not in words_for(proto, "/ip/firewall/address-list/print")


async def test_count_asks_for_the_smallest_row_the_device_will_return():
    rows = [("!re", {".id": f"*{n}"}) for n in range(3)] + [("!done", {})]
    device, proto = router({"/ip/firewall/address-list/print": rows})
    assert await device.count("ip", "firewall", "address-list", where={"list": "x"}) == 3
    assert "=.proplist=.id" in words_for(proto, "/ip/firewall/address-list/print")


async def test_add_still_goes_through_the_coroutine_path():
    """The other half of the split: `add` must be awaited, not iterated."""
    device, proto = router({"/ip/firewall/filter/add": [("!done", {"ret": "*42"})]})
    new_id = await device.add("ip", "firewall", "filter", chain="input", action="drop")
    assert new_id == "*42"
    assert set(words_for(proto, "/ip/firewall/filter/add")) == {"=chain=input", "=action=drop"}


async def test_booleans_become_yes_and_no():
    device, proto = router({"/ip/firewall/filter/add": [("!done", {"ret": "*1"})]})
    await device.add("ip", "firewall", "filter", chain="input", disabled=True, log=False)
    words = words_for(proto, "/ip/firewall/filter/add")
    assert "=disabled=yes" in words
    assert "=log=no" in words


async def test_a_device_refusal_arrives_as_a_router_error_with_its_text():
    class Refusing(FakeProtocol):
        async def readSentence(self):
            raise TrapError(message="no such item")

    proto = Refusing()
    device = RouterOS(RouterConfig(host="192.0.2.1", username="u", password="p"))
    device._api = AsyncApi(proto)

    with pytest.raises(RouterError) as excinfo:
        await device.move("ip", "firewall", "filter", item_id="*99", destination="*1")
    assert "no such item" in str(excinfo.value)
