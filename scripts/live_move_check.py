#!/usr/bin/env python
"""Prove `move` works against a real router, without risking the firewall.

The one claim in this project that unit tests cannot settle is whether RouterOS
accepts an `.id` for `move`'s `destination`. Everything else about the reorder
path is covered; that part is protocol behaviour, and only a device can answer.

Safety, in the order it matters:

* Every rule this creates goes in a **custom chain that nothing jumps to**, and
  is created **disabled**, with `action=return`. Two independent reasons it
  cannot affect a packet.
* It **only ever moves rules it created**, relative to each other.
* It records the order of your real rules first and **asserts they are still in
  that same relative order at the end** — so "did this disturb the firewall?"
  is answered by the script, not by hope.
* Cleanup runs in `finally`, and removes only the ids it created.
* It refuses to start if the working chain already exists.

    MIKROTIK_HOST=10.0.0.1 MIKROTIK_USERNAME=... MIKROTIK_PASSWORD=... \
        uv run python scripts/live_move_check.py
    ... --nat     # also exercise move_nat_rule, same guarantees
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mikrotik_mcp.client import RouterError, RouterOS  # noqa: E402
from mikrotik_mcp.config import from_env  # noqa: E402

FILTER = ("ip", "firewall", "filter")
NAT = ("ip", "firewall", "nat")
CHAIN = "mcp-move-check"
TAG = "mcp-move-check (safe to delete)"

ok, failed = [], []


def check(label: str, got, want) -> None:
    if got == want:
        ok.append(label)
        print(f"  PASS  {label}")
    else:
        failed.append(label)
        print(f"  FAIL  {label}\n          got:  {got}\n          want: {want}")


async def order(router: RouterOS, path: tuple[str, ...]) -> list[str]:
    return [r[".id"] for r in await router.list(*path)]


async def relative(router: RouterOS, path: tuple[str, ...], mine: set[str]) -> list[str]:
    """The order of everything that is not ours."""
    return [i for i in await order(router, path) if i not in mine]


async def check_filter(router: RouterOS) -> None:
    print("\nip/firewall/filter")
    rules = await router.list(*FILTER)

    if any(r.get("chain") == CHAIN for r in rules):
        raise SystemExit(f"chain {CHAIN!r} already has rules — clean it up first")
    if any(r.get("jump-target") == CHAIN for r in rules):
        raise SystemExit(f"something jumps to {CHAIN!r}; it would not be inert")

    untouched_before = [r[".id"] for r in rules]
    mine: set[str] = set()
    try:
        ids = []
        for name in "ABC":
            new = await router.add(
                *FILTER, chain=CHAIN, action="return", disabled=True,
                comment=f"{TAG} {name}",
            )
            ids.append(new)
            mine.add(new)
        a, b, c = ids
        print(f"  created {a} {b} {c} in chain {CHAIN!r}, disabled, nothing jumps to it")

        async def ours() -> list[str]:
            return [i for i in await order(router, FILTER) if i in mine]

        check("created in order", await ours(), [a, b, c])

        await router.move(*FILTER, item_id=c, destination=a)
        check("move C before A", await ours(), [c, a, b])

        await router.move(*FILTER, item_id=c, destination=None)
        check("move C to the end", await ours(), [a, b, c])

        await router.move(*FILTER, item_id=b, destination=a)
        check("move B before A", await ours(), [b, a, c])

        try:
            await router.move(*FILTER, item_id=a, destination="*ZZZZ9")
        except RouterError as exc:
            check("a bad destination is refused", "refused", "refused")
            print(f"          device said: {str(exc).splitlines()[0]}")
        else:
            check("a bad destination is refused", "accepted silently", "refused")
        check("order unchanged after the refusal", await ours(), [b, a, c])
    finally:
        for item_id in sorted(mine):
            try:
                await router.remove(*FILTER, item_id=item_id)
            except RouterError as exc:
                print(f"  WARN  could not remove {item_id}: {exc}")
        check("your rules are untouched", await relative(router, FILTER, mine), untouched_before)


async def check_nat(router: RouterOS) -> None:
    """Same idea, but NAT has no custom chains — so lean on `disabled` instead.

    The two rules are created at the end of the table and only ever moved past
    each other, so no real rule ever changes position relative to another.
    """
    print("\nip/firewall/nat")
    untouched_before = await order(router, NAT)
    mine: set[str] = set()
    try:
        ids = []
        for name in "AB":
            new = await router.add(
                *NAT, chain="dstnat", action="dst-nat", disabled=True,
                protocol="tcp", dst_address="192.0.2.1", dst_port="65001",
                to_addresses="192.0.2.2", comment=f"{TAG} {name}",
            )
            ids.append(new)
            mine.add(new)
        a, b = ids
        print(f"  created {a} {b} in dstnat, disabled, matching TEST-NET-1 only")

        async def ours() -> list[str]:
            return [i for i in await order(router, NAT) if i in mine]

        check("created in order", await ours(), [a, b])
        await router.move(*NAT, item_id=b, destination=a)
        check("move B before A", await ours(), [b, a])
        await router.move(*NAT, item_id=b, destination=None)
        check("move B to the end", await ours(), [a, b])
    finally:
        for item_id in sorted(mine):
            try:
                await router.remove(*NAT, item_id=item_id)
            except RouterError as exc:
                print(f"  WARN  could not remove {item_id}: {exc}")
        check("your NAT rules are untouched", await relative(router, NAT, mine), untouched_before)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--nat", action="store_true", help="also exercise the NAT table")
    args = parser.parse_args()

    router = RouterOS(from_env())
    identity = await router.list("system", "identity")
    print(f"connected to {identity[0].get('name')!r}")
    try:
        await check_filter(router)
        if args.nat:
            await check_nat(router)
    finally:
        await router.close()

    print(f"\n{len(ok)} passed, {len(failed)} failed")
    if failed:
        print("failing: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
