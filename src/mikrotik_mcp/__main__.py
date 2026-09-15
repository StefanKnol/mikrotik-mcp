"""`mikrotik-mcp` — an MCP server for a MikroTik router, over stdio.

    uvx mikrotik-mcp

with MIKROTIK_HOST, MIKROTIK_USERNAME and MIKROTIK_PASSWORD set. Works with any
MCP client that can launch a process.
"""

from __future__ import annotations

import argparse
import logging
import sys

from .config import from_env
from .server import __version__, build_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mikrotik-mcp",
        description="MCP server for a MikroTik RouterOS device (binary API).",
        epilog="Every option also reads from MIKROTIK_<NAME>; prefer the environment "
               "for the password, which would otherwise be visible in `ps`.",
    )
    parser.add_argument("--host", help="Router address, e.g. 192.168.88.1")
    parser.add_argument("--username")
    parser.add_argument("--port", type=int, help="8729 for api-ssl (default), 8728 for plaintext")
    parser.add_argument("--no-tls", dest="use_tls", action="store_false", default=None,
                        help="Use the plaintext API. Sends the router password in the clear.")
    parser.add_argument("--tls-fingerprint", help="SHA-256 of the router certificate, to pin it")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--version", action="version", version=f"mikrotik-mcp {__version__}")
    args = parser.parse_args(argv)

    # stderr, because stdout carries the MCP protocol on this transport.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(levelname)-7s %(name)s: %(message)s")

    config = from_env(
        host=args.host, username=args.username, port=args.port,
        use_tls=args.use_tls, tls_fingerprint=args.tls_fingerprint, timeout=args.timeout,
    )
    build_server(config, title=f"MikroTik {config.host}").run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
