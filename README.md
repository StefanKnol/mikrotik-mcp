# mikrotik-mcp

<!-- The MCP registry verifies package ownership by looking for this token in
     the PyPI description, which is this README. It must sit on its own line. -->
mcp-name: io.github.StefanKnol/mikrotik-mcp

An MCP server for MikroTik RouterOS, over the **binary API** rather than by
driving the CLI over SSH.

That distinction is the whole point. The CLI prints *positional* numbers, which
are not a rule's identity. A server that lists rules by position and then writes
by position either fails outright — `where .id=3` matches nothing, so every
write reports "not found" for rules that plainly exist — or, worse, succeeds
against a different rule once the order has shifted. On a firewall that means
deleting the wrong rule.

The binary API returns the real `.id` (`*7`, `*1f`) on every read. So:

- every read returns `id`, and every write takes one back;
- list results also carry `position`, which is display-only and **refused** for
  writes, with an error that explains why;
- writes read back what they wrote, so a change can be verified rather than assumed;
- `remove_firewall_rule` takes an optional `confirm_comment` and returns the
  rule it deleted.

## Use it

```bash
uvx mikrotik-mcp
```

Configure through the environment — `ps` would show a password passed as a flag:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MIKROTIK_HOST` | — | Router address. Required. |
| `MIKROTIK_USERNAME` | — | Required. |
| `MIKROTIK_PASSWORD` | — | |
| `MIKROTIK_PORT` | `8729` | `8729` for api-ssl, `8728` for plaintext. |
| `MIKROTIK_TLS` | `true` | |
| `MIKROTIK_TLS_FINGERPRINT` | — | SHA-256 of the router certificate, to pin it. |
| `MIKROTIK_TIMEOUT` | `10` | |

In an MCP client's config:

```json
{
  "mcpServers": {
    "mikrotik": {
      "command": "uvx",
      "args": ["mikrotik-mcp"],
      "env": {
        "MIKROTIK_HOST": "192.168.88.1",
        "MIKROTIK_USERNAME": "mcp-agent",
        "MIKROTIK_PASSWORD": "..."
      }
    }
  }
}
```

## On the router

```
/ip service enable api-ssl
/user group add name=mcp policy=api,read,write,test
/user add name=mcp-agent group=mcp password=<strong-password>
```

The `api` policy is not optional, and its absence produces a login error
**identical** to a wrong password — so if credentials look right and login still
fails, check the group first.

Set `MIKROTIK_TLS_FINGERPRINT` if you can. MikroTik's API-SSL certificate is
self-signed, so ordinary CA validation cannot succeed against a stock device;
pinning is what makes the connection authenticated rather than merely encrypted.

## Tools

24 of them, covering system info, interfaces, IP addressing, firewall filter
and NAT, DHCP leases, static DNS, routes and logs — plus `ros_list`, which
reads any RouterOS path and so covers everything without a dedicated tool.

There is deliberately **no** generic write escape hatch.

## With mcphub

Two ways, and the first is the better default:

**Launched as a subprocess** by [mcphub](https://github.com/StefanKnol/mcphub),
configured as a command — `uvx mikrotik-mcp` — with credentials as encrypted
environment variables. It runs in its own process and cannot read credentials
held for other backends.

**Loaded in-process** via the `mcphub.plugins` entry point this package also
ships, which gives typed host/username/password fields in mcphub's settings UI.
Nicer to configure, but an in-process plugin can read everything the hub holds.
Install it into the hub's environment to use this route.

## Publishing to the MCP registry

`server.json` is the manifest for the [official MCP registry](https://registry.modelcontextprotocol.io),
validated against the published schema. It declares the `uvx mikrotik-mcp`
command and every `MIKROTIK_*` variable, marking which are required and which
are secret — so a client that browses the registry can generate a correct
settings form without knowing anything about this server.

Publishing has an order to it, because the registry verifies that whoever
publishes an entry actually owns the package it points at.

**1. The package must already be on PyPI.** The registry fetches
`pypi.org/pypi/mikrotik-mcp/<version>/json` and refuses an entry whose package
does not exist. Tag a release and let CI publish it:

```bash
git tag v0.1.0 && git push --tags
```

(That needs a PyPI Trusted Publisher configured for this project first —
PyPI → your project → Publishing → add a GitHub publisher for
`StefanKnol/mikrotik-mcp`, workflow `ci.yml`, environment `pypi`.)

**2. The README must carry the ownership token.** The registry looks for
`mcp-name: io.github.StefanKnol/mikrotik-mcp` in the PyPI description, which is
this file — it is at the top, on its own line. That is what proves the person
publishing the registry entry controls the PyPI package.

**3. Then publish the entry.**

```bash
curl -sL https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_linux_amd64.tar.gz | tar xz mcp-publisher
./mcp-publisher login github
./mcp-publisher publish
```

`login github` opens a device flow and proves you are `StefanKnol`, which is
what authorises the `io.github.StefanKnol/*` namespace. In CI, `login
github-oidc` does the same from a workflow with `id-token: write`.

Bump `version` in `server.json` and `pyproject.toml` together; the registry
treats each version as its own row.

## Development

```bash
uv sync --extra dev
uv run pytest
```

## License

MIT
