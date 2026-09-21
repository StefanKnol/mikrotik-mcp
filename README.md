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

34 of them, covering system info, interfaces, IP addressing, firewall filter
(IPv4 and IPv6), firewall address lists, NAT, DHCP leases, DNS, routes and logs
— plus `ros_list`, which reads any RouterOS path and so covers everything
without a dedicated tool.

There is deliberately **no** generic write escape hatch.

Three things worth knowing before the first call:

- **Writes take an `id` (`*7`), never a `position`.** Both appear in every list
  result. `position` is where a rule currently sits in evaluation order; it
  shifts whenever anything is added, removed or moved, and it is counted across
  the whole table rather than within the chain you filtered to. Passing one to
  a write is rejected rather than guessed at.
- **IPv4 and IPv6 are separate rule sets.** The firewall tools take a `family`
  and default to `ipv4`, so a device can read as locked down while its IPv6
  table is empty and therefore accepting everything. Listing IPv4 reports the
  IPv6 rule count for exactly this reason.
- **Address lists hold state no configuration export shows.** Entries a rule
  adds at runtime carry a timeout and exist only in memory. Ask
  `list_address_list_entries` for a `count_only` first: a populated block list
  can hold tens of thousands.

## With mcphub

[mcphub](https://github.com/StefanKnol/mcphub) puts MCP servers behind one
sign-in and grants them out per account. One router is one backend, at its own
`/mcp/<slug>`, registered in a client as its own connector.

### Adding it

**From the registry** — the better default. *Add from registry*, search for
`mikrotik-mcp`, and the hub builds the settings form from `server.json` and
launches `uvx mikrotik-mcp` when you enable the backend. It runs in its own
process and cannot read credentials the hub holds for anything else. Backends
added this way start disabled: open it, look at the tool list, then enable.

**As a plugin** — install this package into the hub's own environment and
`mikrotik` appears as a backend kind, with typed fields and a Test button that
reports the router's identity and RouterOS version. Nicer to configure, but an
in-process plugin can read every credential the hub holds. Use it when you
build your own hub image.

### What to set

Either route asks for the same things. As environment variables:

| Variable | Default | |
| --- | --- | --- |
| `MIKROTIK_HOST` | — | Router address. Required. |
| `MIKROTIK_USERNAME` | — | Required. A dedicated user, not `admin`; its group needs the `api` policy. |
| `MIKROTIK_PASSWORD` | — | Required. |
| `MIKROTIK_PORT` | `8729` | `8729` for api-ssl, `8728` for plaintext. |
| `MIKROTIK_TLS` | `true` | Turning it off sends the router password over the network in the clear. |
| `MIKROTIK_TLS_FINGERPRINT` | — | SHA-256 of the router certificate. Pinning it is what makes the TLS connection authenticated rather than merely encrypted. |
| `MIKROTIK_TIMEOUT` | `10` | Seconds. |

No data directory: everything this server reads and writes lives on the router,
so there is no local state to keep. Leave **Give this server a data directory**
unticked.

### Levels

The hub reads `readOnlyHint` and `destructiveHint` from each tool and enforces
the grant's level from those alone — a tool above the level is left out of
`tools/list` and refused if called anyway.

| Level | Gets | |
| --- | --- | --- |
| `viewer` | 17 tools | Reads the whole configuration and changes nothing. |
| `user` | +7 tools | Adds rules and entries, and disables or re-enables them. |
| `admin` | +10 tools | Deletes, edits in place, and reorders. |

**viewer** — `connectivity_check`, `get_dns_settings`, `get_firewall_rule`,
`get_logs`, `get_nat_rule`, `list_address_list_entries`, `list_address_lists`,
`list_dhcp_leases`, `list_dns_adlist`, `list_dns_static`, `list_firewall_rules`,
`list_interfaces`, `list_ip_addresses`, `list_nat_rules`, `list_routes`,
`ros_list`, `system_info`.

**user** adds `add_address_list_entry`, `add_dns_static`, `add_firewall_rule`,
`add_nat_rule`, `make_lease_static`, `set_firewall_rule_enabled`,
`set_nat_rule_enabled`. Each of these writes, and none of them takes anything
away: adding a rule is a write, not a destruction, and disabling one keeps the
rule, its comment and its position so that re-enabling restores exactly what
was there. Disabling is the reversible way to find out whether a rule is
responsible for something, so it sits here rather than behind `admin` — the
alternative would leave a `user` with no safe way to test at all.

**admin** adds the destructive ten:

| Tool | What is lost |
| --- | --- |
| `remove_firewall_rule` | The rule. The returned copy is the only record. |
| `remove_nat_rule` | The rule. |
| `remove_dns_static` | The entry. |
| `remove_address_list_entry` | The entry. A dynamic one returns when its rule next matches; a static one does not. |
| `update_firewall_rule` | The previous values of whatever it sets or clears. |
| `update_nat_rule` | The same. |
| `update_dns_static` | The same. |
| `move_firewall_rule` | The previous order, which is the entire semantics of a firewall. |
| `move_nat_rule` | The same. |
| `set_interface_enabled` | Nothing on disk — but disabling the interface the request came in through severs the only route back, and nothing here can undo that remotely. |

A test pins every one of these assignments by name, so a tool added later fails
the suite until someone decides which level it belongs to.

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

That needs a PyPI Trusted Publisher first, and because this project does not
exist on PyPI yet it has to be a **pending** publisher — the per-project
Publishing tab only appears once a project exists, which is the chicken-and-egg
this page solves:

> pypi.org → Account settings → **Publishing** → *Add a new pending publisher*
>
> | Field | Value |
> | --- | --- |
> | PyPI Project Name | `mikrotik-mcp` |
> | Owner | `StefanKnol` |
> | Repository name | `mikrotik-mcp` |
> | Workflow name | `ci.yml` |
> | Environment name | `pypi` |

The environment name matters: the publish job declares `environment: pypi`, and
PyPI rejects the upload if they disagree.

**2. The README must carry the ownership token.** The registry looks for
`mcp-name: io.github.StefanKnol/mikrotik-mcp` in the PyPI description, which is
this file — it is at the top, on its own line. That is what proves the person
publishing the registry entry controls the PyPI package.

**3. The registry entry publishes itself.** The `registry` job in `ci.yml`
runs after the PyPI upload on the same tag, authenticating with
`mcp-publisher login github-oidc`. GitHub signs a short-lived OIDC token, the
registry verifies it and grants the `io.github.StefanKnol/*` namespace from the
repository owner. There is no secret to store and no device-flow login to sit
through on each release.

It waits for PyPI to actually serve the new version first. The registry fetches
`pypi.org/pypi/mikrotik-mcp/<version>/json` and refuses an entry whose package
it cannot see, and that endpoint lags the upload by some seconds — long enough
that publishing straight afterwards races it.

Re-running it is safe: a version already in the registry is the outcome the job
exists to produce, so it reports that and passes rather than failing on the
registry's duplicate refusal.

To publish by hand — recovering a failed run, or a version released before this
job existed:

```bash
curl -sL https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_linux_amd64.tar.gz | tar xz mcp-publisher
./mcp-publisher login github && ./mcp-publisher publish
```

`login github` opens the device flow and proves you are `StefanKnol`, which
authorises the same namespace the OIDC path gets without asking.

The version appears in four places — `pyproject.toml`, `__version__`,
`server.json`, and again inside that file's `packages` entry. Rather than
edit them by hand:

```bash
uv run python scripts/release.py 0.2.0 --tag
```

It sets all four, verifies them, commits and tags. The registry treats each
version as its own row and checks PyPI has the package at exactly that
version, so the nested `packages[].version` matters as much as the top-level
one — and it is the one that gets missed, because the manifest still validates
without it. A test enforces that they agree.

## Development

```bash
uv sync --extra dev
uv run pytest
```

## License

MIT
