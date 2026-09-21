# Changelog

Versions follow [semantic versioning](https://semver.org). While the major
version is 0, a minor bump is where breaking changes go.

## 0.3.0

### Changed — affects mcphub grants

- `set_firewall_rule_enabled` and `set_nat_rule_enabled` are no longer marked
  destructive, which moves them from `admin` to `user` on an mcphub. Disabling
  a rule keeps the rule, its comment and its position, and re-enabling restores
  exactly what was there — `destructiveHint` is about irreversible loss, not
  about writing. They are also the reversible way to find out whether a rule is
  responsible for something, so gating them at the same level as removal left a
  `user` with no safe way to test at all. Review your grants if you were relying
  on the old split.
- `set_interface_enabled` stays destructive, and now says why: disabling the
  interface a request arrived through severs the only route back, so what is
  lost is the ability to undo it.

### Fixed

- The `mcphub` optional dependency is gone. `mcphub.plugins.base` is supplied by
  the hub, which is what imports the plugin in the first place; the `mcphub`
  name on PyPI belongs to an unrelated project, so `pip install
  mikrotik-mcp[mcphub]` installed something that could never provide that
  module.
- The plugin now subclasses `PluginDefaults`, which is what supplies `variant()`
  — the hook that builds an instance for a pinned version. Without it, listing
  `BackendInstance` fields falls to this package, and a field the hub adds later
  would be dropped silently and only at a pinned version.

### Added

- `MikroTikPlugin.validate()` reports a bad port, a malformed TLS fingerprint,
  or a fingerprint set while TLS is off, against the field it belongs to rather
  than as a connection failure later.
- A test that pins every tool's mcphub level by name. The hub enforces levels
  from annotations alone, so an unannotated tool silently becomes `user`; this
  fails the suite until a new tool is classified deliberately.

## 0.2.0

### Fixed

- **Every non-CRUD RouterOS command was broken**, which meant
  `move_firewall_rule`, `add_firewall_rule(place_before=...)` and
  `make_lease_static` had never worked. `librouteros` splits its async surface
  between coroutines and async generator functions, and the client awaited the
  generator ones. Awaiting an async generator raises `TypeError` before the
  generator body runs, so the command never reached the device — which is why
  the failure left the configuration untouched — and the `TypeError` escaped
  every handler to reach the caller as a bare `Error executing tool
  move_firewall_rule`. Covered now by tests that drive the real `librouteros`
  API over a stand-in protocol and assert on the words that would go over the
  wire; mocking a layer higher is what let this ship green.
- Unexpected failures no longer reach the caller as `Error executing tool
  <name>` with nothing after it. Both the client calls and the tool bodies
  report the exception type and message, and say whether the fault was in this
  server or a refusal by the device.
- `move_firewall_rule` and `place_before` read the order back and fail if the
  rule did not land where it was asked to. A reorder that silently does nothing
  is the one outcome neither may report as success.

### Added

- Address list tools: `list_address_lists`, `list_address_list_entries` (filter
  by list or address, `count_only`, capped output), `add_address_list_entry`
  (with `timeout`) and `remove_address_list_entry`. Entries a rule adds at
  runtime never appear in a configuration export, so a firewall built on named
  lists was previously unreadable through the dedicated tools.
- `family` on every firewall filter tool, for `ipv6/firewall/filter`. Listing
  IPv4 now also reports the IPv6 rule count, and says so plainly when that
  table is empty and therefore accepting everything.
- `get_dns_settings`, `list_dns_adlist` and `update_dns_static`. A static DNS
  entry could be added and removed but not edited, so repointing a name meant
  remove-and-re-add and losing the entry's id.
- NAT gains `get_nat_rule`, `update_nat_rule` (with `unset`) and
  `move_nat_rule`, plus `place_before` on `add_nat_rule` and the
  `confirm_comment` guard on `remove_nat_rule`. NAT is an ordered,
  first-match-wins table like the filter chains, but had no way to read one
  rule, change one in place, or reorder at all — so editing a port forward
  meant deleting it and re-adding it at the end of the table. Reordering is
  shared with the filter tools, verification included.
- NAT matchers: `src_port`, `port`, `src_address_type`, `dst_address_type`,
  `src_address_list`, `dst_address_list`, `out_interface_list`,
  `connection_mark`, `log` and `log_prefix`. `dst_address_type` is the one a
  DNS redirect needs — `dst-address-type=!local` is what stops it NATting
  queries already addressed to the router — and a DNS redirect is a dstnat
  rule, so it belonged here and not only on the filter tools.
- `dst-nat`, `src-nat` and `netmap` are refused without `to_addresses` or
  `to_ports`, and an update may not clear the last of the pair. The
  requirement is on the pair rather than on `to_addresses`, because `dst-nat`
  with only `to_ports` is a good rule — it rewrites the port and leaves the
  address alone. With neither, the rule matches traffic and has nothing to
  send it to, which is never what anyone meant.
- Matchers on `add_firewall_rule` and `update_firewall_rule`: `psd`,
  `connection_limit`, `connection_mark`, `limit`, `tcp_flags`,
  `connection_nat_state`, `src_address_type`, `dst_address_type`,
  `address_list`, `address_list_timeout`, `jump_target`, `reject_with` and
  `port`. Without these the tools could not express most of the rules on a real
  device, and a read-modify-write round trip would drop the matcher and leave a
  rule matching far more traffic than intended.
- `unset` on `update_firewall_rule`, to clear a field rather than change it.
  Omitted arguments still mean "leave alone", and empty string is left to mean
  empty string.
- An action whose companion field is missing is now refused:
  `add-src-to-address-list` and `add-dst-to-address-list` without
  `address_list`, and `jump` without `jump_target`. RouterOS accepts all three,
  reports them valid, and does nothing with them.
- CI verifies that a release tag matches the version inside it
  (`scripts/release.py <version> --check`).

### Changed — breaking

- `disabled`, `dynamic`, `invalid` and `log` are JSON booleans and always
  present. They were RouterOS strings (`"yes"`, `"true"`) that appeared only
  when the device had the property set, so their absence read as unknown rather
  than as false.
- Every response spells the identifier `id`. `get`, `add`, `update` and
  `remove` previously returned `.id` while lists returned `id`.
- Port fields (`src-port`, `dst-port`, `port`, `to-ports`) are always strings.
  RouterOS types them by content, so `9991` arrived as a number and `"80,443"`
  as a string from the same field.
- `list_firewall_rules` returns the matchers that define a rule by default.
  `verbose` now adds the byte and packet counters and nothing else. A
  scan-detection rule previously listed as an unconditional action on a
  protocol.
- `list_dns_static` returns `{count, entries}` rather than a bare array.
- `move_firewall_rule` returns the resulting order of the affected chain
  (`chain_order`) rather than a dump of every rule.

## 0.1.0

Initial release.
