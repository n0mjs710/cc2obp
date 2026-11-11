# Configuring cc2obp

`cc2obp` is configured with one TOML file. Start from the sample:

```
cp cc2obp.toml.sample cc2obp.toml
```

A config has three parts: one `[global]` table (your own identity and
timers), any number of `[[openbridge]]` peers, and any number of `[[link]]`
entries tying one CC-CC conduit to exactly one OpenBridge `(peer, TGID)`.
Each `[[link]]` is self-contained — its own CC-CC identity *and* which
OpenBridge peer/TGID it cross-connects to — so a CC-CC link can never
accidentally fan out to more than one OpenBridge destination, or vice versa.

Every link involves **two other operators** you'll need to coordinate with
before it comes up: whoever runs the far end of the CC-CC conduit (a
c-Bridge Control Center), and whoever runs the OpenBridge peer (HBlink3,
HBlink4, or another OpenBridge-capable product). Neither side can be
configured from guesswork — both ends of each protocol have to agree on
specific values. This document calls those out explicitly.

## `[global]`

Identity and timers used on the CC-CC side; there's only one of this table.

| Field | Meaning |
|---|---|
| `log_level` | `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |
| `cc_site_name` | Presented as this program's site name in the CC-CC handshake. Informational only — not validated by the remote (formal spec §4.3) — but it'll show up in the far Control Center's logs, so pick something recognizable. |
| `cc_mac_address` | 12 hex characters, presented in the handshake. Appears cosmetic; any value works. |
| `cc_version`, `cc_os_version` | Free-text handshake fields. Appear cosmetic. |
| `cc_code_revision` | Free-text handshake field, presented as a build/revision number. What the c-Bridge actually *does* with this one isn't fully known — see the note below. |
| `cc_keepalive_interval` | Seconds between originated CC-CC keepalives. Leave at the default (`10`) unless you have a specific reason not to — this is the protocol's own documented cadence. |
| `cc_link_timeout` | Seconds without a received keepalive before a CC-CC link is declared dead and torn down. Should be a few multiples of `cc_keepalive_interval`. |

None of these fields are validated by the remote beyond the codec/frame-size
fields in the handshake (always `AMBE`/`60`, which `cc2obp` sends
automatically — you don't configure them) — the connection doesn't get
rejected over any of them. Nothing here needs to be coordinated with anyone;
it's purely how *you* identify yourself. That said, "not validated" isn't
the same as "confirmed inert": the c-Bridge is known to log a message
indicating it tries to match features against the `cc_code_revision` value
specifically. What that matching actually changes, if anything, isn't
known — these values were arrived at by interoperability analysis, not
vendor documentation (see the top-level `NOTICE` in `README.md`). In
practice this hasn't caused observed problems with the default sample
value, but if you hit odd behavior on a link and everything else in this
file checks out, `cc_code_revision` is one of the few remaining unknowns
worth varying.

## `[[openbridge]]` — one per remote peer

```toml
[[openbridge]]
name        = "example-peer"
enabled     = true
peer_ip     = "203.0.113.50"
peer_port   = 62031
bind_port   = 62031
network_id  = 3120000
passphrase  = "a-strong-shared-secret"
# preserve_source_peer = false   # optional; see below
```

| Field | Meaning |
|---|---|
| `name` | Your own label for this peer. Referenced by `[[link]].openbridge_system`. Must be unique. |
| `enabled` | `false` means no socket is bound for this peer at all — every link referencing it goes cross-connect-inactive (§ below), without affecting those links' own CC-CC connections. |
| `peer_ip` / `peer_port` | The **remote's** address: where `cc2obp` sends OpenBridge traffic, and the source address/port every packet from that peer is checked against on receive. |
| `bind_port` | **Your own** local UDP port for this peer — independent of `peer_port`. Set it equal to `peer_port` if you want the common symmetric-port convention (as in the example above); set it to something else if this host already has something bound to that port, or you're running more than one peer and need distinct local ports. |
| `network_id` | A DMR-ID-shaped number `cc2obp` presents as its own identity in outgoing OpenBridge frames. Shows up in the remote's logs/dashboard as the originating system. |
| `preserve_source_peer` | Optional, default `false`. The DMRD "Repeater ID" field (bytes 11–14) is required by the data protocol, and OpenBridge convention says to fill it with `network_id` (this server's own ID) — that's what `false` does. But the protocol does not define how a receiver uses that field, and the reference implementation (hblink3) does not validate it: authentication is the HMAC plus the source socket, and the field is only logged/reported. Set `true` to instead forward the **originating source-peer** — the peer ID carried in the CC-CC B-on — untouched, so a call's true RF source propagates end-to-end rather than being replaced by this bridge's `network_id`. Most useful when the far OpenBridge end preserves it too. RadioID issues no IDs to infrastructure servers, so an arbitrary `network_id` propagating like a repeater ID is arguably worse than the real source-peer. |
| `passphrase` | The shared secret for this peer's HMAC-SHA1 frame signing. **Must match exactly** on both ends — OpenBridge has no other authentication. |

**Coordinate with the OpenBridge peer's operator before configuring this:**
- Their listening address and port → your `peer_ip`/`peer_port`.
- A port on your own box for them to send to → tell them this so they can
  configure it as *their* target for you; that's your `bind_port`.
- Agree on the `passphrase` out of band (not over an insecure channel — it's
  the only thing standing between "trusted peer" and "anyone who can guess
  it"; OpenBridge itself provides no other security, see
  `CC-CC_Link_Protocol_Specification.md`'s security considerations section
  for the CC-CC side's equivalent caveat).
- Tell them your `network_id`, and ask if they need to add anything on
  their end (an ACL entry, a bridge rule) referencing it or the TGID you'll
  be using — see the `[[link]].tgid` note below.

If two enabled peers would need to bind the same local port, `cc2obp`
refuses to start with a clear error rather than a bare "address in use" —
give them distinct `bind_port` values.

## `[[link]]` — one per CC-CC conduit

```toml
[[link]]
name                 = "example-link"
enabled              = true
cross_connect_active = true
tgid                 = 9
openbridge_system    = "example-peer"
cc_role              = "outbound"
cc_lid               = 69
cc_remote_ip         = "203.0.113.18"
cc_remote_port       = 42421
cc_remote_voice_port = 42422
cc_channel_name      = "MYBRIDGE-9"
```

| Field | Meaning |
|---|---|
| `name` | Your own label. Must be unique across all links. |
| `enabled` | `false`: no TCP attempt (outbound) or acceptance (inbound); no handshake, no keepalives. The conduit is entirely dark. |
| `cross_connect_active` | `false`: the CC-CC connection stays up — handshake, keepalives, link-test all continue, so the far Control Center sees a healthy link with no reconnect churn — but call traffic is dropped in both directions. Use this for transit-side maintenance; use `enabled = false` to decommission the link entirely. |
| `tgid` | The OpenBridge-side TGID this link maps to. **Local to the OpenBridge conversation with this peer** — it is *not* carried over the CC-CC side at all (CC-CC routes by LID, not TGID; formal spec §5) and does not need to match any number the far Control Center uses internally. It *does* need to match whatever TGID the OpenBridge peer operator expects traffic on for this bridge (see below). |
| `openbridge_system` | References an `[[openbridge]].name`. |
| `cc_role` | `"outbound"`: `cc2obp` dials out to the far Control Center. `"inbound"`: `cc2obp` listens (on the shared TCP 42421) and waits for the far end to dial in. |
| `cc_lid` | The CC-CC Link ID. **Must match what the far Control Center's own bridge configuration expects for this conduit** — this is the actual routing key on the wire (formal spec §5, §7). Two digits on the wire; per the formal spec, encoding for values over 99 is undefined, so stay at or below 99 until that's resolved upstream. |
| `cc_remote_ip` | Required for **both** roles. Outbound: the address dialed. Inbound: the expected/pinned source address of the far end — required to disambiguate incoming connections once more than one remote might connect (see `(cc_remote_ip, cc_lid)` uniqueness below). |
| `cc_remote_port` | **Outbound only** — the far end's TCP control port (normally `42421`). Omit for inbound links; an inbound link never dials out, so it has no use for the remote's control port. |
| `cc_remote_voice_port` | The far end's UDP voice/keepalive port (normally `42422`), both roles. |
| `cc_channel_name` | **Outbound only** — sent as the Bridge Group / channel name in the handshake. Informational, not validated, but should be recognizable to whoever's reading logs on the far end. |

**Coordinate with the far Control Center's operator before configuring
this:**
- Agree on the **`cc_lid`** value — both ends must use the same number; it's
  how the far c-Bridge routes the conduit to the right Bridge Group.
- Agree on **which end dials out**. Whichever end is `outbound` needs the
  other's reachable IP and control port; whichever end is `inbound` needs
  to know the outbound end's source IP ahead of time (that's your
  `cc_remote_ip`, even on the inbound side — it's used to validate the
  incoming connection, not just to dial one).
- Confirm their side is actually configured to bridge this LID into the
  Bridge Group / IPSC LID they intend — that's entirely their own local
  configuration and outside `cc2obp`'s visibility.
- The far end doesn't need to know your `tgid` — that number is purely
  between `cc2obp` and the OpenBridge peer (see above), never carried over
  CC-CC.

### Validation

`cc2obp` refuses to start (with a specific error, not a crash) on any of:

- Duplicate `[[link]].name`, or duplicate `[[openbridge]].name`.
- Duplicate `(openbridge_system, tgid)` across links — that pair is the
  OpenBridge-side routing key and must be unique.
- Duplicate `(cc_remote_ip, cc_lid)` among **inbound** links — that pair is
  how an incoming connection gets matched to a configured link.
- A missing `cc_remote_ip`, or an `openbridge_system` that doesn't reference
  a configured peer.
- Two enabled `[[openbridge]]` peers sharing a `bind_port`.

A duplicate `(cc_remote_ip, cc_remote_port, cc_lid)` across **outbound**
links is logged as a likely typo but does not block startup — each outbound
link gets its own dedicated connection regardless, so it isn't a
correctness problem, just probably not what you meant.

## Multiple links, multiple peers

Nothing about the config format limits you to one of each — add as many
`[[openbridge]]` and `[[link]]` blocks as you need. Two links can share one
`[[openbridge]]` peer (different TGIDs); two links can each reference a
different peer entirely. Each conduit is independent — traffic on one link
never crosses into another.

What you cannot do is point two links at the same OpenBridge `(peer, tgid)`,
or have one CC-CC link cross-connect to more than one OpenBridge
destination — that's full N-way conference bridging, a different problem
`cc2obp` deliberately doesn't solve (see the README). If you need that,
compose it by pointing an HBlink3/HBlink4 `bridge.py`-style confbridge at
one of `cc2obp`'s OpenBridge legs.

## Reloading

`systemctl reload cc2obp` (or `kill -HUP`) re-reads the file and applies the
difference, entry by entry, matched by `name` — see `INSTALL.md`:

- **unchanged** `[[link]]` / `[[openbridge]]` entries are not touched; their
  connections and calls carry on through the reload;
- **`enabled` / `cross_connect_active` changes** take effect on that entry
  alone, as before;
- **any other field change** on a `[[link]]` closes that link's connection
  and brings it back with the new values (an outbound link redials; for an
  inbound link the remote's own reconnect picks it up); on an
  `[[openbridge]]`, that peer's socket is closed and re-bound;
- **removed** entries are torn down, **new** ones are brought up;
- **`[global]`** (identity, timers, `log_level`) is ignored until a full
  restart; a WARNING says so.

Renaming an entry is a remove plus an add. A file that fails to parse or
validate is refused as a whole (logged at ERROR) and the running config
stays in effect — run `--check` first.

If an `[[openbridge]]` peer's `bind_port` can't be bound (at startup or on a
reload, typically because another program already holds the port), that
peer stays down and everything else carries on. Its links stay up, but they
pass no traffic. This is logged at ERROR, with the port, the reason and the
links cut off. A reload that leaves a peer unbound ends with
`reload finished with errors` instead of `reload complete`. cc2obp retries
the bind every 10 seconds, logs `STILL DOWN` at ERROR every 5 minutes while
it keeps failing, and logs `RECOVERED` at WARNING once it binds. Calls
dropped in the meantime are logged with the same reason.

## Testing your config

Before reloading or restarting a running instance, validate the file on its
own — this never binds a socket, so it can't conflict with an instance
that's already using the same ports:

```
./cc2obp -c cc2obp.toml --check
```

On success this prints every configured peer and link (name, enabled/
cross_connect_active state, role, TGID, LID) so you can eyeball that the
edit did what you meant; on failure it prints every problem found, in the
same form `config_load` always produces (see "Validation" above), and
exits 1 without printing a summary.

To actually run it and watch it try to come up:

```
./cc2obp -c cc2obp.toml --log-level DEBUG
```

Watch the log for `link 'NAME': UP` on the CC-CC side and
`openbridge peer 'NAME' socket up` on the OpenBridge side. `--wire`
restricts output to raw hex dumps of what's actually on the wire, useful
when working with the far operator to debug a handshake that isn't coming
up.
