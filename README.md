## PROJECT: CC-CC to OpenBridge Translator ##

**NOTICE:** CC-CC is not a published, open protocol. Support for it here is
derived from interoperability analysis against a production c-Bridge, not
from vendor documentation (see `CC-CC_Link_Protocol_Specification.md`).
Several details remain undefined or assumed (see that document's §13); please
do not ask for features that require further reverse-engineering without
providing verified, legally obtained information about the protocol.

**PURPOSE:** A single, small native daemon that bridges c-Bridge **CC-CC**
links to **OpenBridge** peers — HBlink3, HBlink4, or any other product that
speaks OpenBridge. `cc2obp` is the server-tier counterpart to
[`ipsc2hbpc`](https://github.com/n0mjs710/ipsc2hbpc): where `ipsc2hbpc`
bridges one IPSC repeater system to one HomeBrew network, `cc2obp` bridges
any number of CC-CC links to any number of OpenBridge peers, one CC-CC link
to exactly one OpenBridge `(system, TGID)` at a time.

**WHAT IT DOES:**

Each configured `[[link]]` pairs one CC-CC conduit (a Control Center's Bridge
Group, reached over TCP 42421 + UDP 42422/42420) with one OpenBridge
`(peer, TGID)` pair, always on DMR slot 1 (the OpenBridge convention). A call
originating on either side — CC-CC B-on/voice/B-off, or an OpenBridge DMRD
VOICE_HEAD/burst/VOICE_TERM — is translated in real time and relayed to the
other side, with no playout timer, jitter buffer, or loss concealment:
packets are translated and forwarded on arrival, and gaps present as real
gaps on the far end, not synthesized filler.

**DESIGN GOALS:**

- **Transparent translation only.** No routing, bridging, talkgroup
  rewriting, or DMR-ID lookups. Group voice in, group voice out, unchanged.
- **Single event loop, single thread.** A `poll()`-based loop multiplexes
  every CC-CC and OpenBridge socket and all timers. No threads, no locks.
- **Any number of links, any number of peers.** One shared CC-CC listener
  and voice/keepalive socket serve every configured `[[link]]`; one UDP
  socket per enabled `[[openbridge]]` peer. Strictly 1:1:1 — a CC-CC link
  and an OpenBridge `(system, TGID)` never fan out to more than each other.
  If you need N-way conference bridging spanning CC-CC, compose it by
  pointing an HBlink3 `bridge.py` confbridge at one of `cc2obp`'s OpenBridge
  legs, rather than expecting `cc2obp` itself to do fan-out.
- **One TOML config file.** See `CONFIGURING.md`.
- **No external dependencies.** The TOML parser, HMAC-SHA1, the event loop,
  and the DMR DSP/FEC code are all in this repository and compiled into the
  binary — no Python, no `pip`, no third-party libraries.
- **Config reload via SIGHUP** without a full restart — only the links and
  peers that changed are touched, the rest stay up. Includes the `enabled` /
  `cross_connect_active` runtime toggles, for taking a link out of service,
  or for transit-side maintenance that keeps the far Control Center from
  seeing reconnect churn while you work behind the OpenBridge leg.

**ARCHITECTURE:**

- `dmr/` — self-contained DMR DSP/FEC library (BPTC(196,96), embedded LC,
  AMBE 49↔72-bit conversion, RS(12,9), Hamming, Golay), shared with
  `ipsc2hbpc` and validated bit-for-bit against the reference `dmr_utils3`
  implementation.
- `cccc/` — the CC-CC side: link state machine (handshake, keepalive,
  link-test reflector, B-on/B-off), and the CC-CC 21-byte voice payload ⇄
  AMBE bit-packing.
- `openbridge/` — the OpenBridge side: per-peer UDP socket, HMAC-SHA1
  framing, DMRD send/receive.
- `translate.c` — wires the two sides together: the link table, per-call
  state, and both directional translation flows.
- `tests/` — a DSP self-test against golden vectors, a CC-CC AMBE
  bit-packing test, and two system tests that drive the compiled binary
  over real loopback sockets (SSRC collision; orphaned call and
  sequence/timestamp gap consistency).

**VERIFICATION:**

```
make test
```

runs all four suites — 117 checks as of this writing, 0 failures.

**WHAT IT IS NOT:**

This is not a general-purpose bridge, reflector, or conference server. It
does not do N-way bridging, talkgroup rewriting, or DMR-ID lookups. It
speaks CC-CC on one side and OpenBridge on the other, and only ever
translates one call at a time per configured link.

**REQUIREMENTS:**

- A C11 compiler and `make`
- A CC-CC-speaking remote (a c-Bridge Control Center) to link to
- An OpenBridge-speaking peer to link to — HBlink3, HBlink4, or another
  OpenBridge-capable product

**GETTING STARTED:**

```
make
cp cc2obp.toml.sample cc2obp.toml
# edit cc2obp.toml — see CONFIGURING.md
./cc2obp -c cc2obp.toml --log-level DEBUG
```

See `INSTALL.md` for the systemd service, and `CONFIGURING.md` for how to
fill in a working config, including what you'll need from the operator of
the far end of each link.

**PROPERTY:**

This work represents the author's interpretation of the CC-CC and
OpenBridge protocols. CC-CC behavior is derived from interoperability
analysis against a production c-Bridge (see
`CC-CC_Link_Protocol_Specification.md`); OpenBridge behavior is derived from
HBlink3. The DMR DSP/FEC code is shared with `ipsc2hbpc`, itself a C port of
`dmr_utils3` (N0MJS, with original AMBE work by Mike Zingman N4IRR and FEC
routines after Jonathan Naylor G4KLX).

### No Support Is Provided

This is not commercial software. It is provided free of charge. The author(s)
received no compensation for creating and maintaining it. Countless hours over
many years have gone into the this. If you have problems, the author will try
to help if possible, please have no expectations for support. There is no online
group, such as DVSwitch or groups.io that is an "official" outlet for information.
The only definitive source of information is me. Beware of others claiming to
be authoritative. User-based mutual support is great, and I'm all for it. But
please understand, this is what they are, and I have not sanctioned anyone to be
the "home" of my software packages.

### GitHub "Issues"

Do not use GitHub issues for support. Genuine bugs are accepted as issues. Before 
opening one, make sure that it is a true problem with the software and not merely
a misconfiguration, or contention around a feature that was not supported. Isssues
should never be used to ask for or recommend features. Issues that do not include
complete details, relevent tracebacks, error messages, configuration snippets, 
operatrional conditions surrounding the event, etc. will be closed without action.

***0x49 DE N0MJS***

Copyright (C) 2026 Cortney T. Buffington, N0MJS <n0mjs@me.com>

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
