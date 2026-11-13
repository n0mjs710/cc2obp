# Installation

`cc2obp` is a single C binary with **no external dependencies** — it links
only against the C standard library. Tested on Debian/Ubuntu; adapt paths for
other distros.

## Requirements

- A C11 compiler (`gcc` or `clang`) and `make`
- git

That's it. There is no Python, no venv, no `pip`, and no third-party
libraries. The TOML parser, HMAC-SHA1, the event loop, and the DMR DSP/FEC
code are all included in the repository and compiled into the binary.

## 1 — Clone and build

```
git clone https://github.com/n0mjs710/cc2obp.git
cd cc2obp
make
```

This produces the `cc2obp` binary in the repo root.

## 2 — Run the self-tests (optional but recommended)

```
make test
```

This validates the DMR DSP/FEC core against golden vectors, the CC-CC AMBE
bit-packing, and four system tests that drive the compiled binary over real
loopback sockets (SSRC collision handling; orphaned-call and
sequence/timestamp-gap behavior; SIGHUP reload; per-call OpenBridge
sequence).

## 3 — Install (as root)

```
sudo make install
```

This follows the usual system conventions:

| Item    | Destination                       |
|---------|------------------------------------|
| binary  | `/usr/local/bin/cc2obp`           |
| config  | `/etc/cc2obp/cc2obp.toml`         |
| sample  | `/etc/cc2obp/cc2obp.toml.sample`  |
| service | `/lib/systemd/system/cc2obp.service` |

The service runs as **root** — it's a background daemon; the systemd unit
just runs it that way. Install paths are overridable:

```
sudo make install PREFIX=/usr SYSCONFDIR=/etc UNITDIR=/etc/systemd/system
```

**Your live config is never clobbered.** `make install` writes
`/etc/cc2obp/cc2obp.toml` only if it does not already exist; on every run it
refreshes `cc2obp.toml.sample` next to it. Re-running `sudo make install`
after a `git pull` updates the binary and unit while leaving your config
untouched.

## 4 — Configure

Edit `/etc/cc2obp/cc2obp.toml`. See `CONFIGURING.md` for a full walkthrough,
including what you'll need to coordinate with the operator at each end of
every link before it will come up.

Validate the file before touching the running service — `--check` parses
and validates the config and exits, without binding a single socket, so
it's safe to run against an edit while a real instance is already using
the same ports:

```
/usr/local/bin/cc2obp -c /etc/cc2obp/cc2obp.toml --check
```

Prints a summary of every configured peer and link on success (exit 0), or
every problem found on failure (exit 1) — this is the fast way to answer
"will this reload cleanly?" before running `systemctl reload`.

You can also test against the config manually before enabling the service:

```
/usr/local/bin/cc2obp -c /etc/cc2obp/cc2obp.toml --log-level DEBUG
```

Hit Ctrl-C to stop. `--wire` restricts logging to raw CC-CC/OpenBridge hex
dumps if you need to inspect the wire traffic directly.

## 5 — Enable the service

```
sudo systemctl enable --now cc2obp
```

## 6 — Check the logs

```
journalctl -u cc2obp -f
```

## Reloading config without a restart

Edit the config file, then:

```
sudo systemctl reload cc2obp
```

(equivalent to `sudo kill -HUP` the running process). Only what changed is
touched: a changed or removed `[[link]]` loses its own connection, a changed
or removed `[[openbridge]]` its own socket, a new one is brought up, and every
other link stays up through the reload. A `[global]` change is logged at
WARNING and ignored until a restart. A file that does not parse or validate
is refused and the running config stays in effect. If a peer's `bind_port`
can't be bound, the reload ends with `reload finished with errors` at ERROR.
The peer stays down, its links pass no traffic, and cc2obp retries the bind
every 10 seconds. See `CONFIGURING.md` for details.

## Updating

```
git pull
make
sudo make install          # updates binary + unit, preserves your config
sudo systemctl restart cc2obp
```

## Uninstalling

```
sudo make uninstall        # removes binary + unit; leaves /etc/cc2obp intact
```

## Development runs

When working in the cloned repo, run the freshly built binary against a
local config without installing:

```
make
./cc2obp -c cc2obp.toml --log-level DEBUG
```
