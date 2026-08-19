# Command reference

```
tessera [-q] [-v] [--no-color] <command> [target] [options]
```

Global flags come **before** the subcommand: `tessera -v install root@box`.

## Targets

Every command takes an optional target:

| Form | Means |
|---|---|
| *(omitted)* or `local` | this machine |
| `demo` | a simulated Ubuntu server — nothing is contacted |

The demo server lives in memory for one process, so state does not carry between invocations: `tessera install demo` then `tessera peer list demo` will report an empty server, because the second command starts a fresh simulation. Use the GUI, or a single script, to see the full lifecycle.
| `host` | SSH to `host` as your current user |
| `user@host` | SSH as `user` |
| `user@host:2222` | non-standard SSH port |

Connection options: `--user`, `--port`, `-i/--identity`,
`--ask-sudo-password`, `--offline` (skip public-IP lookup).

`~/.ssh/config` is honoured, so `tessera status prod` works if `prod` is defined
there. The sudo password can also come from `TESSERA_SUDO_PASSWORD`.

## `tessera install`

```bash
tessera install                              # this machine, interactive
tessera install root@box                     # remote, interactive
tessera install root@box --dry-run           # print the plan, change nothing
tessera install root@box -y                  # every default, no prompts
tessera install root@box -e wireguard -e openvpn
tessera install root@box --profile paranoid
```

| Option | Effect |
|---|---|
| `-e, --engine` | `wireguard`, `openvpn` or `tailscale`. Repeatable. |
| `--profile` | `quick`, `balanced`, `paranoid`, `custom` |
| `--peer NAME` | name for the first device (default `laptop`) |
| `--endpoint ADDR` | address clients connect to |
| `--vpn-port N` | port the VPN listens on |
| `-y, --yes` | accept every default, no prompts |
| `--advanced` | ask the advanced questions too |
| `--dry-run` | compile and print the plan, then exit |
| `--show-plan` | print the plan, then ask before applying |
| `-o, --out DIR` | where to write client configs (default `./tessera-clients`) |
| `--no-qr` | do not print a QR code |

### Profiles

| Profile | Behaviour |
|---|---|
| `quick` | Three questions. WireGuard, random port, Quad9, kernel hardening. |
| `balanced` | The full interview, everything pre-filled. **Default.** |
| `paranoid` | Adds fail2ban, automatic security updates, key-only SSH, TLS 1.3. |
| `custom` | Every question, including advanced ones. |

Client configs are written with mode `0600`, created that way from the outset —
writing then `chmod`-ing leaves a window where the key is world-readable.

## `tessera status`

```bash
tessera status root@box
```

Per engine: whether the service is running, connected peers, last handshake and
transfer totals. Read-only.

## `tessera peer`

```bash
tessera peer list root@box
tessera peer add phone root@box
tessera peer add phone root@box --engine openvpn -o ~/vpn
tessera peer remove phone root@box --engine wireguard
```

`--engine` is optional when only one is installed.

Adding a peer generates the keypair **locally**. Only the public key reaches the
server. WireGuard peers are applied with `wg syncconf`, so existing tunnels are
not dropped.

Removing a WireGuard peer disconnects it immediately and rewrites the config.
Removing an OpenVPN peer revokes its certificate, regenerates the CRL and kicks
the session through the management socket — the CRL alone would only take effect
at the next handshake.

## `tessera audit`

```bash
tessera audit root@box
tessera audit root@box -v      # show detail for passing checks too
```

Read-only. Checks SSH policy, pending security updates, firewall and exposed
listeners, kernel currency, disk encryption, file permissions, and per-engine
configuration.

**Exit code 3 when any check fails**, so it drops straight into CI:

```bash
tessera audit root@box || exit 1
```

The worst finding sets the verdict. One failure fails the audit regardless of how
many checks passed.

## `tessera uninstall`

```bash
tessera uninstall root@box --dry-run
tessera uninstall root@box
tessera uninstall root@box --engine openvpn
```

| Option | Effect |
|---|---|
| `-e, --engine` | remove only this engine |
| `--keep-packages` | leave installed software, remove configuration |
| `--keep-hardening` | leave fail2ban, sysctls and SSH policy applied |
| `--keep-backups` | keep `/etc/tessera` and its state history |
| `--dry-run` | print the plan only |
| `-y, --yes` | skip the `REMOVE` confirmation |

See [UNINSTALL.md](UNINSTALL.md).

## `tessera doctor`

```bash
tessera doctor root@box
tessera doctor root@box -e wireguard
```

Inspects without changing anything: distribution, kernel, virtualisation,
default interface, public address, NAT, IPv6, `/dev/net/tun`, firewall, SELinux,
what is already installed, and whether each engine can run here.

Exit code 2 if something would block an install. Safe against production.

## `tessera gui`

Launches the desktop application. Requires PyQt6.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error |
| 2 | blocked by preflight |
| 3 | audit found a failure |

## Environment

| Variable | Effect |
|---|---|
| `TESSERA_SUDO_PASSWORD` | sudo password for the target |
| `NO_COLOR` / `TESSERA_NO_COLOR` | disable colour |
| `QT_QPA_PLATFORM=offscreen` | run the GUI headless (screenshots, CI) |

## Automation

```bash
#!/usr/bin/env bash
set -euo pipefail

for host in vpn-eu vpn-us vpn-ap; do
  tessera install "root@$host" --yes \
      --engine wireguard \
      --endpoint "$host.example.com" \
      --profile paranoid \
      --out "./configs/$host" --no-qr
  tessera audit "root@$host"
done
```

`--yes` never prompts, `--out` collects the configs, and `audit`'s exit code
fails the script if a host came up wrong.
