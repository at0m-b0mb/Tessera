# Changelog

All notable changes to Tessera are recorded here.

## 1.1.1 — 2026-09-17

### Fixed

- `tessera adopt demo` reported that nothing was installed. The simulated
  server did not answer the shell glob that adoption uses to discover a VPN
  (`ls -1 /etc/wireguard/*.conf`), so the headline feature of 1.1.0 could not
  be tried before using it on a real machine. Real servers were unaffected;
  the evaluation path was not.

## 1.1.0 — 2026-09-17

The theme is **continuity**: taking over a VPN you already run, keeping it when
a server dies, and making access end by itself.

### Added

**Server book.** `tessera servers add prod root@vpn.example.com`, then `prod`
works anywhere a target is accepted — CLI and GUI. The file holds no
credentials by design: authentication stays in your ssh-agent and
`~/.ssh/config`, so the book leaking is an inconvenience, not a compromise.

**`tessera adopt`.** Takes over a WireGuard or OpenVPN install that another
tool set up, including `angristan/wireguard-install` and
`angristan/openvpn-install`. It reads the config, imports every peer, and
writes the inventory that was never there. Nothing on the server is changed.
Packages and system settings are recorded as pre-existing so uninstall will
never remove them; the VPN's own files are marked adopted, and the uninstaller
says out loud which files it did not create.

Until now, anyone already running a VPN had no way into Tessera short of
tearing down something that worked.

**Expiring access.** `tessera peer add contractor --expires 14d`. Enforcement
is server-side and self-contained: a daily systemd timer (or cron) runs a
dependency-free POSIX `sh` script that removes expired peers from the live
interface and the config. It keeps working if Tessera is never run against that
server again, because a reminder in someone's calendar is not an access
control. OpenVPN additionally gets a certificate that lapses on the same day,
so the cryptography is the real enforcement.

**Encrypted backup, restore and migration.** `tessera backup` pulls keys,
config and peer list into one file sealed with scrypt + AES-256-GCM;
`tessera restore … --endpoint new.host` rebuilds it elsewhere with the keys
intact, so existing clients still authenticate. There is no flag to skip
encryption: the archive contains the OpenVPN CA private key.

**`tessera verify`.** Compares the server against the inventory and reports
drift — peers added by hand, files removed, services down, a port that changed.
`--fix` reconciles the *inventory only*; it will never add or remove access on
the server.

**`tessera watch`.** Live terminal view of who is connected.

**Shell completions** for bash, zsh and fish, generated from the parser itself
so they cannot drift from the tool. Saved server names complete dynamically.

**A demo server that persists.** `tessera install demo` then `tessera peer add
… demo` now works across commands, so the whole workflow can be walked before
you own a server. `tessera demo reset` starts over.

**`-s/--server`** on every command that takes a target. The positional still
works, but argparse before Python 3.12 cannot reliably parse a positional that
comes after options — `peer add guest --expires 14d prod` fails there — and the
flag reads better anyway.

**GUI**: saved-server picker, expiry on the add-device row, and Adopt, Verify
and Back up on the dashboard.

### Fixed

- `--engine openvpn` was silently discarded: filling in defaults overwrote
  values that had been set explicitly, so a two-engine install quietly became
  WireGuard-only. Added `interview.prepare()` as the one safe way to build a
  spec programmatically.
- The `paranoid` profile's SSH setting was reset by the same bug.
- Demo commands after the first behaved as if nothing was installed, because
  the demo path built an empty inventory instead of loading one.
- `verify` reported files as missing on a healthy demo server.
- `status` showed raw public keys where `watch` showed device names.
- `verify` reported the OpenVPN server's own certificate as an unknown client
  on every install, because the server CN was not excluded when reading
  `index.txt`.

### Security

A full audit of the codebase found five issues, all introduced by this
release's own new code and all fixed before it shipped. Each now has a
regression test in `tests/test_security.py`.

- **Arbitrary file write as root during restore** (high). `tar xzf -C /
  --absolute-names` obeyed whatever paths were in the archive, so a crafted
  backup could write `/etc/cron.d/…`, `/root/.ssh/authorized_keys` or
  `/etc/sudoers.d/…`. Encryption was no defence, because the attacker is
  whoever hands you the file and its passphrase. Archives are now validated and
  re-packed before they reach the server: regular files and directories only,
  paths confined to the three directories Tessera owns, checked after
  normalisation, with setuid/setgid stripped and ownership reset.
- **Symlink attack on a predictable temp path** (high). Restore staged through
  `/tmp/tessera-restore.tgz` as root; any local user could pre-create that as a
  symlink to a file they wanted overwritten. Now staged via `mktemp` in a
  root-only directory.
- **Command injection through the interface name** (high). The name was
  interpolated unquoted into the firewall script that runs as root from
  wg-quick's `PostUp`, and `adopt` learns that name from a *filename* —
  `wg0$(…).conf` is a legal filename. Names are now validated against the
  kernel's own rules at every boundary, and the script refers to `"$IFACE"`.
- **Untrusted peer names from adopted configs** (medium). Names come from a
  config comment or a certificate subject. Every current use quoted them
  correctly, but a tab would have corrupted the expiry table's columns and one
  forgotten quote would have been a root shell. They are sanitised on the way
  in, with the original kept in the peer's note.
- **Host key checking could be disabled** (medium). `extra_opts` passed
  `StrictHostKeyChecking=no` straight through to `ssh`. That option and
  `UserKnownHostsFile=/dev/null` are now refused. Default remains trust-on-first-use;
  `--strict-host-keys` refuses unknown hosts too.

Also hardened: the heredoc delimiter used to write every private key is
re-rolled if it could ever collide with the content.

## 1.0.0

First release.

**Engines** — WireGuard, OpenVPN and Tailscale, installable together on one
server.

**Runs anywhere** — macOS, Windows and Linux, driving a Linux target through the
system `ssh` binary. Nothing is installed on the server.

**Plans** — every operation compiles to a reviewable list of steps with exact
commands, explanations and undo actions. `--dry-run` prints the same plan that
would execute, not a separate code path.

**Client keys are generated locally** — WireGuard keypairs and OpenVPN CSRs are
made on your desktop; only public material reaches the server.

**Inventory-driven removal** — `/etc/tessera/state.json` records every artefact
and whether it pre-existed, so uninstall removes exactly what Tessera added.

**Security audit** — read-only posture checks across SSH, updates, firewall,
kernel, permissions and per-engine configuration. Exit code 3 on failure.

**Two front ends, one engine** — a PyQt6 desktop app and a rich CLI that render
the same question set and drive the same `Session`.

**Demo mode** — `tessera install demo` runs the whole flow against a simulated
server.
