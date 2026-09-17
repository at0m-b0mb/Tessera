# What Tessera does

A reference for every command, and — more usefully — why each one behaves the
way it does. If you only read one section, read [Adopting an existing
install](#adopting-an-existing-install).

## The server book

```bash
tessera servers add prod root@vpn.example.com --note "main exit node"
tessera servers list
tessera status prod
```

Saved under `$XDG_CONFIG_HOME/tessera` (Linux), `~/Library/Application
Support/Tessera` (macOS) or `%APPDATA%\Tessera` (Windows), at mode 0600.

**It contains no secrets, deliberately.** There is no password field and no key
material — only what `ssh` would need on a command line. Authentication stays in
your ssh-agent, your `~/.ssh/config` and your hardware key. That means this file
leaking tells someone your hostnames rather than letting them in, and it means
Tessera never has to implement credential storage, which is a thing that is very
easy to do badly.

A nickname may not contain `@`, `:` or `/`, which is what lets Tessera tell a
saved name from a `user@host:port` target with no ambiguity.

## Adopting an existing install

```bash
tessera adopt root@vpn.example.com
```

Management is driven by `/etc/tessera/state.json`, and until 1.1 only the
installer ever wrote one. Anyone who had already run `wireguard-install.sh` had
no way into the tool short of tearing down a working VPN.

`adopt` reads what is there and writes that inventory: interface, port, subnet,
every peer with its public key and address. For OpenVPN it reads the Easy-RSA
index, including which certificates are revoked.

Two rules keep it safe:

- **Shared resources are marked pre-existing and never removed.** Tessera did
  not install `wireguard-tools`, so it does not get to uninstall it. Same for
  sysctls and firewall state that other things may depend on.
- **The VPN's own files are removable but flagged.** `wg0.conf` unambiguously
  belongs to the VPN, so removal has to include it or "uninstall" means nothing.
  It is marked `adopted`, and the uninstaller says which files it did not create.

It never guesses. A subnet it cannot read is reported as unknown rather than
filled in with something plausible, because a plausible-but-wrong subnet
produces client configs that do not work.

**What it cannot do:** re-export configs for peers it adopted. Their private
keys live on their own devices, which is where they should be. Create a
replacement peer and revoke the old one.

## Expiring access

```bash
tessera peer add contractor --expires 14d
tessera peer add auditor    --expires 2026-12-31
```

Accepts `7d`, `2w`, `6m`, `1y` or an exact date. A month is 30 days and a year
is 365 — stated because "3m" quietly meaning 90 days is a bad surprise when
someone loses access on the wrong Tuesday. Anything under a day is refused,
because the timer runs daily and Tessera will not claim an expiry it cannot
enforce.

Enforcement lives on the server:

- **WireGuard** gets `/etc/tessera/expire.sh`, run daily by a systemd timer
  (`Persistent=true`, so a server that was off over the weekend still revokes on
  Monday) or by cron on OpenRC. It is POSIX `sh` with no dependency on Tessera,
  Python or the network — read it, it is short.
- **OpenVPN** additionally gets a certificate that expires on the same day, so
  the handshake is refused with no help from anything.

The script does the security-critical part only — cutting off access — and
appends to a log. Tessera folds that into the inventory the next time you
connect. Shell is a bad place to do JSON surgery, and a bookkeeping bug that
stopped the revocation running would be far worse than a briefly stale record.

## Backup, restore and migration

```bash
tessera backup prod -o prod.backup
tessera restore prod.backup root@new-host --endpoint new.example.com
```

A VPN server is a small amount of state that is very expensive to lose: the CA
key, the server's WireGuard key and the peer list are what make every client
config still work.

The archive is **always encrypted** and there is no flag to turn that off,
because it contains the CA private key. scrypt (N=2¹⁵) plus AES-256-GCM, with
the header authenticated as associated data, so the manifest cannot be edited
and the KDF cannot be downgraded. A single flipped byte fails the tag and the
restore refuses rather than writing a subtly corrupted PKI.

The format is documented in `core/backup.py` so that if Tessera ever stops
working, `openssl` and `tar` will get your data out.

**Restore validates before it writes.** Archives are re-packed client-side:
regular files and directories only (a symlink member is how you turn "write into
/etc/wireguard" into "write into /root"), paths confined to the three
directories Tessera owns and checked after normalisation, setuid/setgid stripped,
ownership reset to root. Anything else is listed as refused before you confirm.

Migrating keeps the keys, so existing clients still authenticate — but they are
still dialling the old address. `--endpoint` updates the inventory; each device
needs its `Endpoint` line updated too, and Tessera says so, because it cannot
edit files on other people's laptops.

## Drift detection

```bash
tessera verify prod
tessera verify prod --fix
```

The inventory decides what `uninstall` may delete, so it matters that it still
describes reality. Someone edits `wg0.conf` by hand; config management reverts a
sysctl; the expiry timer revokes a peer while nobody is looking.

`verify` compares and reports. It never repairs on its own — silently deleting a
peer a colleague added an hour ago is worse than saying so.

`--fix` reconciles the **inventory only**. It will never add or remove access on
the server. Importing an unknown peer records access that already exists; it
does not grant anything. A repair tool that can hand out access is one nobody
should run unattended.

## Live status

```bash
tessera watch prod
tessera status prod
```

## Shell completion

```bash
tessera completions zsh > "${fpath[1]}/_tessera"
tessera completions bash > /etc/bash_completion.d/tessera
tessera completions fish > ~/.config/fish/completions/tessera.fish
```

Generated from the argument parser itself, so they cannot drift from the tool.
Saved server names complete dynamically.

## The demo server

```bash
tessera install demo
tessera peer add phone demo
tessera demo reset
```

A simulated Ubuntu 24.04 box whose virtual disk persists between commands. The
interview, the plans, the rendered configs and the generated keys are all real —
only the execution is simulated. Nothing about it touches a network.
