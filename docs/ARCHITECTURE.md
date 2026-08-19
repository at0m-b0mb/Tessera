# Architecture

Tessera is a control plane. It runs on your desktop and drives a Linux server
through shell commands sent over SSH. Nothing is installed on the server.

## Layers

```
  tessera/
  ├── branding.py          name, palette, marks
  │
  ├── core/                Qt-free, no I/O beyond the transport, fully testable
  │   ├── transport.py     how we reach the machine (local / ssh)
  │   ├── facts.py         what the machine is       (read-only detection)
  │   ├── models.py        the vocabulary            (plain dataclasses)
  │   ├── plan.py          Step / Plan / Executor    (the trust boundary)
  │   ├── state.py         the on-server inventory   (makes uninstall exact)
  │   ├── keys.py          key material              (born locally, on purpose)
  │   ├── netcalc.py       address planning
  │   ├── interview.py     the questions             (shared by both front ends)
  │   ├── engines/         one module per VPN behind one interface
  │   ├── hardening.py     server hardening, separately from any engine
  │   ├── audit.py         read-only posture checks
  │   ├── uninstall.py     removal, driven by the inventory
  │   ├── qr.py            QR rendering, locally
  │   ├── demo.py          a simulated server
  │   └── manager.py       Session - the only thing front ends talk to
  │
  ├── cli/                 argparse + rich (degrades to plain ANSI)
  └── gui/                 PyQt6
```

The dependency direction is strictly downward. `core` imports nothing from `cli`
or `gui`; `cli` and `gui` import nothing from each other. Both talk to exactly
one object, `manager.Session`.

That is what guarantees feature parity. **There is no operation the GUI can
perform that the CLI cannot**, because neither of them knows how to do anything
on its own.

## The important pieces

### transport.py — how we reach the machine

Two implementations of one interface:

- `LocalTransport` — you are already on the Linux box.
- `SSHTransport` — shells out to the system `ssh` binary.

Using the real `ssh` binary rather than an embedded Python SSH library is a
deliberate trade. It costs us the ability to hold a channel open cheaply, which
we buy back with ControlMaster multiplexing. It gains us `~/.ssh/config`,
ProxyJump, ssh-agent, hardware keys and OpenSSH's own `known_hosts` handling —
none of which we then have to implement, get wrong, or add a bypass flag to.

`write_file` is worth reading. Content goes over **stdin** via a random heredoc
delimiter, never on a command line, so secrets never appear in `ps`, in shell
history or in sudo's audit log. It writes to a temporary file in the target
directory and renames, so a dropped connection cannot leave a half-written key.

### plan.py — the trust boundary

Nothing executes directly. Every operation compiles to a `Plan`: an ordered list
of `Step`s, each carrying its exact command, whether it changes anything, why it
exists, and how to undo it.

Three properties fall out for free:

1. `--dry-run` is not a separate code path. It is the same plan, printed instead
   of run. What you review is literally what executes.
2. Failure is unambiguous. Completed steps are recorded, so the executor can roll
   back in reverse using each step's own undo command.
3. Progress is honest, because the total is known before work starts.

### state.py — the inventory

`/etc/tessera/state.json`, mode 0600, records every artefact Tessera created and
whether it *already existed*:

```json
{
  "engines": {
    "wireguard": {
      "config": {"port": 51820, "interface": "wg0", "server_public_key": "..."},
      "peers": [{"name": "laptop", "public_key": "...", "private_key": ""}],
      "artifacts": [
        {"kind": "package", "ref": "wireguard-tools", "pre_existing": false},
        {"kind": "package", "ref": "iptables",        "pre_existing": true},
        {"kind": "file",    "ref": "/etc/wireguard/wg0.conf"},
        {"kind": "sysctl",  "ref": "net.ipv4.ip_forward", "pre_existing": true}
      ]
    }
  }
}
```

`pre_existing` is the whole design. Uninstall only ever removes entries where it
is false.

Note `"private_key": ""`. Peer private keys are handed to the caller and
deliberately never written here — see below.

### keys.py — where keys are born

Client keypairs are generated **on your desktop**. Only the public key and the
preshared key travel to the server.

For WireGuard this is a Curve25519 scalar, clamped explicitly so the stored bytes
are identical to what `wg genkey` would have produced.

For OpenVPN it is the standard CA flow: local key, local CSR, `easyrsa
import-req` + `sign-req` on the server. The server's CA signs a request; it never
sees a private key.

Server-side keys (the server's own WireGuard key, the OpenVPN CA) obviously have
to live on the server, so those are generated there with `umask 077` and
redirected straight into a 0600 file — never passed as an argument.

### engines/ — one module per VPN

`base.py` holds everything distro-shaped: `pkg_install` knows Debian needs
`DEBIAN_FRONTEND=noninteractive` and Alpine wants `apk add`; the WireGuard engine
just asks for a package by name. Adding a fourth engine is therefore small.

Each engine implements:

```python
plan_install(ctx)            -> Plan
plan_uninstall(ctx, purge)   -> Plan
plan_add_peer(ctx, name)     -> (Plan, Peer, client_config)
plan_remove_peer(ctx, name)  -> Plan
status(ctx)                  -> dict
```

`TailscaleEngine.plan_add_peer` raises with an explanation rather than
pretending: Tailscale devices enrol themselves from the device, and a fake
"add peer" button that cannot work is worse than a sentence saying so.

### interview.py — the questions, defined once

Both front ends walk the same `QUESTIONS` list. The CLI renders each as a prompt;
the GUI renders each as a widget. A question added for one appears in the other
automatically, with the same default, validation and explanation.

Every question carries a `why` that states the *consequence*, not a restatement
of the prompt. Someone who does not know what `AllowedIPs` means cannot answer
"what should AllowedIPs be", but can certainly answer "should all your traffic go
through this server, or only traffic to the server's own network".

`InstallSpec.answered` tracks which keys were set explicitly, so `fill_defaults`
never overwrites a choice. Without it, `--engine openvpn` was silently discarded
by the defaults pass — a bug that is invisible until you go and look at the
server.

## Adding an engine

1. Create `core/engines/yourvpn.py` with a class extending `Engine`.
2. Register it in `core/engines/__init__.py`.
3. Add its questions to `core/interview.py` with a `when=` predicate.
4. Add a config dataclass to `core/models.py` and a field on `InstallSpec`.

No GUI or CLI changes are required. Both discover it.

## Testing

`tests/fake.py` provides a `FakeTransport` that answers from a script and records
every command. That is enough to exercise real plan construction, real config
rendering and the real inventory with no server involved — including the
assertion that a client private key never appears in anything sent to the server.

```bash
python3 tests/test_lifecycle.py
```
