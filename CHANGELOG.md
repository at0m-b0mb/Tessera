# Changelog

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
