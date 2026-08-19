# Removal

The part of a tool like this that people discover last and judge hardest,
because they only reach for it when something has already gone wrong.

```bash
tessera uninstall root@vpn.example.com --dry-run   # read the plan
tessera uninstall root@vpn.example.com             # do it
```

## How it decides what to remove

From the inventory at `/etc/tessera/state.json`, written as the install ran.

Every artefact records whether it **already existed before Tessera got there**:

```json
{"kind": "package", "ref": "wireguard-tools", "pre_existing": false},
{"kind": "package", "ref": "iptables",        "pre_existing": true},
{"kind": "sysctl",  "ref": "net.ipv4.ip_forward", "pre_existing": true}
```

Removal only touches entries where `pre_existing` is false.

Install a VPN on a box that already had `iptables`, and Tessera will not
uninstall `iptables`. IP forwarding you had already enabled stays enabled.

Compare with a fixed removal list written by hand: it removes what its author
remembered on the day they wrote it, and cannot know what *your* install actually
did. It either leaves debris or takes something you still needed.

## Order

Backwards, and that matters:

1. Each engine stops its own services and undoes its live state — `wg-quick down`
   runs `PostDown`, which removes the NAT rules.
2. The inventory is walked in reverse: services disabled, firewall rules closed,
   files shredded, directories removed, packages last.
3. Global artefacts (hardening) if requested.
4. The inventory itself, shredded.
5. A verification step confirms the ports really are closed.

Doing this forwards strands firewall rules with nothing left to remove them.

## Package removal never cascades

```
apt-get remove -y --no-autoremove wireguard wireguard-tools
dnf remove -y --noautoremove ...
```

`--no-autoremove` is not decoration. Without it, apt removes the dependencies it
pulled in — and on a box where something else started depending on one of them in
the meantime, you have just broken an unrelated service during what you thought
was a VPN uninstall.

## Shredding, honestly

Files holding key material are overwritten before being unlinked:

```sh
(command -v shred >/dev/null && shred -u -n 1 /etc/tessera/wg-wg0.key) \
  || rm -f /etc/tessera/wg-wg0.key
```

The test for "is this secret" is deliberately not "does it end in `.conf`". A
WireGuard `.conf` holds private keys and is shredded; `/etc/sysctl.d/99-tessera.conf`
holds the number `1` and is not. Shredding everything indiscriminately makes
removal slower and teaches people to ignore the warning.

**What shredding achieves.** On a spinning disk, overwriting in place genuinely
destroys the data. On an SSD, a copy-on-write filesystem (btrfs, ZFS), or any
journalling filesystem, it may not: the controller or the filesystem is free to
write your overwrite to a different block and leave the original intact until
wear levelling gets to it.

Tessera shreds anyway, because it is strictly better than `unlink`. But the only
real guarantee on flash storage is that the data was encrypted at rest to begin
with — which is why `tessera audit` reports whether the disk is encrypted.

## Partial removal

```bash
tessera uninstall root@box --engine openvpn    # keep WireGuard running
tessera uninstall root@box --keep-packages     # remove config, leave software
tessera uninstall root@box --keep-hardening    # keep fail2ban, sysctls, SSH policy
tessera uninstall root@box --keep-backups      # keep /etc/tessera and its history
```

Removing one engine from a server hosting two leaves the other completely alone,
including its inventory.

## What is not removed

- **Client config files on your own computer.** Tessera never had them; you saved
  them. Delete them yourself.
- **Tailscale's record of the machine** beyond `tailscale logout`. Remove the node
  from your admin console.
- **Anything you created by hand.** If you edited `wg0.conf` directly, that edit
  is not in the inventory and Tessera will not guess about it.

## If removal fails partway

Re-run it. The inventory still records what is left, so the second run continues
from where the first stopped. Rollback is deliberately **not** attempted during
removal: re-creating what was just deleted would leave a half-installed VPN,
which is worse than a clean removal that stopped early and told you where.

## Servers Tessera did not install

```
Nothing to remove: no Tessera-managed install here.
Tessera only removes what it installed. If you set a VPN up by hand it cannot
know what to touch, and will not guess.
```

That is the honest answer. A tool that guesses at removing software it did not
install is a tool that eventually deletes something important.
