# Security model

What Tessera protects against, what it does not, and where the sharp edges are.

## What a VPN actually does for you

Worth stating plainly, because it is routinely oversold.

A VPN moves the point at which your traffic joins the public internet. Instead of
your ISP or the café Wi-Fi seeing which sites you connect to, your server does.

**It does:** hide your browsing from the local network and your ISP; give you an
encrypted path to services on your server's network; let you appear to be in the
server's location.

**It does not:** make you anonymous — your server has your payment details and
your login sessions still identify you; protect you from a compromised device;
stop websites fingerprinting your browser; encrypt anything already using HTTPS
beyond the tunnel's exit.

If your threat model is a state adversary, a self-hosted VPN on a VPS in your own
name is not the tool.

## Trust boundaries

| Component | Trusted with | Notes |
|---|---|---|
| Your desktop | everything | Generates all client keys. Compromise here is total. |
| The SSH channel | server control | Uses your existing OpenSSH trust. Tessera adds none of its own. |
| The server | public keys, its own private key | Never sees client private keys. |
| Tailscale's coordinator | key distribution metadata | Traffic stays end-to-end encrypted. Avoidable with Headscale. |

## Where key material lives

| Key | Generated on | Stored on | Reaches the server? |
|---|---|---|---|
| WireGuard client private | your desktop | your client config only | **no** |
| WireGuard client public | your desktop | server config + inventory | yes |
| Preshared key | your desktop | both | yes — it is symmetric by definition |
| WireGuard server private | server, `umask 077` | `/etc/tessera/wg-*.key`, 0600 | it lives there |
| OpenVPN client private | your desktop | your `.ovpn` only | **no** |
| OpenVPN client cert | signed on server | both | yes — a certificate is public |
| OpenVPN CA private | server | `easy-rsa/pki/private`, 0600 | it lives there |
| Tailscale auth key | you | 0600 file, shredded after use | briefly, then destroyed |

### Why this matters

The installers Tessera takes reference from generate client keys on the server.
That means the server has, at some point, held the private key of every device
that will ever connect to it — in a file, in shell history, and in any backup of
`/root`.

Tessera's server is told **whom to trust**, never **the secret**. An attacker who
takes the server learns the guest list. They cannot forge a guest.

### The cost, stated honestly

Tessera cannot re-issue a config you have lost, because there is nothing to
re-issue it from. `tessera export` exists only to say so clearly and tell you
what to do instead:

```bash
tessera peer add laptop-new --engine wireguard
tessera peer remove laptop  --engine wireguard
```

## Secrets never appear in argv

Everything readable from the process table is treated as public.

- Config content is written over **stdin** with a random heredoc delimiter.
- `wg genkey` is redirected straight into a 0600 file.
- The server private key is substituted into `wg0.conf` by a shell loop reading
  into a variable — not by `sed "s/x/$(cat key)/"`, which would put the key in
  sed's argv.
- Tailscale auth keys are staged to a 0600 file, passed as `--auth-key=file:...`,
  and shredded immediately.
- Steps holding secrets are marked `sensitive` and print as
  `<secret command hidden>`.

## Cryptographic choices

**WireGuard** — no choices to make; that is the point. Tessera always sets a
preshared key. It does not replace the Curve25519 handshake, it sits on top: an
adversary recording traffic today and breaking Curve25519 with a quantum computer
later still faces a 256-bit symmetric secret they never observed. It costs
nothing, so there is no reason not to.

**OpenVPN**

| Choice | Value | Why |
|---|---|---|
| Data cipher | AES-256-GCM | AEAD — no separate MAC to get wrong, no CBC padding oracle. CBC is not offered at all. |
| Certificates | ECDSA P-256 | Equivalent to RSA-3072, handshake an order of magnitude cheaper. |
| Digest | SHA-256 / SHA-512 for the CA | |
| Control channel | `tls-crypt-v2` | Per-client key. A leaked client key does not let an attacker probe as anyone else, and the port is unidentifiable to scanners. |
| TLS floor | 1.2 (1.3 under the hardened profile) | |
| Compression | **off, unconditionally** | Compressing before encrypting leaks plaintext length. That is VORACLE. There is no safe configuration. |

## Supply chain

- Easy-RSA is pinned to a specific release and verified against a SHA-256 shipped
  in the source. A failed checksum aborts before anything runs.
- Tailscale is installed from its official repository with its signing key, not
  by piping a script from the internet into a root shell — which is what
  Tailscale's own documentation suggests.
- Tessera's only required dependency is `cryptography`.

## Network policy

By default VPN clients are blocked from reaching RFC1918 and carrier-grade NAT
ranges through the server. Without that, giving someone VPN access also gives
them your home NAS, your router's admin page, and anything else on the server's
LAN. It is a checkbox, because sometimes reaching that LAN is exactly the point —
but the default is the safe one.

Firewall rules live in one reviewable script per engine, called from
`PostUp`/`PostDown`, and every rule is added with `-C` first so re-running an
install is a no-op rather than stacking a duplicate.

## Hardening

Optional, off by default except the kernel settings, and every item is reversible
by deleting one file:

- Nine sysctl settings that matter specifically on a packet-forwarding host.
- `fail2ban` with a dedicated drop-in, so your own config is untouched.
- Unattended **security** upgrades only.
- Key-only SSH — which Tessera refuses to apply unless an `authorized_keys` file
  already exists, and validates with `sshd -t` before reloading. Getting this
  wrong locks you out of your own server permanently.

## What Tessera does not do

- **Client-side kill switch.** Enforced on the client, not the server. WireGuard's
  `AllowedIPs = 0.0.0.0/0` gets most of the way; a true kill switch needs local
  firewall rules Tessera does not manage.
- **Traffic obfuscation.** OpenVPN on TCP 443 resembles HTTPS to casual
  inspection, but nothing here defeats a serious DPI system. If you need that,
  you need obfs4 or Shadowsocks.
- **Multi-server orchestration.** One server at a time.
- **Guarantee that shredding works.** `shred` overwrites in place, which destroys
  data on a spinning disk. On SSDs, copy-on-write filesystems and journalling
  filesystems it may not, because the controller or filesystem can write
  elsewhere and leave the original block intact. Tessera still shreds — it is
  strictly better than `unlink` — but full-disk encryption is the only real
  guarantee, which is why the audit says so.

## Reporting a vulnerability

Open a security advisory on the repository rather than a public issue.
