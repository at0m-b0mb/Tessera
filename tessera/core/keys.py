"""Key material.

The important decision in this file is *where* keys are born.

The reference WireGuard installer runs ``wg genkey`` on the server for every
client, writes the client's private key into a .conf in someone's home
directory, and leaves it there.  The server therefore knows, has logged, and
still stores the private half of every device that will ever connect to it.
That is a plaintext key at rest on the internet-facing box, and a copy in the
shell history and in any backup of /root.

Tessera generates client keypairs *here*, on your desktop, and sends only the
public key and the preshared key to the server.  The server is told what to
trust; it is never told the secret.  If the server is later compromised, the
attacker learns which devices are allowed in, and cannot become any of them.

Server-side keys (the server's own private key, OpenVPN's CA) obviously have to
exist on the server, so those are generated there with the platform tools and
never travel.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import string
from typing import Tuple

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    _HAVE_CRYPTO = True
except Exception:                                              # pragma: no cover
    _HAVE_CRYPTO = False


B64_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")


def have_local_keygen() -> bool:
    """True when we can make WireGuard keys without the server's help."""
    return _HAVE_CRYPTO


def wg_keypair() -> Tuple[str, str]:
    """Return (private_key, public_key) as base64, exactly like ``wg genkey``.

    WireGuard keys are Curve25519 scalars.  The scalar is *clamped* - low three
    bits cleared, bit 255 cleared, bit 254 set - which forces the key into the
    prime-order subgroup and to a fixed bit length.  That kills small-subgroup
    attacks and makes the scalar multiplication constant-time regardless of the
    key.  OpenSSL clamps during use, but we clamp the stored bytes too so our
    output is byte-identical to what ``wg genkey`` would have produced.
    """
    if not _HAVE_CRYPTO:
        raise RuntimeError(
            "the 'cryptography' package is required for local key generation")
    priv = X25519PrivateKey.generate()
    raw = bytearray(priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    # Re-derive the public key from the clamped scalar so the pair always agrees.
    clamped = X25519PrivateKey.from_private_bytes(bytes(raw))
    pub = clamped.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return (base64.b64encode(bytes(raw)).decode(),
            base64.b64encode(pub).decode())


def wg_pubkey_from_private(private_b64: str) -> str:
    """Recover the public half, e.g. when importing an existing config."""
    if not _HAVE_CRYPTO:
        raise RuntimeError("the 'cryptography' package is required")
    raw = base64.b64decode(private_b64)
    if len(raw) != 32:
        raise ValueError("a WireGuard private key is 32 bytes")
    pub = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()


def wg_psk() -> str:
    """A 256-bit preshared key, like ``wg genpsk``.

    This is mixed into the handshake as an extra symmetric secret.  It does not
    replace the Curve25519 handshake; it sits on top of it, so an adversary who
    records traffic today and breaks Curve25519 with a quantum computer later
    still faces a 256-bit symmetric secret they never saw on the wire.  It costs
    nothing, so Tessera always sets one.
    """
    return base64.b64encode(secrets.token_bytes(32)).decode()


def is_valid_wg_key(value: str) -> bool:
    """A WireGuard key is 32 bytes in base64: 44 chars ending in '='."""
    if not value or len(value) != 44:
        return False
    if not B64_KEY_RE.match(value):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except Exception:                                          # noqa: BLE001
        return False


def random_port(low: int = 49152, high: int = 65535) -> int:
    """A port from the ephemeral range, chosen with a CSPRNG.

    Not a security control - anyone scanning finds it - but it keeps you out of
    the noise floor of bots hammering 1194 and 51820 all day, which measurably
    shrinks your log volume.
    """
    return secrets.randbelow(high - low + 1) + low


def random_token(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def fingerprint(data: str, length: int = 16) -> str:
    """Short, stable, human-comparable digest used for display only."""
    digest = hashlib.sha256(data.encode()).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, length, 2))


def redact(text: str) -> str:
    """Strip anything that looks like a secret out of text bound for a log."""
    if not text:
        return text
    text = re.sub(r"(PrivateKey\s*=\s*)\S+", r"\1<redacted>", text)
    text = re.sub(r"(PresharedKey\s*=\s*)\S+", r"\1<redacted>", text)
    text = re.sub(r"tskey-[A-Za-z0-9-]+", "tskey-<redacted>", text)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                  "<redacted private key>", text, flags=re.S)
    return text


def shred_command(path: str, passes: int = 1) -> str:
    """Best-effort secure delete, with an honest fallback.

    ``shred`` overwrites in place, which genuinely destroys data on a spinning
    disk.  On SSDs, on copy-on-write filesystems (btrfs, ZFS) and on any
    journalling filesystem it may not, because the controller or the filesystem
    can write the overwrite somewhere else and leave the original block intact.
    We still do it - it is strictly better than unlink - but the documentation
    says plainly that on flash storage the only real guarantee is full-disk
    encryption, which is why Tessera recommends that in the audit.
    """
    return ("(command -v shred >/dev/null && shred -u -n {n} {p}) "
            "|| rm -f {p}").format(n=passes, p=_q(path))


def _q(s: str) -> str:
    import shlex
    return shlex.quote(s)


# --------------------------------------------------------------------------- #
# OpenVPN client keys
# --------------------------------------------------------------------------- #
def generate_client_csr(common_name: str, curve: str = "prime256v1",
                        rsa_bits: int = 3072, algo: str = "ecdsa"
                        ) -> Tuple[str, str]:
    """Generate a client key and certificate request *locally*.

    Easy-RSA's ``build-client-full`` makes the key on the server, which means
    the server has held every client's private key.  The proper PKI flow is the
    one certificate authorities have used for thirty years: the subject makes
    its own key, sends a *request* containing only the public half plus a
    self-signature proving possession, and the CA signs that.

    So Tessera generates the key here, sends only the CSR, and asks Easy-RSA to
    ``import-req`` and ``sign-req``.  The private key stays on your desktop.
    A compromised server yields no client identities.

    Returns (private_key_pem, csr_pem).
    """
    if not _HAVE_CRYPTO:
        raise RuntimeError("the 'cryptography' package is required")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    if algo == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        digest = hashes.SHA256()
    else:
        curves = {
            "prime256v1": ec.SECP256R1(), "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
        }
        if curve not in curves:
            raise ValueError("unsupported curve {}".format(curve))
        key = ec.generate_private_key(curves[curve])
        digest = hashes.SHA256() if curve == "prime256v1" else hashes.SHA384()

    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
           .sign(key, digest))

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()).decode()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, csr_pem


def cert_fingerprint(cert_pem: str) -> str:
    """SHA-256 fingerprint of a certificate, formatted like OpenSSL prints it."""
    if not _HAVE_CRYPTO:
        raise RuntimeError("the 'cryptography' package is required")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return ":".join("{:02X}".format(b)
                    for b in cert.fingerprint(hashes.SHA256()))


def cert_expiry(cert_pem: str) -> str:
    """ISO date the certificate stops being valid."""
    if not _HAVE_CRYPTO:
        raise RuntimeError("the 'cryptography' package is required")
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    try:
        return cert.not_valid_after_utc.date().isoformat()
    except AttributeError:                                     # cryptography < 42
        return cert.not_valid_after.date().isoformat()
