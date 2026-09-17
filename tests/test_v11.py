"""Fleet, expiry, backup and drift detection."""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ["TESSERA_CONFIG_DIR"] = tempfile.mkdtemp(prefix="tessera-test-")

from fake import FakeTransport, demo_facts

from tessera.core import backup, expiry, fleet
from tessera.core import interview as iv
from tessera.core.manager import Session
from tessera.core.models import InstallSpec, Target
from tessera.core.state import ServerState


def installed_session(engines=("wireguard",)):
    t = FakeTransport(responses={r"wg pubkey": "SRVPUB0000000000000000000000000="})
    s = Session(t, demo_facts(), ServerState(), Target())
    # prepare(), not "assign then fill_defaults" - see interview.prepare.
    spec = iv.prepare(InstallSpec(), s.facts,
                      engines=list(engines), first_peer="")
    s.install(spec)
    # Files created by shell redirects the fake does not emulate.
    t.files.setdefault("/etc/tessera/wg-wg0.key", "SERVERKEY=")
    t.files.setdefault("/etc/sysctl.d/99-tessera-wireguard.conf",
                       "net.ipv4.ip_forward = 1")
    return s


# --------------------------------------------------------------------------- #
def _clear_book():
    book = fleet.load()
    for name in book.names():
        book.drop(name)
    fleet.save(book)


def test_fleet_roundtrip():
    _clear_book()
    fleet.add("prod", "root@vpn.example.com", note="main", overwrite=True)
    fleet.add("lab", "deploy@10.0.0.9:2222", overwrite=True)
    assert sorted(fleet.load().names()) == ["lab", "prod"]
    t = fleet.resolve("prod")
    assert (t.user, t.host, t.port, t.label) == ("root", "vpn.example.com", 22, "prod")
    t2 = fleet.resolve("deploy@elsewhere.net:2200")
    assert (t2.user, t2.host, t2.port) == ("deploy", "elsewhere.net", 2200)
    fleet.remove("lab")
    assert fleet.load().names() == ["prod"]
    print("  saved, resolved and removed")


def test_fleet_refuses_ambiguous_names():
    for bad in ("demo", "local", "a@b", "has:colon", "x/y"):
        try:
            fleet.validate_name(bad)
            raise AssertionError("{} should be rejected".format(bad))
        except AssertionError:
            raise
        except Exception:
            pass
    fleet.validate_name("prod-eu-1")
    print("  reserved and ambiguous names rejected")


def test_fleet_holds_no_secrets():
    """The whole security argument for this file being 0600 JSON."""
    _clear_book()
    fleet.add("prod-eu", "root@host.example", overwrite=True)
    body = open(fleet.path()).read().lower()
    for word in ("password", "passphrase", "privatekey", "secret", "token"):
        assert word not in body, "server book must never hold {}".format(word)
    if os.name == "posix":
        import stat
        mode = stat.S_IMODE(os.stat(fleet.path()).st_mode)
        assert mode == 0o600, oct(mode)
        print("  no credential fields, mode 0600")
    else:
        # Windows uses ACLs, not mode bits; os.stat reports 0o666 regardless,
        # so asserting on it would be testing the emulation, not the file.
        print("  no credential fields (mode check is POSIX-only)")


# --------------------------------------------------------------------------- #
def test_expiry_durations():
    now = date(2026, 9, 16)
    assert expiry.parse_duration("14d", now=now) == "2026-09-30"
    assert expiry.parse_duration("2w", now=now) == "2026-09-30"
    assert expiry.parse_duration("2026-12-31", now=now) == "2026-12-31"
    for bad in ("12h", "0d", "-1d", "yesterday", "2020-01-01", ""):
        try:
            expiry.parse_duration(bad, now=now)
            raise AssertionError("{} should be rejected".format(bad))
        except AssertionError:
            raise
        except Exception:
            pass
    print("  durations parsed, sub-day and past dates refused")


def test_expiry_installs_self_contained_enforcement():
    s = installed_session()
    peer, _ = s.add_peer("wireguard", "contractor", expires="14d")
    assert peer.access_expires
    assert peer.interface == "wg0"

    table = s.transport.files.get(expiry.TABLE, "")
    assert "contractor" in table and peer.public_key in table
    assert peer.access_expires in table

    script = s.transport.files.get(expiry.SCRIPT, "")
    assert script.startswith("#!/bin/sh"), "must be POSIX sh, not bash"
    # The point of this script is that it works on a machine that has
    # nothing installed on it. Tessera itself is never on the server, so the
    # thing to guard against is a dependency on an interpreter or the network.
    code = "\n".join(l for l in script.splitlines()
                     if l.strip() and not l.strip().startswith("#"))
    for dependency in ("python", "jq", "curl", "wget", "perl"):
        assert dependency not in code, \
            "the revoker must not depend on {}".format(dependency)

    assert "/etc/systemd/system/tessera-expiry.timer" in s.transport.files
    assert "Persistent=true" in s.transport.files[
        "/etc/systemd/system/tessera-expiry.timer"]
    print("  table, dependency-free sh script and a persistent timer")


def test_permanent_peers_are_not_in_the_expiry_table():
    s = installed_session()
    s.add_peer("wireguard", "guest", expires="7d")
    s.add_peer("wireguard", "laptop")
    table = s.transport.files.get(expiry.TABLE, "")
    assert "guest" in table
    assert "laptop" not in table, "a permanent peer must never be scheduled"
    print("  only time-limited peers are scheduled")


def test_openvpn_certificate_lifetime_matches_the_grant():
    from tessera.core.engines import get
    from tessera.core.engines.base import EngineContext
    s = installed_session(engines=("openvpn",))
    ctx = EngineContext(transport=s.transport, facts=s.facts,
                        spec=s.spec_from_state(), state=s.state)
    plan, peer, _ = get("openvpn").plan_add_peer(
        ctx, "contractor", access_expires=expiry.parse_duration("30d"))
    signing = [st for st in plan.steps if "sign" in st.id][0]
    assert "EASYRSA_CERT_EXPIRE=30" in signing.command, signing.command
    print("  a 30-day grant issues a 30-day certificate")


def test_expiry_log_is_reconciled():
    s = installed_session()
    peer, _ = s.add_peer("wireguard", "contractor", expires="7d")
    s.transport.files[expiry.LOG] = "2026-09-30\twireguard\tcontractor\t2026-09-30\n"
    applied = s.reconcile_expiries()
    assert len(applied) == 1
    stored = [p for p in s.state.engine("wireguard").peers
              if p["name"] == "contractor"][0]
    assert stored["revoked"] is True
    assert "expired" in stored["note"]
    print("  server-side revocation folded back into the inventory")


# --------------------------------------------------------------------------- #
def test_backup_is_always_encrypted_and_tamper_evident():
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"PrivateKey = THE-CA-KEY"
        info = tarfile.TarInfo("/etc/wireguard/wg0.conf")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    payload = buf.getvalue()
    m = backup.Manifest(server="prod", engines=["wireguard"], peer_count=3)
    blob = backup.seal(payload, "hunter2hunter2", m)

    assert b"THE-CA-KEY" not in blob, "key material must not survive in cleartext"
    assert backup.peek(blob).peer_count == 3, "manifest readable without the key"

    out, _ = backup.unseal(blob, "hunter2hunter2")
    assert out == payload

    for mutate in (lambda b: b[:-1] + bytes([b[-1] ^ 1]),
                   lambda b: b[:len(backup.MAGIC) + 40] + b"x" + b[len(backup.MAGIC) + 41:]):
        try:
            backup.unseal(mutate(blob), "hunter2hunter2")
            raise AssertionError("tampering should be detected")
        except AssertionError:
            raise
        except Exception:
            pass
    try:
        backup.unseal(blob, "wrong")
        raise AssertionError("wrong passphrase should fail")
    except AssertionError:
        raise
    except Exception:
        pass
    print("  sealed, tamper-evident, manifest still legible")


def test_backup_captures_and_restores():
    s = installed_session()
    s.add_peer("wireguard", "laptop")
    import base64 as b64
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, body in s.transport.files.items():
            data = body.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    s.transport.responses[r"tar czf -"] = b64.b64encode(buf.getvalue()).decode()

    blob, manifest = s.backup("a good passphrase")
    assert manifest.engines == ["wireguard"]
    assert manifest.peer_count == 1
    payload, _ = backup.unseal(blob, "a good passphrase")
    assert "/etc/wireguard/wg0.conf" in backup.contents(payload)
    print("  captured {} · {}".format(manifest.summary(),
                                      len(backup.contents(payload))))


# --------------------------------------------------------------------------- #
def test_verify_is_clean_on_a_fresh_install():
    s = installed_session()
    s.add_peer("wireguard", "laptop")
    problems = [f for f in s.verify() if f.is_problem]
    assert not problems, [(f.level, f.title, f.detail) for f in problems]
    print("  no drift reported on an untouched server")


def test_verify_catches_a_hand_edited_peer():
    s = installed_session()
    s.add_peer("wireguard", "laptop")
    s.transport.files["/etc/wireguard/wg0.conf"] += (
        "\n### Client sneaky\n[Peer]\n"
        "PublicKey = SNEAKY000000000000000000000000000000000000=\n"
        "AllowedIPs = 10.66.66.99/32\n")
    problems = [f for f in s.verify() if f.is_problem]
    assert any("does not know about" in f.title for f in problems), problems
    assert s.fixable()["import"] == ["wireguard:sneaky"]
    assert s.apply_fix() == ["imported sneaky"]
    assert not [f for f in s.verify() if f.is_problem]
    print("  unknown peer detected, imported, drift cleared")


def test_verify_does_not_flag_the_server_certificate():
    """Was: the server's own cert was reported as an unknown client.

    index.txt contains the server certificate alongside the clients. verify
    parsed it without excluding the server's CN, so every real OpenVPN install
    reported a rogue certificate it had "never heard of" - the server itself.
    """
    from tessera.core import verify as verify_mod
    conf = ("port 1194\nproto udp\ncert tessera_abc123.crt\n"
            "key tessera_abc123.key\ncrl-verify crl.pem\n"
            "tls-crypt-v2 tls-crypt-v2.key\ncipher AES-256-GCM\n")
    index = ("V\t350101000000Z\t\t01\tunknown\t/CN=tessera_abc123\n"
             "V\t280101000000Z\t\t02\tunknown\t/CN=laptop\n")
    t = FakeTransport(files={
        "/etc/openvpn/server/server.conf": conf,
        "/etc/openvpn/server/easy-rsa/pki/index.txt": index})
    state = ServerState()
    from tessera.core.state import EngineRecord
    state.set_engine(EngineRecord(
        engine="openvpn",
        peers=[{"name": "laptop", "engine": "openvpn", "revoked": False}]))
    findings = verify_mod._check_openvpn(t, state)
    unknown = [f for f in findings if "does not list" in f.title]
    assert not unknown, [f.detail for f in unknown]

    # And a genuinely unknown client is still caught.
    t.files["/etc/openvpn/server/easy-rsa/pki/index.txt"] = index + (
        "V\t280101000000Z\t\t03\tunknown\t/CN=stranger\n")
    findings = verify_mod._check_openvpn(t, state)
    assert any("stranger" in (f.detail or "") for f in findings), findings
    print("  server cert ignored, real stranger still reported")


def test_verify_never_grants_access():
    """--fix edits the inventory only; it must never touch the server."""
    s = installed_session()
    s.add_peer("wireguard", "laptop")
    s.transport.files["/etc/wireguard/wg0.conf"] += (
        "\n### Client sneaky\n[Peer]\n"
        "PublicKey = SNEAKY000000000000000000000000000000000000=\n"
        "AllowedIPs = 10.66.66.99/32\n")
    before = dict(s.transport.files)
    s.apply_fix()
    changed = {k for k in before
               if k != "/etc/tessera/state.json"
               and before[k] != s.transport.files.get(k)}
    assert not changed, "fix must not modify server config: {}".format(changed)
    print("  repair touched only the inventory")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        print(fn.__name__)
        try:
            fn()
        except Exception:                                      # noqa: BLE001
            failed += 1
            import traceback
            traceback.print_exc()
    print("\n{}/{} passed".format(len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)
