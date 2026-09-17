"""Adopting a server that angristan's installer built."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake import FakeTransport, demo_facts

from tessera.core.manager import Session
from tessera.core.models import Target
from tessera.core.state import ServerState

WG_CONF = """[Interface]
Address = 10.66.66.1/24,fd42:42:42::1/64
ListenPort = 51820
PrivateKey = aFakeServerPrivateKeyValueGoesRightHere1234=
PostUp = iptables -I INPUT -p udp --dport 51820 -j ACCEPT

### Client laptop
[Peer]
PublicKey = cJfKmZ2XxNVQ8sB1oYtE7pR4wLuGh9DkS0aXcVbNmQ0=
PresharedKey = 3CtnCBvtD1vvL4MnW948yxWKvvki+nKC/gIKzwyOzjI=
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128

### Client phone
[Peer]
PublicKey = zQW1SMcHak5byvc0tq0k52+A6CdV9Y1i3z9VyL1wDCI=
AllowedIPs = 10.66.66.3/32

[Peer]
PublicKey = dD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5cD6e=
AllowedIPs = 10.66.66.4/32
"""

PARAMS = """SERVER_PUB_IP=203.0.113.9
SERVER_PUB_NIC=eth0
SERVER_WG_NIC=wg0
SERVER_PORT=51820
CLIENT_DNS_1=1.1.1.1
CLIENT_DNS_2=1.0.0.1
ALLOWED_IPS=0.0.0.0/0,::/0
"""


def angristan_server():
    t = FakeTransport(
        responses={
            r"ls -1 /etc/wireguard/\*\.conf": "/etc/wireguard/wg0.conf\n",
            r"cat /etc/wireguard/wg0.conf": WG_CONF,
            r"cat /etc/wireguard/params": PARAMS,
            r"wg pubkey": "hK3vN9pQwXcR2mT7yB4jL8sF1dG6aZ0eV5nU3iO2kP4=",
        },
        files={"/etc/wireguard/params": PARAMS,
               "/etc/wireguard/wg0.conf": WG_CONF})
    # No tailscale binary on this box.
    t.which = lambda b: None if b == "tailscale" else "/usr/bin/" + b
    return Session(t, demo_facts(), ServerState(), Target(host="vpn.example.com"))


def test_discovers_an_existing_wireguard():
    s = angristan_server()
    found = s.discover()
    assert "wireguard" in found, found
    wg = found["wireguard"]
    assert wg["interface"] == "wg0"
    assert wg["port"] == 51820
    assert len(wg["peers"]) == 3
    assert wg["managed_by"] == "angristan/wireguard-install"
    assert wg["endpoint"] == "203.0.113.9", "should read the params sidecar"
    assert wg["dns"] == ["1.1.1.1", "1.0.0.1"]
    print("  discovered:", wg["interface"], wg["port"],
          "{} peers".format(len(wg["peers"])), "via", wg["managed_by"])


def test_adopt_builds_a_usable_inventory():
    s = angristan_server()
    engines, warnings = s.adopt()
    assert engines == ["wireguard"]
    rec = s.state.engine("wireguard")
    assert rec.config["subnet_v4"] == "10.66.66.0/24"
    assert rec.config["subnet_v6"] == "fd42:42:42::/64"
    assert rec.config["endpoint"] == "203.0.113.9"
    assert rec.config["server_public_key"].endswith("=")
    names = [p["name"] for p in rec.peers]
    assert names == ["laptop", "phone", "peer-3"], names
    addrs = [p["address_v4"] for p in rec.peers]
    assert addrs == ["10.66.66.2", "10.66.66.3", "10.66.66.4"], addrs
    assert any("no name comment" in w for w in warnings), warnings
    print("  adopted peers:", names)
    print("  warning:", [w for w in warnings if "no name" in w][0][:70] + "...")


def test_adopted_peer_gets_the_next_free_address():
    """The whole point: managing the server must work after adoption."""
    s = angristan_server()
    s.adopt()
    s.transport.files["/etc/wireguard/wg0.conf"] = WG_CONF
    peer, config = s.add_peer("wireguard", "newphone")
    assert peer.address_v4 == "10.66.66.5", peer.address_v4
    assert "hK3vN9pQ" in config, "client config must carry the server pubkey"
    assert peer.private_key in config
    assert peer.private_key not in s.transport.all_text(), "KEY LEAKED"
    # The existing peers survived the rewrite.
    conf = s.transport.files["/etc/wireguard/wg0.conf"]
    assert conf.count("[Peer]") == 4, conf.count("[Peer]")
    assert "cJfKmZ2XxNVQ8sB1oYtE7pR4wLuGh9DkS0aXcVbNmQ0=" in conf
    print("  new peer got", peer.address_v4, "- existing 3 peers preserved")


def test_uninstall_after_adopt_spares_shared_packages():
    s = angristan_server()
    s.adopt()
    plan = s.build_uninstall_plan()
    text = plan.describe()
    assert "/etc/wireguard/wg0.conf" in text, "the VPN config must be removable"
    pkg_lines = [l for l in text.splitlines() if "Remove packages" in l]
    assert not pkg_lines, "adopted packages must never be removed: {}".format(pkg_lines)
    removable = {a.ref for a in s.state.removable("wireguard")}
    assert "wireguard-tools" not in removable
    assert "/etc/wireguard/wg0.conf" in removable
    print("  uninstall removes the config, spares the packages")


def test_adopting_twice_is_safe():
    s = angristan_server()
    s.adopt()
    before = len(s.state.engine("wireguard").peers)
    try:
        s.adopt()
        raise AssertionError("second adopt should refuse")
    except Exception as exc:
        assert "already manages" in str(exc) or "nothing to adopt" in str(exc), exc
    assert len(s.state.engine("wireguard").peers) == before
    print("  second adopt refused, inventory intact")


def test_openvpn_adoption_flags_compression():
    conf = ("port 1194\nproto udp\ndev tun\nserver 10.8.0.0 255.255.255.0\n"
            "cipher AES-256-CBC\ncomp-lzo yes\ncert server_xyz.crt\n"
            "tls-crypt tls-crypt.key\n")
    index = ("V\t350101000000Z\t\t01\tunknown\t/CN=server_xyz\n"
             "V\t270415000000Z\t\t02\tunknown\t/CN=alice\n"
             "R\t270415000000Z\t260601000000Z\t03\tunknown\t/CN=bob\n")
    t = FakeTransport(
        responses={r"cat /etc/openvpn/server/server\.conf": conf,
                   r"cat /etc/openvpn/server/easy-rsa/pki/index\.txt": index},
        files={"/etc/openvpn/server/server.conf": conf,
               "/etc/openvpn/server/easy-rsa/pki/index.txt": index})
    t.which = lambda b: None if b == "tailscale" else "/usr/bin/" + b
    s = Session(t, demo_facts(), ServerState(), Target(host="x"))
    engines, warnings = s.adopt()
    assert engines == ["openvpn"]
    rec = s.state.engine("openvpn")
    assert [p["name"] for p in rec.peers] == ["alice", "bob"]
    assert rec.peers[1]["revoked"] is True
    assert any("VORACLE" in w for w in warnings), warnings
    assert any("crl-verify" in w for w in warnings), warnings
    print("  openvpn: 2 certs (1 revoked), flagged compression + missing CRL")


def test_adopt_works_against_the_simulated_server():
    """The demo must be able to demonstrate the headline feature.

    adopt discovers an install with `ls -1 /etc/wireguard/*.conf`. The
    simulator did not answer globs, so `tessera adopt demo` reported that
    nothing was there and anyone evaluating the feature concluded it did not
    work.
    """
    import tempfile

    os.environ["TESSERA_CONFIG_DIR"] = tempfile.mkdtemp(prefix="tessera-demo-")
    from tessera.core import demo
    from tessera.core import interview as iv
    from tessera.core.models import InstallSpec

    demo.reset()
    session = Session.connect(Target(host="demo"))
    spec = iv.prepare(InstallSpec(), session.facts,
                      engines=["wireguard"], first_peer="laptop")
    report, _ = session.install(spec)
    assert report.succeeded

    # A server that has a VPN but no Tessera inventory: exactly what someone
    # arriving from another installer has.
    session.transport.files.pop("/etc/tessera/state.json", None)
    session.transport._save()   # persist, or the next connect reloads it
    fresh = Session.connect(Target(host="demo"))
    assert fresh.state.installed_engines == []

    found = fresh.discover()
    assert "wireguard" in found, found
    engines, _ = fresh.adopt(found)
    assert engines == ["wireguard"]
    assert len(fresh.list_peers("wireguard")) == 1

    peer, _ = fresh.add_peer("wireguard", "after-adoption")
    assert peer.address_v4
    print("  demo: installed, inventory dropped, adopted back, peer added")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        print(fn.__name__)
        try:
            fn()
        except Exception:                                      # noqa: BLE001
            failed += 1
            import traceback; traceback.print_exc()
    print("\n{}/{} passed".format(len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)
