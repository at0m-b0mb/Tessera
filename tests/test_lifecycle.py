"""End-to-end: install, add peers, audit, revoke, uninstall.

Runs entirely against FakeTransport, so it exercises real plan construction,
real config rendering and the real inventory without needing a server.
"""

from __future__ import annotations

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake import FakeTransport, demo_facts

from tessera.core import interview as iv
from tessera.core.manager import Session
from tessera.core.models import InstallSpec, Target
from tessera.core.state import ServerState

SERVER_PUB = "cJfKmZ2XxNVQ8sB1oYtE7pR4wLuGh9DkS0aXcVbNmQ0="


def make_session(**facts_over):
    t = FakeTransport(responses={r"wg pubkey": SERVER_PUB,
                                 r"wg --version": "wireguard-tools v1.0.20210914"})
    return Session(t, demo_facts(**facts_over), ServerState(), Target())


def test_install_wireguard_end_to_end():
    s = make_session()
    spec = iv.fill_defaults(
        iv.apply_profile(InstallSpec(target=s.target), "balanced", s.facts),
        s.facts)
    spec.engines = ["wireguard"]
    spec.first_peer = "laptop"
    spec = iv.fill_defaults(spec, s.facts)

    report, configs = s.install(spec)
    assert report.succeeded, report.failed_step
    assert "wireguard" in s.state.installed_engines
    assert s.state.engine("wireguard").config["server_public_key"] == SERVER_PUB

    key = "wireguard:laptop"
    assert key in configs, list(configs)
    conf = configs[key]
    assert "[Interface]" in conf and "[Peer]" in conf
    assert SERVER_PUB in conf
    assert "PersistentKeepalive" in conf
    print("  install ok:", len(report.plan.steps), "steps,",
          len(s.state.all_artifacts()), "artifacts recorded")


def test_private_key_never_reaches_server():
    s = make_session()
    spec = iv.fill_defaults(InstallSpec(), s.facts)
    spec.engines = ["wireguard"]
    spec.first_peer = ""
    s.install(spec)

    peer, conf = s.add_peer("wireguard", "phone")
    everything_sent = s.transport.all_text() + "\n" + "\n".join(
        c for _, c, _ in s.transport.writes)
    assert peer.private_key, "peer should have a private key"
    assert peer.private_key not in everything_sent, "PRIVATE KEY LEAKED"
    assert peer.private_key in conf, "client config must contain its own key"
    assert peer.public_key in s.transport.files["/etc/wireguard/wg0.conf"]

    # ...and it is not written into the inventory either.
    stored = [p for p in s.state.engine("wireguard").peers if p["name"] == "phone"][0]
    assert stored["private_key"] == "", "inventory must not store private keys"
    print("  key isolation ok: private key absent from server and inventory")


def test_peer_addressing_and_revocation():
    s = make_session()
    spec = iv.fill_defaults(InstallSpec(), s.facts)
    spec.engines = ["wireguard"]; spec.first_peer = ""
    s.install(spec)

    names = ["laptop", "phone", "tablet", "desktop"]
    for n in names:
        s.add_peer("wireguard", n)
    peers = s.list_peers("wireguard")
    assert len(peers) == 4
    v4 = [p.address_v4 for p in peers]
    assert len(set(v4)) == 4, "addresses must be unique: {}".format(v4)

    s.remove_peer("wireguard", "phone")
    assert [p.name for p in s.list_peers("wireguard")] == ["laptop", "tablet", "desktop"]
    conf = s.transport.files["/etc/wireguard/wg0.conf"]
    assert "tessera:peer phone" not in conf
    assert conf.count("[Peer]") == 3

    # The freed address is reused rather than leaked.
    p, _ = s.add_peer("wireguard", "phone2")
    assert p.address_v4 == "10.66.66.3" or p.address_v4 in v4, p.address_v4
    print("  addressing ok:", v4, "-> reuse", p.address_v4)


def test_uninstall_preserves_pre_existing():
    s = make_session()
    spec = iv.fill_defaults(InstallSpec(), s.facts)
    spec.engines = ["wireguard"]; spec.first_peer = ""
    s.install(spec)

    # Mark iptables as something that was already on the box.
    for name in list(s.state.engines):
        for a in s.state.engines[name]["artifacts"]:
            if a["ref"] == "iptables":
                a["pre_existing"] = True

    plan = s.build_uninstall_plan()
    text = plan.describe()
    assert "iptables" not in text.split("Remove packages:")[-1].split("\n")[0], \
        "pre-existing iptables must not be removed"
    assert "wireguard" in text
    assert "shred" in text, "key material must be shredded"
    report = s.uninstall()
    assert report.succeeded
    assert s.state.installed_engines == []
    print("  uninstall ok:", len(plan.steps), "steps, iptables preserved")


def test_preflight_blocks_port_conflict():
    s = make_session()
    s.transport.responses[r"ss -tulnH"] = "51820\n1194\n"
    spec = iv.fill_defaults(InstallSpec(), s.facts)
    spec.engines = ["wireguard"]
    spec.wireguard.port = 51820
    issues = s.preflight(spec)
    blockers = Session.blocking(issues)
    assert blockers, "should block on a port already in use"
    print("  preflight ok:", blockers[0][2][:60])


def test_preflight_blocks_unsupported():
    s = make_session(virt="openvz")
    spec = iv.fill_defaults(InstallSpec(), s.facts)
    spec.engines = ["wireguard"]
    assert Session.blocking(s.preflight(spec)), "OpenVZ must be blocked"
    print("  preflight ok: OpenVZ rejected")


def test_dry_run_changes_nothing():
    s = make_session()
    spec = iv.fill_defaults(InstallSpec(), s.facts)
    spec.engines = ["wireguard"]; spec.first_peer = "laptop"
    report, configs = s.install(spec, dry_run=True)
    assert report.succeeded
    assert s.state.installed_engines == [], "dry run must not touch the inventory"
    assert s.transport.writes == [], "dry run must not write files"
    assert configs == {}
    print("  dry run ok: no writes, no inventory change")


def test_openvpn_uses_local_csr():
    s = make_session()
    s.transport.files["/etc/openvpn/server/easy-rsa/pki/issued/laptop.crt"] = ""
    spec = iv.fill_defaults(InstallSpec(), s.facts)
    spec.engines = ["openvpn"]; spec.first_peer = ""
    report, _ = s.install(spec)
    assert report.succeeded, report.failed_step and report.failed_step.error

    ctx_plan, peer, _ = __import__(
        "tessera.core.engines", fromlist=["get"]).get("openvpn").plan_add_peer(
        __import__("tessera.core.engines.base", fromlist=["EngineContext"])
        .EngineContext(transport=s.transport, facts=s.facts, spec=spec,
                       state=s.state), "laptop")
    uploaded = [c for p, c, _ in s.transport.writes if "PRIVATE KEY" in c]
    csr_steps = [st for st in ctx_plan.steps if st.write]
    assert csr_steps, "a CSR should be uploaded"
    assert "CERTIFICATE REQUEST" in csr_steps[0].write[1]
    assert "PRIVATE KEY" not in csr_steps[0].write[1], "PRIVATE KEY IN CSR UPLOAD"
    assert not uploaded, "no private key should ever be written to the server"
    print("  openvpn ok: CSR uploaded, private key stayed local")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        try:
            print("{}".format(fn.__name__))
            fn()
        except AssertionError as exc:
            failed += 1
            print("  FAIL:", exc)
        except Exception:                                      # noqa: BLE001
            failed += 1
            traceback.print_exc()
    print("\n{}/{} passed".format(len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)
