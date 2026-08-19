"""The interactive interview.

Walks the questions from ``core.interview`` and fills an InstallSpec.  It shows
each question's ``why`` before asking, because a person who understands the
consequence can answer a question they have never seen before - and that is the
entire difference between a tool people adopt and a tool people cargo-cult.
"""

from __future__ import annotations

from typing import List, Optional

from ..core import interview as iv
from ..core.errors import ValidationError
from ..core.models import Facts, InstallSpec
from .ui import UI


def choose_profile(ui: UI) -> str:
    ui.rule("How much do you want to be asked?")
    for meta in iv.PROFILES.values():
        ui.out("  {}  {}".format(meta["label"].ljust(9), meta["summary"]),
               "bold")
        ui.note("  " + meta["detail"])
        ui.out()
    return ui.choose("Profile", [(k, iv.PROFILES[k]["label"]) for k in iv.PROFILES],
                     default="balanced")


def run(ui: UI, spec: InstallSpec, facts: Facts, *,
        profile: str = "", advanced: Optional[bool] = None,
        accept_defaults: bool = False) -> InstallSpec:
    """Ask everything and return the completed spec."""
    if not profile:
        profile = choose_profile(ui)
    spec = iv.apply_profile(spec, profile, facts)

    if accept_defaults or profile == "quick":
        spec = iv.fill_defaults(spec, facts)
        if profile == "quick" and not accept_defaults:
            # Quick still asks the three things nobody can guess for you.
            spec = _ask_subset(ui, spec, facts,
                               ["engines", "first_peer",
                                "wireguard.endpoint", "openvpn.endpoint",
                                "tailscale.auth_key"])
            # Safe to re-run: fill_defaults never overwrites an answer.
            spec = iv.fill_defaults(spec, facts)
        return spec

    show_advanced = advanced if advanced is not None else (profile == "custom")

    # Ask in groups so the flow reads as sections, not one long list.
    asked_groups: List[str] = []
    index = 0
    while index < len(iv.QUESTIONS):
        q = iv.QUESTIONS[index]
        index += 1
        if not q.applies(spec, facts):
            continue
        if q.advanced and not show_advanced:
            continue
        if q.group and q.group not in asked_groups:
            asked_groups.append(q.group)
            ui.out()
            ui.rule(q.group)
        _ask_one(ui, spec, facts, q)
    return spec


def _ask_subset(ui: UI, spec: InstallSpec, facts: Facts,
                keys: List[str]) -> InstallSpec:
    for key in keys:
        q = next((x for x in iv.QUESTIONS if x.key == key), None)
        if q is None or not q.applies(spec, facts):
            continue
        _ask_one(ui, spec, facts, q)
    return spec


def _ask_one(ui: UI, spec: InstallSpec, facts: Facts, q) -> None:
    default = q.resolve_default(spec, facts)
    if q.why:
        ui.note(q.why)

    while True:
        try:
            if q.kind == "bool":
                value = ui.confirm("  " + q.prompt, bool(default))
            elif q.kind == "choice":
                value = ui.choose(q.prompt, q.choices, str(default))
            elif q.kind == "multi":
                value = ui.multichoose(q.prompt, q.choices, default or [])
            elif q.kind == "secret":
                value = ui.ask("  " + q.prompt, "", secret=True)
                if not value:
                    value = default or ""
            else:
                shown = default
                if isinstance(default, list):
                    shown = ", ".join(str(x) for x in default)
                value = ui.ask("  " + q.prompt, "" if shown is None else str(shown))

            warning = iv.answer(spec, facts, q.key, value)
            if warning:
                ui.warn("  " + warning)
            ui.out()
            return
        except ValidationError as exc:
            ui.fail("  " + (exc.message or str(exc)))
        except (KeyboardInterrupt, EOFError):
            raise


def review(ui: UI, spec: InstallSpec, facts: Facts) -> None:
    """Print the answers back before anything is executed."""
    ui.rule("Review")
    rows = [("Target", spec.target.display()),
            ("Server", facts.summary()),
            ("Install", ", ".join(spec.engines) or "nothing")]
    if "wireguard" in spec.engines:
        w = spec.wireguard
        rows += [("WireGuard", "{}:{} on {}".format(
            w.endpoint, w.port, w.interface)),
            ("  subnet", "{}{}".format(
                w.subnet_v4, " + " + w.subnet_v6 if w.enable_ipv6 else "")),
            ("  routes", "all traffic" if w.allowed_ips.startswith("0.0.0.0/0")
             else w.allowed_ips),
            ("  DNS", ", ".join(w.dns))]
    if "openvpn" in spec.engines:
        o = spec.openvpn
        rows += [("OpenVPN", "{}:{}/{}".format(o.endpoint, o.port, o.protocol)),
                 ("  crypto", "{} / {} {}".format(
                     o.cipher, o.cert_type.upper(),
                     o.cert_curve if o.cert_type == "ecdsa" else o.rsa_bits)),
                 ("  control", o.tls_sig)]
    if "tailscale" in spec.engines:
        t = spec.tailscale
        rows += [("Tailscale", t.login_server or "tailscale.com"),
                 ("  exit node", "yes" if t.advertise_exit_node else "no"),
                 ("  auth key", "supplied" if t.auth_key else "interactive")]
    h = spec.hardening
    enabled = [n for n, on in [
        ("kernel hardening", h.sysctl_hardening),
        ("block private nets", h.block_rfc1918_from_vpn),
        ("fail2ban", h.fail2ban),
        ("auto updates", h.unattended_upgrades),
        ("key-only SSH", h.disable_ssh_password_auth)] if on]
    rows.append(("Hardening", ", ".join(enabled) or "none"))
    if spec.first_peer:
        rows.append(("First device", spec.first_peer))
    ui.kv(rows)
    ui.out()
