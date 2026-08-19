"""Removal.

The uninstaller is the part of a tool like this that people discover last and
judge hardest, because they only reach for it when something has already gone
wrong.  So it gets the same care as the installer.

It works from the inventory (see state.py), which means:

  * It removes what *this* install created, not what the author guessed a
    typical install creates.
  * It never removes anything flagged ``pre_existing``.  If iptables was
    already on the box, or IP forwarding was already enabled, Tessera did not
    add it and does not get to take it away.
  * It runs in reverse order: services stop before their configuration is
    deleted, firewall rules come down before the script that removes them is
    itself removed.  Doing it forwards strands rules with nothing left to
    remove them.

Key material is shredded rather than unlinked, with an honest caveat about what
that does and does not achieve on modern storage - see ``keys.shred_command``.
"""

from __future__ import annotations

import shlex
from typing import List, Optional

from .engines import get as get_engine
from .engines.base import EngineContext, pkg_remove
from .errors import StateError
from .keys import shred_command
from .models import Facts
from .plan import Plan, Step, StepKind
from .state import STATE_DIR, STATE_PATH, Artifact, ServerState

#: Directories whose contents are key material, whatever the file is called.
SECRET_DIRS = ("/etc/wireguard", "/etc/openvpn", "/etc/tessera")
#: Filename patterns that are secret regardless of where they live.
SECRET_NAMES = (".key", ".req", ".pem", "state.json", "privkey", "authkey")


def is_secret(path: str) -> bool:
    """Should this file be overwritten before it is unlinked?

    Deliberately not "anything ending in .conf".  A WireGuard .conf holds
    private keys and must be shredded; /etc/sysctl.d/99-tessera.conf holds the
    number 1 and does not.  Shredding everything indiscriminately makes the
    uninstall slower and teaches people to ignore the warning it prints.
    """
    if any(path.startswith(d + "/") or path == d for d in SECRET_DIRS):
        return True
    return any(path.endswith(n) or n in path.rsplit("/", 1)[-1]
               for n in SECRET_NAMES)


def plan(ctx: EngineContext, engines: Optional[List[str]] = None,
         *, purge_packages: bool = True, keep_backups: bool = False,
         remove_hardening: bool = False) -> Plan:
    """Build the removal plan.

    ``engines`` defaults to everything the inventory knows about.  Removing one
    engine from a server that hosts two leaves the other alone.
    """
    state = ctx.state
    targets = engines if engines is not None else list(state.installed_engines)
    if not targets and not remove_hardening:
        raise StateError(
            "nothing to remove: this server has no Tessera-managed install",
            "If you installed a VPN by hand, Tessera cannot know what it "
            "touched and will not guess.")

    p = Plan("Remove {} from {}".format(
        ", ".join(targets) or "hardening", ctx.spec.target.display()))
    p.notes.append(
        "Only artefacts Tessera created are removed. Anything that already "
        "existed on this server before Tessera ran is left untouched.")

    # 1. Let each engine stop its own services and undo its own live state.
    for name in targets:
        engine = get_engine(name)
        try:
            sub = engine.plan_uninstall(ctx)
            p.extend(sub.steps)
        except NotImplementedError:
            pass

    # 2. Walk the inventory backwards.
    for name in targets:
        artifacts = list(reversed(state.removable(name)))
        p.extend(_artifact_steps(ctx.facts, artifacts, name, purge_packages))

    # 3. Global (non-engine) artefacts, e.g. hardening.
    if remove_hardening:
        globals_ = [a for a in state.artifacts
                    if not a.get("pre_existing")]
        arts = [Artifact(**{k: v for k, v in a.items()
                            if k in Artifact.__dataclass_fields__})
                for a in reversed(globals_)]
        p.extend(_artifact_steps(ctx.facts, arts, "", purge_packages))
        p.add(Step("un-sysctl-reload", "Reload kernel settings",
                   StepKind.CONFIG, command="sysctl --system >/dev/null 2>&1; true",
                   critical=False,
                   why="Drops the values we set without needing a reboot."))

    # 4. The inventory itself, once nothing else needs it.
    removing_everything = set(targets) >= set(state.installed_engines)
    if removing_everything:
        if not keep_backups:
            p.add(Step(
                "un-state", "Shred the Tessera inventory", StepKind.CLEANUP,
                command=(shred_command(STATE_PATH) + "; rm -rf {}/backups; "
                         "rmdir {} 2>/dev/null; true").format(
                             shlex.quote(STATE_DIR), shlex.quote(STATE_DIR)),
                critical=False,
                why="The inventory lists every peer public key and the "
                    "server's layout. With nothing left to manage it is "
                    "just a map of a network for whoever finds it."))
        else:
            p.add(Step(
                "un-state-keep", "Keep the inventory for reference",
                StepKind.CLEANUP,
                command="true", critical=False,
                why="Retained at {} because you asked to keep backups."
                    .format(STATE_PATH)))

    p.add(Step("un-verify", "Verify nothing is still listening",
               StepKind.CHECK,
               command=_verify_command(state, targets), critical=False,
               why="Confirms the ports really are closed, rather than "
                   "assuming the stop command worked."))
    return p


def _artifact_steps(f: Facts, artifacts: List[Artifact], engine: str,
                    purge_packages: bool) -> List[Step]:
    steps: List[Step] = []
    packages: List[str] = []

    for a in artifacts:
        sid = "un-{}-{}".format(a.kind, _slug(a.ref))
        if a.kind == "package":
            packages.append(a.ref)
        elif a.kind in ("file", "dir"):
            secret = is_secret(a.ref)
            if a.kind == "dir":
                cmd = ("find {p} -type f -exec sh -c "
                       "'command -v shred >/dev/null && shred -u -n1 \"$1\" "
                       "|| rm -f \"$1\"' _ {{}} \\; 2>/dev/null; "
                       "rm -rf {p}; true").format(p=shlex.quote(a.ref))
                why = ("Removed recursively, shredding each file first because "
                       "this directory held key material.")
            elif secret:
                cmd = shred_command(a.ref) + "; true"
                why = ("Overwritten before unlinking. Note that on SSDs and "
                       "copy-on-write filesystems the controller may keep the "
                       "original block; full-disk encryption is the only "
                       "real guarantee.")
            else:
                cmd = "rm -f {}; true".format(shlex.quote(a.ref))
                why = "Created by Tessera, so Tessera removes it."
            steps.append(Step(sid, "Remove {}".format(a.ref), StepKind.CLEANUP,
                              command=cmd, critical=False, why=why,
                              sensitive=secret))
        elif a.kind == "service":
            steps.append(Step(
                sid, "Disable {}".format(a.ref), StepKind.SERVICE,
                command=("systemctl disable --now {u} 2>/dev/null; "
                         "systemctl reset-failed {u} 2>/dev/null; true").format(
                             u=shlex.quote(a.ref))
                if f.init == "systemd" else
                ("rc-service {u} stop 2>/dev/null; rc-update del {u} "
                 "2>/dev/null; true").format(u=shlex.quote(a.ref)),
                critical=False))
        elif a.kind == "sysctl":
            steps.append(Step(
                sid, "Revert {}".format(a.ref), StepKind.CONFIG,
                command="sysctl -w {}=0 >/dev/null 2>&1; true".format(
                    shlex.quote(a.ref)),
                critical=False,
                why="This was off before Tessera enabled it, so it goes back "
                    "off. Had it already been on, it would not appear here."))
        elif a.kind == "firewall":
            proto, _, port = a.ref.partition("/")
            steps.append(Step(
                sid, "Close {}".format(a.ref), StepKind.FIREWALL,
                command=("iptables -D INPUT -p {pr} --dport {p} -j ACCEPT "
                         "2>/dev/null; ufw delete allow {p}/{pr} 2>/dev/null; "
                         "firewall-cmd --permanent --remove-port={p}/{pr} "
                         "2>/dev/null && firewall-cmd --reload 2>/dev/null; "
                         "true").format(pr=proto, p=port),
                critical=False))
        elif a.kind == "repo":
            continue  # the .list/.repo file is recorded separately as a file

    if packages and purge_packages:
        steps.append(Step(
            "un-packages-{}".format(engine or "global"),
            "Remove packages: {}".format(", ".join(packages)),
            StepKind.PACKAGE, command=pkg_remove(f, packages), critical=False,
            timeout=600,
            why="Only packages Tessera installed. Dependency auto-removal is "
                "explicitly disabled, so nothing else on this server breaks."))
    return steps


def _verify_command(state: ServerState, targets: List[str]) -> str:
    ports: List[str] = []
    for name in targets:
        rec = state.engine(name)
        if rec and rec.config.get("port"):
            ports.append(str(rec.config["port"]))
    if not ports:
        return "true"
    pattern = "|".join(":{}$".format(p) for p in ports)
    return ("! ( ss -tulnH 2>/dev/null | awk '{{print $5}}' "
            "| grep -qE '{}' )").format(pattern)


def _slug(ref: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in ref).strip("-")[:48]
