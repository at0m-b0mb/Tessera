"""Server hardening applied alongside whichever engine you chose.

None of this is VPN-specific, and that is the point.  A freshly installed VPN
on an otherwise untouched VPS is a machine with one carefully secured door in a
wall that still has the windows open.  The most common way people lose a VPN
server is not a flaw in WireGuard; it is SSH password brute-force on the same
box, or a kernel that has not been patched since it was provisioned.

Everything here is optional, every item says what it actually does, and every
item is recorded in the inventory so the uninstaller can put it back.
"""

from __future__ import annotations

import shlex

from .plan import Plan, Step, StepKind
from .engines.base import (EngineContext, already_installed, pkg_install,
                           pkg_remove, svc_enable_start, svc_stop_disable)

SYSCTL_FILE = "/etc/sysctl.d/99-tessera-hardening.conf"

# Network stack settings that are safe on a router/VPN gateway.  Each one is
# here for a reason, not because it appeared on a checklist.
SYSCTL_HARDENING = [
    ("net.ipv4.conf.all.accept_redirects", "0",
     "Ignore ICMP redirects: on a gateway they are an invitation to reroute "
     "your clients' traffic through someone else."),
    ("net.ipv4.conf.all.send_redirects", "0",
     "Do not emit redirects either; a VPN gateway has no business telling "
     "hosts about better routes."),
    ("net.ipv4.conf.all.accept_source_route", "0",
     "Source routing lets a sender pick the return path, which is a clean way "
     "to bypass your firewall. It has no legitimate modern use."),
    ("net.ipv4.conf.all.rp_filter", "1",
     "Reverse-path filtering drops packets arriving on the wrong interface, "
     "which kills the easiest form of address spoofing."),
    ("net.ipv4.tcp_syncookies", "1",
     "Survive a SYN flood without dropping legitimate connections."),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1",
     "Stops the box being used as a smurf amplifier."),
    ("net.ipv6.conf.all.accept_redirects", "0",
     "The IPv6 half of the redirect rule above."),
    ("net.ipv6.conf.all.accept_ra", "0",
     "A gateway should not accept router advertisements from the network it "
     "is serving."),
    ("kernel.kptr_restrict", "2",
     "Hide kernel pointers from unprivileged processes, which removes an easy "
     "source of addresses for local exploits."),
]


def plan(ctx: EngineContext) -> Plan:
    """Build the hardening plan from the user's choices."""
    f = ctx.facts
    cfg = ctx.spec.hardening
    p = Plan("Harden {}".format(ctx.spec.target.display()))

    if cfg.sysctl_hardening:
        body = ["# Written by Tessera. Remove this file to revert every "
                "setting below.", ""]
        for key, value, why in SYSCTL_HARDENING:
            body += ["# {}".format(why), "{} = {}".format(key, value), ""]
        p.add(Step(
            "harden-sysctl", "Apply network stack hardening", StepKind.CONFIG,
            write=(SYSCTL_FILE, "\n".join(body), "0644"),
            undo="rm -f {}".format(shlex.quote(SYSCTL_FILE)),
            why="Nine kernel settings that matter specifically on a machine "
                "that forwards other people's packets."))
        p.add(Step("harden-sysctl-load", "Load the new settings",
                   StepKind.CONFIG,
                   command="sysctl --system >/dev/null 2>&1 || "
                           "sysctl -p {} >/dev/null".format(shlex.quote(SYSCTL_FILE)),
                   critical=False))
        ctx.note("file", SYSCTL_FILE, note="hardening sysctls")

    if cfg.fail2ban:
        existed = already_installed(ctx.transport, f, "fail2ban")
        ctx.note("package", "fail2ban", pre_existing=existed)
        p.add(Step("harden-f2b-install", "Install fail2ban", StepKind.PACKAGE,
                   command=pkg_install(f, ["fail2ban"]),
                   undo=pkg_remove(f, ["fail2ban"]) if not existed else "true",
                   critical=False, timeout=600,
                   why="Bans addresses that fail SSH authentication "
                       "repeatedly. Most VPS log noise is exactly this."))
        p.add(Step(
            "harden-f2b-jail", "Configure the sshd jail", StepKind.CONFIG,
            write=("/etc/fail2ban/jail.d/tessera-sshd.local",
                   _fail2ban_jail(), "0644"),
            undo="rm -f /etc/fail2ban/jail.d/tessera-sshd.local",
            critical=False,
            why="A dedicated drop-in, so your own fail2ban config is not "
                "touched and this file can simply be deleted to revert."))
        ctx.note("file", "/etc/fail2ban/jail.d/tessera-sshd.local")
        p.add(Step("harden-f2b-start", "Enable fail2ban", StepKind.SERVICE,
                   command=svc_enable_start(f, "fail2ban"),
                   undo=svc_stop_disable(f, "fail2ban"), critical=False))
        ctx.note("service", "fail2ban", pre_existing=existed)

    if cfg.unattended_upgrades:
        if f.family == "debian":
            existed = already_installed(ctx.transport, f, "unattended-upgrades")
            ctx.note("package", "unattended-upgrades", pre_existing=existed)
            p.add(Step("harden-uu-install", "Install unattended-upgrades",
                       StepKind.PACKAGE,
                       command=pkg_install(f, ["unattended-upgrades"]),
                       undo=pkg_remove(f, ["unattended-upgrades"]) if not existed else "true",
                       critical=False, timeout=600))
            p.add(Step(
                "harden-uu-conf", "Enable automatic security updates",
                StepKind.CONFIG,
                write=("/etc/apt/apt.conf.d/51tessera-unattended",
                       _unattended_conf(), "0644"),
                undo="rm -f /etc/apt/apt.conf.d/51tessera-unattended",
                critical=False,
                why="Security updates only, applied nightly. A VPN server you "
                    "log into twice a year is otherwise a year behind."))
            ctx.note("file", "/etc/apt/apt.conf.d/51tessera-unattended")
        elif f.family == "rhel":
            existed = already_installed(ctx.transport, f, "dnf-automatic")
            ctx.note("package", "dnf-automatic", pre_existing=existed)
            p.add(Step("harden-dnfauto", "Install dnf-automatic",
                       StepKind.PACKAGE, command=pkg_install(f, ["dnf-automatic"]),
                       critical=False, timeout=600))
            p.add(Step("harden-dnfauto-start", "Enable nightly security updates",
                       StepKind.SERVICE,
                       command=svc_enable_start(f, "dnf-automatic.timer"),
                       undo=svc_stop_disable(f, "dnf-automatic.timer"),
                       critical=False))
            ctx.note("service", "dnf-automatic.timer", pre_existing=existed)

    if cfg.disable_ssh_password_auth:
        p.add(Step(
            "harden-ssh-check", "Confirm a working SSH key is in place",
            StepKind.CHECK,
            command=("test -s ~/.ssh/authorized_keys || "
                     "test -s /root/.ssh/authorized_keys"),
            why="Refuses to disable password login unless a key is already "
                "present. Getting this wrong locks you out of your own "
                "server permanently."))
        p.add(Step(
            "harden-ssh", "Disable SSH password authentication", StepKind.CONFIG,
            write=("/etc/ssh/sshd_config.d/99-tessera.conf",
                   _sshd_conf(), "0644"),
            undo="rm -f /etc/ssh/sshd_config.d/99-tessera.conf",
            why="Keys only. This is the single change that removes the entire "
                "SSH brute-force category."))
        ctx.note("file", "/etc/ssh/sshd_config.d/99-tessera.conf")
        p.add(Step(
            "harden-ssh-validate", "Validate the SSH config before reloading",
            StepKind.CHECK, command="sshd -t",
            why="A syntax error here would take sshd down on reload and lock "
                "you out. We check first, and abort if it does not parse."))
        p.add(Step("harden-ssh-reload", "Reload sshd", StepKind.SERVICE,
                   command="systemctl reload sshd 2>/dev/null || "
                           "systemctl reload ssh 2>/dev/null || true",
                   critical=False))
        p.notes.append(
            "SSH password login is now disabled. Keep your current session "
            "open and confirm you can open a second one before logging out.")

    return p


def _fail2ban_jail() -> str:
    return ("# Written by Tessera. Delete this file to revert.\n"
            "[sshd]\n"
            "enabled  = true\n"
            "port     = ssh\n"
            "backend  = systemd\n"
            "maxretry = 5\n"
            "findtime = 10m\n"
            "bantime  = 1h\n"
            "# Repeat offenders get progressively longer bans.\n"
            "bantime.increment = true\n"
            "bantime.factor    = 2\n"
            "bantime.maxtime   = 7d\n")


def _unattended_conf() -> str:
    return ('// Written by Tessera. Delete this file to revert.\n'
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n'
            'APT::Periodic::AutocleanInterval "7";\n'
            '// Security updates only: feature updates can change behaviour\n'
            '// on a box you are not watching.\n'
            'Unattended-Upgrade::Allowed-Origins {\n'
            '    "${distro_id}:${distro_codename}-security";\n'
            '    "${distro_id}ESMApps:${distro_codename}-apps-security";\n'
            '    "${distro_id}ESM:${distro_codename}-infra-security";\n'
            '};\n'
            '// Reboot only if a package demands it, and at a quiet hour.\n'
            'Unattended-Upgrade::Automatic-Reboot "false";\n')


def _sshd_conf() -> str:
    return ("# Written by Tessera. Delete this file and reload sshd to revert.\n"
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "ChallengeResponseAuthentication no\n"
            "PermitRootLogin prohibit-password\n"
            "PubkeyAuthentication yes\n"
            "MaxAuthTries 3\n")
