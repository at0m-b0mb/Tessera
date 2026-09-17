"""Access that ends by itself.

The most common real request a VPN operator gets is "can you let this person
in for a couple of weeks". The most common way that goes wrong is that nobody
remembers to take them out again, and a contractor who left in March still has
a working key in November.

So expiry has to hold **even if Tessera is never run again**. A reminder in the
operator's calendar is not an access control. That rules out enforcing this
from the client side, and it means the server needs something small and
self-contained that keeps working on its own.

Two mechanisms, picked per engine for what each can actually do:

**OpenVPN expires by itself.** A certificate has a validity period, so a
14-day guest gets a 14-day certificate. When it lapses the server rejects the
handshake with no help from anything. Tessera *also* revokes it on schedule, so
the CRL and reality agree, but the cryptography is the real enforcement.

**WireGuard has no concept of expiry**, so it gets a daily systemd timer (or
cron, on OpenRC boxes) running a small shell script that removes expired peers
from the live interface and from the config. That script is plain POSIX sh with
no dependency on Tessera, Python, or network access. Read it - it is short.

The script does the security-critical part only: cut off access. Bookkeeping -
updating the inventory - is left to Tessera, which reconciles from the log the
script writes the next time you connect. Shell is a bad place to do JSON
surgery, and a bookkeeping bug that stops the revocation running would be much
worse than an inventory that is briefly out of date.
"""

from __future__ import annotations

import re
import shlex
from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional

from .errors import ValidationError
from .models import Peer
from .plan import Plan, Step, StepKind

TABLE = "/etc/tessera/expiry.tsv"
SCRIPT = "/etc/tessera/expire.sh"
LOG = "/etc/tessera/expired.log"
UNIT = "tessera-expiry"

_DURATION = re.compile(r"^\s*(\d+)\s*([hdwmy])\s*$", re.I)
_MULTIPLIER = {"h": 1.0 / 24.0, "d": 1.0, "w": 7.0, "m": 30.0, "y": 365.0}


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_duration(value: str, *, now: Optional[date] = None) -> str:
    """Turn ``14d`` or ``2026-12-31`` into an ISO date.

    Accepts h/d/w/m/y, where a month is 30 days and a year 365 - stated here
    rather than hidden, because "3m" meaning "90 days" is the kind of thing
    that should not be a surprise when someone loses access on the wrong
    Tuesday.
    """
    raw = (value or "").strip()
    if not raw:
        raise ValidationError("an expiry is required")
    today = now or datetime.now(timezone.utc).date()

    m = _DURATION.match(raw)
    if m:
        amount, unit = int(m.group(1)), m.group(2).lower()
        if amount <= 0:
            raise ValidationError("an expiry must be in the future",
                                  "'{}' is zero or negative.".format(raw))
        days = amount * _MULTIPLIER[unit]
        if days < 1:
            # Sub-day expiry cannot be honoured: the timer runs daily.
            raise ValidationError(
                "the shortest expiry Tessera can enforce is one day",
                "The revocation timer runs once a day, so '{}' would not be "
                "enforced on time. For shorter access, remove the peer by "
                "hand with 'tessera peer remove'.".format(raw))
        return (today + timedelta(days=int(round(days)))).isoformat()

    try:
        parsed = datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        raise ValidationError(
            "'{}' is not a duration or a date".format(raw),
            "Use 14d, 2w, 6m, or an exact date like 2026-12-31.")
    if parsed <= today:
        raise ValidationError(
            "{} is not in the future".format(parsed.isoformat()))
    return parsed.isoformat()


def days_left(iso_date: str, *, now: Optional[date] = None) -> Optional[int]:
    if not iso_date:
        return None
    try:
        target = datetime.strptime(iso_date, "%Y-%m-%d").date()
    except ValueError:
        return None
    today = now or datetime.now(timezone.utc).date()
    return (target - today).days


def describe(iso_date: str, *, now: Optional[date] = None) -> str:
    left = days_left(iso_date, now=now)
    if left is None:
        return ""
    if left < 0:
        return "expired {} day{} ago".format(-left, "" if left == -1 else "s")
    if left == 0:
        return "expires today"
    if left == 1:
        return "expires tomorrow"
    return "expires in {} days".format(left)


def cert_days(iso_date: str, *, now: Optional[date] = None) -> int:
    """Certificate lifetime for an OpenVPN peer that expires on this date."""
    left = days_left(iso_date, now=now)
    return max(1, left if left is not None else 1)


# --------------------------------------------------------------------------- #
# The table
# --------------------------------------------------------------------------- #
def render_table(peers: List[Peer]) -> str:
    """Tab-separated, one row per expiring peer. Read by the shell script.

    Deliberately not JSON: the script has to parse this with ``while read`` on
    a box where we cannot assume jq or python exist.
    """
    lines = [
        "# Written by Tessera. One row per peer with an expiry date.",
        "# engine\tname\tinterface_or_blank\tpublic_key_or_blank\texpires",
        "# Removing a row here stops that peer being revoked automatically.",
    ]
    for p in peers:
        if not p.access_expires or p.revoked:
            continue
        fields = [p.engine, p.name, p.interface or "",
                  p.public_key or "", p.access_expires]
        # The script parses this with `while IFS=tab read`. A field containing
        # a tab or newline would shift every column after it, and the row that
        # revokes someone's access is the last place to discover that.
        if any(("\t" in f or "\n" in f) for f in fields):
            continue
        lines.append("\t".join(fields))
    return "\n".join(lines) + "\n"


def render_script(wg_conf_template: str = "/etc/wireguard/%s.conf") -> str:
    """The revoker. POSIX sh, no dependencies, safe to run twice."""
    return r"""#!/bin/sh
# Written by Tessera. Revokes VPN peers whose access has expired.
#
# Runs daily from a systemd timer (or cron). It is deliberately small and has
# no dependency on Tessera, Python or the network: access must end on time even
# if the machine that created these peers is never used again.
#
# It does the security-critical part only - cutting off access - and appends to
# a log that Tessera reconciles into its inventory later. Doing JSON surgery in
# shell would risk a bookkeeping bug stopping the revocation itself, which is a
# far worse failure than an inventory that is briefly stale.
set -u

TABLE=/etc/tessera/expiry.tsv
LOG=/etc/tessera/expired.log
TODAY=$(date -u +%Y-%m-%d)

[ -r "$TABLE" ] || exit 0

# Numeric compare on YYYYMMDD so we never depend on `date -d`, which busybox
# does not support the same way as coreutils.
as_num() { echo "$1" | tr -d '-'; }
TODAY_N=$(as_num "$TODAY")

changed_ifaces=""

while IFS=$(printf '\t') read -r engine name iface pubkey expires; do
    case "$engine" in ''|'#'*) continue ;; esac
    [ -n "${expires:-}" ] || continue
    exp_n=$(as_num "$expires")
    [ "$exp_n" -le "$TODAY_N" ] 2>/dev/null || continue

    case "$engine" in
    wireguard)
        [ -n "$iface" ] || iface=wg0
        conf="/etc/wireguard/${iface}.conf"
        if [ -n "$pubkey" ]; then
            # Cut the live session first. Rewriting the file alone would leave
            # an already-connected device running until the next restart.
            wg set "$iface" peer "$pubkey" remove 2>/dev/null
        fi
        if [ -f "$conf" ] && [ -n "$name" ]; then
            tmp=$(mktemp "${conf}.tessera.XXXXXX") || continue
            chmod 600 "$tmp"
            # Drop the peer block: from its name comment up to the blank
            # line that ends it. Matches both Tessera's marker and the
            # "### Client foo" one angristan's installer writes, since an
            # adopted server has the latter.
            awk -v target="$name" '
                /^###[ \t]*(tessera:peer|Client)[ \t]/ {
                    if ($3 == target) { skip = 1; next } else { skip = 0 }
                }
                skip && /^[ \t]*$/ { skip = 0; next }
                skip { next }
                { print }
            ' "$conf" > "$tmp" && mv -f "$tmp" "$conf" && chmod 600 "$conf"
            rm -f "$tmp" 2>/dev/null
        fi
        changed_ifaces="$changed_ifaces $iface"
        ;;
    openvpn)
        d=/etc/openvpn/server/easy-rsa
        if [ -x "$d/easyrsa" ] && [ -n "$name" ]; then
            ( cd "$d" && ./easyrsa --batch revoke "$name" >/dev/null 2>&1 \
              && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl >/dev/null 2>&1 \
              && cp pki/crl.pem /etc/openvpn/server/crl.pem \
              && chmod 644 /etc/openvpn/server/crl.pem )
            systemctl reload openvpn-server@server 2>/dev/null \
              || systemctl restart openvpn-server@server 2>/dev/null
        fi
        ;;
    esac

    printf '%s\t%s\t%s\t%s\n' "$TODAY" "$engine" "$name" "$expires" >> "$LOG"
    logger -t tessera "revoked expired peer $name ($engine)" 2>/dev/null
done < "$TABLE"

# Reload each touched interface once, not once per peer.
for i in $changed_ifaces; do
    wg syncconf "$i" /dev/null 2>/dev/null
    if command -v wg-quick >/dev/null 2>&1; then
        wg syncconf "$i" "$(wg-quick strip "$i" 2>/dev/null)" 2>/dev/null \
          || wg-quick strip "$i" 2>/dev/null | wg syncconf "$i" /dev/stdin 2>/dev/null
    fi
done

# Drop revoked rows so the table stays a list of live grants.
if [ -s "$TABLE" ]; then
    tmp=$(mktemp /etc/tessera/expiry.XXXXXX) || exit 0
    chmod 600 "$tmp"
    while IFS=$(printf '\t') read -r engine name iface pubkey expires; do
        case "$engine" in
            '#'*) printf '%s\n' "$engine" >> "$tmp"; continue ;;
            '') continue ;;
        esac
        [ -n "${expires:-}" ] || continue
        if [ "$(as_num "$expires")" -gt "$TODAY_N" ] 2>/dev/null; then
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$engine" "$name" "$iface" "$pubkey" "$expires" >> "$tmp"
        fi
    done < "$TABLE"
    mv -f "$tmp" "$TABLE" && chmod 600 "$TABLE"
fi

exit 0
"""


def render_unit() -> str:
    return ("[Unit]\n"
            "Description=Tessera - revoke expired VPN peers\n"
            "Documentation=https://github.com/at0m-b0mb/Tessera\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart={}\n".format(SCRIPT))


def render_timer() -> str:
    return ("[Unit]\n"
            "Description=Tessera - daily check for expired VPN peers\n\n"
            "[Timer]\n"
            "OnCalendar=daily\n"
            "# Catch up after downtime: a server that was off over the weekend\n"
            "# must still revoke on the Monday, not wait for the next window.\n"
            "Persistent=true\n"
            "RandomizedDelaySec=15m\n\n"
            "[Install]\n"
            "WantedBy=timers.target\n")


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #
def plan_install(peers: List[Peer], init: str) -> Plan:
    """Install or refresh the expiry machinery."""
    p = Plan("Schedule automatic revocation")
    p.add(Step("exp-dir", "Create /etc/tessera", StepKind.CONFIG,
               command="mkdir -p /etc/tessera && chmod 700 /etc/tessera",
               why="Holds the expiry table, which lists who has access."))
    p.add(Step("exp-script", "Write the revocation script", StepKind.CONFIG,
               write=(SCRIPT, render_script(), "0700"),
               undo="rm -f {}".format(shlex.quote(SCRIPT)),
               why="Plain POSIX sh with no dependencies, so access still ends "
                   "on time if this machine is never used again."))
    p.add(Step("exp-table", "Write the expiry table", StepKind.CONFIG,
               write=(TABLE, render_table(peers), "0600"),
               undo="rm -f {}".format(shlex.quote(TABLE)),
               why="One row per grant. Delete a row to cancel that expiry."))

    if init == "systemd":
        p.add(Step("exp-unit", "Install the systemd unit", StepKind.SERVICE,
                   write=("/etc/systemd/system/{}.service".format(UNIT),
                          render_unit(), "0644"),
                   undo="rm -f /etc/systemd/system/{}.service".format(UNIT)))
        p.add(Step("exp-timer", "Install the daily timer", StepKind.SERVICE,
                   write=("/etc/systemd/system/{}.timer".format(UNIT),
                          render_timer(), "0644"),
                   undo="rm -f /etc/systemd/system/{}.timer".format(UNIT)))
        p.add(Step("exp-enable", "Enable the timer", StepKind.SERVICE,
                   command=("systemctl daemon-reload && "
                            "systemctl enable --now {}.timer".format(UNIT)),
                   undo="systemctl disable --now {}.timer 2>/dev/null; true".format(UNIT),
                   why="Persistent=true, so a server that was switched off "
                       "over the weekend still revokes on Monday."))
    else:
        p.add(Step("exp-cron", "Add a daily cron entry", StepKind.SERVICE,
                   command=("mkdir -p /etc/periodic/daily 2>/dev/null; "
                            "ln -sf {s} /etc/periodic/daily/tessera-expiry "
                            "2>/dev/null || "
                            "(echo '17 3 * * * {s}' > /etc/cron.d/tessera-expiry "
                            "&& chmod 644 /etc/cron.d/tessera-expiry)").format(
                                s=shlex.quote(SCRIPT)),
                   undo=("rm -f /etc/periodic/daily/tessera-expiry "
                         "/etc/cron.d/tessera-expiry; true"),
                   why="No systemd here, so the same script runs from cron."))
    return p


def plan_refresh(peers: List[Peer]) -> Plan:
    """Rewrite just the table, after a peer is added or removed."""
    p = Plan("Update the expiry table")
    p.add(Step("exp-table", "Refresh the expiry table", StepKind.CONFIG,
               write=(TABLE, render_table(peers), "0600"), critical=False))
    return p


def parse_log(body: str) -> List[Dict[str, str]]:
    """Read what the script revoked while we were not looking."""
    out: List[Dict[str, str]] = []
    for line in (body or "").splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 4:
            out.append({"on": parts[0], "engine": parts[1],
                        "name": parts[2], "expired": parts[3]})
    return out
