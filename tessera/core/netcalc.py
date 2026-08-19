"""Address planning.

The reference scripts do this with ``grep`` against the live config file and a
loop over ``{2..254}``.  That works until two people add a client at the same
moment, or until someone hand-edits the file, or until you want a /22.

Tessera uses Python's ``ipaddress`` module and allocates against the set of
addresses already claimed, so it handles any prefix length, both families, and
tells you honestly when a subnet is full instead of silently reusing .254.
"""

from __future__ import annotations

import ipaddress
import random
from typing import Iterable, List, Optional, Set, Tuple

# Ranges that are private, and therefore safe to use for a VPN without
# colliding with something real on the internet.
RFC1918 = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ULA = ipaddress.ip_network("fd00::/8")

# Networks a VPN client should normally never be able to reach *through* the
# server.  Blocking these is what stops "I gave a friend VPN access" from also
# meaning "I gave a friend access to my home NAS and my router's admin page".
PROTECTED_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10"]
PROTECTED_V6 = ["fc00::/7", "fe80::/10", "::1/128"]


class SubnetFull(Exception):
    pass


def parse_net(cidr: str):
    """Parse a CIDR, tolerating a host address instead of a network address."""
    return ipaddress.ip_network(cidr, strict=False)


def server_address(cidr: str) -> str:
    """The server always takes the first usable address in the subnet."""
    net = parse_net(cidr)
    return str(next(net.hosts()))


def prefix_len(cidr: str) -> int:
    return parse_net(cidr).prefixlen


def usable_count(cidr: str) -> int:
    net = parse_net(cidr)
    if isinstance(net, ipaddress.IPv4Network):
        # Minus network, broadcast and the server itself.
        return max(0, net.num_addresses - 3)
    # IPv6 has no broadcast; cap the number we bother counting.
    return min(net.num_addresses - 2, 1 << 20)


def allocate(cidr: str, taken: Iterable[str],
             preferred: Optional[str] = None) -> str:
    """Return the lowest free host address in ``cidr``.

    ``taken`` may contain bare addresses or CIDRs; both are handled, because
    WireGuard writes peers as ``10.66.66.4/32`` and we should not have to care.
    """
    net = parse_net(cidr)
    claimed: Set[int] = set()
    for entry in taken:
        for addr in _addresses_in(entry):
            claimed.add(int(addr))

    if preferred:
        try:
            cand = ipaddress.ip_address(preferred.split("/")[0])
            if cand in net and int(cand) not in claimed and cand != net.network_address:
                return str(cand)
        except ValueError:
            pass

    hosts = net.hosts()
    first = next(hosts, None)          # reserved for the server
    if first is None:
        raise SubnetFull("{} has no usable addresses".format(cidr))
    claimed.add(int(first))

    for host in net.hosts():
        if int(host) not in claimed:
            return str(host)
    raise SubnetFull(
        "{} is full ({} usable addresses, all assigned)".format(
            cidr, usable_count(cidr)))


def _addresses_in(entry: str) -> List:
    entry = (entry or "").strip()
    if not entry:
        return []
    try:
        if "/" in entry:
            net = ipaddress.ip_network(entry, strict=False)
            # A /32 or /128 is a single host; anything wider we treat as a
            # reservation but do not enumerate a million addresses.
            if net.num_addresses > 4096:
                return [net.network_address]
            return list(net)
        return [ipaddress.ip_address(entry)]
    except ValueError:
        return []


def host_cidr(address: str) -> str:
    """Render an address as the single-host CIDR WireGuard wants."""
    addr = ipaddress.ip_address(address)
    return "{}/{}".format(addr, 32 if addr.version == 4 else 128)


def random_private_v4(prefix: int = 24) -> str:
    """Pick a random RFC1918 /24 to reduce the odds of colliding with a café.

    Everyone's home router is 192.168.0.0/24 or 192.168.1.0/24, and every hotel
    is 10.0.0.0/24.  If your VPN subnet collides with the network the client is
    sitting on, routing breaks in a way that is miserable to debug.  Picking
    randomly inside 10/8 makes that collision unlikely instead of routine.
    """
    a, b = random.randint(20, 250), random.randint(1, 250)
    return "10.{}.{}.0/{}".format(a, b, prefix)


def random_ula() -> str:
    """A random ULA /64, per RFC 4193 which asks for a random global ID."""
    gid = "".join(random.choice("0123456789abcdef") for _ in range(10))
    return "fd{}:{}:{}::/64".format(gid[0:2], gid[2:6], gid[6:10])


def validate_subnet(cidr: str, family: int = 4) -> Tuple[bool, str]:
    """Check a user-supplied subnet, returning (ok, reason)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return False, str(exc)
    if net.version != family:
        return False, "expected IPv{} but got IPv{}".format(family, net.version)
    if net.version == 4:
        if not any(net.subnet_of(p) for p in RFC1918):
            return False, ("{} is not a private range - using public address "
                           "space here will break routing to the real internet"
                           .format(cidr))
        if net.prefixlen > 30:
            return False, "prefix /{} is too small for any clients".format(net.prefixlen)
    else:
        if not net.subnet_of(ULA):
            return False, "{} is not inside fd00::/8 (unique local)".format(cidr)
        if net.prefixlen > 126:
            return False, "prefix /{} is too small".format(net.prefixlen)
    return True, ""


def validate_port(port) -> Tuple[bool, str]:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return False, "port must be a number"
    if not 1 <= p <= 65535:
        return False, "port must be between 1 and 65535"
    if p < 1024:
        return True, "ports below 1024 need root and are heavily scanned"
    return True, ""


def is_private(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def looks_like_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    return all(l and len(l) <= 63 and
               all(c.isalnum() or c == "-" for c in l) and
               not l.startswith("-") and not l.endswith("-")
               for l in labels)
