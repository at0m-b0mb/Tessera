"""One module per VPN technology, behind a single interface."""

from __future__ import annotations

from typing import Dict, List

from .base import Engine, EngineContext
from .openvpn import OpenVPNEngine
from .tailscale import TailscaleEngine
from .wireguard import WireGuardEngine

_REGISTRY: Dict[str, Engine] = {
    "wireguard": WireGuardEngine(),
    "openvpn": OpenVPNEngine(),
    "tailscale": TailscaleEngine(),
}


def get(name: str) -> Engine:
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError("unknown engine '{}' (have: {})".format(
            name, ", ".join(sorted(_REGISTRY)))) from exc


def all_engines() -> List[Engine]:
    return [_REGISTRY[k] for k in ("wireguard", "openvpn", "tailscale")]


__all__ = ["Engine", "EngineContext", "get", "all_engines",
           "WireGuardEngine", "OpenVPNEngine", "TailscaleEngine"]
