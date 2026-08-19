"""Tessera brand constants.

A *tessera hospitalis* was a small token, usually clay or bronze, deliberately
snapped in two.  The host kept one half and the guest took the other; years
later either party -- or their descendants -- could prove the bond by producing
their half and watching the broken edges mate.  Neither half means anything
alone, and a forgery is hopeless because the fracture is unrepeatable.

That is a keypair, two thousand years early, and it is the whole idea behind
this project: your device holds one half, the server holds the other, and the
tunnel exists because the halves fit.
"""

from __future__ import annotations

NAME = "Tessera"
TAGLINE = "Two halves of one token."
DESCRIPTION = (
    "Install, configure and remove WireGuard, OpenVPN and Tailscale "
    "on any Linux server - from any desktop."
)
REPO = "https://github.com/at0m-b0mb/Tessera"
LICENSE = "MIT"

# --- Palette -----------------------------------------------------------------
# Obsidian and bronze, after fired-clay and cast-bronze tesserae.  Deliberately
# not the blue that every other VPN tool uses.
INK          = "#0B0D10"   # deepest background
OBSIDIAN     = "#12151A"   # panel background
SLATE        = "#1B1F26"   # raised surface
SLATE_HI     = "#252A33"   # hover / border
MUTED        = "#6B7280"   # secondary text
BONE         = "#E8E4DC"   # primary text
BONE_DIM     = "#A8A399"   # tertiary text

BRONZE       = "#C88A4A"   # primary accent
BRONZE_HI    = "#E0A868"   # accent hover
BRONZE_DIM   = "#8A5F33"   # accent pressed / borders
AMBER        = "#F0B454"   # highlight, warnings

OK           = "#5BC98C"
WARN         = "#F0B454"
DANGER       = "#E0575B"
INFO         = "#7FA8D4"

# Per-engine accents, harmonised with the palette rather than copied from each
# upstream project's own branding.
ENGINE_COLORS = {
    "wireguard": "#E0575B",
    "openvpn":   "#F0A044",
    "tailscale": "#9BA0F5",
}

ENGINE_LABELS = {
    "wireguard": "WireGuard",
    "openvpn":   "OpenVPN",
    "tailscale": "Tailscale",
}

# --- Marks -------------------------------------------------------------------
# The mark is a square tile split by a jagged fracture into two halves that
# only fit each other.
ASCII_LOGO = r"""
   ______                              
  /_  __/__  ___ ___ ___ _______ _     
   / / / -_)(_-<(_-</ -_) __/ _ `/     
  /_/  \__//___/___/\__/_/  \_,_/      
"""

ASCII_MARK = r"""
    ####\####
    ####/####
"""


def banner(version: str) -> str:
    """Return the CLI banner as plain text (colour applied by the caller)."""
    return "{}\n  {}  v{}\n  {}\n".format(
        ASCII_LOGO.rstrip("\n"), TAGLINE, version, DESCRIPTION
    )
