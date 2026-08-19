"""A Transport that answers from a script instead of touching a real machine.

Every plan in Tessera is built by asking the target questions, so to test plan
construction we need something that can answer them.  This records every
command it is asked to run, which is how the tests assert that (for example) a
private key never appears in an argv.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from tessera.core.transport import CommandResult, Transport


class FakeTransport(Transport):
    label = "fake@testhost"
    is_root = True

    def __init__(self, responses: Optional[Dict[str, str]] = None,
                 files: Optional[Dict[str, str]] = None,
                 fail: Optional[List[str]] = None) -> None:
        self.responses = responses or {}
        self.files: Dict[str, str] = files or {}
        self.fail = fail or []
        self.commands: List[str] = []
        self.writes: List[tuple] = []

    def run(self, command, *, check=False, timeout=300, sink=None,
            input_text=None) -> CommandResult:
        self.commands.append(command)
        for pattern, out in self.responses.items():
            if re.search(pattern, command):
                return CommandResult(command, 0, out, "", 0.0)
        for pattern in self.fail:
            if re.search(pattern, command):
                return CommandResult(command, 1, "", "simulated failure", 0.0)
        return CommandResult(command, 0, "", "", 0.0)

    def run_root(self, command, **kw) -> CommandResult:
        return self.run(command, **kw)

    def write_file(self, path: str, content: str, mode: str = "0600") -> None:
        self.writes.append((path, content, mode))
        self.files[path] = content

    def read_file(self, path: str) -> str:
        if path in self.files:
            return self.files[path]
        raise KeyError("no fake file at {}".format(path))

    def file_exists(self, path: str) -> bool:
        return path in self.files

    def which(self, binary: str) -> Optional[str]:
        return "/usr/bin/" + binary

    # -- assertions -----------------------------------------------------------
    def all_text(self) -> str:
        """Everything we ever sent, for leak checks."""
        return "\n".join(self.commands)


def demo_facts(**over):
    from tessera.core.models import Facts
    f = Facts(os_id="ubuntu", os_name="Ubuntu 24.04 LTS", version_id="24.04",
              version_codename="noble", family="debian", pkg="apt",
              kernel="6.8.0-31-generic", arch="x86_64", init="systemd",
              public_ipv4="203.0.113.10", private_ipv4="10.0.0.5",
              nic="eth0", has_tun=True, has_ipv6=True, firewall="iptables",
              behind_nat=True)
    for k, v in over.items():
        setattr(f, k, v)
    return f
