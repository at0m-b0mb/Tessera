# Contributing

## Running from a clone

```bash
git clone https://github.com/at0m-b0mb/Tessera
cd Tessera
pip install cryptography rich qrcode PyQt6
python3 -m tessera --help
```

## Tests

```bash
python3 tests/test_lifecycle.py
```

They run against `tests/fake.py`, a `Transport` that answers from a script and
records every command — so plan construction, config rendering and the inventory
are all exercised without a server.

The most important test asserts that a client private key never appears in
anything sent to the server. If you change key handling, that test is the one
that matters.

## Screenshots

```bash
QT_QPA_PLATFORM=offscreen python3 scripts/screenshots.py assets/screenshots
```

Renders the real application against the demo server, so the images cannot drift
from the code.

## Brand assets

```bash
python3 scripts/make_assets.py assets
```

The SVG mark is built from the same fracture coordinates the Qt widget paints,
so the icon and the running app stay identical.

## Adding a distribution

Most of it lives in two places:

1. `core/facts.py` — add the `ID` to `FAMILY_FOR_ID`, and a floor to
   `MIN_VERSION` if old releases cannot work.
2. `core/engines/base.py` — if it needs a package manager not already handled,
   add it to `pkg_install`, `pkg_remove`, `pkg_refresh` and `pkg_installed`.

Then add its package names to the `PACKAGES` dict in each engine.

## Adding an engine

1. `core/engines/yourvpn.py`, extending `Engine`.
2. Register in `core/engines/__init__.py`.
3. Questions in `core/interview.py` with a `when=` predicate.
4. A config dataclass in `core/models.py` plus a field on `InstallSpec`.

No CLI or GUI changes needed — both discover it.

## House style

- **Every step needs a `why`.** Say what happens if this is wrong, not what the
  command does. `"0700 so no other user on the box can list the key files"`, not
  `"sets permissions"`.
- **Record artefacts as you create them**, with `pre_existing` set honestly, or
  the uninstaller will remove something it did not add.
- **Never put a secret in argv.** Use `write_file` (stdin) or redirect into a
  file. Mark the step `sensitive=True`.
- **Guard firewall rules with `-C`** so re-running an install is a no-op.
- **Prefer refusing to guessing.** If a target cannot support something, say so
  before installing anything.
- Python 3.9 compatible: `from __future__ import annotations`, no `X | Y` at
  runtime, no `match`.
- Core stays Qt-free.

## Commits

Plain, descriptive messages. Explain why, not what.
