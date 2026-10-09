# Booked Inventory

`booked_inventory.py` is a single-file, Python 3.11 standard-library CLI for
maintaining a local inventory of Booked Scheduler lab hosts and cached,
read-only SSH fabric facts. Reporting commands (`list`, `show`, `links`, and
`status`) only read SQLite; `update`, `probe`, `discover`, and `sync-booked`
are the commands that contact Booked or lab hosts. The remote scripts are
read-only and are regression-tested against state-changing commands.

## Setup

```bash
./scripts/install-hooks.sh
```

This configures `core.hooksPath` to `.githooks`. The pre-commit hook compiles
the CLI and runs the test suite; the pre-push hook runs the suite again.

## Common usage

```bash
# Friendly overview, including all commands and examples.
./booked_inventory.py

# See cache coverage and its age, without a network call.
./booked_inventory.py status

# Refresh Booked metadata and read-only probe stale hosts.
./booked_inventory.py update --max-age 24
./booked_inventory.py refresh --discover

# Inspect the cache. `ls` and `list` are interchangeable.
./booked_inventory.py ls --gen 6k --reachable -w
./booked_inventory.py list --source discovered --json

# Host names are case-insensitive and support a unique partial match.
# A Booked resource name lists all its assigned hosts.
./booked_inventory.py show cn123
./booked_inventory.py show 'Rack A' --json

# Cached fabric/Ethernet peer evidence and common-switch membership.
./booked_inventory.py links --gen CN6000
```

Generation accepts `5k`, `6k`, `5000`, `6000`, `CN5000`, and `CN6000`
case-insensitively. Human-facing output uses color only on a terminal; set
`NO_COLOR=1` or pass `--no-color` to disable it. Use `--json` with `status`,
`list`, `show`, or `links` for scripts. Use `--debug` only when you need a
traceback for an unexpected failure.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite uses only `unittest` and `unittest.mock`, runs in temporary
XDG directories, never opens the real cache DB, and never contacts Booked,
SSH, or the fabric.
