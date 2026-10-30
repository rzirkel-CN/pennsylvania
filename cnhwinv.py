#!/usr/bin/env python3
# noqa: SIZE_OK — the requested single-file CLI owns its complete offline inventory workflow.
"""cnhwinv - Cornelis Networks Hardware Inventory.

Inventories Cornelis lab hosts from Booked Scheduler, fabric discovery, and
read-only SSH probes.

The SQLite cache is the reporting source of truth. `list` may perform one
read-only Booked availability refresh when its cached value is stale; all other
reporting commands remain offline. Use `update` to refresh full inventory data.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
from contextlib import contextmanager
import csv
import difflib
import json
import os
import re
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator, Sequence

VERSION = "1.0.0"
BOOKED_API = "http://booked.cornelisnetworks.com/Web/Services/index.php"
HOSTS_ATTR_ID = 2
CN_VENDOR = "434e"
GEN_BY_DEVICE = {"0001": "CN5000", "0002": "CN6000"}
# PCI display classes (VGA/3D/Display) and processing accelerators (1200, used by
# AMD Instinct MI200/MI300); excludes onboard server BMC VGA (ASPEED 1a03, Matrox 102b).
GPU_CLASSES = {"0300", "0302", "0380", "1200"}
GPU_VENDORS = {"10de": "NVIDIA", "1002": "AMD", "8086": "Intel"}
_IGPU_RE = re.compile(r"\b(UHD|HD|Integrated)\s+Graphics\b", re.IGNORECASE)
_NO_GPU_VALUES = {"-", "none", "n/a", "na", "no", "false", "0", "tbd"}
_DATA_HOME = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
DEFAULT_DB = _DATA_HOME / "cnhwinv/inventory.db"
# Cache location used before the tool was renamed from booked_inventory.
LEGACY_DB = _DATA_HOME / "booked-inventory/inventory.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS fabric_node (
  guid TEXT PRIMARY KEY, type TEXT, name TEXT, vendor_id TEXT, device_id TEXT,
  seen_from TEXT, seen_at TEXT);
CREATE TABLE IF NOT EXISTS resource (
  id INTEGER PRIMARY KEY, name TEXT, schedule_id INTEGER, status_id INTEGER,
  description TEXT, notes TEXT, hosts_raw TEXT, attrs_json TEXT, synced_at TEXT,
  avail_state TEXT, avail_until TEXT, avail_at TEXT, reserved_by TEXT,
  avail_checked_at TEXT);
CREATE TABLE IF NOT EXISTS host (
  name TEXT PRIMARY KEY, probed_at TEXT, reachable INTEGER, error TEXT, fqdn TEXT,
  source TEXT DEFAULT 'booked', model TEXT, cpu TEXT, sockets TEXT, cores TEXT,
  os TEXT, kernel TEXT);
CREATE TABLE IF NOT EXISTS resource_host (
  resource_id INTEGER, host TEXT, PRIMARY KEY (resource_id, host));
CREATE TABLE IF NOT EXISTS adapter (
  host TEXT, pci_addr TEXT, device_id TEXT, generation TEXT, pci_class TEXT,
  description TEXT, PRIMARY KEY (host, pci_addr));
CREATE TABLE IF NOT EXISTS gpu (
  host TEXT, pci_addr TEXT, vendor_id TEXT, device_id TEXT, pci_class TEXT,
  model TEXT, description TEXT, PRIMARY KEY (host, pci_addr));
CREATE TABLE IF NOT EXISTS port (
  host TEXT, ifname TEXT, port INTEGER, pci_addr TEXT, kind TEXT,
  node_guid TEXT, port_guid TEXT, state TEXT, phys_state TEXT, lid TEXT,
  neighbor_type TEXT, neighbor_guid TEXT, neighbor_port INTEGER,
  mac TEXT, netdev TEXT, lldp_json TEXT,
  PRIMARY KEY (host, ifname, port));
"""

TOP_DESCRIPTION = """Inspect the local Booked Scheduler inventory cache without touching lab hosts.

`update` refreshes Booked metadata and SSH-probes hosts. `list` refreshes only
cached Booked availability when it is older than five minutes; use `--offline`
to suppress that read-only refresh. Remote probes and discovery are strictly read-only;
`show` also asks each host's BMC for chassis power status (read-only IPMI).
`checkout` and `checkin` are the only commands that write to Booked."""
TOP_EPILOG = """Common examples:
  cnhwinv status
  cnhwinv update --max-age 24
  cnhwinv ls --gen 6k --reachable -w
  cnhwinv list --gpu
  cnhwinv list --available
  cnhwinv show cn123
  cnhwinv checkout cn123 --for 4h
  cnhwinv checkin cn123
  cnhwinv links --gen CN5000
  cnhwinv --db /tmp/inventory.db list --json
"""

# Junk tokens seen in the Booked "Hosts" free-text field.
_HOST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*\d[A-Za-z0-9_.-]*$")
_SECRET_RE = re.compile(r"(?i)\b(root|admin|user)\s*/\s*[^\s;,]+|passw(or)?d\s*[:=]?\s*[^\s;,]+")
_USE_COLOR = False


class UserError(RuntimeError):
    """A problem that can be explained without exposing a traceback or secret."""


def mask(text: str | None) -> str:
    """Never persist plaintext credentials that people paste into Booked fields."""
    return _SECRET_RE.sub("<redacted>", text or "")


def parse_hosts(raw: str) -> list[str]:
    """Extract plausible hostnames from Booked's free-text Hosts field."""
    hosts: list[str] = []
    for line in (raw or "").splitlines():
        cleaned = re.sub(r"(?i)^\s*(host(name)?s?)\s*[:=-]\s*", "", line).strip()
        # Parenthesized IP addresses and prose after a hostname do not identify hosts.
        cleaned = cleaned.split("(", 1)[0]
        for token in re.split(r"[\s,;]+", cleaned):
            candidate = token.strip(".-: ")
            if candidate and _HOST_RE.fullmatch(candidate) and not candidate.isupper():
                hosts.append(candidate.lower())
    return list(dict.fromkeys(hosts))


# ---------------------------------------------------------------- Booked API
def _creds() -> tuple[str, str]:
    """Read Booked credentials indirectly, without ever displaying their values."""
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    pointer = state / "cn-ai-tools-bootstrap/booked-env-path"
    try:
        env_file = os.environ.get("BOOKED_ENV_FILE") or pointer.read_text().strip()
    except OSError as error:
        raise UserError(
            "Booked credentials file is unavailable. Run the cn-ai-tools bootstrap or set BOOKED_ENV_FILE."
        ) from error
    if not env_file:
        raise UserError("Booked credentials file path is empty. Set BOOKED_ENV_FILE or rerun bootstrap.")
    try:
        content = Path(env_file).expanduser().read_text()
    except OSError as error:
        raise UserError("Booked credentials file is unavailable. Check BOOKED_ENV_FILE or rerun bootstrap.") from error

    values: dict[str, str] = {}
    for line in content.splitlines():
        match = re.match(r"\s*(BOOKED_USERNAME|BOOKED_PASSWORD)\s*=\s*(.*)$", line)
        if match:
            value = match.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[match.group(1)] = value
    try:
        return values["BOOKED_USERNAME"], values["BOOKED_PASSWORD"]
    except KeyError as error:
        raise UserError("Booked credentials file must define BOOKED_USERNAME and BOOKED_PASSWORD.") from error


def _booked_rejection(error: urllib.error.HTTPError) -> str | None:
    """Extract Booked's validation messages (e.g. a reservation conflict) from an HTTP error body."""
    try:
        body = json.loads(error.read() or b"{}")
    except (OSError, ValueError):
        return None
    messages = body.get("errors") if isinstance(body, dict) else None
    if not messages:
        return None
    return "; ".join(str(message) for message in messages)


def _call(
    path: str,
    data: dict | None = None,
    headers: dict[str, str] | None = None,
    method: str | None = None,
) -> dict:
    """Call the Booked REST API and turn transport failures into one clear error."""
    request = urllib.request.Request(
        BOOKED_API + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method or ("POST" if data is not None else "GET"),
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as error:
        # Write requests fail with 400 plus a JSON list of reasons; show those instead of a network hint.
        rejection = _booked_rejection(error)
        if rejection:
            raise UserError(f"Booked rejected the request: {rejection}") from error
        raise UserError("Booked Scheduler is unreachable or returned an invalid response. Check VPN/network access.") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise UserError("Booked Scheduler is unreachable or returned an invalid response. Check VPN/network access.") from error


@contextmanager
def _booked_session() -> Iterator[dict[str, str]]:
    """Authenticate once for a bounded group of read-only Booked API calls."""
    user, password = _creds()
    auth = _call("/Authentication/Authenticate", {"username": user, "password": password})
    if not auth.get("isAuthenticated"):
        raise UserError("Booked authentication failed. Check the configured credentials.")
    headers = {"X-Booked-SessionToken": auth["sessionToken"], "X-Booked-UserId": str(auth["userId"])}
    try:
        yield headers
    finally:
        _call("/Authentication/SignOut", {"userId": auth["userId"], "sessionToken": auth["sessionToken"]})


def booked_resources() -> list[dict]:
    """Authenticate to Booked, return resources, then invalidate its session."""
    with _booked_session() as headers:
        return _call("/Resources/", headers=headers)["resources"]


def _availability_entries(payload: dict) -> list[dict]:
    """Flatten Booked's schedule-grouped availability payload into resource entries."""
    return [entry for group in payload.get("resources") or [] for entry in group]


def _booked_datetime(value: str | None) -> datetime | None:
    """Parse a Booked timestamp, retaining its server-provided timezone offset."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _reservation_owners(payload: dict, now: datetime) -> dict[str, str | None]:
    """Map reservations covering now to their optional Booked user display names."""
    owners: dict[str, str | None] = {}
    for reservation in payload.get("reservations") or []:
        start = _booked_datetime(reservation.get("startDate"))
        end = _booked_datetime(reservation.get("endDate"))
        resource_id = reservation.get("resourceId")
        if resource_id is None or start is None or end is None or not start <= now <= end:
            continue
        owner = " ".join(part for part in (reservation.get("firstName"), reservation.get("lastName")) if part) or None
        owners[str(resource_id)] = owner
    return owners


def _availability_state(status_id: str | int | None, available: bool) -> str:
    """Translate Booked resource status plus calendar availability into one cache state."""
    if str(status_id) in {"0", "2"}:
        return "unavailable"
    return "free" if available else "reserved"


def _fallback_availability(db: sqlite3.Connection, payload: dict, now: datetime) -> None:
    """Update availability from current reservations if the availability endpoint is absent."""
    owners = _reservation_owners(payload, now)
    for resource_id, status_id in db.execute("SELECT id, status_id FROM resource"):
        state = "unavailable" if str(status_id) in {"0", "2"} else ("reserved" if str(resource_id) in owners else "free")
        db.execute(
            "UPDATE resource SET avail_state=?, avail_until=NULL, avail_at=NULL, reserved_by=?, avail_checked_at=datetime('now') WHERE id=?",
            (state, owners.get(str(resource_id)), resource_id),
        )


def fetch_booked(include_resources: bool) -> dict:
    """Fetch Booked data over one session, issuing the independent GETs concurrently.

    The resource list, availability, and current reservations do not depend on
    each other, so they are requested in parallel instead of one after another
    (and across two logins, as before). Reservations are always requested because
    a parallel GET costs no extra wall time; they only supply optional owner names
    unless the availability endpoint is missing. This function never touches
    SQLite, so callers may run it on a worker thread.
    """
    now = datetime.now(timezone.utc)
    query = urllib.parse.quote(now.isoformat())
    paths = {
        "availability": "/Resources/Availability",
        "reservations": f"/Reservations/?startDateTime={query}&endDateTime={query}",
    }
    if include_resources:
        paths["resources"] = "/Resources/"
    with _booked_session() as headers, cf.ThreadPoolExecutor(len(paths)) as executor:
        futures = {key: executor.submit(_call, path, headers=headers) for key, path in paths.items()}
        cf.wait(futures.values())
    snapshot: dict = {"now": now}
    for key, future in futures.items():
        try:
            snapshot[key] = future.result()
        except UserError:
            # Owner names are cosmetic; let the rest of the refresh succeed.
            if key != "reservations":
                raise
            snapshot[key] = None
    if "resources" not in snapshot["availability"] and snapshot["reservations"] is None:
        raise UserError("Booked Scheduler is unreachable or returned an invalid response. Check VPN/network access.")
    return snapshot


def apply_availability(db: sqlite3.Connection, snapshot: dict) -> None:
    """Store availability from a fetch_booked() snapshot (main thread only)."""
    now, payload, reservations = snapshot["now"], snapshot["availability"], snapshot["reservations"] or {}
    if "resources" not in payload:
        _fallback_availability(db, reservations, now)
    else:
        owners = _reservation_owners(reservations, now)
        for entry in _availability_entries(payload):
            resource = entry.get("resource") or {}
            resource_id = resource.get("resourceId")
            if resource_id is None:
                continue
            state = _availability_state(resource.get("statusId"), bool(entry.get("available")))
            db.execute(
                "UPDATE resource SET avail_state=?, avail_until=?, avail_at=?, reserved_by=?, avail_checked_at=datetime('now') WHERE id=?",
                (
                    state,
                    entry.get("availableUntil"),
                    entry.get("availableAt"),
                    owners.get(str(resource_id)) if state == "reserved" else None,
                    resource_id,
                ),
            )
    db.commit()


def refresh_availability(db: sqlite3.Connection) -> None:
    """Refresh all Booked resource availability with concurrent read-only GET requests."""
    apply_availability(db, fetch_booked(include_resources=False))


def cmd_sync_booked(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Replace Booked resource metadata and preserve the local probe cache."""
    apply_booked(db, fetch_booked(include_resources=True))
    return 0


def apply_booked(db: sqlite3.Connection, snapshot: dict) -> None:
    """Replace cached Booked resources and availability from one fetched snapshot."""
    resources = snapshot["resources"]["resources"]
    db.execute("DELETE FROM resource_host")
    db.execute("DELETE FROM resource")
    for resource in resources:
        attributes = {attribute["label"]: mask(attribute.get("value")) for attribute in resource.get("customAttributes") or []}
        raw_hosts = next(
            (
                attribute.get("value") or ""
                for attribute in resource.get("customAttributes") or []
                if int(attribute["id"]) == HOSTS_ATTR_ID
            ),
            "",
        )
        db.execute(
            "INSERT OR REPLACE INTO resource "
            "(id, name, schedule_id, status_id, description, notes, hosts_raw, attrs_json, synced_at) "
            "VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
            (
                resource["resourceId"],
                resource["name"],
                resource.get("scheduleId"),
                resource.get("statusId"),
                mask(resource.get("description")),
                mask(resource.get("notes")),
                mask(raw_hosts),
                json.dumps(attributes),
            ),
        )
        for host in parse_hosts(raw_hosts):
            db.execute("INSERT OR IGNORE INTO resource_host VALUES (?,?)", (resource["resourceId"], host))
            # A formerly discovered host is authoritative Booked inventory once it appears here.
            db.execute("INSERT INTO host(name, source) VALUES (?, 'booked') ON CONFLICT(name) DO UPDATE SET source='booked'", (host,))
    db.commit()
    apply_availability(db, snapshot)
    host_count = db.execute("SELECT count(DISTINCT host) FROM resource_host").fetchone()[0]
    print(f"Synced {len(resources)} resources, {host_count} hosts")


# ---------------------------------------------------------------- SSH probe
# Every command below is read-only. `timeout` bounds each so a wedged tool
# cannot hang the probe. No sudo is used (no password prompts, no privilege).
REMOTE_SCRIPT = r"""
export LC_ALL=C PATH=$PATH:/usr/sbin:/sbin
# The slow external tools (lspci, lldpctl, and two opasmaquery calls per port)
# start up front and run concurrently. Each writes into its own process
# substitution, buffered in a variable so a timed-out or large output never
# blocks on the pipe; results are read back below in the original fixed order.
exec {lspci_fd}< <(o=$(timeout 10 lspci -Dnn 2>/dev/null | grep -E '\[(434e:[0-9a-fA-F]{4}|0300|0302|0380|1200)\]'); [ -n "$o" ] && printf '%s\n' "$o")
exec {lldp_fd}< <(command -v lldpctl >/dev/null && o=$(timeout 10 lldpctl -f json 2>/dev/null) && [ -n "$o" ] && printf '%s\n' "$o")
ports=(); sma_fds=()
for d in /sys/class/infiniband/*; do [ -d "$d" ] || continue
  [ "$(cat $d/device/vendor 2>/dev/null)" = "0x434e" ] || continue
  dev=$(basename "$d"); pci=$(basename "$(readlink -f "$d/device")")
  for p in "$d"/ports/*; do n=$(basename "$p")
    ports+=("$dev|$n|$pci|$(cat $d/node_guid 2>/dev/null)|$(cat $p/state 2>/dev/null)|$(cat $p/phys_state 2>/dev/null)|$(cat $p/lid 2>/dev/null)")
    idx=${dev##*_}; idx=$((idx+1))
    exec {fd}< <(
      o=$( (timeout 10 opasmaquery -o portinfo -h "$idx" -p "$n" 2>&1 | grep -E 'NeighborNodeType|NeighborNodeGuid|failed') &
           timeout 10 opasmaquery -o nodeinfo -h "$idx" -p "$n" 2>/dev/null | grep -E '^\s*NodeGuid'; wait)
      [ -n "$o" ] && printf '%s\n' "$o")
    sma_fds+=("$fd")
  done
done
echo "@@FQDN $(hostname -f 2>/dev/null || hostname)"
echo "@@SYS"
echo "SYS|vendor|$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
echo "SYS|model|$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
echo "SYS|version|$(cat /sys/class/dmi/id/product_version 2>/dev/null)"
echo "SYS|cpu|$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2-)"
echo "SYS|sockets|$(grep '^physical id' /proc/cpuinfo 2>/dev/null | sort -u | wc -l)"
echo "SYS|cores|$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
echo "SYS|os|$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
echo "SYS|kernel|$(uname -r)"
echo "@@LSPCI"; cat <&$lspci_fd
echo "@@IB"
for i in "${!ports[@]}"; do
  IFS='|' read -r dev n _ <<< "${ports[$i]}"
  echo "PORT|${ports[$i]}"
  echo "@@SMA|$dev|$n"
  cat <&${sma_fds[$i]}
  echo "@@END"
done
echo "@@NET"
for n in /sys/class/net/*; do [ -e "$n/device" ] || continue
  pci=$(basename "$(readlink -f "$n/device")")
  ven=$(cat "$n/device/vendor" 2>/dev/null)
  [ "$ven" = "0x434e" ] && [ "$(cat $n/type)" = "1" ] && echo "NET|$(basename $n)|$pci|$(cat $n/address)|$(cat $n/operstate)|$(cat $n/dev_port 2>/dev/null)"
done
echo "@@LLDP"; cat <&$lldp_fd
echo "@@DONE"
"""


def _ssh_run(host: str, script: str, timeout: int) -> subprocess.CompletedProcess:
    """Run a read-only script on host over SSH.

    The script is passed as the remote command (``bash -c '<script>'``) with
    stdin closed instead of being piped to ``bash -s``.  When ssh exits early
    (auth or host-key failure) a stdin write would hit a closed pipe, and main()
    restores the default SIGPIPE action, so that write killed the whole CLI
    once enough sessions ran concurrently.
    """
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        host,
        "bash -c " + shlex.quote(script),
    ]
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    if process.returncode == 255 and _HOST_KEY_FAILURE.search(process.stderr or ""):
        # Lab hosts are reimaged constantly, so a changed host key is expected
        # rather than suspicious.  Drop the stale entry and retry once; the
        # retry records the new key via accept-new.
        _forget_host_key(host)
        process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    return process


_HOST_KEY_FAILURE = re.compile(r"Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|Host key for \S+ has changed")
# ssh-keygen -R rewrites known_hosts in place; serialize it across probe threads.
_KNOWN_HOSTS_LOCK = threading.Lock()


def _known_host_names(host: str) -> tuple[list[str], list[str]]:
    """Return (names keys are stored under, user known_hosts files) for host per `ssh -G`."""
    names, files = [host], []
    try:
        config = subprocess.run(["ssh", "-G", host], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        config = ""
    for line in config.splitlines():
        key, _, value = line.partition(" ")
        if key in ("hostname", "hostkeyalias") and value and value != "none":
            names.append(value)
        elif key == "userknownhostsfile":
            files.extend(value.split())
    return list(dict.fromkeys(names)), files or [str(Path("~/.ssh/known_hosts").expanduser())]


def _forget_host_key(host: str) -> None:
    """Remove host's stale entries from the user's known_hosts files; never raises."""
    names, files = _known_host_names(host)
    with _KNOWN_HOSTS_LOCK:
        for path in files:
            if not Path(path).expanduser().is_file():
                continue
            for name in names:
                try:
                    subprocess.run(
                        ["ssh-keygen", "-R", name, "-f", str(Path(path).expanduser())],
                        stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    pass


# BMC power is queried with read-only `chassis power status` only; nothing here
# can change power state.  Lab BMCs answer at <short-host>-bmc with the
# account from CNHWINV_BMC_USER / CNHWINV_BMC_PASSWORD.  Credentials are never
# stored in this repository; set them in your shell profile.
BMC_TIMEOUT = 15


def bmc_name(host: str) -> str:
    """Return the conventional BMC hostname for a lab host."""
    return host.split(".", 1)[0] + "-bmc"


def bmc_power(host: str, timeout: int = BMC_TIMEOUT) -> dict:
    """Query a host's BMC for chassis power state; never raises."""
    bmc = bmc_name(host)
    result: dict = {"bmc": bmc, "power": None, "error": None}
    try:
        socket.getaddrinfo(bmc, None)
    except OSError:
        result["error"] = "no BMC DNS entry"
        return result
    user, password = os.environ.get("CNHWINV_BMC_USER"), os.environ.get("CNHWINV_BMC_PASSWORD")
    if not user or not password:
        result["error"] = "set CNHWINV_BMC_USER and CNHWINV_BMC_PASSWORD"
        return result
    # The password travels via IPMI_PASSWORD (-E) so it never appears in ps output.
    env = dict(os.environ, IPMI_PASSWORD=password)
    command = ["ipmitool", "-I", "lanplus", "-H", bmc, "-U", user, "-E", "-N", "3", "-R", "2", "chassis", "power", "status"]
    try:
        proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError:
        result["error"] = "ipmitool not installed"
        return result
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
        return result
    match = re.search(r"Chassis Power is (\w+)", proc.stdout)
    if match:
        result["power"] = match.group(1).lower()
    else:
        lines = [line for line in (proc.stderr or proc.stdout).splitlines() if line.strip()]
        result["error"] = lines[-1][:200] if lines else f"ipmitool exited {proc.returncode}"
    return result


def bmc_power_many(hosts: Sequence[str], jobs: int = 32) -> dict[str, dict]:
    """Query several BMCs concurrently, keyed by host."""
    unique = list(dict.fromkeys(hosts))
    if not unique:
        return {}
    with cf.ThreadPoolExecutor(max_workers=min(jobs, len(unique))) as pool:
        return dict(zip(unique, pool.map(bmc_power, unique)))


def _power_text(power: dict | None) -> str:
    """Render a bmc_power result compactly."""
    if not power:
        return "-"
    return power["power"] or f"unknown ({power['error']})"


def ssh_probe(host: str, timeout: int) -> dict:
    """Run the read-only inventory script over SSH and return its raw response."""
    try:
        process = _ssh_run(host, REMOTE_SCRIPT, timeout)
    except subprocess.TimeoutExpired:
        return {"host": host, "error": "timeout"}
    if "@@DONE" not in process.stdout:
        return {"host": host, "error": (process.stderr.strip().splitlines() or ["ssh failed"])[-1][:200]}
    return {"host": host, "out": process.stdout}


def _gpu_model(vendor_id: str, device_id: str, description: str) -> str:
    vendor = GPU_VENDORS.get(vendor_id, vendor_id)
    cleaned = description
    for prefix in ("Advanced Micro Devices, Inc. [AMD/ATI]", "NVIDIA Corporation", "Intel Corporation"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :].strip()
    brackets = [item.strip() for item in re.findall(r"\[([^\]]+)\]", cleaned) if item.strip()]
    label = brackets[-1] if brackets else cleaned
    if not label or label.lower() == "device":
        return f"{vendor} [{vendor_id}:{device_id}]"
    if label.lower().startswith(vendor.lower()):
        return label
    return f"{vendor} {label}"


def parse_probe(output: str) -> dict:
    """Parse stable section markers emitted by REMOTE_SCRIPT into cached facts."""
    result: dict = {"fqdn": None, "adapters": [], "gpus": [], "ports": [], "net": [], "lldp": None, "sys": {}}
    section: str | None = None
    sma_key: tuple[str, int] | None = None
    lldp_lines: list[str] = []
    for line in output.splitlines():
        if line.startswith("@@FQDN"):
            result["fqdn"] = line.split(None, 1)[1] if " " in line else None
            continue
        if line.startswith("@@SMA|"):
            _, device, port = line.split("|")
            sma_key = (device, int(port))
            continue
        if line == "@@END":
            sma_key = None
            continue
        if line.startswith("@@"):
            section = line[2:]
            continue
        if sma_key:
            port = next(item for item in result["ports"] if (item["ifname"], item["port"]) == sma_key)
            if "failed" in line:
                port["neighbor_type"] = "query-failed: " + line.strip()[:80]
            if match := re.match(r"\s*NodeGuid:\s*(0x[0-9a-f]+)", line):
                port["sma_node_guid"] = match.group(1)
            if match := re.search(r"NeighborNodeType:\s*(\S+)", line):
                port["neighbor_type"] = match.group(1)
            if match := re.search(r"NeighborNodeGuid:\s*(0x[0-9a-f]+)\s+NeighborPortNum:\s*(\d+)", line):
                port["neighbor_guid"], port["neighbor_port"] = match.group(1), int(match.group(2))
            continue
        if section == "SYS" and line.startswith("SYS|"):
            _, key, value = (line.split("|", 2) + [""])[:3]
            result["sys"][key] = " ".join(value.split()) or None
            continue
        if section == "LSPCI" and line.strip():
            match = re.match(r"(\S+)\s+(.*?)\s+\[([0-9a-fA-F]{4})\]:\s+(.*)\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]", line)
            if match:
                pci, pci_class, class_id, desc, vendor_id, device_id = (
                    match.group(1),
                    match.group(2),
                    match.group(3).lower(),
                    match.group(4).strip(),
                    match.group(5).lower(),
                    match.group(6).lower(),
                )
                if vendor_id == CN_VENDOR:
                    result["adapters"].append(
                        {
                            "pci": pci,
                            "class": pci_class,
                            "desc": desc,
                            "device": device_id,
                            "gen": GEN_BY_DEVICE.get(device_id, "CN-unknown"),
                        }
                    )
                elif (
                    class_id in GPU_CLASSES
                    and vendor_id in GPU_VENDORS
                    and not (vendor_id == "8086" and (class_id == "1200" or _IGPU_RE.search(desc)))
                ):
                    result["gpus"].append(
                        {
                            "pci": pci,
                            "vendor": vendor_id,
                            "device": device_id,
                            "class": pci_class,
                            "model": _gpu_model(vendor_id, device_id, desc),
                            "desc": desc,
                        }
                    )
        elif section == "IB" and line.startswith("PORT|"):
            _, device, port, pci, guid, state, physical, lid = (line.split("|") + [""] * 8)[:8]
            result["ports"].append(
                {
                    "ifname": device,
                    "port": int(port),
                    "pci": pci,
                    "kind": "opa",
                    "node_guid": "0x" + guid.replace(":", "") if guid else None,
                    "state": state.split(":")[-1].strip(),
                    "phys": physical.split(":")[-1].strip(),
                    "lid": lid,
                    "sma_node_guid": None,
                    "neighbor_type": None,
                    "neighbor_guid": None,
                    "neighbor_port": None,
                }
            )
        elif section == "NET" and line.startswith("NET|"):
            _, netdev, pci, mac, state, devport = (line.split("|") + [""] * 6)[:6]
            result["net"].append({"netdev": netdev, "pci": pci, "mac": mac, "state": state, "dev_port": devport})
        elif section == "LLDP":
            lldp_lines.append(line)
    if lldp_lines:
        try:
            result["lldp"] = json.loads("\n".join(lldp_lines))
        except json.JSONDecodeError:
            result["lldp"] = None
    return result


def _lldp_for(lldp: dict | None, netdev: str) -> dict | None:
    """Extract the chassis and port reported by lldpctl for a netdev."""
    if not lldp:
        return None
    interfaces = lldp.get("lldp", {}).get("interface") or []
    if isinstance(interfaces, dict):
        interfaces = [{name: details} for name, details in interfaces.items()]
    for entry in interfaces:
        for name, details in entry.items():
            if name == netdev:
                chassis = details.get("chassis", {})
                chassis_name = next(iter(chassis), None) if isinstance(chassis, dict) else None
                port = details.get("port", {}).get("id", {}).get("value")
                return {"chassis": chassis_name, "port": port, "descr": details.get("port", {}).get("descr")}
    return None


def store_probe(db: sqlite3.Connection, result: dict) -> None:
    """Persist one successful or failed SSH probe without modifying remote state."""
    host = result["host"]
    if "error" in result:
        db.execute("INSERT OR IGNORE INTO host(name) VALUES (?)", (host,))
        db.execute("UPDATE host SET probed_at=datetime('now'), reachable=0, error=? WHERE name=?", (result["error"], host))
        return

    probe = parse_probe(result["out"])
    db.execute("INSERT OR IGNORE INTO host(name) VALUES (?)", (host,))
    db.execute(
        "UPDATE host SET probed_at=datetime('now'), reachable=1, error=NULL, fqdn=? WHERE name=?",
        (probe["fqdn"], host),
    )
    system = probe["sys"]
    model = " ".join(value for value in (system.get("vendor"), system.get("model")) if value) or None
    db.execute(
        "UPDATE host SET model=?, cpu=?, sockets=?, cores=?, os=?, kernel=? WHERE name=?",
        (model, system.get("cpu"), system.get("sockets"), system.get("cores"), system.get("os"), system.get("kernel"), host),
    )
    db.execute("DELETE FROM adapter WHERE host=?", (host,))
    db.execute("DELETE FROM gpu WHERE host=?", (host,))
    db.execute("DELETE FROM port WHERE host=?", (host,))
    for adapter in probe["adapters"]:
        db.execute(
            "INSERT OR REPLACE INTO adapter VALUES (?,?,?,?,?,?)",
            (host, adapter["pci"], adapter["device"], adapter["gen"], adapter["class"], adapter["desc"]),
        )
    for gpu in probe["gpus"]:
        db.execute(
            "INSERT OR REPLACE INTO gpu VALUES (?,?,?,?,?,?,?)",
            (host, gpu["pci"], gpu["vendor"], gpu["device"], gpu["class"], gpu["model"], gpu["desc"]),
        )
    for port in probe["ports"]:
        db.execute(
            "INSERT OR REPLACE INTO port VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                host,
                port["ifname"],
                port["port"],
                port["pci"],
                "opa",
                port["node_guid"],
                port["sma_node_guid"],
                port["state"],
                port["phys"],
                port["lid"],
                port["neighbor_type"],
                port["neighbor_guid"],
                port["neighbor_port"],
                None,
                None,
                None,
            ),
        )
    for netdev in probe["net"]:
        lldp = _lldp_for(probe["lldp"], netdev["netdev"])
        db.execute(
            "INSERT OR REPLACE INTO port VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                host,
                netdev["netdev"],
                0,
                netdev["pci"],
                "eth",
                None,
                None,
                netdev["state"],
                None,
                None,
                "LLDP" if lldp else None,
                None,
                None,
                netdev["mac"],
                netdev["netdev"],
                json.dumps(lldp) if lldp else None,
            ),
        )


def _stale_hosts(db: sqlite3.Connection, args: argparse.Namespace) -> list[str]:
    """Return cached hosts due for a probe under --force/--max-age."""
    if args.force:
        return [row[0] for row in db.execute("SELECT name FROM host ORDER BY name")]
    return [
        row[0]
        for row in db.execute(
            "SELECT name FROM host WHERE probed_at IS NULL OR probed_at < datetime('now', ?) "
            "OR (reachable=1 AND cpu IS NULL AND os IS NULL) ORDER BY name",
            (f"-{args.max_age} hours",),
        )
    ]


def _report_probe_plan(db: sqlite3.Connection, hosts: list[str], args: argparse.Namespace) -> bool:
    """Explain how many hosts are skipped as fresh; return False if none need probing."""
    total = db.execute("SELECT count(*) FROM host").fetchone()[0]
    if not hosts:
        print("No hosts known; run 'update' first." if not total else f"All {total} hosts are fresh; use --force to re-probe.")
        return False
    if not args.force:
        # Explain the skip so a small batch is not mistaken for a bug.
        print(
            f"Probing {len(hosts)} of {total} hosts ({total - len(hosts)} probed within the last "
            f"{args.max_age:g}h are cached; use --force to re-probe all, --max-age to change the window)",
            file=sys.stderr,
        )
    return True


def cmd_probe(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Probe explicit or stale hosts, retaining partial results after interruption."""
    if args.hosts:
        hosts = [host.lower() for host in args.hosts]
    else:
        hosts = _stale_hosts(db, args)
        if not _report_probe_plan(db, hosts, args):
            return 0
    _probe_hosts(db, hosts, args, show_progress=getattr(args, "discover", False))
    return 0


class _ProbeTracker:
    """Store and report probe results on the thread that owns the SQLite connection."""

    def __init__(self, db: sqlite3.Connection, show_progress: bool) -> None:
        self.db, self.show_progress = db, show_progress
        self.submitted: dict[str, cf.Future] = {}
        self.completed = self.reachable = 0

    def submit(self, executor: cf.Executor, hosts: list[str], timeout: int) -> set[cf.Future]:
        """Start probes for hosts not already in flight; return the new futures."""
        new: set[cf.Future] = set()
        for host in hosts:
            if host not in self.submitted:
                self.db.execute("INSERT OR IGNORE INTO host(name) VALUES (?)", (host,))
                self.submitted[host] = future = executor.submit(ssh_probe, host, timeout)
                new.add(future)
        self.db.commit()
        return new

    def record(self, result: dict) -> None:
        """Commit each result immediately so Ctrl-C loses less work."""
        store_probe(self.db, result)
        self.db.commit()
        self.completed += 1
        self.reachable += "error" not in result
        total = len(self.submitted)
        if self.show_progress:
            progress(self.completed, total, "probe", result["host"])
        else:
            status = "ok" if "error" not in result else "FAIL: " + result["error"]
            print(f"  [{self.completed}/{total}] {result['host']:<28} {status}", file=sys.stderr)

    def summary(self) -> None:
        print(f"Probed {len(self.submitted)} hosts, {self.reachable} reachable")


def _probe_hosts(db: sqlite3.Connection, hosts: list[str], args: argparse.Namespace, show_progress: bool = False) -> None:
    """Probe hosts concurrently and commit each result so Ctrl-C loses less work."""
    tracker = _ProbeTracker(db, show_progress)
    with cf.ThreadPoolExecutor(args.jobs) as executor:
        futures = tracker.submit(executor, hosts, args.timeout)
        if show_progress:
            progress(0, len(hosts), "probe")
        for future in cf.as_completed(futures):
            tracker.record(future.result())
    tracker.summary()


# ---------------------------------------------------------------- discovery
# Read-only fabric query: it asks the SA for node records through ACTIVE ports.
DISCOVER_SCRIPT = r"""
export LC_ALL=C PATH=$PATH:/usr/sbin:/sbin
command -v opasaquery >/dev/null || { echo "@@DONE"; exit 0; }
for d in /sys/class/infiniband/*; do [ -d "$d" ] || continue
  [ "$(cat $d/device/vendor 2>/dev/null)" = "0x434e" ] || continue
  dev=$(basename "$d"); idx=${dev##*_}; idx=$((idx+1))
  for p in "$d"/ports/*; do n=$(basename "$p")
    grep -q ACTIVE "$p/state" 2>/dev/null || continue
    echo "@@SA|$dev|$n"; timeout 20 opasaquery -h "$idx" -p "$n" -o node 2>/dev/null
  done
done
echo "@@DONE"
"""


def progress(done: int, total: int, label: str, extra: str = "") -> None:
    """Draw progress only on interactive stderr, never corrupting piped output."""
    if not sys.stderr.isatty():
        return
    width = 30
    filled = int(width * done / total) if total else width
    percent = 100 * done // total if total else 100
    sys.stderr.write(f"\r{label:<10} [{'#' * filled}{'.' * (width - filled)}] {done}/{total} {percent:3d}% {extra:<30.30}")
    if done >= total:
        sys.stderr.write("\n")
    sys.stderr.flush()


def run_parallel(func: Callable[[str], tuple[str, list[dict]]], items: list[str], jobs: int, label: str) -> list[tuple[str, list[dict]]]:
    """Run fabric SA reads concurrently while respecting non-interactive output."""
    results: list[tuple[str, list[dict]]] = []
    progress(0, len(items), label)
    with cf.ThreadPoolExecutor(jobs) as executor:
        futures = {executor.submit(func, item): item for item in items}
        for index, future in enumerate(cf.as_completed(futures), 1):
            results.append(future.result())
            progress(index, len(items), label, futures[future])
    return results


def _sa_query(host: str, timeout: int) -> tuple[str, list[dict]]:
    """Query node records from a host's fabric SA without making configuration changes."""
    try:
        process = _ssh_run(host, DISCOVER_SCRIPT, timeout)
    except subprocess.TimeoutExpired:
        return host, []
    nodes: list[dict] = []
    current: dict | None = None
    for line in process.stdout.splitlines():
        if match := re.match(r"LID:\s*\S+\s+Type:\s*(\S+)\s+Name:\s*(.*)", line):
            current = {"type": match.group(1), "name": match.group(2).strip()}
            nodes.append(current)
        elif current and (match := re.match(r"NodeGuid:\s*(0x[0-9a-f]+)", line)):
            current["guid"] = match.group(1)
        elif current and (match := re.search(r"VendorID:\s*0x([0-9a-f]+)\s+DeviceId:\s*0x([0-9a-f]+)", line)):
            current["vendor"], current["device"] = match.group(1).zfill(4), match.group(2).zfill(4)
    return host, [node for node in nodes if node.get("guid")]


def _fi_hostname(name: str) -> str | None:
    """Return a plausible short hostname from an FI node description."""
    token = name.split()[0].split(".")[0].lower() if name.split() else ""
    return token if re.fullmatch(r"[a-z0-9][a-z0-9-]*", token) else None


_UNNAMED_FI_TOKENS = frozenset({"cyr", "hfi", "jkr", "localhost", "mfg", "wfr"})


def _name_aliases(name: str | None) -> set[str]:
    """Return the full and short forms used by fabric node descriptions."""
    value = (name or "").strip().lower().rstrip(".")
    return {value, value.split(".", 1)[0]} if value else set()


def _is_unnamed_adapter(name: str) -> bool:
    """Identify vendor/default node descriptions that are not host identities."""
    hostname = _fi_hostname(name)
    return hostname in _UNNAMED_FI_TOKENS if hostname else False


def _known_host_aliases(db: sqlite3.Connection) -> set[str]:
    """Return host and FQDN aliases that identify already-known adapters."""
    aliases: set[str] = set()
    for name, fqdn in db.execute("SELECT name, fqdn FROM host"):
        aliases.update(_name_aliases(name))
        aliases.update(_name_aliases(fqdn))
    return aliases


def _port_guid_owners(db: sqlite3.Connection) -> dict[str, set[str]]:
    """Map lower-cased port GUIDs to all cached hosts that own them."""
    owners: dict[str, set[str]] = {}
    for host, node_guid, port_guid in db.execute("SELECT host, node_guid, port_guid FROM port"):
        for guid in (node_guid, port_guid):
            if guid:
                owners.setdefault(guid.lower(), set()).add(host.lower())
    return owners


def _known_port_guids(db: sqlite3.Connection) -> dict[str, set[str]]:
    """Return every known host's node and port GUIDs for SA coverage checks."""
    hosts: dict[str, set[str]] = {}
    for host, node_guid, port_guid in db.execute("SELECT host, node_guid, port_guid FROM port"):
        guids = hosts.setdefault(host, set())
        guids.update(guid.lower() for guid in (node_guid, port_guid) if guid)
    return hosts


def _active_discovery_hosts(db: sqlite3.Connection) -> set[str]:
    """Return reachable hosts with at least one active Cornelis port."""
    return {
        host
        for (host,) in db.execute(
            "SELECT DISTINCT h.name FROM host h JOIN port p ON p.host=h.name "
            "WHERE h.reachable=1 AND p.kind='opa' AND p.state='ACTIVE'"
        )
    }


def _fabric_covered_hosts(db: sqlite3.Connection, visible_guids: set[str]) -> set[str]:
    """Return hosts that querying would not reveal anything new from."""
    owned = {guid.lower() for guid in _guid_owner(db)}
    ports: dict[str, list[tuple[str | None, str | None]]] = {}
    for host, ntype, nguid in db.execute("SELECT host, neighbor_type, neighbor_guid FROM port WHERE kind='opa' AND state='ACTIVE'"):
        ports.setdefault(host, []).append((ntype, nguid.lower() if nguid else None))
    covered: set[str] = set()
    for host, links in ports.items():
        if any(nguid and nguid in visible_guids for _, nguid in links):
            covered.add(host)
        elif all(nguid and (ntype or "").upper() in ("FI", "HFI") and nguid in owned for ntype, nguid in links):
            covered.add(host)
    return covered


def _discovery_vantages(
    db: sqlite3.Connection, candidates: set[str], queried: set[str], covered: set[str], jobs: int
) -> list[str]:
    """Prefer a previously useful SA source, then bounded uncovered fallbacks."""
    remaining = sorted(candidates - queried - covered)
    if queried:
        # Hosts cabled to the same switch share a fabric, so query one host per
        # distinct neighbor switch first; this keeps SSH fan-out near one per fabric.
        neighbors: dict[str, set[str]] = {}
        for host, guid in db.execute("SELECT host, neighbor_guid FROM port WHERE kind='opa' AND state='ACTIVE'"):
            if guid:
                neighbors.setdefault(host, set()).add(guid.lower())
        picked: list[str] = []
        claimed: set[str] = set()
        for host in remaining:
            switches = neighbors.get(host, set())
            if not switches or not switches & claimed:
                picked.append(host)
                claimed |= switches
        return picked[:jobs]
    prior_sources = [
        source
        for (source,) in db.execute(
            "SELECT seen_from FROM fabric_node WHERE seen_from IS NOT NULL "
            "GROUP BY seen_from ORDER BY count(*) DESC, seen_from"
        )
        if source in remaining
    ]
    return prior_sources[:1] or remaining[:1]


def _cleanup_bogus_discovered_hosts(db: sqlite3.Connection) -> list[str]:
    """Remove placeholder discoveries and discoveries whose FI GUID belongs elsewhere."""
    owners = _port_guid_owners(db)
    fabric_nodes = [
        (guid.lower(), _fi_hostname(name))
        for guid, name in db.execute("SELECT guid, name FROM fabric_node WHERE upper(type)='FI'")
    ]
    bogus: list[str] = []
    for (host,) in db.execute("SELECT name FROM host WHERE source='discovered'"):
        aliases = _name_aliases(host)
        owned_elsewhere = any(
            node_name in aliases and owners.get(guid, set()) - {host.lower()} for guid, node_name in fabric_nodes if node_name
        )
        if _is_unnamed_adapter(host) or owned_elsewhere:
            bogus.append(host)

    for host in bogus:
        db.execute("DELETE FROM resource_host WHERE host=?", (host,))
        db.execute("DELETE FROM adapter WHERE host=?", (host,))
        db.execute("DELETE FROM port WHERE host=?", (host,))
        db.execute("DELETE FROM host WHERE name=?", (host,))
    if bogus:
        db.commit()
    return bogus


def cmd_discover(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Discover only unknown fabric hosts through coverage-aware, read-only SA queries."""
    # Discovery needs SA vantage points, which only exist once hosts are probed;
    # a fresh cache (sync-booked only) would otherwise silently report zeros.
    if not _active_discovery_hosts(db):
        probed = db.execute("SELECT count(*) FROM host WHERE probed_at IS NOT NULL").fetchone()[0]
        why = "no hosts have been probed yet" if not probed else "no probed host has an active Cornelis fabric port"
        print(f"Nothing to discover from: {why}.", file=sys.stderr)
        print("Hint: run 'cnhwinv probe' (or 'cnhwinv update --discover') first; discovery queries the fabric SA from probed hosts.", file=sys.stderr)
        return 1
    removed_hosts = _cleanup_bogus_discovered_hosts(db)
    previously_discovered = db.execute("SELECT count(*) FROM host WHERE source='discovered'").fetchone()[0]
    discovered_hosts: set[str] = set()
    unnamed: dict[str, str | None] = {}
    seen_fis: dict[str, dict] = {}
    # Coverage must come from live SA answers only: seeding it from cached
    # fabric_node rows would skip whole fabrics and miss newly cabled hosts.
    visible_guids: set[str] = set()
    observed_nodes: dict[str, dict] = {}
    queried: set[str] = set()
    covered: set[str] = set()
    coverage_messages: list[tuple[int, int]] = []

    # Keep querying until every active host is covered by some SA answer; the
    # bound only guards against pathological loops, not normal multi-fabric labs.
    for _ in range(50):
        round_seen_fis: dict[str, dict] = {}
        aliases = _known_host_aliases(db)
        port_guids = _known_port_guids(db)
        candidates = _active_discovery_hosts(db)
        sources = _discovery_vantages(db, candidates, queried, covered, args.jobs)
        if not sources:
            break
        queried.update(sources)
        for source, nodes in run_parallel(lambda host: _sa_query(host, args.timeout), sources, args.jobs, "discover"):
            for node in nodes:
                db.execute(
                    "INSERT OR REPLACE INTO fabric_node VALUES (?,?,?,?,?,?,datetime('now'))",
                    (node["guid"], node["type"], node["name"], node.get("vendor"), node.get("device"), source),
                )
                visible_guids.add(node["guid"].lower())
                observed_nodes[node["guid"].lower()] = node
                if node["type"].upper() == "FI":
                    seen_fis[node["guid"].lower()] = node
                    round_seen_fis[node["guid"].lower()] = node
        covered = {host for host, guids in port_guids.items() if guids & visible_guids}
        # A host is also on an already-answered fabric when its neighbor switch
        # appeared in an SA reply, and a host whose every active port is cabled
        # directly to another known host cannot lead to anything unknown.
        covered |= _fabric_covered_hosts(db, visible_guids)
        coverage_messages.append((len(sources), len(covered)))

        guid_owners = _guid_owner(db)
        new_hosts: set[str] = set()
        for node in round_seen_fis.values():
            guid = node["guid"].lower()
            hostname = _fi_hostname(node["name"])
            owner = guid_owners.get(guid)
            is_known = owner is not None or (hostname in aliases if hostname else False)
            if _is_unnamed_adapter(node["name"]):
                unnamed[guid] = owner
            elif hostname and not is_known and hostname not in discovered_hosts:
                new_hosts.add(hostname)

        for host in new_hosts:
            db.execute("INSERT OR IGNORE INTO host(name, source) VALUES (?, 'discovered')", (host,))
        db.commit()
        if not new_hosts:
            continue  # other fabrics may still be uncovered
        discovered_hosts.update(new_hosts)
        _probe_hosts(db, sorted(new_hosts), args, show_progress=True)

    cached_nodes = {
        guid.lower(): {"guid": guid, "type": node_type, "name": name}
        for guid, node_type, name in db.execute("SELECT guid, type, name FROM fabric_node")
    }
    cached_nodes.update(observed_nodes)
    seen_fis = {
        guid: node
        for guid, node in cached_nodes.items()
        if node["type"].upper() == "FI"
    }
    total_queries = sum(queried_count for queried_count, _ in coverage_messages)
    total_covered = coverage_messages[-1][1] if coverage_messages else 0
    print(
        f"Querying fabric SA from {total_queries} vantage host(s) (covering {total_covered} known hosts)",
        file=sys.stderr,
    )

    known_fis = sum(
        _guid_owner(db).get(guid) is not None or (_fi_hostname(node["name"]) in _known_host_aliases(db))
        for guid, node in seen_fis.items()
    )
    switch_count = db.execute("SELECT count(*) FROM fabric_node WHERE upper(type)='SW'").fetchone()[0]
    suffix = f": {', '.join(sorted(discovered_hosts))}" if discovered_hosts else ""
    print(f"Fabric: {len(seen_fis)} adapters seen, {known_fis} belong to known hosts, {len(discovered_hosts)} new host(s){suffix}")
    if unnamed:
        adapters = ", ".join(f"{guid} ({owner})" if owner else guid for guid, owner in sorted(unnamed.items()))
        print(f"Unnamed adapters: {adapters}")
    print(f"Switches: {switch_count}")
    if previously_discovered:
        print(f"Previously discovered hosts: {previously_discovered}")
    if removed_hosts:
        print(f"Removed bogus discovered hosts: {', '.join(sorted(removed_hosts))}", file=sys.stderr)
    return 0


def cmd_update(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Refresh Booked data, probe stale hosts, and optionally discover fabric hosts.

    The Booked fetch and the SSH probes are independent network waits, so they
    overlap: hosts already cached as stale start probing immediately while Booked
    is fetched on its own thread, and hosts that first appear in Booked join the
    same SSH pool as soon as the sync is stored. All SQLite writes stay on this
    thread. Discovery still runs last because it needs the fresh probe results.
    """
    tracker = _ProbeTracker(db, show_progress=getattr(args, "discover", False))
    booked_error: UserError | None = None
    with cf.ThreadPoolExecutor(1) as booked_pool, cf.ThreadPoolExecutor(args.jobs) as ssh_pool:
        booked = booked_pool.submit(fetch_booked, True)
        pending: set[cf.Future] = tracker.submit(ssh_pool, _stale_hosts(db, args), args.timeout)
        pending.add(booked)
        while pending:
            done, pending = cf.wait(pending, return_when=cf.FIRST_COMPLETED)
            for future in done:
                if future is not booked:
                    tracker.record(future.result())
                    continue
                try:
                    apply_booked(db, future.result())
                except UserError as error:
                    # Keep probing the cached hosts; report the Booked failure afterwards.
                    booked_error = error
                    continue
                stale = _stale_hosts(db, args)
                pending |= tracker.submit(ssh_pool, stale, args.timeout)
                _report_probe_plan(db, sorted(tracker.submitted), args)
    if tracker.submitted:
        tracker.summary()
    if booked_error is not None:
        raise booked_error
    if getattr(args, "discover", False):
        cmd_discover(db, args)
    return 0


# ---------------------------------------------------------------- reporting
def _paint(text: str, code: str) -> str:
    """Use ANSI styling only for interactive output that did not opt out."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def _age(timestamp: str | None) -> str:
    """Render SQLite's UTC timestamp as a compact relative cache age."""
    if not timestamp:
        return "never"
    try:
        then = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return timestamp
    seconds = max(0, int((datetime.now(timezone.utc) - then).total_seconds()))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _cache_hint(resource_count: int, synced_at: str | None) -> str | None:
    """Offer the one safe next step when cached Booked data is absent or stale."""
    if not resource_count:
        return "Cache is empty. Run 'update' to fetch Booked resources and probe hosts."
    try:
        stale = (datetime.now(timezone.utc) - datetime.strptime(synced_at or "", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds() > 86400
    except ValueError:
        stale = True
    return "Cache may be stale; run 'update' to refresh Booked data." if stale else None


def _status_data(db: sqlite3.Connection, db_path: Path) -> dict:
    resource_count, synced_at = db.execute("SELECT count(*), max(synced_at) FROM resource").fetchone()
    host_count, probed_count, reachable_count, oldest_probe, newest_probe = db.execute(
        "SELECT count(*), count(probed_at), sum(reachable), min(probed_at), max(probed_at) FROM host"
    ).fetchone()
    gpu_hosts, gpu_devices = db.execute("SELECT count(DISTINCT host), count(*) FROM gpu").fetchone()
    return {
        "database": str(db_path),
        "booked": {"resources": resource_count, "synced_at": synced_at, "age": _age(synced_at)},
        "hosts": {"known": host_count, "probed": probed_count, "reachable": reachable_count or 0, "unprobed": host_count - probed_count},
        "gpus": {"hosts": gpu_hosts, "devices": gpu_devices},
        "probes": {"oldest_at": oldest_probe, "newest_at": newest_probe, "newest_age": _age(newest_probe)},
        "hint": _cache_hint(resource_count, synced_at),
    }


def _json(payload: dict) -> None:
    """Write structured output alone, making it safe to pipe into scripts."""
    print(json.dumps(payload, indent=2, sort_keys=True))


TABLE_FORMATS = ("table", "json", "jsonl", "csv", "tsv")


def _output_format(args: argparse.Namespace) -> str:
    """--json is kept as a shorthand for --format json."""
    return "json" if getattr(args, "json", False) else getattr(args, "format", "table")


def _cell(value: object) -> str:
    """Flatten one value into a single spreadsheet/awk-friendly cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ";".join(_cell(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _emit_records(records: list[dict], fmt: str) -> None:
    """Write one record per line (jsonl) or per row with a header (csv/tsv)."""
    if fmt == "jsonl":
        for record in records:
            print(json.dumps(record, sort_keys=True))
        return
    columns: list[str] = []
    for record in records:
        columns += [key for key in record if key not in columns]
    writer = csv.writer(sys.stdout, delimiter="\t" if fmt == "tsv" else ",", lineterminator="\n")
    writer.writerow(columns)
    for record in records:
        writer.writerow([_cell(record.get(column)) for column in columns])


def cmd_status(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Show cache coverage and age without contacting Booked or SSH."""
    status = _status_data(db, args.db)
    if args.json:
        _json(status)
        return 0
    print(f"Cache: {status['database']}")
    print(f"  Booked:  {status['booked']['resources']} resources, last sync {status['booked']['synced_at'] or 'never'} UTC ({status['booked']['age']})")
    print(
        f"  Hosts:   {status['hosts']['known']} known, {status['hosts']['probed']} probed "
        f"({status['hosts']['reachable']} reachable), {status['hosts']['unprobed']} never probed"
    )
    print(f"  GPUs:    {status['gpus']['hosts']} probed host(s) ({status['gpus']['devices']} PCIe device(s))")
    print(f"  Probes:  oldest {status['probes']['oldest_at'] or '-'} UTC, newest {status['probes']['newest_at'] or '-'} UTC")
    if status["hint"]:
        print(f"Hint: {status['hint']}")
    return 0


def host_gen(db: sqlite3.Connection, host: str) -> str:
    """Classify a host strictly from PCI generation observations."""
    generations = {generation for (generation,) in db.execute("SELECT DISTINCT generation FROM adapter WHERE host=?", (host,))}
    return "+".join(sorted(generations)) if generations else "-"


def _host_gpus(db: sqlite3.Connection, host: str) -> list[dict]:
    """Return cached PCIe GPU rows for host in PCI address order."""
    return [
        {
            "pci_addr": pci,
            "vendor_id": vendor,
            "device_id": device,
            "pci_class": pci_class,
            "model": model,
            "description": description,
        }
        for pci, vendor, device, pci_class, model, description in db.execute(
            "SELECT pci_addr, vendor_id, device_id, pci_class, model, description FROM gpu WHERE host=? ORDER BY pci_addr",
            (host,),
        )
    ]


def _booked_gpus(db: sqlite3.Connection, host: str) -> list[str]:
    """Return distinct non-placeholder Booked GPU attributes mapped to host."""
    gpus: list[str] = []
    rows = db.execute(
        "SELECT r.attrs_json FROM resource_host rh JOIN resource r ON r.id=rh.resource_id "
        "WHERE rh.host=? ORDER BY r.name",
        (host,),
    )
    for (attrs_json,) in rows:
        if not attrs_json:
            continue
        try:
            gpu = (json.loads(attrs_json).get("GPU") or "").strip()
        except json.JSONDecodeError:
            gpu = ""
        if gpu and gpu.lower() not in _NO_GPU_VALUES and gpu not in gpus:
            gpus.append(gpu)
    return gpus


def host_gpu(db: sqlite3.Connection, host: str, gpus: list[dict] | None = None) -> str:
    """Summarize PCIe-probed GPUs for host, falling back to Booked GPU metadata when none are probed."""
    rows = _host_gpus(db, host) if gpus is None else gpus
    models = [gpu["model"] for gpu in rows if gpu["model"]]
    if models:
        counts: dict[str, int] = {}
        for model in models:
            counts[model] = counts.get(model, 0) + 1
        return " + ".join(f"{count}x {model}" if count > 1 else model for model, count in counts.items())
    booked = _booked_gpus(db, host)
    return " + ".join(booked) if booked else "-"


def _matches_gpu(filter_value: str | None, gpu_summary: str, gpus: list[dict]) -> bool:
    if filter_value is None:
        return True
    needle = filter_value.strip().lower()
    if needle in ("", "*", "any", "yes", "true"):
        return gpu_summary != "-"
    if needle in ("none", "no", "false", "-"):
        return gpu_summary == "-"
    if gpu_summary == "-":
        return False
    parts = [gpu_summary]
    for gpu in gpus:
        vendor = GPU_VENDORS.get(gpu["vendor_id"] or "", "")
        parts.extend(
            str(item)
            for item in (
                gpu["pci_addr"],
                vendor,
                f"{gpu['vendor_id']}:{gpu['device_id']}",
                gpu["pci_class"],
                gpu["model"],
                gpu["description"],
            )
            if item
        )
    return needle in " ".join(parts).lower()


def _short(value: str | None, length: int) -> str:
    """Fit verbose DMI strings into a readable fixed-width table cell."""
    cleaned = (value or "-").replace("(R)", "").replace("(TM)", "").replace(" CPU", "").replace(" Processor", "")
    cleaned = cleaned.replace("Red Hat Enterprise Linux", "RHEL")
    cleaned = " ".join(cleaned.split())
    return cleaned if len(cleaned) <= length else cleaned[: length - 1] + "~"


def _availability_is_stale(db: sqlite3.Connection) -> bool:
    """Return whether Booked availability is absent or older than the five-minute cache window."""
    resource_count, checked_at = db.execute("SELECT count(*), min(avail_checked_at) FROM resource").fetchone()
    if not resource_count or not checked_at:
        return bool(resource_count)
    try:
        checked = datetime.strptime(checked_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - checked).total_seconds() > 300


def _booked_summary(resources: list[dict]) -> tuple[str, str | None, str | None]:
    """Reduce zero or more mapped resource states to one host-facing Booked status."""
    if not resources:
        return "-", None, None
    states = {resource.get("avail_state") for resource in resources}
    if states == {"free"}:
        return "free", None, None
    unavailable = [resource for resource in resources if resource.get("avail_state") == "unavailable"]
    if unavailable:
        return "unavailable", None, None
    reserved = [resource for resource in resources if resource.get("avail_state") == "reserved"]
    until = min((resource.get("avail_at") for resource in reserved if resource.get("avail_at")), default=None)
    owners = sorted({resource.get("reserved_by") for resource in reserved if resource.get("reserved_by")})
    return "in use", until, ", ".join(owners) or None


def _booked_cell(status: str, until: str | None, owner: str | None, wide: bool) -> str:
    """Format the human-facing Booked status without losing structured timestamp fields."""
    if status != "in use" or not wide:
        return status
    time = _booked_datetime(until)
    suffix = ""
    if time:
        suffix = f" until {time.strftime('%H:%M')}" if time.date() == datetime.now(time.tzinfo).date() else f" until {time.strftime('%Y-%m-%d %H:%M')}"
    return f"in use{suffix}" + (f" by {owner}" if owner else "")


def _hsn_link(db: sqlite3.Connection, host: str, probed_at: str | None, reachable: bool | None) -> tuple[str, int, int]:
    """Summarize cached Cornelis OPA and Ethernet-mode port link states for one host."""
    if not probed_at or not reachable:
        return "-", 0, 0
    ports = list(db.execute("SELECT kind, state FROM port WHERE host=? AND state IS NOT NULL", (host,)))
    if not ports:
        return "-", 0, 0
    up = sum(state.lower() == "active" if kind == "opa" else state.lower() == "up" for kind, state in ports)
    total = len(ports)
    if up == total:
        return "up", up, total
    if not up:
        return "down", up, total
    return f"{up}/{total} up", up, total


def _normalise_link(value: str) -> str:
    """Accept case-insensitive user link filters while retaining canonical choices."""
    normalized = value.lower()
    if normalized not in {"up", "down", "partial"}:
        raise argparse.ArgumentTypeError("link must be up, down, or partial")
    return normalized


def _normalise_generation(value: str, allow_controls: bool = True) -> str:
    """Accept familiar generation spellings while retaining canonical cached labels."""
    key = value.strip().lower().replace("-", "")
    aliases = {"5000": "CN5000", "5k": "CN5000", "cn5000": "CN5000", "6000": "CN6000", "6k": "CN6000", "cn6000": "CN6000"}
    if allow_controls:
        aliases.update({"mixed": "mixed", "none": "none", "unprobed": "unprobed"})
    if key not in aliases:
        accepted = "5k, 6k, CN5000, or CN6000" + (", mixed, none, or unprobed" if allow_controls else "")
        raise argparse.ArgumentTypeError(f"unknown generation {value!r}; use {accepted}")
    return aliases[key]


def _list_entries(db: sqlite3.Connection, args: argparse.Namespace) -> tuple[list[dict], dict]:
    """Apply reporting filters once and return both rows and a useful summary."""
    rows = db.execute(
        "SELECT h.name, h.reachable, h.probed_at, h.source, h.model, h.cpu, h.os, r.name, "
        "r.avail_state, r.avail_until, r.avail_at, r.reserved_by "
        "FROM host h LEFT JOIN resource_host rh ON rh.host=h.name "
        "LEFT JOIN resource r ON r.id=rh.resource_id ORDER BY h.name, r.name"
    ).fetchall()
    hosts: dict[str, dict] = {}
    for name, reachable, probed_at, source, model, cpu, os_name, resource_name, avail_state, avail_until, avail_at, reserved_by in rows:
        entry = hosts.setdefault(
            name,
            {
                "host": name,
                "reachable": bool(reachable) if probed_at else None,
                "probed_at": probed_at,
                "source": source or "booked",
                "resources": [],
                "model": model,
                "cpu": cpu,
                "os": os_name,
            },
        )
        if resource_name:
            entry["resources"].append(
                {
                    "name": resource_name,
                    "avail_state": avail_state,
                    "avail_until": avail_until,
                    "avail_at": avail_at,
                    "reserved_by": reserved_by,
                }
            )
    entries: list[dict] = []
    for entry in hosts.values():
        name = entry["host"]
        reachable = entry["reachable"]
        probed_at = entry["probed_at"]
        source = entry["source"]
        generation = host_gen(db, name)
        gpus = _host_gpus(db, name)
        gpu = host_gpu(db, name, gpus)
        gpu_source = "pcie" if gpus else ("booked" if gpu != "-" else None)
        platform = ((args.model, entry["model"]), (args.cpu, entry["cpu"]), (args.os, entry["os"]))
        booked_status, booked_until, booked_by = _booked_summary(entry["resources"])
        hsn_link, hsn_ports_up, hsn_ports_total = _hsn_link(db, name, probed_at, reachable)
        if any(filter_value and filter_value.lower() not in (actual or "").lower() for filter_value, actual in platform):
            continue
        if not _matches_gpu(getattr(args, "gpu", None), gpu, gpus):
            continue
        if args.source and source != args.source:
            continue
        if args.reachable and not reachable:
            continue
        if args.available and booked_status != "free":
            continue
        if args.link and (args.link == "partial") != (hsn_ports_total > 0 and 0 < hsn_ports_up < hsn_ports_total):
            continue
        if args.link in ("up", "down") and hsn_link != args.link:
            continue
        if args.gen == "mixed" and "+" not in generation:
            continue
        if args.gen == "none" and not (reachable and generation == "-"):
            continue
        if args.gen == "unprobed" and probed_at:
            continue
        if args.gen in ("CN5000", "CN6000") and args.gen not in generation:
            continue
        entry.update(
            {
                "generation": generation,
                "gpu": None if gpu == "-" else gpu,
                "gpu_count": len(gpus),
                "gpu_source": gpu_source,
                "resources": [resource["name"] for resource in entry["resources"]],
                "hsn_link": hsn_link,
                "hsn_ports_up": hsn_ports_up,
                "hsn_ports_total": hsn_ports_total,
                "booked_status": booked_status,
                "booked_until": booked_until,
                "booked_by": booked_by,
            }
        )
        entries.append(entry)
    summary = {
        "hosts": len(entries),
        "CN5000": sum(entry["generation"] == "CN5000" for entry in entries),
        "CN6000": sum(entry["generation"] == "CN6000" for entry in entries),
        "mixed": sum("+" in entry["generation"] for entry in entries),
        "gpu": sum(bool(entry["gpu"]) for entry in entries),
        "unprobed": sum(entry["probed_at"] is None for entry in entries),
    }
    return entries, summary


def cmd_list(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Print filtered cache entries with a count users can verify at a glance."""
    if not args.offline and _availability_is_stale(db):
        try:
            refresh_availability(db)
        except UserError:
            checked_at = db.execute("SELECT min(avail_checked_at) FROM resource").fetchone()[0]
            print(f"Warning: Booked availability refresh failed; using cached values ({_age(checked_at)}).", file=sys.stderr)
    entries, summary = _list_entries(db, args)
    resource_count, synced_at = db.execute("SELECT count(*), max(synced_at) FROM resource").fetchone()
    hint = _cache_hint(resource_count, synced_at)
    probe_filters = args.model or args.cpu or args.os or (args.gen and args.gen.lower() != "unprobed")
    if not hint and probe_filters:
        unprobed = db.execute("SELECT count(*) FROM host WHERE probed_at IS NULL").fetchone()[0]
        if unprobed:
            hint = (f"{unprobed} host(s) have not been probed, so their model/CPU/OS/generation are unknown "
                    "and they cannot match these filters. Run 'cnhwinv probe' (or 'cnhwinv update') first.")
    fmt = _output_format(args)
    if fmt == "json":
        _json({"hosts": entries, "summary": summary, "hint": hint})
        return 0
    if fmt != "table":
        _emit_records(entries, fmt)
        return 0

    wide = bool(args.wide or args.model or args.cpu or args.os)
    show_gpu = bool(wide or getattr(args, "gpu", None))
    if wide:
        print(f"{'HOST':<26} {'GEN':<14} {'REACH':<9} {'LINK':<10} {'BOOKED':<42} {'MODEL':<34} {'CPU':<44} {'GPU':<30} {'OS':<34} RESOURCES")
    elif show_gpu:
        print(f"{'HOST':<26} {'GEN':<14} {'REACH':<9} {'LINK':<10} {'BOOKED':<12} {'GPU':<30} RESOURCES")
    else:
        print(f"{'HOST':<26} {'GEN':<14} {'REACH':<9} {'LINK':<10} {'BOOKED':<12} RESOURCES")
    for entry in entries:
        reach = "unprobed" if entry["probed_at"] is None else ("yes" if entry["reachable"] else "no")
        generation = entry["generation"]
        gen_color = "36" if generation == "CN5000" else "35" if generation == "CN6000" else "33"
        # Pad before coloring: ANSI escapes must not count toward visible column width.
        rendered_gen = _paint(f"{generation:<14}", gen_color)
        host_cell = f"{entry['host']:<26}"
        rendered_host = _paint(host_cell, "2") if entry["reachable"] is False else host_cell
        resources = "(not in Booked; discovered on fabric)" if entry["source"] == "discovered" else ", ".join(entry["resources"])
        link = entry["hsn_link"]
        link_color = "32" if link == "up" else "31" if link == "down" else "33" if link.endswith(" up") else None
        rendered_link = _paint(f"{link:<10}", link_color) if link_color else f"{link:<10}"
        booked = _booked_cell(entry["booked_status"], entry["booked_until"], entry["booked_by"], wide)
        booked_color = {"free": "32", "in use": "33", "unavailable": "31"}.get(entry["booked_status"])
        rendered_booked = _paint(f"{booked:<42}" if wide else f"{booked:<12}", booked_color) if booked_color else (f"{booked:<42}" if wide else f"{booked:<12}")
        if wide:
            print(
                f"{rendered_host} {rendered_gen} {reach:<9} {rendered_link} {rendered_booked} {_short(entry['model'], 34):<34} "
                f"{_short(entry['cpu'], 44):<44} {_short(entry['gpu'], 30):<30} {_short(entry['os'], 34):<34} {resources}"
            )
        elif show_gpu:
            print(f"{rendered_host} {rendered_gen} {reach:<9} {rendered_link} {rendered_booked} {_short(entry['gpu'], 30):<30} {resources}")
        else:
            print(f"{rendered_host} {rendered_gen} {reach:<9} {rendered_link} {rendered_booked} {resources}")
    print(
        f"{summary['hosts']} host{'s' if summary['hosts'] != 1 else ''} "
        f"({summary['CN5000']} CN5000, {summary['CN6000']} CN6000, "
        f"{summary['mixed']} mixed, {summary['gpu']} GPU, {summary['unprobed']} unprobed)"
    )
    if hint:
        print(f"Hint: {hint}")
    return 0


def _guid_owner(db: sqlite3.Connection) -> dict[str, str]:
    """Map case-insensitive sysfs and SMA GUID forms to their local host port."""
    owners = {
        guid.lower(): f"{host}:{interface}"
        for guid, host, interface in db.execute("SELECT node_guid, host, ifname FROM port WHERE node_guid IS NOT NULL")
    }
    owners.update(
        {
            guid.lower(): f"{host}:{interface}"
            for guid, host, interface in db.execute("SELECT port_guid, host, ifname FROM port WHERE port_guid IS NOT NULL")
        }
    )
    return owners


def _link_records(db: sqlite3.Connection, where: str, params: tuple) -> list[dict]:
    """Produce link facts in a shape useful to both the text and JSON reporters."""
    owners = _guid_owner(db)
    switch_names = dict(db.execute("SELECT guid, name FROM fabric_node WHERE type='SW'"))
    query = (
        "SELECT p.host, p.ifname, p.port, p.kind, p.state, p.neighbor_type, p.neighbor_guid, "
        "p.neighbor_port, p.mac, p.lldp_json, a.generation "
        "FROM port p LEFT JOIN adapter a ON a.host=p.host AND a.pci_addr=p.pci_addr "
        f"WHERE {where} ORDER BY p.neighbor_guid, p.neighbor_port, p.host, p.ifname, p.port"
    )
    links: list[dict] = []
    for host, interface, port, kind, state, neighbor_type, neighbor_guid, neighbor_port, mac, lldp_json, generation in db.execute(query, params):
        local = f"{host}:{interface}" + (f"/{port}" if kind == "opa" else "")
        peer: str
        direct = False
        if kind == "eth":
            lldp = json.loads(lldp_json) if lldp_json else None
            peer = f"LLDP {lldp['chassis']} port {lldp['port']}" if lldp else "(no LLDP neighbor data)"
        elif neighbor_guid:
            peer_host = owners.get(neighbor_guid)
            switch_name = switch_names.get(neighbor_guid)
            direct = peer_host is not None
            identity = peer_host or (f"{switch_name!r} {neighbor_guid}" if switch_name else neighbor_guid)
            peer = f"{neighbor_type} {identity} port {neighbor_port}" + (" [direct host-to-host]" if direct else "")
        elif neighbor_type and neighbor_type.startswith("query-failed"):
            peer = f"(neighbor unknown: {neighbor_type[14:]})"
        else:
            peer = "(no neighbor reported; link down)"
        links.append(
            {
                "host": host,
                "interface": interface,
                "port": port,
                "kind": kind,
                "state": state,
                "generation": generation,
                "mac": mac,
                "neighbor_type": neighbor_type,
                "neighbor_guid": neighbor_guid,
                "neighbor_port": neighbor_port,
                "peer": peer,
                "direct_host_link": direct,
                "local": local,
            }
        )
    return links


def _print_links(db: sqlite3.Connection, where: str, params: tuple) -> None:
    """Retain a simple textual helper for callers that want one host's links."""
    for link in _link_records(db, where, params):
        print(f"  {link['local']:<34} {link['generation'] or '?':<7} {link['state'] or '?':<7} -> {link['peer']}")


def _fabric_groups(db: sqlite3.Connection) -> list[dict]:
    """Group host ports by their common switch GUID to show fabric membership."""
    groups: list[dict] = []
    query = (
        "SELECT neighbor_guid, group_concat(host || ':' || ifname || '/' || port || '->p' || neighbor_port, '  ') "
        "FROM port WHERE neighbor_type='Switch' GROUP BY neighbor_guid ORDER BY neighbor_guid"
    )
    for guid, members in db.execute(query):
        name = db.execute("SELECT name FROM fabric_node WHERE guid=?", (guid,)).fetchone()
        groups.append({"guid": guid, "name": name[0] if name else None, "members": members})
    return groups


def _resource_detail(db: sqlite3.Connection, resource_id: int) -> dict:
    """Gather every cached Booked resource fact plus mapped-host summaries."""
    row = db.execute(
        "SELECT id, name, schedule_id, status_id, description, notes, hosts_raw, attrs_json, synced_at, "
        "avail_state, avail_until, avail_at, reserved_by, avail_checked_at FROM resource WHERE id=?",
        (resource_id,),
    ).fetchone()
    if not row:
        raise UserError(f"Booked resource {resource_id}: not in database")
    attributes = json.loads(row[7]) if row[7] else {}
    mapped_hosts = [
        {
            "host": host,
            "generation": host_gen(db, host),
            "gpu": None if (gpu := host_gpu(db, host)) == "-" else gpu,
            "reachable": bool(reachable) if probed_at else None,
            "probed_at": probed_at,
        }
        for host, reachable, probed_at in db.execute(
            "SELECT h.name, h.reachable, h.probed_at FROM resource_host rh JOIN host h ON h.name=rh.host "
            "WHERE rh.resource_id=? ORDER BY h.name",
            (resource_id,),
        )
    ]
    return {
        "resource_id": row[0],
        "name": row[1],
        "schedule_id": row[2],
        "status_id": row[3],
        "status": {"0": "Hidden", "1": "Available", "2": "Unavailable"}.get(str(row[3]), f"Unknown ({row[3]})"),
        "description": mask(row[4]) or None,
        "notes": mask(row[5]) or None,
        "raw_hosts": mask(row[6]) or None,
        "attributes": {label: mask(value) for label, value in attributes.items() if value},
        "synced_at": row[8],
        "synced_age": _age(row[8]),
        "avail_state": row[9],
        "avail_until": row[10],
        "avail_at": row[11],
        "reserved_by": row[12],
        "avail_checked_at": row[13],
        "avail_checked_age": _age(row[13]),
        "mapped_hosts": mapped_hosts,
    }


def _port_detail(db: sqlite3.Connection, host: str) -> list[dict]:
    """Gather all stored port columns with resolved fabric neighbor names."""
    owners = _guid_owner(db)
    switch_names = dict(db.execute("SELECT guid, name FROM fabric_node WHERE type='SW'"))
    ports: list[dict] = []
    for row in db.execute(
        "SELECT ifname, port, pci_addr, kind, node_guid, port_guid, state, phys_state, lid, neighbor_type, "
        "neighbor_guid, neighbor_port, mac, netdev, lldp_json FROM port WHERE host=? ORDER BY kind, ifname, port",
        (host,),
    ):
        lldp = json.loads(row[14]) if row[14] else None
        neighbor_name = owners.get((row[10] or "").lower()) or switch_names.get(row[10])
        ports.append(
            {
                "ifname": row[0],
                "port": row[1],
                "pci_addr": row[2],
                "kind": row[3],
                "node_guid": row[4],
                "port_guid": row[5],
                "state": row[6],
                "phys_state": row[7],
                "lid": row[8],
                "neighbor_type": row[9],
                "neighbor_guid": row[10],
                "neighbor_port": row[11],
                "neighbor_name": neighbor_name,
                "mac": row[12],
                "netdev": row[13],
                "lldp": lldp,
            }
        )
    return ports


def _host_detail(db: sqlite3.Connection, host: str) -> dict:
    """Gather every cached host fact, including complete mapped-resource details."""
    row = db.execute(
        "SELECT name, probed_at, reachable, error, fqdn, source, model, cpu, sockets, cores, os, kernel FROM host WHERE name=?",
        (host,),
    ).fetchone()
    if not row:
        raise UserError(f"{host}: not in database")
    resources = [
        _resource_detail(db, resource_id)
        for (resource_id,) in db.execute("SELECT resource_id FROM resource_host WHERE host=? ORDER BY resource_id", (host,))
    ]
    adapters = [
        {"pci_addr": pci, "device_id": device, "generation": generation, "pci_class": pci_class, "description": description}
        for pci, device, generation, pci_class, description in db.execute(
            "SELECT pci_addr, device_id, generation, pci_class, description FROM adapter WHERE host=? ORDER BY pci_addr", (host,)
        )
    ]
    gpus = _host_gpus(db, host)
    gpu_summary = host_gpu(db, host, gpus)
    gpu_source = "pcie" if gpus else ("booked" if gpu_summary != "-" else None)
    return {
        "host": row[0],
        "generation": host_gen(db, row[0]),
        "gpu": None if gpu_summary == "-" else gpu_summary,
        "gpu_source": gpu_source,
        "probed_at": row[1],
        "reachable": bool(row[2]) if row[1] else None,
        "error": row[3],
        "fqdn": row[4],
        "source": row[5] or "booked",
        "model": row[6],
        "cpu": row[7],
        "sockets": row[8],
        "cores": row[9],
        "os": row[10],
        "kernel": row[11],
        "resources": resources,
        "adapters": adapters,
        "gpus": gpus,
        "ports": _port_detail(db, host),
    }


def _print_multiline(label: str, value: str | None, indent: str = "  ") -> None:
    """Print a non-empty multiline cached field with continuation indentation."""
    if not value:
        return
    lines = value.splitlines() or [value]
    print(f"{indent}{label}: {lines[0]}")
    for line in lines[1:]:
        print(f"{indent}  {line}")


def _full_booked_time(value: str | None) -> str | None:
    """Render a Booked timestamp as a full local date and time for detail output."""
    time = _booked_datetime(value)
    return time.strftime("%Y-%m-%d %H:%M %z") if time else value


def _print_resource_detail(detail: dict, indent: str = "") -> None:
    """Render every non-empty cached Booked resource field safely for terminals."""
    print(f"{indent}Booked resource {detail['resource_id']}: {detail['name']}")
    if detail["schedule_id"] is not None:
        print(f"{indent}  Schedule: {detail['schedule_id']}")
    print(f"{indent}  Status: {detail['status']}")
    if detail["avail_state"]:
        print(f"{indent}  Availability: {detail['avail_state']}")
    if detail["reserved_by"]:
        print(f"{indent}  Reserved by: {detail['reserved_by']}")
    if detail["avail_until"]:
        print(f"{indent}  Available until: {_full_booked_time(detail['avail_until'])}")
    if detail["avail_at"]:
        print(f"{indent}  Free again at: {_full_booked_time(detail['avail_at'])}")
    if detail["avail_checked_at"]:
        print(f"{indent}  Availability checked: {detail['avail_checked_at']} UTC ({detail['avail_checked_age']})")
    if detail["synced_at"]:
        print(f"{indent}  Synced: {detail['synced_at']} UTC ({detail['synced_age']})")
    _print_multiline("Description", detail["description"], indent + "  ")
    _print_multiline("Notes", detail["notes"], indent + "  ")
    if detail["attributes"]:
        print(f"{indent}  Attributes:")
        for label, value in detail["attributes"].items():
            _print_multiline(label, value, indent + "    ")
    _print_multiline("Raw hosts", detail["raw_hosts"], indent + "  ")
    if detail["mapped_hosts"]:
        print(f"{indent}  Mapped hosts:")
        for host in detail["mapped_hosts"]:
            reach = "unprobed" if host["reachable"] is None else ("yes" if host["reachable"] else "no")
            gpu = f"  gpu={host['gpu']}" if host.get("gpu") else ""
            power = f"  power={_power_text(host['power'])}" if "power" in host else ""
            print(f"{indent}    {host['host']}  gen={host['generation']}{gpu}  reachable={reach}{power}")


def _print_host_detail(detail: dict) -> None:
    """Render every non-empty cached host, adapter, GPU, port, and resource fact."""
    print(f"Host: {detail['host']}")
    for label, key in (("Generation", "generation"), ("GPU", "gpu"), ("Source", "source"), ("FQDN", "fqdn"), ("Probed", "probed_at"), ("Model", "model"), ("CPU", "cpu"), ("Sockets", "sockets"), ("Cores", "cores"), ("OS", "os"), ("Kernel", "kernel"), ("Error", "error")):
        if detail[key] is not None:
            value = f"{detail[key]} (Booked)" if key == "gpu" and detail.get("gpu_source") == "booked" else detail[key]
            print(f"  {label}: {value}")
    if detail["reachable"] is not None:
        print(f"  Reachable: {'yes' if detail['reachable'] else 'no'}")
    if "power" in detail:
        power = detail["power"]
        print(f"  Power (BMC {power['bmc']}): {_power_text(power)}")
    if detail["adapters"]:
        print("  Adapters:")
        for adapter in detail["adapters"]:
            fields = [adapter["pci_addr"], adapter["generation"], f"[434e:{adapter['device_id']}]", adapter["pci_class"], adapter["description"]]
            print("    " + "  ".join(str(field) for field in fields if field))
    if detail["gpus"]:
        print("  GPUs:")
        for gpu in detail["gpus"]:
            fields = [gpu["pci_addr"], gpu["model"], f"[{gpu['vendor_id']}:{gpu['device_id']}]", gpu["pci_class"], gpu["description"]]
            print("    " + "  ".join(str(field) for field in fields if field))
    if detail["ports"]:
        print("  Ports:")
        for port in detail["ports"]:
            print(f"    {port['kind']} {port['ifname']}/{port['port']}")
            for label, key in (("PCI", "pci_addr"), ("State", "state"), ("Physical state", "phys_state"), ("LID", "lid"), ("Node GUID", "node_guid"), ("Port GUID", "port_guid"), ("MAC", "mac"), ("Netdev", "netdev")):
                if port[key] is not None:
                    print(f"      {label}: {port[key]}")
            if port["neighbor_type"] or port["neighbor_guid"] or port["neighbor_port"] is not None:
                neighbor = " ".join(str(value) for value in (port["neighbor_type"], port["neighbor_name"] or port["neighbor_guid"], f"port {port['neighbor_port']}" if port["neighbor_port"] is not None else None) if value)
                print(f"      Neighbor: {neighbor}")
            if port["lldp"]:
                print(f"      LLDP: {json.dumps(port['lldp'], sort_keys=True)}")
    for resource in detail["resources"]:
        _print_resource_detail(resource, "  ")


def _refresh_show_availability(db: sqlite3.Connection, offline: bool) -> None:
    """Refresh stale Booked availability for show unless the caller requires cached-only data."""
    if offline or not _availability_is_stale(db):
        return
    try:
        refresh_availability(db)
    except UserError:
        checked_at = db.execute("SELECT min(avail_checked_at) FROM resource").fetchone()[0]
        print(f"Warning: Booked availability refresh failed; using cached values ({_age(checked_at)}).", file=sys.stderr)


def _show_detail(db: sqlite3.Connection, args: argparse.Namespace, kind: str, key) -> int:
    """Build, optionally BMC-annotate, and print one host or resource detail."""
    detail = _host_detail(db, key) if kind == "host" else _resource_detail(db, key)
    if not (args.offline or args.no_power):
        if kind == "host":
            detail["power"] = bmc_power_many([detail["host"]])[detail["host"]]
        else:
            powers = bmc_power_many([host["host"] for host in detail["mapped_hosts"]])
            for host in detail["mapped_hosts"]:
                host["power"] = powers[host["host"]]
    if args.json:
        _json(detail)
    elif kind == "host":
        _print_host_detail(detail)
    else:
        _print_resource_detail(detail)
    return 0


def cmd_show(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Resolve host/resource names and show complete cache facts plus live BMC power."""
    _refresh_show_availability(db, args.offline)
    query = args.host.strip().lower()
    hosts = [host for (host,) in db.execute("SELECT name FROM host ORDER BY name")]
    resources = [(resource_id, name) for resource_id, name in db.execute("SELECT id, name FROM resource ORDER BY name")]
    exact_hosts = [host for host in hosts if host.lower() == query]
    short_hosts = [host for host in hosts if host.lower().split(".", 1)[0] == query]
    exact_resources = [resource for resource in resources if resource[1].lower() == query]
    host_matches = [host for host in hosts if query in host.lower()]
    resource_matches = [resource for resource in resources if query in resource[1].lower()]

    if exact_hosts:
        return _show_detail(db, args, "host", exact_hosts[0])
    if len(short_hosts) == 1:
        return _show_detail(db, args, "host", short_hosts[0])
    if exact_resources:
        return _show_detail(db, args, "resource", exact_resources[0][0])
    if len(host_matches) > 1:
        raise UserError(f"{args.host!r} matches multiple hosts: {', '.join(host_matches)}")
    if len(resource_matches) > 1:
        raise UserError(f"{args.host!r} matches multiple Booked resources: {', '.join(name for _, name in resource_matches)}")
    if host_matches and resource_matches:
        candidates = [host_matches[0], resource_matches[0][1]]
        raise UserError(f"{args.host!r} matches multiple cached items: {', '.join(candidates)}")
    if host_matches:
        return _show_detail(db, args, "host", host_matches[0])
    if resource_matches:
        return _show_detail(db, args, "resource", resource_matches[0][0])

    names = hosts + [name for _, name in resources]
    suggestions = difflib.get_close_matches(query, names, n=5, cutoff=0.45)
    suffix = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
    raise UserError(f"{args.host!r} is not in the cache.{suffix}")


def cmd_links(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Report cached peer evidence and common-switch fabric membership."""
    where, params = ("a.generation=?", (args.gen,)) if args.gen else ("1=1", ())
    links = _link_records(db, where, params)
    groups = _fabric_groups(db)
    fmt = _output_format(args)
    if fmt == "json":
        _json({"links": links, "fabrics": groups})
        return 0
    if fmt != "table":
        # Flat formats carry the per-port link records; fabric groups are derived from them.
        _emit_records(links, fmt)
        return 0
    for link in links:
        print(f"  {link['local']:<34} {link['generation'] or '?':<7} {link['state'] or '?':<7} -> {link['peer']}")
    print("\nFabrics (hosts sharing a neighbor switch GUID):")
    for group in groups:
        name = f" ({group['name']})" if group["name"] else ""
        print(f"  switch {group['guid']}{name}: {group['members']}")
    return 0


# ---------------------------------------------------------------- Booked checkout / checkin
# These are the only code paths that write to Booked; everything else stays read-only.
_DURATION_RE = re.compile(r"(\d+)\s*([dhm])", re.IGNORECASE)
_DURATION_UNITS = {"d": 86400, "h": 3600, "m": 60}
DEFAULT_CHECKOUT = "8h"


def _parse_duration(value: str) -> timedelta:
    """Parse '90m', '4h', '2d', or '1h30m' into a positive timedelta."""
    text = value.strip().lower().replace(" ", "")
    if text.isdigit():
        # A bare number is hours; that is what people mean by "check it out for 4".
        text += "h"
    parts = _DURATION_RE.findall(text)
    if not parts or "".join(f"{n}{u}" for n, u in parts) != text:
        raise argparse.ArgumentTypeError(f"invalid duration {value!r}; use e.g. 30m, 4h, 2d, or 1h30m")
    seconds = sum(int(number) * _DURATION_UNITS[unit] for number, unit in parts)
    if seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be positive")
    return timedelta(seconds=seconds)


def _parse_when(value: str, now: datetime) -> datetime:
    """Parse an ISO timestamp or HH:MM (next occurrence) as local time."""
    text = value.strip()
    clock = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if clock:
        hour, minute = int(clock.group(1)), int(clock.group(2))
        if hour > 23 or minute > 59:
            raise UserError(f"invalid time {value!r}")
        moment = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        return moment if moment > now else moment + timedelta(days=1)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as error:
        raise UserError(f"invalid time {value!r}; use HH:MM or YYYY-MM-DDTHH:MM") from error
    return moment.astimezone() if moment.tzinfo else moment.replace(tzinfo=now.tzinfo)


def _resolve_resource(db: sqlite3.Connection, query: str) -> tuple[int, str]:
    """Map a resource name or host name (full, short, or unique partial) to one Booked resource."""
    needle = query.strip().lower()
    resources = list(db.execute("SELECT id, name FROM resource ORDER BY name"))
    if not resources:
        raise UserError("No Booked resources cached. Run `cnhwinv sync-booked` first.")

    def host_resources(where: str, param: str) -> list[tuple[int, str]]:
        return list(
            db.execute(
                "SELECT DISTINCT r.id, r.name FROM resource_host rh JOIN resource r ON r.id=rh.resource_id "
                f"WHERE {where} ORDER BY r.name",
                (param,),
            )
        )

    exact = [resource for resource in resources if resource[1].lower() == needle]
    if exact:
        return exact[0]
    for where, param in (
        ("lower(rh.host)=?", needle),
        ("lower(rh.host) LIKE ? ESCAPE '\\'", needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + ".%"),
    ):
        mapped = host_resources(where, param)
        if len(mapped) == 1:
            return mapped[0]
        if len(mapped) > 1:
            names = ", ".join(name for _, name in mapped)
            raise UserError(f"Host {query!r} belongs to several Booked resources: {names}. Check out one by name.")
    partial = [resource for resource in resources if needle in resource[1].lower()]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        raise UserError(f"{query!r} matches multiple Booked resources: {', '.join(name for _, name in partial)}")
    hosts = {host for (host,) in db.execute("SELECT DISTINCT host FROM resource_host") if needle in host.lower()}
    if len(hosts) == 1:
        return _resolve_resource(db, hosts.pop())
    if len(hosts) > 1:
        raise UserError(f"{query!r} matches multiple hosts: {', '.join(sorted(hosts))}")
    names = [name for _, name in resources] + [host for (host,) in db.execute("SELECT DISTINCT host FROM resource_host")]
    suggestions = difflib.get_close_matches(needle, names, n=5, cutoff=0.45)
    suffix = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
    raise UserError(f"{query!r} is not a cached Booked resource or mapped host.{suffix}")


def _booked_timestamp(moment: datetime) -> str:
    return moment.astimezone().replace(microsecond=0).isoformat()


def _my_reservations(headers: dict[str, str], now: datetime, resource_id: int | None, horizon: timedelta) -> list[dict]:
    """Return the session user's reservations that have not ended yet (optionally for one resource)."""
    params = {
        "userId": headers["X-Booked-UserId"],
        "startDateTime": _booked_timestamp(now),
        "endDateTime": _booked_timestamp(now + horizon),
    }
    if resource_id is not None:
        params["resourceId"] = str(resource_id)
    payload = _call(f"/Reservations/?{urllib.parse.urlencode(params)}", headers=headers)
    mine = []
    for reservation in payload.get("reservations") or []:
        end = _booked_datetime(reservation.get("endDate"))
        if str(reservation.get("userId")) != headers["X-Booked-UserId"] or (end is not None and end <= now):
            continue
        if resource_id is not None and str(reservation.get("resourceId")) != str(resource_id):
            continue
        mine.append(reservation)
    return sorted(mine, key=lambda reservation: reservation.get("startDate") or "")


def _refresh_after_write(db: sqlite3.Connection) -> None:
    """Keep the cached availability truthful after a write; a failure here is only a warning."""
    try:
        refresh_availability(db)
    except UserError as error:
        print(f"Warning: could not refresh cached availability: {error}", file=sys.stderr)


def cmd_checkout(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Create a Booked reservation for a resource (or the resource a host belongs to)."""
    resource_id, resource_name = _resolve_resource(db, args.name)
    now = datetime.now().astimezone().replace(second=0, microsecond=0)
    start = _parse_when(args.start, now) if args.start else now
    if args.until:
        end = _parse_when(args.until, start)
    else:
        end = start + (args.duration or _parse_duration(DEFAULT_CHECKOUT))
    if end <= start:
        raise UserError("End time must be after the start time.")
    request = {
        "resourceId": resource_id,
        "startDateTime": _booked_timestamp(start),
        "endDateTime": _booked_timestamp(end),
        "title": args.title or f"cnhwinv checkout: {resource_name}",
        "description": args.description or "",
    }
    summary = {"resource_id": resource_id, "resource": resource_name, "start": request["startDateTime"], "end": request["endDateTime"]}
    if args.dry_run:
        if args.json:
            _json({**summary, "dry_run": True})
        else:
            print(f"Would check out {resource_name} (resource {resource_id}) from {request['startDateTime']} until {request['endDateTime']}.")
        return 0
    with _booked_session() as headers:
        request["userId"] = int(headers["X-Booked-UserId"])
        result = _call("/Reservations/", request, headers=headers)
    reference = result.get("referenceNumber")
    if not reference:
        message = result.get("message") or "no reference number returned"
        raise UserError(f"Booked did not confirm the reservation: {message}")
    summary.update(reference=reference, pending_approval=bool(result.get("isPendingApproval")))
    _refresh_after_write(db)
    if args.json:
        _json(summary)
        return 0
    print(f"Checked out {resource_name} until {_full_booked_time(summary['end'])} (reference {reference}).")
    if summary["pending_approval"]:
        print("Note: this reservation is pending approval by a Booked administrator.")
    return 0


def cmd_checkin(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Release your own Booked reservation(s) for a resource, or list what you have checked out."""
    now = datetime.now().astimezone()
    horizon = timedelta(days=args.days)
    resource = _resolve_resource(db, args.name) if args.name else None
    with _booked_session() as headers:
        mine = _my_reservations(headers, now, resource[0] if resource else None, horizon)
        if args.ref:
            mine = [reservation for reservation in mine if reservation.get("referenceNumber") == args.ref]
        if not args.name:
            # Without a target this is a listing; never release anything implicitly.
            if args.json:
                _json({"reservations": mine})
            elif not mine:
                print(f"You have no Booked reservations in the next {args.days} days.")
            else:
                for reservation in mine:
                    print(
                        f"  {reservation.get('resourceName') or reservation.get('resourceId'):<28} "
                        f"{_full_booked_time(reservation.get('startDate'))} -> {_full_booked_time(reservation.get('endDate'))}  "
                        f"{reservation.get('referenceNumber')}"
                    )
            return 0
        if not mine:
            raise UserError(f"You have no current or upcoming reservation for {resource[1]}.")
        if len(mine) > 1 and not (args.all or args.ref):
            listing = ", ".join(
                f"{reservation.get('referenceNumber')} ({_full_booked_time(reservation.get('startDate'))})" for reservation in mine
            )
            raise UserError(f"You have {len(mine)} reservations for {resource[1]}: {listing}. Use --ref or --all.")
        released = []
        for reservation in mine:
            reference = reservation["referenceNumber"]
            _call(f"/Reservations/{urllib.parse.quote(reference)}?updateScope=this", headers=headers, method="DELETE")
            released.append(reference)
    _refresh_after_write(db)
    if args.json:
        _json({"resource": resource[1], "released": released})
    else:
        print(f"Checked in {resource[1]} (released {', '.join(released)}).")
    return 0


# ---------------------------------------------------------------- CLI setup
def _subparser(
    subparsers: argparse._SubParsersAction,
    name: str,
    *,
    help_text: str,
    examples: str,
    aliases: list[str] | None = None,
) -> argparse.ArgumentParser:
    """Give every subcommand a concise purpose and directly runnable examples."""
    return subparsers.add_parser(
        name,
        aliases=aliases or [],
        help=help_text,
        description=help_text,
        epilog=f"Examples:\n  {examples}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def _generation_argument(value: str) -> str:
    return _normalise_generation(value, allow_controls=True)


def _link_generation_argument(value: str) -> str:
    return _normalise_generation(value, allow_controls=False)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser separately so tests can guarantee compatibility."""
    parser = argparse.ArgumentParser(
        description=TOP_DESCRIPTION,
        epilog=TOP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, metavar="PATH", help="SQLite cache path (default: %(default)s)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color even in a terminal")
    parser.add_argument("--debug", action="store_true", help="show a traceback when a command fails")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="cmd", title="commands", metavar="COMMAND")

    _subparser(
        subparsers,
        "sync-booked",
        help_text="Fetch Booked resources into the local cache (no SSH).",
        examples="cnhwinv sync-booked",
    )

    def probe_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--jobs", type=int, default=128, help="parallel SSH sessions (default: 128)")
        command.add_argument("--timeout", type=int, default=60, help="per-host timeout in seconds (default: 60)")
        command.add_argument("--max-age", type=float, default=24, metavar="HOURS", help="probe cache freshness window (default: 24)")
        command.add_argument("--force", action="store_true", help="ignore cached probes")

    probe = _subparser(
        subparsers,
        "probe",
        help_text="Read-only SSH probe of named or stale cached hosts.",
        examples="cnhwinv probe cn123\n  cnhwinv probe --force --jobs 8",
    )
    probe.add_argument("hosts", nargs="*", help="specific hosts to probe")
    probe_options(probe)

    update = _subparser(
        subparsers,
        "update",
        aliases=["refresh"],
        help_text="Refresh Booked resources and read-only probe stale hosts.",
        examples="cnhwinv update --max-age 24\n  cnhwinv refresh --discover",
    )
    update.set_defaults(hosts=[])
    probe_options(update)
    update.add_argument("--discover", action="store_true", help="also find unbooked hosts through read-only fabric SA queries")

    discover = _subparser(
        subparsers,
        "discover",
        help_text="Discover unbooked fabric hosts using read-only SA queries.",
        examples="cnhwinv discover --jobs 8",
    )
    discover.add_argument("--jobs", type=int, default=128, help="parallel SSH sessions for SA queries and probes (default: 128)")
    discover.add_argument("--timeout", type=int, default=60, help="per-host timeout in seconds (default: 60)")

    status = _subparser(
        subparsers,
        "status",
        help_text="Show local cache age and probe coverage without network access.",
        examples="cnhwinv status\n  cnhwinv status --json",
    )
    status.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    listing = _subparser(
        subparsers,
        "list",
        aliases=["ls"],
        help_text="List cached hosts; refreshes Booked availability older than five minutes unless --offline is used.",
        examples="cnhwinv ls --gen 6k --reachable -w\n  cnhwinv list --gpu\n  cnhwinv list --gpu nvidia --available\n  cnhwinv list --available\n  cnhwinv list --link down --gen 5k\n  cnhwinv list --offline --source discovered --json\n  cnhwinv ls --gen 5k -o csv > cn5000.csv\n  cnhwinv ls -o tsv | awk -F'\\t' '$3==\"yes\"{print $1}'",
    )
    listing.add_argument("--gen", type=_generation_argument, metavar="GEN", help="5k/6k/CN5000/CN6000, mixed, none, or unprobed")
    listing.add_argument("--reachable", action="store_true", help="only latest probes that were reachable")
    listing.add_argument("--wide", "-w", action="store_true", help="also show server model, CPU, GPU, and OS")
    listing.add_argument("--model", help="filter server model substring (case-insensitive)")
    listing.add_argument("--cpu", help="filter CPU model substring (case-insensitive)")
    listing.add_argument("--gpu", nargs="?", const="*", metavar="GPU", help="only hosts with a GPU, or filter GPU model/vendor substring (or 'none')")
    listing.add_argument("--os", help="filter OS substring (case-insensitive)")
    listing.add_argument("--source", choices=["booked", "discovered"], help="filter Booked or fabric-discovered hosts")
    listing.add_argument("--available", action="store_true", help="only hosts whose mapped Booked resources are all free")
    listing.add_argument("--link", type=_normalise_link, metavar="STATE", help="filter HSN link: up, down, or partial")
    listing.add_argument("--offline", action="store_true", help="do not refresh Booked availability; use cached values only")
    listing.add_argument("--json", action="store_true", help="shorthand for --format json")
    listing.add_argument("--format", "-o", choices=TABLE_FORMATS, default="table", help="output format: table (default), json, jsonl, csv, or tsv")

    show = _subparser(
        subparsers,
        "show",
        help_text="Show complete cached facts plus live BMC power status; refreshes Booked availability older than five minutes unless --offline is used.",
        examples="cnhwinv show cn123\n  cnhwinv show cn123 --offline\n  cnhwinv show 'Rack A' --json\n  cnhwinv show 'Rack A' --no-power",
    )
    show.add_argument("host", metavar="HOST_OR_RESOURCE", help="case-insensitive full or unique partial name")
    show.add_argument("--offline", action="store_true", help="cached values only: no Booked refresh and no BMC queries")
    show.add_argument("--no-power", action="store_true", help="skip the read-only BMC chassis power query")
    show.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    links = _subparser(
        subparsers,
        "links",
        help_text="Show cached fabric and Ethernet neighbor evidence.",
        examples="cnhwinv links\n  cnhwinv links --gen CN6000 --json\n  cnhwinv links -o csv",
    )
    links.add_argument("--gen", type=_link_generation_argument, metavar="GEN", help="5k/6k/CN5000, or CN6000")
    links.add_argument("--json", action="store_true", help="shorthand for --format json")
    links.add_argument("--format", "-o", choices=TABLE_FORMATS, default="table", help="output format: table (default), json, jsonl, csv, or tsv")

    checkout = _subparser(
        subparsers,
        "checkout",
        aliases=["reserve"],
        help_text=f"Reserve a Booked resource (by resource or host name) for yourself; default {DEFAULT_CHECKOUT} starting now.",
        examples="cnhwinv checkout cn123\n  cnhwinv checkout 'Rack A' --for 2d\n  cnhwinv checkout cn123 --start 09:00 --until 17:00\n  cnhwinv checkout cn123 --for 90m --dry-run",
    )
    checkout.add_argument("name", metavar="HOST_OR_RESOURCE", help="resource name, or a host mapped to exactly one resource")
    timing = checkout.add_mutually_exclusive_group()
    timing.add_argument("--for", dest="duration", type=_parse_duration, metavar="DURATION", help=f"length, e.g. 30m, 4h, 2d, 1h30m (default: {DEFAULT_CHECKOUT})")
    timing.add_argument("--until", metavar="TIME", help="end time: HH:MM (next occurrence) or YYYY-MM-DDTHH:MM")
    checkout.add_argument("--start", metavar="TIME", help="start time: HH:MM or YYYY-MM-DDTHH:MM (default: now)")
    checkout.add_argument("--title", help="reservation title (default: 'cnhwinv checkout: <resource>')")
    checkout.add_argument("--description", help="reservation description")
    checkout.add_argument("--dry-run", "-n", action="store_true", help="show what would be reserved without contacting Booked")
    checkout.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    checkin = _subparser(
        subparsers,
        "checkin",
        aliases=["release"],
        help_text="Release your Booked reservation for a resource; with no name, list your reservations.",
        examples="cnhwinv checkin\n  cnhwinv checkin cn123\n  cnhwinv checkin 'Rack A' --all",
    )
    checkin.add_argument("name", nargs="?", metavar="HOST_OR_RESOURCE", help="resource name, or a host mapped to exactly one resource")
    checkin.add_argument("--ref", metavar="REFERENCE", help="release only this reservation reference number")
    checkin.add_argument("--all", action="store_true", help="release every current/upcoming reservation you hold on the resource")
    checkin.add_argument("--days", type=int, default=30, help="how far ahead to look for your reservations (default: 30)")
    checkin.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def open_db(path: Path) -> sqlite3.Connection:
    """Open and migrate the cache, reporting filesystem/database failures cleanly."""
    db_path = path.expanduser()
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(db_path)
        db.executescript(SCHEMA)
        columns = {row[1] for row in db.execute("PRAGMA table_info(host)")}
        for column in ("source", "model", "cpu", "sockets", "cores", "os", "kernel"):
            if column not in columns:
                declaration = "TEXT DEFAULT 'booked'" if column == "source" else "TEXT"
                db.execute(f"ALTER TABLE host ADD COLUMN {column} {declaration}")
        resource_columns = {row[1] for row in db.execute("PRAGMA table_info(resource)")}
        for column in ("avail_state", "avail_until", "avail_at", "reserved_by", "avail_checked_at"):
            if column not in resource_columns:
                db.execute(f"ALTER TABLE resource ADD COLUMN {column} TEXT")
        db.commit()
        return db
    except (OSError, sqlite3.Error) as error:
        raise UserError(f"Cannot open cache database {db_path}: {error}") from error


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and convert expected local/network errors into helpful status codes."""
    global _USE_COLOR
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not arguments:
        parser.print_help()
        return 0
    args = parser.parse_args(arguments)
    _USE_COLOR = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    commands: dict[str, Callable[[sqlite3.Connection, argparse.Namespace], int]] = {
        "update": cmd_update,
        "refresh": cmd_update,
        "discover": cmd_discover,
        "status": cmd_status,
        "sync-booked": cmd_sync_booked,
        "probe": cmd_probe,
        "list": cmd_list,
        "ls": cmd_list,
        "show": cmd_show,
        "links": cmd_links,
        "checkout": cmd_checkout,
        "reserve": cmd_checkout,
        "checkin": cmd_checkin,
        "release": cmd_checkin,
    }
    if args.db == DEFAULT_DB and not DEFAULT_DB.exists() and LEGACY_DB.exists():
        # Carry the cache over from the pre-rename location instead of starting empty.
        DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
        LEGACY_DB.rename(DEFAULT_DB)
        print(f"Moved cache {LEGACY_DB} -> {DEFAULT_DB}", file=sys.stderr)
    try:
        db = open_db(args.db)
        try:
            return commands[args.cmd](db, args)
        finally:
            db.close()
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except UserError as error:
        if args.debug:
            traceback.print_exc()
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error, urllib.error.URLError) as error:
        if args.debug:
            traceback.print_exc()
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except Exception as error:  # Top-level CLI boundary: --debug intentionally exposes this traceback.
        if args.debug:
            traceback.print_exc()
        else:
            print(f"Error: unexpected failure ({error}). Re-run with --debug for details.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Behave normally when a downstream pipe such as head closes early.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    sys.exit(main())
