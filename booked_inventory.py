#!/usr/bin/env python3
# noqa: SIZE_OK — the requested single-file CLI owns its complete offline inventory workflow.
"""Inventory Cornelis lab hosts from Booked Scheduler and read-only SSH probes.

The SQLite cache is the reporting source of truth: `list`, `show`, `links`, and
`status` never contact Booked or any lab host. Use `update` to refresh it.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import difflib
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

VERSION = "1.0.0"
BOOKED_API = "http://booked.cornelisnetworks.com/Web/Services/index.php"
HOSTS_ATTR_ID = 2
CN_VENDOR = "434e"
GEN_BY_DEVICE = {"0001": "CN5000", "0002": "CN6000"}
DEFAULT_DB = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "booked-inventory/inventory.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS fabric_node (
  guid TEXT PRIMARY KEY, type TEXT, name TEXT, vendor_id TEXT, device_id TEXT,
  seen_from TEXT, seen_at TEXT);
CREATE TABLE IF NOT EXISTS resource (
  id INTEGER PRIMARY KEY, name TEXT, schedule_id INTEGER, status_id INTEGER,
  description TEXT, notes TEXT, hosts_raw TEXT, attrs_json TEXT, synced_at TEXT);
CREATE TABLE IF NOT EXISTS host (
  name TEXT PRIMARY KEY, probed_at TEXT, reachable INTEGER, error TEXT, fqdn TEXT,
  source TEXT DEFAULT 'booked', model TEXT, cpu TEXT, sockets TEXT, cores TEXT,
  os TEXT, kernel TEXT);
CREATE TABLE IF NOT EXISTS resource_host (
  resource_id INTEGER, host TEXT, PRIMARY KEY (resource_id, host));
CREATE TABLE IF NOT EXISTS adapter (
  host TEXT, pci_addr TEXT, device_id TEXT, generation TEXT, pci_class TEXT,
  description TEXT, PRIMARY KEY (host, pci_addr));
CREATE TABLE IF NOT EXISTS port (
  host TEXT, ifname TEXT, port INTEGER, pci_addr TEXT, kind TEXT,
  node_guid TEXT, port_guid TEXT, state TEXT, phys_state TEXT, lid TEXT,
  neighbor_type TEXT, neighbor_guid TEXT, neighbor_port INTEGER,
  mac TEXT, netdev TEXT, lldp_json TEXT,
  PRIMARY KEY (host, ifname, port));
"""

TOP_DESCRIPTION = """Inspect the local Booked Scheduler inventory cache without touching lab hosts.

`update` is the only convenience command that contacts Booked and SSH-probes
hosts. Remote probes and discovery are strictly read-only."""
TOP_EPILOG = """Common examples:
  booked_inventory.py status
  booked_inventory.py update --max-age 24
  booked_inventory.py ls --gen 6k --reachable -w
  booked_inventory.py show cn123
  booked_inventory.py links --gen CN5000
  booked_inventory.py --db /tmp/inventory.db list --json
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


def _call(path: str, data: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> dict:
    """Call the Booked REST API and turn transport failures into one clear error."""
    request = urllib.request.Request(
        BOOKED_API + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise UserError("Booked Scheduler is unreachable or returned an invalid response. Check VPN/network access.") from error


def booked_resources() -> list[dict]:
    """Authenticate to Booked, return resources, then invalidate its session."""
    user, password = _creds()
    auth = _call("/Authentication/Authenticate", {"username": user, "password": password})
    if not auth.get("isAuthenticated"):
        raise UserError("Booked authentication failed. Check the configured credentials.")
    headers = {"X-Booked-SessionToken": auth["sessionToken"], "X-Booked-UserId": str(auth["userId"])}
    try:
        return _call("/Resources/", headers=headers)["resources"]
    finally:
        _call("/Authentication/SignOut", {"userId": auth["userId"], "sessionToken": auth["sessionToken"]})


def cmd_sync_booked(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Replace Booked resource metadata and preserve the local probe cache."""
    resources = booked_resources()
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
            "INSERT OR REPLACE INTO resource VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
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
    host_count = db.execute("SELECT count(DISTINCT host) FROM resource_host").fetchone()[0]
    print(f"Synced {len(resources)} resources, {host_count} hosts")
    return 0


# ---------------------------------------------------------------- SSH probe
# Every command below is read-only. `timeout` bounds each so a wedged tool
# cannot hang the probe. No sudo is used (no password prompts, no privilege).
REMOTE_SCRIPT = r"""
export LC_ALL=C PATH=$PATH:/usr/sbin:/sbin
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
echo "@@LSPCI"; timeout 10 lspci -Dnn -d 434e: 2>/dev/null
echo "@@IB"
for d in /sys/class/infiniband/*; do [ -d "$d" ] || continue
  [ "$(cat $d/device/vendor 2>/dev/null)" = "0x434e" ] || continue
  dev=$(basename "$d"); pci=$(basename "$(readlink -f "$d/device")")
  for p in "$d"/ports/*; do n=$(basename "$p")
    echo "PORT|$dev|$n|$pci|$(cat $d/node_guid 2>/dev/null)|$(cat $p/state 2>/dev/null)|$(cat $p/phys_state 2>/dev/null)|$(cat $p/lid 2>/dev/null)"
    idx=${dev##*_}; idx=$((idx+1))
    echo "@@SMA|$dev|$n"
    timeout 10 opasmaquery -o portinfo -h "$idx" -p "$n" 2>&1 | grep -E 'NeighborNodeType|NeighborNodeGuid|failed'
    timeout 10 opasmaquery -o nodeinfo -h "$idx" -p "$n" 2>/dev/null | grep -E '^\s*NodeGuid'
    echo "@@END"
  done
done
echo "@@NET"
for n in /sys/class/net/*; do [ -e "$n/device" ] || continue
  pci=$(basename "$(readlink -f "$n/device")")
  ven=$(cat "$n/device/vendor" 2>/dev/null)
  [ "$ven" = "0x434e" ] && [ "$(cat $n/type)" = "1" ] && echo "NET|$(basename $n)|$pci|$(cat $n/address)|$(cat $n/operstate)|$(cat $n/dev_port 2>/dev/null)"
done
echo "@@LLDP"
command -v lldpctl >/dev/null && timeout 10 lldpctl -f json 2>/dev/null
echo "@@DONE"
"""


def ssh_probe(host: str, timeout: int) -> dict:
    """Run the read-only inventory script over SSH and return its raw response."""
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        host,
        "bash -s",
    ]
    try:
        process = subprocess.run(command, input=REMOTE_SCRIPT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"host": host, "error": "timeout"}
    if "@@DONE" not in process.stdout:
        return {"host": host, "error": (process.stderr.strip().splitlines() or ["ssh failed"])[-1][:200]}
    return {"host": host, "out": process.stdout}


def parse_probe(output: str) -> dict:
    """Parse stable section markers emitted by REMOTE_SCRIPT into cached facts."""
    result: dict = {"fqdn": None, "adapters": [], "ports": [], "net": [], "lldp": None, "sys": {}}
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
            match = re.match(r"(\S+)\s+(.*?)\s+\[(\w{4})\]:\s+(.*)\[434e:(\w{4})\]", line)
            if match:
                result["adapters"].append(
                    {
                        "pci": match.group(1),
                        "class": match.group(2),
                        "desc": match.group(4).strip(),
                        "device": match.group(5),
                        "gen": GEN_BY_DEVICE.get(match.group(5), "CN-unknown"),
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
    db.execute("DELETE FROM port WHERE host=?", (host,))
    for adapter in probe["adapters"]:
        db.execute(
            "INSERT OR REPLACE INTO adapter VALUES (?,?,?,?,?,?)",
            (host, adapter["pci"], adapter["device"], adapter["gen"], adapter["class"], adapter["desc"]),
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


def cmd_probe(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Probe explicit or stale hosts, retaining partial results after interruption."""
    if args.hosts:
        hosts = [host.lower() for host in args.hosts]
    elif args.force:
        hosts = [row[0] for row in db.execute("SELECT name FROM host ORDER BY name")]
    else:
        hosts = [
            row[0]
            for row in db.execute(
                "SELECT name FROM host WHERE probed_at IS NULL OR probed_at < datetime('now', ?) "
                "OR (reachable=1 AND cpu IS NULL AND os IS NULL) ORDER BY name",
                (f"-{args.max_age} hours",),
            )
        ]
    if not hosts:
        total = db.execute("SELECT count(*) FROM host").fetchone()[0]
        print("No hosts known; run 'update' first." if not total else f"All {total} hosts are fresh; use --force to re-probe.")
        return 0
    _probe_hosts(db, hosts, args, show_progress=getattr(args, "discover", False))
    return 0


def _probe_hosts(db: sqlite3.Connection, hosts: list[str], args: argparse.Namespace, show_progress: bool = False) -> None:
    """Probe hosts concurrently and commit each result so Ctrl-C loses less work."""
    for host in hosts:
        db.execute("INSERT OR IGNORE INTO host(name) VALUES (?)", (host,))
    reachable = completed = 0
    with cf.ThreadPoolExecutor(args.jobs) as executor:
        futures = [executor.submit(ssh_probe, host, args.timeout) for host in hosts]
        if show_progress:
            progress(0, len(hosts), "probe")
        for future in cf.as_completed(futures):
            result = future.result()
            store_probe(db, result)
            completed += 1
            reachable += "error" not in result
            db.commit()
            if show_progress:
                progress(completed, len(hosts), "probe", result["host"])
            else:
                status = "ok" if "error" not in result else "FAIL: " + result["error"]
                print(f"  [{completed}/{len(hosts)}] {result['host']:<28} {status}", file=sys.stderr)
    print(f"Probed {len(hosts)} hosts, {reachable} reachable")


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
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        host,
        "bash -s",
    ]
    try:
        process = subprocess.run(command, input=DISCOVER_SCRIPT, capture_output=True, text=True, timeout=timeout)
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


def cmd_discover(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Discover unbooked hosts from read-only SA node records, then probe them."""
    queried: set[str] = set()
    discovered_total = 0
    for round_number in range(1, 6):
        sources = [
            host
            for (host,) in db.execute(
                "SELECT DISTINCT h.name FROM host h JOIN port p ON p.host=h.name "
                "WHERE h.reachable=1 AND p.kind='opa' AND p.state='ACTIVE'"
            )
            if host not in queried
        ]
        if not sources:
            break
        queried.update(sources)
        print(f"Discovery round {round_number}: querying fabric SA from {len(sources)} hosts", file=sys.stderr)
        results = run_parallel(lambda host: _sa_query(host, args.timeout), sources, args.jobs, "discover")
        known = {host for (host,) in db.execute("SELECT name FROM host")}
        new_hosts: set[str] = set()
        for source, nodes in results:
            for node in nodes:
                db.execute(
                    "INSERT OR REPLACE INTO fabric_node VALUES (?,?,?,?,?,?,datetime('now'))",
                    (node["guid"], node["type"], node["name"], node.get("vendor"), node.get("device"), source),
                )
                hostname = _fi_hostname(node["name"]) if node["type"] == "FI" else None
                if hostname and hostname not in known:
                    new_hosts.add(hostname)
        for host in new_hosts:
            db.execute("INSERT OR IGNORE INTO host(name, source) VALUES (?, 'discovered')", (host,))
        db.commit()
        suffix = f": {', '.join(sorted(new_hosts))}" if new_hosts else ""
        print(f"  found {len(new_hosts)} new host(s) not in Booked{suffix}", file=sys.stderr)
        if not new_hosts:
            break
        discovered_total += len(new_hosts)
        _probe_hosts(db, sorted(new_hosts), args, show_progress=True)
    switch_count = db.execute("SELECT count(*) FROM fabric_node WHERE type='SW'").fetchone()[0]
    print(f"Discovery complete: {discovered_total} new host(s), {switch_count} switch(es) recorded")
    return 0


def cmd_update(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Refresh Booked data, probe stale hosts, and optionally discover fabric hosts."""
    cmd_sync_booked(db, args)
    cmd_probe(db, args)
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
    return {
        "database": str(db_path),
        "booked": {"resources": resource_count, "synced_at": synced_at, "age": _age(synced_at)},
        "hosts": {"known": host_count, "probed": probed_count, "reachable": reachable_count or 0, "unprobed": host_count - probed_count},
        "probes": {"oldest_at": oldest_probe, "newest_at": newest_probe, "newest_age": _age(newest_probe)},
        "hint": _cache_hint(resource_count, synced_at),
    }


def _json(payload: dict) -> None:
    """Write structured output alone, making it safe to pipe into scripts."""
    print(json.dumps(payload, indent=2, sort_keys=True))


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
    print(f"  Probes:  oldest {status['probes']['oldest_at'] or '-'} UTC, newest {status['probes']['newest_at'] or '-'} UTC")
    if status["hint"]:
        print(f"Hint: {status['hint']}")
    return 0


def host_gen(db: sqlite3.Connection, host: str) -> str:
    """Classify a host strictly from PCI generation observations."""
    generations = {generation for (generation,) in db.execute("SELECT DISTINCT generation FROM adapter WHERE host=?", (host,))}
    return "+".join(sorted(generations)) if generations else "-"


def _short(value: str | None, length: int) -> str:
    """Fit verbose DMI strings into a readable fixed-width table cell."""
    cleaned = (value or "-").replace("(R)", "").replace("(TM)", "").replace(" CPU", "").replace(" Processor", "")
    cleaned = cleaned.replace("Red Hat Enterprise Linux", "RHEL")
    cleaned = " ".join(cleaned.split())
    return cleaned if len(cleaned) <= length else cleaned[: length - 1] + "~"


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
        "SELECT h.name, h.reachable, h.probed_at, group_concat(DISTINCT r.name), h.source, h.model, h.cpu, h.os "
        "FROM host h LEFT JOIN resource_host rh ON rh.host=h.name "
        "LEFT JOIN resource r ON r.id=rh.resource_id GROUP BY h.name ORDER BY h.name"
    ).fetchall()
    entries: list[dict] = []
    for name, reachable, probed_at, resources, source, model, cpu, os_name in rows:
        generation = host_gen(db, name)
        platform = ((args.model, model), (args.cpu, cpu), (args.os, os_name))
        if any(filter_value and filter_value.lower() not in (actual or "").lower() for filter_value, actual in platform):
            continue
        if args.source and (source or "booked") != args.source:
            continue
        if args.reachable and not reachable:
            continue
        if args.gen == "mixed" and "+" not in generation:
            continue
        if args.gen == "none" and not (reachable and generation == "-"):
            continue
        if args.gen == "unprobed" and probed_at:
            continue
        if args.gen in ("CN5000", "CN6000") and args.gen not in generation:
            continue
        entries.append(
            {
                "host": name,
                "generation": generation,
                "reachable": bool(reachable) if probed_at else None,
                "probed_at": probed_at,
                "source": source or "booked",
                "resources": [] if source == "discovered" else (resources.split(",") if resources else []),
                "model": model,
                "cpu": cpu,
                "os": os_name,
            }
        )
    summary = {
        "hosts": len(entries),
        "CN5000": sum(entry["generation"] == "CN5000" for entry in entries),
        "CN6000": sum(entry["generation"] == "CN6000" for entry in entries),
        "mixed": sum("+" in entry["generation"] for entry in entries),
        "unprobed": sum(entry["probed_at"] is None for entry in entries),
    }
    return entries, summary


def cmd_list(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Print filtered cache entries with a count users can verify at a glance."""
    entries, summary = _list_entries(db, args)
    resource_count, synced_at = db.execute("SELECT count(*), max(synced_at) FROM resource").fetchone()
    hint = _cache_hint(resource_count, synced_at)
    if args.json:
        _json({"hosts": entries, "summary": summary, "hint": hint})
        return 0

    wide = args.wide or args.model or args.cpu or args.os
    if wide:
        print(f"{'HOST':<26} {'GEN':<14} {'REACH':<9} {'MODEL':<34} {'CPU':<44} {'OS':<34} RESOURCES")
    else:
        print(f"{'HOST':<26} {'GEN':<14} {'REACH':<9} RESOURCES")
    for entry in entries:
        reach = "unprobed" if entry["probed_at"] is None else ("yes" if entry["reachable"] else "no")
        generation = entry["generation"]
        gen_color = "36" if generation == "CN5000" else "35" if generation == "CN6000" else "33"
        # Pad before coloring: ANSI escapes must not count toward visible column width.
        rendered_gen = _paint(f"{generation:<14}", gen_color)
        host_cell = f"{entry['host']:<26}"
        rendered_host = _paint(host_cell, "2") if entry["reachable"] is False else host_cell
        resources = "(not in Booked; discovered on fabric)" if entry["source"] == "discovered" else ", ".join(entry["resources"])
        if wide:
            print(
                f"{rendered_host} {rendered_gen} {reach:<9} {_short(entry['model'], 34):<34} "
                f"{_short(entry['cpu'], 44):<44} {_short(entry['os'], 34):<34} {resources}"
            )
        else:
            print(f"{rendered_host} {rendered_gen} {reach:<9} {resources}")
    print(
        f"{summary['hosts']} host{'s' if summary['hosts'] != 1 else ''} "
        f"({summary['CN5000']} CN5000, {summary['CN6000']} CN6000, "
        f"{summary['mixed']} mixed, {summary['unprobed']} unprobed)"
    )
    if hint:
        print(f"Hint: {hint}")
    return 0


def _guid_owner(db: sqlite3.Connection) -> dict[str, str]:
    """Map both sysfs and SMA node GUID forms to their locally probed host port."""
    owners = {guid: f"{host}:{interface}" for guid, host, interface in db.execute("SELECT node_guid, host, ifname FROM port WHERE node_guid IS NOT NULL")}
    owners.update({guid: f"{host}:{interface}" for guid, host, interface in db.execute("SELECT port_guid, host, ifname FROM port WHERE port_guid IS NOT NULL")})
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


def _host_detail(db: sqlite3.Connection, host: str) -> dict:
    """Gather all local cache facts for a resolved host name."""
    row = db.execute(
        "SELECT name, probed_at, reachable, error, fqdn, source, model, cpu, sockets, cores, os, kernel FROM host WHERE name=?",
        (host,),
    ).fetchone()
    if not row:
        raise UserError(f"{host}: not in database")
    resources = [
        {"id": resource_id, "name": name}
        for resource_id, name in db.execute(
            "SELECT r.id, r.name FROM resource r JOIN resource_host rh ON rh.resource_id=r.id WHERE rh.host=? ORDER BY r.name",
            (host,),
        )
    ]
    adapters = [
        {"pci_addr": pci, "device_id": device, "generation": generation, "pci_class": pci_class, "description": description}
        for pci, device, generation, pci_class, description in db.execute(
            "SELECT pci_addr, device_id, generation, pci_class, description FROM adapter WHERE host=? ORDER BY pci_addr", (host,)
        )
    ]
    return {
        "host": row[0],
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
        "links": _link_records(db, "p.host=?", (host,)),
    }


def _print_host_detail(detail: dict) -> None:
    """Render one host's cached facts for an interactive terminal."""
    print(
        f"Host: {detail['host']}  fqdn={detail['fqdn'] or '-'}  reachable="
        f"{'unprobed' if detail['reachable'] is None else detail['reachable']}  probed={detail['probed_at'] or '-'}  {detail['error'] or ''}"
    )
    if detail["reachable"]:
        print(f"  Model:  {detail['model'] or '?'}")
        socket_detail = f"  ({detail['sockets']} socket(s), {detail['cores']} logical CPUs)" if detail["sockets"] else ""
        print(f"  CPU:    {detail['cpu'] or '?'}{socket_detail}")
        print(f"  OS:     {detail['os'] or '?'}  (kernel {detail['kernel'] or '?'})")
    for resource in detail["resources"]:
        print(f"  Booked resource {resource['id']}: {resource['name']}")
    for adapter in detail["adapters"]:
        print(
            f"  {adapter['pci_addr']}  {adapter['generation']}  [434e:{adapter['device_id']}]  "
            f"{adapter['pci_class']}  {adapter['description']}"
        )
    for link in detail["links"]:
        print(f"  {link['local']:<34} {link['generation'] or '?':<7} {link['state'] or '?':<7} -> {link['peer']}")


def _resource_detail(db: sqlite3.Connection, resource_id: int) -> dict:
    """Gather the hosts assigned to a Booked resource without reaching Booked."""
    resource = db.execute("SELECT id, name FROM resource WHERE id=?", (resource_id,)).fetchone()
    hosts = [host for (host,) in db.execute("SELECT host FROM resource_host WHERE resource_id=? ORDER BY host", (resource_id,))]
    return {"resource_id": resource[0], "name": resource[1], "hosts": hosts}


def cmd_show(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Resolve host/resource names flexibly and show cache facts or helpful candidates."""
    query = args.host.strip().lower()
    hosts = [host for (host,) in db.execute("SELECT name FROM host ORDER BY name")]
    resources = [(resource_id, name) for resource_id, name in db.execute("SELECT id, name FROM resource ORDER BY name")]
    exact_hosts = [host for host in hosts if host.lower() == query]
    exact_resources = [resource for resource in resources if resource[1].lower() == query]
    host_matches = [host for host in hosts if query in host.lower()]
    resource_matches = [resource for resource in resources if query in resource[1].lower()]

    if exact_hosts:
        detail = _host_detail(db, exact_hosts[0])
        if args.json:
            _json(detail)
        else:
            _print_host_detail(detail)
        return 0
    if exact_resources:
        detail = _resource_detail(db, exact_resources[0][0])
        if args.json:
            _json(detail)
        else:
            print(f"Booked resource {detail['resource_id']}: {detail['name']}")
            print(f"Hosts ({len(detail['hosts'])}):")
            for host in detail["hosts"]:
                print(f"  {host}")
        return 0
    if len(host_matches) > 1:
        raise UserError(f"{args.host!r} matches multiple hosts: {', '.join(host_matches)}")
    if len(resource_matches) > 1:
        raise UserError(f"{args.host!r} matches multiple Booked resources: {', '.join(name for _, name in resource_matches)}")
    if host_matches and resource_matches:
        candidates = [host_matches[0], resource_matches[0][1]]
        raise UserError(f"{args.host!r} matches multiple cached items: {', '.join(candidates)}")
    if host_matches:
        detail = _host_detail(db, host_matches[0])
        if args.json:
            _json(detail)
        else:
            _print_host_detail(detail)
        return 0
    if resource_matches:
        detail = _resource_detail(db, resource_matches[0][0])
        if args.json:
            _json(detail)
        else:
            print(f"Booked resource {detail['resource_id']}: {detail['name']}")
            print(f"Hosts ({len(detail['hosts'])}):")
            for host in detail["hosts"]:
                print(f"  {host}")
        return 0

    names = hosts + [name for _, name in resources]
    suggestions = difflib.get_close_matches(query, names, n=5, cutoff=0.45)
    suffix = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
    raise UserError(f"{args.host!r} is not in the cache.{suffix}")


def cmd_links(db: sqlite3.Connection, args: argparse.Namespace) -> int:
    """Report cached peer evidence and common-switch fabric membership."""
    where, params = ("a.generation=?", (args.gen,)) if args.gen else ("1=1", ())
    links = _link_records(db, where, params)
    groups = _fabric_groups(db)
    if args.json:
        _json({"links": links, "fabrics": groups})
        return 0
    for link in links:
        print(f"  {link['local']:<34} {link['generation'] or '?':<7} {link['state'] or '?':<7} -> {link['peer']}")
    print("\nFabrics (hosts sharing a neighbor switch GUID):")
    for group in groups:
        name = f" ({group['name']})" if group["name"] else ""
        print(f"  switch {group['guid']}{name}: {group['members']}")
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
        examples="booked_inventory.py sync-booked",
    )

    def probe_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--jobs", type=int, default=16, help="parallel SSH sessions (default: 16)")
        command.add_argument("--timeout", type=int, default=60, help="per-host timeout in seconds (default: 60)")
        command.add_argument("--max-age", type=float, default=24, metavar="HOURS", help="probe cache freshness window (default: 24)")
        command.add_argument("--force", action="store_true", help="ignore cached probes")

    probe = _subparser(
        subparsers,
        "probe",
        help_text="Read-only SSH probe of named or stale cached hosts.",
        examples="booked_inventory.py probe cn123\n  booked_inventory.py probe --force --jobs 8",
    )
    probe.add_argument("hosts", nargs="*", help="specific hosts to probe")
    probe_options(probe)

    update = _subparser(
        subparsers,
        "update",
        aliases=["refresh"],
        help_text="Refresh Booked resources and read-only probe stale hosts.",
        examples="booked_inventory.py update --max-age 24\n  booked_inventory.py refresh --discover",
    )
    update.set_defaults(hosts=[])
    probe_options(update)
    update.add_argument("--discover", action="store_true", help="also find unbooked hosts through read-only fabric SA queries")

    discover = _subparser(
        subparsers,
        "discover",
        help_text="Discover unbooked fabric hosts using read-only SA queries.",
        examples="booked_inventory.py discover --jobs 8",
    )
    discover.add_argument("--jobs", type=int, default=16, help="parallel SA queries (default: 16)")
    discover.add_argument("--timeout", type=int, default=60, help="per-host timeout in seconds (default: 60)")

    status = _subparser(
        subparsers,
        "status",
        help_text="Show local cache age and probe coverage without network access.",
        examples="booked_inventory.py status\n  booked_inventory.py status --json",
    )
    status.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    listing = _subparser(
        subparsers,
        "list",
        aliases=["ls"],
        help_text="List cached hosts; use filters without contacting Booked or SSH.",
        examples="booked_inventory.py ls --gen 6k --reachable -w\n  booked_inventory.py list --source discovered --json",
    )
    listing.add_argument("--gen", type=_generation_argument, metavar="GEN", help="5k/6k/CN5000/CN6000, mixed, none, or unprobed")
    listing.add_argument("--reachable", action="store_true", help="only latest probes that were reachable")
    listing.add_argument("--wide", "-w", action="store_true", help="also show server model, CPU, and OS")
    listing.add_argument("--model", help="filter server model substring (case-insensitive)")
    listing.add_argument("--cpu", help="filter CPU model substring (case-insensitive)")
    listing.add_argument("--os", help="filter OS substring (case-insensitive)")
    listing.add_argument("--source", choices=["booked", "discovered"], help="filter Booked or fabric-discovered hosts")
    listing.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    show = _subparser(
        subparsers,
        "show",
        help_text="Show one host or one Booked resource from the cache.",
        examples="booked_inventory.py show cn123\n  booked_inventory.py show 'Rack A' --json",
    )
    show.add_argument("host", metavar="HOST_OR_RESOURCE", help="case-insensitive full or unique partial name")
    show.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    links = _subparser(
        subparsers,
        "links",
        help_text="Show cached fabric and Ethernet neighbor evidence.",
        examples="booked_inventory.py links\n  booked_inventory.py links --gen CN6000 --json",
    )
    links.add_argument("--gen", type=_link_generation_argument, metavar="GEN", help="5k/6k/CN5000, or CN6000")
    links.add_argument("--json", action="store_true", help="emit machine-readable JSON")
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
    }
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
