"""Regression tests for the offline, stdlib-only cnhwinv (Cornelis Networks Hardware Inventory) CLI."""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

_TEST_HOME = tempfile.TemporaryDirectory()
os.environ["XDG_DATA_HOME"] = _TEST_HOME.name
os.environ["XDG_STATE_HOME"] = _TEST_HOME.name

import cnhwinv as bi


PROBE_OUTPUT = """@@FQDN cn-host01.example.com
@@SYS
SYS|vendor|Cornelis Networks
SYS|model|CN6000 Test Platform
SYS|cpu|Intel(R) Xeon(R) Gold 6430
SYS|sockets|2
SYS|cores|64
SYS|os|Rocky Linux 9.4
SYS|kernel|5.14.0-test
@@LSPCI
0000:0b:00.0 3D controller [0302]: NVIDIA Corporation AD102GL [L40S] [10de:26b9] (rev a1)
0000:35:00.0 VGA compatible controller [0300]: Matrox Electronics Systems Ltd. Integrated Matrox G200eW3 Graphics Controller [102b:0536] (rev 08)
0000:41:00.0 Network controller [0280]: Cornelis Networks Inc CN5000 [434e:0001]
0000:81:00.0 Network controller [0280]: Cornelis Networks Inc CN6000 [434e:0002]
0001:0b:00.0 3D controller [0302]: NVIDIA Corporation AD102GL [L40S] [10de:26b9] (rev a1)
PCIE|0000:0b:00.0|2.5 GT/s PCIe|16|16.0 GT/s PCIe|16|32.0 GT/s PCIe|16
PCIE|0001:0b:00.0|16.0 GT/s PCIe|16|16.0 GT/s PCIe|16|32.0 GT/s PCIe|16
SLOT|0000:0a:02.0|32.0 GT/s PCIe|16|2.5 GT/s PCIe|16
SLOT|0000:5b:02.0|32.0 GT/s PCIe|16|32.0 GT/s PCIe|16
SLOT|0000:83:06.0|32.0 GT/s PCIe|8|8.0 GT/s PCIe|4
SLOT|0001:0a:02.0|32.0 GT/s PCIe|16|16.0 GT/s PCIe|16
@@IB
PORT|hfi1_0|1|0000:41:00.0|00:11:22:33:44:55:66:77|4: ACTIVE|5: LinkUp|17
@@SMA|hfi1_0|1
  NodeGuid: 0x0011223344556677
  NeighborNodeType: FI
  NeighborNodeGuid: 0x8899aabbccddeeff NeighborPortNum: 2
@@END
@@NET
NET|ens1|0000:81:00.0|02:00:00:00:00:01|up|0
@@LLDP
{"lldp": {"interface": [{"ens1": {"chassis": {"switch-a": {}}, "port": {"id": {"value": "Ethernet1/1"}, "descr": "uplink"}}}]}}
@@DONE
"""


class TtyBuffer(io.StringIO):
    """StringIO that lets color policy tests emulate a terminal."""

    def isatty(self) -> bool:
        return True


REAL_BMC_POWER = bi.bmc_power
BMC_ENV = {"CNHWINV_BMC_USER": "testuser", "CNHWINV_BMC_PASSWORD": "testpass"}


class InventoryTestCase(unittest.TestCase):
    """Each test gets an independent SQLite cache outside the real XDG cache."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "inventory.db"
        self.db = bi.open_db(self.db_path)
        # Never reach real BMCs from tests; individual tests override this stub.
        bmc = mock.patch.object(bi, "bmc_power", side_effect=lambda host: {"bmc": bi.bmc_name(host), "power": None, "error": "stubbed"})
        self.bmc_power = bmc.start()
        self.addCleanup(bmc.stop)

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = bi.main(["--db", str(self.db_path), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def add_host(
        self,
        name: str,
        *,
        reachable: int = 1,
        source: str = "booked",
        model: str = "Lenovo SR655",
        cpu: str = "AMD EPYC 9654",
        os_name: str = "Rocky Linux 9",
    ) -> None:
        self.db.execute(
            "INSERT INTO host(name, probed_at, reachable, source, model, cpu, os) "
            "VALUES (?, datetime('now'), ?, ?, ?, ?, ?)",
            (name, reachable, source, model, cpu, os_name),
        )
        self.db.commit()

    def add_adapter(self, host: str, pci: str, generation: str) -> None:
        device = "0001" if generation == "CN5000" else "0002"
        self.db.execute(
            "INSERT INTO adapter(host, pci_addr, device_id, generation, pci_class, description) "
            "VALUES (?, ?, ?, ?, 'Network controller', 'Cornelis adapter')",
            (host, pci, device, generation),
        )
        self.db.commit()

    def add_gpu(
        self,
        host: str,
        pci: str = "0000:0b:00.0",
        *,
        vendor_id: str = "10de",
        device_id: str = "26b9",
        pci_class: str = "3D controller",
        model: str = "NVIDIA L40S",
        description: str = "NVIDIA Corporation AD102GL [L40S]",
        pcie_gen: str | None = "Gen4",
        pcie_width: str | None = "x16",
        pcie_cur: str | None = "Gen4 x16",
        pcie_max: str | None = "Gen4 x16",
    ) -> None:
        self.db.execute(
            "INSERT INTO gpu(host, pci_addr, vendor_id, device_id, pci_class, model, description, pcie_gen, pcie_width, pcie_cur, pcie_max) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (host, pci, vendor_id, device_id, pci_class, model, description, pcie_gen, pcie_width, pcie_cur, pcie_max),
        )
        self.db.commit()

    def add_slot(
        self,
        host: str,
        pci: str = "0000:0a:02.0",
        *,
        pcie_gen: str = "Gen5",
        pcie_width: str = "x16",
        pcie_cur: str | None = "Gen5 x16",
        pcie_max: str | None = "Gen5 x16",
    ) -> None:
        self.db.execute(
            "INSERT INTO slot(host, pci_addr, pcie_gen, pcie_width, pcie_cur, pcie_max) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (host, pci, pcie_gen, pcie_width, pcie_cur, pcie_max),
        )
        self.db.commit()

    def add_resource(
        self,
        resource_id: int,
        name: str,
        hosts: list[str],
        *,
        avail_state: str = "free",
        avail_until: str | None = None,
        avail_at: str | None = None,
        reserved_by: str | None = None,
    ) -> None:
        self.db.execute(
            "INSERT INTO resource(id, name, synced_at, avail_state, avail_until, avail_at, reserved_by, avail_checked_at) "
            "VALUES (?, ?, datetime('now'), ?, ?, ?, ?, datetime('now'))",
            (resource_id, name, avail_state, avail_until, avail_at, reserved_by),
        )
        self.db.executemany(
            "INSERT INTO resource_host(resource_id, host) VALUES (?, ?)",
            [(resource_id, host) for host in hosts],
        )
        self.db.commit()

    def test_mask_redacts_credentials_without_erasing_other_text(self) -> None:
        self.assertEqual(bi.mask("root / secret; rack A"), "<redacted>; rack A")
        self.assertEqual(bi.mask("Password: hunter2"), "<redacted>")
        self.assertEqual(bi.mask(None), "")

    def test_parse_hosts_keeps_valid_hostnames_and_drops_booked_prose(self) -> None:
        raw = """Hostname: cn-host01 (10.0.0.1)
cn-host02
- 1x CYR
ETHERNET
CURRENTLY SET UP AS B2B
Host Interface: HFI 1, Port 2
CN-HOST01
"""
        self.assertEqual(bi.parse_hosts(raw), ["cn-host01", "cn-host02"])

    def test_show_host_reports_bmc_power(self) -> None:
        self.add_host("pwr01")
        self.bmc_power.side_effect = lambda host: {"bmc": "pwr01-bmc", "power": "on", "error": None}
        with mock.patch.object(bi, "_refresh_show_availability"):
            code, text, _ = self.run_cli("show", "pwr01")
        self.assertEqual(code, 0)
        self.assertIn("Power (BMC pwr01-bmc): on", text)

    def test_show_resource_queries_all_mapped_bmcs_and_json_includes_power(self) -> None:
        self.add_host("pwr01")
        self.add_host("pwr02")
        self.add_resource(9, "Power rack", ["pwr01", "pwr02"])
        states = {"pwr01": "on", "pwr02": "off"}
        self.bmc_power.side_effect = lambda host: {"bmc": host + "-bmc", "power": states[host], "error": None}
        with mock.patch.object(bi, "_refresh_show_availability"):
            code, text, _ = self.run_cli("show", "power rack")
            self.assertIn("pwr01  gen=-  reachable=yes  power=on", text)
            self.assertIn("pwr02  gen=-  reachable=yes  power=off", text)
            code, text, _ = self.run_cli("show", "power rack", "--json")
        self.assertEqual(code, 0)
        self.assertEqual([h["power"]["power"] for h in json.loads(text)["mapped_hosts"]], ["on", "off"])

    def test_show_offline_and_no_power_skip_bmc(self) -> None:
        self.add_host("pwr01")
        for flags in (("--offline",), ("--no-power",)):
            with mock.patch.object(bi, "_refresh_show_availability"):
                code, text, _ = self.run_cli("show", "pwr01", *flags)
            self.assertEqual(code, 0)
            self.assertNotIn("Power", text)
        self.bmc_power.assert_not_called()

    def test_bmc_power_parses_ipmitool_and_hides_password(self) -> None:
        done = subprocess.CompletedProcess([], 0, "Chassis Power is on\n", "")
        with mock.patch.dict(os.environ, BMC_ENV), mock.patch.object(bi.socket, "getaddrinfo"), mock.patch.object(
            bi.subprocess, "run", return_value=done
        ) as run:
            result = REAL_BMC_POWER("cn123.cornelisnetworks.com")
        self.assertEqual(result, {"bmc": "cn123-bmc", "power": "on", "error": None})
        command = run.call_args.args[0]
        self.assertEqual(command[-3:], ["chassis", "power", "status"])
        self.assertIn("-E", command)
        self.assertEqual(command[command.index("-U") + 1], "testuser")
        self.assertNotIn("testpass", command)
        self.assertEqual(run.call_args.kwargs["env"]["IPMI_PASSWORD"], "testpass")

    def test_bmc_power_requires_credentials_from_environment(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("CNHWINV_BMC_")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(bi.socket, "getaddrinfo"), mock.patch.object(
            bi.subprocess, "run"
        ) as run:
            result = REAL_BMC_POWER("cn123")
        self.assertIn("CNHWINV_BMC_PASSWORD", result["error"])
        run.assert_not_called()

    def test_ssh_run_replaces_changed_host_key_and_retries(self) -> None:
        bad = subprocess.CompletedProcess([], 255, "", "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.\n")
        good = subprocess.CompletedProcess([], 0, "@@DONE\n", "")
        config = subprocess.CompletedProcess([], 0, "hostname cn1.example.com\nuserknownhostsfile /kh\n", "")
        calls = []

        def fake_run(command, **_):
            calls.append(command)
            if command[:2] == ["ssh", "-G"]:
                return config
            if command[0] == "ssh-keygen":
                return subprocess.CompletedProcess(command, 0, "", "")
            return bad if sum(c[0] == "ssh" and c[1] != "-G" for c in calls) == 1 else good

        with mock.patch.object(bi.subprocess, "run", side_effect=fake_run), mock.patch.object(bi.Path, "is_file", return_value=True):
            result = bi.ssh_probe("cn1", 30)
        self.assertEqual(result, {"host": "cn1", "out": "@@DONE\n"})
        removed = [c for c in calls if c[0] == "ssh-keygen"]
        self.assertEqual(removed, [["ssh-keygen", "-R", "cn1", "-f", "/kh"], ["ssh-keygen", "-R", "cn1.example.com", "-f", "/kh"]])

    def test_bmc_power_reports_missing_dns_and_errors(self) -> None:
        with mock.patch.object(bi.socket, "getaddrinfo", side_effect=OSError):
            self.assertEqual(REAL_BMC_POWER("nobmc01")["error"], "no BMC DNS entry")
        failed = subprocess.CompletedProcess([], 1, "", "Error: Unable to establish IPMI v2 / RMCP+ session\n")
        with mock.patch.dict(os.environ, BMC_ENV), mock.patch.object(bi.socket, "getaddrinfo"), mock.patch.object(bi.subprocess, "run", return_value=failed):
            result = REAL_BMC_POWER("dead01")
        self.assertIsNone(result["power"])
        self.assertIn("Unable to establish", result["error"])

    def test_ssh_probe_uses_mocked_subprocess_and_read_only_script(self) -> None:
        process = mock.Mock(stdout="@@DONE\n", stderr="")
        with mock.patch.object(bi.subprocess, "run", return_value=process) as run:
            result = bi.ssh_probe("cn-host01", 30)
        self.assertEqual(result, {"host": "cn-host01", "out": "@@DONE\n"})
        command = run.call_args.args[0]
        self.assertEqual(command[0], "ssh")
        # Script travels as the remote command with stdin closed, so an early
        # ssh exit can never SIGPIPE the CLI on a stdin write.
        self.assertEqual(command[-1], "bash -c " + bi.shlex.quote(bi.REMOTE_SCRIPT))
        self.assertIs(run.call_args.kwargs["stdin"], bi.subprocess.DEVNULL)
        self.assertNotIn("input", run.call_args.kwargs)
        self.assertNotIn("sudo", bi.REMOTE_SCRIPT)

    def test_booked_transport_error_is_a_friendly_user_error(self) -> None:
        with mock.patch.object(bi.urllib.request, "urlopen", side_effect=bi.urllib.error.URLError("offline")):
            with self.assertRaises(bi.UserError) as caught:
                bi._call("/Resources/")
        self.assertIn("Booked Scheduler is unreachable", str(caught.exception))

    def test_parse_probe_handles_mixed_generation_opa_ethernet_and_system_data(self) -> None:
        parsed = bi.parse_probe(PROBE_OUTPUT)
        self.assertEqual(parsed["fqdn"], "cn-host01.example.com")
        self.assertEqual(parsed["sys"]["cpu"], "Intel(R) Xeon(R) Gold 6430")
        self.assertEqual([adapter["gen"] for adapter in parsed["adapters"]], ["CN5000", "CN6000"])
        self.assertEqual([gpu["model"] for gpu in parsed["gpus"]], ["NVIDIA L40S", "NVIDIA L40S"])
        self.assertEqual(parsed["ports"][0]["neighbor_guid"], "0x8899aabbccddeeff")
        self.assertEqual(parsed["ports"][0]["neighbor_port"], 2)
        self.assertEqual(parsed["net"][0]["netdev"], "ens1")
        self.assertEqual(parsed["lldp"]["lldp"]["interface"][0]["ens1"]["port"]["id"]["value"], "Ethernet1/1")

    def test_parse_probe_records_a_busy_sma_query_without_losing_the_port(self) -> None:
        output = """@@IB
PORT|hfi1_0|1|0000:41:00.0|00:11:22:33:44:55:66:77|4: ACTIVE|5: LinkUp|17
@@SMA|hfi1_0|1
opasmaquery: failed to open port: Device or resource busy
@@END
@@DONE
"""
        parsed = bi.parse_probe(output)
        self.assertEqual(parsed["ports"][0]["neighbor_type"], "query-failed: opasmaquery: failed to open port: Device or resource busy")

    def test_open_db_migrates_an_old_host_table_before_store_probe(self) -> None:
        self.db.close()
        self.db_path.unlink()
        old = sqlite3.connect(self.db_path)
        old.execute("CREATE TABLE host (name TEXT PRIMARY KEY, probed_at TEXT, reachable INTEGER, error TEXT, fqdn TEXT)")
        old.execute("CREATE TABLE gpu (host TEXT, pci_addr TEXT, vendor_id TEXT, device_id TEXT, pci_class TEXT, model TEXT, description TEXT, PRIMARY KEY (host, pci_addr))")
        old.commit()
        old.close()
        self.db = bi.open_db(self.db_path)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(host)")}
        self.assertTrue({"source", "model", "cpu", "sockets", "cores", "os", "kernel"}.issubset(columns))
        gpu_columns = {row[1] for row in self.db.execute("PRAGMA table_info(gpu)")}
        self.assertTrue({"pcie_gen", "pcie_width", "pcie_cur", "pcie_max"}.issubset(gpu_columns))
        bi.store_probe(self.db, {"host": "cn-host01", "out": PROBE_OUTPUT})
        self.db.commit()
        row = self.db.execute("SELECT reachable, model, cpu, os FROM host WHERE name='cn-host01'").fetchone()
        self.assertEqual(tuple(row), (1, "Cornelis Networks CN6000 Test Platform", "Intel(R) Xeon(R) Gold 6430", "Rocky Linux 9.4"))
        ports = self.db.execute("SELECT kind, ifname FROM port WHERE host='cn-host01' ORDER BY kind").fetchall()
        self.assertEqual([tuple(port) for port in ports], [("eth", "ens1"), ("opa", "hfi1_0")])
        gpus = self.db.execute("SELECT pci_addr, vendor_id, model, pcie_gen, pcie_width, pcie_cur, pcie_max FROM gpu WHERE host='cn-host01' ORDER BY pci_addr").fetchall()
        self.assertEqual(
            [tuple(gpu) for gpu in gpus],
            [
                ("0000:0b:00.0", "10de", "NVIDIA L40S", "Gen4", "x16", "Gen1 x16", "Gen4 x16"),
                ("0001:0b:00.0", "10de", "NVIDIA L40S", "Gen4", "x16", "Gen4 x16", "Gen4 x16"),
            ],
        )

    def test_host_gen_classifies_single_mixed_and_unprobed_hosts(self) -> None:
        self.add_host("fivek01")
        self.add_host("sixk01")
        self.add_host("mixed01")
        self.add_host("unknown01")
        self.add_adapter("fivek01", "0000:01:00.0", "CN5000")
        self.add_adapter("sixk01", "0000:02:00.0", "CN6000")
        self.add_adapter("mixed01", "0000:03:00.0", "CN5000")
        self.add_adapter("mixed01", "0000:04:00.0", "CN6000")
        self.assertEqual(bi.host_gen(self.db, "fivek01"), "CN5000")
        self.assertEqual(bi.host_gen(self.db, "sixk01"), "CN6000")
        self.assertEqual(bi.host_gen(self.db, "mixed01"), "CN5000+CN6000")
        self.assertEqual(bi.host_gen(self.db, "unknown01"), "-")

    def test_list_filters_generation_alias_reachability_source_and_platform_fields(self) -> None:
        self.add_host("fivek01", model="Lenovo SR655", cpu="AMD EPYC 9654", os_name="Rocky Linux 9")
        self.add_host("sixk01", model="Dell R760", cpu="Intel Xeon 6", os_name="Ubuntu 24.04")
        self.add_host("offline01", reachable=0, source="discovered", model="Dell R760", cpu="Intel Xeon 6", os_name="Ubuntu 24.04")
        self.add_adapter("fivek01", "0000:01:00.0", "CN5000")
        self.add_adapter("sixk01", "0000:02:00.0", "CN6000")
        self.add_adapter("offline01", "0000:03:00.0", "CN6000")
        self.add_resource(1, "Rack A", ["fivek01", "sixk01"])
        code, text, _ = self.run_cli("list", "--gen", "6k", "--reachable", "--model", "dell", "--cpu", "xeon", "--os", "ubuntu")
        self.assertEqual(code, 0)
        self.assertIn("sixk01", text)
        self.assertNotIn("offline01", text)
        self.assertIn("1 host (0 CN5000, 1 CN6000", text)

    def test_list_hsn_link_summary_filter_and_structured_fields(self) -> None:
        self.add_host("up01")
        self.add_host("partial01")
        self.add_host("down01")
        self.add_host("noport01")
        self.db.execute("INSERT INTO host(name, source) VALUES ('unprobed01', 'booked')")
        self.db.executemany(
            "INSERT INTO port(host, ifname, port, kind, state) VALUES (?, ?, ?, ?, ?)",
            [
                ("up01", "hfi1_0", 1, "opa", "ACTIVE"),
                ("up01", "ens1", 0, "eth", "up"),
                ("partial01", "hfi1_0", 1, "opa", "ACTIVE"),
                ("partial01", "hfi1_0", 2, "opa", "DOWN"),
                ("down01", "hfi1_0", 1, "opa", "DOWN"),
            ],
        )
        self.db.commit()

        code, text, _ = self.run_cli("list", "--offline")

        self.assertEqual(code, 0)
        self.assertIn("LINK", text)
        self.assertIn("up01", text)
        self.assertIn("1/2 up", text)
        self.assertIn("down01", text)

        code, text, _ = self.run_cli("list", "--offline", "--link", "PARTIAL")

        self.assertEqual(code, 0)
        self.assertIn("partial01", text)
        self.assertNotIn("up01", text)
        self.assertNotIn("down01", text)

        code, text, _ = self.run_cli("list", "--offline", "-o", "csv")

        self.assertEqual(code, 0)
        rows = {row["host"]: row for row in __import__("csv").DictReader(io.StringIO(text))}
        self.assertEqual((rows["up01"]["hsn_link"], rows["up01"]["hsn_ports_up"], rows["up01"]["hsn_ports_total"]), ("up", "2", "2"))
        self.assertEqual((rows["partial01"]["hsn_link"], rows["partial01"]["hsn_ports_up"], rows["partial01"]["hsn_ports_total"]), ("1/2 up", "1", "2"))
        self.assertEqual((rows["down01"]["hsn_link"], rows["down01"]["hsn_ports_up"], rows["down01"]["hsn_ports_total"]), ("down", "0", "1"))
        self.assertEqual((rows["noport01"]["hsn_link"], rows["unprobed01"]["hsn_link"]), ("-", "-"))

    def test_list_hsn_link_tty_colors(self) -> None:
        self.add_host("up01")
        self.add_host("partial01")
        self.add_host("down01")
        self.db.executemany(
            "INSERT INTO port(host, ifname, port, kind, state) VALUES (?, ?, ?, 'opa', ?)",
            [
                ("up01", "hfi1_0", 1, "ACTIVE"),
                ("partial01", "hfi1_0", 1, "ACTIVE"),
                ("partial01", "hfi1_0", 2, "DOWN"),
                ("down01", "hfi1_0", 1, "DOWN"),
            ],
        )
        self.db.commit()
        tty = TtyBuffer()

        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "stdout", tty):
            code = bi.main(["--db", str(self.db_path), "list", "--offline"])

        self.assertEqual(code, 0)
        self.assertIn("\x1b[32mup", tty.getvalue())
        self.assertIn("\x1b[33m1/2 up", tty.getvalue())
        self.assertIn("\x1b[31mdown", tty.getvalue())

    def test_sync_booked_populates_cached_availability(self) -> None:
        resources = [
            {
                "resourceId": 1,
                "name": "Sync rack",
                "statusId": 1,
                "customAttributes": [{"id": 2, "label": "Hosts", "value": "sync01"}],
            }
        ]
        availability = {
            "resources": [
                [
                    {
                        "available": False,
                        "availableAt": "2026-10-17T15:30:00-0600",
                        "availableUntil": "2026-10-17T14:30:00-0600",
                        "resource": {"resourceId": "1", "statusId": "1"},
                    }
                ]
            ]
        }

        with mock.patch.object(bi, "_booked_session") as session, mock.patch.object(
            bi, "_call", side_effect=lambda path, **_: {"resources": resources} if path == "/Resources/" else availability
        ):
            session.return_value.__enter__.return_value = {"X-Booked-SessionToken": "token"}
            bi.cmd_sync_booked(self.db, argparse.Namespace())

        row = self.db.execute("SELECT avail_state, avail_at FROM resource WHERE id=1").fetchone()
        self.assertEqual(tuple(row), ("reserved", "2026-10-17T15:30:00-0600"))
        self.assertEqual(self.db.execute("SELECT host FROM resource_host WHERE resource_id=1").fetchone()[0], "sync01")

    def test_list_booked_column_summarizes_multiple_resources_and_available_filter(self) -> None:
        self.add_host("free01")
        self.add_host("busy01")
        self.add_host("mixed01")
        self.add_host("discovered01", source="discovered")
        self.add_resource(1, "Free rack", ["free01", "mixed01"])
        self.add_resource(2, "Busy rack", ["busy01", "mixed01"], avail_state="reserved", avail_at="2026-10-17T15:30:00-0600", reserved_by="Ada Lovelace")

        code, text, _ = self.run_cli("list", "--offline", "--wide")

        self.assertEqual(code, 0)
        self.assertIn("BOOKED", text)
        self.assertIn("free01", text)
        self.assertIn("free", text)
        self.assertIn("busy01", text)
        self.assertIn("in use until 2026-10-17 15:30 by Ada Lovelace", text)
        self.assertIn("mixed01", text)
        self.assertIn("in use until 2026-10-17 15:30 by Ada Lovelace", text)
        self.assertIn("discovered01", text)
        self.assertIn("-", text)

        code, text, _ = self.run_cli("list", "--offline", "--available")

        self.assertEqual(code, 0)
        self.assertIn("free01", text)
        self.assertNotIn("busy01", text)
        self.assertNotIn("mixed01", text)
        self.assertNotIn("discovered01", text)

    def test_refresh_availability_uses_batched_gets_and_reservation_owner(self) -> None:
        self.add_host("refresh01")
        self.add_resource(1, "Refresh rack", ["refresh01"])
        responses = [
            {
                "resources": [
                    [
                        {
                            "available": False,
                            "availableAt": "2026-10-17T15:30:00-0600",
                            "availableUntil": "2026-10-17T14:30:00-0600",
                            "resource": {"resourceId": "1", "statusId": "1"},
                        }
                    ]
                ]
            },
            {
                "reservations": [
                    {
                        "resourceId": "1",
                        "startDate": "2026-10-17T12:30:00-0600",
                        "endDate": "2026-10-17T15:30:00-0600",
                        "firstName": "Ada",
                        "lastName": "Lovelace",
                    }
                ]
            },
        ]

        with mock.patch.object(bi, "_booked_session") as session, mock.patch.object(
            bi, "_call", side_effect=lambda path, **_: responses[0] if path.startswith("/Resources/Availability") else responses[1]
        ) as call, mock.patch.object(
            bi, "datetime"
        ) as clock:
            session.return_value.__enter__.return_value = {"X-Booked-SessionToken": "token"}
            clock.now.return_value = datetime(2026, 10, 17, 20, 0, tzinfo=timezone.utc)
            clock.fromisoformat.side_effect = datetime.fromisoformat
            bi.refresh_availability(self.db)

        self.assertEqual(call.call_count, 2)
        state, until, owner = self.db.execute("SELECT avail_state, avail_at, reserved_by FROM resource WHERE id=1").fetchone()
        self.assertEqual((state, until, owner), ("reserved", "2026-10-17T15:30:00-0600", "Ada Lovelace"))

    def test_refresh_availability_falls_back_to_current_reservations_when_needed(self) -> None:
        self.add_host("fallback01")
        self.add_resource(1, "Fallback rack", ["fallback01"], avail_state="free")
        responses = [
            {},
            {
                "reservations": [
                    {
                        "resourceId": "1",
                        "startDate": "2026-10-17T12:30:00-0600",
                        "endDate": "2026-10-17T15:30:00-0600",
                        "firstName": "Ada",
                        "lastName": "Lovelace",
                    }
                ]
            },
        ]

        with mock.patch.object(bi, "_booked_session") as session, mock.patch.object(
            bi, "_call", side_effect=lambda path, **_: responses[0] if path.startswith("/Resources/Availability") else responses[1]
        ) as call, mock.patch.object(
            bi, "datetime"
        ) as clock:
            session.return_value.__enter__.return_value = {"X-Booked-SessionToken": "token"}
            clock.now.return_value = datetime(2026, 10, 17, 20, 0, tzinfo=timezone.utc)
            clock.fromisoformat.side_effect = datetime.fromisoformat
            bi.refresh_availability(self.db)

        self.assertEqual(call.call_count, 2)
        state, owner = self.db.execute("SELECT avail_state, reserved_by FROM resource WHERE id=1").fetchone()
        self.assertEqual((state, owner), ("reserved", "Ada Lovelace"))

    def update_args(self) -> argparse.Namespace:
        return argparse.Namespace(jobs=4, timeout=5, max_age=24, force=False, discover=False)

    def test_update_probes_cached_stale_hosts_while_booked_fetch_is_pending(self) -> None:
        self.add_host("stale01")
        self.add_host("fresh01")
        self.db.execute("UPDATE host SET probed_at=datetime('now', '-2 days') WHERE name='stale01'")
        self.db.commit()
        probed_before_booked = threading.Event()
        probed: list[str] = []

        def slow_fetch(include_resources: bool) -> dict:
            # Booked must not gate the cached stale probe: wait until it has run.
            self.assertTrue(include_resources)
            self.assertTrue(probed_before_booked.wait(5))
            return {"snapshot": True}

        def apply(db: sqlite3.Connection, snapshot: dict) -> None:
            db.execute("INSERT INTO host(name, source) VALUES ('new01', 'booked')")
            db.commit()

        def probe(host: str, timeout: int) -> dict:
            probed.append(host)
            if host == "stale01":
                probed_before_booked.set()
            return {"host": host, "error": "unreachable"}

        with mock.patch.object(bi, "fetch_booked", side_effect=slow_fetch), mock.patch.object(
            bi, "apply_booked", side_effect=apply
        ), mock.patch.object(bi, "ssh_probe", side_effect=probe), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(bi.cmd_update(self.db, self.update_args()), 0)

        self.assertEqual(sorted(probed), ["new01", "stale01"])
        self.assertEqual(probed[0], "stale01")

    def test_update_still_probes_when_booked_fails_then_reports_error(self) -> None:
        self.add_host("stale01")
        self.db.execute("UPDATE host SET probed_at=datetime('now', '-2 days')")
        self.db.commit()
        probed: list[str] = []

        def probe(host: str, timeout: int) -> dict:
            probed.append(host)
            return {"host": host, "error": "unreachable"}

        with mock.patch.object(bi, "fetch_booked", side_effect=bi.UserError("booked down")), mock.patch.object(
            bi, "ssh_probe", side_effect=probe
        ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(bi.UserError):
                bi.cmd_update(self.db, self.update_args())

        self.assertEqual(probed, ["stale01"])

    def test_fetch_booked_issues_gets_concurrently(self) -> None:
        barrier = threading.Barrier(3, timeout=5)

        def call(path: str, **_: object) -> dict:
            # Each GET blocks until all three are in flight; serial calls would time out.
            barrier.wait()
            return {"resources": []} if path.startswith("/Resources/") else {"reservations": []}

        with mock.patch.object(bi, "_booked_session") as session, mock.patch.object(bi, "_call", side_effect=call):
            session.return_value.__enter__.return_value = {"X-Booked-SessionToken": "token"}
            snapshot = bi.fetch_booked(True)

        self.assertIsNotNone(snapshot["resources"])
        self.assertIsNotNone(snapshot["reservations"])

    def test_list_offline_skips_availability_refresh_and_falls_back_after_failure(self) -> None:
        self.add_host("cached01")
        self.add_resource(1, "Cached rack", ["cached01"], avail_state="free")
        self.db.execute("UPDATE resource SET avail_checked_at=datetime('now', '-10 minutes')")
        self.db.commit()

        with mock.patch.object(bi, "refresh_availability") as refresh:
            code, text, error = self.run_cli("list", "--offline")
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        refresh.assert_not_called()
        self.assertIn("cached01", text)

        with mock.patch.object(bi, "refresh_availability", side_effect=bi.UserError("offline")):
            code, text, error = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("cached01", text)
        self.assertIn("Warning: Booked availability refresh failed; using cached values", error)

    def test_list_structured_output_includes_booked_fields(self) -> None:
        self.add_host("structured01")
        self.add_resource(
            1,
            "Structured rack",
            ["structured01"],
            avail_state="reserved",
            avail_at="2026-10-17T15:30:00-0600",
            reserved_by="Ada Lovelace",
        )

        code, text, _ = self.run_cli("list", "--offline", "--json")

        self.assertEqual(code, 0)
        entry = json.loads(text)["hosts"][0]
        self.assertEqual(entry["booked_status"], "in use")
        self.assertEqual(entry["booked_until"], "2026-10-17T15:30:00-0600")
        self.assertEqual(entry["booked_by"], "Ada Lovelace")

        code, text, _ = self.run_cli("list", "--offline", "-o", "csv")

        self.assertEqual(code, 0)
        row = next(__import__("csv").DictReader(io.StringIO(text)))
        self.assertEqual(row["booked_status"], "in use")
        self.assertEqual(row["booked_until"], "2026-10-17T15:30:00-0600")
        self.assertEqual(row["booked_by"], "Ada Lovelace")

    def test_open_db_migrates_old_resource_table_with_availability_columns(self) -> None:
        self.db.close()
        self.db_path.unlink()
        old = sqlite3.connect(self.db_path)
        old.executescript(
            "CREATE TABLE resource (id INTEGER PRIMARY KEY, name TEXT, schedule_id INTEGER, status_id INTEGER, "
            "description TEXT, notes TEXT, hosts_raw TEXT, attrs_json TEXT, synced_at TEXT);"
        )
        old.commit()
        old.close()

        self.db = bi.open_db(self.db_path)

        columns = {row[1] for row in self.db.execute("PRAGMA table_info(resource)")}
        self.assertTrue({"avail_state", "avail_until", "avail_at", "reserved_by", "avail_checked_at"}.issubset(columns))

    def test_list_alias_wide_and_source_filter_remain_backward_compatible(self) -> None:
        self.add_host("discovered01", source="discovered")
        self.add_adapter("discovered01", "0000:03:00.0", "CN6000")
        code, text, _ = self.run_cli("ls", "--source", "discovered", "-w")
        self.assertEqual(code, 0)
        self.assertIn("MODEL", text)
        self.assertIn("discovered01", text)

    def test_show_resource_displays_full_cached_booked_details(self) -> None:
        self.add_host("detail01")
        self.add_resource(7, "Detail rack", ["detail01"], avail_state="reserved", avail_at="2026-11-16T13:59:00-0600", reserved_by="Ada Lovelace")
        self.db.execute(
            "UPDATE resource SET schedule_id=9, status_id=1, description=?, notes=?, hosts_raw=?, attrs_json=?, "
            "synced_at=datetime('now', '-1 hour'), avail_checked_at=datetime('now', '-2 minutes') WHERE id=7",
            (
                "Rack description\nSecond line",
                "Password: hunter2\nKeep cool",
                "detail01\ndetail02",
                json.dumps({"Console": "ttyS0", "Secret": "Password: hunter2"}),
            ),
        )
        self.db.commit()

        code, text, _ = self.run_cli("show", "detail rack", "--offline")

        self.assertEqual(code, 0)
        self.assertIn("Booked resource 7: Detail rack", text)
        self.assertIn("Schedule: 9", text)
        self.assertIn("Status: Available", text)
        self.assertIn("Availability: reserved", text)
        self.assertIn("Reserved by: Ada Lovelace", text)
        self.assertIn("Free again at: 2026-11-16 13:59", text)
        self.assertIn("Description:", text)
        self.assertIn("Rack description", text)
        self.assertIn("Notes:", text)
        self.assertIn("<redacted>", text)
        self.assertNotIn("hunter2", text)
        self.assertIn("Attributes:", text)
        self.assertIn("Console: ttyS0", text)
        self.assertIn("Raw hosts:", text)
        self.assertIn("detail01", text)
        self.assertIn("Mapped hosts:", text)

    def test_show_host_includes_resource_attributes_and_complete_ports(self) -> None:
        self.add_host("detail01")
        self.add_adapter("detail01", "0000:01:00.0", "CN5000")
        self.add_resource(7, "Detail rack", ["detail01"])
        self.db.execute("UPDATE resource SET attrs_json=? WHERE id=7", (json.dumps({"Console": "ttyS0"}),))
        self.db.execute(
            "INSERT INTO port(host, ifname, port, pci_addr, kind, node_guid, port_guid, state, phys_state, lid, "
            "neighbor_type, neighbor_guid, neighbor_port, mac, netdev, lldp_json) "
            "VALUES ('detail01', 'hfi1_0', 1, '0000:01:00.0', 'opa', '0xaaa', '0xaab', 'ACTIVE', 'LinkUp', '17', "
            "'Switch', '0xswitch', 5, NULL, NULL, NULL)"
        )
        self.db.execute("INSERT INTO fabric_node(guid, type, name) VALUES ('0xswitch', 'SW', 'core-switch')")
        self.db.execute(
            "INSERT INTO port(host, ifname, port, pci_addr, kind, state, mac, netdev, lldp_json) "
            "VALUES ('detail01', 'ens1', 0, '0000:02:00.0', 'eth', 'up', '02:00:00:00:00:01', 'ens1', ?) ",
            (json.dumps({"chassis": "switch-a", "port": "Ethernet1/1"}),),
        )
        self.db.commit()

        code, text, _ = self.run_cli("show", "detail01", "--offline")

        self.assertEqual(code, 0)
        self.assertIn("Source: booked", text)
        self.assertIn("Adapters:", text)
        self.assertIn("0000:01:00.0", text)
        self.assertIn("Ports:", text)
        self.assertIn("Physical state: LinkUp", text)
        self.assertIn("Neighbor: Switch core-switch", text)
        self.assertIn("LLDP:", text)
        self.assertIn("Console: ttyS0", text)

    def test_show_json_contains_resource_attributes_and_show_offline_skips_refresh(self) -> None:
        self.add_host("json-detail01")
        self.add_resource(7, "JSON detail", ["json-detail01"])
        self.db.execute("UPDATE resource SET attrs_json=?, avail_checked_at=datetime('now', '-10 minutes') WHERE id=7", (json.dumps({"Console": "ttyS0"}),))
        self.db.commit()

        with mock.patch.object(bi, "refresh_availability") as refresh:
            code, text, _ = self.run_cli("show", "JSON detail", "--offline", "--json")

        self.assertEqual(code, 0)
        refresh.assert_not_called()
        detail = json.loads(text)
        self.assertEqual(detail["attributes"], {"Console": "ttyS0"})
        self.assertEqual(detail["mapped_hosts"][0]["host"], "json-detail01")

    def test_wide_list_in_use_includes_date_when_not_today(self) -> None:
        self.add_host("dated01")
        self.add_resource(1, "Dated rack", ["dated01"], avail_state="reserved", avail_at="2026-11-16T13:59:00-0600", reserved_by="Ada")

        code, text, _ = self.run_cli("list", "--offline", "--wide")

        self.assertEqual(code, 0)
        self.assertIn("in use until 2026-11-16 13:59 by Ada", text)

    def test_show_resolves_unique_case_insensitive_substring(self) -> None:
        self.add_host("cn-alpha01")
        code, text, _ = self.run_cli("show", "ALPHA")
        self.assertEqual(code, 0)
        self.assertIn("Host: cn-alpha01", text)

    def test_show_prefers_an_exact_short_hostname_over_substring_matches(self) -> None:
        self.add_host("arm-01.cornelisnetworks.com")
        self.add_host("sw-arm-01")

        code, text, _ = self.run_cli("show", "arm-01", "--offline")

        self.assertEqual(code, 0)
        self.assertIn("Host: arm-01.cornelisnetworks.com", text)
        self.assertNotIn("Host: sw-arm-01", text)

    def test_show_reports_ambiguous_host_matches(self) -> None:
        self.add_host("lab-alpha01")
        self.add_host("lab-beta01")
        code, _, error = self.run_cli("show", "lab")
        self.assertEqual(code, 2)
        self.assertIn("matches multiple hosts", error)
        self.assertIn("lab-alpha01", error)
        self.assertIn("lab-beta01", error)

    def test_show_suggests_close_hostnames_when_no_host_matches(self) -> None:
        self.add_host("cn-alpha01")
        code, _, error = self.run_cli("show", "cn-alphx01")
        self.assertEqual(code, 2)
        self.assertIn("Did you mean: cn-alpha01", error)

    def test_show_accepts_a_booked_resource_name_and_lists_its_hosts(self) -> None:
        self.add_host("node01")
        self.add_host("node02")
        self.add_resource(42, "CN Lab Rack A", ["node01", "node02"])
        code, text, _ = self.run_cli("show", "rack a")
        self.assertEqual(code, 0)
        self.assertIn("Booked resource 42: CN Lab Rack A", text)
        self.assertIn("node01", text)
        self.assertIn("node02", text)

    def test_show_reports_host_and_resource_name_collisions_as_ambiguous(self) -> None:
        self.add_host("rack-a01")
        self.add_resource(42, "Rack A", ["rack-a01"])
        code, _, error = self.run_cli("show", "rack")
        self.assertEqual(code, 2)
        self.assertIn("matches multiple cached items", error)

    def test_links_reports_direct_fabric_peer_and_switch_grouping(self) -> None:
        self.add_host("source01")
        self.add_host("peer01")
        self.add_adapter("source01", "0000:01:00.0", "CN5000")
        self.add_adapter("peer01", "0000:02:00.0", "CN5000")
        self.db.executemany(
            "INSERT INTO port(host, ifname, port, pci_addr, kind, node_guid, state, neighbor_type, neighbor_guid, neighbor_port) "
            "VALUES (?, ?, ?, ?, 'opa', ?, 'ACTIVE', ?, ?, ?)",
            [
                ("source01", "hfi1_0", 1, "0000:01:00.0", "0xaaa", "FI", "0xbbb", 2),
                ("peer01", "hfi1_0", 2, "0000:02:00.0", "0xbbb", "Switch", "0xswitch", 7),
                ("source01", "hfi1_0", 2, "0000:01:00.0", "0xaac", "Switch", "0xswitch", 8),
            ],
        )
        self.db.execute("INSERT INTO fabric_node(guid, type, name) VALUES ('0xswitch', 'SW', 'core-switch')")
        self.db.commit()
        self.assertEqual(bi._guid_owner(self.db)["0xbbb"], "peer01:hfi1_0")
        code, text, _ = self.run_cli("links")
        self.assertEqual(code, 0)
        self.assertIn("direct host-to-host", text)
        self.assertIn("core-switch", text)
        self.assertIn("Fabrics", text)

    def test_short_normalizes_known_platform_labels_and_truncates(self) -> None:
        self.assertEqual(bi._short("Red Hat Enterprise Linux 9 (R)", 20), "RHEL 9")
        self.assertEqual(bi._short("abcdefgh", 5), "abcd~")

    def test_json_output_for_each_reporting_command_is_valid_json(self) -> None:
        self.add_host("json01")
        self.add_adapter("json01", "0000:01:00.0", "CN5000")
        self.add_resource(1, "JSON rack", ["json01"])
        for args in (("list", "--json"), ("show", "json01", "--json"), ("links", "--json"), ("status", "--json")):
            with self.subTest(args=args):
                code, text, _ = self.run_cli(*args)
                self.assertEqual(code, 0)
                self.assertIsInstance(json.loads(text), dict)

    def test_flat_output_formats_for_list_and_links(self) -> None:
        import csv as _csv, io as _io
        self.add_host("flat01", model="Dell R7625")
        self.add_adapter("flat01", "0000:01:00.0", "CN5000")
        self.add_resource(1, "Flat rack", ["flat01"])
        code, text, _ = self.run_cli("list", "--format", "csv")
        self.assertEqual(code, 0)
        rows = list(_csv.DictReader(_io.StringIO(text)))
        self.assertEqual(rows[0]["host"], "flat01")
        self.assertEqual(rows[0]["generation"], "CN5000")
        self.assertEqual(rows[0]["resources"], "Flat rack")
        code, text, _ = self.run_cli("ls", "-o", "tsv")
        self.assertEqual(text.splitlines()[0].split("\t")[0], "host")
        self.assertEqual(text.splitlines()[1].split("\t")[0], "flat01")
        code, text, _ = self.run_cli("list", "-o", "jsonl")
        self.assertEqual([json.loads(line)["host"] for line in text.splitlines()], ["flat01"])
        code, text, _ = self.run_cli("links", "-o", "csv")
        self.assertEqual(code, 0)
        self.assertTrue(text.startswith("host,") or text.strip() == "")

    def test_color_is_disabled_for_non_tty_and_when_no_color_is_set(self) -> None:
        self.add_host("color01")
        self.add_adapter("color01", "0000:01:00.0", "CN5000")
        code, text, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b[", text)
        tty = TtyBuffer()
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False), mock.patch.object(sys, "stdout", tty):
            code = bi.main(["--db", str(self.db_path), "list"])
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b[", tty.getvalue())

    def test_tty_colors_preserve_text_table_column_padding(self) -> None:
        self.add_host("offline01", reachable=0)
        self.add_adapter("offline01", "0000:01:00.0", "CN5000")
        tty = TtyBuffer()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "stdout", tty):
            code = bi.main(["--db", str(self.db_path), "list"])
        self.assertEqual(code, 0)
        self.assertIn("\x1b[2moffline01", tty.getvalue())
        self.assertIn("\x1b[0m \x1b[36mCN5000", tty.getvalue())
        plain_tty = TtyBuffer()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "stdout", plain_tty):
            code = bi.main(["--db", str(self.db_path), "--no-color", "list"])
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b[", plain_tty.getvalue())

    def test_main_returns_130_for_keyboard_interrupt_without_a_traceback(self) -> None:
        with mock.patch.object(bi, "open_db", side_effect=KeyboardInterrupt):
            code, _, error = self.run_cli("status")
        self.assertEqual(code, 130)
        self.assertEqual(error, "Cancelled.\n")

    def test_bad_database_path_is_a_friendly_user_error(self) -> None:
        blocker = Path(self.tempdir.name) / "blocker"
        blocker.write_text("not a directory")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = bi.main(["--db", str(blocker / "inventory.db"), "status"])
        self.assertEqual(code, 2)
        self.assertIn("Cannot open cache database", stderr.getvalue())

    def test_no_args_prints_help_without_an_argparse_error(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = bi.main([])
        self.assertEqual(code, 0)
        self.assertIn("Common examples", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_parser_accepts_existing_commands_options_and_friendly_aliases(self) -> None:
        parser = bi.build_parser()
        cases = [
            ["sync-booked"],
            ["probe", "host01", "--jobs", "2", "--timeout", "5", "--max-age", "1", "--force"],
            ["update", "--discover", "--jobs", "2", "--timeout", "5", "--max-age", "1", "--force"],
            ["refresh", "--jobs", "2"],
            ["discover", "--jobs", "2", "--timeout", "5"],
            ["status"],
            ["list", "--gen", "5000", "--reachable", "--wide", "--model", "SR655", "--cpu", "EPYC", "--os", "Rocky", "--source", "booked", "--available", "--link", "up", "--offline"],
            ["ls", "--gen", "CN6000"],
            ["show", "host01", "--offline"],
            ["links", "--gen", "6000"],
        ]
        for args in cases:
            with self.subTest(args=args):
                parser.parse_args(args)

    def test_missing_credentials_is_a_friendly_user_error(self) -> None:
        missing = Path(self.tempdir.name) / "missing-state"
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(missing)}, clear=False):
            with self.assertRaises(bi.UserError) as caught:
                bi._creds()
        self.assertIn("Booked credentials file is unavailable", str(caught.exception))

    def discover_args(self) -> argparse.Namespace:
        return argparse.Namespace(jobs=4, timeout=30)

    def add_opa_port(self, host: str, guid: str, *, port_guid: str | None = None) -> None:
        self.db.execute(
            "INSERT INTO port(host, ifname, port, kind, node_guid, port_guid, state) "
            "VALUES (?, 'hfi1_0', 1, 'opa', ?, ?, 'ACTIVE')",
            (host, guid, port_guid),
        )
        self.db.commit()

    def test_discover_on_unprobed_cache_explains_probe_is_needed(self) -> None:
        self.db.execute("INSERT INTO host(name, source) VALUES ('fresh01', 'booked')")
        self.db.commit()
        with mock.patch.object(bi, "_sa_query") as query:
            code, stdout, stderr = self.run_cli("discover")
        self.assertEqual(code, 1)
        query.assert_not_called()
        self.assertIn("no hosts have been probed yet", stderr)
        self.assertIn("cnhwinv probe", stderr)

    def test_list_filter_on_unprobed_hosts_hints_to_probe(self) -> None:
        self.db.execute("INSERT INTO resource(id, name, synced_at) VALUES (1, 'r', datetime('now'))")
        self.db.execute("INSERT INTO host(name, source) VALUES ('fresh01', 'booked')")
        self.db.commit()
        code, stdout, _ = self.run_cli("list", "--model", "sr655")
        self.assertEqual(code, 0)
        self.assertIn("1 host(s) have not been probed", stdout)
        code, stdout, _ = self.run_cli("list")
        self.assertNotIn("have not been probed", stdout)

    def test_discover_queries_one_vantage_when_its_sa_results_cover_other_hosts(self) -> None:
        self.add_host("vantage01")
        self.add_host("zcovered02")
        self.add_opa_port("vantage01", "0xaaa")
        self.add_opa_port("zcovered02", "0xbbb")
        responses = {
            "vantage01": [
                {"guid": "0xaaa", "type": "FI", "name": "vantage01 hfi1_0"},
                {"guid": "0xbbb", "type": "FI", "name": "zcovered02 hfi1_0"},
            ]
        }
        with mock.patch.object(bi, "_sa_query", side_effect=lambda host, _: (host, responses[host])) as query, mock.patch.object(
            bi, "_probe_hosts"
        ):
            code = bi.cmd_discover(self.db, self.discover_args())
        self.assertEqual(code, 0)
        self.assertEqual(query.call_args_list, [mock.call("vantage01", 30)])

    def test_discover_treats_guid_owned_fi_as_known_even_when_name_differs(self) -> None:
        self.add_host("vantage01")
        self.add_host("booked01")
        self.add_opa_port("vantage01", "0xaaa")
        self.add_opa_port("booked01", "0xnode-owned", port_guid="0xport-owned")
        nodes = [
            {"guid": "0xaaa", "type": "FI", "name": "vantage01 hfi1_0"},
            {"guid": "0xport-owned", "type": "FI", "name": "different-name hfi1_0"},
        ]
        with mock.patch.object(bi, "_sa_query", return_value=("vantage01", nodes)), mock.patch.object(bi, "_probe_hosts") as probe:
            bi.cmd_discover(self.db, self.discover_args())
        self.assertIsNone(self.db.execute("SELECT name FROM host WHERE name='different-name'").fetchone())
        probe.assert_not_called()

    def test_discover_treats_fqdn_short_name_as_known(self) -> None:
        self.add_host("arm-01.cornelisnetworks.com")
        self.add_host("vantage01")
        self.add_opa_port("vantage01", "0xaaa")
        nodes = [
            {"guid": "0xaaa", "type": "FI", "name": "vantage01 hfi1_0"},
            {"guid": "0xarm", "type": "FI", "name": "arm-01 hfi1_0"},
        ]
        with mock.patch.object(bi, "_sa_query", return_value=("vantage01", nodes)), mock.patch.object(bi, "_probe_hosts") as probe:
            bi.cmd_discover(self.db, self.discover_args())
        self.assertIsNone(self.db.execute("SELECT name FROM host WHERE name='arm-01'").fetchone())
        probe.assert_not_called()

    def test_discover_reports_denylisted_adapter_without_creating_a_host(self) -> None:
        self.add_host("vantage01")
        self.add_opa_port("vantage01", "0xaaa")
        nodes = [
            {"guid": "0xaaa", "type": "FI", "name": "vantage01 hfi1_0"},
            {"guid": "0xjkr", "type": "FI", "name": "JKR MFG"},
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), mock.patch.object(bi, "_sa_query", return_value=("vantage01", nodes)), mock.patch.object(
            bi, "_probe_hosts"
        ) as probe:
            bi.cmd_discover(self.db, self.discover_args())
        self.assertIsNone(self.db.execute("SELECT name FROM host WHERE name='jkr'").fetchone())
        self.assertIn("Unnamed adapters: 0xjkr", stdout.getvalue())
        probe.assert_not_called()

    def test_discover_removes_bogus_discovered_host_owned_by_another_host(self) -> None:
        self.add_host("vantage01")
        self.add_host("asic-fw-10")
        self.add_host("jkr", source="discovered")
        self.add_adapter("jkr", "0000:01:00.0", "CN5000")
        self.add_opa_port("vantage01", "0xaaa")
        self.add_opa_port("asic-fw-10", "0xjkr")
        self.add_opa_port("jkr", "0xold")
        self.add_resource(1, "orphan resource", ["jkr"])
        with mock.patch.object(bi, "_sa_query", return_value=("vantage01", [{"guid": "0xaaa", "type": "FI", "name": "vantage01 hfi1_0"}])), mock.patch.object(
            bi, "_probe_hosts"
        ):
            bi.cmd_discover(self.db, self.discover_args())
        self.assertIsNone(self.db.execute("SELECT name FROM host WHERE name='jkr'").fetchone())
        self.assertEqual(self.db.execute("SELECT count(*) FROM adapter WHERE host='jkr'").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM port WHERE host='jkr'").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM resource_host WHERE host='jkr'").fetchone()[0], 0)

    def test_discover_inserts_and_probes_a_genuinely_new_host(self) -> None:
        self.add_host("vantage01")
        self.add_opa_port("vantage01", "0xaaa")
        nodes = [
            {"guid": "0xaaa", "type": "FI", "name": "vantage01 hfi1_0"},
            {"guid": "0xnew", "type": "FI", "name": "opx-emr-006 hfi1_0"},
        ]
        with mock.patch.object(bi, "_sa_query", return_value=("vantage01", nodes)), mock.patch.object(bi, "_probe_hosts") as probe:
            bi.cmd_discover(self.db, self.discover_args())
        self.assertEqual(self.db.execute("SELECT source FROM host WHERE name='opx-emr-006'").fetchone()[0], "discovered")
        probe.assert_called_once_with(self.db, ["opx-emr-006"], mock.ANY, show_progress=True)

    def test_remote_probe_and_discovery_scripts_exclude_state_changing_commands(self) -> None:
        scripts = f"{bi.REMOTE_SCRIPT}\n{bi.DISCOVER_SCRIPT}"
        forbidden = [
            r"\breboot\b", r"\bshutdown\b", r"\brmmod\b", r"\bmodprobe\b", r"\bifdown\b",
            r"\bip\s+link\s+set\b", r"\bethtool\s+-s\b", r"\bopaportconfig\b", r"\becho\b[^\n]*>\s*/sys",
            r"\brm\b", r"\bdd\b", r"\bsudo\b", r"\bsystemctl\s+(?:start|stop|restart)\b",
        ]
        for command in forbidden:
            with self.subTest(command=command):
                self.assertNotRegex(scripts, command)

    # ------------------------------------------------------------ checkout/checkin
    def booked_writes(self, responses: dict[str, object]):
        """Patch the Booked session and record every _call made through it."""
        calls: list[tuple[str, object, str | None]] = []

        def fake_call(path, data=None, headers=None, method=None):
            calls.append((path, data, method))
            for prefix, response in responses.items():
                if path.startswith(prefix):
                    return response
            return {}

        session = mock.patch.object(bi, "_booked_session")
        started = session.start()
        self.addCleanup(session.stop)
        started.return_value.__enter__.return_value = {"X-Booked-SessionToken": "t", "X-Booked-UserId": "251"}
        call = mock.patch.object(bi, "_call", side_effect=fake_call)
        call.start()
        self.addCleanup(call.stop)
        refresh = mock.patch.object(bi, "refresh_availability")
        refresh.start()
        self.addCleanup(refresh.stop)
        return calls

    def test_parse_duration_accepts_units_and_rejects_garbage(self) -> None:
        self.assertEqual(bi._parse_duration("90m").total_seconds(), 5400)
        self.assertEqual(bi._parse_duration("4").total_seconds(), 4 * 3600)
        self.assertEqual(bi._parse_duration("2d").total_seconds(), 2 * 86400)
        for bad in ("4x", "", "-1h", "0h"):
            with self.subTest(value=bad), self.assertRaises(argparse.ArgumentTypeError):
                bi._parse_duration(bad)

    def test_resolve_resource_by_name_host_and_reports_ambiguity(self) -> None:
        self.add_resource(10, "CN-B2B-07", ["cn-b2b-07a.cornelisnetworks.com"])
        self.add_resource(11, "CN-B2B-08", ["cn-b2b-08a.cornelisnetworks.com"])
        self.assertEqual(bi._resolve_resource(self.db, "CN-B2B-07"), (10, "CN-B2B-07"))
        self.assertEqual(bi._resolve_resource(self.db, "cn-b2b-08a"), (11, "CN-B2B-08"))
        with self.assertRaisesRegex(bi.UserError, "CN-B2B-07"):
            bi._resolve_resource(self.db, "b2b")
        with self.assertRaises(bi.UserError):
            bi._resolve_resource(self.db, "nothing-like-it")

    def test_checkout_dry_run_does_not_contact_booked(self) -> None:
        self.add_resource(10, "CN-B2B-07", ["cn-b2b-07a"])
        with mock.patch.object(bi, "_booked_session") as session, mock.patch.object(bi, "_call") as call:
            code, out, _ = self.run_cli("checkout", "cn-b2b-07a", "--for", "90m", "-n")
        self.assertEqual(code, 0)
        self.assertIn("Would check out CN-B2B-07 (resource 10)", out)
        session.assert_not_called()
        call.assert_not_called()

    def test_checkout_posts_reservation_for_current_user(self) -> None:
        self.add_resource(10, "CN-B2B-07", ["cn-b2b-07a"])
        calls = self.booked_writes({"/Reservations/": {"referenceNumber": "abc123", "isPendingApproval": False}})
        code, out, _ = self.run_cli("checkout", "CN-B2B-07", "--for", "2h", "--json")
        self.assertEqual(code, 0)
        path, payload, method = calls[0]
        self.assertEqual((path, method), ("/Reservations/", None))
        self.assertEqual(payload["resourceId"], 10)
        self.assertEqual(payload["userId"], 251)
        start = datetime.fromisoformat(payload["startDateTime"])
        end = datetime.fromisoformat(payload["endDateTime"])
        self.assertEqual((end - start).total_seconds(), 7200)
        self.assertEqual(json.loads(out)["reference"], "abc123")

    def test_checkout_rejects_end_before_start(self) -> None:
        self.add_resource(10, "CN-B2B-07", ["cn-b2b-07a"])
        code, _, err = self.run_cli("checkout", "CN-B2B-07", "--start", "2030-01-01T10:00", "--until", "2030-01-01T09:00", "-n")
        self.assertEqual(code, 2)
        self.assertIn("End time must be after", err)

    def reservation(self, reference: str, hours: int = 1) -> dict[str, object]:
        start = datetime.now().astimezone()
        return {
            "referenceNumber": reference,
            "resourceId": 10,
            "resourceName": "CN-B2B-07",
            "userId": 251,
            "startDate": start.isoformat(),
            "endDate": start.replace(year=start.year + 1).isoformat() if hours else start.isoformat(),
        }

    def test_checkin_releases_single_reservation_with_delete(self) -> None:
        self.add_resource(10, "CN-B2B-07", ["cn-b2b-07a"])
        calls = self.booked_writes({"/Reservations/?": {"reservations": [self.reservation("ref1")]}})
        code, out, _ = self.run_cli("checkin", "cn-b2b-07a")
        self.assertEqual(code, 0, out)
        self.assertIn("released ref1", out)
        deletes = [(path, method) for path, _, method in calls if method == "DELETE"]
        self.assertEqual(deletes, [("/Reservations/ref1?updateScope=this", "DELETE")])

    def test_checkin_requires_ref_or_all_when_several_reservations(self) -> None:
        self.add_resource(10, "CN-B2B-07", ["cn-b2b-07a"])
        reservations = {"reservations": [self.reservation("ref1"), self.reservation("ref2")]}
        calls = self.booked_writes({"/Reservations/?": reservations})
        code, _, err = self.run_cli("checkin", "CN-B2B-07")
        self.assertEqual(code, 2)
        self.assertIn("--ref or --all", err)
        self.assertFalse([c for c in calls if c[2] == "DELETE"])
        code, out, _ = self.run_cli("checkin", "CN-B2B-07", "--ref", "ref2")
        self.assertEqual(code, 0)
        self.assertEqual([c[0] for c in calls if c[2] == "DELETE"], ["/Reservations/ref2?updateScope=this"])

    def test_checkin_without_name_only_lists(self) -> None:
        calls = self.booked_writes({"/Reservations/?": {"reservations": [self.reservation("ref1")]}})
        code, out, _ = self.run_cli("checkin")
        self.assertEqual(code, 0)
        self.assertIn("ref1", out)
        self.assertFalse([c for c in calls if c[2] == "DELETE"])

    def test_call_surfaces_booked_rejection_messages(self) -> None:
        error = bi.urllib.error.HTTPError(
            "http://x", 400, "Bad Request", {}, io.BytesIO(b'{"errors":["Missing or invalid resourceId"]}')
        )
        with mock.patch.object(bi.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(bi.UserError, "Booked rejected the request: Missing or invalid resourceId"):
                bi._call("/Reservations/", {})

    def test_gpu_model_and_host_gpu_summarize_probed_and_booked_gpus(self) -> None:
        self.assertEqual(
            bi._gpu_model("1002", "738c", "Advanced Micro Devices, Inc. [AMD/ATI] Arcturus GL-XL [Instinct MI100]"),
            "AMD Instinct MI100",
        )
        self.assertEqual(bi._gpu_model("10de", "2900", "NVIDIA Corporation Device"), "NVIDIA [10de:2900]")
        parsed = bi.parse_probe(
            "@@LSPCI\n"
            "0000:dd:00.0 Processing accelerators [1200]: Advanced Micro Devices, Inc. [AMD/ATI] Aqua Vanjaram [Instinct MI300X] [1002:74a1]\n"
            "0000:00:02.0 VGA compatible controller [0300]: Intel Corporation UHD Graphics 770 [8086:4680]\n"
            "0000:6a:00.0 Processing accelerators [1200]: Intel Corporation Device [8086:2710]\n"
            "PCIE|0000:dd:00.0|8.0 GT/s PCIe|8|32.0 GT/s PCIe|16|8.0 GT/s PCIe|8\n"
            "@@DONE\n"
        )
        self.assertEqual([gpu["model"] for gpu in parsed["gpus"]], ["AMD Instinct MI300X"])
        self.assertEqual((parsed["gpus"][0]["pcie_gen"], parsed["gpus"][0]["pcie_width"], parsed["gpus"][0]["pcie_max"]), ("Gen3", "x8", "Gen5 x16"))
        self.add_host("dual01")
        self.add_gpu("dual01", "0000:0b:00.0", model="NVIDIA L40S")
        self.add_gpu("dual01", "0001:0b:00.0", model="NVIDIA L40S")
        self.add_host("legacy-gpu01")
        self.add_gpu("legacy-gpu01", "0000:0c:00.0", model="NVIDIA A100", pcie_gen=None, pcie_width=None, pcie_cur=None, pcie_max=None)
        self.add_host("booked-gpu01", reachable=0)
        self.add_resource(1, "GPU-DEV-02", ["booked-gpu01"])
        self.db.execute("UPDATE resource SET attrs_json=? WHERE id=1", (json.dumps({"GPU": "Nvidia A40"}),))
        self.add_host("placeholder01")
        self.add_resource(2, "Placeholder", ["placeholder01"])
        self.db.execute("UPDATE resource SET attrs_json=? WHERE id=2", (json.dumps({"GPU": "None"}),))
        self.add_host("nogpu01")
        self.db.commit()
        self.assertEqual(bi.host_gpu(self.db, "dual01"), "2x NVIDIA L40S (Gen4 x16)")
        self.assertEqual(bi.host_gpu(self.db, "legacy-gpu01"), "NVIDIA A100")
        self.assertEqual(bi.host_gpu(self.db, "booked-gpu01"), "Nvidia A40")
        self.assertEqual(bi.host_gpu(self.db, "placeholder01"), "-")
        self.assertEqual(bi.host_gpu(self.db, "nogpu01"), "-")
        short_gpu = bi._short("AMD Radeon RX 9070/9070 XT/9070 GRE (Gen5 x16)", 38)
        self.assertEqual(len(short_gpu), 38)
        self.assertTrue(short_gpu.endswith("(Gen5 x16)"))

    def test_list_show_and_status_report_and_filter_gpus(self) -> None:
        self.add_host("gpu-nv01")
        self.add_adapter("gpu-nv01", "0000:01:00.0", "CN6000")
        self.add_gpu("gpu-nv01", "0000:0b:00.0", model="NVIDIA L40S", pcie_cur="Gen1 x16", pcie_max="Gen4 x16")
        self.add_gpu("gpu-nv01", "0001:0b:00.0", model="NVIDIA L40S", pcie_cur="Gen4 x16", pcie_max="Gen4 x16")
        self.add_resource(1, "gpu_b2b_01", ["gpu-nv01"])
        self.add_host("gpu-amd01")
        self.add_gpu(
            "gpu-amd01",
            "0000:43:00.0",
            vendor_id="1002",
            device_id="738c",
            pci_class="Display controller",
            model="AMD Instinct MI100",
            description="Advanced Micro Devices, Inc. [AMD/ATI] Arcturus GL-XL [Instinct MI100]",
        )
        self.add_host("cpu-only01")
        self.add_host("booked-only01", reachable=0)
        self.add_resource(2, "GPU-DEV-02", ["booked-only01"])
        self.db.execute("UPDATE resource SET attrs_json=? WHERE id=2", (json.dumps({"GPU": "Nvidia A40"}),))
        self.db.commit()

        code, text, _ = self.run_cli("list", "--offline", "--gpu")
        self.assertEqual(code, 0)
        self.assertIn("GPU", text.splitlines()[0])
        self.assertIn("gpu-nv01", text)
        self.assertIn("2x NVIDIA L40S (Gen4 x16)", text)
        self.assertIn("gpu-amd01", text)
        self.assertIn("AMD Instinct MI100 (Gen4 x16)", text)
        self.assertIn("Nvidia A40 (Booked)", text)
        self.assertNotIn("cpu-only01", text)

        code, text, _ = self.run_cli("list", "--offline", "--gpu", "10de:26b9", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(text)
        self.assertEqual([h["host"] for h in payload["hosts"]], ["gpu-nv01"])
        self.assertEqual(payload["hosts"][0]["gpu"], "2x NVIDIA L40S (Gen4 x16)")
        self.assertEqual(payload["hosts"][0]["gpu_count"], 2)
        self.assertEqual(payload["hosts"][0]["gpu_source"], "pcie")
        self.assertEqual(payload["summary"]["gpu"], 1)

        code, text, _ = self.run_cli("list", "--offline", "--gpu", "none")
        self.assertEqual(code, 0)
        self.assertIn("cpu-only01", text)
        self.assertNotIn("gpu-nv01", text)

        code, text, _ = self.run_cli("show", "gpu-nv01", "--offline")
        self.assertEqual(code, 0)
        self.assertIn("GPU: 2x NVIDIA L40S (Gen4 x16)", text)
        self.assertIn("GPUs:", text)
        self.assertIn("0000:0b:00.0  NVIDIA L40S  [10de:26b9]  PCIe Gen4 x16 (cur Gen1 x16)", text)
        self.assertIn("0001:0b:00.0  NVIDIA L40S  [10de:26b9]  PCIe Gen4 x16  3D controller", text)

        code, text, _ = self.run_cli("show", "gpu_b2b_01", "--offline")
        self.assertEqual(code, 0)
        self.assertIn("gpu=2x NVIDIA L40S (Gen4 x16)", text)

        code, text, _ = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("GPUs:    2 probed host(s) (3 PCIe device(s))", text)

    def test_pcie_slots_summary_filtering_and_show(self) -> None:
        bi.store_probe(self.db, {"host": "cn-host01", "out": PROBE_OUTPUT})
        self.add_host("single-gen5")
        self.add_slot("single-gen5", "0000:e0:01.1", pcie_gen="Gen5", pcie_width="x16")
        self.add_slot("single-gen5", "0000:a0:01.1", pcie_gen="Gen4", pcie_width="x16")
        self.add_host("venice01")
        self.add_slot("venice01", "0000:10:03.1", pcie_gen="Gen6", pcie_width="x16")
        self.add_slot("venice01", "0000:30:03.1", pcie_gen="Gen6", pcie_width="x16")
        self.add_host("noslots01")
        self.db.commit()

        self.assertEqual(bi.host_slots(self.db, "cn-host01"), "3x Gen5 x16 + Gen5 x8")
        self.assertEqual(bi.host_slots(self.db, "single-gen5"), "Gen5 x16 + Gen4 x16")
        self.assertEqual(bi.host_slots(self.db, "venice01"), "2x Gen6 x16")

        code, text, _ = self.run_cli("list", "--offline", "--pcie", "2x gen5")
        self.assertEqual(code, 0)
        self.assertIn("SLOTS", text.splitlines()[0])
        self.assertIn("cn-host01", text)
        self.assertIn("3x Gen5 x16 + Gen5 x8", text)
        self.assertNotIn("single-gen5", text)
        self.assertNotIn("venice01", text)

        code, text, _ = self.run_cli("list", "--offline", "--pcie", "gen1")
        self.assertEqual(code, 0)
        self.assertNotIn("cn-host01", text)

        code, text, _ = self.run_cli("list", "--offline", "--pcie", ">2 gen5")
        self.assertEqual(code, 0)
        self.assertIn("cn-host01", text)

        code, text, _ = self.run_cli("list", "--offline", "--pcie", "none")
        self.assertEqual(code, 0)
        self.assertIn("noslots01", text)
        self.assertNotIn("cn-host01", text)

        code, text, _ = self.run_cli("list", "--offline", "--slots", "2x gen6", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(text)
        self.assertEqual([h["host"] for h in payload["hosts"]], ["venice01"])
        self.assertEqual(payload["hosts"][0]["pcie_slots"], "2x Gen6 x16")

        code, text, _ = self.run_cli("show", "cn-host01", "--offline")
        self.assertEqual(code, 0)
        self.assertIn("PCIe slots: 3x Gen5 x16 + Gen5 x8", text)
        self.assertIn("Slots:", text)
        self.assertIn("0000:0a:02.0  PCIe Gen5 x16 (cur Gen1 x16)", text)

    def test_arm_cpu_probe_parsing_midr_lscpu_bios_and_sockets(self) -> None:
        grace_probe = """@@FQDN arm-grace01.example.com
@@SYS
SYS|vendor|NVIDIA
SYS|model|Grace CPU Superchip
SYS|arch|aarch64
SYS|cpu|
SYS|cpu_proc|
SYS|cpu_impl|0x41
SYS|cpu_part|0xd4f
SYS|lscpu_vendor|ARM
SYS|lscpu_model|-
SYS|lscpu_bios|NVIDIA Grace
SYS|lscpu_sockets|2
SYS|sockets|0
SYS|cores|144
SYS|os|Rocky Linux 9.4 (Blue Onyx)
SYS|kernel|5.14.0-427.el9.aarch64
@@DONE
"""
        parsed = bi.parse_probe(grace_probe)
        self.assertEqual(parsed["sys"]["cpu"], "NVIDIA Grace (ARM Neoverse-V2)")
        self.assertEqual(parsed["sys"]["sockets"], "2")
        self.assertEqual(parsed["sys"]["cores"], "144")

        # When lscpu is unavailable or returns "-" for Model name, MIDR resolves the core.
        midr_only = bi.parse_probe(
            "@@SYS\nSYS|arch|aarch64\nSYS|cpu|\nSYS|cpu_impl|0x41\nSYS|cpu_part|0xd4f\n"
            "SYS|lscpu_vendor|\nSYS|lscpu_model|\nSYS|sockets|0\nSYS|cores|72\n@@DONE\n"
        )
        self.assertEqual(midr_only["sys"]["cpu"], "ARM Neoverse-V2")
        self.assertEqual(midr_only["sys"]["sockets"], "1")

        # Generic /proc/cpuinfo ARM placeholder is replaced when MIDR or lscpu knows the core.
        generic_upgraded = bi.parse_probe(
            "@@SYS\nSYS|arch|aarch64\nSYS|cpu|ARMv8 Processor rev 0 (v8l)\n"
            "SYS|cpu_impl|0x41\nSYS|cpu_part|0xd0c\n"
            "SYS|lscpu_bios|Ampere(R) Altra(R) Processor Q80-30 CPU @ 3.0GHz Not Specified\n"
            "SYS|sockets|0\nSYS|cores|80\n@@DONE\n"
        )
        self.assertEqual(
            generic_upgraded["sys"]["cpu"],
            "Ampere(R) Altra(R) Processor Q80-30 CPU @ 3.0GHz (ARM Neoverse-N1)",
        )
        self.assertEqual(generic_upgraded["sys"]["sockets"], "1")
        short_cpu = bi._short(generic_upgraded["sys"]["cpu"], 44)
        self.assertEqual(len(short_cpu), 44)
        self.assertTrue(short_cpu.endswith("(ARM Neoverse-N1)"))

        # Vendor-specific and unknown ARM MIDR part numbers format cleanly without duplicating vendor.
        self.assertEqual(bi._cpu_model({"cpu_impl": "0xc0", "cpu_part": "0xac3"}), "Ampere-1")
        self.assertEqual(bi._cpu_model({"cpu_impl": "0x46", "cpu_part": "0x001"}), "Fujitsu A64FX")
        self.assertEqual(bi._cpu_model({"cpu_impl": "0x41", "cpu_part": "0xdff"}), "ARM [0x41:0xdff]")
        self.assertEqual(
            bi._cpu_model({"cpu_proc": "ARMv7 Processor rev 3 (v7l)", "arch": "armv7l"}),
            "ARMv7 Processor rev 3 (v7l)",
        )
        self.assertEqual(bi._cpu_model({"arch": "aarch64"}), "ARM64")

    def test_arm_cpu_list_filtering_show_and_stale_reprobe(self) -> None:
        grace_probe = """@@FQDN arm-grace01.example.com
@@SYS
SYS|vendor|NVIDIA
SYS|model|Grace Superchip
SYS|arch|aarch64
SYS|cpu|
SYS|cpu_impl|0x41
SYS|cpu_part|0xd4f
SYS|lscpu_bios|NVIDIA Grace
SYS|sockets|2
SYS|cores|144
SYS|os|Rocky Linux 9.4
SYS|kernel|5.14.0-427.el9.aarch64
@@DONE
"""
        bi.store_probe(self.db, {"host": "arm-grace01", "out": grace_probe})
        self.add_host("arm-a64fx01", model="Fujitsu FX700", cpu="Fujitsu A64FX", os_name="Rocky Linux 9")
        self.add_host("arm-ampere01", model="Mt. Jade", cpu="Ampere-1", os_name="Ubuntu 24.04")
        self.add_host("x86-epyc01", model="Lenovo SR655", cpu="AMD EPYC 9654", os_name="Rocky Linux 9")
        self.db.execute("INSERT INTO host(name, source) VALUES ('unprobed01', 'booked')")
        self.db.commit()

        for query in ("arm", "ARM64", "aarch64"):
            code, text, _ = self.run_cli("list", "--offline", "--cpu", query, "--json")
            self.assertEqual(code, 0)
            hosts = [h["host"] for h in json.loads(text)["hosts"]]
            self.assertEqual(hosts, ["arm-a64fx01", "arm-ampere01", "arm-grace01"])

        code, text, _ = self.run_cli("list", "--offline", "--cpu", "neoverse", "--json")
        self.assertEqual(code, 0)
        self.assertEqual([h["host"] for h in json.loads(text)["hosts"]], ["arm-grace01"])

        code, text, _ = self.run_cli("list", "--offline", "--cpu", "x86", "--json")
        self.assertEqual(code, 0)
        self.assertEqual([h["host"] for h in json.loads(text)["hosts"]], ["x86-epyc01"])

        # Kernel architecture fallback when CPU model string is absent or custom.
        self.assertTrue(bi._matches_cpu("arm", None, "5.14.0-427.el9.aarch64"))
        self.assertTrue(bi._matches_cpu("x86", None, "5.14.0-427.el9.x86_64"))
        self.assertFalse(bi._matches_cpu("arm", None, None))
        self.assertTrue(bi._matches_cpu("", None, None))

        code, text, _ = self.run_cli("show", "arm-grace01", "--offline")
        self.assertEqual(code, 0)
        self.assertIn("CPU: NVIDIA Grace (ARM Neoverse-V2)", text)
        self.assertIn("Sockets: 2", text)
        self.assertIn("Cores: 144", text)

        # Reachable ARM hosts cached before ARM support had sockets='0';
        # _stale_hosts must re-probe them once while leaving hosts with sockets!='0' fresh.
        self.db.execute(
            "INSERT INTO host(name, probed_at, reachable, cpu, sockets, cores, os) "
            "VALUES ('legacy-arm01', datetime('now'), 1, NULL, '0', '80', 'Rocky Linux 9.4')"
        )
        self.db.execute(
            "INSERT INTO host(name, probed_at, reachable, cpu, sockets, cores, os) "
            "VALUES ('no-os-release01', datetime('now'), 1, 'ARM Neoverse-N1', '1', '80', NULL)"
        )
        self.db.commit()
        stale = bi._stale_hosts(self.db, self.update_args())
        self.assertIn("legacy-arm01", stale)
        self.assertNotIn("no-os-release01", stale)
        self.assertNotIn("arm-grace01", stale)
        self.assertNotIn("x86-epyc01", stale)


if __name__ == "__main__":
    unittest.main()
