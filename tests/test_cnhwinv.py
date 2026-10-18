"""Regression tests for the offline, stdlib-only cnhwinv (Cornelis Networks Hardware Inventory) CLI."""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import io
import json
import os
import sqlite3
import sys
import tempfile
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
0000:41:00.0 Network controller [0280]: Cornelis Networks Inc CN5000 [434e:0001]
0000:81:00.0 Network controller [0280]: Cornelis Networks Inc CN6000 [434e:0002]
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


class InventoryTestCase(unittest.TestCase):
    """Each test gets an independent SQLite cache outside the real XDG cache."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "inventory.db"
        self.db = bi.open_db(self.db_path)

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

    def test_ssh_probe_uses_mocked_subprocess_and_read_only_script(self) -> None:
        process = mock.Mock(stdout="@@DONE\n", stderr="")
        with mock.patch.object(bi.subprocess, "run", return_value=process) as run:
            result = bi.ssh_probe("cn-host01", 30)
        self.assertEqual(result, {"host": "cn-host01", "out": "@@DONE\n"})
        command = run.call_args.args[0]
        self.assertEqual(command[0], "ssh")
        self.assertEqual(run.call_args.kwargs["input"], bi.REMOTE_SCRIPT)
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
        old.commit()
        old.close()
        self.db = bi.open_db(self.db_path)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(host)")}
        self.assertTrue({"source", "model", "cpu", "sockets", "cores", "os", "kernel"}.issubset(columns))
        bi.store_probe(self.db, {"host": "cn-host01", "out": PROBE_OUTPUT})
        self.db.commit()
        row = self.db.execute("SELECT reachable, model, cpu, os FROM host WHERE name='cn-host01'").fetchone()
        self.assertEqual(tuple(row), (1, "Cornelis Networks CN6000 Test Platform", "Intel(R) Xeon(R) Gold 6430", "Rocky Linux 9.4"))
        ports = self.db.execute("SELECT kind, ifname FROM port WHERE host='cn-host01' ORDER BY kind").fetchall()
        self.assertEqual([tuple(port) for port in ports], [("eth", "ens1"), ("opa", "hfi1_0")])

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

        with mock.patch.object(bi, "_booked_session") as session, mock.patch.object(bi, "_call", side_effect=responses) as call, mock.patch.object(
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

        with mock.patch.object(bi, "_booked_session") as session, mock.patch.object(bi, "_call", side_effect=responses) as call, mock.patch.object(
            bi, "datetime"
        ) as clock:
            session.return_value.__enter__.return_value = {"X-Booked-SessionToken": "token"}
            clock.now.return_value = datetime(2026, 10, 17, 20, 0, tzinfo=timezone.utc)
            clock.fromisoformat.side_effect = datetime.fromisoformat
            bi.refresh_availability(self.db)

        self.assertEqual(call.call_count, 2)
        state, owner = self.db.execute("SELECT avail_state, reserved_by FROM resource WHERE id=1").fetchone()
        self.assertEqual((state, owner), ("reserved", "Ada Lovelace"))

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


if __name__ == "__main__":
    unittest.main()
