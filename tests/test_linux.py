"""Synthetic /proc fixtures only: no host process, socket, argv or env reads."""
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sentinel_watch import linux


def encoded(address, port):
    raw = ipaddress.ip_address(address).packed
    words = "".join(f"{int.from_bytes(raw[i:i + 4], sys.byteorder):08X}" for i in range(0, len(raw), 4))
    return f"{words}:{port:04X}"


def row(local="192.0.2.10", peer="198.51.100.20", local_port=50000, peer_port=443,
        state=1, inode=123, uid=1000):
    return f"0: {encoded(local, local_port)} {encoded(peer, peer_port)} {state:02X} 00000000:00000000 00:00000000 00000000 {uid} 0 {inode} 1 0\n"


class LinuxFixtures(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            native_mkdir = os.mkdir
            patcher = mock.patch.object(os, "mkdir", side_effect=lambda path, mode=0o777, **kw:
                                        native_mkdir(path, 0o777 if mode == 0o700 else mode, **kw))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix=".test-linux-", dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.links = {}
        (self.root / "net").mkdir()
        (self.root / "sys/kernel/random").mkdir(parents=True)
        (self.root / "sys/kernel/random/boot_id").write_text("12345678-1234-5678-1234-567812345678\n")
        self.table(4)
        self.table(6)
        patcher = mock.patch.object(linux, "_readlink", side_effect=lambda path: self.links[str(path)])
        patcher.start()
        self.addCleanup(patcher.stop)

    def table(self, family, rows=""):
        path = self.root / ("net/tcp" if family == 4 else "net/tcp6")
        path.write_text("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + rows)

    def process(self, pid=10, inode=123, start=100, executable="/usr/bin/synthetic-client", content=b"synthetic executable"):
        path = self.root / str(pid)
        path.mkdir(exist_ok=True)
        (path / "fd").mkdir(exist_ok=True)
        # comm intentionally contains spaces and ')' to exercise field indexing.
        fields = ["S"] + ["0"] * 18 + [str(start)]
        (path / "stat").write_text(f"{pid} (odd ) process) " + " ".join(fields) + "\n")
        (path / "exe").write_bytes(content)
        (path / "fd/3").write_bytes(b"")
        self.links[str(path / "exe")] = executable
        self.links[str(path / "fd/3")] = f"socket:[{inode}]"
        return path

    def collect(self, **kwargs):
        return linux.collect_linux_records("synthetic-linux-actor", 1000.0, self.root, **kwargs)

    def test_tcp4_known_binary_and_listener_are_distinct(self):
        self.table(4, row() + row(local="0.0.0.0", peer="0.0.0.0", local_port=22, peer_port=0, state=10, inode=124))
        self.process()
        self.process(pid=11, inode=124, executable="/usr/sbin/synthetic-server")
        result = self.collect()
        connection, listener = result["records"]
        self.assertEqual((connection["kind"], connection["transport"], connection["destination_address"], connection["destination_port"]),
                         ("native_tcp", "TCP", "198.51.100.20", 443))
        self.assertEqual((listener["kind"], listener["destination_address"], listener["destination_port"]), ("listener", "0.0.0.0", 22))
        self.assertEqual(connection["evidence"]["direction"], "unknown")
        self.assertTrue(connection["evidence"]["app_identity_complete"])
        self.assertEqual(result["coverage"]["attributed"], 2)
        self.assertTrue(result["coverage"]["ok"])
        self.assertFalse(result["coverage"]["complete_stream_visibility"])

    def test_tcp6_native_word_byte_order(self):
        self.table(6, row(local="2001:db8::10", peer="2001:db8::20", inode=123))
        self.process()
        record = self.collect()["records"][0]
        self.assertEqual(record["destination_address"], "2001:db8::20")
        self.assertEqual(record["evidence"]["local_address"], "2001:db8::10")
        self.assertEqual(record["evidence"]["address_family"], 6)

    def test_ipv6_link_local_scope_is_not_invented(self):
        self.table(6, row(local="fe80::10", peer="fe80::20"))
        self.process()
        result = self.collect()
        self.assertFalse(result["records"][0]["evidence"]["endpoint_complete"])
        self.assertFalse(result["records"][0]["evidence"]["ipv6_interface_scope_known"])
        self.assertNotIn("%", result["records"][0]["destination_address"])
        self.assertEqual(result["coverage"]["unscoped_ipv6_link_local"], 1)

    def test_ordinary_binary_context_survives_pid_and_starttime_change(self):
        self.table(4, row())
        process = self.process()
        first = self.collect()["records"][0]
        (process / "fd/3").unlink()
        self.process(pid=20, start=200)
        second = self.collect()["records"][0]
        self.assertEqual(first["app_context_key"], second["app_context_key"])
        self.assertNotEqual(first["observation_id"], second["observation_id"])

    def test_binary_change_changes_context(self):
        self.table(4, row())
        process = self.process()
        first = self.collect()["records"][0]
        (process / "exe").write_bytes(b"updated synthetic executable")
        second = self.collect()["records"][0]
        self.assertNotEqual(first["app_context_key"], second["app_context_key"])

    def test_interpreter_is_process_lifetime_not_script_identity(self):
        self.table(4, row())
        self.process(executable="/usr/bin/python3.12")
        first = self.collect()["records"][0]
        second = self.collect()["records"][0]
        self.assertEqual(first["app_context_key"], second["app_context_key"])
        self.assertEqual(first["evidence"]["identity_scope"], "process_lifetime")
        self.assertFalse(first["evidence"]["script_identity_known"])
        self.process(start=101, executable="/usr/bin/python3.12")
        third = self.collect()["records"][0]
        self.assertNotEqual(first["app_context_key"], third["app_context_key"])

    def test_interpreter_boot_change_rebinds_context(self):
        self.table(4, row())
        self.process(executable="/usr/bin/node")
        first = self.collect()["records"][0]
        (self.root / "sys/kernel/random/boot_id").write_text("22345678-1234-5678-1234-567812345678")
        second = self.collect()["records"][0]
        self.assertNotEqual(first["app_context_key"], second["app_context_key"])
        self.assertNotIn("22345678-1234", json.dumps(second))

    def test_unowned_socket_context_is_capture_specific(self):
        self.table(4, row())
        first = self.collect()["records"][0]
        second = self.collect()["records"][0]
        self.assertFalse(first["evidence"]["app_identity_complete"])
        self.assertEqual(first["evidence"]["attribution_error"], "E_OWNER_UNKNOWN")
        self.assertNotEqual(first["app_context_key"], second["app_context_key"])

    def test_multiple_holders_are_not_arbitrarily_assigned(self):
        self.table(4, row())
        self.process()
        self.process(pid=20)
        record = self.collect()["records"][0]
        self.assertEqual(record["evidence"]["attribution_error"], "E_OWNER_AMBIGUOUS")
        self.assertNotIn("executable_path", record["evidence"])

    def test_pid_reuse_during_attribution_fails_closed(self):
        self.table(4, row())
        self.process()
        with mock.patch.object(linux, "_starttime", side_effect=[100, 100, 200]):
            record = self.collect()["records"][0]
        self.assertFalse(record["evidence"]["app_identity_complete"])
        self.assertEqual(record["evidence"]["attribution_error"], "E_PROCESS_CHANGED")
        self.assertNotIn("executable_sha256", record["evidence"])

    def test_socket_fd_reuse_during_hashing_fails_closed(self):
        self.table(4, row())
        process = self.process()
        original = linux._binary
        def changed(*args):
            value = original(*args)
            self.links[str(process / "fd/3")] = "socket:[999]"
            return value
        with mock.patch.object(linux, "_binary", side_effect=changed):
            record = self.collect()["records"][0]
        self.assertEqual(record["evidence"]["attribution_error"], "E_PROCESS_CHANGED")

    def test_exec_with_same_pid_starttime_fails_closed(self):
        self.table(4, row())
        process = self.process()
        original = linux._binary
        def changed(*args):
            value = original(*args)
            self.links[str(process / "exe")] = "/usr/bin/different-client"
            return value
        with mock.patch.object(linux, "_binary", side_effect=changed):
            record = self.collect()["records"][0]
        self.assertEqual(record["evidence"]["attribution_error"], "E_EXE_CHANGED")

    def test_socket_missing_from_second_table_is_unattributed(self):
        self.table(4, row())
        self.process()
        original = linux._read_table
        calls = 0
        def disappearing(path, family, coverage):
            nonlocal calls
            calls += 1
            result = original(path, family, coverage)
            return [] if calls > 2 else result
        with mock.patch.object(linux, "_read_table", side_effect=disappearing):
            record = self.collect()["records"][0]
        self.assertEqual(record["evidence"]["attribution_error"], "E_SOCKET_CHANGED")

    def test_large_or_unreadable_binary_stays_unknown(self):
        self.table(4, row())
        self.process(content=b"too large")
        with mock.patch.object(linux, "MAX_BINARY_BYTES", 3):
            record = self.collect()["records"][0]
        self.assertEqual(record["evidence"]["attribution_error"], "E_BINARY_LIMIT")
        self.assertFalse(record["evidence"]["app_identity_complete"])
        self.assertNotIn("executable_path", record["evidence"])

    def test_unreadable_executable_stays_unknown(self):
        self.table(4, row())
        process = self.process()
        (process / "exe").unlink()
        record = self.collect()["records"][0]
        self.assertEqual(record["evidence"]["attribution_error"], "E_PROCESS_UNAVAILABLE")
        self.assertFalse(record["evidence"]["app_identity_complete"])

    def test_oversized_metadata_path_is_not_emitted(self):
        self.table(4, row())
        self.process(executable="/" + "\u00e9" * 1500)
        record = self.collect()["records"][0]
        self.assertEqual(record["evidence"]["attribution_error"], "E_EXE_PATH")
        self.assertNotIn("executable_path", record["evidence"])

    def test_other_tcp_states_are_not_connections_or_listeners(self):
        self.table(4, row(state=2) + row(state=6))
        self.assertEqual(self.collect()["records"], [])

    def test_malformed_rows_and_missing_ipv6_report_gaps(self):
        self.table(4, "not a socket row\n")
        (self.root / "net/tcp6").unlink()
        result = self.collect()
        self.assertEqual(result["records"], [])
        self.assertFalse(result["coverage"]["ok"])
        self.assertFalse(result["coverage"]["tcp6_read_ok"])
        self.assertGreater(result["coverage"]["parse_errors"], 0)

    def test_row_limit_is_reported(self):
        self.table(4, row() + row(inode=124))
        with mock.patch.object(linux, "MAX_ROWS", 1):
            result = self.collect()
        self.assertEqual(len(result["records"]), 1)
        self.assertTrue(result["coverage"]["limits_reached"])
        self.assertFalse(result["coverage"]["ok"])
        self.assertFalse(result["records"][0]["evidence"]["app_identity_complete"])

    def test_arguments_environment_and_payload_are_never_opened(self):
        self.table(4, row())
        process = self.process()
        (process / "cmdline").write_text("FAKE_PRIVATE_ARGUMENT")
        (process / "environ").write_text("FAKE_PRIVATE_ENVIRONMENT")
        original = linux._read_text
        opened = []
        def guarded(path, maximum):
            opened.append(path.name)
            self.assertNotIn(path.name, ("cmdline", "environ"))
            return original(path, maximum)
        with mock.patch.object(linux, "_read_text", side_effect=guarded):
            result = self.collect()
        self.assertNotIn("FAKE_PRIVATE", json.dumps(result))
        self.assertFalse(result["coverage"]["arguments_or_environment_read"])

    def test_records_match_existing_review_ingest_schema(self):
        from sentinel_watch.review import ReviewQueue
        self.table(4, row())
        self.process()
        record = self.collect()["records"][0]
        with ReviewQueue(self.root / "fixture.sqlite3") as queue:
            view = queue.ingest(record)
            self.assertEqual(view["status"], "pending")

    def test_invalid_actor_or_timestamp_rejected_before_reads(self):
        with mock.patch.object(linux, "_read_text", side_effect=AssertionError("read")):
            for actor, observed in [("bad\nactor", 1), ("actor", True), ("actor", float("nan"))]:
                with self.assertRaises(linux.ObservationError):
                    linux.collect_linux_records(actor, observed, self.root)


if __name__ == "__main__":
    unittest.main()
