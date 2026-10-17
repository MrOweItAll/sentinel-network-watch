"""Synthetic owner-table fixtures only: no live IP Helper, sockets or credentials."""

from contextlib import redirect_stdout
import ctypes
import io
import ipaddress
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from sentinel_watch import windows as sut


def address4(value):
    return int.from_bytes(ipaddress.IPv4Address(value).packed, "little")


def port(value):
    return int.from_bytes(struct.pack("!H", value) + b"\x00\x00", "little")


def scope(value):
    return int.from_bytes(struct.pack("!I", value), "little")


def table(protocol, family, *rows):
    return struct.pack("<I", len(rows)) + b"".join(sut.ROW_STRUCTS[(protocol, family)].pack(*row) for row in rows)


TCP4_ROW = (5, address4("192.0.2.10"), port(49152), address4("198.51.100.20"), port(443), 4294967295)


class ParserTests(unittest.TestCase):
    def test_sdk_row_sizes(self):
        self.assertEqual([sut.ROW_STRUCTS[key].size for key in
                          (("TCP", sut.AF_INET), ("TCP", sut.AF_INET6),
                           ("UDP", sut.AF_INET), ("UDP", sut.AF_INET6))], [24, 56, 12, 28])

    def test_ipv4_tuple_port_pid_and_state(self):
        row = sut.parse_owner_table(table("TCP", sut.AF_INET, TCP4_ROW), "TCP", sut.AF_INET)[0]
        self.assertEqual((row["local_address"], row["local_port"], row["remote_address"],
                          row["remote_port"], row["pid"], row["state_code"], row["state"]),
                         ("192.0.2.10", 49152, "198.51.100.20", 443, 4294967295, 5, "Established"))
        self.assertTrue(row["remote_endpoint_meaningful"])

    def test_port_byte_order_boundaries_and_unused_high_word(self):
        for value in (0, 1, 22, 53, 80, 443, 1053, 3000, 49152, 65535):
            self.assertEqual(sut.decode_port(port(value)), value)
            self.assertEqual(sut.decode_port(port(value) | 0xCAFE0000), value)

    def test_ipv6_addresses_scopes_ports_pid_and_layout(self):
        wire = (ipaddress.IPv6Address("fe80::1234").packed, scope(17), port(1053),
                ipaddress.IPv6Address("fe80::abcd").packed, scope(29), port(65535), 8, 123456)
        row = sut.parse_owner_table(table("TCP", sut.AF_INET6, wire), "TCP", sut.AF_INET6)[0]
        self.assertEqual((row["local_address"], row["local_scope_id"], row["local_port"],
                          row["remote_address"], row["remote_scope_id"], row["remote_port"],
                          row["pid"], row["state_code"]),
                         ("fe80::1234", 17, 1053, "fe80::abcd", 29, 65535, 123456, 8))
        self.assertEqual(row["local_scope_id_raw"], scope(17))
        self.assertEqual(row["remote_scope_id_raw"], scope(29))
        self.assertEqual(row["local_address_scoped"], "fe80::1234%17")
        self.assertEqual(row["state"], "CloseWait")

    def test_listener_preserves_tuple_but_marks_remote_undefined(self):
        listener = (2, address4("0.0.0.0"), port(80), address4("0.0.0.0"), 0, 4)
        row = sut.parse_owner_table(table("TCP", sut.AF_INET, listener), "TCP", sut.AF_INET)[0]
        self.assertEqual(row["state"], "Listen")
        self.assertFalse(row["remote_endpoint_meaningful"])

    def test_udp_has_local_endpoint_only_not_a_remote_or_listen_claim(self):
        for family, wire in ((sut.AF_INET, (address4("127.0.0.1"), port(53), 0)),
                             (sut.AF_INET6, (ipaddress.IPv6Address("::1").packed, 0, port(5353), 9876))):
            row = sut.parse_owner_table(table("UDP", family, wire), "UDP", family)[0]
            self.assertFalse(row["remote_peer_available"])
            self.assertNotIn("remote_address", row)
            self.assertNotIn("state", row)
            self.assertEqual(row["local_port"], 53 if family == sut.AF_INET else 5353)

    def test_unknown_state_retains_numeric_value(self):
        wire = (999,) + TCP4_ROW[1:]
        row = sut.parse_owner_table(table("TCP", sut.AF_INET, wire), "TCP", sut.AF_INET)[0]
        self.assertEqual((row["state_code"], row["state"]), (999, "Unknown"))

    def test_multiple_rows_count_and_extra_allocation_padding(self):
        raw = table("TCP", sut.AF_INET, TCP4_ROW, TCP4_ROW) + b"\x00" * 100
        rows = sut.parse_owner_table(raw, "TCP", sut.AF_INET)
        self.assertEqual(len(rows), 2)
        self.assertEqual([row["row_index"] for row in rows], [0, 1])
        self.assertEqual(sut.parse_owner_table(struct.pack("<I", 0) + b"padding", "UDP", sut.AF_INET), [])

    def test_truncated_count_and_rows_are_rejected(self):
        for raw in (b"", b"\x00" * 3, struct.pack("<I", 1), table("TCP", sut.AF_INET, TCP4_ROW)[:-1]):
            with self.assertRaises(sut.OwnerTableError) as error:
                sut.parse_owner_table(raw, "TCP", sut.AF_INET)
            self.assertEqual(error.exception.code, "E_TABLE_TRUNCATED")
        with self.assertRaises(sut.OwnerTableError) as error:
            sut.parse_owner_table(struct.pack("<I", sut.MAX_ROWS + 1), "TCP", sut.AF_INET)
        self.assertEqual(error.exception.code, "E_TABLE_COUNT")


class BufferTests(unittest.TestCase):
    def test_native_size_query_and_buffer_growth_retry(self):
        payload = table("TCP", sut.AF_INET, TCP4_ROW)
        calls = []
        def function(buffer, size_pointer, ordered, family, table_class, reserved):
            calls.append((buffer is None, ordered, family, table_class, reserved))
            size = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_uint32)).contents
            if buffer is None:
                size.value = 4
                return 122
            if size.value < len(payload):
                size.value = len(payload)
                return 122
            ctypes.memmove(buffer, payload, len(payload))
            size.value = len(payload)
            return 0
        self.assertEqual(sut.read_raw_table(function, sut.AF_INET, sut.TCP_TABLE_OWNER_PID_ALL), payload)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(item[1:] == (False, 2, 5, 0) for item in calls))

    def test_api_error_size_cap_and_bounded_churn(self):
        with self.assertRaises(sut.OwnerTableError) as error:
            sut.read_raw_table(lambda *args: 5, sut.AF_INET, 5)
        self.assertEqual((error.exception.code, error.exception.api_return_code), ("E_API_RETURN", 5))
        def churn(buffer, pointer, *args):
            size = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents
            size.value = max(4, size.value + 4)
            return 122
        with self.assertRaises(sut.OwnerTableError) as error:
            sut.read_raw_table(churn, sut.AF_INET, 5, max_attempts=2)
        self.assertEqual(error.exception.code, "E_API_CHURN")
        def enormous(buffer, pointer, *args):
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents.value = sut.MAX_TABLE_BYTES + 1
            return 122
        with self.assertRaises(sut.OwnerTableError) as error:
            sut.read_raw_table(enormous, sut.AF_INET, 5)
        self.assertEqual(error.exception.code, "E_API_SIZE")

    def test_snapshot_fake_api_partial_failure_and_safe_summary(self):
        class FakeApi:
            def read(self, protocol, family):
                if family == sut.AF_INET6:
                    raise sut.OwnerTableError("E_API_RETURN", 50)
                return table(protocol, family, TCP4_ROW) if protocol == "TCP" else table(protocol, family)
        snapshot = sut.collect_snapshot(api=FakeApi(), clock=lambda: 2_000_000_000)
        self.assertFalse(snapshot["ok"])
        summary = sut.safe_summary(snapshot)
        self.assertEqual(summary["counts"], {"TCP_IPv4": 1, "TCP_IPv6": 0})
        text = json.dumps(summary)
        for detail in ("192.0.2.10", "198.51.100.20", "4294967295", "local_address", "remote_address"):
            self.assertNotIn(detail, text)
        self.assertEqual(summary["errors"][0]["api_return_code"], 50)


class OutputTests(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            real_mkdir = os.mkdir
            def inherited_mode(path, mode=0o777, *, dir_fd=None):
                return real_mkdir(path, 0o777 if mode == 0o700 else mode)
            patcher = mock.patch("os.mkdir", side_effect=inherited_mode)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.parent = Path(__file__).resolve().parent
        self.temporary = tempfile.TemporaryDirectory(prefix=".owner-table-fixtures-", dir=self.parent)
        self.addCleanup(self.cleanup)
        self.root = Path(self.temporary.name) / "access"
        self.root.mkdir()
        self.private = self.root / "private"
        self.private.mkdir()

    def cleanup(self):
        self.assertEqual(Path(self.temporary.name).resolve().parent, self.parent)
        self.temporary.cleanup()

    def test_output_containment_existing_parent_and_no_overwrite(self):
        output = self.private / "fixture.json"
        self.assertEqual(sut.validate_output_path(output, self.root), output)
        for path in (self.root.parent / "outside.json", self.root / ".." / "outside.json",
                     self.root / "missing" / "fixture.json", self.private / "fixture.txt"):
            with self.assertRaises(sut.OwnerTableError):
                sut.validate_output_path(path, self.root)
        output.write_text("public fixture")
        with self.assertRaises(sut.OwnerTableError) as error:
            sut.validate_output_path(output, self.root)
        self.assertEqual(error.exception.code, "E_OUTPUT_EXISTS")

    def test_reparse_directory_is_rejected(self):
        actual_lstat = Path.lstat
        def lstat(path, *args, **kwargs):
            if path == self.private:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400)
            return actual_lstat(path, *args, **kwargs)
        with mock.patch.object(Path, "lstat", lstat), self.assertRaises(sut.OwnerTableError):
            sut.validate_output_path(self.private / "fixture.json", self.root)

    def test_invalid_output_prevents_any_capture_and_stdout_is_fixed_only(self):
        stream = io.StringIO()
        with mock.patch.object(sut, "collect_snapshot") as capture, redirect_stdout(stream):
            result = sut.main(["--output", str(self.root.parent / "outside.json")])
        self.assertEqual(result, 1)
        capture.assert_not_called()
        self.assertEqual(json.loads(stream.getvalue())["error"], "E_OUTPUT_PATH")

    def test_valid_cli_writes_rows_only_to_private_file_and_prints_counts(self):
        class FakeApi:
            def read(self, protocol, family):
                return table(protocol, family, TCP4_ROW) if family == sut.AF_INET else table(protocol, family)
        snapshot = sut.collect_snapshot(api=FakeApi(), clock=lambda: 2_000_000_000)
        output = self.private / "snapshot.json"
        stream = io.StringIO()
        with mock.patch.object(sut, "ACCESS_ROOT", self.root), \
                mock.patch.object(sut, "collect_snapshot", return_value=snapshot) as capture, \
                redirect_stdout(stream):
            result = sut.main(["--output", str(output)])
        self.assertEqual(result, 0)
        capture.assert_called_once_with(include_udp=False)
        self.assertEqual(json.loads(output.read_text())["tables"]["TCP_IPv4"]["rows"][0]["local_address"], "192.0.2.10")
        public = stream.getvalue()
        self.assertEqual(json.loads(public)["counts"], {"TCP_IPv4": 1, "TCP_IPv6": 0})
        for private_value in ("192.0.2.10", "198.51.100.20", "4294967295", str(output)):
            self.assertNotIn(private_value, public)


if __name__ == "__main__":
    unittest.main(verbosity=2)
