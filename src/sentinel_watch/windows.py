#!/usr/bin/env python3
"""Read Windows owner-PID endpoint tables without packets or process arguments.

Importing this module never loads the API or captures a table. The executable
entry point writes endpoint details only into an explicitly selected private case
folder; stdout contains counts/error codes.
"""

from __future__ import annotations

import argparse
from .arguments import SafeArgumentParser
import ctypes
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import stat
import struct
import time

AF_INET = 2
AF_INET6 = 23  # Windows value, independent of the test host's socket module.
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
ERROR_INSUFFICIENT_BUFFER = 122
MAX_TABLE_BYTES = 64 * 1024 * 1024
MAX_ROWS = 1_000_000
ACCESS_ROOT = None
ROW_STRUCTS = {
    ("TCP", AF_INET): struct.Struct("<6I"),
    ("TCP", AF_INET6): struct.Struct("<16sII16sIIII"),
    ("UDP", AF_INET): struct.Struct("<3I"),
    ("UDP", AF_INET6): struct.Struct("<16sIII"),
}
TCP_STATES = {
    1: "Closed", 2: "Listen", 3: "SynSent", 4: "SynReceived",
    5: "Established", 6: "FinWait1", 7: "FinWait2", 8: "CloseWait",
    9: "Closing", 10: "LastAck", 11: "TimeWait", 12: "DeleteTcb",
}
SAFE_ERRORS = frozenset({
    "E_PLATFORM", "E_ARGUMENT", "E_API_LOAD", "E_API_RETURN", "E_API_SIZE",
    "E_API_CHURN", "E_TABLE_TRUNCATED", "E_TABLE_COUNT", "E_TABLE_FORMAT",
    "E_OUTPUT_PATH", "E_OUTPUT_EXISTS", "E_OUTPUT_WRITE", "E_CAPTURE",
})


class OwnerTableError(Exception):
    def __init__(self, code: str, api_return_code: int | None = None):
        self.code = code if code in SAFE_ERRORS else "E_CAPTURE"
        self.api_return_code = api_return_code
        super().__init__(self.code)


def decode_port(value: int) -> int:
    """Windows stores a network-order unsigned short in the DWORD's low half."""
    return int.from_bytes(struct.pack("<H", value & 0xFFFF), "big")


def decode_scope(value: int) -> int:
    """SDK documents IPv6 scope DWORDs as network byte order (ntohl)."""
    return int.from_bytes(struct.pack("<I", value), "big")


def _ipv4(value: int) -> str:
    # in_addr bytes are already in network order in Windows memory.
    return str(ipaddress.IPv4Address(struct.pack("<I", value)))


def _scope_fields(local: bytes, local_scope_raw: int,
                  remote: bytes | None = None, remote_scope_raw: int = 0) -> dict:
    result = {}
    endpoints = (("local", local, local_scope_raw),)
    if remote is not None:
        endpoints += (("remote", remote, remote_scope_raw),)
    for side, address, raw_scope in endpoints:
        text = str(ipaddress.IPv6Address(address))
        scope = decode_scope(raw_scope)
        result.update({side + "_address": text, side + "_scope_id": scope,
                       side + "_scope_id_raw": raw_scope,
                       side + "_address_scoped": text + ("%" + str(scope) if scope else "")})
    return result


def parse_owner_table(raw: bytes, protocol: str, family: int) -> list[dict]:
    """Parse only dwNumEntries rows; allocation padding is deliberately ignored."""
    if (protocol, family) not in ROW_STRUCTS or not isinstance(raw, bytes):
        raise OwnerTableError("E_ARGUMENT")
    if len(raw) < 4:
        raise OwnerTableError("E_TABLE_TRUNCATED")
    count = struct.unpack_from("<I", raw)[0]
    row_struct = ROW_STRUCTS[(protocol, family)]
    if count > MAX_ROWS:
        raise OwnerTableError("E_TABLE_COUNT")
    if 4 + count * row_struct.size > len(raw):
        raise OwnerTableError("E_TABLE_TRUNCATED")
    rows = []
    for index in range(count):
        fields = row_struct.unpack_from(raw, 4 + index * row_struct.size)
        row = {"protocol": protocol, "family": "IPv4" if family == AF_INET else "IPv6",
               "row_index": index}
        if protocol == "TCP" and family == AF_INET:
            state, local, local_port, remote, remote_port, pid = fields
            row.update(local_address=_ipv4(local), remote_address=_ipv4(remote),
                       local_port=decode_port(local_port), remote_port=decode_port(remote_port))
        elif protocol == "TCP":
            local, local_scope, local_port, remote, remote_scope, remote_port, state, pid = fields
            row.update(_scope_fields(local, local_scope, remote, remote_scope))
            row.update(local_port=decode_port(local_port), remote_port=decode_port(remote_port))
        elif family == AF_INET:
            local, local_port, pid = fields
            row.update(local_address=_ipv4(local), local_port=decode_port(local_port))
        else:
            local, local_scope, local_port, pid = fields
            row.update(_scope_fields(local, local_scope))
            row.update(local_port=decode_port(local_port))
        row["pid"] = pid
        if protocol == "TCP":
            row.update(state_code=state, state=TCP_STATES.get(state, "Unknown"),
                       remote_endpoint_meaningful=state != 2)
        else:
            # A bound UDP endpoint is not evidence that it is receiving traffic.
            row["remote_peer_available"] = False
        rows.append(row)
    return rows


def read_raw_table(function, family: int, table_class: int,
                   max_attempts: int = 5) -> bytes:
    """Retry a bounded number of size races; never silently truncate a table."""
    size = ctypes.c_uint32(0)
    code = int(function(None, ctypes.byref(size), False, family, table_class, 0))
    if code not in (0, ERROR_INSUFFICIENT_BUFFER):
        raise OwnerTableError("E_API_RETURN", code)
    for _ in range(max_attempts):
        requested = int(size.value)
        if not 4 <= requested <= MAX_TABLE_BYTES:
            raise OwnerTableError("E_API_SIZE", code)
        buffer = ctypes.create_string_buffer(requested)
        size = ctypes.c_uint32(requested)
        code = int(function(buffer, ctypes.byref(size), False, family, table_class, 0))
        if code == ERROR_INSUFFICIENT_BUFFER:
            continue
        if code != 0:
            raise OwnerTableError("E_API_RETURN", code)
        if not 4 <= size.value <= requested:
            raise OwnerTableError("E_API_SIZE", code)
        return bytes(buffer.raw[:size.value])
    raise OwnerTableError("E_API_CHURN", code)


class WindowsOwnerApi:
    def __init__(self):
        if os.name != "nt":
            raise OwnerTableError("E_PLATFORM")
        try:
            # LOAD_LIBRARY_SEARCH_SYSTEM32: never search the project/current folder.
            self.library = ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800)
            arguments = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32,
                         ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
            for name in ("GetExtendedTcpTable", "GetExtendedUdpTable"):
                function = getattr(self.library, name)
                function.argtypes = arguments
                function.restype = ctypes.c_uint32
        except Exception:
            raise OwnerTableError("E_API_LOAD") from None

    def read(self, protocol: str, family: int) -> bytes:
        if (protocol, family) not in ROW_STRUCTS:
            raise OwnerTableError("E_ARGUMENT")
        function = (self.library.GetExtendedTcpTable if protocol == "TCP"
                    else self.library.GetExtendedUdpTable)
        return read_raw_table(function, family,
                              TCP_TABLE_OWNER_PID_ALL if protocol == "TCP" else UDP_TABLE_OWNER_PID)


def _utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def collect_snapshot(include_udp: bool = False, api=None, clock=time.time) -> dict:
    """Explicit local API capture. Tables are separate observations, not atomic."""
    api = WindowsOwnerApi() if api is None else api
    began = clock()
    tables = {}
    for protocol in (("TCP", "UDP") if include_udp else ("TCP",)):
        for family in (AF_INET, AF_INET6):
            key = protocol + ("_IPv4" if family == AF_INET else "_IPv6")
            started = clock()
            table = {"protocol": protocol, "family": "IPv4" if family == AF_INET else "IPv6",
                     "api": "GetExtendedTcpTable" if protocol == "TCP" else "GetExtendedUdpTable",
                     "table_class": TCP_TABLE_OWNER_PID_ALL if protocol == "TCP" else UDP_TABLE_OWNER_PID,
                     "capture_started_utc": _utc(started), "rows": [], "ok": False}
            try:
                table["rows"] = parse_owner_table(api.read(protocol, family), protocol, family)
                table.update(ok=True, api_return_code=0)
            except OwnerTableError as error:
                table.update(error=error.code, api_return_code=error.api_return_code)
            except Exception:
                table.update(error="E_CAPTURE", api_return_code=None)
            table.update(row_count=len(table["rows"]), capture_finished_utc=_utc(clock()))
            tables[key] = table
    return {"schema_version": 1, "source": "Windows IP Helper owner PID tables",
            "capture_started_utc": _utc(began), "capture_finished_utc": _utc(clock()),
            "tables_observed_atomically": False, "contains_process_arguments": False,
            "contains_packet_payloads": False, "tables": tables,
            "ok": all(table["ok"] for table in tables.values())}


def safe_summary(snapshot: dict) -> dict:
    """Never send addresses, ports, PIDs, output paths or process details to stdout."""
    return {"ok": bool(snapshot["ok"]),
            "counts": {key: table["row_count"] for key, table in snapshot["tables"].items()},
            "errors": [{"table": key, "code": table["error"],
                        "api_return_code": table.get("api_return_code")}
                       for key, table in snapshot["tables"].items() if not table["ok"]]}


def _reparse(meta) -> bool:
    return stat.S_ISLNK(meta.st_mode) or bool(
        getattr(meta, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def validate_output_path(path: Path, access_root: Path | None = None) -> Path:
    """The caller creates and secures the existing parent directory's Windows ACL."""
    try:
        root = Path(os.path.abspath(ACCESS_ROOT if access_root is None else access_root))
        output = Path(os.path.abspath(path))
        relative = output.relative_to(root)
        if not relative.parts or output.suffix.lower() != ".json":
            raise OwnerTableError("E_OUTPUT_PATH")
        for directory in reversed(root.parents):
            meta = directory.lstat()
            if not stat.S_ISDIR(meta.st_mode) or _reparse(meta):
                raise OwnerTableError("E_OUTPUT_PATH")
        current = root
        for part in (None,) + relative.parts[:-1]:
            current = current if part is None else current / part
            meta = current.lstat()
            if not stat.S_ISDIR(meta.st_mode) or _reparse(meta):
                raise OwnerTableError("E_OUTPUT_PATH")
        if output.exists() or output.is_symlink():
            raise OwnerTableError("E_OUTPUT_EXISTS")
        if not output.parent.resolve().is_relative_to(root.resolve()):
            raise OwnerTableError("E_OUTPUT_PATH")
        return output
    except OwnerTableError:
        raise
    except Exception:
        raise OwnerTableError("E_OUTPUT_PATH") from None


def write_private_snapshot(path: Path, snapshot: dict) -> None:
    path = validate_output_path(path)
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write((json.dumps(snapshot, sort_keys=True) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise OwnerTableError("E_OUTPUT_EXISTS") from None
    except Exception:
        raise OwnerTableError("E_OUTPUT_WRITE") from None
    finally:
        if fd is not None:
            os.close(fd)


def main(argv=None) -> int:
    global ACCESS_ROOT
    parser = SafeArgumentParser(description="Save owner-PID tables privately; stdout is counts only.")
    parser.add_argument("--case-dir", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--include-udp", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.case_dir is not None:
            from .privacy import verify_case
            ACCESS_ROOT = verify_case(args.case_dir)
        # Validate before any DLL loading or endpoint capture.
        output = validate_output_path(args.output)
        snapshot = collect_snapshot(include_udp=args.include_udp)
        write_private_snapshot(output, snapshot)
        print(json.dumps(safe_summary(snapshot), sort_keys=True))
        return 0 if snapshot["ok"] else 1
    except OwnerTableError as error:
        print(json.dumps({"ok": False, "error": error.code, "api_return_code": error.api_return_code}))
        return 1
    except Exception:
        print(json.dumps({"ok": False, "error": "E_CAPTURE"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
