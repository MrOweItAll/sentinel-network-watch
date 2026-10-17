"""Bounded, read-only TCP observations of the collector's Linux network namespace.

This is a non-atomic snapshot, not a flow recorder or an initiator detector.
Only /proc TCP tables, PID stat/fd/exe, and boot_id metadata are read. Executable
bytes are hashed through /proc/PID/exe; command lines, environments and socket
payloads are never opened. An executable hash is not a verdict about safety.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

MAX_TABLE_BYTES = 4 * 1024 * 1024
MAX_ROWS = 8192
MAX_PIDS = 4096
MAX_FDS_PER_PID = 4096
MAX_FD_LINKS = 65536
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_HASH_BYTES = 512 * 1024 * 1024
JOB_SECONDS = 10
_INTERPRETER = re.compile(r"(?:python(?:\d+(?:\.\d+)*)?[a-z]*|pypy(?:\d+(?:\.\d+)*)?|node(?:js)?|deno|perl(?:\d+(?:\.\d+)*)?|ruby(?:\d+(?:\.\d+)*)?|php(?:\d+(?:\.\d+)*)?|java|dotnet|julia|lua(?:\d+(?:\.\d+)*)?|R|Rscript|sh|bash|dash|zsh|ksh|fish|ash|busybox)")


class ObservationError(ValueError):
    """A fixed, credential-free error code."""


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _safe_text(value, maximum=2048):
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and len(json.dumps(value, ensure_ascii=True)) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _read_text(path, maximum):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ObservationError("E_READ_LIMIT")
    return data.decode("ascii", errors="strict")


def _readlink(path):
    return os.readlink(path)


def _starttime(path, pid):
    text = _read_text(path / "stat", 8192)
    # comm may contain spaces and closing parentheses. Remaining fields begin
    # after its LAST closing parenthesis; starttime is field 22 (index 19 here).
    left, right = text.find("("), text.rfind(")")
    if left < 1 or right <= left or int(text[:left].strip()) != pid:
        raise ObservationError("E_PROCESS_STAT")
    fields = text[right + 1:].split()
    if len(fields) < 20 or not re.fullmatch(r"[0-9]{1,20}", fields[19]):
        raise ObservationError("E_PROCESS_STAT")
    return int(fields[19])


def _address(encoded, family):
    address, port = encoded.split(":")
    width = 8 if family == 4 else 32
    if not re.fullmatch(r"[0-9A-Fa-f]{" + str(width) + r"}", address) or not re.fullmatch(r"[0-9A-Fa-f]{4}", port):
        raise ObservationError("E_TCP_ROW")
    # The kernel prints native uint32 words, including each IPv6 word.
    raw = b"".join(int(address[i:i + 8], 16).to_bytes(4, sys.byteorder) for i in range(0, width, 8))
    return str(ipaddress.ip_address(raw)), int(port, 16)


def _read_table(path, family, coverage):
    rows = []
    try:
        text = _read_text(path, MAX_TABLE_BYTES)
    except ObservationError:
        coverage["limits_reached"] = True
        coverage[f"tcp{family}_read_ok"] = False
        return rows
    except (OSError, ValueError, UnicodeError):
        coverage[f"tcp{family}_read_ok"] = False
        return rows
    coverage[f"tcp{family}_read_ok"] = True
    lines = text.splitlines()
    if not lines or "local_address" not in lines[0]:
        coverage["parse_errors"] += 1
        return rows
    for number, line in enumerate(lines[1:]):
        if number >= MAX_ROWS:
            coverage["limits_reached"] = True
            break
        if not line.strip():
            continue
        try:
            if len(line) > 4096:
                raise ObservationError("E_TCP_ROW")
            fields = line.split()
            if len(fields) < 10 or not re.fullmatch(r"[0-9A-Fa-f]{2}", fields[3]):
                raise ObservationError("E_TCP_ROW")
            state = int(fields[3], 16)
            if state not in (1, 10):
                continue
            local, local_port = _address(fields[1], family)
            peer, peer_port = _address(fields[2], family)
            if not re.fullmatch(r"[0-9]{1,20}", fields[7]) or not re.fullmatch(r"[0-9]{1,20}", fields[9]):
                raise ObservationError("E_TCP_ROW")
            if local_port == 0 or (state == 1 and (peer_port == 0 or ipaddress.ip_address(peer).is_unspecified)):
                raise ObservationError("E_TCP_ROW")
            rows.append((family, state, local, local_port, peer, peer_port, int(fields[7]), int(fields[9])))
        except (ValueError, IndexError):
            coverage["parse_errors"] += 1
    return rows


def _expired(deadline, monotonic, coverage):
    if monotonic() >= deadline:
        coverage["budget_exhausted"] = True
        coverage["limits_reached"] = True
        return True
    return False


def _owners(root, wanted, deadline, monotonic, coverage):
    owners = {}
    if not wanted:
        coverage["process_scan_ok"] = True
        return owners
    pids = []
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if re.fullmatch(r"[0-9]{1,10}", entry.name) and entry.is_dir(follow_symlinks=False):
                    if len(pids) >= MAX_PIDS:
                        coverage["limits_reached"] = True
                        break
                    pids.append(int(entry.name))
    except OSError:
        coverage["process_scan_ok"] = False
        return owners
    coverage["process_scan_ok"] = True
    for pid in sorted(pids):
        if _expired(deadline, monotonic, coverage):
            break
        process = root / str(pid)
        try:
            start = _starttime(process, pid)
            seen = set()
            with os.scandir(process / "fd") as descriptors:
                for number, entry in enumerate(descriptors):
                    if number >= MAX_FDS_PER_PID or coverage["fd_links_read"] >= MAX_FD_LINKS:
                        coverage["limits_reached"] = True
                        break
                    if _expired(deadline, monotonic, coverage):
                        break
                    coverage["fd_links_read"] += 1
                    try:
                        target = _readlink(process / "fd" / entry.name)
                        match = re.fullmatch(r"socket:\[([0-9]{1,20})\]", target)
                        inode = int(match[1]) if match else None
                        if inode in wanted and inode not in seen:
                            owners.setdefault(inode, []).append((pid, entry.name, start))
                            seen.add(inode)
                    except OSError:
                        continue
        except (OSError, ValueError, UnicodeError):
            coverage["processes_unreadable"] += 1
        if coverage["fd_links_read"] >= MAX_FD_LINKS:
            break
    return owners


def _file_identity(meta):
    return meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns


def _binary(process, deadline, monotonic, coverage, cache):
    path = _readlink(process / "exe")
    if not _safe_text(path) or not path.startswith("/") or path.endswith(" (deleted)"):
        raise ObservationError("E_EXE_PATH")
    # Deliberately follow this kernel magic link to the running executable,
    # not its pathname (which may refer to a different mount/update).
    fd = os.open(process / "exe", os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BINARY_BYTES:
            raise ObservationError("E_BINARY_LIMIT")
        identity = _file_identity(before)
        if identity in cache:
            digest = cache[identity]
        else:
            digestor = hashlib.sha256()
            total = 0
            while True:
                if _expired(deadline, monotonic, coverage):
                    raise ObservationError("E_BUDGET")
                chunk = stream.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                coverage["executable_bytes_hashed"] += len(chunk)
                if total > MAX_BINARY_BYTES or coverage["executable_bytes_hashed"] > MAX_HASH_BYTES:
                    coverage["limits_reached"] = True
                    raise ObservationError("E_BINARY_LIMIT")
                digestor.update(chunk)
            if total != before.st_size:
                raise ObservationError("E_EXE_CHANGED")
            digest = digestor.hexdigest()
        if _file_identity(os.fstat(stream.fileno())) != identity:
            raise ObservationError("E_EXE_CHANGED")
        after = os.stat(process / "exe")
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or _readlink(process / "exe") != path:
            raise ObservationError("E_EXE_CHANGED")
        cache[identity] = digest
    return path, digest, (before.st_dev, before.st_ino)


def collect_linux_records(actor_key, observed_at=None, proc_root=Path("/proc"), *, monotonic=None):
    """Return review-ingest records plus explicit snapshot/attribution coverage.

    Unknown owners are capture-scoped. Interpreter contexts are process-lifetime
    scoped (boot/PID/starttime), with no claim about the script being executed.
    proc_root and monotonic permit offline fixtures; no host setting is changed.
    """
    if not _safe_text(actor_key, 512):
        raise ObservationError("E_ACTOR")
    observed_at = time.time() if observed_at is None else observed_at
    if isinstance(observed_at, bool) or not isinstance(observed_at, (int, float)) or not math.isfinite(observed_at) or observed_at < 0:
        raise ObservationError("E_OBSERVED_AT")
    root = Path(proc_root)
    monotonic = monotonic or time.monotonic
    deadline = monotonic() + JOB_SECONDS
    capture = uuid.uuid4().hex
    coverage = {"ok": False, "scope": "collector_current_network_namespace", "tcp_only": True,
                "udp_observed": False, "ipv6_supported": True, "complete_stream_visibility": False,
                "short_connections_may_be_missed": True, "snapshot_atomic": False,
                "initiator_inferred": False, "arguments_or_environment_read": False,
                "tcp4_read_ok": False, "tcp6_read_ok": False, "process_scan_ok": False,
                "parse_errors": 0, "limits_reached": False, "budget_exhausted": False,
                "processes_unreadable": 0, "fd_links_read": 0, "executable_bytes_hashed": 0}
    rows = _read_table(root / "net/tcp", 4, coverage) + _read_table(root / "net/tcp6", 6, coverage)
    # Bound both families together, with an explicit telemetry gap if truncated.
    if len(rows) > MAX_ROWS:
        rows = rows[:MAX_ROWS]
        coverage["limits_reached"] = True
    owners = _owners(root, {row[7] for row in rows if row[7]}, deadline, monotonic, coverage)
    owner_scan_complete = coverage["process_scan_ok"] and not coverage["limits_reached"]
    try:
        boot = _read_text(root / "sys/kernel/random/boot_id", 128).strip()
        boot = str(uuid.UUID(boot))
    except (OSError, ValueError, UnicodeError):
        boot = None
    after_coverage = {"parse_errors": 0, "limits_reached": False}
    after_rows = set(_read_table(root / "net/tcp", 4, after_coverage) + _read_table(root / "net/tcp6", 6, after_coverage))
    coverage["tables_revalidated"] = bool(after_coverage.get("tcp4_read_ok") and after_coverage.get("tcp6_read_ok"))
    coverage["parse_errors"] += after_coverage["parse_errors"]
    coverage["limits_reached"] |= after_coverage["limits_reached"]
    records, cache = [], {}
    for index, row in enumerate(rows):
        family, state, local, local_port, peer, peer_port, uid, inode = row
        destination = local if state == 10 else peer
        endpoint_complete = not (family == 6 and ipaddress.ip_address(destination).is_link_local)
        evidence = {"source": "linux_proc_tcp_snapshot", "address_family": family, "raw_state": state,
                    "local_address": local, "local_port": local_port, "socket_inode": inode,
                    "socket_uid": uid, "direction": "unknown", "identity_scope": "capture",
                    "endpoint_complete": endpoint_complete,
                    "ipv6_interface_scope_known": family != 6 or not ipaddress.ip_address(destination).is_link_local,
                    "app_identity_complete": False, "attribution_error": "E_OWNER_UNKNOWN"}
        context = "linux-unattributed-v1:" + _digest([capture, row])
        candidates = owners.get(inode, [])
        try:
            if row not in after_rows:
                raise ObservationError("E_SOCKET_CHANGED")
            if not owner_scan_complete:
                raise ObservationError("E_OWNER_SCAN_INCOMPLETE")
            if len(candidates) != 1:
                raise ObservationError("E_OWNER_AMBIGUOUS" if candidates else "E_OWNER_UNKNOWN")
            if _expired(deadline, monotonic, coverage):
                raise ObservationError("E_BUDGET")
            pid, descriptor, start = candidates[0]
            process = root / str(pid)
            if _starttime(process, pid) != start or _readlink(process / "fd" / descriptor) != f"socket:[{inode}]":
                raise ObservationError("E_PROCESS_CHANGED")
            path, binary_hash, binary_inode = _binary(process, deadline, monotonic, coverage, cache)
            if _starttime(process, pid) != start or _readlink(process / "fd" / descriptor) != f"socket:[{inode}]":
                raise ObservationError("E_PROCESS_CHANGED")
            final_exe = os.stat(process / "exe")
            if (final_exe.st_dev, final_exe.st_ino) != binary_inode or _readlink(process / "exe") != path:
                raise ObservationError("E_EXE_CHANGED")
            name = path.rsplit("/", 1)[-1]
            interpreted = bool(_INTERPRETER.fullmatch(name))
            if interpreted and boot is None:
                raise ObservationError("E_BOOT_ID_UNAVAILABLE")
            identity = {"path": path, "sha256": binary_hash, "socket_uid": uid}
            scope = "process_lifetime" if interpreted else "ordinary_binary"
            if interpreted:
                identity.update(pid=pid, process_start_ticks=start, boot=boot)
            context = "linux-" + scope + "-v1:" + _digest(identity)
            evidence.update(identity_scope=scope, app_identity_complete=True, attribution_error="",
                            executable_path=path, executable_name=name[:128], executable_sha256=binary_hash,
                            pid=pid, process_start_ticks=start, script_identity_known=False)
        except ObservationError as error:
            evidence["attribution_error"] = str(error)
        except (OSError, ValueError, UnicodeError):
            evidence["attribution_error"] = "E_PROCESS_UNAVAILABLE"
        record = {"actor_key": actor_key, "app_context_key": context,
                  "kind": "listener" if state == 10 else "native_tcp", "transport": "TCP",
                  "destination_address": destination,
                  "destination_port": local_port if state == 10 else peer_port,
                  "evidence": evidence, "observed_at": observed_at,
                  "observation_id": "linux:" + capture + ":" + str(index)}
        records.append(record)
    coverage.update(records=len(records), established=sum(row[1] == 1 for row in rows),
                    listeners=sum(row[1] == 10 for row in rows),
                    attributed=sum(record["evidence"]["app_identity_complete"] for record in records))
    coverage["unattributed"] = len(records) - coverage["attributed"]
    coverage["unscoped_ipv6_link_local"] = sum(not record["evidence"]["endpoint_complete"] for record in records)
    coverage["ok"] = bool(coverage["tcp4_read_ok"] and coverage["tcp6_read_ok"] and coverage["tables_revalidated"]
                          and coverage["process_scan_ok"] and not coverage["limits_reached"] and not coverage["parse_errors"])
    return {"records": records, "coverage": coverage}
