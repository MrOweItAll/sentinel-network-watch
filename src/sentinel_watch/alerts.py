#!/usr/bin/env python3
"""Small, persistent Sentinel service-alert publisher; Python standard library only.

Endpoint credentials belong only in the private configuration, never in arguments or
reports. Delivery is at least once: an ambiguous POST is searched for before another
POST, but a server cache cannot prove that an absent message was never delivered.
"""

from __future__ import annotations

import argparse
from .arguments import SafeArgumentParser
import contextlib
import email.utils
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import random
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable, Mapping

try:
    import fcntl
except ImportError:  # Enables nonsecret fixture tests on Windows.
    fcntl = None


DEFAULT_CONFIG = Path("/etc/sentinel-alerts/config.json")
DEFAULT_STATE = Path("/var/lib/sentinel-alerts")
ROUTER_COLLECTOR_TIMER = Path("/etc/systemd/system/sentinel-router.timer")
ROUTER_COLLECTOR_STATUS = Path("/var/lib/sentinel-router/status.json")
MAX_RESPONSE_BYTES = 128 * 1024
MAX_EVENTS = 4096
MAX_VERIFIED = 2000
VERIFIED_RETENTION = 30 * 86400
HTTP_TIMEOUT = 12
SERVER_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
ROUTER_NOTICE_CATEGORIES = frozenset({
    "inventory_change", "router_collection_degraded", "router_collection_recovered",
})
SAFE_CODES = frozenset({
    "E_ARGUMENT", "E_AUTH", "E_BUSY", "E_CONFIG", "E_HTTP_CLIENT",
    "E_HTTP_SERVER", "E_INTERNAL", "E_NETWORK", "E_PRIVILEGE",
    "E_PUBLISH_RESPONSE", "E_QUEUE_FULL", "E_RATE_LIMIT", "E_READBACK_PENDING",
    "E_READBACK_RESPONSE", "E_REDIRECT", "E_RESPONSE_TOO_LARGE", "E_STATE",
    "E_TLS",
})


class SafeError(Exception):
    """Only fixed, public error codes may leave the implementation."""

    def __init__(self, code: str):
        self.code = code if code in SAFE_CODES else "E_INTERNAL"
        super().__init__(self.code)


class TransportError(SafeError):
    pass


@dataclass(frozen=True)
class Config:
    base_url: str
    topic: str
    token: str | None = None
    health_profile: str = "outbox"
    dns_port: int = 1053
    web_port: int = 3000
    container_name: str = "sentinel-adguard"

    def validate(self) -> "Config":
        try:
            if (self.health_profile not in ("outbox", "adguard")
                    or type(self.dns_port) is not int or not 1 <= self.dns_port <= 65535
                    or type(self.web_port) is not int or not 1 <= self.web_port <= 65535
                    or not isinstance(self.container_name, str)
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.container_name) is None):
                raise SafeError("E_CONFIG")
            parsed = urllib.parse.urlsplit(self.base_url)
            port = parsed.port
            if (parsed.scheme != "https" or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.query or parsed.fragment or parsed.path not in ("", "/")
                    or (port is not None and not 1 <= port <= 65535)
                    or any(ord(c) < 33 for c in self.base_url)
                    or re.fullmatch(r"[-_A-Za-z0-9]{1,64}", self.topic) is None
                    or (self.token is not None and
                        (not isinstance(self.token, str) or not self.token
                         or len(self.token) > 4096
                         or any(ord(c) < 33 or ord(c) > 126 for c in self.token)))):
                raise SafeError("E_CONFIG")
        except (TypeError, ValueError, AttributeError):
            raise SafeError("E_CONFIG") from None
        return self

    @property
    def topic_url(self) -> str:
        return self.base_url.rstrip("/") + "/" + self.topic


def load_config(path: Path) -> Config:
    """Read a single owned, private regular file, without following its last link."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                or meta.st_size > 16384):
            raise SafeError("E_CONFIG")
        if os.name == "posix" and (meta.st_uid != os.geteuid() or meta.st_mode & 0o077):
            raise SafeError("E_CONFIG")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise SafeError("E_CONFIG")
        obj = json.loads(raw)
        if not isinstance(obj, dict) or set(obj) - {"base_url", "topic", "token", "health_profile", "dns_port", "web_port", "container_name"}:
            raise SafeError("E_CONFIG")
        return Config(obj["base_url"], obj["topic"], obj.get("token"),
                      obj.get("health_profile", "outbox"), obj.get("dns_port", 1053),
                      obj.get("web_port", 3000), obj.get("container_name", "sentinel-adguard")).validate()
    except SafeError:
        raise
    except Exception:
        raise SafeError("E_CONFIG") from None
    finally:
        if fd is not None:
            os.close(fd)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """Verified HTTPS, no ambient proxy configuration and no redirect forwarding."""

    def __init__(self):
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def request(self, method: str, url: str, headers: Mapping[str, str],
                body: bytes | None) -> HttpResponse:
        response = None
        try:
            request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
            try:
                response = self._opener.open(request, timeout=HTTP_TIMEOUT)
            except urllib.error.HTTPError as error:
                response = error  # The response body and exception text are never logged.
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise TransportError("E_RESPONSE_TOO_LARGE")
            return HttpResponse(int(response.code), data,
                                {str(k).lower(): str(v) for k, v in response.headers.items()})
        except TransportError:
            raise
        except ssl.SSLError:
            raise TransportError("E_TLS") from None
        except urllib.error.URLError as error:
            raise TransportError("E_TLS" if isinstance(error.reason, ssl.SSLError)
                                 else "E_NETWORK") from None
        except Exception:
            raise TransportError("E_NETWORK") from None
        finally:
            if response is not None:
                response.close()


def retry_after_seconds(value: str | None, now: float) -> int | None:
    """Accept Retry-After seconds or an HTTP date; never wait more than one day."""
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        value = value.strip()
        if value.isascii() and value.isdecimal():
            delay = int(value)
        else:
            date = email.utils.parsedate_to_datetime(value)
            if date.tzinfo is None:
                return None
            delay = math.ceil(date.timestamp() - now)
        return min(86400, max(0, delay))
    except (ValueError, TypeError, OverflowError):
        return None


def _subprocess_ok(command: list[str]) -> bool:
    try:
        return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=5, check=False).returncode == 0
    except Exception:
        return False


def _container_running(container_name: str = "sentinel-adguard") -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/docker", "inspect", "--type", "container", "--format",
             "{{json .State}}", container_name],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
        if result.returncode or len(result.stdout) > MAX_RESPONSE_BYTES:
            return False
        state = json.loads(result.stdout)
        return (state.get("Running") is True and state.get("Restarting") is False
                and state.get("Dead") is False and state.get("Status") == "running")
    except Exception:
        return False


def _dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a bounded DNS name, including compression pointers."""
    labels: list[str] = []
    end = None
    visited: set[int] = set()
    for _ in range(128):
        if offset >= len(packet) or offset in visited:
            raise ValueError("dns")
        visited.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("dns")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
        elif length == 0:
            return ".".join(labels).lower(), end if end is not None else offset + 1
        elif length & 0xC0 or length > 63 or offset + length + 1 > len(packet):
            raise ValueError("dns")
        else:
            labels.append(packet[offset + 1:offset + length + 1].decode("ascii"))
            offset += length + 1
    raise ValueError("dns")


def _dns_valid(packet: bytes, query_id: int) -> bool:
    try:
        if len(packet) < 12:
            return False
        ident, flags, qd, an, _, _ = struct.unpack("!6H", packet[:12])
        if (ident != query_id or flags & 0x8000 == 0 or flags & 0x7800
                or flags & 0x0200 or flags & 0x000F or qd != 1 or an < 1 or an > 128):
            return False
        name, offset = _dns_name(packet, 12)
        if name != "example.org" or packet[offset:offset + 4] != b"\x00\x01\x00\x01":
            return False
        offset += 4
        for _ in range(an):
            _, offset = _dns_name(packet, offset)
            if offset + 10 > len(packet):
                return False
            rtype, rclass, _, length = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            if offset + length > len(packet):
                return False
            if rtype == 1 and rclass == 1 and length == 4:
                if ipaddress.IPv4Address(packet[offset:offset + length]).is_global:
                    return True
            offset += length
        return False
    except Exception:
        return False


def _recv_exact(stream: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise OSError("dns")
        result.extend(part)
    return bytes(result)


def _dns_check(tcp: bool, port: int = 1053) -> bool:
    try:
        ident = secrets.randbelow(65536)
        packet = (struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0)
                  + b"\x07example\x03org\x00\x00\x01\x00\x01")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            stream.connect(("127.0.0.1", port))
            if tcp:
                stream.sendall(struct.pack("!H", len(packet)) + packet)
                length = struct.unpack("!H", _recv_exact(stream, 2))[0]
                if not 12 <= length <= 8192:
                    return False
                response = _recv_exact(stream, length)
            else:
                stream.send(packet)
                response = stream.recv(8192)
        return _dns_valid(response, ident)
    except Exception:
        return False


def _web_check(port: int = 3000) -> bool:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", "/", headers={"Connection": "close"})
        response = connection.getresponse()
        return response.status in (200, 302)
    except Exception:
        return False
    finally:
        connection.close()


def _outbox_filesystem_ok(state_dir: Path = DEFAULT_STATE) -> bool:
    try:
        # ProtectSystem=strict deliberately presents / as read-only. Probe the
        # service's writable state bind mount, which actually stores the outbox.
        usage = os.statvfs(state_dir)
        minimum = max(1024 ** 3, int(usage.f_blocks * usage.f_frsize * 0.05))
        return (not usage.f_flag & getattr(os, "ST_RDONLY", 1)
                and usage.f_bavail * usage.f_frsize >= minimum and usage.f_favail >= 1024)
    except Exception:
        return False


def _router_collector_fresh(now: float | None = None) -> bool:
    """Check only collector liveness, independently of its capability/health notices."""
    fd = None
    try:
        fd = os.open(ROUTER_COLLECTOR_STATUS, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_uid != 0
                or meta.st_size > 65536):
            return False
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(65537)
        if len(raw) > 65536:
            return False
        value = json.loads(raw)
        checked = value.get("checked_at") if isinstance(value, dict) else None
        if isinstance(checked, bool) or not isinstance(checked, (int, float)) or not math.isfinite(checked):
            return False
        age = (time.time() if now is None else now) - checked
        return math.isfinite(age) and -30 <= age <= 180
    except Exception:
        return False
    finally:
        if fd is not None:
            os.close(fd)


def service_checks(config: Config | None = None, state_dir: Path = DEFAULT_STATE) -> dict[str, bool]:
    """Outbox-only by default; optional explicit Linux AdGuard health profile."""
    checks = {"outbox_filesystem": _outbox_filesystem_ok(state_dir)}
    if config is not None and config.health_profile == "adguard":
        checks.update({
            "docker_service": _subprocess_ok(["/usr/bin/systemctl", "is-active", "--quiet", "docker.service"]),
            "adguard_container": _container_running(config.container_name),
            "dns_udp": _dns_check(False, config.dns_port),
            "dns_tcp": _dns_check(True, config.dns_port),
            "adguard_web": _web_check(config.web_port),
        })
        if ROUTER_COLLECTOR_TIMER.exists():
            checks["router_collector_fresh"] = _router_collector_fresh()
    return checks


def boot_id() -> str:
    try:
        return str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
    except Exception:
        return "unknown"


def _atomic_status(state_dir: Path, status_value: dict):
    temporary = state_dir / ("status-" + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(status_value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, state_dir / "status.json")
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _failure_status(state_dir: Path | None, code: str):
    # Best effort only: a full/read-only filesystem may prevent even this record.
    if state_dir is None:
        return
    try:
        meta = state_dir.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or
                (os.name == "posix" and (meta.st_uid != os.geteuid() or meta.st_mode & 0o077))):
            return
        _atomic_status(state_dir, {"ok": False, "error": code, "last_error": code,
                                  "checked_at": time.time(), "delivery_state": "degraded"})
    except Exception:
        pass


class _FileLock:
    def __init__(self, path: Path):
        self.path, self.fd = path, None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        meta = os.fstat(self.fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
            os.close(self.fd)
            self.fd = None
            raise SafeError("E_STATE")
        try:
            if fcntl is not None:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                if meta.st_size == 0:
                    os.write(self.fd, b"0")
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(self.fd)
            self.fd = None
            raise SafeError("E_BUSY") from None
        return self

    def __exit__(self, *args):
        if self.fd is not None:
            os.close(self.fd)


@contextlib.contextmanager
def _transaction(connection: sqlite3.Connection):
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


class AlertEngine:
    def __init__(self, state_dir: Path, config: Config, transport=None,
                 clock: Callable[[], float] = time.time,
                 check_provider: Callable[[], Mapping[str, bool]] | None = None,
                 boot_id_provider: Callable[[], str] | None = None,
                 rng=None, max_events: int = MAX_EVENTS):
        self.config = config.validate()
        self.state_dir = Path(state_dir)
        self.transport = transport if transport is not None else UrllibTransport()
        self.clock = clock
        self.check_provider = check_provider if check_provider is not None else lambda: service_checks(self.config, self.state_dir)
        self.boot_id_provider = boot_id_provider if boot_id_provider is not None else boot_id
        self.rng = rng if rng is not None else random.SystemRandom()
        self.max_events = max_events
        os.umask(0o077)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or (os.name == "posix" and info.st_uid != os.geteuid()):
            raise SafeError("E_STATE")
        self.state_dir.chmod(0o700)
        self.db_path = self.state_dir / "outbox.sqlite3"
        if self.db_path.exists() or self.db_path.is_symlink():
            info = self.db_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (os.name == "posix" and info.st_uid != os.geteuid())):
                raise SafeError("E_STATE")
            self.db_path.chmod(0o600)
        else:
            fd = os.open(self.db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
        with self._locked_connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS health(
                    id INTEGER PRIMARY KEY CHECK(id=1), stable TEXT NOT NULL,
                    failures INTEGER NOT NULL, successes INTEGER NOT NULL,
                    checked REAL, observed INTEGER, checks TEXT NOT NULL);
                INSERT OR IGNORE INTO health VALUES(1,'unknown',0,0,NULL,NULL,'{}');
                CREATE TABLE IF NOT EXISTS events(
                    event_id TEXT PRIMARY KEY, kind TEXT NOT NULL, body TEXT NOT NULL,
                    priority INTEGER NOT NULL, created REAL NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','posting','accepted','verified')),
                    attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL,
                    server_id TEXT, accepted_at REAL, verified_at REAL, last_error TEXT);
                CREATE INDEX IF NOT EXISTS events_due ON events(state,next_attempt,created);
            """)

    @contextlib.contextmanager
    def _locked_connection(self):
        with _FileLock(self.state_dir / "run.lock"):
            connection = sqlite3.connect(self.db_path, timeout=3, isolation_level=None)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA busy_timeout=3000")
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                yield connection
            finally:
                connection.close()

    def _enqueue(self, connection, kind: str, now: float, event_id: str | None = None) -> str:
        count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count >= self.max_events:
            # History may yield space under pressure; an unverified intent may not.
            connection.execute(
                "DELETE FROM events WHERE event_id IN (SELECT event_id FROM events "
                "WHERE state='verified' ORDER BY verified_at,event_id LIMIT ?)",
                (count - self.max_events + 1,),
            )
            if connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= self.max_events:
                raise SafeError("E_QUEUE_FULL")
        event_id = str(uuid.uuid4()) if event_id is None else event_id
        templates = {
            "boot": "Sentinel monitoring started.",
            "down": "Sentinel service checks need attention.",
            "recovery": "Sentinel service checks recovered.",
            "test": "Sentinel alert delivery test.",
            "inventory_change": "Sentinel observed a network inventory change. Review the local report.",
            "router_collection_degraded": "Sentinel router monitoring needs attention. Review the local report.",
            "router_collection_recovered": "Sentinel router monitoring recovered.",
        }
        body = templates[kind] + " Event " + event_id
        connection.execute(
            "INSERT INTO events(event_id,kind,body,priority,created,state,next_attempt) "
            "VALUES(?,?,?,?,?,'pending',?)",
            (event_id, kind, body, 4 if kind in ("down", "router_collection_degraded") else 3, now, now),
        )
        return event_id

    def enqueue_test(self) -> str:
        """Explicitly requested delivery test; UUID is for private fixture/DB use."""
        with self._locked_connection() as connection, _transaction(connection):
            return self._enqueue(connection, "test", self.clock())

    def enqueue_router_notice(self, notice_id: str, category: str) -> str:
        """Commit an opaque collector notice before its source is acknowledged.

        The collector persists uuid4().hex until acknowledgement and supplies only
        a fixed category. Replays return the same retained event without publishing.
        Verified history follows normal retention/capacity limits; unverified
        intents are never evicted. Source acknowledgements must also persist.
        """
        if (not isinstance(notice_id, str) or re.fullmatch(r"[0-9a-f]{32}", notice_id) is None
                or not isinstance(category, str) or category not in ROUTER_NOTICE_CATEGORIES):
            raise SafeError("E_ARGUMENT")
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "sentinel-router-notice/v1/" + notice_id))
        with self._locked_connection() as connection, _transaction(connection):
            existing = connection.execute("SELECT kind FROM events WHERE event_id=?", (event_id,)).fetchone()
            if existing is not None:
                if existing["kind"] != category:
                    raise SafeError("E_ARGUMENT")
                return event_id
            now = self.clock()
            self._prune(connection, now)
            return self._enqueue(connection, category, now, event_id)

    def _prune(self, connection, now: float):
        connection.execute("DELETE FROM events WHERE state='verified' AND verified_at<?",
                           (now - VERIFIED_RETENTION,))
        connection.execute(
            "DELETE FROM events WHERE event_id IN (SELECT event_id FROM events "
            "WHERE state='verified' ORDER BY verified_at DESC,event_id DESC LIMIT -1 OFFSET ?)",
            (MAX_VERIFIED,),
        )

    def _observe(self, connection, checks: Mapping[str, bool], current_boot: str, now: float):
        # The observation and all resulting intents either commit together or roll back.
        with _transaction(connection):
            self._prune(connection, now)
            previous_boot = connection.execute("SELECT value FROM metadata WHERE key='boot_id'").fetchone()
            if current_boot != "unknown" and (previous_boot is None or previous_boot[0] != current_boot):
                self._enqueue(connection, "boot", now)
                connection.execute("INSERT OR REPLACE INTO metadata VALUES('boot_id',?)", (current_boot,))
            old = connection.execute("SELECT * FROM health WHERE id=1").fetchone()
            healthy = all(checks.values())
            failures = 0 if healthy else min(old["failures"] + 1, 1000000)
            successes = min(old["successes"] + 1, 1000000) if healthy else 0
            stable = old["stable"]
            if not healthy and failures >= 2 and stable != "down":
                self._enqueue(connection, "down", now)
                stable = "down"
            elif healthy and stable == "down" and successes >= 2:
                self._enqueue(connection, "recovery", now)
                stable = "healthy"
            elif healthy and stable == "unknown":
                stable = "healthy"
            connection.execute(
                "UPDATE health SET stable=?,failures=?,successes=?,checked=?,observed=?,checks=? WHERE id=1",
                (stable, failures, successes, now, int(healthy), json.dumps(dict(checks), sort_keys=True)),
            )

    def _backoff(self, attempts: int) -> float:
        base = min(3600, 30 * 2 ** min(max(attempts - 1, 0), 7))
        return min(3600, base + self.rng.uniform(0, base * 0.2))

    def _schedule(self, connection, event, state: str, error: str, now: float,
                  delay: float | None = None):
        if error not in SAFE_CODES:
            error = "E_INTERNAL"
        if delay is None:
            delay = self._backoff(event["attempts"])
        connection.execute("UPDATE events SET state=?,next_attempt=?,last_error=? WHERE event_id=?",
                           (state, now + min(86400, max(0, delay)), error, event["event_id"]))

    def _headers(self, event=None) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "sentinel-alerts/1"}
        if self.config.token:
            headers["Authorization"] = "Bearer " + self.config.token
        if event is not None:
            headers.update({"Content-Type": "text/plain; charset=utf-8", "Title": "Sentinel",
                            "Priority": str(event["priority"]), "Cache": "yes"})
        return headers

    def _request(self, method: str, url: str, headers, body=None) -> HttpResponse:
        try:
            response = self.transport.request(method, url, headers, body)
            if (not isinstance(response, HttpResponse) or not isinstance(response.status, int)
                    or not isinstance(response.body, bytes)):
                raise TransportError("E_NETWORK")
            if len(response.body) > MAX_RESPONSE_BYTES:
                raise TransportError("E_RESPONSE_TOO_LARGE")
            return response
        except TransportError:
            raise
        except Exception:
            raise TransportError("E_NETWORK") from None

    def _http_failure(self, connection, event, state: str, response: HttpResponse, now: float) -> bool:
        status = response.status
        if 200 <= status < 300:
            return False
        headers = {str(k).lower(): v for k, v in response.headers.items()}
        if status in (401, 403):
            error, delay = "E_AUTH", 3600
        elif status == 429:
            error = "E_RATE_LIMIT"
            delay = max(self._backoff(event["attempts"]),
                        retry_after_seconds(headers.get("retry-after"), now) or 0)
        elif 300 <= status < 400:
            error, delay = "E_REDIRECT", 3600
        elif 400 <= status < 500:
            error, delay = "E_HTTP_CLIENT", 3600
        else:
            error, delay = "E_HTTP_SERVER", self._backoff(event["attempts"])
        self._schedule(connection, event, state, error, now, delay)
        return True

    def _message_matches(self, obj, event, server_id: str | None = None) -> bool:
        return (isinstance(obj, dict) and obj.get("event") == "message"
                and isinstance(obj.get("id"), str) and SERVER_ID_RE.fullmatch(obj["id"]) is not None
                and (server_id is None or obj["id"] == server_id)
                and obj.get("topic") == self.config.topic and obj.get("message") == event["body"])

    def _read_messages(self, body: bytes) -> list[dict]:
        try:
            result = []
            for line in body.splitlines():
                if line.strip():
                    obj = json.loads(line)
                    if not isinstance(obj, dict):
                        raise ValueError("shape")
                    result.append(obj)
            return result
        except Exception:
            raise SafeError("E_READBACK_RESPONSE") from None

    def _mark_verified(self, connection, event, server_id: str, now: float):
        connection.execute(
            "UPDATE events SET state='verified',server_id=?,accepted_at=COALESCE(accepted_at,?),"
            "verified_at=?,next_attempt=?,last_error=NULL WHERE event_id=?",
            (server_id, now, now, now, event["event_id"]),
        )

    def _readback(self, connection, event, now: float, ambiguous: bool):
        query = {"poll": "1"}
        if ambiguous:
            query["message"] = event["body"]
        else:
            query["id"] = event["server_id"]
        url = self.config.topic_url + "/json?" + urllib.parse.urlencode(query)
        try:
            response = self._request("GET", url, self._headers())
            if self._http_failure(connection, event, event["state"], response, now):
                return
            messages = self._read_messages(response.body)
            for obj in messages:
                if self._message_matches(obj, event, None if ambiguous else event["server_id"]):
                    self._mark_verified(connection, event, obj["id"], now)
                    return
            # Absence from cache is not proof of non-delivery. Retry POST only on a
            # later tick, with the same application marker, after this recovery GET.
            self._schedule(connection, event, "pending" if ambiguous else "accepted",
                           "E_READBACK_PENDING", now)
        except SafeError as error:
            self._schedule(connection, event, event["state"], error.code, now)

    def _attempt_one(self, connection, now: float):
        event = connection.execute(
            "SELECT * FROM events WHERE state!='verified' AND next_attempt<=? "
            "ORDER BY created,event_id LIMIT 1", (now,),
        ).fetchone()
        if event is None:
            return
        connection.execute("UPDATE events SET attempts=attempts+1 WHERE event_id=?", (event["event_id"],))
        event = dict(connection.execute("SELECT * FROM events WHERE event_id=?", (event["event_id"],)).fetchone())
        if event["state"] in ("accepted", "posting"):
            self._readback(connection, event, now, event["state"] == "posting")
            return
        # Persist posting before any network call. A process crash leaves an
        # ambiguous intent that must pass through recovery GET before re-POST.
        connection.execute("UPDATE events SET state='posting',last_error=NULL WHERE event_id=?",
                           (event["event_id"],))
        event["state"] = "posting"
        try:
            response = self._request("POST", self.config.topic_url,
                                     self._headers(event), event["body"].encode("utf-8"))
            if not 200 <= response.status < 300:
                # Explicit client refusals did not accept the event; server-side
                # failures/timeouts remain ambiguous and are searched before retry.
                state = "pending" if 300 <= response.status < 500 and response.status != 408 else "posting"
                self._http_failure(connection, event, state, response, now)
                return
            try:
                obj = json.loads(response.body)
            except Exception:
                raise SafeError("E_PUBLISH_RESPONSE") from None
            if not self._message_matches(obj, event):
                raise SafeError("E_PUBLISH_RESPONSE")
            connection.execute(
                "UPDATE events SET state='accepted',server_id=?,accepted_at=?,next_attempt=?,last_error=NULL "
                "WHERE event_id=?", (obj["id"], now, now, event["event_id"]),
            )
            event.update(state="accepted", server_id=obj["id"], accepted_at=now)
            self._readback(connection, event, now, False)
        except SafeError as error:
            self._schedule(connection, event, "posting", error.code, now)

    def _status(self, connection, now: float) -> dict:
        health = connection.execute("SELECT * FROM health WHERE id=1").fetchone()
        counts = {name: 0 for name in ("pending", "posting", "accepted", "verified")}
        for row in connection.execute("SELECT state,COUNT(*) AS total FROM events GROUP BY state"):
            counts[row["state"]] = row["total"]
        latest_error = connection.execute(
            "SELECT last_error FROM events WHERE state!='verified' AND last_error IS NOT NULL "
            "ORDER BY next_attempt DESC LIMIT 1").fetchone()
        blocked = connection.execute(
            "SELECT COUNT(*) FROM events WHERE state!='verified' AND last_error IN "
            "('E_AUTH','E_HTTP_CLIENT','E_REDIRECT')").fetchone()[0]
        oldest = connection.execute("SELECT MIN(created) FROM events WHERE state!='verified'").fetchone()[0]
        last_verified = connection.execute("SELECT MAX(verified_at) FROM events").fetchone()[0]
        code = latest_error[0] if latest_error and latest_error[0] in SAFE_CODES else None
        return {
            "ok": True, "health_state": health["stable"],
            "observed_healthy": None if health["observed"] is None else bool(health["observed"]),
            "consecutive_failures": health["failures"], "consecutive_successes": health["successes"],
            "checks": json.loads(health["checks"]), "checked_at": health["checked"],
            "outbox": counts, "blocked_events": blocked,
            "oldest_pending_age_seconds": None if oldest is None else max(0, int(now - oldest)),
            "last_verified_at": last_verified, "last_error": code,
            "delivery_state": "blocked" if blocked else "pending" if any(counts[s] for s in
                              ("pending", "posting", "accepted")) else "verified" if last_verified is not None else "not_yet_tested",
            "same_host_outage_detection": False,
        }

    def _write_status(self, status_value: dict):
        # This file is credential-free, but stays inside the private state directory.
        _atomic_status(self.state_dir, status_value)

    def tick(self) -> dict:
        with self._locked_connection() as connection:
            now = self.clock()
            try:
                raw_checks = self.check_provider()
                checks = {str(k): bool(v) for k, v in raw_checks.items()}
                if any(re.fullmatch(r"[a-z][a-z0-9_]{0,39}", key) is None for key in checks):
                    raise SafeError("E_STATE")
                current_boot = self.boot_id_provider()
                if not isinstance(current_boot, str) or len(current_boot) > 128:
                    raise SafeError("E_STATE")
                observation_error = None
                try:
                    self._observe(connection, checks, current_boot, now)
                except SafeError as error:
                    if error.code != "E_QUEUE_FULL":
                        raise
                    observation_error = error.code
                # A full queue must still drain. The rolled-back observation is
                # retried on a later tick instead of being silently lost.
                self._attempt_one(connection, now)
                result = self._status(connection, now)
                if observation_error is not None:
                    result.update(ok=False, last_error=observation_error)
            except SafeError as error:
                result = self._status(connection, now)
                result.update(ok=False, last_error=error.code)
            self._write_status(result)
            return result

    def status(self) -> dict:
        with self._locked_connection() as connection:
            return self._status(connection, self.clock())


def main(argv=None) -> int:
    parser = SafeArgumentParser(description="Sentinel service-alert outbox; no credentials in arguments.")
    parser.add_argument("command", choices=("tick", "status", "enqueue-test"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--test-paths", action="store_true",
                        help="Allow both path overrides for isolated, nonsecret local fixtures only.")
    args = parser.parse_args(argv)
    state_path = None
    try:
        if args.test_paths and (args.config is None or args.state_dir is None):
            raise SafeError("E_ARGUMENT")
        if not args.test_paths and (os.name != "posix" or os.geteuid() != 0):
            raise SafeError("E_PRIVILEGE")
        config_path = args.config if args.config is not None else DEFAULT_CONFIG
        state_path = args.state_dir if args.state_dir is not None else DEFAULT_STATE
        engine = AlertEngine(state_path, load_config(config_path))
        if args.command == "enqueue-test":
            engine.enqueue_test()
            result = engine.status()
            result["test_enqueued"] = True
        elif args.command == "tick":
            result = engine.tick()
        else:
            result = engine.status()
        print(json.dumps(result, sort_keys=True))
        return 0 if result["ok"] else 1
    except SafeError as error:
        _failure_status(state_path, error.code)
        print(json.dumps({"ok": False, "error": error.code}))
        return 1
    except Exception:
        _failure_status(state_path, "E_STATE")
        print(json.dumps({"ok": False, "error": "E_STATE"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
