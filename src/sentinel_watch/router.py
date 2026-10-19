#!/usr/bin/env python3
"""Read-only, unauthenticated router-log observations; no setter or credential API.

Raw responses and the searchable database are private. Counts represent router
records/observations, never byte totals, complete flows, authorization or trust.
Unverified pagination is explicitly incomplete until the actual schema is checked.
"""
from __future__ import annotations
import argparse
from .arguments import SafeArgumentParser
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import sys
import time
import uuid
try:
    import fcntl
except ImportError:
    fcntl = None

DEFAULT_STATE = Path('/var/lib/sentinel-router')
DEFAULT_CONFIG = Path('/etc/sentinel-router/config.json')
SUPPORTED_PROFILE = 'linksys-ea7300-v2-2.0.4.216940'
MAX_RESPONSE = 1024 * 1024
DISK_CAP = 200 * 1024 * 1024
RETENTION = 7 * 86400
SOCKET_TIMEOUT = 4
JOB_BUDGET = 75
PAGE_SIZE = 255
MAX_PAGES = 1
FIRST_INDEX = 1
LOG_SCHEMA_VERIFIED = True  # Actual outgoing response + vendor troubleshooting UI checked.
MAX_OBSERVATIONS = 50000
MAX_DEVICES = 4096
MAX_ADDRESSES = 32768
MAX_NOTICES = 4096
INVENTORY_NOTICE_COOLDOWN = 3600
NOTICE_CATEGORIES = {'inventory_change', 'router_collection_degraded', 'router_collection_recovered'}
LOGS = ('incoming', 'outgoing', 'security')
ACTIONS = {'identity': 'core/GetDeviceInfo', 'settings': 'routerlog/GetLogSettings', 'devices': 'devicelist/GetDevices',
           **{k: 'routerlog/Get' + k.title() + 'LogEntries' for k in LOGS}}
KNOWN_RESULTS = {'OK', 'ErrorInvalidFirstEntryIndex', 'ErrorInvalidInput',
                 '_ErrorUnauthorized', 'ErrorUnauthorized', '_ErrorUnknownAction',
                 'ErrorUnknownAction', 'ErrorInvalidAction'}


class SafeError(Exception):
    pass


def need(condition, code):
    if not condition:
        raise SafeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def private_dir(path):
    if not path.exists():
        path.mkdir(mode=0o700)
        sync_directory(path.parent)
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and path.resolve() == path, 'E_DIRECTORY')
    if os.name == 'posix':
        need(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, 'E_DIRECTORY')


def sync_directory(path):
    if os.name == 'posix':
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    sync_directory(path.parent)


def public_schema(value):
    # No field names or string/numeric values from router data are public.
    if isinstance(value, dict):
        return {'type': 'object', 'field_count': len(value),
                'field_types': sorted(type(v).__name__ for v in value.values())}
    if isinstance(value, list):
        return {'type': 'array', 'count': len(value)}
    return {'type': type(value).__name__}


class RouterClient:
    def __init__(self, deadline, *, gateway, profile=SUPPORTED_PROFILE):
        need(isinstance(gateway, str) and 0 < len(gateway) <= 128 and
             not any(ord(c) < 33 or ord(c) > 126 for c in gateway), 'E_ROUTER_CONFIG')
        try:
            self.gateway = str(ipaddress.ip_address(gateway))
        except (ValueError, TypeError):
            raise SafeError('E_ROUTER_CONFIG') from None
        need(profile == SUPPORTED_PROFILE, 'E_ROUTER_PROFILE')
        self.profile = profile
        self.deadline = deadline

    def request(self, key, index=FIRST_INDEX):
        need(key in ACTIONS, 'E_ACTION')
        need(type(index) is int and 1 <= index < 2**31, 'E_PAGINATION')
        remaining = self.deadline - time.monotonic()
        need(remaining >= 1, 'E_JOB_BUDGET')
        body = {'firstEntryIndex': index, 'entryCount': PAGE_SIZE} if key in LOGS else {}
        raw = canonical(body).encode()
        timeout = min(SOCKET_TIMEOUT, remaining)
        per_request_deadline = time.monotonic() + timeout
        conn = http.client.HTTPConnection(self.gateway, 80, timeout=timeout)
        data, http_status = bytearray(), 0
        try:
            conn.request('POST', '/JNAP/', raw, {
                'X-JNAP-Action': 'http://linksys.com/jnap/' + ACTIONS[key],
                'Content-Type': 'application/json', 'Connection': 'close'})
            response = conn.getresponse()
            http_status = response.status
            while True:
                remaining = min(self.deadline, per_request_deadline) - time.monotonic()
                need(remaining > 0, 'E_REQUEST_TIMEOUT')
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
                chunk = response.read1(min(16384, MAX_RESPONSE + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_RESPONSE:
                    return response.status, bytes(data[:MAX_RESPONSE]), True
            return response.status, bytes(data), False
        except SafeError:
            if data:
                return http_status, bytes(data), True
            raise
        except (OSError, http.client.HTTPException):
            if data:
                return http_status, bytes(data), True
            raise SafeError('E_ROUTER_NETWORK') from None
        finally:
            conn.close()


def envelope(raw, status):
    need(status == 200, 'E_ROUTER_HTTP')
    try:
        obj = json.loads(raw)
    except Exception:
        raise SafeError('E_ROUTER_JSON') from None
    need(isinstance(obj, dict), 'E_ROUTER_SCHEMA')
    result = obj.get('result', obj.get('response'))
    if 'result' in obj and 'response' in obj:
        need(obj['result'] == obj['response'], 'E_ROUTER_SCHEMA')
    code = result if isinstance(result, str) and result in KNOWN_RESULTS else 'other'
    return code, obj.get('output')


def log_page(output, index=FIRST_INDEX, kind='outgoing'):
    """Vendor UI uses a fixed 1/255 window. No sequence/EOF semantics are known.

    Source: public troubleshooting-1.0.99.216935.js, sha256
    b1b863eb80a67842f4de5ef6501395a0944c228bbca9a98f9ea6069baf244ba4.
    Incoming/security field names are vendor-rendered; unknown fields/types keep
    the whole raw response unprocessed for review. Empty arrays are valid.
    """
    need(index == FIRST_INDEX and kind in LOGS, 'E_PAGINATION')
    need(isinstance(output, dict) and set(output) == {'entries'} and
         isinstance(output['entries'], list), 'E_LOG_SCHEMA')
    fields = {'incoming': {'source', 'destinationPort'},
              'outgoing': {'source', 'destination', 'destinationPort', 'service'},
              'security': {'ipAddress', 'macAddress', 'timestamp', 'authSucceeded'}}[kind]
    # Outgoing service is an optional display label. Preserve its absence and
    # the original row; a present value must still be a bounded string.
    required = fields - {'service'} if kind == 'outgoing' else fields
    rows = output['entries']
    need(len(rows) <= PAGE_SIZE, 'E_LOG_SCHEMA')
    for row in rows:
        need(isinstance(row, dict) and required <= set(row) <= fields, 'E_LOG_ROW_SCHEMA')
        for field, value in row.items():
            if field == 'destinationPort':
                need(type(value) is int and 0 <= value <= 65535, 'E_LOG_ROW_SCHEMA')
            elif field == 'authSucceeded':
                need(type(value) is bool, 'E_LOG_ROW_SCHEMA')
            elif field == 'timestamp':
                need(type(value) in (str, int, float), 'E_LOG_ROW_SCHEMA')
            else:
                need(isinstance(value, str) and len(value) <= 8192, 'E_LOG_ROW_SCHEMA')
    return rows, None, False


def router_timestamp(row):
    if isinstance(row, dict):
        for key in ('timestamp', 'time', 'dateTime', 'eventTime', 'date'):
            value = row.get(key)
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                return canonical({'field': key, 'uninterpreted_value': value})
    return None


def device_addresses(device):
    found = set()
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ('ipAddress', 'ipAddresses'):
                    for text in child if isinstance(child, list) else [child]:
                        if isinstance(text, str):
                            try:
                                found.add(str(ipaddress.ip_address(text)))
                            except ValueError:
                                pass
                if isinstance(child, (dict, list)):
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(device)
    need(len(found) <= 128, 'E_DEVICE_SCHEMA')
    return sorted(found)


def device_key(device):
    identifier = device.get('deviceID')
    need(isinstance(identifier, str) and 0 < len(identifier) <= 256, 'E_DEVICE_IDENTITY')
    return hashlib.sha256(identifier.encode()).hexdigest()


class Store:
    def __init__(self, path, cap=DISK_CAP, clock=time.time):
        self.path, self.cap, self.clock = Path(path), cap, clock
        self.job_deadline = None
        os.umask(0o077)
        private_dir(self.path)
        self.raw_dir = self.path / 'raw'
        private_dir(self.raw_dir)
        self.lock = os.open(self.path / 'run.lock', os.O_RDWR | os.O_CREAT |
                            getattr(os, 'O_NOFOLLOW', 0), 0o600)
        if fcntl is not None:
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(self.lock)
                raise SafeError('E_BUSY') from None
        db = self.path / 'observations.sqlite3'
        if db.exists() or db.is_symlink():
            s = db.lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
                 (os.name != 'posix' or s.st_uid == os.geteuid()), 'E_DATABASE')
        self.db = sqlite3.connect(db, timeout=3)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA auto_vacuum=INCREMENTAL')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY,kind TEXT,observed REAL,
            filename TEXT,bytes INTEGER,processed INTEGER DEFAULT 0);
          CREATE TABLE IF NOT EXISTS observations(kind TEXT,record_hash TEXT,raw_json TEXT,
            router_timestamp_json TEXT,first_seen REAL,last_seen REAL,poll_sightings INTEGER,
            baseline INTEGER,last_poll_id TEXT,
            candidate_class TEXT DEFAULT 'unknown',PRIMARY KEY(kind,record_hash));
          CREATE TABLE IF NOT EXISTS devices(device_key TEXT PRIMARY KEY,device_json TEXT,
            first_seen REAL,last_seen REAL,baseline INTEGER,consecutive INTEGER,
            last_inventory_seq INTEGER,confirmed INTEGER,notice_id TEXT);
          CREATE TABLE IF NOT EXISTS device_addresses(address TEXT,device_key TEXT,
            first_seen REAL,last_seen REAL,PRIMARY KEY(address,device_key));
          CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);
          CREATE TABLE IF NOT EXISTS notices(id TEXT PRIMARY KEY,created REAL,category TEXT,
            record_count INTEGER,acknowledged INTEGER DEFAULT 0,acked_at REAL);
          CREATE TABLE IF NOT EXISTS health(id INTEGER PRIMARY KEY,stable TEXT,
            failures INTEGER,successes INTEGER,checked REAL);
          INSERT OR IGNORE INTO health VALUES(1,'unknown',0,0,NULL);
        ''')
        self.db.commit()
        if os.name == 'posix':
            os.chmod(db, 0o600)

    def close(self):
        self.db.close()
        os.close(self.lock)

    def disk_bytes(self):
        total = 0
        for p in self.path.rglob('*'):
            s = p.lstat()
            need(not stat.S_ISLNK(s.st_mode), 'E_STATE_SYMLINK')
            if stat.S_ISREG(s.st_mode):
                total += s.st_size
        return total

    def bump(self, key, amount):
        old = self.db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
        self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',
                        (key, str((int(old[0]) if old else 0) + amount)))

    def begin_poll(self):
        with self.db:
            self.bump('poll_sequence', 1)
            return int(self.db.execute("SELECT value FROM metadata WHERE key='poll_sequence'").fetchone()[0])

    def prune_tables(self):
        cutoff = self.clock() - RETENTION
        with self.db:
            expired = self.db.execute('DELETE FROM observations WHERE last_seen<?', (cutoff,)).rowcount
            self.bump('observation_expired_total', expired)
            count = self.db.execute('SELECT COUNT(*) FROM observations').fetchone()[0]
            excess = max(0, count - MAX_OBSERVATIONS)
            if excess:
                self.db.execute('DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations ORDER BY last_seen,first_seen,rowid LIMIT ?)', (excess,))
                self.bump('observation_cap_pruned_total', excess)
            old_notices = self.db.execute('DELETE FROM notices WHERE acknowledged=1 AND acked_at<?', (cutoff,)).rowcount
            self.bump('acknowledged_notice_expired_total', old_notices)
            eligible = self.db.execute('''SELECT device_key FROM devices d WHERE last_seen<?
              AND NOT (baseline=0 AND confirmed=1 AND notice_id IS NULL)
              AND NOT EXISTS(SELECT 1 FROM notices n WHERE n.id=d.notice_id AND n.acknowledged=0)''', (cutoff,)).fetchall()
            for row in eligible:
                self.db.execute('DELETE FROM device_addresses WHERE device_key=?', (row[0],))
                self.db.execute('DELETE FROM devices WHERE device_key=?', (row[0],))
            self.bump('device_expired_total', len(eligible))
            self.db.execute('''DELETE FROM device_addresses WHERE last_seen<? AND NOT EXISTS
              (SELECT 1 FROM devices d WHERE d.device_key=device_addresses.device_key AND
                ((d.baseline=0 AND d.confirmed=1 AND d.notice_id IS NULL) OR EXISTS
                  (SELECT 1 FROM notices n WHERE n.id=d.notice_id AND n.acknowledged=0)))''', (cutoff,))
        self.db.execute('PRAGMA incremental_vacuum(256)')

    def make_space(self, reserve):
        """Delete only already processed raw snapshots. Unknown data is retained."""
        expired, cap_pruned = 0, 0
        used = self.disk_bytes()
        rows = self.db.execute('SELECT * FROM snapshots WHERE processed=1 ORDER BY observed,id').fetchall()
        for row in rows:
            old = row['observed'] < self.clock() - RETENTION
            over = used + reserve > self.cap
            if not old and not over:
                break
            filename = row['filename']
            need(re.fullmatch(r'[a-f0-9]{32}\.raw', filename) is not None, 'E_RAW_PATH')
            file = self.raw_dir / filename
            if file.exists():
                s = file.lstat()
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'E_RAW_PATH')
                file.unlink()
                used -= s.st_size
            self.db.execute('DELETE FROM snapshots WHERE id=?', (row['id'],))
            expired += int(old)
            cap_pruned += int(not old)
        if cap_pruned:
            previous = self.db.execute("SELECT value FROM metadata WHERE key='raw_cap_pruned_total'").fetchone()
            self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',
                            ('raw_cap_pruned_total', str((int(previous[0]) if previous else 0) + cap_pruned)))
        self.db.commit()
        # Collected log observations have no alert payload attached. Under hard
        # disk pressure their history can shorten, with a persistent counter.
        while self.disk_bytes() + reserve > self.cap:
            need(self.job_deadline is None or time.monotonic() < self.job_deadline, 'E_JOB_BUDGET')
            with self.db:
                removed = self.db.execute('DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations ORDER BY last_seen,first_seen,rowid LIMIT 256)').rowcount
                self.bump('observation_cap_pruned_total', removed)
            if not removed:
                break
            self.db.execute('PRAGMA incremental_vacuum(1024)')
        need(self.disk_bytes() + reserve <= self.cap, 'E_STORAGE_CAP_UNCOLLECTED_RETAINED')
        return expired, cap_pruned

    def save_raw(self, kind, raw):
        ident = uuid.uuid4().hex
        filename = ident + '.raw'
        private_write(self.raw_dir / filename, raw)
        self.db.execute('INSERT INTO snapshots(id,kind,observed,filename,bytes) VALUES(?,?,?,?,?)',
                        (ident, kind, self.clock(), filename, len(raw)))
        self.db.commit()
        return ident

    def records(self, kind, rows, snapshot, poll_id=None, baseline=None):
        if baseline is None:
            baseline = self.db.execute('SELECT 1 FROM metadata WHERE key=?', ('baseline_' + kind,)).fetchone() is None
        poll_id = poll_id or uuid.uuid4().hex
        now, new, seen = self.clock(), 0, set()
        with self.db:
            for row in rows:
                text = canonical(row)
                fingerprint = hashlib.sha256(text.encode()).hexdigest()
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                cur = self.db.execute('''INSERT OR IGNORE INTO observations
                  (kind,record_hash,raw_json,router_timestamp_json,first_seen,last_seen,poll_sightings,baseline,last_poll_id)
                  VALUES(?,?,?,?,?,?,1,?,?)''',
                  (kind, fingerprint, text, router_timestamp(row), now, now, int(baseline), poll_id))
                new += cur.rowcount
                if not cur.rowcount:
                    self.db.execute('''UPDATE observations SET last_seen=?,
                      poll_sightings=poll_sightings+CASE WHEN last_poll_id=? THEN 0 ELSE 1 END,
                      last_poll_id=? WHERE kind=? AND record_hash=?''',
                      (now, poll_id, poll_id, kind, fingerprint))
            self.db.execute('INSERT OR IGNORE INTO metadata VALUES(?,?)', ('baseline_' + kind, str(now)))
            self.db.execute('UPDATE snapshots SET processed=1 WHERE id=?', (snapshot,))
            self.bump('observation_insertions_total', new)
        return new, int(baseline) * new

    def devices(self, output, snapshot, poll_sequence):
        need(isinstance(output, dict) and isinstance(output.get('devices'), list), 'E_DEVICE_SCHEMA')
        devices = output['devices']
        need(len(devices) <= 2048 and all(isinstance(x, dict) for x in devices), 'E_DEVICE_SCHEMA')
        now = self.clock()
        address_count = 0
        with self.db:
            first_inventory = self.db.execute("SELECT 1 FROM metadata WHERE key='inventory_baseline_done'").fetchone() is None
            keys = {device_key(d) for d in devices}
            need(len(keys) == len(devices), 'E_DEVICE_IDENTITY')
            existing = {row[0] for row in self.db.execute('SELECT device_key FROM devices')}
            excess = max(0, len(existing | keys) - MAX_DEVICES)
            if excess:
                eligible = [row[0] for row in self.db.execute('''SELECT device_key FROM devices d
                  WHERE NOT (baseline=0 AND confirmed=1 AND notice_id IS NULL)
                  AND NOT EXISTS(SELECT 1 FROM notices n WHERE n.id=d.notice_id AND n.acknowledged=0)
                  ORDER BY last_seen,first_seen,device_key''') if row[0] not in keys]
                need(len(eligible) >= excess, 'E_DEVICE_CAP_UNACKNOWLEDGED_RETAINED')
                for key in eligible[:excess]:
                    self.db.execute('DELETE FROM device_addresses WHERE device_key=?', (key,))
                    self.db.execute('DELETE FROM devices WHERE device_key=?', (key,))
                self.bump('device_cap_pruned_total', excess)
            for device in devices:
                text = canonical(device)
                key = device_key(device)
                old = self.db.execute('SELECT * FROM devices WHERE device_key=?', (key,)).fetchone()
                consecutive = min(2, old['consecutive'] + 1) if old and old['last_inventory_seq'] == poll_sequence - 1 else 1
                if old:
                    self.db.execute('''UPDATE devices SET device_json=?,last_seen=?,consecutive=?,
                      last_inventory_seq=?,confirmed=? WHERE device_key=?''',
                      (text, now, consecutive, poll_sequence, int(consecutive >= 2 or old['confirmed']), key))
                else:
                    self.db.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,?,0,NULL)',
                                    (key, text, now, now, int(first_inventory), 1, poll_sequence))
                for address in device_addresses(device):
                    address_count += 1
                    need(address_count <= 8192, 'E_DEVICE_SCHEMA')
                    self.db.execute('''INSERT INTO device_addresses VALUES(?,?,?,?)
                      ON CONFLICT(address,device_key) DO UPDATE SET last_seen=excluded.last_seen''',
                      (address, key, now, now))
            self.db.execute('UPDATE snapshots SET processed=1 WHERE id=?', (snapshot,))
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES('inventory_baseline_done','1')")
            excess = max(0, self.db.execute('SELECT COUNT(*) FROM device_addresses').fetchone()[0] - MAX_ADDRESSES)
            if excess:
                eligible = self.db.execute('''SELECT a.rowid FROM device_addresses a JOIN devices d ON d.device_key=a.device_key
                  WHERE NOT (d.baseline=0 AND d.confirmed=1 AND d.notice_id IS NULL)
                  AND NOT EXISTS(SELECT 1 FROM notices n WHERE n.id=d.notice_id AND n.acknowledged=0)
                  ORDER BY a.last_seen,a.rowid LIMIT ?''', (excess,)).fetchall()
                need(len(eligible) == excess, 'E_ADDRESS_CAP_UNACKNOWLEDGED_RETAINED')
                for row in eligible:
                    self.db.execute('DELETE FROM device_addresses WHERE rowid=?', (row[0],))
                self.bump('address_cap_pruned_total', excess)
        return len(devices)

    def _new_notice(self, category, count):
        need(category in NOTICE_CATEGORIES, 'E_NOTICE_CATEGORY')
        total = self.db.execute('SELECT COUNT(*) FROM notices').fetchone()[0]
        if total >= MAX_NOTICES:
            needed = total - MAX_NOTICES + 1
            eligible = self.db.execute('SELECT id FROM notices WHERE acknowledged=1 ORDER BY acked_at,id LIMIT ?', (needed,)).fetchall()
            need(len(eligible) == needed, 'E_NOTICE_CAP_UNACKNOWLEDGED_RETAINED')
            for row in eligible:
                self.db.execute('DELETE FROM notices WHERE id=?', (row[0],))
            self.bump('acknowledged_notice_cap_pruned_total', needed)
        ident = uuid.uuid4().hex
        self.db.execute('INSERT INTO notices(id,created,category,record_count) VALUES(?,?,?,?)',
                        (ident, self.clock(), category, count))
        return ident

    def prepare_inventory_notice(self):
        # A first baseline is never approval/trust and never alerts. Only later
        # additions observed in two successive collection polls become candidates.
        with self.db:
            count = self.db.execute('SELECT COUNT(*) FROM devices WHERE baseline=0 AND confirmed=1 AND notice_id IS NULL').fetchone()[0]
            old = self.db.execute("SELECT value FROM metadata WHERE key='inventory_last_notice'").fetchone()
            cooling = old is not None and self.clock() - float(old[0]) < INVENTORY_NOTICE_COOLDOWN
            pending = self.db.execute("SELECT 1 FROM notices WHERE category='inventory_change' AND acknowledged=0").fetchone()
            if count and not cooling and not pending:
                ident = self._new_notice('inventory_change', count)
                self.db.execute('UPDATE devices SET notice_id=? WHERE baseline=0 AND confirmed=1 AND notice_id IS NULL', (ident,))
                self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', ('inventory_last_notice', str(self.clock())))

    def observe_health(self, healthy):
        with self.db:
            old = self.db.execute('SELECT * FROM health WHERE id=1').fetchone()
            failures = 0 if healthy else min(1000000, old['failures'] + 1)
            successes = min(1000000, old['successes'] + 1) if healthy else 0
            stable = old['stable']
            if not healthy and failures >= 2 and stable != 'degraded':
                self._new_notice('router_collection_degraded', 0)
                stable = 'degraded'
            elif healthy and successes >= 2 and stable == 'degraded':
                self._new_notice('router_collection_recovered', 0)
                stable = 'healthy'
            elif healthy and stable == 'unknown':
                stable = 'healthy'
            self.db.execute('UPDATE health SET stable=?,failures=?,successes=?,checked=? WHERE id=1',
                            (stable, failures, successes, self.clock()))

    def pending_notices(self):
        # Parent integration durably queues a FIXED generic alert, then acks ID.
        return [dict(r) for r in self.db.execute('SELECT id,created,category,record_count FROM notices WHERE acknowledged=0 ORDER BY created,id')]

    def acknowledge_notice(self, notice_id):
        need(re.fullmatch(r'[a-f0-9]{32}', notice_id) is not None, 'E_NOTICE')
        with self.db:
            self.db.execute('UPDATE notices SET acknowledged=1,acked_at=? WHERE id=?', (self.clock(), notice_id))


def collect(store, client=None, *, gateway=None, profile=SUPPORTED_PROFILE):
    deadline = time.monotonic() + JOB_BUDGET
    client = client or RouterClient(deadline, gateway=gateway, profile=profile)
    store.job_deadline = deadline
    store.prune_tables()
    poll_sequence = store.begin_poll()
    poll_id = uuid.uuid4().hex
    status = {'ok': False, 'checked_at': store.clock(), 'logging_enabled': None, 'router_identity_ok': False,
              'api': {}, 'new_record_count': 0, 'baseline_record_count': 0,
              'gaps': [], 'limitations': [], 'raw_expired_count': 0, 'raw_cap_pruned_count': 0,
              'complete_stream_visibility': False, 'classification': 'unknown',
              'historical_completeness': False, 'window_entry_limit': PAGE_SIZE,
              'deduplication_is_observation_based': True, 'poll_interval_seconds': 60}
    def fetch(key, index=FIRST_INDEX):
        need(time.monotonic() < deadline, 'E_JOB_BUDGET')
        expired, pruned = store.make_space(4 * MAX_RESPONSE)
        status['raw_expired_count'] += expired
        status['raw_cap_pruned_count'] += pruned
        http, raw, truncated = client.request(key, index)
        snapshot = store.save_raw(key, raw)
        info = status['api'].setdefault(key, {'pages': 0, 'rows_observed': 0})
        info['pages'] += 1
        info['http_status'], info['response_truncated'] = http, truncated
        need(not truncated, 'E_RESPONSE_TRUNCATED')
        result, output = envelope(raw, http)
        info['result_code'], info['schema'] = result, public_schema(output)
        if result != 'OK':
            # A recognized refusal contains no collected entries to preserve.
            if output is None and result != 'other':
                with store.db:
                    store.db.execute('UPDATE snapshots SET processed=1 WHERE id=?', (snapshot,))
            raise SafeError('E_API_READ')
        return output, snapshot, info
    for key in ('identity', 'settings', 'devices') + LOGS:
        try:
            output, snapshot, info = fetch(key)
            if key == 'identity':
                need(isinstance(output, dict) and output.get('modelNumber') == 'EA7300' and
                     output.get('hardwareVersion') == '2' and output.get('firmwareVersion') == '2.0.4.216940', 'E_ROUTER_IDENTITY')
                status['router_identity_ok'] = True
                with store.db:
                    store.db.execute('UPDATE snapshots SET processed=1 WHERE id=?', (snapshot,))
            elif key == 'settings':
                need(isinstance(output, dict) and set(output) == {'isLoggingEnabled'} and
                     type(output['isLoggingEnabled']) is bool, 'E_SETTINGS_SCHEMA')
                status['logging_enabled'] = output['isLoggingEnabled']
                with store.db:
                    store.db.execute('UPDATE snapshots SET processed=1 WHERE id=?', (snapshot,))
            elif key == 'devices':
                info['device_records'] = store.devices(output, snapshot, poll_sequence)
            else:
                need(LOG_SCHEMA_VERIFIED, 'E_LOG_SCHEMA_UNVERIFIED')
                baseline_kind = store.db.execute('SELECT 1 FROM metadata WHERE key=?', ('baseline_' + key,)).fetchone() is None
                rows, _, _ = log_page(output, FIRST_INDEX, key)
                new, baseline = store.records(key, rows, snapshot, poll_id, baseline_kind)
                info.update(rows_observed=len(rows), historical_completeness=False,
                            window_at_capacity=len(rows) == PAGE_SIZE)
                status['new_record_count'] += new
                status['baseline_record_count'] += baseline
                status['limitations'].append({'source': key, 'code': 'FIXED_WINDOW_COMPLETENESS_UNKNOWN'})
        except SafeError as error:
            status['gaps'].append({'source': key, 'code': str(error)})
            if key == 'identity':
                break
        except Exception:
            status['gaps'].append({'source': key, 'code': 'E_COLLECTION'})
            if key == 'identity':
                break
    if status['logging_enabled'] is False:
        status['gaps'].append({'source': 'settings', 'code': 'E_LOGGING_DISABLED'})
    status['collection_ok'] = status['logging_enabled'] is True and not status['gaps']
    status['notification_ok'] = True
    try:
        store.prepare_inventory_notice()
        store.observe_health(status['collection_ok'])
    except SafeError as error:
        status['notification_ok'] = False
        status['gaps'].append({'source': 'notices', 'code': str(error)})
    store.prune_tables()
    status['pending_generic_notices'] = store.db.execute('SELECT COUNT(*) FROM notices WHERE acknowledged=0').fetchone()[0]
    status['unnotified_confirmed_inventory_additions'] = store.db.execute('SELECT COUNT(*) FROM devices WHERE baseline=0 AND confirmed=1 AND notice_id IS NULL').fetchone()[0]
    status['retained_device_count'] = store.db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
    status['retained_baseline_device_count'] = store.db.execute('SELECT COUNT(*) FROM devices WHERE baseline=1').fetchone()[0]
    status['baseline_is_trust_approval'] = False
    status['retained_unique_observations'] = {row[0]: row[1] for row in store.db.execute('SELECT kind,COUNT(*) FROM observations GROUP BY kind')}
    insertions = store.db.execute("SELECT value FROM metadata WHERE key='observation_insertions_total'").fetchone()
    status['observation_insertions_total'] = int(insertions[0]) if insertions else 0
    status['dedup_scope'] = 'retained_history_not_unique_connections'
    status['collection_health'] = store.db.execute('SELECT stable FROM health WHERE id=1').fetchone()[0]
    status['raw_unprocessed_snapshots'] = store.db.execute('SELECT COUNT(*) FROM snapshots WHERE processed=0').fetchone()[0]
    status['private_disk_bytes'] = store.disk_bytes()
    pruned = store.db.execute("SELECT value FROM metadata WHERE key='raw_cap_pruned_total'").fetchone()
    status['raw_cap_pruned_total'] = int(pruned[0]) if pruned else 0
    status['retention_counters'] = {r[0]: int(r[1]) for r in store.db.execute("SELECT key,value FROM metadata WHERE key IN ('observation_expired_total','observation_cap_pruned_total','device_expired_total','device_cap_pruned_total','address_cap_pruned_total','acknowledged_notice_expired_total','acknowledged_notice_cap_pruned_total')")}
    status['retention_shortened_by_cap'] = status['raw_cap_pruned_total'] > 0 or any(
        v > 0 for k, v in status['retention_counters'].items() if 'cap_pruned' in k)
    status['ok'] = status['collection_ok'] and status['notification_ok']
    raw = (canonical(status) + '\n').encode()
    tmp = store.path / (uuid.uuid4().hex + '.status.tmp')
    private_write(tmp, raw)
    os.replace(tmp, store.path / 'status.json')
    sync_directory(store.path)
    return status


def load_config(path=DEFAULT_CONFIG):
    """Read an owned private config; the gateway must be explicitly supplied."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= 16384, 'E_ROUTER_CONFIG')
        if os.name == 'posix':
            need(meta.st_uid == os.geteuid() and not meta.st_mode & 0o077, 'E_ROUTER_CONFIG')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(16385)
        need(len(raw) <= 16384, 'E_ROUTER_CONFIG')
        value = json.loads(raw)
        need(isinstance(value, dict) and set(value) <= {'gateway', 'profile'}, 'E_ROUTER_CONFIG')
        profile = value.get('profile', SUPPORTED_PROFILE)
        client = RouterClient(time.monotonic() + JOB_BUDGET, gateway=value['gateway'], profile=profile)
        return {'gateway': client.gateway, 'profile': client.profile}
    except SafeError:
        raise
    except Exception:
        raise SafeError('E_ROUTER_CONFIG') from None
    finally:
        if fd is not None:
            os.close(fd)


def main(argv=None):
    parser = SafeArgumentParser(description='Read-only router log observations; no credentials.')
    parser.add_argument('command', choices=('collect', 'status', 'notices'))
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('--test-paths', action='store_true')
    args = parser.parse_args(argv)
    store = None
    try:
        need(args.test_paths or (os.name == 'posix' and os.geteuid() == 0), 'E_PRIVILEGE')
        store = Store(args.state_dir or DEFAULT_STATE)
        if args.command == 'collect':
            result = collect(store, **load_config(args.config))
        elif args.command == 'status':
            result = json.loads((store.path / 'status.json').read_bytes())
        else:
            result = {'pending_notices': store.pending_notices()}
        print(canonical(result))
        return 0 if result.get('ok', True) else 1
    except SafeError as error:
        print(canonical({'ok': False, 'error': str(error)}))
        return 1
    except Exception:
        print(canonical({'ok': False, 'error': 'E_STATE'}))
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == '__main__':
    raise SystemExit(main())
