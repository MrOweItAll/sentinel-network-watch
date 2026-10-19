"""Unprivileged HTTPS console runtime. No privileged command or credential API."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import time

MAX_SNAPSHOT = 4 * 1024 * 1024
FEED = Path('/var/lib/sentinel-console-feed/snapshot.json')
STATE = Path('/var/lib/sentinel-console')


class ConsoleError(ValueError):
    pass


def read_feed(path=FEED):
    """Read a fixed root-owned, group-readable handoff; never follow symlinks."""
    path = Path(path)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or
            stat.S_IMODE(parent.st_mode) != 0o750 or parent.st_gid not in os.getgroups() + [os.getegid()]):
        raise ConsoleError('E_FEED_DIRECTORY')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != parent.st_gid or
                stat.S_IMODE(meta.st_mode) != 0o640 or meta.st_nlink != 1 or meta.st_size > MAX_SNAPSHOT):
            raise ConsoleError('E_FEED_PERMISSIONS')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(MAX_SNAPSHOT + 1)
        data = json.loads(raw)
        if (len(raw) > MAX_SNAPSHOT or not isinstance(data, dict) or data.get('schema_version') != 1 or
                type(data.get('generated_at')) not in (int, float) or not math.isfinite(data['generated_at']) or
                not isinstance(data.get('sources'), dict) or not isinstance(data.get('connections'), list) or
                len(data['connections']) > 1000 or any(not isinstance(row, dict) for row in data['connections'])):
            raise ConsoleError('E_FEED_SCHEMA')
        age = time.time() - data['generated_at']
        if age < -30 or age > 90:
            for source in data.get('sources', {}).values():
                if isinstance(source, dict):
                    source['state'] = 'stale'
                    source['reason'] = 'Observation feed is stale; displayed entries are retained evidence, not current activity.'
            for row in data['connections']:
                if row.get('source') == 'linux':
                    row['state'] = 'history'
        return data
    except (OSError, ValueError, TypeError, KeyError):
        raise ConsoleError('E_FEED_READ') from None
    finally:
        if fd is not None:
            os.close(fd)


def snapshot():
    try:
        return read_feed()
    except (OSError, ConsoleError):
        return {'schema_version': 1, 'generated_at': 0, 'connections': [], 'counters': [],
                'sources': {'feed': {'state': 'unavailable', 'checked_at': time.time(),
                                    'reason': 'Observation feed unavailable. No coverage can be inferred.'}},
                'capabilities': {}, 'truncation': {'connections': False}}


class ReviewStore:
    """Private local review journal; assessments never invoke enforcement."""
    def __init__(self, path):
        self.path = Path(path)
        parent = self.path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077):
            raise ConsoleError('E_REVIEW_DIRECTORY')
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            os.close(fd)
        meta = self.path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077 or meta.st_nlink != 1):
            raise ConsoleError('E_REVIEW_PERMISSIONS')
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, decision TEXT NOT NULL, note TEXT NOT NULL, updated_at REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS review_history (sequence INTEGER PRIMARY KEY, id TEXT NOT NULL, decision TEXT NOT NULL, note TEXT NOT NULL, updated_at REAL NOT NULL)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('PRAGMA busy_timeout=5000')
            db.execute('PRAGMA trusted_schema=OFF')
            with db:
                yield db
        finally:
            db.close()

    def annotations(self):
        with self.connect() as db:
            rows = db.execute('SELECT id,decision,note,updated_at FROM reviews ORDER BY updated_at DESC LIMIT 5000')
            return {r[0]: {'decision': r[1], 'note': r[2], 'updated_at': r[3]} for r in rows}

    def update_review(self, id, decision, note):
        if (not isinstance(id, str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', id) is None or
                decision not in ('recognize', 'unrecognized', 'investigate') or not isinstance(note, str) or
                len(note) > 500 or any(ord(c) < 32 or ord(c) == 127 for c in note)):
            raise ConsoleError('E_REVIEW_INPUT')
        now = time.time()
        with self.connect() as db:
            if db.execute('SELECT COUNT(*) FROM reviews').fetchone()[0] >= 5000 and not db.execute('SELECT 1 FROM reviews WHERE id=?', (id,)).fetchone():
                raise ConsoleError('E_REVIEW_LIMIT')
            if db.execute('SELECT COUNT(*) FROM review_history').fetchone()[0] >= 100000:
                raise ConsoleError('E_REVIEW_HISTORY_LIMIT')
            db.execute('INSERT INTO reviews VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET decision=excluded.decision,note=excluded.note,updated_at=excluded.updated_at', (id, decision, note, now))
            db.execute('INSERT INTO review_history(id,decision,note,updated_at) VALUES (?,?,?,?)', (id, decision, note, now))
        return {'ok': True, 'decision': decision, 'updated_at': now, 'traffic_changed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Private Sentinel home-network HTTPS console')
    parser.add_argument('--config', default='/etc/sentinel-console/config.json')
    args = parser.parse_args(argv)
    if os.name != 'posix' or os.geteuid() == 0:
        raise ConsoleError('E_UNPRIVILEGED_REQUIRED')
    config_path = Path(args.config)
    m = config_path.lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022 or m.st_nlink != 1 or m.st_size > 4096:
        raise ConsoleError('E_CONFIG_PERMISSIONS')
    config = json.loads(config_path.read_bytes())
    if set(config) != {'bind', 'port', 'allowed_cidr', 'auth_path'}:
        raise ConsoleError('E_CONFIG')
    if config['auth_path'] != str(STATE / 'dashboard-auth.json'):
        raise ConsoleError('E_AUTH_PATH')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(STATE / 'server.crt', STATE / 'server.key')
    from .console_server import create_server
    server = create_server(config, snapshot, ReviewStore(STATE / 'reviews.sqlite3'), tls)
    with server:
        server.serve_forever(poll_interval=.5)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('SENTINEL_CONSOLE_ERROR=E_STARTUP', flush=True)
        raise SystemExit(1)
