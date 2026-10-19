"""Sanitized retained-router-history handoff and unprivileged read-only paging.

This is retained observation history, not sessions, event timestamps or flows.
No source raw JSON, device records, credentials, or review notes are exported.
"""
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

HISTORY_PATH = Path('/var/lib/sentinel-console-feed/history.sqlite3')
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_HISTORY_BYTES = 128 * 1024 * 1024
MAX_SOURCE_ROWS = 100000
EXPORT_SECONDS = 8
READ_SECONDS = 3
META_KEYS = {'schema_version', 'network_id', 'binding_sha256', 'generated_at',
             'collector_checked_at', 'state', 'raw_retained_count', 'exported_count', 'row_errors'}
ROW_KEYS = {'id', 'source', 'state', 'direction', 'direction_basis', 'source_address', 'source_port',
            'destination_address', 'destination_port', 'source_scope', 'destination_scope', 'address_family',
            'transport', 'application', 'observed_at', 'time_basis', 'summary', 'reason', 'next_step',
            'severity', 'flags', 'service_hint', 'rx_bytes', 'tx_bytes', 'rx_bytes_per_second',
            'tx_bytes_per_second', 'network_id'}
DECISIONS = {'recognize', 'unrecognized', 'investigate'}
_ID = re.compile(r'[0-9a-f]{64}\Z')


class HistoryError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise HistoryError(code)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns)


def file_metadata(meta, uid, gid, mode):
    need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
         and not getattr(meta, 'st_file_attributes', 0) & 0x400, 'E_HISTORY_FILE')
    if os.name == 'posix':
        need(meta.st_uid == uid and meta.st_gid == gid and stat.S_IMODE(meta.st_mode) == mode, 'E_HISTORY_FILE')


def context(snapshot, now):
    try:
        network = snapshot['network_id']
        binding = snapshot['network_binding_sha256']
        guard = snapshot['sources']['guard']
        need(str(uuid.UUID(network)) == network and uuid.UUID(network).int != 0 and _ID.fullmatch(binding), 'E_HISTORY_CONTEXT')
        need(guard.get('matches') is True and guard.get('state') == 'ok'
             and finite(snapshot.get('generated_at')) and -30 <= now - snapshot['generated_at'] <= 90
             and finite(guard.get('checked_at')) and -30 <= now - guard['checked_at'] <= 90, 'E_HISTORY_CONTEXT')
        return network, binding
    except (KeyError, TypeError, ValueError, AttributeError):
        raise HistoryError('E_HISTORY_CONTEXT') from None


def unavailable(reason='Retained history is unavailable.', state='unavailable'):
    return {'available': False, 'state': state, 'generated_at': None, 'collector_checked_at': None,
            'raw_retained_count': None, 'total_observations': None, 'row_errors': None, 'reason': reason}


def validate_row(row, network):
    need(isinstance(row, dict) and set(row) == ROW_KEYS and isinstance(row['id'], str)
         and _ID.fullmatch(row['id']) and row['network_id'] == network and row['source'] == 'router'
         and row['state'] == 'history' and row['direction'] in ('vendor_incoming', 'vendor_outgoing')
         and row['transport'] == 'unknown' and finite(row['observed_at'])
         and row['time_basis'] == 'collector_last_seen', 'E_HISTORY_ROW')
    for key in ('rx_bytes', 'tx_bytes', 'rx_bytes_per_second', 'tx_bytes_per_second', 'source_port'):
        need(row[key] is None, 'E_HISTORY_ROW')
    need(type(row['destination_port']) is int and 0 <= row['destination_port'] <= 65535, 'E_HISTORY_ROW')
    for key in ('source_address', 'destination_address'):
        value = row[key]
        need(value is None or isinstance(value, str) and len(value) <= 253
             and all(32 <= ord(c) < 127 for c in value), 'E_HISTORY_ROW')
    for key in ('summary', 'reason', 'next_step', 'direction_basis', 'application', 'service_hint',
                'source_scope', 'destination_scope', 'severity'):
        need(isinstance(row[key], str) and len(row[key]) <= 2048
             and all(32 <= ord(c) < 127 for c in row[key]), 'E_HISTORY_ROW')
    need(isinstance(row['flags'], list) and len(row['flags']) <= 8, 'E_HISTORY_ROW')
    for flag in row['flags']:
        need(isinstance(flag, dict) and set(flag) == {'code', 'severity', 'reason', 'next_step'}
             and all(isinstance(value, str) and len(value) <= 1024
                     and all(32 <= ord(c) < 127 for c in value) for value in flag.values()), 'E_HISTORY_ROW')
    return row


def _directory(path, uid, gid):
    meta = path.lstat()
    need(stat.S_ISDIR(meta.st_mode) and not getattr(meta, 'st_file_attributes', 0) & 0x400, 'E_HISTORY_DIRECTORY')
    if os.name == 'posix':
        need(meta.st_uid == uid and meta.st_gid == gid and stat.S_IMODE(meta.st_mode) == 0o750, 'E_HISTORY_DIRECTORY')


def export_history(router_state, snapshot, path=HISTORY_PATH, *, gid, uid=0, now=None, monotonic=None):
    """Root worker only: stream all source rows into an atomic sanitized handoff.

    Failure preserves the old handoff, and must be published in sources.history.
    Limits abort the whole new generation; no arbitrary retention is discarded.
    """
    from . import console_feed as feed
    now = time.time() if now is None else now
    clock = time.monotonic if monotonic is None else monotonic
    deadline = clock() + EXPORT_SECONDS
    path = Path(path)
    lock = source = target = None
    source_fd = None
    temporary = None
    result = unavailable()
    try:
        network, binding = context(snapshot, now)
        need(router_state is not None, 'E_HISTORY_DISABLED')
        root = Path(router_state)
        feed._directory(root, uid, private=True)
        lock = os.open(root / 'run.lock', os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        lock_meta = os.fstat(lock)
        need(stat.S_ISREG(lock_meta.st_mode) and lock_meta.st_nlink == 1
             and not getattr(lock_meta, 'st_file_attributes', 0) & 0x400, 'E_HISTORY_LOCK')
        if os.name == 'posix':
            need(lock_meta.st_uid == uid and not lock_meta.st_mode & 0o077 and feed.fcntl is not None, 'E_HISTORY_LOCK')
            try:
                feed.fcntl.flock(lock, feed.fcntl.LOCK_SH | feed.fcntl.LOCK_NB)
            except OSError:
                raise HistoryError('E_HISTORY_BUSY') from None
        status = json.loads(feed._read(root / 'status.json', 128 * 1024, uid=uid, private=True))
        database = root / 'observations.sqlite3'
        need(not any(os.path.lexists(str(database) + suffix) for suffix in ('-wal', '-shm', '-journal')), 'E_HISTORY_SIDECAR')
        source_fd = os.open(database, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        before = os.fstat(source_fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_SOURCE_BYTES
             and not getattr(before, 'st_file_attributes', 0) & 0x400, 'E_HISTORY_SOURCE')
        if os.name == 'posix':
            need(before.st_uid == uid and not before.st_mode & 0o077, 'E_HISTORY_SOURCE')
        source_uri = ('file:/proc/self/fd/' + str(source_fd)) if os.name == 'posix' else database.absolute().as_uri()
        source = sqlite3.connect(source_uri + '?mode=ro&immutable=1', uri=True, timeout=1)
        source.execute('PRAGMA query_only=ON')
        source.execute('PRAGMA trusted_schema=OFF')
        source.set_progress_handler(lambda: int(clock() > deadline), 1000)
        raw_count = source.execute("SELECT COUNT(*) FROM observations WHERE kind IN ('incoming','outgoing')").fetchone()[0]
        need(type(raw_count) is int and 0 <= raw_count <= MAX_SOURCE_ROWS, 'E_HISTORY_ROW_LIMIT')
        feed._directory(path.parent.parent, uid)
        if not path.parent.exists():
            path.parent.mkdir(mode=0o750)
            if os.name == 'posix':
                os.chown(path.parent, uid, gid)
                path.parent.chmod(0o750)
        _directory(path.parent, uid, gid)
        if os.path.lexists(path):
            file_metadata(path.lstat(), uid, gid, 0o640)
        temporary = path.with_name('.history-' + uuid.uuid4().hex + '.sqlite3')
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o640)
        try:
            if os.name == 'posix':
                os.fchown(fd, uid, gid)
                os.fchmod(fd, 0o640)
        finally:
            os.close(fd)
        target = sqlite3.connect(temporary, timeout=1)
        target.execute('PRAGMA journal_mode=DELETE')
        target.execute('PRAGMA synchronous=FULL')
        target.execute('PRAGMA cache_size=-2048')
        target.execute('PRAGMA temp_store=MEMORY')
        target.execute('PRAGMA max_page_count=' + str(MAX_HISTORY_BYTES // 4096))
        target.set_progress_handler(lambda: int(clock() > deadline), 1000)
        target.executescript('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);'
            'CREATE TABLE history(id TEXT PRIMARY KEY,direction TEXT NOT NULL,observed_at REAL NOT NULL,'
            'first_observed_at REAL NOT NULL,observation_count INTEGER NOT NULL,search_text TEXT NOT NULL,row_json TEXT NOT NULL);')
        has_first = 'first_seen' in {row[1] for row in source.execute('PRAGMA table_info(observations)')}
        first_column = 'first_seen' if has_first else 'last_seen'
        rows = source.execute("SELECT kind,raw_json," + first_column +
                              ",last_seen FROM observations WHERE kind IN ('incoming','outgoing')")
        errors = 0
        for kind, raw, first, observed in rows:
            need(clock() <= deadline, 'E_HISTORY_RUNTIME_LIMIT')
            try:
                need(isinstance(raw, str) and len(raw) <= 65536, 'E_HISTORY_ROW')
                row = feed._router_connection(kind, json.loads(raw), observed)
                row['id'] = feed._digest([network, binding, row['id']])
                row['network_id'] = network
                validate_row(row, network)
                need(observed <= now + 30, 'E_HISTORY_ROW')
                first = first if finite(first) and first <= observed else observed
                text = ' '.join(str(row.get(key) or '') for key in ('source_address', 'destination_address',
                    'destination_port', 'application', 'service_hint', 'summary')).casefold()
                encoded = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False)
                need(len(encoded) <= 16384, 'E_HISTORY_ROW')
            except Exception:
                errors += 1
                continue
            target.execute('INSERT INTO history VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                'first_observed_at=MIN(history.first_observed_at,excluded.first_observed_at),'
                'observation_count=history.observation_count+1,'
                'search_text=CASE WHEN excluded.observed_at>=history.observed_at THEN excluded.search_text ELSE history.search_text END,'
                'row_json=CASE WHEN excluded.observed_at>=history.observed_at THEN excluded.row_json ELSE history.row_json END,'
                'observed_at=MAX(history.observed_at,excluded.observed_at)',
                (row['id'], row['direction'], observed, first, 1, text, encoded))
        need(identity(before) == identity(os.fstat(source_fd)) == identity(database.lstat()), 'E_HISTORY_SOURCE_CHANGED')
        exported = target.execute('SELECT COUNT(*) FROM history').fetchone()[0]
        checked = status.get('checked_at') if isinstance(status, dict) else None
        fresh = finite(checked) and -30 <= now - checked <= 180
        state = 'stale' if not fresh else 'partial' if errors or status.get('collection_ok') is not True else 'ok'
        meta = {'schema_version': 1, 'network_id': network, 'binding_sha256': binding, 'generated_at': now,
                'collector_checked_at': checked if finite(checked) else None, 'state': state,
                'raw_retained_count': raw_count, 'exported_count': exported, 'row_errors': errors}
        target.executemany('INSERT INTO metadata VALUES(?,?)', ((key, json.dumps(value)) for key, value in meta.items()))
        target.execute('CREATE INDEX history_order ON history(observed_at DESC,id)')
        need(clock() <= deadline, 'E_HISTORY_RUNTIME_LIMIT')
        target.commit()
        target.close(); target = None
        need(temporary.stat().st_size <= MAX_HISTORY_BYTES, 'E_HISTORY_OUTPUT_LIMIT')
        fd = os.open(temporary, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
        try:
            file_metadata(os.fstat(fd), uid, gid, 0o640)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        if os.name == 'posix':
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
        result = {'available': True, 'state': state, 'generated_at': now, 'collector_checked_at': meta['collector_checked_at'],
                  'raw_retained_count': raw_count, 'total_observations': exported, 'row_errors': errors,
                  'reason': 'All valid retained router records exported; rows remain history, not sessions or flow counts.'}
    except Exception as error:
        code = str(error) if isinstance(error, HistoryError) else 'E_HISTORY_EXPORT'
        if clock() > deadline:
            code = 'E_HISTORY_RUNTIME_LIMIT'
        # SQLITE_FULL is stable code 13. Python 3.10 exposes neither the module
        # constant nor sqlite_errorcode, so retain SQLite's exact legacy message.
        elif (getattr(error, 'sqlite_errorcode', None) == 13 or
              isinstance(error, sqlite3.OperationalError) and str(error) == 'database or disk is full'):
            code = 'E_HISTORY_OUTPUT_LIMIT'
        result = unavailable('Retained-history export did not complete: ' + code, 'unavailable' if code in
                             ('E_HISTORY_CONTEXT', 'E_HISTORY_DISABLED', 'E_HISTORY_BUSY') else 'error')
    finally:
        for db in (target, source):
            if db is not None: db.close()
        for fd in (source_fd, lock):
            if fd is not None: os.close(fd)
        if temporary is not None:
            for suffix in ('', '-journal', '-wal', '-shm'):
                candidate = Path(str(temporary) + suffix)
                if os.path.lexists(candidate): candidate.unlink()
    return result


def annotations_index(annotations):
    need(isinstance(annotations, dict) and len(annotations) <= 5000, 'E_HISTORY_ANNOTATIONS')
    result = {}
    for ident, annotation in annotations.items():
        need(isinstance(ident, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', ident)
             and isinstance(annotation, dict) and annotation.get('decision') in DECISIONS, 'E_HISTORY_ANNOTATIONS')
        result[ident] = annotation['decision']
    return result


def validate_query(query):
    need(isinstance(query, dict) and set(query) == {'offset', 'limit', 'search', 'direction', 'review'}, 'E_HISTORY_QUERY')
    need(type(query['offset']) is int and 0 <= query['offset'] <= 2**63 - 1
         and type(query['limit']) is int and 1 <= query['limit'] <= 100
         and isinstance(query['search'], str) and len(query['search']) <= 200
         and all(32 <= ord(c) and ord(c) != 127 for c in query['search'])
         and query['direction'] in ('all', 'vendor_outgoing', 'vendor_incoming')
         and query['review'] in ('all', 'pending', 'unrecognized', 'investigate', 'recognize'), 'E_HISTORY_QUERY')
    return dict(query)


class HistoryReader:
    def __init__(self, path=HISTORY_PATH, *, _uid=0, _gid=None, _clock=None):
        self.path, self.uid, self.gid = Path(path), _uid, _gid
        self.clock = time.time if _clock is None else _clock

    @contextmanager
    def open(self, snapshot):
        now = self.clock()
        network, binding = context(snapshot, now)
        source_info = snapshot.get('sources', {}).get('history')
        need(not isinstance(source_info, dict) or source_info.get('available') is not False, 'E_HISTORY_EXPORT_UNAVAILABLE')
        gid = self.gid
        if os.name == 'posix' and gid is None:
            import grp
            gid = grp.getgrnam('sentinelconsole').gr_gid
            need(gid in os.getgroups() + [os.getegid()], 'E_HISTORY_GROUP')
        _directory(self.path.parent, self.uid, gid)
        file_metadata(self.path.lstat(), self.uid, gid, 0o640)
        need(not any(os.path.lexists(str(self.path) + suffix) for suffix in ('-wal', '-shm', '-journal')), 'E_HISTORY_SIDECAR')
        fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        db = None
        try:
            before = os.fstat(fd)
            file_metadata(before, self.uid, gid, 0o640)
            need(before.st_size <= MAX_HISTORY_BYTES, 'E_HISTORY_SIZE')
            uri = ('file:/proc/self/fd/' + str(fd)) if os.name == 'posix' else self.path.absolute().as_uri()
            db = sqlite3.connect(uri + '?mode=ro&immutable=1', uri=True, timeout=1)
            db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
            deadline = time.monotonic() + READ_SECONDS
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            meta = {key: json.loads(value) for key, value in db.execute('SELECT key,value FROM metadata')}
            need(set(meta) == META_KEYS and type(meta['schema_version']) is int and meta['schema_version'] == 1
                 and meta['network_id'] == network and meta['binding_sha256'] == binding, 'E_HISTORY_CONTEXT')
            need(finite(meta['generated_at']) and (meta['collector_checked_at'] is None or finite(meta['collector_checked_at']))
                 and meta['state'] in ('ok', 'partial', 'stale')
                 and all(type(meta[key]) is int and 0 <= meta[key] <= MAX_SOURCE_ROWS for key in
                         ('raw_retained_count', 'exported_count', 'row_errors'))
                 and meta['exported_count'] + meta['row_errors'] <= meta['raw_retained_count'], 'E_HISTORY_META')
            need(db.execute('SELECT COUNT(*) FROM history').fetchone()[0] == meta['exported_count'], 'E_HISTORY_META')
            fresh = -30 <= now - meta['generated_at'] <= 90 and finite(meta['collector_checked_at']) and -30 <= now - meta['collector_checked_at'] <= 180
            summary = {'available': True, 'state': meta['state'] if fresh else 'stale', 'generated_at': meta['generated_at'],
                'collector_checked_at': meta['collector_checked_at'], 'raw_retained_count': meta['raw_retained_count'],
                'total_observations': meta['exported_count'], 'row_errors': meta['row_errors'],
                'reason': 'Retained router observations, not current sessions, flow counts, byte totals or proven event times.'}
            yield db, summary, meta
            need(identity(before) == identity(os.fstat(fd)), 'E_HISTORY_CHANGED')
        finally:
            if db is not None: db.close()
            os.close(fd)

    def summary(self, snapshot, annotations):
        try:
            annotations_index(annotations)
            with self.open(snapshot) as (_, result, _):
                return result
        except Exception:
            return unavailable('Retained history or its fresh network context is unavailable.')

    def page(self, query, annotations, snapshot):
        query = validate_query(query)
        base = {'rows': [], 'total_matches': None, 'offset': query['offset'], 'limit': query['limit'], 'has_more': False}
        try:
            reviewed = annotations_index(annotations)
            with self.open(snapshot) as (db, summary, meta):
                where, parameters = [], []
                if query['direction'] != 'all':
                    where.append('direction=?'); parameters.append(query['direction'])
                if query['search']:
                    where.append('instr(search_text,?)>0'); parameters.append(query['search'].casefold())
                if query['review'] != 'all':
                    identifiers = list(reviewed) if query['review'] == 'pending' else [key for key, decision in reviewed.items() if decision == query['review']]
                    if identifiers:
                        where.append('id ' + ('NOT IN' if query['review'] == 'pending' else 'IN') + '(' + ','.join('?' for _ in identifiers) + ')')
                        parameters.extend(identifiers)
                    elif query['review'] != 'pending':
                        where.append('0')
                clause = ' WHERE ' + ' AND '.join(where) if where else ''
                total = db.execute('SELECT COUNT(*) FROM history' + clause, parameters).fetchone()[0]
                rows = []
                for raw, first, count in db.execute('SELECT row_json,first_observed_at,observation_count FROM history' + clause +
                        ' ORDER BY observed_at DESC,id LIMIT ? OFFSET ?', parameters + [query['limit'], query['offset']]):
                    need(isinstance(raw, str) and len(raw) <= 16384 and finite(first)
                         and type(count) is int and 1 <= count <= meta['raw_retained_count'], 'E_HISTORY_ROW')
                    row = validate_row(json.loads(raw), meta['network_id'])
                    row.update(first_observed_at=first, observation_count=count,
                        aggregation_note='Retained source records coalesced by endpoint; this count is not sessions, flows, polls or bytes.',
                        review_status=reviewed.get(row['id'], 'pending'))
                    rows.append(row)
                return {**summary, **base, 'rows': rows, 'total_matches': total,
                        'has_more': query['offset'] + len(rows) < total}
        except Exception:
            return {**unavailable('Retained history could not be read in the current network context.'), **base}

    def contains(self, ident, snapshot):
        if not isinstance(ident, str) or not _ID.fullmatch(ident):
            return False
        try:
            with self.open(snapshot) as (db, summary, meta):
                if summary['state'] == 'stale':
                    return False
                found = db.execute('SELECT row_json FROM history WHERE id=?', (ident,)).fetchone()
                if not found or not isinstance(found[0], str) or len(found[0]) > 16384:
                    return False
                return validate_row(json.loads(found[0]), meta['network_id'])['id'] == ident
        except Exception:
            return False
