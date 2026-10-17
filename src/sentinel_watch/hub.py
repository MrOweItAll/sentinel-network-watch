"""Autonomous local hub. Observations and review intent never enforce traffic policy."""
from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import threading
import time
import uuid

from .review import ReviewQueue, ReviewError, validate_path

DEFAULT_CONFIG = Path('/etc/sentinel-hub/config.json')
DEFAULT_STATE = Path('/var/lib/sentinel-hub')
MAX_FILE = 4 * 1024 * 1024
MAX_DB = 200 * 1024 * 1024
OWN_OBSERVATION_WINDOW = 10000
PENDING_RECOVERY_LIMIT = 128
UNKNOWN_GROUPING_NOTE = 'unattributed observations; may contain different processes; not proven one application/session'


class HubError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def private_dir(path):
    path = Path(os.path.abspath(path))
    for p in (*reversed(path.parents), path):
        if p.exists() or p.is_symlink():
            m = p.lstat()
            if stat.S_ISLNK(m.st_mode) or getattr(m, 'st_file_attributes', 0) & 0x400:
                raise HubError('E_PRIVATE_PATH')
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    m = path.stat()
    if not stat.S_ISDIR(m.st_mode) or (os.name == 'posix' and
            (m.st_uid != os.geteuid() or m.st_mode & 0o077)):
        raise HubError('E_PRIVATE_DIRECTORY')
    return path


def read_private(path, max_bytes=MAX_FILE):
    path = validate_path(Path(path), must_exist=True)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as f:
        meta = os.fstat(f.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > max_bytes:
            raise HubError('E_PRIVATE_FILE')
        if os.name == 'posix' and (meta.st_uid != os.geteuid() or meta.st_mode & 0o077):
            raise HubError('E_PRIVATE_FILE')
        raw = f.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise HubError('E_FILE_LIMIT')
    return json.loads(raw)


def write_private(path, value, *, exclusive=False):
    path = Path(path)
    private_dir(path.parent)
    if path.exists() or path.is_symlink():
        validate_path(path, must_exist=True)
    target = path if exclusive else path.with_name(uuid.uuid4().hex + '.tmp')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(canonical(value) + '\n'); f.flush(); os.fsync(f.fileno())
        if not exclusive:
            os.replace(target, path)
        if os.name == 'posix':
            d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(d)
            finally: os.close(d)
    finally:
        if not exclusive and target.exists():
            target.unlink()


def host_fingerprint():
    """A local binding hint, never authentication of a remote device."""
    value = Path('/etc/machine-id').read_text().strip()
    if not re.fullmatch(r'[0-9a-f]{32}', value) or set(value) == {'0'}:
        raise HubError('E_HOST_BINDING')
    return digest(['sentinel-linux-host/v1', value])


def gateway_context():
    """Read local routing/ARP metadata only. No discovery, DNS or probing."""
    gateways = []
    for line in Path('/proc/net/route').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[1] == '00000000' and int(fields[3], 16) & 2:
            gateways.append((int(fields[6]), fields[0], socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])))
    if not gateways:
        return {'fingerprint': None, 'gateway': None, 'mac_known': False}
    _, interface, gateway = sorted(gateways)[0]
    mac = None
    for line in Path('/proc/net/arp').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 6 and fields[0] == gateway and fields[5] == interface and int(fields[2], 16) & 2:
            if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', fields[3].lower()):
                mac = fields[3].lower()
    return {'fingerprint': digest(['sentinel-network-hint/v1', gateway, mac]) if mac else None,
            'gateway': gateway, 'mac_known': mac is not None}


def load_config(path):
    c = read_private(path, 16384)
    required = {'schema_version', 'state_dir', 'network_id', 'network_label', 'actor_key',
                'expected_host_fingerprint', 'expected_gateway_fingerprint'}
    allowed = required | {'collection_interval_seconds', 'linux_enabled', 'router_state_dir',
                          'router_expected_gateway', 'alerts_config_path', 'auth_path', 'port'}
    if not isinstance(c, dict) or not required <= c.keys() or set(c) - allowed:
        raise HubError('E_HUB_CONFIG')
    try:
        if c['schema_version'] != 1 or uuid.UUID(c['network_id']).int == 0:
            raise ValueError
        if not all(isinstance(c[k], str) and 1 <= len(c[k]) <= 128 and
                   not any(ord(x) < 32 for x in c[k]) for k in ('actor_key', 'network_label')):
            raise ValueError
        for k in ('expected_host_fingerprint', 'expected_gateway_fingerprint'):
            if not re.fullmatch(r'[0-9a-f]{64}', c[k]): raise ValueError
        if not Path(c['state_dir']).is_absolute(): raise ValueError
        if type(c.get('port', 8765)) is not int or c.get('port', 8765) != 8765: raise ValueError
        if type(c.get('linux_enabled', True)) is not bool: raise ValueError
        interval = c.get('collection_interval_seconds', 60)
        if type(interval) is not int or not 30 <= interval <= 3600: raise ValueError
        for k in ('router_state_dir', 'alerts_config_path', 'auth_path'):
            if c.get(k) is not None and not Path(c[k]).is_absolute(): raise ValueError
        if c.get('router_expected_gateway') is not None:
            ipaddress.ip_address(c['router_expected_gateway'])
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HubError('E_HUB_CONFIG') from None
    return c


class Hub:
    def __init__(self, config_path=DEFAULT_CONFIG, *, clock=time.time,
                 host_provider=host_fingerprint, network_provider=gateway_context,
                 linux_provider=None, alert_factory=None):
        self.config_path = Path(config_path)
        self.config = load_config(config_path)
        self.clock, self.host_provider, self.network_provider = clock, host_provider, network_provider
        self.linux_provider, self.alert_factory = linux_provider, alert_factory
        self.lock = threading.RLock()
        self.state = private_dir(self.config['state_dir'])
        self.profiles_path = self.state / 'networks.json'
        if not self.profiles_path.exists():
            initial = {'network_id': self.config['network_id'], 'label': self.config['network_label'],
                       'gateway_fingerprint': self.config['expected_gateway_fingerprint'],
                       'router_enabled': bool(self.config.get('router_state_dir'))}
            write_private(self.profiles_path, {'active': initial['network_id'], 'profiles': [initial]}, exclusive=True)
        self._profiles()
        with self._queue() as q:
            pass

    def _profiles(self):
        value = read_private(self.profiles_path, 65536)
        if not isinstance(value, dict) or not isinstance(value.get('profiles'), list) or not 1 <= len(value['profiles']) <= 100:
            raise HubError('E_NETWORK_PROFILES')
        seen = set()
        for p in value['profiles']:
            try:
                if set(p) != {'network_id', 'label', 'gateway_fingerprint', 'router_enabled'}: raise ValueError
                if uuid.UUID(p['network_id']).int == 0 or p['network_id'] in seen: raise ValueError
                if not isinstance(p['label'], str) or not 1 <= len(p['label']) <= 128: raise ValueError
                if not re.fullmatch(r'[0-9a-f]{64}', p['gateway_fingerprint']): raise ValueError
                if type(p['router_enabled']) is not bool: raise ValueError
                seen.add(p['network_id'])
            except (KeyError, ValueError, TypeError):
                raise HubError('E_NETWORK_PROFILES') from None
        if value.get('active') not in seen: raise HubError('E_NETWORK_PROFILES')
        return value

    def _profile(self):
        p = self._profiles()
        return next(x for x in p['profiles'] if x['network_id'] == p['active'])

    def _folder(self):
        return private_dir(self.state / 'networks' / self._profile()['network_id'])

    def _queue(self):
        path = self._folder() / 'review.sqlite3'
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
        if os.name == 'posix' and (path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077):
            raise HubError('E_DATABASE_PERMISSIONS')
        q = ReviewQueue(path, clock=self.clock, max_db_bytes=MAX_DB)
        try:
            self._schema(q)
        except BaseException:
            q.close()
            raise
        return q

    @staticmethod
    @contextlib.contextmanager
    def _mutation(q):
        """All hub ledger changes share the review queue's fail-closed byte cap."""
        with q.db:
            if not q.db.in_transaction:
                q.db.execute('BEGIN IMMEDIATE')
            yield
            q._check_capacity()

    @staticmethod
    def _schema(q):
        statements = '''
          CREATE TABLE IF NOT EXISTS hub_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS hub_recognitions(actor TEXT,app TEXT,created REAL,details TEXT,
            PRIMARY KEY(actor,app));
          CREATE TABLE IF NOT EXISTS hub_audit(id INTEGER PRIMARY KEY,created REAL,kind TEXT,details TEXT);
          CREATE TABLE IF NOT EXISTS hub_notices(id TEXT PRIMARY KEY,category TEXT,created REAL,handed INTEGER DEFAULT 0);
          CREATE TABLE IF NOT EXISTS hub_flagged(fingerprint TEXT PRIMARY KEY,created REAL);
          CREATE TABLE IF NOT EXISTS hub_cycles(id INTEGER PRIMARY KEY,created REAL,details TEXT);
          CREATE TABLE IF NOT EXISTS hub_observation_ids(id INTEGER PRIMARY KEY AUTOINCREMENT,
            observation_id TEXT UNIQUE NOT NULL,record_json TEXT,router_kind TEXT,
            router_record_hash TEXT,router_last_poll_id TEXT,eligible INTEGER NOT NULL DEFAULT 1);
          CREATE TABLE IF NOT EXISTS hub_router_watermarks(kind TEXT,record_hash TEXT,last_poll_id TEXT NOT NULL,
            PRIMARY KEY(kind,record_hash));
        '''
        with Hub._mutation(q):
            for statement in statements.split(';'):
                if statement.strip():
                    q.db.execute(statement)

    def _context(self):
        p = self._profile()
        current = self.network_provider()
        host_ok = self.host_provider() == self.config['expected_host_fingerprint']
        match = host_ok and current.get('fingerprint') == p['gateway_fingerprint']
        return {'network_id': p['network_id'], 'label': p['label'], 'context_matches': match,
                'reason': None if match else 'E_HOST_BINDING' if not host_ok else 'E_NETWORK_REVIEW_REQUIRED',
                'current_gateway_hint': current.get('gateway'), 'hints_are_authentication': False}

    @staticmethod
    def _identity_complete(row):
        e = row['evidence']
        if row.get('app_context_key','').startswith('unattributed-linux-endpoint:'): return False
        if e.get('endpoint_complete') is False: return False
        if 'signature_status' in e and e['signature_status'] != 'Valid': return False
        if row['kind'] == 'router_record': return False
        if e.get('app_identity_complete') is not None:
            return e['app_identity_complete'] is True
        return (e.get('process_identity_correlated') is True and
                isinstance(e.get('binary_sha256'), str) and
                bool(re.fullmatch(r'[0-9a-f]{64}', e['binary_sha256'])))

    def _rows(self, q):
        known = {(r[0], r[1]) for r in q.db.execute('SELECT actor,app FROM hub_recognitions')}
        rows = q.export_records()
        network_id = self._profile()['network_id']
        for r in rows:
            r['application_recognized'] = (r['actor_key'], r['app_context_key']) in known and self._identity_complete(r)
            r['approval_available'] = self._identity_complete(r) and r['transport'] != 'unknown' and r['destination_address'] is not None
            if r['status'] in ('pending','approved') and not r['approval_available']:
                r['effective_approval_suspended'] = r['status'] == 'approved'
                r['status'] = 'pending_more_evidence'
                if r['decision'] is not None:
                    r['decision']['active'] = False
                    r['decision']['identity_evidence_incomplete'] = True
            r['recently_observed'] = 0 <= self.clock() - r['last_seen'] <= max(180, 3 * self.config.get('collection_interval_seconds', 60))
            r['network_id'] = network_id
        return rows

    def relationships(self, limit=200, offset=0, status=None):
        if type(limit) is not int or not 1 <= limit <= 50000 or type(offset) is not int or offset < 0:
            raise HubError('E_PAGINATION')
        with self.lock, self._queue() as q:
            rows = self._rows(q)
            if status is not None:
                if status not in ('pending','pending_more_evidence','approved','not_approved'): raise HubError('E_STATUS')
                rows = [r for r in rows if r['status'] == status]
            return rows[offset:offset+limit]

    def _last(self, q):
        r = q.db.execute("SELECT value FROM hub_metadata WHERE key='last_cycle'").fetchone()
        return json.loads(r[0]) if r else None

    def existing_services(self):
        """Read a bounded legacy status summary, never its configuration or topic."""
        path = Path('/var/lib/sentinel-alerts/status.json')
        try:
            if not path.exists(): return {}
            value = read_private(path,65536)
            checked = value.get('checked_at')
            if type(checked) not in (int,float) or not math.isfinite(checked): raise ValueError
            age = self.clock()-checked
            checks = {k:v for k,v in value.get('checks',{}).items()
                      if isinstance(k,str) and re.fullmatch(r'[a-z][a-z0-9_]{0,39}',k) and type(v) is bool}
            health = value.get('health_state')
            delivery = value.get('delivery_state')
            return {'alerts_and_adguard':{'available':True,'fresh':-30<=age<=180,
                    'age_seconds':max(0,age), 'checks':checks,
                    'health_state':health if health in ('healthy','down','unhealthy','unknown') else 'unknown',
                    'delivery_state':delivery if delivery in ('verified','pending','blocked','not_yet_tested','degraded') else 'unknown'}}
        except Exception:
            return {'alerts_and_adguard':{'available':False,'fresh':False,'error':'E_SERVICE_STATUS'}}

    def overview(self):
        with self.lock, self._queue() as q:
            last = self._last(q)
            runtime_error = self._worker_error(last)
            age = None if last is None else max(0, self.clock() - last['checked_at'])
            stale = last is None or age > max(180, 3 * self.config.get('collection_interval_seconds',60))
            counts = {k:0 for k in ('pending','pending_more_evidence','approved','not_approved')}
            for r in self._rows(q): counts[r['status']] += 1
            return {'ok': bool(last and last.get('ok') and not stale and runtime_error is None and self._context()['context_matches']),
                    'checked_at': self.clock(), 'network': self._context(), 'profiles': self._profiles()['profiles'],
                    'queue': {'relationships':sum(counts.values()),'counts':counts,'blocking_action':False}, 'last_collection': last, 'collection_age_seconds': age,
                    'existing_services': self.existing_services(),
                    'collection_stale': stale, 'autonomous': True, 'blocking_enabled': False,
                    'worker_error':runtime_error,
                    'complete_network_visibility': False,
                    'pending_notification_handoffs': q.db.execute('SELECT COUNT(*) FROM hub_notices WHERE handed=0').fetchone()[0],
                    'application_recognition_count': q.db.execute('SELECT COUNT(*) FROM hub_recognitions').fetchone()[0],
                    'observation_retention':self._retention_status(q),
                    'coverage_limits': ['Linux current network namespace TCP snapshots only; short-lived and UDP flows can be missed.',
                       'Router retained rows lack transport, event time, byte counts and application identity.',
                       'No all-household packet sensor, automatic blocking or encrypted-content authorization analysis.',
                       'An external observer is needed to detect total hub or Internet outage.']}

    def _worker_error(self, last):
        path = self.state/'worker-error.json'
        if not path.exists() and not path.is_symlink():
            return None
        try:
            error = read_private(path, 1024)
            checked = error.get('checked_at') if isinstance(error,dict) else None
            if (error.get('ok') is not False or error.get('code') != 'E_HUB_CYCLE'
                    or isinstance(checked,bool) or not isinstance(checked,(int,float))
                    or not math.isfinite(checked)):
                raise HubError('E_WORKER_STATUS')
            if last is None or checked >= last['checked_at']:
                return {'ok':False,'code':'E_HUB_CYCLE','checked_at':checked}
            return None
        except Exception:
            return {'ok':False,'code':'E_WORKER_STATUS'}

    def report(self):
        with self.lock, self._queue() as q:
            rows = self._rows(q)
            result = {'schema_version': 1, 'generated_at': self.clock(), 'overview': self.overview(),
                    'relationships': rows[:200], 'total_relationships':len(rows),
                    'relationships_in_report':min(200,len(rows)), 'report_truncated':len(rows)>200,
                    'full_queue_available_in_pages':True,
                    'recent_cycles': [json.loads(r[0]) for r in q.db.execute('SELECT details FROM hub_cycles ORDER BY id DESC LIMIT 20')],
                    'decision_audit': [dict(r) for r in q.db.execute('SELECT * FROM decisions ORDER BY id DESC LIMIT 200')],
                    'counts_are': 'observations and review items; not sessions, packets or byte volumes'}
            # Fit the authenticated web transport's limit without claiming a complete export.
            while len(canonical(result).encode()) > 3*1024*1024:
                if result['recent_cycles']: result['recent_cycles'].pop()
                elif result['relationships']: result['relationships'].pop()
                elif result['decision_audit']: result['decision_audit'].pop()
                else: raise HubError('E_REPORT_LIMIT')
                result['report_truncated']=True
            result['relationships_in_report']=len(result['relationships'])
            return result

    def decide(self, review_id, decision, duration_seconds=None, until_revoked=False, *, expected_relationship_key=None):
        with self.lock, self._queue() as q:
            if not self._context()['context_matches']: raise HubError('E_NETWORK_REVIEW_REQUIRED')
            row = q.read(review_id)
            if expected_relationship_key != row['relationship_key']: raise HubError('E_STALE_REVIEW')
            if decision == 'approve' and not self._identity_complete(row): raise HubError('E_APPLICATION_EVIDENCE_REQUIRED')
            if decision not in ('approve','reject','revoke'):
                raise ReviewError('E_EXPLICIT_ENDPOINT_DECISION_REQUIRED')
            if decision != 'revoke':
                if type(until_revoked) is not bool:
                    raise ReviewError('E_EXPIRY_REQUIRED')
                if until_revoked:
                    if duration_seconds is not None: raise ReviewError('E_EXPIRY_CONFLICT')
                elif type(duration_seconds) is not int or not 1 <= duration_seconds <= 86400:
                    raise ReviewError('E_EXPIRY_REQUIRED')
                if decision == 'approve' and (row['destination_address'] is None or row['transport']=='unknown'):
                    raise ReviewError('E_INCOMPLETE_ENDPOINT')
            now = self.clock()
            if isinstance(now,bool) or not isinstance(now,(int,float)) or not math.isfinite(now):
                raise ReviewError('E_CLOCK')
            expires = now if decision=='revoke' else None if until_revoked else now+duration_seconds
            with self._mutation(q):
                q.db.execute("INSERT INTO decisions(relationship_id,relationship_key,decision,scope,decided_at,expires_at,until_revoked) VALUES(?,?,?,'endpoint',?,?,?)",
                             (q._id(review_id),row['relationship_key'],decision,now,expires,int(until_revoked) if decision!='revoke' else 0))
                result = q.read(review_id)
                q.db.execute('INSERT INTO hub_audit(created,kind,details) VALUES(?,?,?)',
                             (now, 'decision', canonical({'review_id':review_id,'decision':result['decision']})))
            return result

    def recognize(self, review_id, *, expected_app_context_key=None):
        with self.lock, self._queue() as q:
            if not self._context()['context_matches']: raise HubError('E_NETWORK_REVIEW_REQUIRED')
            r = q.read(review_id)
            if r['app_context_key'] != expected_app_context_key: raise HubError('E_STALE_REVIEW')
            if not self._identity_complete(r): raise HubError('E_APPLICATION_EVIDENCE_REQUIRED')
            details = {'review_id':review_id, 'actor_key':r['actor_key'], 'app_context_key':r['app_context_key'],
                       'binary_sha256':r['evidence'].get('binary_sha256',r['evidence'].get('executable_sha256')), 'endpoint_permission_granted':False}
            with self._mutation(q):
                q.db.execute('INSERT OR IGNORE INTO hub_recognitions VALUES(?,?,?,?)',
                             (r['actor_key'],r['app_context_key'],self.clock(),canonical(details)))
            return {'ok':True,'endpoint_permission_granted':False,'new_endpoints_require_review':True}

    def onboard_network(self, label):
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 128 or any(ord(c)<32 for c in label):
            raise HubError('E_NETWORK_LABEL')
        with self.lock:
            if self.host_provider() != self.config['expected_host_fingerprint']: raise HubError('E_HOST_BINDING')
            current = self.network_provider()
            if not current.get('fingerprint'): raise HubError('E_NETWORK_HINT_UNAVAILABLE')
            profiles = self._profiles()
            if len(profiles['profiles']) >= 100: raise HubError('E_NETWORK_PROFILE_CAP')
            if any(p['gateway_fingerprint'] == current['fingerprint'] for p in profiles['profiles']):
                raise HubError('E_SELECT_EXISTING_NETWORK')
            p = {'network_id':str(uuid.uuid4()),'label':label.strip(), 'gateway_fingerprint':current['fingerprint'], 'router_enabled':False}
            profiles['profiles'].append(p); profiles['active'] = p['network_id']
            write_private(self.profiles_path, profiles)
            with self._queue() as q: pass
            return {'ok':True, 'network':self._context(), 'old_approvals_inherited':False,'router_feed_enabled':False}

    def activate_network(self, network_id):
        with self.lock:
            if self.host_provider() != self.config['expected_host_fingerprint']: raise HubError('E_HOST_BINDING')
            profiles = self._profiles()
            p = next((p for p in profiles['profiles'] if p['network_id'] == network_id),None)
            if p is None or p['gateway_fingerprint'] != self.network_provider().get('fingerprint'):
                raise HubError('E_NETWORK_CONTEXT_MISMATCH')
            profiles['active'] = network_id
            write_private(self.profiles_path, profiles)
            return {'ok':True,'network':self._context(),'network_settings_changed':False}

    def _router_records(self):
        if self.config.get('router_expected_gateway') != self.network_provider().get('gateway'):
            raise HubError('E_ROUTER_GATEWAY_MISMATCH')
        source = Path(self.config['router_state_dir'])
        status = read_private(source / 'status.json', 65536)
        age = self.clock() - status.get('checked_at', 0)
        if not -30 <= age <= 180 or status.get('collection_ok') is not True:
            raise HubError('E_ROUTER_STALE_OR_GAP')
        path = validate_path(source / 'observations.sqlite3', must_exist=True)
        conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('PRAGMA query_only=ON')
            rows = conn.execute("SELECT kind,record_hash,raw_json,first_seen,last_seen,poll_sightings,last_poll_id FROM observations WHERE kind IN ('outgoing','incoming') ORDER BY kind,record_hash LIMIT 50001").fetchall()
        finally: conn.close()
        if len(rows) > 50000: raise HubError('E_ROUTER_ROW_CAP')
        result = []
        for row in rows:
            raw = json.loads(row['raw_json'])
            source_ip = str(ipaddress.ip_address(raw['source']))
            port = raw['destinationPort']
            address = str(ipaddress.ip_address(raw['destination'])) if row['kind']=='outgoing' else None
            key = {'actor_key':'network:'+self._profile()['network_id']+'/router-source:'+source_ip,
                   'app_context_key':'router:'+row['kind']+':application-unreported',
                   'kind':'router_record','transport':'unknown','destination_address':address,'destination_port':port}
            result.append({**key,'observed_at':row['last_seen'],
                           'observation_id':'router:'+row['kind']+':'+row['record_hash']+':'+str(row['last_poll_id']),
                           'evidence':{'source':'router retained observation','source_address':source_ip,
                                        'router_kind':row['kind'],'router_record_hash':row['record_hash'],
                                        'router_last_poll_id':str(row['last_poll_id']),
                                       'application_name':'unreported','app_identity_complete':False,
                                       'direction':'vendor '+row['kind']+' label; initiation/outcome not proven',
                                       'source_poll_sightings':row['poll_sightings'],'router_event_time_available':False}})
        return result, {'collection_ok':True,'retained_rows':len(rows),'complete_stream_visibility':False,
                        'ingestion_scope':'retained_history_not_current_sessions',
                        'rows_recently_seen':sum(0 <= self.clock()-r['last_seen'] <= 180 for r in rows),
                        'last_collected_at':status['checked_at'],'limitations':status.get('limitations',[])}

    def _engine(self, checks):
        if self.alert_factory is not None: return self.alert_factory(checks)
        if not self.config.get('alerts_config_path'): return None
        from .alerts import AlertEngine, load_config, service_checks
        checks = {**checks, **service_checks(state_dir=self.state)}
        return AlertEngine(self.state/'alerts',load_config(Path(self.config['alerts_config_path'])),
                           check_provider=lambda:checks, clock=self.clock)

    def import_case(self, source_database, *, expected_sha256, recognition=None):
        """One-time local migration into an empty profile; preserve IDs, evidence and fixed expiries.

        No HTTP route exposes this operation. Caller preserves the original project
        and supplies its already verified, closed database snapshot.
        """
        from .alerts import _FileLock
        # The daemon owns this lock for its entire lifetime. Never replace a
        # database inode that a running collector or dashboard might hold open.
        with self.lock, _FileLock(self.state/'daemon.lock'):
            return self._import_case(source_database, expected_sha256=expected_sha256, recognition=recognition)

    @staticmethod
    def _import_hash(path):
        path = validate_path(path, must_exist=True)
        for suffix in ('-journal','-wal','-shm'):
            sidecar = Path(str(path)+suffix)
            if sidecar.exists() or sidecar.is_symlink():
                raise HubError('E_IMPORT_SOURCE_NOT_CLOSED')
        fd = os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise HubError('E_IMPORT_SOURCE')
            if info.st_size > MAX_DB:
                raise HubError('E_IMPORT_CAP')
            value = hashlib.sha256()
            size = 0
            while True:
                chunk = f.read(1024*1024)
                if not chunk: break
                size += len(chunk)
                if size > MAX_DB: raise HubError('E_IMPORT_CAP')
                value.update(chunk)
            return value.hexdigest()

    def _import_case(self, source_database, *, expected_sha256, recognition=None):
        source = validate_path(Path(source_database), must_exist=True)
        if not isinstance(expected_sha256,str) or not re.fullmatch(r'[0-9a-f]{64}',expected_sha256):
            raise HubError('E_IMPORT_HASH')
        if self._import_hash(source) != expected_sha256:
            raise HubError('E_IMPORT_HASH')
        if recognition is not None:
            try:
                import datetime
                if (not isinstance(recognition,dict) or recognition.get('endpoint_permission_granted') is not False
                        or not isinstance(recognition.get('binary_sha256'),str)
                        or not re.fullmatch(r'[0-9a-f]{64}',recognition['binary_sha256'])
                        or len(canonical(recognition).encode())>16384):
                    raise ValueError
                parsed = datetime.datetime.fromisoformat(recognition['recognized_at_utc'])
                created = parsed.timestamp()
                if parsed.tzinfo is None or not math.isfinite(created): raise ValueError
                if not all(isinstance(recognition[k],str) and 1<=len(recognition[k])<=512
                           for k in ('actor_key','app_context_key')): raise ValueError
            except (KeyError,ValueError,TypeError,OverflowError):
                raise HubError('E_RECOGNITION_IMPORT') from None
        with self._queue() as q:
            if q.db.execute('SELECT COUNT(*) FROM relationships').fetchone()[0] or self._last(q):
                raise HubError('E_IMPORT_TARGET_NOT_EMPTY')
            target = q.path
        staged = target.with_name(uuid.uuid4().hex+'.import')
        try:
            conn = sqlite3.connect(source.as_uri()+'?mode=ro', uri=True, timeout=3)
            try:
                conn.execute('PRAGMA query_only=ON')
                if conn.execute('PRAGMA quick_check').fetchone()[0]!='ok': raise HubError('E_IMPORT_INTEGRITY')
                if conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]:
                    raise HubError('E_IMPORT_SCHEMA')
                if conn.execute('SELECT COUNT(*) FROM relationships').fetchone()[0]>50000: raise HubError('E_IMPORT_CAP')
                fd=os.open(staged,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd)
                out=sqlite3.connect(staged)
                try: conn.backup(out)
                finally: out.close()
            finally: conn.close()
            if self._import_hash(source) != expected_sha256:
                raise HubError('E_IMPORT_SOURCE_CHANGED')
            # Complete and validate the staged database, including recognition
            # and its audit, before publishing any imported rows or decisions.
            with ReviewQueue(staged,clock=self.clock,max_db_bytes=MAX_DB) as q:
                self._schema(q)
                if q.db.execute('PRAGMA foreign_key_check').fetchone() is not None:
                    raise HubError('E_IMPORT_INTEGRITY')
                with self._mutation(q):
                    # Imported IDs are historical evidence, even if their source
                    # was another hub. Never treat them as this collector's
                    # disposable replay metadata or resume its runtime spool.
                    q.db.execute('UPDATE hub_observation_ids SET eligible=0')
                    q.db.execute('DELETE FROM hub_router_watermarks')
                    if recognition is not None:
                        rows=q.db.execute('SELECT kind,evidence_json FROM relationships WHERE actor_key=? AND app_context_key=?',
                                          (recognition['actor_key'],recognition['app_context_key'])).fetchall()
                        valid = False
                        for row in rows:
                            evidence=json.loads(row['evidence_json'])
                            actual=evidence.get('binary_sha256',evidence.get('executable_sha256'))
                            if actual==recognition['binary_sha256'] and self._identity_complete({'kind':row['kind'],'evidence':evidence}):
                                valid=True
                        if not valid: raise HubError('E_RECOGNITION_IMPORT')
                        q.db.execute('INSERT INTO hub_recognitions VALUES(?,?,?,?)',
                                     (recognition['actor_key'],recognition['app_context_key'],created,canonical(recognition)))
                    q.db.execute('INSERT INTO hub_audit(created,kind,details) VALUES(?,?,?)',
                                 (self.clock(),'historical_import',canonical({'source_sha256':expected_sha256,'expiry_renewed':False,'source_actor_rebound':False})))
                result = {'ok':True,'imported_relationships':q.status()['relationships'],
                          'decisions':q.db.execute('SELECT COUNT(*) FROM decisions').fetchone()[0],
                          'fixed_expiries_preserved':True,'origin_identities_preserved':True}
            fd=os.open(staged,os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
            try: os.fsync(fd)
            finally: os.close(fd)
            os.replace(staged,target)
            if os.name=='posix':
                fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
                try: os.fsync(fd)
                finally: os.close(fd)
            return result
        finally:
            if staged.exists():
                staged.unlink()

    def test_alert(self):
        with self.lock:
            engine = self._engine({'hub_collection':bool(self.overview()['ok'])})
            if engine is None: raise HubError('E_ALERTS_NOT_CONFIGURED')
            event_id = engine.enqueue_test()
            return {'ok':True,'test_queued':True,'event_id':event_id,
                    'human_receipt_confirmed':False,'will_send_on_background_tick':True}

    def create_backup(self, passphrase):
        from .hub_backup import create_hub_backup
        return create_hub_backup(self, passphrase)

    def backup_download(self, backup_id):
        from .hub_backup import backup_path
        with self.lock:
            return backup_path(self, backup_id)

    @staticmethod
    def _bucket_linux(record):
        evidence = record.get('evidence',{})
        if (evidence.get('source')!='linux_proc_tcp_snapshot'
                or evidence.get('app_identity_complete') is not False
                or not record.get('app_context_key','').startswith('linux-unattributed-v1:')):
            return record
        result = dict(record)
        evidence = dict(evidence)
        evidence.update(capture_app_context_key=record['app_context_key'],
                        grouping_note=UNKNOWN_GROUPING_NOTE, identity_scope='unattributed_endpoint_bucket',
                        application_name='Unattributed Linux observations',app_identity_complete=False)
        # This key identifies an observation bucket, never a process identity.
        result['app_context_key']='unattributed-linux-endpoint:'+digest([
            record['actor_key'],record['kind'],record['transport'],record['destination_address'],
            record['destination_port'],evidence.get('local_address'),evidence.get('local_port'),
            evidence.get('socket_uid')])
        result['evidence']=evidence
        return result

    @staticmethod
    def _watermark(record):
        e=record['evidence']
        if (e.get('router_kind') not in ('incoming','outgoing')
                or not isinstance(e.get('router_record_hash'),str)
                or not re.fullmatch(r'[0-9a-f]{64}',e['router_record_hash'])
                or not isinstance(e.get('router_last_poll_id'),str)
                or not 1<=len(e['router_last_poll_id'])<=128
                or any(ord(c)<32 for c in e['router_last_poll_id'])):
            raise HubError('E_ROUTER_WATERMARK_SCHEMA')
        return (e['router_kind'],e['router_record_hash'],e['router_last_poll_id'])

    def _ack_observation(self,q,observation_id,watermark):
        with self._mutation(q):
            if watermark is not None:
                q.db.execute('INSERT INTO hub_router_watermarks VALUES(?,?,?) ON CONFLICT(kind,record_hash) DO UPDATE SET last_poll_id=excluded.last_poll_id',watermark)
            q.db.execute('UPDATE hub_observation_ids SET record_json=NULL WHERE observation_id=? AND eligible=1',(observation_id,))

    def _ingest_generated(self,q,record,source):
        watermark=self._watermark(record) if source=='router' else None
        if watermark is not None:
            previous=q.db.execute('SELECT last_poll_id FROM hub_router_watermarks WHERE kind=? AND record_hash=?',watermark[:2]).fetchone()
            if previous and previous[0]==watermark[2]:
                return {'hub_skipped_unchanged':True,'new_sighting':False}
        original_id=record.get('observation_id')
        if not isinstance(original_id,str) or not original_id.startswith(source+':'):
            # Fixture/manual producer IDs are neither claimed nor compacted.
            return q.ingest(record)
        prepared=dict(record)
        observation_id=source+':hub-v1:'+digest([self._profile()['network_id'],original_id])
        prepared['observation_id']=observation_id
        encoded=canonical(prepared)
        if len(encoded.encode())>16384: raise HubError('E_GENERATED_RECORD_CAP')
        owned=q.db.execute('SELECT record_json,eligible FROM hub_observation_ids WHERE observation_id=?',(observation_id,)).fetchone()
        if owned and owned['eligible'] and owned['record_json'] is not None and owned['record_json']!=encoded:
            raise HubError('E_OBSERVATION_ID_CONFLICT')
        if owned is None and q.db.execute('SELECT 1 FROM observations WHERE observation_id=?',(observation_id,)).fetchone() is None:
            # Reserve provenance and replayable input before the core's own
            # committing ingest. A crash can then replay exactly this input.
            with self._mutation(q):
                q.db.execute('INSERT INTO hub_observation_ids(observation_id,record_json,router_kind,router_record_hash,router_last_poll_id) VALUES(?,?,?,?,?)',
                             (observation_id,encoded,*(watermark or (None,None,None))))
        result=q.ingest(prepared)
        self._ack_observation(q,observation_id,watermark)
        return result

    def _recover_observations(self,q):
        pending=q.db.execute('SELECT observation_id,record_json,router_kind,router_record_hash,router_last_poll_id FROM hub_observation_ids WHERE eligible=1 AND record_json IS NOT NULL ORDER BY id LIMIT ?',
                             (PENDING_RECOVERY_LIMIT,)).fetchall()
        for row in pending:
            record=json.loads(row['record_json'])
            if record.get('observation_id')!=row['observation_id']:
                raise HubError('E_PENDING_OBSERVATION_STATE')
            q.ingest(record)
            watermark=(row['router_kind'],row['router_record_hash'],row['router_last_poll_id']) if row['router_kind'] is not None else None
            self._ack_observation(q,row['observation_id'],watermark)
        if q.db.execute('SELECT 1 FROM hub_observation_ids WHERE eligible=1 AND record_json IS NOT NULL LIMIT 1').fetchone():
            raise HubError('E_PENDING_OBSERVATION_BACKLOG')
        return len(pending)

    def _compact_observations(self,q):
        with self._mutation(q):
            if q.db.execute('SELECT 1 FROM hub_observation_ids WHERE eligible=1 AND record_json IS NOT NULL LIMIT 1').fetchone():
                raise HubError('E_PENDING_OBSERVATION_STATE')
            old=q.db.execute('SELECT observation_id FROM hub_observation_ids WHERE eligible=1 ORDER BY id DESC LIMIT -1 OFFSET ?',
                             (OWN_OBSERVATION_WINDOW,)).fetchall()
            for row in old:
                if not re.fullmatch(r'(?:linux|router):hub-v1:[0-9a-f]{64}',row[0]):
                    raise HubError('E_OWNED_OBSERVATION_STATE')
            q.db.executemany('DELETE FROM observations WHERE observation_id=?',[(r[0],) for r in old])
            q.db.executemany('DELETE FROM hub_observation_ids WHERE observation_id=? AND eligible=1',[(r[0],) for r in old])
            if old:
                previous=q.db.execute("SELECT value FROM hub_metadata WHERE key='own_observation_ids_compacted'").fetchone()
                count=int(previous[0]) if previous else 0
                q.db.execute("INSERT INTO hub_metadata VALUES('own_observation_ids_compacted',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(str(count+len(old)),))

    @staticmethod
    def _retention_status(q):
        counter=q.db.execute("SELECT value FROM hub_metadata WHERE key='own_observation_ids_compacted'").fetchone()
        return {'own_replay_id_limit':OWN_OBSERVATION_WINDOW,
                'own_replay_ids_retained':q.db.execute('SELECT COUNT(*) FROM hub_observation_ids WHERE eligible=1 AND record_json IS NULL').fetchone()[0],
                'pending_observation_records':q.db.execute('SELECT COUNT(*) FROM hub_observation_ids WHERE eligible=1 AND record_json IS NOT NULL').fetchone()[0],
                'own_replay_ids_compacted_total':int(counter[0]) if counter else 0,
                'router_watermarks':q.db.execute('SELECT COUNT(*) FROM hub_router_watermarks').fetchone()[0],
                'imported_observation_ids_compacted':False,
                'relationship_aggregates_and_decisions_preserved':True,
                'linux_replay_beyond_window_detectable':False}

    def tick(self):
        with self.lock, self._queue() as q:
            now = self.clock()
            result = {'checked_at':now,'ok':True,'gaps':[],'sources':{},'network_id':self._profile()['network_id'],
                      'automatic_blocking':False,'complete_network_visibility':False}
            context = self._context()
            if not context['context_matches']:
                result['gaps'].append({'source':'network','code':context['reason']})
            records = []
            intake_ready=True
            try:
                result['recovered_pending_observations']=self._recover_observations(q)
            except Exception:
                intake_ready=False
                result['gaps'].append({'source':'intake','code':'E_PENDING_OBSERVATION_RECOVERY'})
            if intake_ready and context['context_matches'] and self.config.get('linux_enabled',True):
                try:
                    provider = self.linux_provider
                    if provider is None:
                        from .linux import collect_linux_records
                        provider = collect_linux_records
                    capture = provider(actor_key='network:'+self._profile()['network_id']+'/'+self.config['actor_key'],observed_at=now)
                    records.extend(('linux',self._bucket_linux(r)) for r in capture['records']); result['sources']['linux'] = capture['coverage']
                    if capture['coverage'].get('ok') is False:
                        result['gaps'].append({'source':'linux','code':'E_LINUX_PARTIAL'})
                except Exception:
                    result['gaps'].append({'source':'linux','code':'E_LINUX_COLLECTION'})
            if intake_ready and context['context_matches'] and self._profile()['router_enabled']:
                try:
                    rr, coverage = self._router_records(); records.extend(('router',r) for r in rr); result['sources']['router'] = coverage
                except Exception:
                    result['gaps'].append({'source':'router','code':'E_ROUTER_STALE_OR_GAP'})
            elif not self._profile()['router_enabled']:
                result['sources']['router'] = {'configured':False,'complete_stream_visibility':False}
            ingested = skipped = 0
            for source,r in records:
                try:
                    observed=self._ingest_generated(q,r,source)
                    if observed.get('hub_skipped_unchanged'): skipped+=1
                    else: ingested+=1
                except Exception:
                    intake_ready=False
                    result['gaps'].append({'source':'intake','code':'E_INTAKE_OR_CAP'}); break
            if intake_ready:
                try: self._compact_observations(q)
                except Exception:
                    result['gaps'].append({'source':'retention','code':'E_OBSERVATION_COMPACTION'})
            result['observations_processed'] = ingested
            result['router_rows_skipped_unchanged']=skipped
            result['observation_retention']=self._retention_status(q)
            result['ok'] = not result['gaps']
            try:
                self._reconcile(q, result)
            except Exception:
                result['ok'] = False; result['gaps'].append({'source':'notices','code':'E_NOTICE_CAP_OR_STATE'})
            try:
                engine = self._engine({'hub_collection':result['ok']})
                if engine is None:
                    result['alerts'] = {'configured':False,'delivery_state':'not_configured'}
                    result['ok'] = False
                    result['gaps'].append({'source':'alerts','code':'E_ALERTS_NOT_CONFIGURED'})
                else:
                    try:
                        for n in q.db.execute('SELECT id,category FROM hub_notices WHERE handed=0 ORDER BY created,id LIMIT 32').fetchall():
                            engine.enqueue_hub_notice(n['id'],n['category'])
                            with self._mutation(q):
                                q.db.execute('UPDATE hub_notices SET handed=1 WHERE id=?',(n['id'],))
                    finally:
                        # Full queues and failed acknowledgements must still
                        # drain; pending source intent is retried next cycle.
                        result['alerts'] = engine.tick()
                    if not result['alerts'].get('ok') or result['alerts'].get('delivery_state') == 'blocked':
                        result['ok'] = False; result['gaps'].append({'source':'alerts','code':'E_ALERT_DELIVERY'})
            except Exception:
                result['ok'] = False; result['gaps'].append({'source':'alerts','code':'E_ALERT_HANDOFF'})
            # Keep a bounded operational journal; relationship/decision/flag evidence is never pruned here.
            with self._mutation(q):
                q.db.execute('INSERT INTO hub_cycles(created,details) VALUES(?,?)',(now,canonical(result)))
                q.db.execute('DELETE FROM hub_cycles WHERE id NOT IN (SELECT id FROM hub_cycles ORDER BY id DESC LIMIT 1000)')
                q.db.execute("INSERT INTO hub_metadata VALUES('last_cycle',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(canonical(result),))
            write_private(self._folder()/'status.json', result)
            return result

    def _reconcile(self, q, result):
        """Recover missing notices after a crash; no approval or notification intent is silently dropped."""
        collection_ok = not result['gaps']
        result['collection_ok_before_alerts'] = collection_ok
        with self._mutation(q):
            fresh = []
            for r in self._rows(q):
                if r['status'] in ('pending','pending_more_evidence','not_approved'):
                    token = digest([r['relationship_key'],r['status'],r['decision']])
                    if q.db.execute('SELECT 1 FROM hub_flagged WHERE fingerprint=?',(token,)).fetchone() is None:
                        fresh.append(token)
            row = q.db.execute("SELECT value FROM hub_metadata WHERE key='collection_health'").fetchone()
            old = json.loads(row[0]) if row else None
            if old is not None and type(old) is not bool:
                raise HubError('E_COLLECTION_HEALTH_STATE')
            transition = ('monitoring_gap' if not collection_ok and old is not False else
                          'monitoring_recovered' if collection_ok and old is False else None)
            pending=q.db.execute('SELECT COUNT(*) FROM hub_notices WHERE handed=0').fetchone()[0]
            if pending+bool(fresh)+bool(transition)>4096:
                raise HubError('E_NOTICE_CAP')
            if fresh:
                q.db.execute('INSERT INTO hub_notices(id,category,created) VALUES(?,?,?)',(uuid.uuid4().hex,'review_needed',self.clock()))
                q.db.executemany('INSERT OR IGNORE INTO hub_flagged VALUES(?,?)',[(x,self.clock()) for x in fresh])
            if transition:
                q.db.execute('INSERT INTO hub_notices(id,category,created) VALUES(?,?,?)',(uuid.uuid4().hex,transition,self.clock()))
            q.db.execute("INSERT INTO hub_metadata VALUES('collection_health',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(canonical(collection_ok),))

