"""Privileged, one-shot read-only collection for the unprivileged console.

The bounded snapshot and sanitized retained-history handoff are published. No commands, DNS lookups, router calls,
credentials, payloads, process arguments or environments are collected here.
Interface byte counters describe this host, never household or per-flow totals.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
import uuid
try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import grp
except ImportError:
    grp = None

from .linux import collect_linux_records

OUTPUT = Path('/var/lib/sentinel-console-feed/snapshot.json')
ROUTER_STATE = Path('/var/lib/sentinel-router')
MAX_JSON = 4 * 1024 * 1024
MAX_CONNECTIONS = 1000
MAX_DEVICES = 250
MAX_INTERFACES = 64
MAX_DB = 256 * 1024 * 1024
GROUP = 'sentinelconsole'
_IFACE = re.compile(r'[A-Za-z0-9_.:@-]{1,32}\Z')
_PORT_HINTS = {22: 'SSH remote administration', 53: 'DNS name lookup',
               80: 'HTTP web traffic', 443: 'HTTPS or other encrypted web traffic',
               853: 'encrypted DNS', 5223: 'push notification traffic'}


class FeedError(ValueError):
    pass


def _need(value, code):
    if not value:
        raise FeedError(code)


def _text(value, limit=96):
    if not isinstance(value, str):
        return ''
    return ''.join(c for c in value if 32 <= ord(c) < 127)[:limit]


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _reparse(meta):
    return bool(getattr(meta, 'st_file_attributes', 0) & 0x400)


def _file_identity(meta):
    common = (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns)
    # Windows can change archive metadata when SQLite opens immutable files.
    # Production is Linux and retains its full inode change-time guard.
    return common + ((meta.st_ctime_ns,) if os.name == 'posix' else ())


def _directory(path, uid=0, private=False):
    for part in reversed((Path(path), *Path(path).parents)):
        meta = part.lstat()
        _need(stat.S_ISDIR(meta.st_mode) and not _reparse(meta), 'E_DIRECTORY')
        if os.name == 'posix':
            _need(meta.st_uid in (0, uid) and not meta.st_mode & 0o022, 'E_DIRECTORY')
    if private and os.name == 'posix':
        _need(not Path(path).stat().st_mode & 0o077, 'E_PRIVATE_DIRECTORY')


def _read(path, limit, *, uid=0, private=False, check_parent=True):
    path = Path(path)
    if check_parent:
        _directory(path.parent, uid, private)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and not _reparse(before) and before.st_size <= limit, 'E_FILE')
        if os.name == 'posix':
            _need(before.st_uid == uid and not before.st_mode & (0o077 if private else 0o022), 'E_FILE')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        _need(len(raw) <= limit and _file_identity(before) == _file_identity(after), 'E_FILE_CHANGED')
        return raw
    finally:
        if fd is not None:
            os.close(fd)


def _kernel_number(path, *, uid=0):
    """Read only a known net attribute, bounding contents rather than sysfs size.

    Kernel interface directories are symlinks by design. The final attribute
    cannot be a link, and must remain a single owned non-writable regular file.
    Private/configuration readers retain their advertised-size checks above.
    """
    path = Path(path)
    _need(path.name == 'ifindex' or
          (path.parent.name == 'statistics' and path.name in ('rx_bytes', 'tx_bytes')), 'E_KERNEL_ATTRIBUTE')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and not _reparse(before), 'E_KERNEL_ATTRIBUTE')
        if os.name == 'posix':
            _need(before.st_uid == uid and not before.st_mode & 0o022, 'E_KERNEL_ATTRIBUTE')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(129)
            after = os.fstat(stream.fileno())
        _need(len(raw) <= 128 and (before.st_dev, before.st_ino, before.st_mode,
              before.st_nlink) == (after.st_dev, after.st_ino, after.st_mode, after.st_nlink), 'E_KERNEL_ATTRIBUTE')
        text = raw.decode('ascii').strip()
        _need(re.fullmatch(r'[0-9]{1,20}', text), 'E_COUNTER')
        value = int(text)
        _need(value < 2 ** 64, 'E_COUNTER')
        return value
    finally:
        if fd is not None:
            os.close(fd)


def address_scope(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return 'unknown'
    for name in ('unspecified', 'loopback', 'link_local', 'multicast'):
        if getattr(address, 'is_' + name):
            return name
    if address.is_global:
        return 'global'
    return 'private' if address.is_private else 'reserved'


def _address(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        # Router-reported DNS names are hints only; never resolve them or show URLs.
        text = _text(value, 253)
        return text if text and any(c.isalpha() for c in text) and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', text) else None


def _port(value):
    return value if type(value) is int and 0 <= value <= 65535 else None


def _flag(code, reason, next_step):
    return {'code': code, 'severity': 'REVIEW', 'reason': reason, 'next_step': next_step}


def _connection(source, state, direction, src, sport, dst, dport, app,
                observed, transport, flags, identity='', service=None):
    hint = _PORT_HINTS.get(dport, '')
    if hint:
        hint = 'Port hint: ' + hint + '; application purpose is not proven.'
    vendor = _text(service, 48).upper()
    if vendor in {'HTTP', 'HTTPS', 'DNS', 'SSH', 'SSL', 'TLS', 'NTP', 'QUIC', 'MDNS', 'SMB', 'SMTP', 'IMAP'}:
        hint = 'Router service label: ' + vendor + ' (unverified).'
    peer = (dst or 'unreported destination') + (':' + str(dport) if dport is not None else '')
    if state == 'listening':
        summary = app + ' has a TCP listening socket on ' + (src or 'an unreported address') + ':' + str(sport) + '.'
        basis = 'A listening socket does not establish external reachability or an incoming connection.'
    elif source == 'linux':
        summary = app + ' has an observed TCP peer at ' + peer + '.'
        basis = 'Local and peer endpoints were captured on this host; initiation and contents are unknown.'
    else:
        label = 'incoming' if direction == 'vendor_incoming' else 'outgoing'
        summary = 'The router retained an ' + label + '-labelled observation from ' + (src or 'an unreported source') + ' to ' + peer + '.'
        basis = 'This is retained router history, not a current session or proof of initiation or outcome.'
    first = flags[0] if flags else None
    return {'id': _digest([source, state, direction, src, sport, dst, dport, transport, identity]),
            'source': source, 'state': state, 'direction': direction,
            'direction_basis': basis, 'source_address': src, 'source_port': sport,
            'destination_address': dst, 'destination_port': dport,
            'source_scope': address_scope(src), 'destination_scope': address_scope(dst),
            'address_family': 6 if ':' in (src or dst or '') else 4 if address_scope(src or dst) != 'unknown' else None,
            'transport': transport, 'application': app, 'observed_at': observed,
            'time_basis': 'collector_last_seen' if source == 'router' else 'host_snapshot',
            'summary': summary, 'reason': (first['reason'] + ' ' if first else '') + basis,
            'next_step': first['next_step'] if first else 'Review the observed endpoint if it is unexpected; no blocking was performed.',
            'severity': 'REVIEW' if flags else 'INFO', 'flags': flags, 'service_hint': hint,
            'rx_bytes': None, 'tx_bytes': None, 'rx_bytes_per_second': None, 'tx_bytes_per_second': None}


def linux_connections(records, now, limit):
    result = []
    errors = 0
    for record in records[:limit]:
        try:
            evidence = record.get('evidence', {})
            listener = record.get('kind') == 'listener'
            _need(record.get('kind') in ('listener', 'native_tcp') and record.get('transport') == 'TCP', 'E_LINUX_ROW')
            src, sport = _address(evidence.get('local_address')), _port(evidence.get('local_port'))
            dst = None if listener else _address(record.get('destination_address'))
            dport = None if listener else _port(record.get('destination_port'))
            app = _text(evidence.get('executable_name') or evidence.get('application_name'))
            app = app.rsplit('/', 1)[-1].rsplit('\\', 1)[-1] or 'Unattributed'
            flags = []
            if evidence.get('app_identity_complete') is not True:
                flags.append(_flag('APP_UNATTRIBUTED', 'The process owning this socket was not safely attributed.',
                                   'Review attribution coverage; an unknown process is not proof of malicious activity.'))
            if listener and address_scope(src) not in ('loopback', 'unknown'):
                flags.append(_flag('LISTENER_NON_LOOPBACK', 'This listener is bound beyond loopback; reachability was not tested.',
                                   'Identify the application and intended listening scope before changing anything.'))
            if not listener and (dst is None or dport is None or evidence.get('endpoint_complete') is False):
                flags.append(_flag('ENDPOINT_INCOMPLETE', 'Some endpoint or IPv6 interface-scope evidence is incomplete.',
                                   'Collect the missing scope evidence before making an endpoint decision.'))
            observed = record.get('observed_at')
            result.append(_connection('linux', 'listening' if listener else 'current',
                          'listening' if listener else 'unknown', src, sport, dst, dport, app,
                          observed if _finite(observed) else now, 'TCP', flags,
                          _text(record.get('app_context_key'), 192)
                          if evidence.get('app_identity_complete') is True else 'unattributed'))
        except Exception:
            errors += 1
    return result, errors


def _router_connection(kind, raw, observed):
    _need(isinstance(raw, dict) and kind in ('incoming', 'outgoing'), 'E_ROUTER_ROW')
    src, port = _address(raw.get('source')), _port(raw.get('destinationPort'))
    dst = _address(raw.get('destination')) if kind == 'outgoing' else None
    _need(port is not None and _finite(observed), 'E_ROUTER_ROW')
    flags = []
    if kind == 'incoming':
        flags.append(_flag('RETAINED_INCOMING_LABEL', 'The router labelled this retained record incoming; acceptance and initiation are unproven.',
                           'Correlate it with the intended service and current device evidence before acting.'))
    if src is None or (kind == 'outgoing' and dst is None):
        flags.append(_flag('ENDPOINT_INCOMPLETE', 'The retained record does not provide a usable complete endpoint.',
                           'Review the source capability; do not infer a missing address or transport.'))
    return _connection('router', 'history', 'vendor_' + kind, src, None, dst, port,
                       'Unreported by router', observed, 'unknown', flags, service=raw.get('service'))


def _device(raw, key, first, last):
    _need(isinstance(raw, dict), 'E_DEVICE_ROW')
    model = raw.get('model') if isinstance(raw.get('model'), dict) else {}
    connections = raw.get('connections') if isinstance(raw.get('connections'), list) else []
    ips = sorted({_address(c.get(k)) for c in connections if isinstance(c, dict)
                  for k in ('ipAddress', 'ipv6Address') if _address(c.get(k))})[:16]
    macs = set()
    for value in (raw.get('knownMACAddresses') or [])[:32]:
        if isinstance(value, str) and re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', value):
            macs.add(value.lower())
    return {'id': _digest(['router-device', key]), 'name': _text(raw.get('friendlyName')) or 'Unlabelled device',
            'manufacturer': _text(model.get('manufacturer')), 'model': _text(model.get('modelNumber')),
            'addresses': ips, 'known_mac_addresses': sorted(macs),
            'first_observed_at': first if _finite(first) else None, 'observed_at': last if _finite(last) else None,
            'state': 'saved_inventory', 'online_verified': False, 'identity_approved': False,
            'reason': 'Saved router inventory can be stale; names, MAC history and IP matches do not prove current ownership or online status.'}


def router_snapshot(path=ROUTER_STATE, *, now=None, limit=500, uid=0):
    now = time.time() if now is None else now
    info = {'state': 'unavailable', 'checked_at': None, 'reason': 'Router retained history is unavailable.',
            'coverage': {'live_sessions': False, 'event_time_available': False, 'byte_counters': False,
                         'complete_stream_visibility': False}, 'errors': [], 'truncated': False}
    if path is None:
        info['reason'] = 'Router input is disabled.'
        return [], [], info
    lock = db = None
    rows, devices = [], []
    try:
        path = Path(path)
        _directory(path, uid, private=True)
        lock = os.open(path / 'run.lock', os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        meta = os.fstat(lock)
        _need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and not _reparse(meta), 'E_ROUTER_LOCK')
        if os.name == 'posix':
            _need(meta.st_uid == uid and not meta.st_mode & 0o077 and fcntl is not None, 'E_ROUTER_LOCK')
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError:
                raise FeedError('E_ROUTER_BUSY') from None
        status = json.loads(_read(path / 'status.json', 128 * 1024, uid=uid, private=True))
        database = path / 'observations.sqlite3'
        # Validate without reading the whole database. The application lock excludes
        # its writer; immutable SQLite prevents sidecar creation/recovery.
        fd = os.open(database, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        before = os.fstat(fd)
        os.close(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not _reparse(before)
              and before.st_size <= MAX_DB, 'E_ROUTER_DATABASE')
        if os.name == 'posix':
            _need(before.st_uid == uid and not before.st_mode & 0o077, 'E_ROUTER_DATABASE')
        _need(not any(os.path.lexists(str(database) + s) for s in ('-wal', '-shm', '-journal')), 'E_ROUTER_SIDECAR')
        db = sqlite3.connect(database.absolute().as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)
        db.execute('PRAGMA query_only=ON')
        _need(db.execute('PRAGMA query_only').fetchone()[0] == 1, 'E_ROUTER_QUERY_ONLY')
        total = db.execute("SELECT COUNT(*) FROM observations WHERE kind IN ('incoming','outgoing')").fetchone()[0]
        errors = 0
        for kind, raw, observed in db.execute("SELECT kind,raw_json,last_seen FROM observations WHERE kind IN ('incoming','outgoing') ORDER BY last_seen DESC LIMIT ?", (limit,)):
            try:
                _need(isinstance(raw, str) and len(raw) <= 65536, 'E_ROUTER_ROW')
                rows.append(_router_connection(kind, json.loads(raw), observed))
            except Exception:
                errors += 1
        device_total = db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        for key, raw, first, last in db.execute('SELECT device_key,device_json,first_seen,last_seen FROM devices ORDER BY last_seen DESC LIMIT ?', (MAX_DEVICES,)):
            try:
                _need(isinstance(raw, str) and len(raw) <= 65536, 'E_DEVICE_ROW')
                devices.append(_device(json.loads(raw), key, first, last))
            except Exception:
                errors += 1
        after = database.lstat()
        _need(_file_identity(before) == _file_identity(after), 'E_ROUTER_CHANGED')
        checked = status.get('checked_at') if isinstance(status, dict) else None
        fresh = _finite(checked) and -30 <= now - checked <= 180
        good = isinstance(status, dict) and status.get('collection_ok') is True
        info.update(state='stale' if not fresh else 'partial' if not good or errors else 'ok',
                    checked_at=checked if _finite(checked) else None,
                    reason='Retained router history; this is not a current-session feed.',
                    retained_connection_rows=total, rows_exported=len(rows), row_errors=errors,
                    truncated=total > limit, rows_omitted=max(0, total - limit),
                    device_rows_omitted=max(0, device_total - MAX_DEVICES),
                    collection_ok=good, notification_ok=status.get('notification_ok') is True,
                    alert_queue_handoff_ok=status.get('alert_queue_handoff_ok') is True)
    except FeedError as error:
        rows, devices = [], []
        info['state'], info['errors'] = 'partial' if str(error) == 'E_ROUTER_BUSY' else 'error', [str(error)]
        if str(error) == 'E_ROUTER_BUSY':
            info['reason'] = 'The router writer is active; no history was read this cycle.'
    except FileNotFoundError:
        info['errors'] = ['E_ROUTER_UNAVAILABLE']
    except Exception:
        rows, devices = [], []
        info['state'], info['errors'] = 'error', ['E_ROUTER_READ']
    finally:
        if db is not None:
            db.close()
        if lock is not None:
            os.close(lock)
    return rows, devices, info


def interface_counters(sys_net=Path('/sys/class/net'), *, previous=None, boot_id=None,
                       now=None, monotonic_ns=None, uid=0):
    now = time.time() if now is None else now
    mono = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    previous = previous if isinstance(previous, dict) else {}
    old_rows = previous.get('counters') if isinstance(previous.get('counters'), list) else []
    old = {item.get('interface'): item for item in old_rows[:MAX_INTERFACES] if isinstance(item, dict)}
    result = []
    errors = 0
    _directory(Path(sys_net), uid)
    entries = sorted(Path(sys_net).iterdir(), key=lambda p: p.name)
    for path in entries[:MAX_INTERFACES]:
        try:
            _need(_IFACE.fullmatch(path.name) and path.name not in ('.', '..'), 'E_INTERFACE')
            values = {}
            for key, file in (('rx_bytes', 'statistics/rx_bytes'), ('tx_bytes', 'statistics/tx_bytes'), ('ifindex', 'ifindex')):
                values[key] = _kernel_number(path / file, uid=uid)
            _need(values['ifindex'] > 0, 'E_COUNTER')
            prior = old.get(path.name)
            elapsed = None
            reset, reset_reason, rate_state = False, None, 'baseline'
            if prior:
                if not boot_id or previous.get('boot_id') != boot_id:
                    reset, reset_reason = True, 'boot_changed_or_unavailable'
                elif prior.get('ifindex') != values['ifindex']:
                    reset, reset_reason = True, 'interface_changed'
                elif any(type(prior.get(k)) is not int or not 0 <= prior[k] <= values[k] for k in ('rx_bytes', 'tx_bytes')):
                    reset, reset_reason = True, 'counter_decreased_or_invalid'
                elif type(previous.get('counter_monotonic_ns')) is not int or not 0 <= previous['counter_monotonic_ns'] < mono:
                    reset, reset_reason = True, 'monotonic_baseline_invalid'
                else:
                    elapsed = (mono - previous['counter_monotonic_ns']) / 1_000_000_000
                    rate_state = 'measured_average'
            rx_rate = (values['rx_bytes'] - prior['rx_bytes']) / elapsed if elapsed else None
            tx_rate = (values['tx_bytes'] - prior['tx_bytes']) / elapsed if elapsed else None
            result.append({'id': _digest(['host-interface', path.name]), 'interface': path.name,
                           'scope': 'host-interface', 'physical': (path / 'device').exists(),
                           **values, 'rx_bytes_per_second': rx_rate, 'tx_bytes_per_second': tx_rate,
                           'interval_seconds': elapsed, 'reset': reset, 'reset_reason': reset_reason,
                           'rate_state': 'reset' if reset else rate_state, 'observed_at': now,
                           'reason': 'Kernel counters for this host interface; can reset. Do not sum bridges or infer household/per-flow totals.'})
        except Exception:
            errors += 1
    return result, {'state': 'partial' if errors or len(entries) > MAX_INTERFACES else 'ok',
                    'checked_at': now, 'reason': 'This host only; received/sent bytes do not identify the connection initiator.',
                    'coverage': {'scope': 'host-interface', 'non_atomic_snapshot': True,
                                 'household_totals': False, 'per_flow_totals': False},
                    'read_errors': errors, 'interfaces_omitted': max(0, len(entries) - MAX_INTERFACES)}


def network_context(proc_root=Path('/proc'), *, uid=0):
    """Passive IPv4 default-route/ARP identity hint; never probes or authenticates."""
    route = _read(Path(proc_root) / 'net/route', 65536, uid=uid, check_parent=False).decode('ascii')
    candidates = []
    for line in route.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[1] != '00000000' or fields[7] != '00000000':
            continue
        try:
            if int(fields[3], 16) & 3 != 3 or not _IFACE.fullmatch(fields[0]):
                continue
            gateway = str(ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[2]), 'little')))
            if gateway == '0.0.0.0':
                continue
            candidates.append((int(fields[6]), fields[0], gateway))
        except (ValueError, OverflowError):
            continue
    _need(candidates, 'E_GATEWAY_UNAVAILABLE')
    candidates.sort()
    lowest = [row for row in candidates if row[0] == candidates[0][0]]
    _need(len({(row[1], row[2]) for row in lowest}) == 1, 'E_GATEWAY_AMBIGUOUS')
    _, interface, gateway = lowest[0]
    arp = _read(Path(proc_root) / 'net/arp', 65536, uid=uid, check_parent=False).decode('ascii')
    macs = set()
    for line in arp.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6 or fields[0] != gateway or fields[5] != interface:
            continue
        try:
            mac = fields[3].lower()
            if int(fields[2], 16) & 2 and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) and mac != '00:00:00:00:00:00' and not int(mac[:2], 16) & 1:
                macs.add(mac)
        except ValueError:
            continue
    _need(len(macs) == 1, 'E_GATEWAY_MAC_UNAVAILABLE')
    return {'gateway': gateway, 'mac': next(iter(macs)), 'interface': interface}


def _guard(config, current):
    try:
        network_id = str(uuid.UUID(config['network_id']))
        _need(uuid.UUID(network_id).int != 0, 'E_NETWORK_CONFIG')
        expected_ip = str(ipaddress.IPv4Address(config['expected_gateway_ipv4']))
        expected_mac = config['expected_gateway_mac'].lower()
        _need(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', expected_mac)
              and expected_mac != '00:00:00:00:00:00' and not int(expected_mac[:2], 16) & 1, 'E_NETWORK_CONFIG')
        matches = current.get('gateway') == expected_ip and current.get('mac') == expected_mac
        binding = _digest(['console-network/v1', current.get('gateway'), current.get('mac')]) if matches else None
        return {'matches': matches, 'network_id': network_id if matches else None,
                'configured_network_id': network_id, 'binding_sha256': binding,
                'state': 'ok' if matches else 'unavailable', 'identity_hint_only': True,
                'reason': 'Passive IPv4 gateway/MAC matches the reviewed context; this is an identity hint only.' if matches else
                          'The gateway context changed or is unavailable. Connection export is paused until network review.',
                'coverage': {'ipv4_default_gateway_binding': True, 'ipv6_only_context_supported': False}}
    except Exception:
        return {'matches': False, 'network_id': None, 'binding_sha256': None,
                'state': 'unavailable', 'identity_hint_only': True,
                'reason': 'A reviewed network identity and gateway binding are required before exporting connections.',
                'coverage': {'ipv4_default_gateway_binding': False, 'ipv6_only_context_supported': False}}


def _device_aliases(rows, devices, now):
    for row in rows:
        possible = [device for device in devices if row.get('source_address') in device['addresses']
                    and _finite(device.get('observed_at')) and 0 <= now - device['observed_at'] <= 180
                    and _finite(row.get('observed_at')) and abs(row['observed_at'] - device['observed_at']) <= 180]
        if len(possible) == 1 and possible[0]['name'] != 'Unlabelled device':
            row['device_name'] = possible[0]['name']
            row['device_mapping_confidence'] = 'recent_router_report_only'
            row['device_mapping_reason'] = 'Unique recent router IP association; the retained event time, ownership and online state remain unproven.'
        elif len(possible) > 1:
            row['device_mapping_confidence'] = 'ambiguous'


def _deduplicate(rows):
    """Stable endpoint IDs coalesce observations, never claim unique sessions."""
    combined = {}
    for row in rows:
        old = combined.get(row['id'])
        count = (old.get('observation_count', 1) if old else 0) + 1
        first = min(old.get('first_observed_at', old['observed_at']), row['observed_at']) if old else row['observed_at']
        chosen = dict(row if not old or row['observed_at'] >= old['observed_at'] else old)
        flags = {flag['code']: flag for item in ((old,) if old else ()) + (row,) for flag in item['flags']}
        chosen['flags'] = list(flags.values())
        chosen['severity'] = 'REVIEW' if flags else 'INFO'
        chosen.update(observation_count=count, first_observed_at=first,
                      aggregation_note='Matching endpoint observations coalesced; may represent distinct connections or processes. This count is not sessions, flows or bytes.'
                      if count > 1 else 'One exported observation; this is not a session, flow or byte count.')
        combined[row['id']] = chosen
    return list(combined.values())


def build_snapshot(*, previous=None, linux_provider=None, router_state=ROUTER_STATE,
                   proc_root=Path('/proc'), sys_net=Path('/sys/class/net'), now=None,
                   monotonic_ns=None, uid=0, network_config=None, network_provider=None):
    now = time.time() if now is None else now
    mono = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    _need(_finite(now) and type(mono) is int and mono >= 0, 'E_TIME')
    boot = None
    try:
        text = _read(Path(proc_root) / 'sys/kernel/random/boot_id', 128, uid=uid, check_parent=False).decode().strip()
        boot = str(uuid.UUID(text))
    except Exception:
        pass
    try:
        current = network_provider() if network_provider else network_context(proc_root, uid=uid)
    except Exception:
        current = {}
    guard = _guard(network_config, current)
    sources = {'guard': {**guard, 'checked_at': now}}
    connections = []
    try:
        _need(guard['matches'], 'E_NETWORK_REVIEW_REQUIRED')
        capture = (linux_provider or collect_linux_records)('linux:console-host', now, Path(proc_root))
        records, coverage = capture['records'], capture['coverage']
        _need(isinstance(records, list) and isinstance(coverage, dict), 'E_LINUX_CAPTURE')
        connections, errors = linux_connections(records, now, MAX_CONNECTIONS // 2)
        allowed = ('tcp4_read_ok', 'tcp6_read_ok', 'tables_revalidated', 'process_scan_ok',
                   'limits_reached', 'budget_exhausted', 'parse_errors', 'attributed', 'unattributed')
        clean = {key: coverage[key] for key in allowed if type(coverage.get(key)) in (bool, int)}
        clean.update(scope='host_current_network_namespace', tcp_only=True, udp_observed=False,
                     complete_stream_visibility=False, non_atomic_snapshot=True)
        sources['linux'] = {'state': 'ok' if coverage.get('ok') is True and not errors and len(records) <= MAX_CONNECTIONS // 2 else 'partial',
                            'checked_at': now, 'reason': 'Only this host current-namespace TCP sockets; short-lived activity may be missed.',
                            'coverage': clean, 'row_errors': errors,
                            'rows_omitted': max(0, len(records) - MAX_CONNECTIONS // 2)}
    except Exception:
        sources['linux'] = {'state': 'error' if guard['matches'] else 'unavailable', 'checked_at': now,
                            'reason': 'Local TCP collection did not complete.' if guard['matches'] else guard['reason'],
                            'coverage': {'complete_stream_visibility': False}, 'errors': ['E_LINUX_CAPTURE']}
    router_rows, devices, sources['router'] = router_snapshot(router_state if guard['matches'] else None, now=now, limit=MAX_CONNECTIONS // 2, uid=uid)
    if not guard['matches']:
        sources['router']['reason'] = guard['reason']
    _device_aliases(router_rows, devices, now)
    connections.extend(router_rows)
    for row in connections:
        row['id'] = _digest([guard['network_id'], guard['binding_sha256'], row['id']])
        row['network_id'] = guard['network_id']
    for device in devices:
        device['id'] = _digest([guard['network_id'], guard['binding_sha256'], device['id']])
    connections = _deduplicate(connections)
    counter_previous = previous if isinstance(previous, dict) and previous.get('network_id') == guard['network_id'] and previous.get('network_binding_sha256') == guard['binding_sha256'] and guard['matches'] else None
    try:
        counters, sources['interfaces'] = interface_counters(sys_net, previous=counter_previous, boot_id=boot, now=now, monotonic_ns=mono, uid=uid)
    except Exception:
        counters = []
        sources['interfaces'] = {'state': 'error', 'checked_at': now, 'reason': 'Host interface counters were unavailable.',
                                 'coverage': {'household_totals': False}, 'errors': ['E_INTERFACE_READ']}
    for counter in counters:
        counter['id'] = _digest([guard['network_id'], guard['binding_sha256'], counter['id']])
        counter['network_id'] = guard['network_id']
    snapshot = {'schema_version': 1, 'generated_at': now, 'boot_id': boot, 'counter_monotonic_ns': mono,
                'network_id': guard['network_id'], 'network_binding_sha256': guard['binding_sha256'],
                'sources': sources, 'connections': connections, 'counters': counters, 'devices': devices,
                'capabilities': {'host_tcp': {'available': sources['linux']['state'] in ('ok', 'partial'), 'scope': 'this_host_only'},
                    'host_interface_counters': {'available': bool(counters), 'scope': 'this_host_only'},
                    'router_history': {'available': sources['router']['state'] in ('ok', 'partial', 'stale'), 'live': False},
                    'per_flow_counters': {'available': False, 'reason': 'No per-flow byte source is installed.'},
                    'household_counters': {'available': False, 'reason': 'Router rows contain no traffic byte counts.'},
                    'disconnect': {'available': False, 'reason': 'This worker observes only; no network or router controls.'}},
                'partial_coverage': True, 'truncation': {'connection_limit': MAX_CONNECTIONS,
                    'connections_omitted': sources['linux'].get('rows_omitted', 0) + sources['router'].get('rows_omitted', 0),
                    'json_size_limited': False}}
    encode_snapshot(snapshot)
    return snapshot


def encode_snapshot(snapshot):
    while True:
        raw = (json.dumps(snapshot, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(raw) <= MAX_JSON:
            return raw
        snapshot['truncation']['json_size_limited'] = True
        if snapshot['connections']:
            count = max(1, len(snapshot['connections']) // 10)
            del snapshot['connections'][-count:]
            snapshot['truncation']['connections_omitted'] += count
        elif snapshot['devices']:
            del snapshot['devices'][-1:]
            snapshot['truncation']['devices_omitted'] = snapshot['truncation'].get('devices_omitted', 0) + 1
        else:
            raise FeedError('E_OUTPUT_SIZE')


def read_previous(path=OUTPUT, *, uid=0, gid=None):
    if not os.path.lexists(path):
        return None
    raw = _read(path, MAX_JSON, uid=uid)
    meta = Path(path).lstat()
    if os.name == 'posix':
        _need(stat.S_IMODE(meta.st_mode) == 0o640 and (gid is None or meta.st_gid == gid), 'E_SNAPSHOT_MODE')
    value = json.loads(raw)
    _need(isinstance(value, dict) and value.get('schema_version') == 1, 'E_SNAPSHOT_SCHEMA')
    return value


def publish(snapshot, path=OUTPUT, *, gid, uid=0):
    path = Path(path)
    _directory(path.parent.parent, uid)
    if not path.parent.exists():
        path.parent.mkdir(mode=0o750)
        if os.name == 'posix':
            os.chown(path.parent, uid, gid)
            path.parent.chmod(0o750)
    _directory(path.parent, uid)
    meta = path.parent.lstat()
    if os.name == 'posix':
        _need(meta.st_gid == gid and stat.S_IMODE(meta.st_mode) == 0o750, 'E_OUTPUT_DIRECTORY')
    if os.path.lexists(path):
        read_previous(path, uid=uid, gid=gid)
    temporary = path.with_name('.snapshot-' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o640)
    try:
        if os.name == 'posix':
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o640)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(encode_snapshot(snapshot))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if fd is not None:
            os.close(fd)
        if temporary.exists():
            temporary.unlink()


def load_config(path):
    _need(Path(path).is_absolute(), 'E_CONFIG_PATH')
    value = json.loads(_read(path, 16384, private=True))
    required = {'schema_version', 'network_id', 'expected_gateway_ipv4', 'expected_gateway_mac'}
    _need(isinstance(value, dict) and required <= set(value) <= required | {'router_state'}
          and type(value.get('schema_version')) is int and value['schema_version'] == 1, 'E_CONFIG')
    router = value.get('router_state', str(ROUTER_STATE))
    _need(router is None or router == str(ROUTER_STATE), 'E_CONFIG_SOURCE')
    value['expected_gateway_ipv4'] = str(ipaddress.IPv4Address(value['expected_gateway_ipv4']))
    value['expected_gateway_mac'] = value['expected_gateway_mac'].lower()
    probe = _guard(value, {'gateway': value.get('expected_gateway_ipv4'), 'mac': value.get('expected_gateway_mac')})
    _need(probe['matches'], 'E_CONFIG_NETWORK')
    return {'router_state': Path(router) if router is not None else None, 'network_config': value}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Publish a bounded local read-only console snapshot.')
    parser.add_argument('--config', type=Path)
    args = parser.parse_args(argv)
    try:
        _need(sys.platform.startswith('linux') and os.geteuid() == 0 and grp is not None, 'E_PRIVILEGE')
        gid = grp.getgrnam(GROUP).gr_gid
        _need(args.config is not None, 'E_CONFIG_REQUIRED')
        config = load_config(args.config)
        previous = read_previous(gid=gid)
        snapshot = build_snapshot(previous=previous, **config)
        from .console_history import export_history
        snapshot['sources']['history'] = export_history(config['router_state'], snapshot, gid=gid)
        publish(snapshot, gid=gid)
        return 0
    except Exception:
        # No paths, captured data or exception text on stdout/stderr.
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
