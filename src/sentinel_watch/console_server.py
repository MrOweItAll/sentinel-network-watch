"""Authenticated, annotation-only HTTPS console for an explicitly chosen LAN.

The caller supplies a server TLS context and an owned private PasswordAuth file.
No forwarding headers, commands, connection controls or credential APIs exist.
The provider and store are local, bounded data interfaces, not request paths.
"""
from __future__ import annotations

from collections import deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
from socketserver import ThreadingMixIn
import ssl
import threading
import time
from urllib.parse import urlsplit

from .dashboard import PasswordAuth

COOKIE = '__Host-sentinel'
MAX_BODY = 16_384
MAX_RESPONSE = 4 * 1024 * 1024
MAX_HEADERS = 8192
MAX_WIRE = MAX_HEADERS + MAX_BODY + 4096
MAX_CONNECTIONS = 8
HANDSHAKE_SECONDS = 5
CONNECTION_SECONDS = 20
SESSION_SECONDS = 8 * 3600
IDLE_SECONDS = 30 * 60
DECISIONS = frozenset(('recognize', 'unrecognized', 'investigate'))
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
HISTORY_SUMMARY_FIELDS = frozenset(('available', 'state', 'generated_at', 'collector_checked_at',
                                  'raw_retained_count', 'total_observations', 'row_errors', 'reason'))
HISTORY_QUERY_FIELDS = frozenset(('offset', 'limit', 'search', 'direction', 'review'))
SECRET_KEY = re.compile(r'password|passphrase|secret|token|credential|authorization|cookie|private.?key|^topic$|^base_url$|^salt$', re.I)


class ConsoleError(ValueError):
    pass


class HistoryFailure(RuntimeError):
    def __init__(self, code):
        self.code = code


def _history_query(value):
    return (isinstance(value, dict) and set(value) == HISTORY_QUERY_FIELDS
            and type(value['offset']) is int and 0 <= value['offset'] <= 2 ** 63 - 1
            and type(value['limit']) is int and 1 <= value['limit'] <= 100
            and isinstance(value['search'], str) and len(value['search']) <= 200
            and all(ord(char) >= 32 and ord(char) != 127 for char in value['search'])
            and value['direction'] in ('all', 'vendor_outgoing', 'vendor_incoming')
            and value['review'] in ('all', 'pending', 'unrecognized', 'investigate', 'recognize'))


def _history_unavailable():
    return {'available': False, 'state': 'unavailable', 'generated_at': None,
            'collector_checked_at': None, 'raw_retained_count': None,
            'total_observations': None, 'row_errors': None,
            'reason': 'Retained router history is unavailable.'}


def _history_summary(value):
    if not isinstance(value, dict) or set(value) != HISTORY_SUMMARY_FIELDS:
        raise HistoryFailure('E_HISTORY_DATA')
    if (type(value['available']) is not bool or value['state'] not in ('ok', 'partial', 'stale', 'unavailable', 'error')
            or not isinstance(value['reason'], str) or len(value['reason']) > 1000):
        raise HistoryFailure('E_HISTORY_DATA')
    for name in ('generated_at', 'collector_checked_at'):
        item = value[name]
        try:
            valid = item is None or (type(item) in (int, float) and math.isfinite(item) and item >= 0)
        except OverflowError:
            valid = False
        if not valid:
            raise HistoryFailure('E_HISTORY_DATA')
    for name in ('raw_retained_count', 'total_observations', 'row_errors'):
        item = value[name]
        if item is None and not value['available']:
            continue
        if type(item) is not int or not 0 <= item <= 2 ** 63 - 1:
            raise HistoryFailure('E_HISTORY_DATA')
    try:
        _json(value, reject_credentials=True)
    except ConsoleError:
        raise HistoryFailure('E_HISTORY_DATA') from None
    return value


def _history_context(snapshot):
    sources = snapshot.get('sources', {})
    guard = sources.get('guard', {}) if isinstance(sources, dict) else {}
    return (isinstance(guard, dict) and guard.get('matches') is True and guard.get('state') == 'ok'
            and isinstance(snapshot.get('network_id'), str) and ID.fullmatch(snapshot['network_id']) is not None
            and guard.get('network_id') == snapshot['network_id']
            and isinstance(snapshot.get('network_binding_sha256'), str)
            and re.fullmatch(r'[0-9a-f]{64}', snapshot['network_binding_sha256']) is not None
            and guard.get('binding_sha256') == snapshot['network_binding_sha256'])


def validate_config(config):
    """No wildcard/IPv6 listener, implicit CIDR, alternate port or proxy mode."""
    try:
        if not isinstance(config, dict) or set(config) != {'bind', 'port', 'allowed_cidr', 'auth_path'}:
            raise ValueError
        address = ipaddress.IPv4Address(config['bind'])
        network = ipaddress.IPv4Network(config['allowed_cidr'], strict=True)
        if (str(address) != config['bind'] or address.is_unspecified or address.is_multicast
                or network.prefixlen == 0 or address not in network
                or (network.prefixlen < 31 and address in (network.network_address, network.broadcast_address))
                or type(config['port']) is not int or config['port'] != 8443
                or not isinstance(config['auth_path'], (str, Path))
                or not Path(config['auth_path']).is_absolute()):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise ConsoleError('E_CONSOLE_CONFIG') from None
    return {'bind': str(address), 'port': 8443, 'allowed_cidr': str(network),
            'auth_path': Path(config['auth_path'])}


def _json(value, *, reject_credentials=False):
    """Bound depth, collection sizes and strings before encoding local data."""
    count, budget = 0, 0
    def inspect(item, depth=0):
        nonlocal count, budget
        count += 1
        budget += 2
        if count > 100_000 or depth > 16:
            raise ConsoleError('E_DATA_LIMIT')
        if isinstance(item, dict):
            for key, child in item.items():
                if (not isinstance(key, str) or len(key) > 256
                        or (reject_credentials and SECRET_KEY.search(key))):
                    raise ConsoleError('E_DATA_SCHEMA')
                budget += len(json.dumps(key, ensure_ascii=True)) + 1
                inspect(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in item:
                inspect(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > 65536:
                raise ConsoleError('E_DATA_LIMIT')
            budget += len(json.dumps(item, ensure_ascii=True))
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise ConsoleError('E_DATA_SCHEMA')
        if budget > MAX_RESPONSE:
            raise ConsoleError('E_DATA_LIMIT')
    inspect(value)
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()
    except (ValueError, TypeError, OverflowError):
        raise ConsoleError('E_DATA_SCHEMA') from None
    if len(raw) > MAX_RESPONSE:
        raise ConsoleError('E_DATA_LIMIT')
    return raw


class ConsoleApp:
    """Pure, thread-safe request router. Store methods must themselves be durable.

    provider() -> {connections: [{id: stable safe string, ...}], ...}
    store.annotations() -> dict; store.update_review(id, decision, note) -> dict.
    Annotation decisions express recognition/review only, never endpoint access.
    """
    def __init__(self, config, provider, state_store, auth, *, clock=time.monotonic, history_provider=None):
        self.config = validate_config(config)
        self.origin = 'https://' + self.config['bind'] + ':8443'
        self.host = urlsplit(self.origin).netloc
        self.network = ipaddress.IPv4Network(self.config['allowed_cidr'])
        self.provider, self.store, self.auth, self.clock = provider, state_store, auth, clock
        self.history = history_provider
        self.sessions = {}
        self.failures = deque()
        self.lock = threading.RLock()

    def allowed_peer(self, address):
        try:
            return ipaddress.IPv4Address(address) in self.network
        except (ValueError, TypeError):
            return False

    @staticmethod
    def response(status, value, extra=None):
        raw = value if isinstance(value, bytes) else _json(value)
        if len(raw) > MAX_RESPONSE:
            raise ConsoleError('E_DATA_LIMIT')
        headers = {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
                   'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                   'X-Frame-Options': 'DENY', 'Strict-Transport-Security': 'max-age=86400',
                   'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
                   'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"}
        headers.update(extra or {})
        return status, raw, headers

    def html(self, value):
        nonce = secrets.token_urlsafe(24)
        return self.response(200, value.replace('__NONCE__', nonce).encode(), {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Security-Policy': "default-src 'none'; script-src 'nonce-" + nonce +
            "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})

    def _snapshot(self):
        value = self.provider()
        if not isinstance(value, dict) or not isinstance(value.get('connections'), list):
            raise ConsoleError('E_SNAPSHOT')
        if len(value['connections']) > 5000:
            raise ConsoleError('E_DATA_LIMIT')
        ids = set()
        for row in value['connections']:
            ident = row.get('id') if isinstance(row, dict) else None
            if not isinstance(ident, str) or ID.fullmatch(ident) is None or ident in ids:
                raise ConsoleError('E_SNAPSHOT')
            ids.add(ident)
        _json(value, reject_credentials=True)
        return value, ids

    def _annotations(self):
        value = self.store.annotations()
        if not isinstance(value, dict):
            raise ConsoleError('E_ANNOTATIONS')
        _json(value, reject_credentials=True)
        return value

    def _history_call(self, method, *args):
        if self.history is None:
            raise HistoryFailure('E_HISTORY_UNAVAILABLE')
        try:
            return getattr(self.history, method)(*args)
        except Exception:
            raise HistoryFailure('E_HISTORY_UNAVAILABLE') from None

    def _history_page(self, query, annotations, snapshot):
        value = self._history_call('page', query, annotations, snapshot)
        fields = HISTORY_SUMMARY_FIELDS | {'rows', 'total_matches', 'offset', 'limit', 'has_more'}
        if not isinstance(value, dict) or set(value) != fields:
            raise HistoryFailure('E_HISTORY_DATA')
        summary = _history_summary({key: value[key] for key in HISTORY_SUMMARY_FIELDS})
        if not summary['available']:
            raise HistoryFailure('E_HISTORY_UNAVAILABLE')
        rows = value['rows']
        if (not isinstance(rows, list) or len(rows) > query['limit']
                or type(value['total_matches']) is not int or not 0 <= value['total_matches'] <= 2 ** 63 - 1
                or type(value['offset']) is not int or value['offset'] != query['offset']
                or type(value['limit']) is not int or value['limit'] != query['limit']
                or type(value['has_more']) is not bool
                or value['has_more'] != (query['offset'] + len(rows) < value['total_matches'])
                or len(rows) > max(0, value['total_matches'] - query['offset'])):
            raise HistoryFailure('E_HISTORY_DATA')
        ids = set()
        for row in rows:
            ident = row.get('id') if isinstance(row, dict) else None
            if (not isinstance(ident, str) or ID.fullmatch(ident) is None or ident in ids
                    or row.get('source') != 'router' or row.get('state') != 'history'
                    or row.get('transport') != 'unknown'
                    or row.get('direction') not in ('vendor_outgoing', 'vendor_incoming')
                    or row.get('network_id') != snapshot.get('network_id')):
                raise HistoryFailure('E_HISTORY_DATA')
            for name in ('source_address', 'destination_address'):
                if name not in row or (row[name] is not None and (not isinstance(row[name], str) or len(row[name]) > 253)):
                    raise HistoryFailure('E_HISTORY_DATA')
            for name in ('source_port', 'destination_port'):
                if name not in row or (row[name] is not None and (type(row[name]) is not int or not 0 <= row[name] <= 65535)):
                    raise HistoryFailure('E_HISTORY_DATA')
            for name in ('summary', 'reason', 'next_step'):
                if not isinstance(row.get(name), str) or len(row[name]) > 2000:
                    raise HistoryFailure('E_HISTORY_DATA')
            if not isinstance(row.get('flags'), list) or len(row['flags']) > 16:
                raise HistoryFailure('E_HISTORY_DATA')
            observed = row.get('observed_at')
            try:
                valid = type(observed) in (int, float) and math.isfinite(observed) and observed >= 0
            except OverflowError:
                valid = False
            if not valid:
                raise HistoryFailure('E_HISTORY_DATA')
            ids.add(ident)
        try:
            _json(value, reject_credentials=True)
        except ConsoleError:
            raise HistoryFailure('E_HISTORY_DATA') from None
        return value, ids

    def _session(self, headers, peer):
        now = self.clock()
        self.sessions = {key: value for key, value in self.sessions.items()
                         if now - value['created'] < SESSION_SECONDS and now - value['seen'] < IDLE_SECONDS}
        try:
            jar = SimpleCookie(); jar.load(headers.get('cookie', ''))
            ident = jar[COOKIE].value
            session = self.sessions.get(ident)
            if session is None or session['peer'] != peer:
                return None, None
            session['seen'] = now
            return ident, session
        except Exception:
            return None, None

    def dispatch(self, method, target, headers=(), body=b'', *, client_ip):
        with self.lock:
            try:
                return self._dispatch(method, target, headers, body, client_ip)
            except ConsoleError:
                return self.response(400, {'error': 'E_REQUEST'})
            except HistoryFailure as error:
                return self.response(503, {'error': error.code})
            except Exception:
                return self.response(503, {'error': 'E_OPERATION'})

    def _dispatch(self, method, target, headers, body, peer):
        if not self.allowed_peer(peer):
            return self.response(403, {'error': 'E_NETWORK'})
        pairs = list(headers.items()) if hasattr(headers, 'items') else list(headers)
        if sum(len(str(k)) + len(str(v)) for k, v in pairs) > MAX_HEADERS:
            return self.response(400, {'error': 'E_HEADERS'})
        values = {}
        for key, value in pairs:
            key, value = str(key).lower(), str(value)
            if key in values:
                return self.response(400, {'error': 'E_HEADERS'})
            if key == 'forwarded' or key == 'x-real-ip' or key.startswith('x-forwarded-'):
                return self.response(403, {'error': 'E_FORWARDING'})
            values[key] = value
        if values.get('host') != self.host:
            return self.response(403, {'error': 'E_HOST'})
        if 'origin' in values and values['origin'] != self.origin:
            return self.response(403, {'error': 'E_ORIGIN'})
        if values.get('sec-fetch-site') == 'cross-site':
            return self.response(403, {'error': 'E_ORIGIN'})
        if 'transfer-encoding' in values or not isinstance(body, bytes) or len(body) > MAX_BODY:
            return self.response(400, {'error': 'E_BODY'})
        if not isinstance(target, str) or len(target) > 2048:
            return self.response(400, {'error': 'E_PATH'})
        url = urlsplit(target)
        if url.scheme or url.netloc or url.query or url.fragment or not url.path.startswith('/'):
            return self.response(400, {'error': 'E_PATH'})
        path = url.path
        if method not in ('GET', 'POST'):
            return self.response(405, {'error': 'E_METHOD'})
        if method == 'GET' and path == '/login':
            return self.html(LOGIN_HTML)
        data = {}
        if method == 'POST':
            if values.get('origin') != self.origin:
                return self.response(403, {'error': 'E_ORIGIN'})
            if values.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                return self.response(415, {'error': 'E_CONTENT_TYPE'})
            try:
                def unique_object(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value:
                            raise ValueError
                        value[key] = item
                    return value
                data = json.loads(body, object_pairs_hook=unique_object)
            except Exception:
                return self.response(400, {'error': 'E_JSON'})
            if not isinstance(data, dict):
                return self.response(400, {'error': 'E_JSON'})
        if method == 'POST' and path == '/api/login':
            now = self.clock()
            while self.failures and now - self.failures[0][0] >= 60:
                self.failures.popleft()
            if len(self.failures) >= 25 or sum(address == peer for _, address in self.failures) >= 5:
                return self.response(429, {'error': 'E_LOGIN_RATE'}, {'Retry-After': '60'})
            if set(data) != {'username', 'password'} or not self.auth.verify(data.get('username'), data.get('password')):
                self.failures.append((now, peer))
                return self.response(401, {'error': 'E_LOGIN'})
            self.failures = deque((when, address) for when, address in self.failures if address != peer)
            self._session({}, peer)  # Prune expired sessions before applying the cap.
            if len(self.sessions) >= 32:
                self.sessions.pop(next(iter(self.sessions)))
            ident, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[ident] = {'created': now, 'seen': now, 'csrf': csrf, 'peer': peer}
            return self.response(200, {'ok': True, 'csrf_token': csrf}, {
                'Set-Cookie': COOKIE + '=' + ident + '; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + str(SESSION_SECONDS)})
        ident, session = self._session(values, peer)
        if session is None:
            if method == 'GET' and path == '/':
                return self.response(303, b'', {'Location': '/login'})
            return self.response(401, {'error': 'E_LOGIN_REQUIRED'})
        if method == 'GET':
            if path == '/':
                from .console_ui import HTML
                return self.html(HTML)
            if path == '/api/session':
                return self.response(200, {'ok': True, 'csrf_token': session['csrf']})
            if path == '/api/snapshot':
                snapshot, _ = self._snapshot()
                annotations = self._annotations()
                result = {'snapshot': snapshot, 'annotations': annotations}
                if self.history is not None:
                    try:
                        result['history'] = _history_summary(self._history_call('summary', snapshot, annotations))
                    except HistoryFailure:
                        result['history'] = _history_unavailable()
                return self.response(200, result)
            return self.response(404, {'error': 'E_NOT_FOUND'})
        if not hmac.compare_digest(values.get('x-csrf-token', ''), session['csrf']):
            return self.response(403, {'error': 'E_CSRF'})
        if path == '/api/logout' and not data:
            self.sessions.pop(ident, None)
            return self.response(200, {'ok': True}, {
                'Set-Cookie': COOKIE + '=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
        if path == '/api/history':
            if not _history_query(data):
                return self.response(400, {'error': 'E_HISTORY_QUERY'})
            snapshot, _ = self._snapshot()
            annotations = self._annotations()
            history, ids = self._history_page(data, annotations, snapshot)
            return self.response(200, {'history': history,
                                      'annotations': {key: annotations[key] for key in ids if key in annotations}})
        if path == '/api/review':
            if set(data) != {'id', 'decision', 'note'}:
                raise ConsoleError('E_REVIEW')
            ident, decision, note = data['id'], data['decision'], data['note']
            if (not isinstance(ident, str) or ID.fullmatch(ident) is None
                    or not isinstance(decision, str) or decision not in DECISIONS
                    or not isinstance(note, str) or len(note) > 500
                    or any(ord(char) < 32 or ord(char) == 127 for char in note)):
                raise ConsoleError('E_REVIEW')
            snapshot, ids = self._snapshot()
            if ident not in ids:
                present = (self._history_call('contains', ident, snapshot)
                           if self.history is not None and _history_context(snapshot) else False)
                if type(present) is not bool:
                    raise HistoryFailure('E_HISTORY_DATA')
                if not present:
                    return self.response(409, {'error': 'E_STALE_REVIEW'})
            annotation = self.store.update_review(ident, decision, note)
            if not isinstance(annotation, dict):
                raise ConsoleError('E_ANNOTATIONS')
            _json(annotation, reject_credentials=True)
            return self.response(200, {'ok': True, 'annotation': annotation})
        return self.response(404, {'error': 'E_NOT_FOUND'})


class _BoundedInput:
    def __init__(self, stream):
        self.stream, self.used = stream, 0

    def _take(self, method, count):
        remaining = MAX_WIRE - self.used
        raw = method(min(remaining + 1, count) if count >= 0 else remaining + 1)
        self.used += len(raw)
        if self.used > MAX_WIRE:
            raise OSError('request limit')
        return raw

    def readline(self, count=-1):
        return self._take(self.stream.readline, count)

    def read(self, count=-1):
        return self._take(self.stream.read, count)

    def close(self):
        self.stream.close()


def _close_socket(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass


class _TLSServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(self, address, handler, app, context):
        self.app, self.tls_context = app, context
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def verify_request(self, request, client_address):
        return self.app.allowed_peer(client_address[0])

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            _close_socket(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            _close_socket(request)

    def process_request_thread(self, request, client_address):
        connection, deadline = request, None
        try:
            request.settimeout(HANDSHAKE_SECONDS)
            connection = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
            deadline = threading.Timer(CONNECTION_SECONDS, _close_socket, args=(connection,))
            deadline.daemon = True; deadline.start()
            connection.settimeout(HANDSHAKE_SECONDS)
            connection.do_handshake()
            connection.settimeout(HANDSHAKE_SECONDS)
            self.finish_request(connection, client_address)
        except Exception:
            pass  # Never emit TLS, request, password or provider exception text.
        finally:
            if deadline is not None:
                deadline.cancel()
            _close_socket(connection)
            self._slots.release()

    def handle_error(self, request, client_address):
        pass


def create_server(config, provider, state_store, tls_context, *, history_provider=None):
    """Return a bounded HTTPS server. Caller owns serve_forever/shutdown lifecycle."""
    config = validate_config(config)
    if os.name == 'posix' and os.geteuid() == 0:
        raise ConsoleError('E_UNPRIVILEGED_REQUIRED')
    if (not isinstance(tls_context, ssl.SSLContext) or tls_context.protocol != ssl.PROTOCOL_TLS_SERVER
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2):
        raise ConsoleError('E_TLS_CONTEXT')
    auth = PasswordAuth(config['auth_path'])
    app = ConsoleApp(config, provider, state_store, auth, history_provider=history_provider)

    class Handler(BaseHTTPRequestHandler):
        server_version = 'Sentinel'; sys_version = ''

        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            self.rfile = _BoundedInput(self.rfile)

        def send_error(self, code, message=None, explain=None):
            self._write(ConsoleApp.response(code, {'error': 'E_HTTP'}))

        def _write(self, response):
            status, raw, headers = response
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Connection', 'close'); self.end_headers()
            self.close_connection = True
            try:
                self.wfile.write(raw)
            except OSError:
                pass

        def _handle(self):
            try:
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) > 1 or self.headers.get('Transfer-Encoding'):
                    raise ValueError
                length = int(lengths[0]) if lengths else 0
                if not 0 <= length <= MAX_BODY:
                    raise ValueError
                body = self.rfile.read(length) if length else b''
                if len(body) != length:
                    raise ValueError
                response = self.server.app.dispatch(self.command, self.path,
                    list(self.headers.raw_items()), body, client_ip=self.client_address[0])
            except Exception:
                response = ConsoleApp.response(400, {'error': 'E_HTTP'})
            self._write(response)

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle

    return _TLSServer((config['bind'], config['port']), Handler, app, tls_context)


LOGIN_HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel sign in</title>
<style nonce="__NONCE__">body{font:16px system-ui;max-width:28rem;margin:8vh auto;padding:1rem;background:#10202b;color:#edf4f7}label,input,button{display:block;box-sizing:border-box;width:100%;margin:.8rem 0}input,button{padding:.8rem;font:inherit}button{cursor:pointer;background:#9ce2cf;border:0;border-radius:.4rem}small{color:#becbd2}</style></head><body><h1>Sentinel</h1><p>Sign in to your private home-network console.</p><form id="login"><label>Username<input id="username" autocomplete="username" value="sentinel" required></label><label>Password<input id="password" type="password" autocomplete="current-password" required maxlength="256"></label><button>Sign in</button></form><p id="message" role="status"></p><small>Use the separate Sentinel account, not your Ubuntu administrator password.</small>
<script nonce="__NONCE__">document.getElementById('login').onsubmit=async event=>{event.preventDefault();const password=document.getElementById('password');try{const response=await fetch('/api/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:password.value})});password.value='';if(response.ok){location.replace('/');return;}document.getElementById('message').textContent=response.status===429?'Too many attempts. Wait one minute and try again.':'Sign-in was not accepted.';}catch{password.value='';document.getElementById('message').textContent='The local console could not be reached.';}};</script></body></html>'''
