#!/usr/bin/env python3
"""Normal-user, synthetic-only acceptance of the real Sentinel Qt client.

This is an offline fixture runner, not an installed client or a credential tool.
It creates temporary loopback HTTPS servers and ephemeral certificates. It never
uses the production console, trust store, account, password, cookie or CA key.
Root reviews/runs this separately; importing it does not start Qt or a server.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

FIXTURE_PASSWORD = 'Synthetic-engine-fixture-only-2026!'
FIXTURE_COOKIE = 'synthetic-engine-session-only'
FIXTURE_CSRF = 'synthetic-engine-csrf-only'
MAX_REPORT = 64 * 1024
MAX_EXPORT = 4 * 1024 * 1024
CASE_SECONDS = 8
TOTAL_SECONDS = 240
STDERR_LIMIT = 8192
PROGRESS_ROOT = None
PROGRESS_CHECKS = {}
PROGRESS_PHASE = 'not_started'
PROGRESS_TEST_PHASE = 'not_started'


class FixtureFailure(Exception):
    """Only fixed, nonsecret identifiers leave the harness."""


def require(value, code):
    if not value:
        raise FixtureFailure(code)


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise


def private_dir(path):
    path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
            and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'E_FIXTURE_PRIVATE_DIRECTORY')
    return path


def checkpoint(phase):
    """Only fixed fixture phase names and check booleans are persisted."""
    global PROGRESS_PHASE, PROGRESS_TEST_PHASE
    require(re.fullmatch(r'[a-z][a-z0-9_]{0,79}', phase), 'E_PROGRESS_PHASE')
    PROGRESS_PHASE = phase
    if not phase.startswith(('window_shutdown_', 'window_close_', 'window_closed_', 'worker_cleanup_')):
        PROGRESS_TEST_PHASE = phase
    if PROGRESS_ROOT is None:
        return
    value = {'phase': phase, 'test_phase': PROGRESS_TEST_PHASE, 'checks': dict(PROGRESS_CHECKS)}
    require(all(re.fullmatch(r'[a-z][a-z0-9_]{0,95}', name) and type(passed) is bool
                for name, passed in value['checks'].items()), 'E_PROGRESS_SCHEMA')
    raw = json.dumps(value, sort_keys=True).encode()
    require(len(raw) <= 16384, 'E_PROGRESS_LIMIT')
    temporary = PROGRESS_ROOT / 'progress-next.json'
    write_new(temporary, raw)
    os.replace(temporary, PROGRESS_ROOT / 'progress.json')


def environment_safe():
    require(os.name == 'posix' and os.geteuid() != 0, 'E_NORMAL_USER_REQUIRED')
    for name in ('QTWEBENGINE_DISABLE_SANDBOX', 'QTWEBENGINE_REMOTE_DEBUGGING',
                 'QTWEBENGINEPROCESS_PATH', 'QTWEBENGINE_CHROMIUM_FLAGS', 'CHROMIUM_FLAGS'):
        require(not os.environ.get(name), 'E_UNSAFE_ENGINE_ENVIRONMENT')
    require(os.environ.get('QT_QPA_PLATFORM', 'offscreen') == 'offscreen', 'E_OFFSCREEN_REQUIRED')


def certificates(root):
    """All generated keys/certificates are disposable synthetic fixtures."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)
    def authority(label):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    ca_key, ca = authority('Synthetic Sentinel Engine CA')
    wrong_key, wrong_ca = authority('Synthetic Unapproved Engine CA')
    fixtures = {}
    for name in ('good', 'wrong_ca', 'wrong_ip', 'expired', 'future'):
        key = ec.generate_private_key(ec.SECP256R1())
        issuer_key, issuer = (wrong_key, wrong_ca) if name == 'wrong_ca' else (ca_key, ca)
        start, end = now - timedelta(hours=1), now + timedelta(days=1)
        if name == 'expired':
            start, end = now - timedelta(days=3), now - timedelta(days=2)
        elif name == 'future':
            start, end = now + timedelta(days=2), now + timedelta(days=3)
        address = '127.0.0.2' if name == 'wrong_ip' else '127.0.0.1'
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic Engine Fixture')]))
                .issuer_name(issuer.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(address))]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(issuer_key, hashes.SHA256()))
        key_path, cert_path = root / (name + '.key'), root / (name + '.pem')
        write_new(key_path, key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        write_new(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        fixtures[name] = (cert_path, key_path)
    return ca.public_bytes(serialization.Encoding.DER), fixtures


PAGE = '''<!doctype html><html><head><title>Synthetic Sentinel fixture</title></head><body>
<h1 id="marker">Synthetic Sentinel engine fixture</h1>
<input id="username" value="sentinel"><input id="password" type="password">
<button id="login">Sign in</button><p id="result"></p>
<script>
window.fixtureLogin=null;
document.getElementById('login').onclick=async()=>{
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});
  window.fixtureLogin={status:r.status,data:await r.json()};
  document.getElementById('password').value='';
  document.getElementById('result').textContent=r.ok?'Signed in':'Failed';
};
</script></body></html>'''


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, certificate=None, key=None, *, capture=False):
        self.hits, self.requests, self.capture, self.annotations = 0, {}, capture, {}
        self.external_origin = None
        self.mutex = threading.Lock()
        super().__init__(('127.0.0.1', 0), FixtureHandler)
        if certificate:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certificate, key)
            self.socket = context.wrap_socket(self.socket, server_side=True)
        self.origin = ('https' if certificate else 'http') + '://127.0.0.1:' + str(self.server_port)
        self.thread = threading.Thread(target=self.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)
        require(not self.thread.is_alive(), 'E_FIXTURE_SERVER_STOP')


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def _count(self):
        self.connection.settimeout(3)
        with self.server.mutex:
            self.server.hits += 1
            self.server.requests[self.path] = self.server.requests.get(self.path, 0) + 1

    def _send(self, status, value, extra=None, html=False):
        body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        for name, val in (extra or {}).items():
            self.send_header(name, val)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        self.close_connection = True

    def _authenticated(self):
        return '__Host-sentinel-fixture=' + FIXTURE_COOKIE in self.headers.get('Cookie', '').split('; ')

    def do_GET(self):
        self._count()
        if self.server.capture:
            return self._send(200, 'Synthetic external capture', html=True)
        if self.path in ('/', '/login'):
            return self._send(200, PAGE, html=True)
        if self.path == '/redirect':
            return self._send(302, {}, {'Location': self.server.external_origin + '/redirect-target'})
        if self.path == '/attachment':
            return self._send(200, {'snapshot': {}, 'annotations': {}},
                              {'Content-Disposition': 'attachment; filename="synthetic.json"'})
        if self.path == '/api/session':
            return self._send(200 if self._authenticated() else 401,
                              {'ok': self._authenticated(), 'csrf_token': FIXTURE_CSRF} if self._authenticated() else {'error': 'E_LOGIN_REQUIRED'})
        if self.path == '/api/snapshot' and self._authenticated():
            return self._send(200, {'snapshot': {'synthetic': True, 'connections': [{'id': 'fixture-1'}]},
                                   'annotations': self.server.annotations})
        return self._send(404, {'error': 'E_NOT_FOUND'})

    def do_POST(self):
        self._count()
        try:
            length = int(self.headers.get('Content-Length', '0'))
            require(0 < length < 16384, 'E_FIXTURE_REQUEST')
            data = json.loads(self.rfile.read(length))
        except Exception:
            return self._send(400, {'error': 'E_FIXTURE_REQUEST'})
        if self.path == '/api/login':
            good = data == {'username': 'sentinel', 'password': FIXTURE_PASSWORD}
            return self._send(200 if good else 401, {'ok': good, 'csrf_token': FIXTURE_CSRF} if good else {'error': 'E_LOGIN'},
                {'Set-Cookie': '__Host-sentinel-fixture=' + FIXTURE_COOKIE + '; Path=/; Secure; HttpOnly; SameSite=Strict'} if good else None)
        if not self._authenticated() or self.headers.get('X-CSRF-Token') != FIXTURE_CSRF:
            return self._send(403, {'error': 'E_SESSION'})
        if self.path == '/api/review' and data == {'id': 'fixture-1', 'decision': 'recognize', 'note': 'Synthetic fixture'}:
            self.server.annotations['fixture-1'] = {'decision': 'recognize', 'note': 'Synthetic fixture'}
            return self._send(200, {'ok': True})
        if self.path == '/api/logout' and data == {}:
            return self._send(200, {'ok': True}, {'Set-Cookie': '__Host-sentinel-fixture=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'})
        return self._send(400, {'error': 'E_FIXTURE_REQUEST'})


class EngineHarness:
    def __init__(self, app, client, root, ca_der):
        self.app, self.client, self.root, self.ca_der = app, client, root, ca_der
        self.ca_hash = hashlib.sha256(ca_der).hexdigest()
        self.checks, self.windows, self.number = {}, [], 0

    def spin(self, condition, seconds=CASE_SECONDS):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.app.processEvents()
            if condition():
                return True
            time.sleep(0.005)
        return False

    def check(self, name, condition):
        self.checks[name] = bool(condition)
        PROGRESS_CHECKS[name] = bool(condition)
        checkpoint(PROGRESS_PHASE)

    def js(self, window, script, seconds=CASE_SECONDS):
        result = []
        window.page.runJavaScript(script, lambda value: result.append(value))
        require(self.spin(lambda: bool(result), seconds), 'E_JAVASCRIPT_TIMEOUT')
        return result[0]

    def async_js(self, window, expression):
        # Only trusted, synthetic fixture scripts are evaluated; not production data.
        self.js(window, "window.__fixtureResult=null;(async()=>{try{window.__fixtureResult={ok:true,value:await (" +
                expression + ")};}catch(e){window.__fixtureResult={ok:false};}})();")
        value = None
        def ready():
            nonlocal value
            value = self.js(window, 'JSON.stringify(window.__fixtureResult)', 2)
            return value is not None and value != 'null'
        require(self.spin(ready), 'E_ASYNC_FIXTURE_TIMEOUT')
        value = json.loads(value)
        require(value.get('ok') is True, 'E_ASYNC_FIXTURE_REJECTED')
        return value['value']

    def window(self, origin):
        checkpoint('create_window_' + str(self.number + 1))
        self.number += 1
        state = private_dir(self.root / ('state-' + str(self.number)))
        reports = private_dir(self.root / ('reports-' + str(self.number)))
        window = self.client.create_window(self.app, origin, self.ca_der, self.ca_hash, state, reports)
        window._fixture_reports = reports
        window._fixture_state = state
        window._fixture_index = self.number
        window._fixture_errors = []
        window.page.certificateError.connect(lambda _error: window._fixture_errors.append(True))
        self.windows.append(window)
        require(window.profile.isOffTheRecord(), 'E_NOT_OFF_THE_RECORD')
        extra = window.profile.additionalTrustedCertificates()
        require(len(extra) == 1 and hashlib.sha256(bytes(extra[0].toDer())).hexdigest() == self.ca_hash,
                'E_PROFILE_CA_MISMATCH')
        window.show()
        return window

    def load(self, window, url, *, blocked=False):
        from PySide6.QtCore import QUrl
        result = []
        def finished(ok):
            result.append(bool(ok))
        window.view.loadFinished.connect(finished)
        try:
            window.view.setUrl(QUrl(url))
            arrived = self.spin(lambda: bool(result), 1.5 if blocked else CASE_SECONDS)
            if blocked and not arrived:
                return False
            require(arrived, 'E_PAGE_LOAD_TIMEOUT')
            return result[-1]
        finally:
            window.view.loadFinished.disconnect(finished)

    def close(self, window):
        checkpoint('window_shutdown_' + str(window._fixture_index))
        window.shutdown()
        checkpoint('window_close_' + str(window._fixture_index))
        window.close()
        window.deleteLater()
        self.app.processEvents()
        checkpoint('window_closed_' + str(window._fixture_index))
        if window in self.windows:
            self.windows.remove(window)

    def renderer(self, window):
        pid = window.page.renderProcessPid()
        require(type(pid) is int and pid > 1, 'E_RENDERER_PID')
        path = Path('/proc') / str(pid)
        raw = (path / 'status').read_bytes()
        require(len(raw) <= 65536, 'E_RENDERER_STATUS_LIMIT')
        fields = dict(line.split(':', 1) for line in raw.decode('ascii', 'strict').splitlines() if ':' in line)
        self.check('renderer_uid_nonroot', all(int(value) > 0 for value in fields.get('Uid', '0').split()))
        self.check('renderer_capabilities_empty', int(fields.get('CapEff', '1').strip(), 16) == 0)
        self.check('renderer_seccomp_filter', fields.get('Seccomp', '').strip() == '2')
        self.check('renderer_no_new_privileges', fields.get('NoNewPrivs', '').strip() == '1')
        metadata = {}
        for name in ('user', 'pid', 'net'):
            try:
                metadata[name + '_namespace_separate'] = os.readlink(path / 'ns' / name) != os.readlink('/proc/self/ns/' + name)
            except OSError:
                metadata[name + '_namespace_observable'] = False
        try:
            label = (path / 'attr/current').read_bytes()
            require(len(label) <= 4096, 'E_APPARMOR_LABEL_LIMIT')
            label = label.strip()
            metadata['apparmor_label_observable'] = bool(label)
            name = label.rsplit(b' (', 1)[0]
            metadata['apparmor_named_profile_present'] = bool(name) and name != b'unconfined'
            metadata['apparmor_enforce_mode_observed'] = label.endswith(b' (enforce)')
        except OSError:
            metadata['apparmor_label_observable'] = False
        return metadata

    def login(self, window):
        self.js(window, "window.fixtureLogin=null;document.getElementById('password').value=" + json.dumps(FIXTURE_PASSWORD) +
                ";document.getElementById('login').click();")
        require(self.spin(lambda: self.js(window, 'window.fixtureLogin!==null', 2)), 'E_LOGIN_FIXTURE_TIMEOUT')
        return self.js(window, 'window.fixtureLogin.status') == 200

    def fetch(self, window, path, data=None):
        options = "{credentials:'same-origin',cache:'no-store'}"
        if data is not None:
            options = "{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':" + json.dumps(FIXTURE_CSRF) + "},body:" + json.dumps(json.dumps(data)) + "}"
        return self.async_js(window, "fetch(" + json.dumps(path) + "," + options + ").then(async r=>({status:r.status,data:await r.json()}))")

    def download(self, window, content, mime='application/json', name='../../escape.json'):
        self.js(window, "(()=>{let u=URL.createObjectURL(new Blob([" + json.dumps(content) +
                "],{type:" + json.dumps(mime) + "}));let a=document.createElement('a');a.href=u;a.download=" +
                json.dumps(name) + ";a.click();setTimeout(()=>URL.revokeObjectURL(u),3000);})();")


def worker(module_root, root):
    global PROGRESS_ROOT
    PROGRESS_ROOT = root
    checkpoint('worker_environment')
    environment_safe()
    signal.alarm(TOTAL_SECONDS)
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'
    sys.path.insert(0, str(module_root))
    from PySide6.QtWidgets import QApplication
    from sentinel_watch import console_client
    require(Path(console_client.__file__).resolve() == module_root / 'sentinel_watch' / 'console_client.py',
            'E_CLIENT_IMPORT_PROVENANCE')
    client_source_hash = hashlib.sha256(Path(console_client.__file__).read_bytes()).hexdigest()

    checkpoint('application_create')
    app = QApplication(['sentinel-engine-synthetic-acceptance'])
    app.setQuitOnLastWindowClosed(False)
    checkpoint('synthetic_certificates')
    ca_der, fixtures = certificates(root)
    servers, harness, metadata = [], None, {}
    try:
        checkpoint('synthetic_servers')
        good = FixtureServer(*fixtures['good']); servers.append(good)
        external = FixtureServer(*fixtures['good'], capture=True); servers.append(external)
        plain = FixtureServer(capture=True); servers.append(plain)
        good.external_origin = external.origin
        harness = EngineHarness(app, console_client, root, ca_der)
        window = harness.window(good.origin)
        checkpoint('good_page_load')
        harness.check('good_ca_document_loaded', harness.load(window, good.origin + '/') and
                      harness.js(window, "document.getElementById('marker').textContent") == 'Synthetic Sentinel engine fixture')
        harness.check('off_the_record', window.profile.isOffTheRecord())
        checkpoint('renderer_sandbox_metadata')
        metadata = harness.renderer(window)
        harness.check('good_ca_no_certificate_errors', not window._fixture_errors)
        checkpoint('synthetic_screenshot')
        from PySide6.QtCore import QBuffer, QIODevice
        harness.spin(lambda: False, 0.3)
        image = QBuffer()
        image.open(QIODevice.OpenModeFlag.WriteOnly)
        require(window.grab().save(image, 'PNG'), 'E_FIXTURE_SCREENSHOT')
        png = bytes(image.data())
        require(64 <= len(png) <= 4 * 1024 * 1024, 'E_FIXTURE_SCREENSHOT_SIZE')
        write_new(root / 'synthetic-window.png', png)
        harness.check('synthetic_window_screenshot', True)
        checkpoint('synthetic_login')
        harness.check('login_native_page', harness.login(window))
        checkpoint('synthetic_session')
        session = harness.fetch(window, '/api/session')
        harness.check('session_cookie_and_csrf', session['status'] == 200 and session['data']['csrf_token'] == FIXTURE_CSRF)
        checkpoint('synthetic_snapshot')
        snapshot = harness.fetch(window, '/api/snapshot')
        harness.check('snapshot_authenticated', snapshot['status'] == 200 and snapshot['data']['snapshot']['synthetic'] is True)
        checkpoint('synthetic_review')
        review = harness.fetch(window, '/api/review', {'id': 'fixture-1', 'decision': 'recognize', 'note': 'Synthetic fixture'})
        harness.check('review_synthetic_only', review['status'] == 200 and good.annotations.get('fixture-1', {}).get('decision') == 'recognize')
        checkpoint('synthetic_logout')
        logout = harness.fetch(window, '/api/logout', {})
        harness.check('logout_clears_session', logout['status'] == 200 and harness.fetch(window, '/api/session')['status'] == 401)
        checkpoint('synthetic_relogin')
        harness.check('login_again_for_restart', harness.login(window))
        # Restart without logout; server still accepts the old synthetic cookie.
        harness.close(window)
        window = harness.window(good.origin)
        checkpoint('restart_page_load')
        require(harness.load(window, good.origin + '/'), 'E_RESTART_PAGE')
        harness.check('restart_clears_profile_session', harness.fetch(window, '/api/session')['status'] == 401)

        for name in ('wrong_ca', 'wrong_ip', 'expired', 'future'):
            checkpoint('tls_case_' + name)
            server = FixtureServer(*fixtures[name]); servers.append(server)
            bad_window = harness.window(server.origin)
            loaded = harness.load(bad_window, server.origin + '/')
            harness.check(name + '_certificate_rejected', not loaded and bool(bad_window._fixture_errors) and server.hits == 0)
            harness.close(bad_window)

        # All origins below are disposable loopback fixtures. Never probe the LAN.
        checkpoint('cross_origin_resource_attempts')
        attacks = """(()=>{const u=EXTERNAL;fetch(u+'/fetch').catch(()=>{});
          let i=new Image();i.src=u+'/image';document.body.append(i);
          let f=document.createElement('iframe');f.src=u+'/frame';document.body.append(f);
          let s=document.createElement('script');s.src=u+'/script';document.body.append(s);
          window.open(u+'/window','_blank');window.open('/same-origin-window','_blank');
          try{new WebSocket(u.replace('https:','wss:')+'/socket')}catch(e){}
          fetch(PLAIN+'/downgrade').catch(()=>{});return true;})()"""
        harness.js(window, attacks.replace('EXTERNAL', json.dumps(external.origin)).replace('PLAIN', json.dumps(plain.origin)))
        harness.spin(lambda: False, 1.2)
        harness.check('external_subresources_and_windows_zero_hits', external.hits == 0 and plain.hits == 0
                      and good.requests.get('/same-origin-window', 0) == 0)
        checkpoint('cross_origin_redirect_attempt')
        prior_rejections = window.policy_rejections
        harness.load(window, good.origin + '/redirect', blocked=True)
        harness.spin(lambda: False, 0.4)
        harness.check('external_redirect_zero_hits', external.hits == 0 and window.policy_rejections > prior_rejections)
        require(harness.load(window, good.origin + '/'), 'E_RECOVER_AFTER_REDIRECT')
        checkpoint('cross_origin_navigation_attempt')
        prior_rejections = window.policy_rejections
        harness.load(window, external.origin + '/direct', blocked=True)
        harness.check('external_navigation_zero_hits', external.hits == 0 and window.policy_rejections > prior_rejections)
        require(harness.load(window, good.origin + '/'), 'E_RECOVER_AFTER_NAVIGATION')
        # A synthetic local file is safe to attempt; no real file is requested.
        forbidden = root / 'synthetic-navigation.html'
        write_new(forbidden, b'<title>SHOULD NEVER RENDER</title>')
        for label, target in (('file', forbidden.as_uri()), ('data', 'data:text/html,<title>SHOULD NEVER RENDER</title>')):
            checkpoint('blocked_scheme_' + label)
            prior_rejections = window.policy_rejections
            harness.load(window, target, blocked=True)
            harness.check(label + '_navigation_rejected', window.policy_rejections > prior_rejections
                          and harness.js(window, 'document.title') != 'SHOULD NEVER RENDER')
            require(harness.load(window, good.origin + '/'), 'E_RECOVER_AFTER_SCHEME')

        # Blob report is the sole download exception. The caller never picks a path.
        checkpoint('valid_json_blob_export')
        report_body = json.dumps({'snapshot': {'synthetic': True}, 'annotations': {}}, separators=(',', ':'))
        reports = window._fixture_reports
        checkpoint('second_json_blob_export')
        harness.download(window, report_body)
        require(harness.spin(lambda: len(list(reports.glob('*.json'))) == 1), 'E_GOOD_REPORT_TIMEOUT')
        first = next(reports.glob('*.json'))
        first_bytes = first.read_bytes()
        harness.check('same_origin_json_blob_export', first_bytes == report_body.encode()
                      and first.parent == reports and first.name != 'escape.json'
                      and not first.is_symlink() and stat.S_IMODE(first.stat().st_mode) == 0o600)
        harness.download(window, report_body)
        require(harness.spin(lambda: len(list(reports.glob('*.json'))) == 2), 'E_SECOND_REPORT_TIMEOUT')
        harness.check('reports_never_overwrite', first.read_bytes() == first_bytes)
        checkpoint('invalid_download_cases')
        for content, mime in ((report_body, 'application/octet-stream'), ('invalid json', 'application/json'),
                              (json.dumps({'wrong_schema': True}), 'application/json'),
                              ('x' * (MAX_EXPORT + 1), 'application/json')):
            before = window.download_counts['accepted'] + window.download_counts['rejected']
            harness.download(window, content, mime)
            require(harness.spin(lambda: window.download_counts['accepted'] + window.download_counts['rejected'] > before),
                    'E_DOWNLOAD_POLICY_TIMEOUT')
            require(harness.spin(lambda: not window.downloads), 'E_DOWNLOAD_COMPLETION_TIMEOUT')
        checkpoint('non_blob_attachment_attempt')
        harness.js(window, "(()=>{let a=document.createElement('a');a.href='/attachment';a.download='bad.json';a.click();})()")
        harness.spin(lambda: False, 1)
        harness.check('other_downloads_denied', len(list(reports.glob('*.json'))) == 2
                      and window.download_counts['published'] == 2 and not window.downloads)
        harness.check('export_cannot_escape_private_directory', not (root / 'escape.json').exists()
                      and not (root.parent / 'escape.json').exists())
        harness.check('private_state_and_reports', all(stat.S_IMODE(path.stat().st_mode) == 0o700 and
                      path.stat().st_uid == os.geteuid() for path in (window._fixture_state, reports)))
        # Scan only synthetic GUI state; never inspect production paths or key files.
        checkpoint('synthetic_private_state_scan')
        files, total = 0, 0
        secret_leak = False
        for directory in root.glob('state-*'):
            for path in directory.rglob('*'):
                info = path.lstat()
                require(not path.is_symlink(), 'E_STATE_SYMLINK')
                if stat.S_ISREG(info.st_mode):
                    files += 1; total += info.st_size
                    require(info.st_size <= 8 * 1024 * 1024 and total <= 32 * 1024 * 1024 and files <= 256, 'E_STATE_SCAN_LIMIT')
                    raw = path.read_bytes()
                    secret_leak |= FIXTURE_PASSWORD.encode() in raw or FIXTURE_COOKIE.encode() in raw
        harness.check('no_synthetic_credentials_in_state', not secret_leak)
        harness.check('external_servers_still_zero_hits', external.hits == 0 and plain.hits == 0)
        checkpoint('cases_complete')
        return {'ok': all(harness.checks.values()), 'checks': harness.checks,
                'renderer_metadata': metadata, 'error_code': None,
                'client_source_sha256': client_source_hash,
                'visual_render_verified': False,
                'synthetic_only': True, 'production_contacted': False,
                'production_credentials_used': False, 'sandbox_disabled': False}
    finally:
        if harness is not None:
            for window in list(harness.windows):
                try:
                    harness.close(window)
                except Exception:
                    pass
        for server in reversed(servers):
            server.close()
        app.processEvents()
        checkpoint('worker_cleanup_complete')


def stop_worker_group(process):
    """The group belongs only to our start_new_session child and its renderers."""
    require(process.pid > 1 and process.pid != os.getpgrp(), 'E_WORKER_GROUP')
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # The leader can exit while a renderer remains in this same owned group.
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        raise FixtureFailure('E_WORKER_GROUP_CLEANUP') from None


class SyntheticStderr:
    """Continuously drain the synthetic worker; retain at most 8 KiB in RAM."""
    def __init__(self, stream):
        self.stream, self.tail, self.total = stream, bytearray(), 0
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        try:
            while True:
                raw = self.stream.read(4096)
                if not raw:
                    return
                self.total = min(1_000_000_000, self.total + len(raw))
                self.tail.extend(raw)
                if len(self.tail) > STDERR_LIMIT:
                    del self.tail[:-STDERR_LIMIT]
        except (OSError, ValueError):
            return

    def finish(self):
        self.thread.join(timeout=2)
        return {'synthetic_stderr_tail': bytes(self.tail).decode('utf-8', 'replace'),
                'synthetic_stderr_bytes_captured': len(self.tail),
                'synthetic_stderr_truncated': self.total > STDERR_LIMIT,
                'synthetic_stderr_reader_finished': not self.thread.is_alive()}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Synthetic Qt-engine acceptance; no production access.')
    parser.add_argument('--module-root', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--worker-directory', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    started = time.time()
    report = {'ok': False, 'checks': {}, 'error_code': 'E_ENGINE_ACCEPTANCE',
              'synthetic_only': True, 'production_contacted': False,
              'production_credentials_used': False, 'sandbox_disabled': False}
    if args.worker_directory is not None:
        try:
            report = worker(args.module_root.resolve(strict=True), args.worker_directory.resolve(strict=True))
        except FixtureFailure as error:
            report['error_code'] = str(error) if re.fullmatch(r'E_[A-Z0-9_]{1,64}', str(error)) else 'E_FIXTURE_FAILURE'
        except ImportError:
            report['error_code'] = 'E_ENGINE_DEPENDENCY'
        except BaseException as error:
            report['error_code'] = 'E_ENGINE_RUNTIME'
            report['exception_class'] = type(error).__name__ if type(error).__name__ in (
                'RuntimeError', 'TypeError', 'ValueError', 'AttributeError', 'PermissionError',
                'FileNotFoundError', 'OSError', 'KeyError', 'IndexError', 'AssertionError') else 'Other'
        report['last_phase'] = PROGRESS_PHASE
        report['last_test_phase'] = PROGRESS_TEST_PHASE
        report['visual_render_verified'] = False
        if not report['checks']:
            report['checks'] = dict(PROGRESS_CHECKS)
        raw = json.dumps(report, sort_keys=True, allow_nan=False).encode()
        require(len(raw) <= MAX_REPORT, 'E_REPORT_LIMIT')
        write_new(args.report, raw, 0o600)
        return 0 if report['ok'] else 1
    try:
        environment_safe()
        module_root = args.module_root.resolve(strict=True)
        require((module_root / 'sentinel_watch' / 'console_client.py').is_file(), 'E_CLIENT_MODULE_MISSING')
        require(args.report.is_absolute() and not args.report.exists() and not args.report.is_symlink(), 'E_REPORT_PATH')
        with tempfile.TemporaryDirectory(prefix='sentinel-engine-synthetic-') as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            child_report = root / 'result.json'
            command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--module-root', str(module_root),
                       '--report', str(child_report), '--worker-directory', str(root)]
            process, diagnostic = None, None
            try:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.PIPE, start_new_session=True)
                diagnostic = SyntheticStderr(process.stderr)
                returncode = process.wait(timeout=TOTAL_SECONDS + 15)
                if child_report.exists():
                    raw = child_report.read_bytes()
                    require(len(raw) <= MAX_REPORT, 'E_REPORT_LIMIT')
                    report = json.loads(raw)
                    require(type(report.get('ok')) is bool and isinstance(report.get('checks'), dict), 'E_REPORT_SCHEMA')
                else:
                    report['error_code'] = 'E_ENGINE_PROCESS_EXIT'
                    progress = root / 'progress.json'
                    if progress.exists():
                        raw = progress.read_bytes()
                        require(len(raw) <= 16384, 'E_PROGRESS_LIMIT')
                        value = json.loads(raw)
                        require(set(value) == {'phase', 'test_phase', 'checks'} and
                                re.fullmatch(r'[a-z][a-z0-9_]{0,79}', value['phase']) and
                                re.fullmatch(r'[a-z][a-z0-9_]{0,79}', value['test_phase']) and
                                isinstance(value['checks'], dict) and
                                all(re.fullmatch(r'[a-z][a-z0-9_]{0,95}', name) and type(passed) is bool
                                    for name, passed in value['checks'].items()), 'E_PROGRESS_SCHEMA')
                        report['last_phase'], report['checks'] = value['phase'], value['checks']
                        report['last_test_phase'] = value['test_phase']
                report['worker_returncode'] = returncode
                report['worker_exit_success'] = returncode == 0
                report['ok'] = report['ok'] and returncode == 0
                screenshot = root / 'synthetic-window.png'
                if screenshot.exists():
                    png = screenshot.read_bytes()
                    require(64 <= len(png) <= 4 * 1024 * 1024, 'E_FIXTURE_SCREENSHOT_SIZE')
                    write_new(args.report.with_suffix('.synthetic.png'), png, 0o644)
                    report['synthetic_screenshot_saved'] = True
            except subprocess.TimeoutExpired:
                report['error_code'] = 'E_ENGINE_DEADLINE'
            finally:
                if process is not None:
                    stop_worker_group(process)
                    report['worker_returncode'] = process.returncode
                if diagnostic is not None:
                    report.update(diagnostic.finish())
    except FixtureFailure as error:
        report['error_code'] = str(error) if re.fullmatch(r'E_[A-Z0-9_]{1,64}', str(error)) else 'E_FIXTURE_FAILURE'
    except BaseException:
        report['error_code'] = 'E_ENGINE_PREPARATION'
    report['elapsed_seconds'] = round(time.time() - started, 2)
    raw = json.dumps(report, sort_keys=True, allow_nan=False).encode()
    require(len(raw) <= MAX_REPORT, 'E_REPORT_LIMIT')
    # Diagnostic stderr is synthetic-only, but keep the report private anyway.
    write_new(args.report, raw, 0o600)
    print(json.dumps({'ok': report['ok'], 'check_count': len(report['checks']),
                      'error_code': report['error_code']}, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
