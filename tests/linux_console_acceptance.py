"""Synthetic unprivileged Linux TLS acceptance; loopback only, no external calls.

Usage: python3 -B console-linux-acceptance.py --source-root /reviewed/bundle/src
Only its own temporary certificate, salted verifier and review DB are written.
No production configuration, sources, credentials, ports or services are changed.
If loopback 8443 is occupied, fail without stopping the existing listener.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time


class CheckFailure(Exception):
    pass


def main():
    checks = {}
    server = worker = None
    old_umask = None
    old_alarm = None
    phrase = None

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise CheckFailure()

    # Never print parsed arguments or exception text, including on usage errors.
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise CheckFailure()

    try:
        parser = Parser(add_help=False)
        parser.add_argument('--source-root', required=True)
        args = parser.parse_args()
        check('linux_unprivileged', sys.platform.startswith('linux') and os.geteuid() != 0)
        def deadline_expired(signum, frame):
            raise CheckFailure()
        old_alarm = signal.signal(signal.SIGALRM, deadline_expired)
        signal.setitimer(signal.ITIMER_REAL, 50)
        source = Path(args.source_root)
        check('source_package_present', source.is_absolute() and
              all((source/'sentinel_watch'/name).is_file() for name in
                  ('console.py', 'console_server.py', 'console_ui.py', 'dashboard.py')))
        check('openssl_present', Path('/usr/bin/openssl').is_file())
        sys.path.insert(0, str(source))
        sys.dont_write_bytecode = True
        from sentinel_watch.console_server import create_server
        from sentinel_watch.console import ReviewStore
        from sentinel_watch.dashboard import write_password_file

        old_umask = os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix='sentinel-console-acceptance-') as tmp:
            directory = Path(tmp)
            directory.chmod(0o700)
            key, certificate = directory/'server.key', directory/'server.crt'
            generated = subprocess.run([
                '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-sha256', '-days', '1', '-subj', '/CN=Sentinel Synthetic Acceptance',
                '-addext', 'subjectAltName=IP:127.0.0.1',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-keyout', str(key), '-out', str(certificate)],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=25, check=False,
                env={'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'OPENSSL_CONF':'/dev/null'})
            check('ephemeral_certificate_generated', generated.returncode == 0 and key.is_file() and certificate.is_file())
            key.chmod(0o600); certificate.chmod(0o600)
            phrase = secrets.token_urlsafe(36)
            auth_path = directory/'synthetic-auth.json'
            write_password_file(auth_path, phrase)
            check('salted_private_verifier_only', stat.S_IMODE(auth_path.stat().st_mode) == 0o600 and
                  phrase.encode() not in auth_path.read_bytes())
            store = ReviewStore(directory/'synthetic-reviews.sqlite3')
            calls = {'provider': 0}
            def feed():
                calls['provider'] += 1
                return {'connections':[{'id':'synthetic:connection-1',
                    'source':'synthetic', 'peer':'198.51.100.20', 'label':'Synthetic caf\u00e9 \u6771\u4eac'}],
                    'coverage':{'complete_visibility':False}}
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_cert_chain(certificate, key)
            config = {'bind':'127.0.0.1', 'port':8443, 'allowed_cidr':'127.0.0.0/8', 'auth_path':str(auth_path)}
            server = create_server(config, feed, store, tls)
            check('loopback_server_created', server.server_address == ('127.0.0.1',8443))
            worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval':0.05}, daemon=True)
            worker.start()
            client_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_tls.minimum_version = ssl.TLSVersion.TLSv1_2
            client_tls.load_verify_locations(cafile=certificate)
            check('client_verifies_certificate_and_hostname', client_tls.verify_mode == ssl.CERT_REQUIRED and client_tls.check_hostname)
            origin = 'https://127.0.0.1:8443'
            responses = []

            def request(method, path, *, data=None, cookie=None, csrf=None, extra=None):
                headers = {'Host':'127.0.0.1:8443'}
                body = None
                if data is not None:
                    body = json.dumps(data, ensure_ascii=False).encode('utf-8')
                    headers.update({'Content-Type':'application/json', 'Origin':origin})
                if cookie is not None: headers['Cookie'] = cookie
                if csrf is not None: headers['X-CSRF-Token'] = csrf
                headers.update(extra or {})
                connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=client_tls, timeout=7)
                try:
                    connection.request(method, path, body=body, headers=headers)
                    response = connection.getresponse()
                    raw = response.read(4*1024*1024+1)
                    values = {name.lower():value for name,value in response.getheaders()}
                    responses.append(raw)
                    return response.status, raw, values
                finally:
                    connection.close()

            check('wrong_host_unauthenticated_forbidden', request('GET','/api/snapshot',extra={'Host':'invalid.example:8443'})[0] == 403)
            check('wrong_origin_unauthenticated_forbidden', request('GET','/api/snapshot',extra={'Origin':'https://invalid.example'})[0] == 403)
            check('snapshot_requires_login', request('GET','/api/snapshot')[0] == 401 and calls['provider'] == 0)
            check('login_page_served_over_verified_tls', request('GET','/login')[0] == 200)
            untrusted_rejected = False
            untrusted = http.client.HTTPSConnection('127.0.0.1',8443,context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),timeout=5)
            try:
                untrusted.request('GET','/login')
                untrusted.getresponse()
            except ssl.SSLCertVerificationError:
                untrusted_rejected = True
            finally:
                untrusted.close()
            check('untrusted_certificate_rejected', untrusted_rejected)

            plaintext = b''
            with socket.create_connection(('127.0.0.1',8443),timeout=3) as raw_socket:
                raw_socket.settimeout(6)
                try:
                    raw_socket.sendall(b'GET /login HTTP/1.1\r\nHost: 127.0.0.1:8443\r\nConnection: close\r\n\r\n')
                    plaintext = raw_socket.recv(4096)
                except OSError:
                    pass
            check('plaintext_http_not_served', b'HTTP/' not in plaintext and b'<html' not in plaintext.lower())

            check('bad_login_denied', request('POST','/api/login',data={'username':'sentinel','password':'not-the-synthetic-passphrase'})[0] == 401)
            status, raw, headers = request('POST','/api/login',data={'username':'sentinel','password':phrase})
            check('valid_login_accepted', status == 200)
            cookie_header = headers.get('set-cookie','')
            cookie = cookie_header.split(';')[0]
            csrf = json.loads(raw)['csrf_token']
            check('secure_session_cookie', cookie.startswith('__Host-sentinel=') and
                  all(part in cookie_header for part in ('; Secure','; HttpOnly','; SameSite=Strict','; Path=/')))
            status, raw, _ = request('GET','/api/session',cookie=cookie)
            check('authenticated_session_read', status == 200 and json.loads(raw)['csrf_token'] == csrf)
            status, raw, headers = request('GET','/',cookie=cookie)
            check('authenticated_ui_served', status == 200 and b'<html' in raw.lower() and
                  b'__NONCE__' not in raw and 'nonce-' in headers.get('content-security-policy',''))
            status, raw, _ = request('GET','/api/snapshot',cookie=cookie)
            snapshot = json.loads(raw)
            check('actual_snapshot_contract', status == 200 and snapshot['annotations'] == {} and
                  snapshot['snapshot']['connections'][0]['id'] == 'synthetic:connection-1')
            note = 'Investigate caf\u00e9 \u6771\u4eac \u2194 evidence'
            review = {'id':'synthetic:connection-1','decision':'investigate','note':note}
            check('mutation_without_csrf_denied', request('POST','/api/review',data=review,cookie=cookie)[0] == 403)
            check('mutation_wrong_origin_denied', request('POST','/api/review',data=review,cookie=cookie,csrf=csrf,
                  extra={'Origin':'https://invalid.example'})[0] == 403)
            status, raw, _ = request('POST','/api/review',data=review,cookie=cookie,csrf=csrf)
            check('review_annotation_only', status == 200 and json.loads(raw)['annotation']['traffic_changed'] is False)
            status, raw, _ = request('GET','/api/snapshot',cookie=cookie)
            check('unicode_review_durably_roundtrips', status == 200 and
                  json.loads(raw)['annotations']['synthetic:connection-1']['note'] == note and
                  ReviewStore(store.path).annotations()['synthetic:connection-1']['note'] == note)
            check('enforcement_endpoint_absent', request('POST','/api/block',data={},cookie=cookie,csrf=csrf)[0] == 404)
            status, _, headers = request('POST','/api/logout',data={},cookie=cookie,csrf=csrf)
            check('logout_revokes_session', status == 200 and 'Max-Age=0' in headers.get('set-cookie','') and
                  request('GET','/api/snapshot',cookie=cookie)[0] == 401)
            check('synthetic_password_not_in_responses', all(phrase.encode() not in value for value in responses))
            check('private_review_database', stat.S_IMODE(store.path.stat().st_mode) == 0o600 and store.path.stat().st_nlink == 1)
            phrase = None
    except BaseException:
        checks['completed_without_unexpected_error'] = False
    finally:
        phrase = None
        if old_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_alarm)
        if server is not None:
            started = time.monotonic()
            stopper = threading.Thread(target=server.shutdown, daemon=True)
            stopper.start(); stopper.join(3)
            server.server_close()
            if worker is not None: worker.join(3)
            checks['server_stop_bounded'] = (not stopper.is_alive() and
                (worker is None or not worker.is_alive()) and time.monotonic()-started < 7)
        if old_umask is not None:
            os.umask(old_umask)
    ok = bool(checks) and all(checks.values())
    print(json.dumps({'ok':ok,'test_count':len(checks),'checks':checks},sort_keys=True))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
