"""Offline synthetic console fixtures. No sockets, real accounts or host capture."""
import io
from email.message import Message
import json
from pathlib import Path
import ssl
import types
import unittest
from unittest.mock import Mock, patch

from sentinel_watch import console_server as c


def config():
    return {'bind': '192.0.2.10', 'port': 8443, 'allowed_cidr': '192.0.2.0/24',
            'auth_path': str(Path(__file__).absolute().parent / 'synthetic-not-read.json')}


class Store:
    def __init__(self):
        self.values, self.calls = {}, []

    def annotations(self):
        return self.values.copy()

    def update_review(self, ident, decision, note):
        self.calls.append((ident, decision, note))
        value = {'decision': decision, 'note': note, 'updated_at': 1000000}
        self.values[ident] = value
        return value.copy()


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.auth = Mock()
        self.auth.verify.side_effect = lambda username, password: username == 'sentinel' and password == 'FAKE_ONLY_password'
        self.provider = Mock(return_value={'connections': [{'id': 'observed-1', 'peer': '198.51.100.20'}],
                                         'coverage': {'complete_visibility': False}})
        self.store = Store()
        self.app = c.ConsoleApp(config(), self.provider, self.store, self.auth, clock=lambda: self.now)
        self.cookie, self.csrf = '', ''

    def request(self, path='/api/snapshot', *, method='GET', data=None, headers=None, peer='192.0.2.20', raw=None):
        values = {'Host': self.app.host}
        if self.cookie:
            values['Cookie'] = self.cookie
        if method == 'POST':
            values.update({'Origin': self.app.origin, 'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf})
        values.update(headers or {})
        body = raw if raw is not None else b'' if data is None else json.dumps(data).encode()
        return self.app.dispatch(method, path, values, body, client_ip=peer)

    def login(self, peer='192.0.2.20'):
        response = self.request('/api/login', method='POST', data={'username': 'sentinel', 'password': 'FAKE_ONLY_password'}, peer=peer)
        self.assertEqual(response[0], 200)
        self.cookie = response[2]['Set-Cookie'].split(';')[0]
        self.csrf = json.loads(response[1])['csrf_token']
        return response

    def review(self, **changes):
        value = {'id': 'observed-1', 'decision': 'investigate', 'note': 'Check with the owner.'}
        value.update(changes)
        return self.request('/api/review', method='POST', data=value)

    def test_only_login_html_is_public_and_provider_is_not_called(self):
        response = self.request('/')
        self.assertEqual(response[0], 303)
        self.assertEqual(response[2]['Location'], '/login')
        for path in ('/api/session', '/api/snapshot'):
            self.assertEqual(self.request(path)[0], 401)
        login = self.request('/login')
        self.assertEqual(login[0], 200)
        self.assertIn(b'type="password"', login[1])
        self.assertNotIn(b'__NONCE__', login[1])
        self.assertIn("script-src 'nonce-", login[2]['Content-Security-Policy'])
        self.assertNotIn(b'198.51.100.20', login[1])
        self.provider.assert_not_called()

    def test_host_secure_cookie_and_session_contract(self):
        response = self.login()
        cookie = response[2]['Set-Cookie']
        for part in ('__Host-sentinel=', '; Secure', '; HttpOnly', '; SameSite=Strict', '; Path=/'):
            self.assertIn(part, cookie)
        self.assertNotIn('Domain=', cookie)
        self.assertNotIn(b'FAKE_ONLY_password', response[1])
        self.assertEqual(json.loads(self.request('/api/session')[1]), {'ok': True, 'csrf_token': self.csrf})
        self.assertEqual(self.request(peer='192.0.2.21')[0], 401)

    def test_snapshot_and_authenticated_html_are_bounded_data_only(self):
        self.login()
        snapshot = self.request()
        self.assertEqual(snapshot[0], 200)
        self.assertEqual(json.loads(snapshot[1]), {'snapshot': self.provider.return_value, 'annotations': {}})
        self.assertEqual(snapshot[2]['Cache-Control'], 'no-store')
        self.assertNotIn('Access-Control-Allow-Origin', snapshot[2])
        module = types.SimpleNamespace(HTML='<html><script nonce="__NONCE__"></script></html>')
        with patch.dict('sys.modules', {'sentinel_watch.console_ui': module}):
            page = self.request('/')
        self.assertEqual(page[0], 200)
        self.assertNotIn(b'__NONCE__', page[1])

    def test_cidr_ipv6_forwarding_and_host_origin_rebinding_rejected(self):
        self.login()
        for peer in ('198.51.100.20', '::1', '::ffff:192.0.2.20', 'not-an-address'):
            with self.subTest(peer=peer):
                self.assertEqual(self.request(peer=peer)[0], 403)
        for headers in ({'Host': 'attacker.invalid:8443'}, {'Origin': 'https://attacker.invalid'},
                        {'Origin': 'http://192.0.2.10:8443'}, {'Sec-Fetch-Site': 'cross-site'},
                        {'Forwarded': 'for=192.0.2.20'}, {'X-Forwarded-For': '192.0.2.20'},
                        {'X-Forwarded-Proto': 'https'}, {'X-Real-IP': '192.0.2.20'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request(headers=headers)[0], 403)
        self.provider.reset_mock()
        response = self.app.dispatch('GET', '/api/snapshot', [('Host', self.app.host), ('host', self.app.host)], client_ip='192.0.2.20')
        self.assertEqual(response[0], 400)
        self.provider.assert_not_called()

    def test_review_needs_auth_origin_csrf_and_never_enforces(self):
        self.assertEqual(self.review()[0], 401)
        self.login()
        data = {'id': 'observed-1', 'decision': 'recognize', 'note': ''}
        for headers in ({'X-CSRF-Token': ''}, {'Origin': 'null'}, {'Origin': ''}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('/api/review', method='POST', data=data, headers=headers)[0], 403)
        for decision in sorted(c.DECISIONS):
            response = self.review(decision=decision)
            self.assertEqual(response[0], 200)
            self.assertEqual(json.loads(response[1])['annotation']['decision'], decision)
        for decision in ('approve', 'reject', 'disconnect', 'block', 'allow', 'revoke'):
            with self.subTest(decision=decision):
                self.assertEqual(self.review(decision=decision)[0], 400)
        self.assertEqual(len(self.store.calls), 3)

    def test_stale_id_and_note_limits_do_not_update_store(self):
        self.login()
        self.assertEqual(self.review(id='absent')[0], 409)
        for changes in ({'id': '../private'}, {'note': 'x' * 501}, {'note': 'line\nbreak'},
                        {'note': 'control\x7f'}, {'note': None}, {'decision': []}):
            with self.subTest(changes=changes):
                self.assertEqual(self.review(**changes)[0], 400)
        self.assertEqual(self.store.calls, [])
        self.assertEqual(self.review(note='x' * 500)[0], 200)

    def test_provider_failures_secrets_duplicate_ids_and_nonfinite_values_fail_closed(self):
        self.login()
        for value in ({'connections': [{'id': 'same'}, {'id': 'same'}]},
                      {'connections': [], 'password': 'FAKE_PRIVATE_VALUE'},
                      {'connections': [], 'nested': {'topic': 'FAKE_PRIVATE_VALUE'}},
                      {'connections': [], 'value': float('nan')},
                      {'connections': [], 'value': 'x' * 65537},
                      {'connections': [{'missing_id': True}]}, {'wrong': []}):
            self.provider.return_value = value
            with self.subTest(keys=list(value)):
                response = self.request()
                self.assertNotEqual(response[0], 200)
                self.assertNotIn(b'FAKE_PRIVATE_VALUE', response[1])
        self.provider.side_effect = RuntimeError('FAKE_PRIVATE_ERROR')
        response = self.request()
        self.assertEqual(response[0], 503)
        self.assertNotIn(b'FAKE_PRIVATE_ERROR', response[1])

    def test_annotation_credentials_and_store_errors_are_not_returned(self):
        self.login()
        self.store.values = {'observed-1': {'token': 'FAKE_PRIVATE_VALUE'}}
        response = self.request()
        self.assertNotEqual(response[0], 200)
        self.assertNotIn(b'FAKE_PRIVATE_VALUE', response[1])
        self.store.update_review = Mock(side_effect=RuntimeError('FAKE_PRIVATE_ERROR'))
        response = self.review()
        self.assertEqual(response[0], 503)
        self.assertNotIn(b'FAKE_PRIVATE_ERROR', response[1])

    def test_login_rate_is_bounded_per_peer_and_globally(self):
        for _ in range(5):
            self.assertEqual(self.request('/api/login', method='POST', data={'username': 'sentinel', 'password': 'wrong'})[0], 401)
        self.assertEqual(self.request('/api/login', method='POST', data={'username': 'sentinel', 'password': 'FAKE_ONLY_password'})[0], 429)
        self.login(peer='192.0.2.21')
        self.now += 61
        self.login()
        for index in range(25):
            peer = '192.0.2.' + str(30 + index)
            self.assertEqual(self.request('/api/login', method='POST', data={'username': 'sentinel', 'password': 'wrong'}, peer=peer)[0], 401)
        self.assertEqual(self.request('/api/login', method='POST', data={'username': 'sentinel', 'password': 'FAKE_ONLY_password'}, peer='192.0.2.99')[0], 429)
        self.assertEqual(len(self.app.failures), 25)

    def test_absolute_idle_expiry_and_logout_invalidate_session(self):
        self.login()
        self.now += c.IDLE_SECONDS
        self.assertEqual(self.request()[0], 401)
        self.login()
        for _ in range(c.SESSION_SECONDS // 600):
            self.now += 600
            response = self.request('/api/session')
        self.assertEqual(response[0], 401)
        self.login()
        response = self.request('/api/logout', method='POST', data={})
        self.assertEqual(response[0], 200)
        self.assertIn('Secure', response[2]['Set-Cookie'])
        self.assertIn('Max-Age=0', response[2]['Set-Cookie'])
        self.assertEqual(self.request()[0], 401)

    def test_methods_paths_content_type_body_and_extra_fields_are_strict(self):
        self.login()
        for path in ('https://192.0.2.10:8443/api/snapshot', '/api/snapshot?x=1', '/api/snapshot#x'):
            self.assertEqual(self.request(path)[0], 400)
        self.assertEqual(self.request(method='PUT')[0], 405)
        self.assertEqual(self.request('/api/review', method='POST', data={}, headers={'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(self.request('/api/review', method='POST', raw=b'x' * (c.MAX_BODY + 1))[0], 400)
        self.assertEqual(self.request('/api/review', method='POST', raw=b'{}', headers={'Transfer-Encoding': 'chunked'})[0], 400)
        self.assertEqual(self.request('/api/review', method='POST', data={'id': 'observed-1', 'decision': 'recognize', 'note': '', 'command': 'never'})[0], 400)
        self.assertEqual(self.store.calls, [])

    def test_duplicate_json_fields_depth_and_encoded_size_fail_closed(self):
        self.login()
        raw = b'{"id":"observed-1","decision":"recognize","note":"first","note":"second"}'
        self.assertEqual(self.request('/api/review', method='POST', raw=raw)[0], 400)
        self.assertEqual(self.store.calls, [])
        deep = []
        for _ in range(20):
            deep = [deep]
        for value in (deep, ['x' * 65536] * 70, ['\u2000' * 65536] * 12):
            with self.subTest(kind=type(value).__name__), self.assertRaises(c.ConsoleError):
                c._json(value)


class ServerBoundaryTests(unittest.TestCase):
    def test_config_rejects_wildcard_ipv6_wrong_cidr_port_and_extra_options(self):
        for changes in ({'bind': '0.0.0.0'}, {'bind': '::'}, {'bind': 'router.invalid'},
                        {'allowed_cidr': '0.0.0.0/0'}, {'allowed_cidr': '198.51.100.0/24'},
                        {'allowed_cidr': '192.0.2.1/24'}, {'port': 443}, {'port': True},
                        {'auth_path': 'relative'}, {'proxy': True}):
            value = config(); value.update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(c.ConsoleError, '^E_CONSOLE_CONFIG$'):
                c.validate_config(value)

    def test_tls_and_unprivileged_checks_precede_auth_read_or_listener(self):
        with patch.object(c, 'PasswordAuth', side_effect=AssertionError('auth read')), \
             patch.object(c, '_TLSServer', side_effect=AssertionError('socket')):
            if c.os.name == 'posix':
                with patch.object(c.os, 'geteuid', return_value=0), self.assertRaisesRegex(c.ConsoleError, 'E_UNPRIVILEGED_REQUIRED'):
                    c.create_server(config(), Mock(), Mock(), None)
            with patch.object(c.os, 'geteuid', return_value=1000, create=True):
                insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                insecure.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                for context in (None, ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), insecure):
                    with self.subTest(context=type(context).__name__), self.assertRaisesRegex(c.ConsoleError, 'E_TLS_CONTEXT'):
                        c.create_server(config(), Mock(), Mock(), context)

    def test_factory_passes_explicit_tls_context_and_never_uses_http_server_directly(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with patch.object(c.os, 'geteuid', return_value=1000, create=True), \
             patch.object(c, 'PasswordAuth') as auth, patch.object(c, '_TLSServer') as server:
            result = c.create_server(config(), Mock(), Store(), context)
        self.assertIs(result, server.return_value)
        self.assertEqual(server.call_args.args[0], ('192.0.2.10', 8443))
        self.assertIs(server.call_args.args[3], context)
        auth.assert_called_once_with(Path(config()['auth_path']))

    def test_handshake_must_finish_before_http_dispatch_and_has_deadline(self):
        server = object.__new__(c._TLSServer)
        server.tls_context, server._slots = Mock(), Mock()
        server.finish_request = Mock()
        raw, encrypted = Mock(), Mock()
        server.tls_context.wrap_socket.return_value = encrypted
        calls = []
        encrypted.do_handshake.side_effect = lambda: calls.append('handshake')
        server.finish_request.side_effect = lambda *_: calls.append('http')
        with patch.object(c.threading, 'Timer') as timer:
            server.process_request_thread(raw, ('192.0.2.20', 12345))
        self.assertEqual(calls, ['handshake', 'http'])
        server.tls_context.wrap_socket.assert_called_once_with(raw, server_side=True, do_handshake_on_connect=False)
        timer.assert_called_once_with(c.CONNECTION_SECONDS, c._close_socket, args=(encrypted,))
        timer.return_value.start.assert_called_once(); timer.return_value.cancel.assert_called_once()
        server._slots.release.assert_called_once()

    def test_failed_tls_and_saturated_workers_never_parse_plaintext(self):
        server = object.__new__(c._TLSServer)
        server.tls_context, server._slots, server.finish_request = Mock(), Mock(), Mock()
        raw, encrypted = Mock(), Mock()
        encrypted.do_handshake.side_effect = ssl.SSLError('FAKE_PRIVATE_TLS_ERROR')
        server.tls_context.wrap_socket.return_value = encrypted
        with patch.object(c.threading, 'Timer'):
            server.process_request_thread(raw, ('192.0.2.20', 12345))
        server.finish_request.assert_not_called()
        encrypted.close.assert_called_once(); server._slots.release.assert_called_once()
        server._slots.acquire.return_value = False
        server.tls_context.reset_mock()
        server.process_request(raw, ('192.0.2.20', 12345))
        server.tls_context.wrap_socket.assert_not_called()
        raw.close.assert_called_once()

    def test_pre_handshake_cidr_gate_and_wire_budget(self):
        server = object.__new__(c._TLSServer)
        server.app = c.ConsoleApp(config(), Mock(), Store(), Mock())
        self.assertFalse(server.verify_request(Mock(), ('198.51.100.20', 12345)))
        self.assertTrue(server.verify_request(Mock(), ('192.0.2.20', 12345)))
        stream = c._BoundedInput(io.BytesIO(b'x' * (c.MAX_WIRE + 1)))
        self.assertEqual(len(stream.read(c.MAX_WIRE)), c.MAX_WIRE)
        with self.assertRaises(OSError):
            stream.read(1)

    def test_http_adapter_rejects_ambiguous_or_truncated_framing_before_dispatch(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with patch.object(c.os, 'geteuid', return_value=1000, create=True), \
             patch.object(c, 'PasswordAuth'), patch.object(c, '_TLSServer') as server:
            c.create_server(config(), Mock(), Store(), context)
        handler_class = server.call_args.args[1]
        cases = [([('Content-Length', '2'), ('Content-Length', '2')], b'{}'),
                 ([('Transfer-Encoding', 'chunked')], b'{}'),
                 ([('Content-Length', '-1')], b''),
                 ([('Content-Length', str(c.MAX_BODY + 1))], b''),
                 ([('Content-Length', 'invalid')], b''),
                 ([('Content-Length', '5')], b'{}')]
        for fields, body in cases:
            handler = object.__new__(handler_class)
            handler.command, handler.path = 'POST', '/api/review'
            handler.client_address = ('192.0.2.20', 12345)
            handler.headers, handler.rfile = Message(), io.BytesIO(body)
            for key, value in fields:
                handler.headers[key] = value
            handler.server, handler._write = Mock(), Mock()
            with self.subTest(fields=fields):
                handler._handle()
                self.assertEqual(handler._write.call_args.args[0][0], 400)
                handler.server.app.dispatch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
