"""Offline behavioral fixtures for the Sentinel alert outbox; stdlib only."""
from collections import deque
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from email.utils import format_datetime
from email.message import Message
import io
import json
import os
from pathlib import Path
import random
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit
import urllib.error
import urllib.request
import urllib.response

from sentinel_watch import alerts as sut


class Clock:
    def __init__(self):
        self.now = 2_000_000_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeTransport:
    """A tiny cached ntfy model with explicit per-request failure injection."""
    def __init__(self, topic):
        self.topic = topic
        self.calls = []
        self.actions = deque()
        self.messages = []

    def response(self, status, value, headers=None):
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        return sut.HttpResponse(status=status, body=body, headers=headers or {})

    def accept(self, body, sequence_id=None):
        record = {'id': 'fixture-' + str(len(self.messages) + 1), 'event': 'message',
                  'topic': self.topic, 'message': body.decode('utf-8'), 'time': 2_000_000_000}
        if sequence_id is not None:
            record['sequence_id'] = sequence_id
        self.messages.append(record)
        return self.response(200, record)

    def request(self, method, url, headers, body=None):
        self.calls.append({'method': method, 'url': url, 'headers': dict(headers), 'body': body})
        if self.actions:
            expected_method, action = self.actions.popleft()
            if method != expected_method:
                raise AssertionError('Unexpected request order in fixture')
            if isinstance(action, BaseException):
                raise action
            if callable(action):
                return action(method, url, headers, body)
            if action is not None:
                return action
        if method == 'POST':
            return self.accept(body, headers.get('X-Sequence-ID'))
        if method != 'GET':
            raise AssertionError('Unexpected method in fixture')
        query = parse_qs(urlsplit(url).query)
        messages = self.messages
        if 'id' in query:
            messages = [row for row in messages if row['id'] == query['id'][0]]
        if 'message' in query:
            messages = [row for row in messages if row['message'] == query['message'][0]]
        return self.response(200, b''.join(json.dumps(row).encode() + b'\n' for row in messages))

    def methods(self):
        return [call['method'] for call in self.calls]

    def posts(self):
        return [call for call in self.calls if call['method'] == 'POST']


class AlertEngineTests(unittest.TestCase):
    def setUp(self):
        # Fail immediately if a regression escapes the injected transport.
        for target in ('socket.getaddrinfo', 'socket.socket.connect', 'socket.socket.connect_ex'):
            patcher = mock.patch(target, side_effect=AssertionError('Real network forbidden in tests'))
            patcher.start()
            self.addCleanup(patcher.stop)
        if os.name == 'nt':
            # Windows 3.14's mkdir0700 DACL excludes the test AppContainer.
            # Inherit the workspace DACL in this fixture only; POSIX checks stay intact.
            real_mkdir = os.mkdir
            def inherited_directory_mode(path, mode=0o777, *, dir_fd=None):
                mode = 0o777 if mode == 0o700 else mode
                return real_mkdir(path, mode) if dir_fd is None else real_mkdir(path, mode, dir_fd=dir_fd)
            patcher = mock.patch('os.mkdir', side_effect=inherited_directory_mode)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.scratch_parent = Path(__file__).resolve().parent
        self.directory = tempfile.TemporaryDirectory(prefix='.sentinel-tests-', dir=self.scratch_parent)
        self.addCleanup(self.cleanup_directory)
        self.state = Path(self.directory.name) / 'state'
        self.clock = Clock()
        self.health = {'fixture': True}
        self.config = sut.Config(base_url='https://ntfy.test.invalid', topic='fixture-private-topic',
                                 token='FAKE_ONLY_token_7465_no_real_credential')
        self.http = FakeTransport(self.config.topic)
        self.engines = []
        self.addCleanup(self.close_engines)
        self.engine = self.new_engine()
        # Drain the one boot event and establish healthy transition counters.
        for _ in range(3):
            self.engine.tick()
            self.clock.advance(1)
        self.http.calls.clear()

    def close_engines(self):
        for engine in self.engines:
            if callable(getattr(engine, 'close', None)):
                engine.close()

    def cleanup_directory(self):
        self.assertEqual(Path(self.directory.name).resolve().parent, self.scratch_parent)
        self.directory.cleanup()

    def new_engine(self, *, state=None, **options):
        engine = sut.AlertEngine(state or self.state, self.config, transport=self.http, clock=self.clock,
                                 check_provider=lambda: dict(self.health),
                                 boot_id_provider=lambda: 'fixture-same-boot', rng=random.Random(7), **options)
        self.engines.append(engine)
        return engine

    def later(self, seconds=86_401):
        self.clock.advance(seconds)
        return self.engine.tick()

    def test_pending_event_survives_restart_and_is_sent_once(self):
        event = self.engine.enqueue_test()
        self.engine = self.new_engine()
        self.engine.tick()
        self.assertEqual(self.http.methods(), ['POST', 'GET'])
        self.assertEqual(self.http.posts()[0]['headers']['X-Sequence-ID'], event)
        self.assertNotIn(event.encode(), self.http.posts()[0]['body'])
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(len(self.http.posts()), 1)

    def test_full_queue_rolls_back_observation_but_drains_then_allows_boot(self):
        state = self.state.parent / 'full-outbox'
        engine = self.new_engine(state=state, max_events=1)
        existing = engine.enqueue_test()
        first = engine.tick()
        self.assertFalse(first['ok'])
        self.assertEqual(first['last_error'], 'E_QUEUE_FULL')
        self.assertEqual(first['outbox']['verified'], 1)
        self.assertEqual(first['health_state'], 'unknown')
        self.assertEqual(first['consecutive_successes'], 0)
        self.assertIsNone(first['checked_at'])
        self.assertEqual(self.http.posts()[0]['headers']['X-Sequence-ID'], existing)
        self.assertNotIn(existing.encode(), self.http.posts()[0]['body'])
        # Restart proves the failed observation did not commit its boot marker.
        self.clock.advance(1)
        engine = self.new_engine(state=state, max_events=1)
        second = engine.tick()
        self.assertTrue(second['ok'])
        self.assertEqual(second['health_state'], 'healthy')
        self.assertEqual(len(self.http.posts()), 2)
        self.assertNotEqual(self.http.posts()[0]['body'], self.http.posts()[1]['body'])
        engine.tick()
        self.assertEqual(len(self.http.posts()), 2)

    def test_single_run_lock_rejects_concurrent_engine_tick(self):
        with sut._FileLock(self.state / 'run.lock'):
            with self.assertRaises(sut.SafeError) as caught:
                self.engine.tick()
            self.assertEqual(caught.exception.code, 'E_BUSY')
            self.assertEqual(self.http.calls, [])
        self.assertTrue(self.engine.tick()['ok'])

    def test_down_and_recovery_transitions_deduplicate_across_restart(self):
        self.health['fixture'] = False
        self.engine.tick()
        self.assertEqual(self.http.methods(), [])
        self.engine.tick()
        self.assertEqual(len(self.http.posts()), 1)
        down_body = self.http.posts()[0]['body']
        self.engine = self.new_engine()
        for _ in range(4):
            self.later()
        self.assertEqual(len(self.http.posts()), 1)
        self.health['fixture'] = True
        self.engine.tick()
        self.assertEqual(len(self.http.posts()), 1)
        self.engine.tick()
        self.assertEqual(len(self.http.posts()), 2)
        self.assertNotEqual(down_body, self.http.posts()[1]['body'])
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(len(self.http.posts()), 2)

    def test_accepted_publish_readback_failure_never_reposts_after_restart(self):
        self.engine.enqueue_test()
        self.http.actions.extend([('POST', None), ('GET', self.http.response(503, {'error': 'temporary'}))])
        self.engine.tick()
        self.assertEqual(self.http.methods(), ['POST', 'GET'])
        accepted_id = self.http.messages[-1]['id']
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(self.http.methods(), ['POST', 'GET', 'GET'])
        self.assertEqual(parse_qs(urlsplit(self.http.calls[-1]['url']).query).get('id'), [accepted_id])
        self.later()
        self.assertEqual(len(self.http.posts()), 1)

    def test_timeout_after_acceptance_reads_back_before_any_republish(self):
        event = self.engine.enqueue_test()
        def accepted_then_timeout(method, url, headers, body):
            self.http.accept(body, headers.get('X-Sequence-ID'))
            raise sut.TransportError('E_NETWORK')
        self.http.actions.append(('POST', accepted_then_timeout))
        self.engine.tick()
        self.assertEqual(self.http.methods(), ['POST'])
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(self.http.methods(), ['POST', 'GET'])
        query = parse_qs(urlsplit(self.http.calls[-1]['url']).query)
        self.assertEqual(query['message'][0], self.http.posts()[0]['body'].decode())
        self.assertNotIn(event, query['message'][0])
        self.assertEqual(self.http.posts()[0]['headers']['X-Sequence-ID'], event)
        self.later()
        self.assertEqual(len(self.http.posts()), 1)

    def test_timeout_without_acceptance_checks_cache_then_defers_republish(self):
        self.engine.enqueue_test()
        self.http.actions.append(('POST', sut.TransportError('E_NETWORK')))
        self.engine.tick()
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(self.http.methods(), ['POST', 'GET'])
        self.later()
        self.assertEqual(self.http.methods(), ['POST', 'GET', 'POST', 'GET'])

    def test_retry_after_numeric_is_a_minimum_not_an_immediate_retry(self):
        self.engine.enqueue_test()
        self.http.actions.append(('POST', self.http.response(429, {'code': 42901}, {'Retry-After': '120'})))
        self.engine.tick()
        self.later(119)
        self.assertEqual(len(self.http.posts()), 1)
        self.later(3_600)
        self.assertEqual(len(self.http.posts()), 2)

    def test_retry_after_http_date_is_honored(self):
        self.engine.enqueue_test()
        retry_at = format_datetime(datetime.fromtimestamp(self.clock() + 180, timezone.utc), usegmt=True)
        self.http.actions.append(('POST', self.http.response(429, {'code': 42901}, {'Retry-After': retry_at})))
        self.engine.tick()
        self.later(179)
        self.assertEqual(len(self.http.posts()), 1)
        self.later(3_600)
        self.assertEqual(len(self.http.posts()), 2)

    def test_retry_after_parser_rejects_invalid_and_caps_extreme_values(self):
        self.assertEqual(sut.retry_after_seconds('120', self.clock()), 120)
        self.assertEqual(sut.retry_after_seconds('999999999', self.clock()), 86_400)
        value = sut.retry_after_seconds('not-a-date', self.clock())
        self.assertIn(value, (None, 0))

    def test_auth_failure_blocks_for_one_hour_and_survives_restart(self):
        self.engine.enqueue_test()
        self.http.actions.append(('POST', self.http.response(401, {'error': 'unauthorized'})))
        status = self.engine.tick()
        self.assertIn('E_AUTH', json.dumps(status))
        self.engine = self.new_engine()
        self.later(3_599)
        self.assertEqual(len(self.http.posts()), 1)
        self.later(2)
        self.assertEqual(len(self.http.posts()), 2)

    def test_wrong_readback_id_does_not_confirm_or_cause_a_second_post(self):
        self.engine.enqueue_test()
        def wrong_id(method, url, headers, body):
            record = dict(self.http.messages[-1], id='different-valid-id')
            return self.http.response(200, json.dumps(record).encode() + b'\n')
        self.http.actions.extend([('POST', None), ('GET', wrong_id)])
        status = self.engine.tick()
        self.assertIn('E_READBACK_PENDING', json.dumps(status))
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(self.http.methods(), ['POST', 'GET', 'GET'])

    def test_invalid_publish_json_recovers_by_readback_before_republishing(self):
        self.engine.enqueue_test()
        self.http.actions.append(('POST', self.http.response(200, b'not JSON')))
        status = self.engine.tick()
        self.assertIn('E_PUBLISH_RESPONSE', json.dumps(status))
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(self.http.methods(), ['POST', 'GET'])

    def test_invalid_publish_id_is_not_trusted(self):
        self.engine.enqueue_test()
        def malformed_id(method, url, headers, body):
            return self.http.response(200, {'id': '../not-safe', 'event': 'message',
                                           'topic': self.config.topic, 'message': body.decode()})
        self.http.actions.append(('POST', malformed_id))
        status = self.engine.tick()
        self.assertIn('E_PUBLISH_RESPONSE', json.dumps(status))
        self.engine = self.new_engine()
        self.later()
        self.assertEqual(self.http.methods(), ['POST', 'GET'])

    def test_redirect_is_rejected_without_following_location(self):
        self.engine.enqueue_test()
        self.http.actions.append(('POST', self.http.response(302, b'', {'Location': 'https://other.invalid/stolen'})))
        status = self.engine.tick()
        self.assertIn('E_REDIRECT', json.dumps(status))
        self.assertEqual(self.http.methods(), ['POST'])
        self.assertTrue(all(urlsplit(call['url']).hostname == 'ntfy.test.invalid' for call in self.http.calls))

    def test_actual_urllib_transport_does_not_follow_cross_origin_redirect(self):
        seen = []
        def synthetic_https(handler, request):
            seen.append(request.full_url)
            headers = Message()
            headers['Location'] = 'https://other.invalid/collect'
            code = 302 if len(seen) == 1 else 200
            response = urllib.response.addinfourl(io.BytesIO(b''), headers, request.full_url, code=code)
            response.msg = 'Found' if code == 302 else 'OK'
            return response
        with mock.patch.object(urllib.request.HTTPSHandler, 'https_open', synthetic_https):
            transport = sut.UrllibTransport()
            response = transport.request('POST', self.config.topic_url,
                {'Authorization': 'Bearer ' + self.config.token}, b'fixture')
        self.assertEqual(response.status, 302)
        self.assertEqual(seen, [self.config.topic_url])

    def test_actual_transport_network_exception_redacts_fake_credentials(self):
        transport = sut.UrllibTransport()
        failure = urllib.error.URLError('FAKE transport detail ' + self.config.token + ' ' + self.config.topic_url)
        with mock.patch.object(transport._opener, 'open', side_effect=failure):
            with self.assertRaises(sut.TransportError) as caught:
                transport.request('POST', self.config.topic_url,
                    {'Authorization': 'Bearer ' + self.config.token}, b'fixture')
        self.assertEqual(str(caught.exception), 'E_NETWORK')
        self.assertNotIn(self.config.token, str(caught.exception))

    def test_server_error_cannot_put_fake_credentials_in_status_or_output(self):
        self.engine.enqueue_test()
        fake_secret = self.config.token
        self.http.actions.append(('POST', self.http.response(403, {'error': fake_secret,
            'url': 'https://ntfy.test.invalid/' + self.config.topic + '?auth=' + fake_secret})))
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = self.engine.tick()
            public = self.engine.status()
        rendered = json.dumps([status, public]) + stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(fake_secret, rendered)
        self.assertNotIn(self.config.topic, rendered)
        self.assertNotIn('https://ntfy.test.invalid', rendered)
        self.assertIn('E_AUTH', rendered)
        for call in self.http.calls:
            self.assertNotIn(fake_secret, call['url'])
            self.assertEqual(call['headers'].get('Authorization'), 'Bearer ' + fake_secret)


class OutboxFilesystemTests(unittest.TestCase):
    @staticmethod
    def usage(**changes):
        # 100 GiB total, 6 GiB available: above both the 1 GiB and 5% floors.
        values = dict(f_blocks=26_214_400, f_frsize=4096,
                      f_bavail=1_572_864, f_favail=4096, f_flag=0)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_probes_writable_outbox_bind_when_root_is_read_only(self):
        def sandbox_mount(path):
            if str(path) == '/':
                return self.usage(f_flag=getattr(sut.os, 'ST_RDONLY', 1))
            self.assertEqual(path, sut.DEFAULT_STATE)
            return self.usage()
        with mock.patch.object(sut.os, 'statvfs', side_effect=sandbox_mount,
                               create=True) as statvfs:
            self.assertTrue(sut._outbox_filesystem_ok())
        statvfs.assert_called_once_with(sut.DEFAULT_STATE)

    def test_read_only_insufficient_bytes_and_insufficient_inodes_fail(self):
        cases = {
            'read_only': self.usage(f_flag=getattr(sut.os, 'ST_RDONLY', 1)),
            'below_1gib_floor': self.usage(f_blocks=1_310_720, f_bavail=262_143),
            'below_5percent_floor': self.usage(f_bavail=262_144),
            'below_inode_floor': self.usage(f_favail=1023),
        }
        for name, usage in cases.items():
            with self.subTest(name=name):
                with mock.patch.object(sut.os, 'statvfs', return_value=usage,
                                       create=True):
                    self.assertFalse(sut._outbox_filesystem_ok())
        with mock.patch.object(sut.os, 'statvfs', side_effect=OSError('fixture'),
                               create=True):
            self.assertFalse(sut._outbox_filesystem_ok())

    def test_exact_minimum_bytes_and_inodes_are_accepted(self):
        boundary = self.usage(f_blocks=1_310_720, f_bavail=262_144, f_favail=1024)
        with mock.patch.object(sut.os, 'statvfs', return_value=boundary, create=True):
            self.assertTrue(sut._outbox_filesystem_ok())

    def test_public_probe_name_describes_outbox_filesystem(self):
        with mock.patch.object(sut, '_subprocess_ok', return_value=True), \
             mock.patch.object(sut, '_container_running', return_value=True), \
             mock.patch.object(sut, '_dns_check', return_value=True), \
             mock.patch.object(sut, '_web_check', return_value=True), \
             mock.patch.object(sut, '_outbox_filesystem_ok', return_value=True):
            checks = sut.service_checks()
        self.assertTrue(checks['outbox_filesystem'])
        self.assertNotIn('root_filesystem', checks)
        self.assertTrue(all(checks.values()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
