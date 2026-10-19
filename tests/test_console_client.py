"""Pure policy fixtures: no Qt, network, production configuration or credentials."""
import hashlib
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from sentinel_watch import console_client as client

ORIGIN = 'https://192.168.50.10:8443'
BLOB = 'blob:' + ORIGIN + '/9252d83d-c74b-4aa5-b8dc-ff5046fc45bd'
DER = b'\x30\x3e' + b'X' * 62  # Synthetic envelope, not a real X509 certificate.
HASH = hashlib.sha256(DER).hexdigest()


class ClientPolicyTests(unittest.TestCase):
    def test_process_backend_is_software_without_changing_other_environment(self):
        environment = {'QT_QUICK_BACKEND': 'opengl', 'SYNTHETIC_UNRELATED': 'preserved'}
        client.prepare_process_environment(environment)
        self.assertEqual(environment, {'QT_QUICK_BACKEND': 'software', 'SYNTHETIC_UNRELATED': 'preserved'})

    def test_unsafe_engine_process_flags_proxies_and_debug_are_rejected_before_backend_change(self):
        for key in client.UNSAFE_ENVIRONMENT:
            with self.subTest(key=key):
                environment = {key: 'synthetic-forbidden-value', 'QT_QUICK_BACKEND': 'original'}
                with self.assertRaisesRegex(client.ClientError, 'E_CLIENT_ENVIRONMENT'):
                    client.prepare_process_environment(environment)
                self.assertEqual(environment['QT_QUICK_BACKEND'], 'original')
        self.assertIn('QTWEBENGINEPROCESS_PATH', client.UNSAFE_ENVIRONMENT)
        self.assertIn('CHROMIUM_FLAGS', client.UNSAFE_ENVIRONMENT)

    def test_config_has_no_url_ca_path_or_credential_override(self):
        valid = {'schema_version': 1, 'origin': ORIGIN, 'ca_der_sha256': HASH}
        self.assertEqual(client.validate_config(valid), valid)
        for extra in ('password', 'ca_path', 'proxy', 'ignore_certificate_errors'):
            with self.subTest(extra=extra), self.assertRaises(client.ClientError):
                client.validate_config({**valid, extra: 'synthetic'})
        for bad in ('http://192.168.50.10:8443', 'https://127.0.0.1:8443', 'https://0.0.0.0:8443',
                    'https://8.8.8.8:8443', 'https://192.168.50.10:443', ORIGIN + '/', ORIGIN + '?secret=x'):
            with self.subTest(url=bad), self.assertRaises(client.ClientError):
                client.validate_config({**valid, 'origin': bad})

    def test_same_origin_resources_queries_and_fragments_allowed(self):
        for url in (ORIGIN, ORIGIN + '/', ORIGIN + '/api/snapshot', ORIGIN + '/?view=all#details'):
            self.assertTrue(client.same_origin(url, ORIGIN))

    def test_origin_confusion_and_custom_schemes_rejected(self):
        urls = ('https://192.168.50.10.evil:8443/', 'https://192.168.50.10:8444/',
                'https://name@192.168.50.10:8443/', 'https://192.168.50.10:8443@evil:8443/',
                'https://192.168.50.10:08443/', 'https://192.168.50.10%2eevil:8443/',
                'https://192.168.50.10:8443\\@evil/', 'http://192.168.50.10:8443/',
                'wss://192.168.50.10:8443/', 'file:///etc/passwd', 'data:text/html,test',
                'javascript:alert(1)', 'qrc:/test', 'about:blank', '\n' + ORIGIN,
                ORIGIN + '/\x00', 'https://[::1]:8443/')
        for url in urls:
            with self.subTest(url=url):
                self.assertFalse(client.same_origin(url, ORIGIN))

    def test_blob_only_from_exact_app_origin_with_opaque_identifier(self):
        self.assertTrue(client.report_blob(BLOB, ORIGIN))
        for url in ('blob:null/9252d83d-c74b-4aa5-b8dc-ff5046fc45bd',
                    BLOB.replace('192.168.50.10', '192.168.50.11'), BLOB + '/extra',
                    BLOB + '?extra=x', BLOB + '#extra', 'blob:' + ORIGIN + '/../../report.json'):
            with self.subTest(url=url):
                self.assertFalse(client.report_blob(url, ORIGIN))

    def test_download_requires_origin_page_json_and_bounded_known_size(self):
        self.assertTrue(client.download_allowed(BLOB, ORIGIN + '/', ORIGIN, 'application/json', 128))
        for url, page, mime, size, save in (
                (ORIGIN + '/report.json', ORIGIN, 'application/json', 128, False),
                (BLOB, 'https://evil.example:8443', 'application/json', 128, False),
                (BLOB, ORIGIN, 'text/html', 128, False), (BLOB, ORIGIN, 'application/json', -1, False),
                (BLOB, ORIGIN, 'application/json', 0, False), (BLOB, ORIGIN, 'application/json', True, False),
                (BLOB, ORIGIN, 'application/json', client.MAX_REPORT_BYTES + 1, False),
                (BLOB, ORIGIN, 'application/json', 128, True)):
            with self.subTest(url=url, page=page, mime=mime, size=size, save=save):
                self.assertFalse(client.download_allowed(url, page, ORIGIN, mime, size, save_page=save))

    def test_interceptor_defaults_blocked_on_policy_and_qt_api_failures(self):
        class Info:
            def __init__(self, url, fail=None):
                self.url, self.fail, self.blocks = url, fail, []
            def block(self, value):
                self.blocks.append(value)
            def requestUrl(self):
                if self.fail == 'requestUrl':
                    raise RuntimeError('synthetic unavailable API')
                return SimpleNamespace(toString=lambda: self.url)
            def isDownload(self):
                if self.fail == 'isDownload':
                    raise RuntimeError('synthetic unavailable API')
                return True
            def firstPartyUrl(self):
                if self.fail == 'firstPartyUrl':
                    raise RuntimeError('synthetic unavailable API')
                return SimpleNamespace(toString=lambda: ORIGIN)
        allowed = Info(ORIGIN + '/')
        self.assertTrue(client.gate_request(allowed, ORIGIN))
        self.assertEqual(allowed.blocks, [True, False])
        blob = Info(BLOB)
        self.assertTrue(client.gate_request(blob, ORIGIN))
        self.assertEqual(blob.blocks, [True, False])
        for url, failure in (('https://evil.example:8443', None), (BLOB, 'requestUrl'),
                             (BLOB, 'isDownload'), (BLOB, 'firstPartyUrl')):
            info = Info(url, failure)
            self.assertFalse(client.gate_request(info, ORIGIN))
            self.assertEqual(info.blocks, [True])

    def test_ca_must_be_exact_one_bounded_der_envelope_and_hash(self):
        self.assertEqual(client.validate_ca_der(DER, HASH), DER)
        bad_values = (DER + DER, DER + b'garbage', b'-----BEGIN CERTIFICATE-----',
                      b'\x30\x80' + b'X' * 62, b'\x30\x81\x3d' + b'X' * 61,
                      b'\x30\x82\x00\x3c' + b'X' * 60)
        for raw in bad_values:
            with self.subTest(length=len(raw)), self.assertRaises(client.ClientError):
                client.validate_ca_der(raw, hashlib.sha256(raw).hexdigest())
        with self.assertRaises(client.ClientError):
            client.validate_ca_der(DER, '0' * 64)

    def test_root_config_and_private_state_metadata_reject_links_and_writeability(self):
        def metadata(mode, uid=0, links=1):
            return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)
        client._metadata(metadata(stat.S_IFREG | 0o644), 0)
        client._metadata(metadata(stat.S_IFDIR | 0o700, uid=1000), 1000, directory=True, private=True)
        for item in (metadata(stat.S_IFLNK | 0o777), metadata(stat.S_IFREG | 0o666),
                     metadata(stat.S_IFREG | 0o644, uid=1000), metadata(stat.S_IFREG | 0o644, links=2)):
            with self.assertRaises(client.ClientError):
                client._metadata(item, 0)
        with self.assertRaises(client.ClientError):
            client._metadata(metadata(stat.S_IFDIR | 0o755, uid=1000), 1000, directory=True, private=True)

    def test_report_requires_bounded_json_and_only_export_top_level_fields(self):
        raw = json.dumps({'snapshot': {'connections': []}, 'annotations': {}}).encode()
        self.assertEqual(client.validate_report(raw), raw)
        for bad in (b'<html>not json', b'{}', b'[]', b'{"snapshot":[],"annotations":{}}',
                    b'{"snapshot":{},"annotations":{},"password":"synthetic"}',
                    b'X' * (client.MAX_REPORT_BYTES + 1)):
            with self.subTest(length=len(bad)), self.assertRaises(client.ClientError):
                client.validate_report(bad)

    def test_report_publication_uses_generated_name_and_exclusive_no_follow(self):
        raw = b'{"snapshot":{},"annotations":{}}'
        with mock.patch.object(client, 'private_directory'), mock.patch.object(client.os, 'getuid', return_value=1000, create=True), \
             mock.patch.object(client.os, 'O_NOFOLLOW', 0x20000, create=True), \
             mock.patch.object(client.os, 'open', side_effect=FileExistsError) as opened:
            with self.assertRaises(FileExistsError):
                client.publish_report(Path('/synthetic-reports'), raw)
            path, flags, mode = opened.call_args.args
            self.assertEqual(path.parent, Path('/synthetic-reports'))
            self.assertRegex(path.name, r'^sentinel-report-\d{8}T\d{6}Z-[0-9a-f]{32}\.json$')
            self.assertTrue(flags & client.os.O_EXCL)
            self.assertTrue(flags & client.os.O_NOFOLLOW)
            self.assertEqual(mode, 0o600)

    def test_normal_import_does_not_require_qt_and_launcher_has_no_argument_override(self):
        with mock.patch.object(client.sys, 'platform', 'linux'), mock.patch.object(client.os, 'getuid', return_value=1000, create=True), \
             mock.patch.object(client, 'load_fixed_config') as loaded, mock.patch.object(sys.stderr, 'write'):
            self.assertEqual(client.main(['--url', ORIGIN]), 1)
            loaded.assert_not_called()


if __name__ == '__main__':
    unittest.main()
