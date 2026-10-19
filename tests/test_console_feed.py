"""Synthetic console snapshots only: no real processes, network or credentials."""
import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from sentinel_watch import console_feed as feed

BOOT = '12345678-1234-5678-1234-567812345678'


class ConsoleFeedTests(unittest.TestCase):
    def setUp(self):
        for target in ('socket.getaddrinfo', 'socket.socket.connect', 'socket.socket.connect_ex'):
            patch = mock.patch(target, side_effect=AssertionError('No real network in fixtures'))
            patch.start()
            self.addCleanup(patch.stop)
        if os.name == 'nt':
            original = os.mkdir
            patch = mock.patch('os.mkdir', side_effect=lambda path, mode=0o777, **kw:
                               original(path, 0o777 if mode == 0o700 else mode, **kw))
            patch.start()
            self.addCleanup(patch.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='.test-console-feed-', dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.uid = os.getuid() if os.name == 'posix' else 0
        self.gid = os.getgid() if os.name == 'posix' else 0
        self.proc = self.root / 'proc'
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text(BOOT)
        self.net = self.root / 'net'
        self.net.mkdir()
        self.interface()
        self.now = 2_000_000_000.0
        self.config = {'network_id': '22345678-1234-5678-1234-567812345678',
                       'expected_gateway_ipv4': '192.168.8.1',
                       'expected_gateway_mac': '02:11:22:33:44:55'}
        self.current = {'gateway': '192.168.8.1', 'mac': '02:11:22:33:44:55', 'interface': 'eth0'}
        self.records = [self.record()]

    def interface(self, name='eth0', rx=100, tx=200, index=2):
        path = self.net / name
        (path / 'statistics').mkdir(parents=True, exist_ok=True)
        (path / 'statistics/rx_bytes').write_text(str(rx))
        (path / 'statistics/tx_bytes').write_text(str(tx))
        (path / 'ifindex').write_text(str(index))

    def record(self, **changes):
        value = {'kind': 'native_tcp', 'transport': 'TCP', 'destination_address': '1.1.1.1',
                 'destination_port': 443, 'app_context_key': 'binary:fixture', 'observed_at': 2_000_000_000.0,
                 'evidence': {'local_address': '192.168.8.10', 'local_port': 50000,
                              'executable_name': 'fixture-browser', 'app_identity_complete': True,
                              'endpoint_complete': True}}
        value.update(changes)
        return value

    def capture(self, actor, observed, proc):
        return {'records': copy.deepcopy(self.records), 'coverage': {'ok': True, 'tcp4_read_ok': True,
                'tcp6_read_ok': True, 'tables_revalidated': True, 'process_scan_ok': True}}

    def snapshot(self, **changes):
        args = {'linux_provider': self.capture, 'router_state': None, 'proc_root': self.proc,
                'sys_net': self.net, 'now': self.now, 'monotonic_ns': 10_000_000_000,
                'uid': self.uid, 'network_config': self.config,
                'network_provider': lambda: dict(self.current)}
        args.update(changes)
        return feed.build_snapshot(**args)

    def router(self, *, rows=None, devices=None, age=0):
        root = self.root / 'router'
        root.mkdir(mode=0o700)
        (root / 'run.lock').write_bytes(b'')
        (root / 'run.lock').chmod(0o600)
        status = {'checked_at': self.now - age, 'collection_ok': True, 'notification_ok': True,
                  'alert_queue_handoff_ok': True, 'private_field_not_for_export': 'SYNTHETIC_PRIVATE_MARKER'}
        (root / 'status.json').write_text(json.dumps(status))
        (root / 'status.json').chmod(0o600)
        with closing(sqlite3.connect(root / 'observations.sqlite3')) as db:
            db.executescript('CREATE TABLE observations(kind TEXT,raw_json TEXT,last_seen REAL);'
                             'CREATE TABLE devices(device_key TEXT,device_json TEXT,first_seen REAL,last_seen REAL);')
            for kind, raw, seen in rows or []:
                db.execute('INSERT INTO observations VALUES(?,?,?)', (kind, json.dumps(raw), seen))
            for key, raw, first, last in devices or []:
                db.execute('INSERT INTO devices VALUES(?,?,?,?)', (key, json.dumps(raw), first, last))
            db.commit()
        (root / 'observations.sqlite3').chmod(0o600)
        return root

    def outgoing(self):
        return {'source': '192.168.8.20', 'destination': '1.1.1.1', 'destinationPort': 443}

    def device(self, name='Fixture television'):
        return {'friendlyName': name, 'model': {'manufacturer': 'Fixture vendor', 'modelNumber': 'Fixture model'},
                'connections': [{'ipAddress': '192.168.8.20'}],
                'knownMACAddresses': ['02:aa:bb:cc:dd:ee'],
                'password': 'SYNTHETIC_PRIVATE_MARKER'}

    def test_snapshot_contract_current_tcp_and_no_per_flow_bytes_or_direction_claim(self):
        result = self.snapshot()
        row = result['connections'][0]
        self.assertEqual((result['schema_version'], row['state'], row['direction'], row['transport']), (1, 'current', 'unknown', 'TCP'))
        self.assertEqual((row['source_scope'], row['destination_scope']), ('private', 'global'))
        self.assertEqual(row['application'], 'fixture-browser')
        self.assertEqual(row['severity'], 'INFO')
        for key in ('rx_bytes', 'tx_bytes', 'rx_bytes_per_second', 'tx_bytes_per_second'):
            self.assertIsNone(row[key])
        self.assertFalse(result['capabilities']['disconnect']['available'])
        self.assertFalse(result['capabilities']['household_counters']['available'])
        self.assertTrue(result['partial_coverage'])

    def test_real_interface_deltas_use_monotonic_elapsed_and_host_scope(self):
        before = self.snapshot()
        self.interface(rx=300, tx=500)
        after = self.snapshot(previous=before, monotonic_ns=12_000_000_000)
        counter = after['counters'][0]
        self.assertEqual((counter['rx_bytes'], counter['tx_bytes']), (300, 500))
        self.assertEqual((counter['rx_bytes_per_second'], counter['tx_bytes_per_second']), (100, 150))
        self.assertEqual(counter['interval_seconds'], 2)
        self.assertEqual(counter['scope'], 'host-interface')
        self.assertFalse(counter['reset'])

    def test_sysfs_page_sized_metadata_allows_short_bounded_counters_but_not_private_reads(self):
        real_stat = os.fstat
        def advertised_page(fd):
            actual = real_stat(fd)
            fields = {name: getattr(actual, name) for name in dir(actual) if name.startswith('st_')}
            fields['st_size'] = 4096
            return SimpleNamespace(**fields)
        with mock.patch.object(feed.os, 'fstat', side_effect=advertised_page):
            counters, source = feed.interface_counters(self.net, uid=self.uid, boot_id=BOOT,
                                                        now=self.now, monotonic_ns=10_000_000_000)
            self.assertEqual(source['state'], 'ok')
            self.assertEqual((counters[0]['rx_bytes'], counters[0]['tx_bytes']), (100, 200))
            with self.assertRaises(feed.FeedError):
                feed._read(self.net / 'eth0/statistics/rx_bytes', 128, uid=self.uid, check_parent=False)
        with self.assertRaisesRegex(feed.FeedError, 'E_KERNEL_ATTRIBUTE'):
            feed._kernel_number(self.root / 'unapproved-attribute', uid=self.uid)

    def test_network_uuid_change_resets_rate_baseline_even_with_same_gateway(self):
        previous = self.snapshot()
        self.interface(rx=500, tx=800)
        changed = dict(self.config, network_id=str(uuid.uuid4()))
        result = self.snapshot(previous=previous, network_config=changed, monotonic_ns=12_000_000_000)
        self.assertNotEqual(result['network_id'], previous['network_id'])
        self.assertIsNone(result['counters'][0]['rx_bytes_per_second'])
        self.assertIsNone(result['counters'][0]['interval_seconds'])

    def test_boot_change_counter_decrease_ifindex_change_and_invalid_clock_reset(self):
        for change, reason in (('boot', 'boot_changed_or_unavailable'), ('decrease', 'counter_decreased_or_invalid'),
                               ('ifindex', 'interface_changed'), ('clock', 'monotonic_baseline_invalid')):
            with self.subTest(change=change):
                self.interface(rx=100, tx=200, index=2)
                previous = self.snapshot()
                if change == 'boot': previous['boot_id'] = str(uuid.uuid4())
                if change == 'decrease': self.interface(rx=99)
                if change == 'ifindex': self.interface(index=3)
                if change == 'clock': previous['counter_monotonic_ns'] = 99_000_000_000
                counter = self.snapshot(previous=previous, monotonic_ns=12_000_000_000)['counters'][0]
                self.assertTrue(counter['reset'])
                self.assertEqual(counter['reset_reason'], reason)
                self.assertIsNone(counter['rx_bytes_per_second'])

    def test_negative_previous_counter_is_not_turned_into_extra_traffic(self):
        previous = self.snapshot()
        previous['counters'][0]['rx_bytes'] = -1
        row = self.snapshot(previous=previous, monotonic_ns=12_000_000_000)['counters'][0]
        self.assertTrue(row['reset'])
        self.assertIsNone(row['rx_bytes_per_second'])

    def test_stable_ids_and_network_or_gateway_change_cannot_inherit_them(self):
        first = self.snapshot()['connections'][0]['id']
        self.assertEqual(first, self.snapshot(now=self.now + 30)['connections'][0]['id'])
        other = dict(self.config, network_id=str(uuid.uuid4()))
        self.assertNotEqual(first, self.snapshot(network_config=other)['connections'][0]['id'])
        current = dict(self.current, mac='02:11:22:33:44:66')
        config = dict(self.config, expected_gateway_mac=current['mac'])
        self.assertNotEqual(first, self.snapshot(network_config=config, network_provider=lambda: current)['connections'][0]['id'])

    def test_unattributed_capture_specific_context_does_not_churn_ids_or_claim_safety(self):
        self.records[0]['evidence']['app_identity_complete'] = False
        self.records[0]['app_context_key'] = 'capture:one'
        a = self.snapshot()['connections'][0]
        self.records[0]['app_context_key'] = 'capture:two'
        b = self.snapshot()['connections'][0]
        self.assertEqual(a['id'], b['id'])
        self.assertEqual(a['severity'], 'REVIEW')
        self.assertIn('not proof of malicious', a['next_step'])

    def test_guard_mismatch_exports_no_connections_and_does_not_reuse_old_rows_or_rates(self):
        previous = self.snapshot()
        result = self.snapshot(previous=previous, network_provider=lambda: dict(self.current, mac='02:11:22:33:44:66'))
        self.assertIsNone(result['network_id'])
        self.assertFalse(result['sources']['guard']['matches'])
        self.assertEqual(result['connections'], [])
        self.assertIsNone(result['counters'][0]['rx_bytes_per_second'])
        self.assertFalse(result['capabilities']['host_tcp']['available'])

    def test_guard_missing_passive_arp_context_is_fail_closed(self):
        with mock.patch.object(feed, 'collect_linux_records', side_effect=AssertionError('Must not collect')):
            result = self.snapshot(linux_provider=None, network_provider=lambda: {})
        self.assertEqual(result['connections'], [])
        self.assertFalse(result['sources']['guard']['matches'])

    def test_passive_default_route_and_resolved_arp_match_without_network_calls(self):
        (self.proc / 'net').mkdir()
        (self.proc / 'net/route').write_text('Iface Destination Gateway Flags RefCnt Use Metric Mask\n'
                                           'eth0 00000000 0108A8C0 0003 0 0 100 00000000\n')
        (self.proc / 'net/arp').write_text('IP address HW type Flags HW address Mask Device\n'
                                         '192.168.8.1 0x1 0x2 02:11:22:33:44:55 * eth0\n')
        self.assertEqual(feed.network_context(self.proc, uid=self.uid), self.current)
        (self.proc / 'net/arp').write_text('IP address HW type Flags HW address Mask Device\n')
        with self.assertRaisesRegex(feed.FeedError, 'E_GATEWAY_MAC_UNAVAILABLE'):
            feed.network_context(self.proc, uid=self.uid)

    def test_router_history_is_read_only_and_never_promoted_to_live_or_tcp(self):
        root = self.router(rows=[('outgoing', self.outgoing(), self.now - 10),
                                 ('incoming', {'source': '8.8.8.8', 'destinationPort': 22}, self.now - 20)])
        before = (root / 'observations.sqlite3').read_bytes()
        rows, devices, source = feed.router_snapshot(root, now=self.now, uid=self.uid)
        self.assertEqual(before, (root / 'observations.sqlite3').read_bytes())
        self.assertEqual(source['state'], 'ok')
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['state'] == 'history' and row['transport'] == 'unknown' for row in rows))
        incoming = next(row for row in rows if row['direction'] == 'vendor_incoming')
        self.assertIsNone(incoming['destination_address'])
        self.assertEqual(incoming['severity'], 'REVIEW')
        self.assertNotIn('SYNTHETIC_PRIVATE_MARKER', json.dumps([rows, devices, source]))
        self.assertFalse(any(root.glob('*-wal')))

    def test_router_status_stale_history_remains_explicitly_stale(self):
        root = self.router(rows=[('outgoing', self.outgoing(), self.now - 1000)], age=1000)
        rows, _, source = feed.router_snapshot(root, now=self.now, uid=self.uid)
        self.assertEqual(source['state'], 'stale')
        self.assertEqual(rows[0]['state'], 'history')

    def test_device_alias_requires_unique_recent_time_bounded_report_not_online_trust(self):
        root = self.router(rows=[('outgoing', self.outgoing(), self.now - 1)],
                           devices=[('fixture-key', self.device(), self.now - 100, self.now - 1)])
        result = self.snapshot(router_state=root)
        row = next(row for row in result['connections'] if row['source'] == 'router')
        self.assertEqual(row['device_name'], 'Fixture television')
        self.assertEqual(row['device_mapping_confidence'], 'recent_router_report_only')
        self.assertFalse(result['devices'][0]['online_verified'])
        self.assertFalse(result['devices'][0]['identity_approved'])
        self.assertNotIn('SYNTHETIC_PRIVATE_MARKER', json.dumps(result))
        devices = copy.deepcopy(result['devices'])
        rows = [feed._router_connection('outgoing', self.outgoing(), self.now)]
        feed._device_aliases(rows, devices + copy.deepcopy(devices), self.now)
        self.assertNotIn('device_name', rows[0])
        self.assertEqual(rows[0]['device_mapping_confidence'], 'ambiguous')
        devices[0]['observed_at'] = self.now - 1000
        rows = [feed._router_connection('outgoing', self.outgoing(), self.now)]
        feed._device_aliases(rows, devices, self.now)
        self.assertNotIn('device_name', rows[0])

    def test_private_ipv6_scopes_and_listener_flag_do_not_claim_ipv6_router_coverage(self):
        for address, expected in (('::1', 'loopback'), ('fe80::1', 'link_local'), ('fd00::1', 'private'),
                                  ('2606:4700:4700::1111', 'global'), ('0.0.0.0', 'unspecified')):
            self.assertEqual(feed.address_scope(address), expected)
        record = self.record(kind='listener')
        record['evidence']['local_address'] = '0.0.0.0'
        self.records = [record]
        result = self.snapshot()
        self.assertIn('LISTENER_NON_LOOPBACK', [flag['code'] for flag in result['connections'][0]['flags']])
        self.assertFalse(result['sources']['router']['coverage']['complete_stream_visibility'])

    def test_capture_errors_redact_exception_details_and_unapproved_fields(self):
        def fail(*args):
            raise RuntimeError('SYNTHETIC_PRIVATE_MARKER token=never-real')
        result = self.snapshot(linux_provider=fail)
        self.assertEqual(result['sources']['linux']['state'], 'error')
        self.assertNotIn('SYNTHETIC_PRIVATE_MARKER', json.dumps(result))

    def test_row_and_json_caps_are_explicit(self):
        self.records = [self.record(destination_port=port + 1000) for port in range(1100)]
        result = self.snapshot()
        self.assertLessEqual(len(result['connections']), feed.MAX_CONNECTIONS)
        self.assertEqual(result['truncation']['connections_omitted'], 600)
        self.assertEqual(result['sources']['linux']['state'], 'partial')
        self.records = [self.record(destination_port=port + 1000) for port in range(50)]
        with mock.patch.object(feed, 'MAX_JSON', 12000):
            result = self.snapshot()
            raw = feed.encode_snapshot(result)
            self.assertLessEqual(len(raw), 12000)
            self.assertTrue(result['truncation']['json_size_limited'])
            self.assertGreater(result['truncation']['connections_omitted'], 0)

    def test_atomic_publication_checksum_and_reject_hardlinked_previous(self):
        result = self.snapshot()
        path = self.root / 'output/snapshot.json'
        feed.publish(result, path, uid=self.uid, gid=self.gid)
        self.assertEqual(json.loads(path.read_bytes()), result)
        if os.name == 'posix':
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o750)
        self.assertEqual(feed.read_previous(path, uid=self.uid, gid=self.gid)['schema_version'], 1)
        alias = path.with_name('alias')
        try:
            os.link(path, alias)
        except PermissionError:
            self.skipTest('This Windows sandbox forbids creation of a hard link; Linux exercises the actual link guard.')
        with self.assertRaises(feed.FeedError):
            feed.read_previous(path, uid=self.uid, gid=self.gid)

    def test_config_rejects_arbitrary_sources_secret_keys_and_unbound_network(self):
        valid = {'schema_version': 1, **self.config, 'router_state': None}
        with mock.patch.object(feed, '_read', return_value=json.dumps(valid).encode()):
            self.assertIsNone(feed.load_config(self.root / 'config.json')['router_state'])
        for value in (dict(valid, router_state='/arbitrary/source'), dict(valid, token='SYNTHETIC_PRIVATE_MARKER'),
                      dict(valid, network_id=str(uuid.UUID(int=0))), dict(valid, expected_gateway_mac='00:00:00:00:00:00')):
            with self.subTest(keys=sorted(value)), mock.patch.object(feed, '_read', return_value=json.dumps(value).encode()):
                with self.assertRaises((feed.FeedError, ValueError)):
                    feed.load_config(self.root / 'config.json')

    def test_duplicate_router_service_variants_and_linux_rows_have_unique_ids_and_observation_counts(self):
        self.records = [self.record(), self.record()]
        outgoing = self.outgoing()
        root = self.router(rows=[('outgoing', outgoing, self.now - 20),
                                 ('outgoing', dict(outgoing, service='HTTPS'), self.now - 1)])
        result = self.snapshot(router_state=root)
        self.assertEqual(len(result['connections']), 2)
        self.assertEqual(len({row['id'] for row in result['connections']}), 2)
        self.assertTrue(all(row['observation_count'] == 2 for row in result['connections']))
        router = next(row for row in result['connections'] if row['source'] == 'router')
        self.assertEqual(router['observed_at'], self.now - 1)
        self.assertEqual(router['first_observed_at'], self.now - 20)
        self.assertIn('not sessions', router['aggregation_note'])


if __name__ == '__main__':
    unittest.main()
