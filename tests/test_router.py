"""Synthetic local fixtures; never contacts a router or reads credentials."""
import os
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from sentinel_watch import router as r
ROW = {'source': '192.0.2.10', 'destination': '198.51.100.20', 'destinationPort': 443, 'service': 'HTTPS'}


class Fake:
    def __init__(self, devices=(), outgoing=(), broken=False):
        self.devices, self.outgoing, self.broken = list(devices), list(outgoing), broken

    def request(self, key, index=r.FIRST_INDEX):
        if self.broken:
            raise r.SafeError('E_ROUTER_NETWORK')
        output = ({'modelNumber': 'EA7300', 'hardwareVersion': '2', 'firmwareVersion': '2.0.4.216940'} if key == 'identity' else
                  {'isLoggingEnabled': True} if key == 'settings' else
                  {'devices': self.devices} if key == 'devices' else
                  {'entries': self.outgoing if key == 'outgoing' else []})
        return 200, json.dumps({'result': 'OK', 'output': output}).encode(), False


def device(name):
    return {'deviceID': name, 'ipAddresses': ['192.0.2.10']}


class Fixtures(unittest.TestCase):
    def setUp(self):
        if os.name == 'nt':
            original = os.mkdir
            def inherited(path, mode=0o777, *, dir_fd=None):
                return original(path, 0o777 if mode == 0o700 else mode) if dir_fd is None else original(path, mode, dir_fd=dir_fd)
            shim = patch('os.mkdir', side_effect=inherited)
            shim.start(); self.addCleanup(shim.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='router-log-fixture-', dir=Path(__file__).resolve().parent)
        self.assertEqual(Path(self.temp.name).resolve().parent, Path(__file__).resolve().parent)
        self.clock = [1000000.0]
        self.store = r.Store(Path(self.temp.name) / 'state', clock=lambda: self.clock[0])

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def snapshot(self, kind='incoming', raw=b'{}'):
        return self.store.save_raw(kind, raw)

    def poll(self, **kwargs):
        self.clock[0] += 60
        return r.collect(self.store, Fake(**kwargs))

    def test_setter_and_zero_index_rejected_before_network(self):
        with patch.object(r.http.client, 'HTTPConnection', side_effect=AssertionError('network')):
            for key, index in (('SetLogSettings', 1), ('incoming', 0)):
                with self.assertRaises(r.SafeError):
                    r.RouterClient(time.monotonic() + 20, gateway='192.0.2.1').request(key, index)

    def test_gateway_must_be_explicit_ip_literal_and_profile_must_match(self):
        with patch.object(r.http.client,'HTTPConnection',side_effect=AssertionError('network')):
            for gateway in (None,True,123,'','router.test.invalid','192.0.2.1\n'):
                with self.subTest(gateway=gateway),self.assertRaises(r.SafeError):
                    r.RouterClient(time.monotonic()+20,gateway=gateway)
            with self.assertRaises(r.SafeError):
                r.RouterClient(time.monotonic()+20,gateway='192.0.2.1',profile='unknown-router')
            with self.assertRaises(r.SafeError):
                r.collect(self.store)
        self.assertFalse(hasattr(r,'GATEWAY'))

    def test_private_router_config_has_no_gateway_fallback(self):
        path=Path(self.temp.name)/'router-config.json'
        for value in ({}, {'gateway':'192.0.2.1','unexpected':True},
                      {'gateway':'192.0.2.1','profile':'unknown'}):
            path.write_text(json.dumps(value));path.chmod(0o600)
            with self.subTest(value=value),self.assertRaises(r.SafeError):r.load_config(path)
        path.write_text(json.dumps({'gateway':'192.0.2.1'}))
        self.assertEqual(r.load_config(path),{'gateway':'192.0.2.1','profile':r.SUPPORTED_PROFILE})

    def test_client_fixed_get_window_no_auth(self):
        connection, response = Mock(), Mock()
        raw = b'{"result":"OK","output":{}}'
        response.status, response.read1.side_effect = 200, [raw, b'']
        connection.getresponse.return_value = response
        with patch.object(r.http.client, 'HTTPConnection', return_value=connection) as constructor:
            self.assertEqual(r.RouterClient(time.monotonic() + 20, gateway='192.0.2.1').request('incoming'), (200, raw, False))
        self.assertEqual(constructor.call_args.args[:2], ('192.0.2.1', 80))
        method, path, body, headers = connection.request.call_args.args
        self.assertEqual((method, path), ('POST', '/JNAP/'))
        self.assertEqual(json.loads(body), {'firstEntryIndex': 1, 'entryCount': 255})
        self.assertEqual(headers['X-JNAP-Action'], 'http://linksys.com/jnap/routerlog/GetIncomingLogEntries')
        self.assertFalse(any('authorization' in k.lower() or 'cookie' in k.lower() for k in headers))

    def test_actual_fixed_window_empty_sources_not_degraded(self):
        status = self.poll(outgoing=[ROW])
        self.assertTrue(status['ok'])
        self.assertEqual(status['collection_health'], 'healthy')
        self.assertFalse(status['historical_completeness'])
        self.assertFalse(status['complete_stream_visibility'])
        self.assertEqual(status['api']['incoming']['rows_observed'], 0)
        self.assertEqual(status['api']['security']['rows_observed'], 0)
        self.assertEqual(len(status['limitations']), 3)
        self.assertEqual(self.store.pending_notices(), [])

    def test_unknown_nonempty_schema_retained_and_degrades(self):
        class Unknown(Fake):
            def request(self, key, index=1):
                if key in r.LOGS:
                    return 200, b'{"result":"OK","output":{"entries":[{"unverified":"x"}]}}', False
                return super().request(key, index)
        for _ in range(2):
            status = r.collect(self.store, Unknown())
        self.assertFalse(status['ok'])
        self.assertEqual(status['raw_unprocessed_snapshots'], 6)
        self.assertEqual({g['code'] for g in status['gaps']}, {'E_LOG_ROW_SCHEMA'})
        self.assertEqual([n['category'] for n in self.store.pending_notices()], ['router_collection_degraded'])

    def test_log_rows_dedup_never_generate_destination_notices(self):
        first = self.poll(outgoing=[ROW, ROW])
        second = self.poll(outgoing=[ROW, dict(ROW, destination='203.0.113.9')])
        self.assertEqual(first['new_record_count'], 1)
        self.assertEqual(second['new_record_count'], 1)
        stored = self.store.db.execute('SELECT poll_sightings,candidate_class,router_timestamp_json FROM observations WHERE raw_json=?', (r.canonical(ROW),)).fetchone()
        self.assertEqual(stored['poll_sightings'], 2)
        self.assertEqual(stored['candidate_class'], 'unknown')
        self.assertIsNone(stored['router_timestamp_json'])
        self.assertEqual(self.store.pending_notices(), [])

    def test_inventory_baseline_then_two_polls_and_cooldown(self):
        self.poll(devices=[device('baseline')])
        self.poll(devices=[device('baseline'), device('new-a')])
        self.assertEqual(self.store.pending_notices(), [])
        self.poll(devices=[device('baseline'), device('new-a')])
        notice = self.store.pending_notices()[0]
        self.assertEqual((notice['category'], notice['record_count']), ('inventory_change', 1))
        self.store.acknowledge_notice(notice['id'])
        self.poll(devices=[device('baseline'), device('new-a'), device('new-b')])
        self.poll(devices=[device('baseline'), device('new-a'), device('new-b')])
        self.assertEqual(self.store.pending_notices(), [])
        self.clock[0] += r.INVENTORY_NOTICE_COOLDOWN
        self.poll(devices=[device('baseline'), device('new-a'), device('new-b')])
        self.assertEqual(self.store.pending_notices()[0]['record_count'], 1)

    def test_failed_inventory_poll_breaks_confirmation(self):
        self.poll()
        self.poll(devices=[device('new')])
        self.poll(broken=True)
        self.poll(devices=[device('new')])
        self.assertEqual(self.store.pending_notices(), [])
        self.poll(devices=[device('new')])
        self.assertEqual(self.store.pending_notices()[0]['category'], 'inventory_change')

    def test_health_stable_notice_and_two_good_poll_recovery(self):
        self.poll()
        self.poll(broken=True)
        self.assertEqual(self.store.pending_notices(), [])
        self.poll(broken=True)
        original = self.store.pending_notices()[0]['id']
        self.poll(broken=True)
        self.assertEqual(self.store.pending_notices()[0]['id'], original)
        self.poll()
        self.assertEqual(len(self.store.pending_notices()), 1)
        self.poll()
        self.assertEqual({n['category'] for n in self.store.pending_notices()},
                         {'router_collection_degraded', 'router_collection_recovered'})

    def test_device_commit_before_notice_recovers_after_crash(self):
        self.poll()
        for _ in range(2):
            seq = self.store.begin_poll()
            self.store.devices({'devices': [device('new')]}, self.snapshot('devices'), seq)
        self.assertEqual(self.store.pending_notices(), [])
        self.store.prepare_inventory_notice()
        ident = self.store.pending_notices()[0]['id']
        self.store.prepare_inventory_notice()
        self.assertEqual(self.store.pending_notices()[0]['id'], ident)

    def test_retention_preserves_unacknowledged_notice_and_context(self):
        self.poll()
        self.poll(devices=[device('new')])
        self.poll(devices=[device('new')])
        ident = self.store.pending_notices()[0]['id']
        self.clock[0] += r.RETENTION + 1
        self.store.prune_tables()
        self.assertEqual(len(self.store.pending_notices()), 1)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM devices').fetchone()[0], 1)
        self.store.acknowledge_notice(ident)
        self.store.prune_tables()
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM devices').fetchone()[0], 0)
        self.clock[0] += r.RETENTION + 1
        self.store.prune_tables()
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM notices').fetchone()[0], 0)

    def test_observation_count_cap_reported(self):
        self.poll(outgoing=[ROW, dict(ROW, destination='203.0.113.9'), dict(ROW, destination='203.0.113.10')])
        with patch.object(r, 'MAX_OBSERVATIONS', 2):
            self.store.prune_tables()
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM observations').fetchone()[0], 2)
        self.assertEqual(int(self.store.db.execute("SELECT value FROM metadata WHERE key='observation_cap_pruned_total'").fetchone()[0]), 1)

    def test_raw_cap_preserves_unprocessed_data(self):
        ident = self.snapshot(raw=b'x' * 10000)
        self.store.cap = self.store.disk_bytes() - 1
        with self.assertRaisesRegex(r.SafeError, '^E_STORAGE_CAP_UNCOLLECTED_RETAINED$'):
            self.store.make_space(0)
        filename = self.store.db.execute('SELECT filename FROM snapshots WHERE id=?', (ident,)).fetchone()[0]
        self.assertEqual((self.store.raw_dir / filename).read_bytes(), b'x' * 10000)

    def test_raw_cap_prunes_processed_evidence_with_counter(self):
        ident = self.snapshot(raw=b'x' * 10000)
        with self.store.db:
            self.store.db.execute('UPDATE snapshots SET processed=1 WHERE id=?', (ident,))
        self.store.cap = self.store.disk_bytes() - 5000
        self.assertEqual(self.store.make_space(0), (0, 1))

    def test_public_status_has_no_private_values(self):
        status = self.poll(devices=[device('synthetic-private-hostname')], outgoing=[ROW])
        for private in ('synthetic-private-hostname', '192.0.2.10', '198.51.100.20', 'HTTPS'):
            self.assertNotIn(private, json.dumps(status))

    def test_security_timestamp_uninterpreted(self):
        row = {'ipAddress': '192.0.2.10', 'macAddress': '02:00:00:00:00:01', 'timestamp': 123456, 'authSucceeded': False}
        parsed, next_index, complete = r.log_page({'entries': [row]}, 1, 'security')
        self.assertEqual(parsed, [row])
        self.assertIsNone(next_index)
        self.assertFalse(complete)
        self.assertIn('123456', r.router_timestamp(row))


if __name__ == '__main__':
    unittest.main()
