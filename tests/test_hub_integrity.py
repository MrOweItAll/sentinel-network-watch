"""Offline regression fixtures for atomic publication and bounded hub mutations."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from sentinel_watch import alerts, hub
from sentinel_watch.review import ReviewError, ReviewQueue


class Engine:
    def __init__(self):
        self.ids = {}

    def enqueue_hub_notice(self, notice_id, category):
        self.ids.setdefault(notice_id, category)

    def tick(self):
        return {'ok': True, 'delivery_state': 'verified'}


class HubIntegrityTests(unittest.TestCase):
    def setUp(self):
        # Python's Windows 0700 ACL specialization excludes some sandbox tokens.
        # Scope the workaround to synthetic fixtures; POSIX runtime checks stay.
        if os.name == 'nt':
            mkdir = os.mkdir
            patcher = mock.patch.object(os, 'mkdir', side_effect=lambda p, mode=0o777, **kw:
                                        mkdir(p, 0o777 if mode == 0o700 else mode, **kw))
            patcher.start()
            self.addCleanup(patcher.stop)
        temporary = tempfile.TemporaryDirectory(prefix='.test-hub-integrity-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.state = self.root/'state'
        self.state.mkdir(mode=0o700)
        self.cfg = self.root/'config.json'
        self.now = 2_000_000_000.0
        self.sequence = 0
        self.engine = Engine()
        hub.write_private(self.cfg, {'schema_version':1, 'state_dir':str(self.state),
            'network_id':str(uuid.uuid4()), 'network_label':'Synthetic network',
            'actor_key':'linux:synthetic', 'expected_host_fingerprint':'a'*64,
            'expected_gateway_fingerprint':'b'*64, 'collection_interval_seconds':60}, exclusive=True)
        self.h = hub.Hub(self.cfg, clock=lambda:self.now, host_provider=lambda:'a'*64,
            network_provider=lambda:{'fingerprint':'b'*64, 'gateway':'192.0.2.1'},
            linux_provider=self.capture, alert_factory=lambda checks:self.engine)

    def capture(self, actor_key, observed_at):
        self.sequence += 1
        return {'records':[{'actor_key':actor_key, 'app_context_key':'binary:synthetic',
            'kind':'native_tcp', 'transport':'TCP', 'destination_address':'192.0.2.20',
            'destination_port':443, 'observed_at':observed_at,
            'observation_id':'synthetic:'+str(self.sequence),
            'evidence':{'application_name':'Synthetic', 'app_identity_complete':True,
                        'binary_sha256':'c'*64, 'endpoint_complete':True}}], 'coverage':{'ok':True}}

    def source(self):
        path = self.root/'source.sqlite3'
        with ReviewQueue(path, clock=lambda:1234) as q:
            row = q.ingest(self.capture('windows:origin', 1234)['records'][0])
            q.decide(row['review_id'], 'approve', scope_endpoint=True, expires_seconds=86400)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def recognition(self):
        return {'actor_key':'windows:origin', 'app_context_key':'binary:synthetic',
                'binary_sha256':'c'*64, 'recognized_at_utc':'2023-11-14T22:13:20+00:00',
                'endpoint_permission_granted':False}

    def test_import_recognition_and_audit_complete_before_publication_preserve_expiry(self):
        source, digest = self.source()
        result = self.h.import_case(source, expected_sha256=digest, recognition=self.recognition())
        self.assertEqual(result['decisions'], 1)
        row = self.h.relationships()[0]
        self.assertEqual(row['actor_key'], 'windows:origin')
        self.assertEqual(row['decision']['decided_at'], 1234)
        self.assertEqual(row['decision']['expires_at'], 1234+86400)
        self.assertTrue(row['application_recognized'])
        with self.h._queue() as q:
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM hub_audit').fetchone()[0], 1)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)

    def test_bad_recognition_never_replaces_empty_target(self):
        source, digest = self.source()
        with self.h._queue() as q:
            target = q.path
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        recognition = {**self.recognition(), 'binary_sha256':'d'*64}
        with self.assertRaisesRegex(hub.HubError, 'E_RECOGNITION_IMPORT'):
            self.h.import_case(source, expected_sha256=digest, recognition=recognition)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before)
        self.assertEqual(self.h.relationships(), [])
        self.assertEqual(list(target.parent.glob('*.import')), [])

    def test_staged_audit_capacity_failure_preserves_target_and_source(self):
        source, digest = self.source()
        with self.h._queue() as q:
            target = q.path
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        original = ReviewQueue._check_capacity
        def check(q):
            original(q)
            if q.path.suffix == '.import' and q.db.execute('SELECT COUNT(*) FROM hub_audit').fetchone()[0]:
                raise ReviewError('E_QUEUE_CAP')
        with mock.patch.object(ReviewQueue, '_check_capacity', check):
            with self.assertRaisesRegex(ReviewError, 'E_QUEUE_CAP'):
                self.h.import_case(source, expected_sha256=digest)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
        self.assertEqual(list(target.parent.glob('*.import')), [])

    def test_publication_failure_preserves_target(self):
        source, digest = self.source()
        with self.h._queue() as q:
            target = q.path
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        with mock.patch.object(hub.os, 'replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                self.h.import_case(source, expected_sha256=digest)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before)
        self.assertEqual(list(target.parent.glob('*.import')), [])

    def test_import_refuses_running_daemon_lock(self):
        source, digest = self.source()
        with alerts._FileLock(self.state/'daemon.lock'):
            with self.assertRaises(alerts.SafeError):
                self.h.import_case(source, expected_sha256=digest)
        self.assertEqual(self.h.relationships(), [])

    def test_source_size_is_checked_before_hasher_or_contents(self):
        source = self.root/'oversize.sqlite3'
        source.write_bytes(b'x'*4097)
        with mock.patch.object(hub, 'MAX_DB', 4096), mock.patch.object(hub.hashlib, 'sha256') as hasher:
            with self.assertRaisesRegex(hub.HubError, 'E_IMPORT_CAP'):
                hub.Hub._import_hash(source)
            hasher.assert_not_called()

    def test_import_rejects_sidecar_not_a_closed_snapshot(self):
        source, digest = self.source()
        Path(str(source)+'-wal').write_bytes(b'')
        with self.assertRaisesRegex(hub.HubError, 'E_IMPORT_SOURCE_NOT_CLOSED'):
            self.h.import_case(source, expected_sha256=digest)
        self.assertEqual(self.h.relationships(), [])

    def test_health_notice_and_marker_survive_crash_before_last_cycle(self):
        with self.h._queue() as q:
            self.h._reconcile(q, {'gaps':[{'code':'SYNTHETIC'}]})
            self.assertIsNone(self.h._last(q))
        with self.h._queue() as q:
            self.h._reconcile(q, {'gaps':[{'code':'SYNTHETIC'}]})
            self.h._reconcile(q, {'gaps':[]})
            self.h._reconcile(q, {'gaps':[]})
            kinds = [r[0] for r in q.db.execute('SELECT category FROM hub_notices ORDER BY rowid')]
        self.assertEqual(kinds, ['monitoring_gap', 'monitoring_recovered'])

    def test_reconciliation_capacity_rolls_back_intent_flags_and_health_together(self):
        with self.h._queue() as q:
            q.ingest(self.capture('linux:synthetic', self.now)['records'][0])
            with mock.patch.object(q, '_check_capacity', side_effect=ReviewError('E_QUEUE_CAP')):
                with self.assertRaisesRegex(ReviewError, 'E_QUEUE_CAP'):
                    self.h._reconcile(q, {'gaps':[{'code':'SYNTHETIC'}]})
            for table in ('hub_notices', 'hub_flagged', 'hub_metadata'):
                self.assertEqual(q.db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0], 0)
            self.h._reconcile(q, {'gaps':[{'code':'SYNTHETIC'}]})
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM hub_notices').fetchone()[0], 2)

    def test_decision_and_audit_capacity_failure_roll_back_together(self):
        self.h.tick()
        row = self.h.relationships()[0]
        original = ReviewQueue._check_capacity
        def check(q):
            original(q)
            if q.db.execute('SELECT COUNT(*) FROM hub_audit').fetchone()[0]:
                raise ReviewError('E_QUEUE_CAP')
        with mock.patch.object(ReviewQueue, '_check_capacity', check):
            with self.assertRaisesRegex(ReviewError, 'E_QUEUE_CAP'):
                self.h.decide(row['review_id'], 'approve', 86400, expected_relationship_key=row['relationship_key'])
        with self.h._queue() as q:
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM decisions').fetchone()[0], 0)
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM hub_audit').fetchone()[0], 0)

    def test_recognition_capacity_failure_preserves_unrecognized_state(self):
        self.h.tick()
        row = self.h.relationships()[0]
        original = ReviewQueue._check_capacity
        def check(q):
            original(q)
            if q.db.execute('SELECT COUNT(*) FROM hub_recognitions').fetchone()[0]:
                raise ReviewError('E_QUEUE_CAP')
        with mock.patch.object(ReviewQueue, '_check_capacity', check):
            with self.assertRaisesRegex(ReviewError, 'E_QUEUE_CAP'):
                self.h.recognize(row['review_id'], expected_app_context_key=row['app_context_key'])
        self.assertFalse(self.h.relationships()[0]['application_recognized'])

    def test_notice_ack_capacity_failure_keeps_durable_retry_intent(self):
        original = ReviewQueue._check_capacity
        def check(q):
            original(q)
            if q.db.execute('SELECT COUNT(*) FROM hub_notices WHERE handed=1').fetchone()[0]:
                raise ReviewError('E_QUEUE_CAP')
        with mock.patch.object(ReviewQueue, '_check_capacity', check):
            result = self.h.tick()
        self.assertFalse(result['ok'])
        self.assertEqual(self.h.overview()['pending_notification_handoffs'], 1)
        self.h.tick()
        self.assertEqual(self.h.overview()['pending_notification_handoffs'], 0)
        self.assertEqual(len(self.engine.ids), 1)

    def test_cycle_capacity_failure_does_not_commit_last_cycle(self):
        original = ReviewQueue._check_capacity
        def check(q):
            original(q)
            if q.db.execute('SELECT COUNT(*) FROM hub_cycles').fetchone()[0]:
                raise ReviewError('E_QUEUE_CAP')
        with mock.patch.object(ReviewQueue, '_check_capacity', check):
            with self.assertRaisesRegex(ReviewError, 'E_QUEUE_CAP'):
                self.h.tick()
        with self.h._queue() as q:
            self.assertIsNone(self.h._last(q))
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM hub_cycles').fetchone()[0], 0)

    def test_full_outbox_still_drains_then_retries_pending_handoff(self):
        class FullUntilDrained(Engine):
            def __init__(self):
                super().__init__()
                self.full = True
                self.drains = 0
            def enqueue_hub_notice(self, notice_id, category):
                if self.full: raise alerts.SafeError('E_QUEUE_FULL')
                super().enqueue_hub_notice(notice_id, category)
            def tick(self):
                self.full = False
                self.drains += 1
                return super().tick()
        engine = FullUntilDrained()
        self.h.alert_factory = lambda checks:engine
        self.assertFalse(self.h.tick()['ok'])
        self.assertEqual(engine.drains, 1)
        self.assertEqual(self.h.overview()['pending_notification_handoffs'], 1)
        self.h.tick()
        self.assertEqual(self.h.overview()['pending_notification_handoffs'], 0)
        self.assertEqual(len(engine.ids), 1)

    def test_schema_creation_capacity_failure_is_transactional(self):
        path = self.root/'plain.sqlite3'
        with ReviewQueue(path) as q:
            with mock.patch.object(q, '_check_capacity', side_effect=ReviewError('E_QUEUE_CAP')):
                with self.assertRaisesRegex(ReviewError, 'E_QUEUE_CAP'):
                    hub.Hub._schema(q)
            self.assertEqual(q.db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'hub_%'").fetchone()[0], 0)

    def test_new_worker_failure_degrades_overview_until_newer_success(self):
        self.h.tick()
        hub.write_private(self.state/'worker-error.json', {'ok':False, 'code':'E_HUB_CYCLE', 'checked_at':self.now+1})
        overview = self.h.overview()
        self.assertFalse(overview['ok'])
        self.assertFalse(overview['collection_stale'])
        self.assertEqual(overview['worker_error']['code'], 'E_HUB_CYCLE')
        self.now += 2
        self.h.tick()
        self.assertTrue(self.h.overview()['ok'])
        self.assertIsNone(self.h.overview()['worker_error'])

    def test_real_outbox_health_uses_own_state_filesystem(self):
        self.h.alert_factory = None
        self.h.config['alerts_config_path'] = str(self.root/'synthetic-alert-config.json')
        with mock.patch.object(alerts, 'load_config', return_value=alerts.Config('https://example.invalid','synthetic')), \
                mock.patch.object(alerts, 'service_checks', return_value={'outbox_filesystem':False}) as checks, \
                mock.patch.object(alerts, 'AlertEngine') as engine:
            self.h._engine({'hub_collection':True})
        checks.assert_called_once_with(state_dir=self.state)
        self.assertFalse(engine.call_args.kwargs['check_provider']()['outbox_filesystem'])


if __name__ == '__main__':
    unittest.main()
