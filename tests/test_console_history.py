"""Synthetic retained history: no router calls, credentials or production state."""
from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from sentinel_watch import console_feed as feed
from sentinel_watch import console_history as history


class HistoryTests(unittest.TestCase):
    def setUp(self):
        for target in ('socket.getaddrinfo', 'socket.socket.connect', 'socket.socket.connect_ex'):
            patch = mock.patch(target, side_effect=AssertionError('No network in fixtures'))
            patch.start(); self.addCleanup(patch.stop)
        if os.name == 'nt':
            mkdir = os.mkdir
            patch = mock.patch('os.mkdir', side_effect=lambda path, mode=0o777, **kw:
                               mkdir(path, 0o777 if mode == 0o700 else mode, **kw))
            patch.start(); self.addCleanup(patch.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='.test-console-history-', dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.uid = os.getuid() if os.name == 'posix' else 0
        self.gid = os.getgid() if os.name == 'posix' else 0
        self.now = 2_000_000_000.0
        self.snapshot = {'generated_at': self.now, 'network_id': '22345678-1234-5678-1234-567812345678',
            'network_binding_sha256': 'b' * 64, 'sources': {'guard': {'matches': True, 'state': 'ok', 'checked_at': self.now}}}
        self.source = self.root / 'router'; self.source.mkdir(mode=0o700)
        (self.source / 'run.lock').write_bytes(b''); (self.source / 'run.lock').chmod(0o600)
        self.handoff = self.root / 'handoff'; self.handoff.mkdir(mode=0o750); self.handoff.chmod(0o750)
        self.path = self.handoff / 'history.sqlite3'
        self.query = {'offset': 0, 'limit': 100, 'search': '', 'direction': 'all', 'review': 'all'}
        self.write_source()

    def raw(self, number):
        return {'source': '192.168.50.20', 'destination': 'peer' + str(number) + '.example',
                'destinationPort': 1000 + number, 'password': 'SYNTHETIC_PRIVATE_MARKER'}

    def write_source(self, count=625, rows=None, checked=None):
        status = {'checked_at': self.now if checked is None else checked, 'collection_ok': True,
                  'private_value': 'SYNTHETIC_PRIVATE_MARKER'}
        (self.source / 'status.json').write_text(json.dumps(status)); (self.source / 'status.json').chmod(0o600)
        database = self.source / 'observations.sqlite3'
        with closing(sqlite3.connect(database)) as db:
            db.executescript('DROP TABLE IF EXISTS observations; CREATE TABLE observations('
                             'id INTEGER PRIMARY KEY,kind TEXT,raw_json TEXT,first_seen REAL,last_seen REAL);')
            for index, (kind, raw, first, seen) in enumerate(rows if rows is not None else
                    [('outgoing', self.raw(i), self.now - i - 100, self.now - i) for i in range(count)]):
                db.execute('INSERT INTO observations VALUES(?,?,?,?,?)',
                           (index, kind, json.dumps(raw) if isinstance(raw, dict) else raw, first, seen))
            db.commit()
        database.chmod(0o600)

    def export(self, **options):
        return history.export_history(self.source, self.snapshot, self.path, gid=self.gid, uid=self.uid, now=self.now, **options)

    def reader(self, now=None):
        return history.HistoryReader(self.path, _uid=self.uid, _gid=self.gid, _clock=lambda: self.now if now is None else now)

    def page(self, annotations=None, **query):
        return self.reader().page({**self.query, **query}, annotations or {}, self.snapshot)

    def expected_id(self, number):
        row = feed._router_connection('outgoing', self.raw(number), self.now - number)
        return feed._digest([self.snapshot['network_id'], self.snapshot['network_binding_sha256'], row['id']])

    def test_all_625_rows_exported_with_no_raw_secret_or_device_columns(self):
        before = (self.source / 'observations.sqlite3').read_bytes()
        result = self.export()
        self.assertTrue(result['available'], result)
        self.assertEqual((result['raw_retained_count'], result['total_observations'], result['row_errors']), (625, 625, 0))
        self.assertEqual(before, (self.source / 'observations.sqlite3').read_bytes())
        self.assertNotIn(b'SYNTHETIC_PRIVATE_MARKER', self.path.read_bytes())
        with closing(sqlite3.connect(self.path)) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertEqual(tables, {'metadata', 'history'})
        self.assertFalse(any(self.source.glob('*-wal')))

    def test_paging_and_literal_search_beyond_first_500_keep_existing_ids(self):
        self.export()
        page = self.page(offset=600, limit=25)
        self.assertTrue(page['available'], page)
        self.assertEqual((page['total_matches'], len(page['rows']), page['has_more']), (625, 25, False))
        self.assertEqual(page['rows'][20]['id'], self.expected_id(620))
        found = self.page(search='PEER620.EXAMPLE')
        self.assertEqual(found['total_matches'], 1)
        self.assertEqual(found['rows'][0]['id'], self.expected_id(620))
        self.assertEqual(self.page(search="%' OR 1=1--")['total_matches'], 0)

    def test_pending_is_unannotated_and_explicit_unrecognized_is_distinct(self):
        self.export()
        annotations = {self.expected_id(620): {'decision': 'unrecognized'}, self.expected_id(621): {'decision': 'recognize'},
                       self.expected_id(622): {'decision': 'investigate'}}
        self.assertEqual(self.page(annotations, review='pending')['total_matches'], 622)
        for number, decision in ((620, 'unrecognized'), (621, 'recognize'), (622, 'investigate')):
            row = self.page(annotations, review=decision)['rows'][0]
            self.assertEqual(row['id'], self.expected_id(number)); self.assertEqual(row['review_status'], decision)
        self.assertTrue(self.reader().contains(self.expected_id(624), self.snapshot))

    def test_full_5000_annotation_index_is_bound_and_filters_beyond_first_500(self):
        self.export()
        annotations = {self.expected_id(i): {'decision': 'recognize'} for i in range(624)}
        annotations.update({'synthetic-other-' + str(i): {'decision': 'investigate'} for i in range(5000 - len(annotations))})
        pending = self.page(annotations, review='pending')
        self.assertTrue(pending['available'], pending)
        self.assertEqual(pending['total_matches'], 1)
        self.assertEqual(pending['rows'][0]['id'], self.expected_id(624))
        self.assertEqual(self.page(annotations, review='recognize')['total_matches'], 624)

    def test_duplicate_variants_aggregate_retained_records_not_flows(self):
        raw = self.raw(1)
        self.write_source(rows=[('outgoing', raw, self.now - 100, self.now - 20),
                                ('outgoing', dict(raw, service='HTTPS'), self.now - 50, self.now - 1),
                                ('incoming', {'source': '203.0.113.10', 'destinationPort': 22}, self.now - 40, self.now - 2)])
        result = self.export(); self.assertEqual((result['raw_retained_count'], result['total_observations']), (3, 2))
        outgoing = self.page(direction='vendor_outgoing')['rows'][0]
        self.assertEqual((outgoing['observation_count'], outgoing['first_observed_at'], outgoing['observed_at']),
                         (2, self.now - 100, self.now - 1))
        self.assertEqual(outgoing['id'], self.expected_id(1))
        self.assertIn('not sessions', outgoing['aggregation_note'])
        self.assertEqual(outgoing['transport'], 'unknown'); self.assertIsNone(outgoing['rx_bytes'])
        incoming = self.page(direction='vendor_incoming')['rows'][0]
        self.assertIsNone(incoming['destination_address']); self.assertEqual(incoming['state'], 'history')

    def test_invalid_source_rows_report_gap_without_hiding_valid_history(self):
        self.write_source(rows=[('outgoing', self.raw(1), self.now - 100, self.now),
                                ('outgoing', 'not JSON', self.now - 100, self.now)])
        result = self.export()
        self.assertEqual((result['state'], result['raw_retained_count'], result['total_observations'], result['row_errors']), ('partial', 2, 1, 1))
        self.assertEqual(len(self.page()['rows']), 1)

    def test_context_change_and_unfresh_current_guard_never_inherit_reviews(self):
        self.export(); changed = copy.deepcopy(self.snapshot)
        changed['network_id'] = '32345678-1234-5678-1234-567812345678'
        self.assertFalse(self.reader().summary(changed, {})['available'])
        self.assertFalse(self.reader().contains(self.expected_id(1), changed))
        changed = copy.deepcopy(self.snapshot); changed['network_binding_sha256'] = 'c' * 64
        self.assertFalse(self.reader().summary(changed, {})['available'])
        changed = copy.deepcopy(self.snapshot); changed['sources']['guard']['state'] = 'stale'
        self.assertFalse(self.reader().contains(self.expected_id(1), changed))
        self.assertFalse(self.reader().summary(changed, {})['available'])

    def test_old_archive_browsable_only_with_fresh_matching_context_but_not_review_authority(self):
        self.export()
        fresh_context = copy.deepcopy(self.snapshot)
        fresh_context['generated_at'] += 200; fresh_context['sources']['guard']['checked_at'] += 200
        reader = self.reader(now=self.now + 200)
        summary = reader.summary(fresh_context, {})
        self.assertTrue(summary['available']); self.assertEqual(summary['state'], 'stale')
        self.assertFalse(reader.contains(self.expected_id(1), fresh_context))
        self.assertFalse(reader.summary(self.snapshot, {})['available'])

    def test_failed_new_generation_preserves_previous_bytes_and_is_explicit(self):
        self.export(); before = self.path.read_bytes()
        with mock.patch.object(history, 'MAX_SOURCE_ROWS', 10):
            result = self.export()
        self.assertFalse(result['available']); self.assertIn('E_HISTORY_ROW_LIMIT', result['reason'])
        self.assertEqual(before, self.path.read_bytes())
        failed_snapshot = copy.deepcopy(self.snapshot); failed_snapshot['sources']['history'] = result
        self.assertFalse(self.reader().summary(failed_snapshot, {})['available'])
        self.assertFalse(self.reader().contains(self.expected_id(1), failed_snapshot))

    def test_runtime_and_output_limits_fail_without_partial_replacement(self):
        self.export(); before = self.path.read_bytes()
        tick = [0]
        def elapsed():
            tick[0] += 1
            return 0 if tick[0] == 1 else 100
        self.assertIn('E_HISTORY_RUNTIME_LIMIT', self.export(monotonic=elapsed)['reason'])
        self.assertEqual(before, self.path.read_bytes())
        with mock.patch.object(history, 'MAX_HISTORY_BYTES', 4096):
            result = self.export()
        self.assertFalse(result['available']); self.assertIn('E_HISTORY_OUTPUT_LIMIT', result['reason'])
        self.assertEqual(before, self.path.read_bytes())

    def test_atomic_replacement_is_seen_by_next_request_and_retains_no_old_rows(self):
        self.export(); before = self.path.read_bytes()
        self.write_source(count=2); self.export()
        self.assertNotEqual(before, self.path.read_bytes())
        self.assertEqual(self.reader().summary(self.snapshot, {})['total_observations'], 2)
        self.assertFalse(self.reader().contains(self.expected_id(624), self.snapshot))

    @unittest.skipUnless(os.name == 'posix', 'Pinned-fd replacement semantics require POSIX; sequential replacement is tested everywhere.')
    def test_reader_in_progress_keeps_its_old_inode_across_atomic_replacement(self):
        self.export()
        with self.reader().open(self.snapshot) as (db, _, _):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM history').fetchone()[0], 625)
            self.write_source(count=2)
            self.assertTrue(self.export()['available'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM history').fetchone()[0], 625)
        self.assertEqual(self.reader().summary(self.snapshot, {})['total_observations'], 2)

    def test_actual_handoff_symlink_is_unavailable(self):
        self.export()
        alias = self.handoff / 'symlink.sqlite3'
        try:
            os.symlink(self.path, alias)
        except (OSError, NotImplementedError):
            self.skipTest('This platform/sandbox does not permit creating a synthetic symlink.')
        reader = history.HistoryReader(alias, _uid=self.uid, _gid=self.gid, _clock=lambda: self.now)
        self.assertFalse(reader.summary(self.snapshot, {})['available'])

    def test_actual_hardlink_cannot_be_served_or_overwritten(self):
        self.export(); before = self.path.read_bytes()
        try:
            os.link(self.path, self.handoff / 'alias.sqlite3')
        except (OSError, NotImplementedError):
            self.skipTest('This platform/sandbox does not permit creating a synthetic hard link.')
        self.assertFalse(self.reader().summary(self.snapshot, {})['available'])
        self.assertFalse(self.export()['available'])
        self.assertEqual(before, self.path.read_bytes())

    def test_bad_queries_rejected_and_unavailable_counts_not_fabricated_zero(self):
        for change in ({'offset': True}, {'offset': -1}, {'limit': 101}, {'limit': 0}, {'search': 'x' * 201},
                       {'search': 'bad\ntext'}, {'review': 'approved'}, {'direction': 'outgoing'}, {'extra': True}):
            with self.subTest(change=change), self.assertRaisesRegex(history.HistoryError, 'E_HISTORY_QUERY'):
                self.reader().page({**self.query, **change}, {}, self.snapshot)
        summary = self.reader().summary(self.snapshot, {})
        self.assertFalse(summary['available']); self.assertIsNone(summary['total_observations'])
        self.export()
        annotations = {'id' + str(i): {'decision': 'recognize'} for i in range(5001)}
        self.assertFalse(self.reader().summary(self.snapshot, annotations)['available'])

    def test_link_and_exact_permission_guards(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=2, st_nlink=1)
        with mock.patch.object(history.os, 'name', 'posix'):
            history.file_metadata(good, 0, 2, 0o640)
            for change in ({'st_mode': stat.S_IFLNK | 0o777}, {'st_nlink': 2}, {'st_uid': 1000},
                           {'st_gid': 3}, {'st_mode': stat.S_IFREG | 0o644}):
                fields = vars(good).copy(); fields.update(change)
                with self.assertRaises(history.HistoryError):
                    history.file_metadata(SimpleNamespace(**fields), 0, 2, 0o640)


if __name__ == '__main__':
    unittest.main()
