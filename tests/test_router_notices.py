"""Offline router-notice API fixtures; no live network, configuration or credentials."""

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

from sentinel_watch import alerts as sut
import test_alerts as fixtures


class RouterNoticeTests(unittest.TestCase):
    def setUp(self):
        # Reuse the established isolated state, denied sockets and Windows test ACL shim.
        self.fixture = fixtures.AlertEngineTests(
            "test_pending_event_survives_restart_and_is_sent_once")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.engine = self.fixture.engine
        self.http = self.fixture.http

    def event(self, event_id):
        with closing(sqlite3.connect(self.engine.db_path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
            return None if row is None else dict(row)

    def test_categories_enqueue_only_fixed_private_safe_messages_without_network(self):
        for category in sorted(sut.ROUTER_NOTICE_CATEGORIES):
            with self.subTest(category=category):
                notice_id = uuid.uuid4().hex
                event_id = self.engine.enqueue_router_notice(notice_id, category)
                row = self.event(event_id)
                self.assertEqual(row["kind"], category)
                self.assertEqual(row["state"], "pending")
                self.assertEqual(str(uuid.UUID(event_id)), event_id)
                self.assertNotIn(notice_id, row["body"])
                self.assertNotIn(self.fixture.config.topic, row["body"])
                self.assertNotIn(self.fixture.config.token, row["body"])
                self.assertIn(" Event " + event_id, row["body"])
                self.assertEqual(row["priority"], 4 if category == "router_collection_degraded" else 3)
        self.assertEqual(self.http.calls, [])

    def test_pending_notice_replay_after_crash_before_ack_is_idempotent(self):
        notice_id = uuid.uuid4().hex
        event_id = self.engine.enqueue_router_notice(notice_id, "inventory_change")
        original = self.event(event_id)
        self.engine = self.fixture.new_engine()
        replay = self.engine.enqueue_router_notice(notice_id, "inventory_change")
        self.assertEqual(replay, event_id)
        self.assertEqual(self.event(event_id), original)
        self.assertEqual(self.http.calls, [])
        self.engine.tick()
        self.assertEqual(self.http.methods(), ["POST", "GET"])

    def test_verified_replay_after_restart_does_not_reset_or_republish(self):
        notice_id = uuid.uuid4().hex
        event_id = self.engine.enqueue_router_notice(notice_id, "router_collection_recovered")
        self.engine.tick()
        original = self.event(event_id)
        self.assertEqual(original["state"], "verified")
        self.engine = self.fixture.new_engine()
        self.assertEqual(self.engine.enqueue_router_notice(notice_id, "router_collection_recovered"), event_id)
        self.assertEqual(self.event(event_id), original)
        self.engine.tick()
        self.assertEqual(len(self.http.posts()), 1)

    def test_notice_id_cannot_change_category(self):
        notice_id = uuid.uuid4().hex
        event_id = self.engine.enqueue_router_notice(notice_id, "router_collection_degraded")
        original = self.event(event_id)
        with self.assertRaises(sut.SafeError) as error:
            self.engine.enqueue_router_notice(notice_id, "router_collection_recovered")
        self.assertEqual(error.exception.code, "E_ARGUMENT")
        self.assertEqual(self.event(event_id), original)

    def test_only_opaque_lowercase_32hex_ids_and_fixed_categories_are_accepted(self):
        invalid_ids = ("", "private-topic", "192.0.2.10", uuid.uuid4().hex.upper(),
                       str(uuid.uuid4()), "a" * 31, "a" * 33, "g" * 32, None)
        for notice_id in invalid_ids:
            with self.subTest(notice_id=notice_id), self.assertRaises(sut.SafeError) as error:
                self.engine.enqueue_router_notice(notice_id, "inventory_change")
            self.assertEqual(error.exception.code, "E_ARGUMENT")
        for category in ("boot", "test", "private details", "INVENTORY_CHANGE", None):
            with self.subTest(category=category), self.assertRaises(sut.SafeError) as error:
                self.engine.enqueue_router_notice(uuid.uuid4().hex, category)
            self.assertEqual(error.exception.code, "E_ARGUMENT")
        self.assertEqual(self.http.calls, [])

    def test_full_queue_accepts_duplicate_but_retains_unverified_before_new_notice(self):
        self.engine = sut.AlertEngine(
            Path(self.fixture.directory.name) / "capacity", self.fixture.config,
            transport=self.http, clock=self.fixture.clock, check_provider=lambda: {},
            boot_id_provider=lambda: "unknown", max_events=1)
        first = uuid.uuid4().hex
        second = uuid.uuid4().hex
        first_event = self.engine.enqueue_router_notice(first, "inventory_change")
        self.assertEqual(self.engine.enqueue_router_notice(first, "inventory_change"), first_event)
        with self.assertRaises(sut.SafeError) as error:
            self.engine.enqueue_router_notice(second, "inventory_change")
        self.assertEqual(error.exception.code, "E_QUEUE_FULL")
        self.assertEqual(self.event(first_event)["state"], "pending")
        self.engine.tick()
        self.assertEqual(self.event(first_event)["state"], "verified")
        second_event = self.engine.enqueue_router_notice(second, "inventory_change")
        self.assertIsNone(self.event(first_event))
        self.assertEqual(self.event(second_event)["state"], "pending")

    def test_enqueue_failure_rolls_back_history_pruning(self):
        with closing(sqlite3.connect(self.engine.db_path)) as connection:
            connection.execute("UPDATE events SET verified_at=? WHERE state='verified'",
                               (self.fixture.clock() - sut.VERIFIED_RETENTION - 1,))
            before = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            connection.commit()
        with mock.patch.object(self.engine, "_enqueue", side_effect=sut.SafeError("E_QUEUE_FULL")):
            with self.assertRaises(sut.SafeError):
                self.engine.enqueue_router_notice(uuid.uuid4().hex, "inventory_change")
        with closing(sqlite3.connect(self.engine.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], before)

    def test_old_unverified_notice_survives_pruning(self):
        event_id = self.engine.enqueue_router_notice(uuid.uuid4().hex, "inventory_change")
        self.fixture.clock.advance(sut.VERIFIED_RETENTION + 1)
        self.engine.enqueue_router_notice(uuid.uuid4().hex, "inventory_change")
        self.assertEqual(self.event(event_id)["state"], "pending")

    def test_shared_lock_rejects_concurrent_enqueue_then_replay_succeeds(self):
        notice_id = uuid.uuid4().hex
        with sut._FileLock(self.engine.state_dir / "run.lock"):
            with self.assertRaises(sut.SafeError) as error:
                self.engine.enqueue_router_notice(notice_id, "inventory_change")
        self.assertEqual(error.exception.code, "E_BUSY")
        first = self.engine.enqueue_router_notice(notice_id, "inventory_change")
        self.assertEqual(self.engine.enqueue_router_notice(notice_id, "inventory_change"), first)

    def test_safe_status_contains_no_notice_or_server_or_endpoint_ids(self):
        notice_id = uuid.uuid4().hex
        event_id = self.engine.enqueue_router_notice(notice_id, "inventory_change")
        self.engine.tick()
        status_text = json.dumps(self.engine.status())
        for private_value in (notice_id, event_id, self.event(event_id)["server_id"],
                              self.fixture.config.topic, self.fixture.config.token):
            self.assertNotIn(private_value, status_text)


class RouterFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AlertEngineTests(
            "test_pending_event_survives_restart_and_is_sent_once")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.path = Path(self.fixture.directory.name) / "router-status.json"
        self.now = self.fixture.clock()
        patcher = mock.patch.object(sut, "ROUTER_COLLECTOR_STATUS", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.real_fstat = os.fstat

    def meta(self, fd, uid=0, nlink=1, mode=None):
        actual = self.real_fstat(fd)
        return SimpleNamespace(st_mode=actual.st_mode if mode is None else mode,
                               st_nlink=nlink, st_uid=uid, st_size=actual.st_size)

    def fresh(self, value):
        self.path.write_text(json.dumps(value), encoding="utf-8")
        with mock.patch.object(sut.os, "fstat", side_effect=self.meta):
            return sut._router_collector_fresh(self.now)

    def test_fresh_status_ignores_capability_and_operational_outcomes(self):
        self.assertTrue(self.fresh({"checked_at": self.now, "ok": False,
                                   "complete_stream_visibility": False, "gaps": ["unsupported"]}))
        self.assertTrue(self.fresh({"checked_at": self.now - 180}))
        self.assertTrue(self.fresh({"checked_at": self.now + 30}))

    def test_stale_and_excessively_future_timestamps_fail(self):
        self.assertFalse(self.fresh({"checked_at": self.now - 180.01}))
        self.assertFalse(self.fresh({"checked_at": self.now + 30.01}))

    def test_nonfinite_non_numeric_boolean_or_missing_timestamps_fail(self):
        for value in (float("nan"), float("inf"), float("-inf"), "2000000000", True, None):
            with self.subTest(value=value):
                self.assertFalse(self.fresh({"checked_at": value}))
        self.assertFalse(self.fresh({}))
        self.assertFalse(self.fresh([]))

    def test_missing_malformed_and_oversized_status_fail(self):
        self.assertFalse(sut._router_collector_fresh(self.now))
        for raw in (b"not json", b"x" * 65537):
            self.path.write_bytes(raw)
            with mock.patch.object(sut.os, "fstat", side_effect=self.meta):
                self.assertFalse(sut._router_collector_fresh(self.now))

    def test_nonroot_linked_and_nonregular_files_fail(self):
        self.path.write_text(json.dumps({"checked_at": self.now}), encoding="utf-8")
        for overrides in ({"uid": 1000}, {"nlink": 2}, {"mode": stat.S_IFLNK | 0o600}):
            with self.subTest(overrides=overrides), mock.patch.object(
                    sut.os, "fstat", side_effect=lambda fd: self.meta(fd, **overrides)):
                self.assertFalse(sut._router_collector_fresh(self.now))

    def test_health_check_is_gated_on_installed_timer_only(self):
        timer = Path(self.fixture.directory.name) / "sentinel-router.timer"
        with mock.patch.object(sut, "ROUTER_COLLECTOR_TIMER", timer), \
                mock.patch.object(sut, "_subprocess_ok", return_value=True), \
                mock.patch.object(sut, "_container_running", return_value=True), \
                mock.patch.object(sut, "_dns_check", return_value=True), \
                mock.patch.object(sut, "_web_check", return_value=True), \
                mock.patch.object(sut, "_outbox_filesystem_ok", return_value=True), \
                mock.patch.object(sut, "_router_collector_fresh", return_value=True) as probe:
            self.assertNotIn("router_collector_fresh", sut.service_checks(sut.Config("https://ntfy.test.invalid", "fixture", health_profile="adguard")))
            probe.assert_not_called()
            timer.touch()
            self.assertIs(sut.service_checks(sut.Config("https://ntfy.test.invalid", "fixture", health_profile="adguard"))["router_collector_fresh"], True)
            probe.assert_called_once_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
