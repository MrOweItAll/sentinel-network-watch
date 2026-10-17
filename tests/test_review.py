"""Offline fixtures only; no endpoint discovery, DNS or network calls."""
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel_watch import review as cr


class ReviewQueueTests(unittest.TestCase):
    def setUp(self):
        # Windows 3.14's mkdir(mode=0700) DACL excludes this sandbox token.
        # Use inherited ACLs for fixture folders only, never alter production.
        self.root = Path(__file__).parent / ("fixture-review-" + os.urandom(8).hex())
        self.root.mkdir(mode=0o777)
        self.now = 1000.0
        self.queue = cr.ReviewQueue(self.root / "review.db", clock=lambda: self.now)
        self.network_guard = patch.object(socket, "socket", side_effect=AssertionError("offline fixture"))
        self.network_guard.start()

    def tearDown(self):
        self.network_guard.stop()
        self.queue.close()
        shutil.rmtree(self.root)

    def record(self, **changes):
        record = dict(actor_key="windows:fixture", app_context_key="process:fixture:created-1",
                      kind="native_tcp", transport="TCP", destination_address="192.0.2.5",
                      destination_port=443, observed_at=1000, observation_id="capture-1:row-1",
                      evidence={"source": "fixture", "pid": 42, "state": "Established"})
        record.update(changes)
        return record

    def approve(self, rid, **changes):
        args = dict(scope_endpoint=True, expires_seconds=60)
        args.update(changes)
        return self.queue.decide(rid, "approve", **args)

    def test_first_observation_is_pending_and_replay_idempotent(self):
        first = self.queue.ingest(self.record())
        self.assertEqual((first["review_id"], first["status"], first["sightings"]), ("C0001", "pending", 1))
        again = self.queue.ingest(self.record())
        self.assertFalse(again["new_sighting"])
        self.assertEqual(again["sightings"], 1)

    def test_reused_observation_id_with_changed_evidence_rejected(self):
        self.queue.ingest(self.record())
        with self.assertRaisesRegex(cr.ReviewError, "E_OBSERVATION_ID_CONFLICT"):
            self.queue.ingest(self.record(evidence={"state": "Listen"}))
        self.assertEqual(self.queue.status()["relationships"], 1)

    def test_relationship_key_is_exact_for_every_field(self):
        original = self.queue.ingest(self.record())
        self.approve(original["review_id"])
        changes = [("actor_key", "router:fixture"), ("app_context_key", "process:fixture:created-2"),
                   ("kind", "listener"), ("transport", "unknown"),
                   ("destination_address", "192.0.2.6"), ("destination_port", 8443)]
        for index, (key, value) in enumerate(changes):
            with self.subTest(key=key):
                row = self.queue.ingest(self.record(**{key: value, "observation_id": f"other-{index}"}))
                self.assertNotEqual(row["review_id"], original["review_id"])
                self.assertEqual(row["status"], "pending_more_evidence" if key == "transport" else "pending")

    def test_router_unknown_transport_cannot_inherit_tcp(self):
        first = self.queue.ingest(self.record(kind="router_record"))
        self.approve(first["review_id"])
        row = self.queue.ingest(self.record(kind="router_record", transport="unknown", observation_id="router-unknown"))
        self.assertEqual(row["status"], "pending_more_evidence")

    def test_unknown_transport_is_unapprovable_but_can_be_rejected(self):
        row = self.queue.ingest(self.record(kind="router_record", transport="unknown"))
        self.assertEqual(row["status"], "pending_more_evidence")
        with self.assertRaisesRegex(cr.ReviewError, "E_INCOMPLETE_ENDPOINT"):
            self.approve(row["review_id"])
        rejected = self.queue.decide(row["review_id"], "reject", scope_endpoint=True, expires_seconds=60)
        self.assertEqual(rejected["status"], "not_approved")
        self.assertFalse(rejected["blocking_action"])
        self.now += 60
        self.assertEqual(self.queue.read(row["review_id"])["status"], "pending_more_evidence")

    def test_legacy_unknown_transport_approval_is_preserved_but_ineffective(self):
        row = self.queue.ingest(self.record(kind="router_record", transport="unknown"))
        # Model a pre-policy decision in this temporary fixture database only.
        with self.queue.db:
            self.queue.db.execute("""INSERT INTO decisions
                (relationship_id,relationship_key,decision,scope,decided_at,expires_at,until_revoked)
                VALUES(1,?,'approve','endpoint',1000,1060,0)""", (row["relationship_key"],))
        current = self.queue.read(row["review_id"])
        self.assertEqual(current["status"], "pending_more_evidence")
        self.assertEqual(current["decision"]["decision"], "approve")
        self.assertFalse(current["decision"]["active"])
        self.assertEqual(self.queue.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0], 1)

    def test_expiry_returns_pending_exact_boundary(self):
        row = self.queue.ingest(self.record())
        self.assertEqual(self.approve(row["review_id"])["status"], "approved")
        self.now = 1060
        self.assertEqual(self.queue.read(row["review_id"])["status"], "pending")

    def test_reject_does_not_block_and_can_be_reconsidered(self):
        rid = self.queue.ingest(self.record())["review_id"]
        row = self.queue.decide(rid, "reject", scope_endpoint=True, until_revoked=True)
        self.assertEqual(row["status"], "not_approved")
        self.assertFalse(row["blocking_action"])
        self.assertEqual(self.approve(rid)["status"], "approved")

    def test_persistence_and_sequential_ids(self):
        rid = self.queue.ingest(self.record())["review_id"]
        self.approve(rid, expires_seconds=None, until_revoked=True)
        self.queue.close()
        self.queue = cr.ReviewQueue(self.root / "review.db", clock=lambda: self.now)
        self.now += 100000
        self.assertEqual(self.queue.read(rid)["status"], "approved")
        self.assertEqual(self.queue.ingest(self.record(destination_port=80, observation_id="second"))["review_id"], "C0002")

    def test_sightings_and_time_range_not_session_count(self):
        self.queue.ingest(self.record())
        later = self.queue.ingest(self.record(observation_id="new-capture", observed_at=1200))
        earlier = self.queue.ingest(self.record(observation_id="older-capture", observed_at=900))
        self.assertEqual((earlier["first_seen"], later["last_seen"], earlier["sightings"]), (900, 1200, 3))
        self.assertNotIn("sessions", earlier)

    def test_incomplete_router_endpoint_stays_unapprovable(self):
        row = self.queue.ingest(self.record(kind="router_record", transport="TCP", destination_address=None))
        self.assertEqual(row["status"], "pending_more_evidence")
        with self.assertRaisesRegex(cr.ReviewError, "E_INCOMPLETE_ENDPOINT"):
            self.approve(row["review_id"])
        complete = self.queue.ingest(self.record(kind="router_record", transport="TCP", observation_id="complete"))
        self.assertNotEqual(row["review_id"], complete["review_id"])
        self.assertEqual(self.queue.status()["counts"]["pending_more_evidence"], 1)

    def test_address_canonicalization_preserves_ipv6_scope(self):
        a = self.queue.ingest(self.record(destination_address="fe80:0:0:0:0:0:0:1%12"))
        self.assertEqual(a["destination_address"], "fe80::1%12")
        b = self.queue.ingest(self.record(destination_address="fe80::1%13", observation_id="scope13"))
        self.assertNotEqual(a["review_id"], b["review_id"])

    def test_invalid_ports_and_blank_context_rejected(self):
        for port in (-1, 0, 65536, True, "443", 1.0, None):
            with self.subTest(port=port), self.assertRaises(cr.ReviewError):
                self.queue.ingest(self.record(destination_port=port))
        with self.assertRaises(cr.ReviewError):
            self.queue.ingest(self.record(app_context_key=""))

    def test_metadata_never_truncated_or_private_fields_accepted(self):
        for evidence in ({"source": "x" * 2049}, {"token": "fixture-nonsecret"},
                         {"nested": {"x": 1}}, {"n": float("nan")},
                         {str(i): "x" * 1000 for i in range(9)}):
            with self.subTest(keys=list(evidence)), self.assertRaises(cr.ReviewError):
                self.queue.ingest(self.record(evidence=evidence))
        self.assertEqual(self.queue.status()["relationships"], 0)

    def test_decision_needs_explicit_scope_and_duration(self):
        rid = self.queue.ingest(self.record())["review_id"]
        for kwargs in ({}, {"scope_endpoint": True}, {"scope_endpoint": True, "expires_seconds": 0},
                       {"scope_endpoint": True, "expires_seconds": 86401},
                       {"scope_endpoint": True, "expires_seconds": 60, "until_revoked": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(cr.ReviewError):
                self.queue.decide(rid, "approve", **kwargs)
        self.assertEqual(self.queue.read(rid)["status"], "pending")

    def test_default_observation_hash_is_idempotent(self):
        record = self.record()
        del record["observation_id"]
        del record["observed_at"]
        self.queue.ingest(record)
        self.now += 2
        self.assertFalse(self.queue.ingest(record)["new_sighting"])

    def test_path_rejects_outside_cli_root_and_hardlinks(self):
        with patch.object(cr, "CASE_ROOT", self.root / 'another-case'):
            with self.assertRaisesRegex(cr.ReviewError, "E_PATH_OUTSIDE_PRIVATE_ROOT"):
                cr.validate_path(self.root / "other.db", project_access=True)
        target = self.root / "review.db"
        original = Path.lstat
        def hardlinked(path):
            info = original(path)
            if path == target:
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=2,
                                       st_file_attributes=getattr(info, "st_file_attributes", 0))
            return info
        with patch.object(Path, "lstat", hardlinked):
            with self.assertRaisesRegex(cr.ReviewError, "E_PATH_NOT_PRIVATE_REGULAR_FILE"):
                cr.validate_path(target)

    def test_path_rejects_reparse_ancestor(self):
        original = Path.lstat
        def reparse(path):
            info = original(path)
            if path == self.root:
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                       st_file_attributes=0x400)
            return info
        with patch.object(Path, "lstat", reparse):
            with self.assertRaisesRegex(cr.ReviewError, "E_PATH_LINK"):
                cr.validate_path(self.root / "review.db")

    def test_corrupt_truncated_json_is_not_an_observation(self):
        with self.assertRaises(json.JSONDecodeError):
            json.loads('{"actor_key":"fixture","evidence":')
        self.assertEqual(self.queue.status()["relationships"], 0)

    def test_record_cap_rolls_back_without_discarding_existing(self):
        self.queue.max_records = 1
        rid = self.queue.ingest(self.record())["review_id"]
        self.approve(rid)
        with self.assertRaisesRegex(cr.ReviewError, "E_QUEUE_CAP"):
            self.queue.ingest(self.record(destination_port=8443, observation_id="over-cap"))
        self.assertEqual(self.queue.status()["relationships"], 1)
        self.assertEqual(self.queue.read(rid)["status"], "approved")
        self.assertFalse(self.queue.ingest(self.record())["new_sighting"])

    def test_database_logical_cap_rolls_back_new_observation(self):
        self.queue.max_db_bytes = 4096
        with self.assertRaisesRegex(cr.ReviewError, "E_QUEUE_CAP"):
            self.queue.ingest(self.record())
        self.assertEqual(self.queue.status()["relationships"], 0)


if __name__ == "__main__":
    unittest.main()
