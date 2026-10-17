"""Synthetic hub trees and SQLite backups only; no installed config reads."""
import hashlib
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sentinel_watch import backup, hub_backup

PASSWORD = "synthetic-hub-backup-passphrase"
NETWORKS = ("12345678-1234-5678-1234-567812345678", "22345678-1234-5678-1234-567812345678")


class TrackingLock:
    def __init__(self):
        self.active = False
        self.count = 0

    def __enter__(self):
        self.active = True
        self.count += 1
        return self

    def __exit__(self, *_):
        self.active = False


class FakeGpg:
    def __init__(self):
        self.archive = None

    def __call__(self, command, **options):
        if "--decrypt" in command:
            options["stdout"].write(self.archive)
            status = b"[GNUPG:] GOODMDC\n[GNUPG:] DECRYPTION_OKAY\n"
        else:
            self.archive = Path(command[-1]).read_bytes()
            options["stdout"].write(b"FAKE-CIPHER:" + hashlib.sha256(self.archive).digest())
            status = b"[GNUPG:] END_ENCRYPTION\n"
        return SimpleNamespace(returncode=0, stderr=status)


class HubBackupFixtures(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            native_mkdir = os.mkdir
            patcher = mock.patch.object(os, "mkdir", side_effect=lambda path, mode=0o777, **kw:
                                        native_mkdir(path, 0o777 if mode == 0o700 else mode, **kw))
            patcher.start()
            self.addCleanup(patcher.stop)
        # Keep synthetic private files outside a possibly synced checkout. The
        # production hardlink guard must not be weakened to accommodate sync.
        self.temporary = tempfile.TemporaryDirectory(prefix="sentinel-test-hub-backup-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.code = self.root / "code"
        self.code.mkdir(mode=0o700)
        self.write(self.code / "hub.py", b"# synthetic hub code\n")
        self.config = self.write(self.root / "config.json", b'{"synthetic":"hub"}\n')
        self.auth = self.write(self.root / "dashboard-auth.json", b'{"synthetic":"private-auth-hash"}\n')
        self.ntfy = self.write(self.root / "ntfy.json", b'{"token":"FAKE_PRIVATE_NTFY"}\n')
        self.write(self.state / "networks.json", b'{"synthetic":"all-network-profiles"}\n')
        self.write(self.state / "worker-error.json", b'{"ok":false,"code":"E_SYNTHETIC_GAP"}\n')
        self.hub = SimpleNamespace(state=self.state, config_path=self.config,
                                   config={"auth_path": str(self.auth), "alerts_config_path": str(self.ntfy)}, lock=TrackingLock())
        self.databases = []
        for number, network in enumerate(NETWORKS):
            self.database(self.state / "networks" / network / "review.sqlite3", f"network-{number}")
            self.write(self.state / "networks" / network / "status.json", b'{"ok":true}\n')
        self.database(self.state / "alerts/outbox.sqlite3", "pending-notification-intent")
        self.database(self.state / "hub-extra.db", "root-owned-database")
        self.gpg = FakeGpg()
        self.captured = {}
        self.original_create = backup.create_backup
        self.original_inspect = backup.inspect_backup
        self.create_patch = mock.patch.object(backup, "create_backup", side_effect=self._create)
        self.inspect_patch = mock.patch.object(backup, "inspect_backup", side_effect=lambda *a, **kw:
                                             self.original_inspect(*a, **kw, runner=self.gpg))
        for patcher in (mock.patch.object(hub_backup, "CODE_ROOT", self.code),
                        mock.patch.object(hub_backup, "UNIT_PATHS", {}), self.create_patch, self.inspect_patch):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, path, body):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
        return path

    def database(self, path, value):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.write(path, b"")
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE evidence(value TEXT)")
            connection.execute("INSERT INTO evidence VALUES(?)", (value,))
            connection.commit()
        self.databases.append(path)
        return path

    def _create(self, source_files, output_dir, passphrase):
        self.assertTrue(self.hub.lock.active)
        self.assertEqual(output_dir, self.state / "backups")
        self.captured = dict(source_files)
        for name, source in source_files.items():
            if source.suffix == ".sqlite3" and "sqlite-snapshots" not in name:
                if not name.startswith("hub/state/migration/original-windows/"):
                    self.assertNotIn(source, self.databases)
        return self.original_create(source_files, output_dir, passphrase, runner=self.gpg)

    def create(self):
        return hub_backup.create_hub_backup(self.hub, PASSWORD)

    def test_all_network_databases_outbox_and_metadata_are_included(self):
        result = self.create()
        names = set(result["manifest"]["files"])
        for network in NETWORKS:
            self.assertIn(f"hub/state/networks/{network}/review.sqlite3", names)
            self.assertIn(f"hub/state/networks/{network}/status.json", names)
        self.assertIn("hub/state/alerts/outbox.sqlite3", names)
        self.assertIn("hub/state/hub-extra.db", names)
        self.assertIn("hub/state/worker-error.json", names)
        self.assertIn("hub/config.json", names)
        self.assertIn("hub/dashboard-auth.json", names)
        self.assertIn("hub/notifications-config.json", names)
        self.assertEqual(result["sqlite_databases_snapshotted"], 4)
        self.assertTrue(result["integrity_verified"])
        self.assertFalse(result["restore_verified"])
        self.assertFalse(result["system_backup_complete"])
        self.assertTrue(result["local_only"])
        self.assertFalse(result["offhost_copy_verified"])
        self.assertIn("adguard_home_runtime_config_state", result["missing_components"])
        self.assertFalse(self.hub.lock.active)
        self.assertFalse(list(self.state.glob(".hub-backup-*")))

    def test_sqlite_wal_committed_rows_are_snapshotted_without_raw_sidecars(self):
        source = self.databases[0]
        connection = sqlite3.connect(source)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO evidence VALUES('committed-in-wal')")
        connection.commit()
        original = hub_backup._snapshot_database
        rows = []
        def inspect_snapshot(origin, target, deadline):
            self.assertTrue(self.hub.lock.active)
            original(origin, target, deadline)
            if origin == source:
                with closing(sqlite3.connect(target)) as copied:
                    rows.extend(copied.execute("SELECT value FROM evidence").fetchall())
        with mock.patch.object(hub_backup, "_snapshot_database", side_effect=inspect_snapshot):
            result = self.create()
        self.assertIn(("committed-in-wal",), rows)
        self.assertFalse(any(name.endswith(("-wal", "-shm", "-journal")) for name in result["manifest"]["files"]))
        self.assertGreater(result["excluded_transient_entries"], 0)

    def test_historical_closed_original_bytes_and_receipts_are_preserved(self):
        directory = self.state / "migration/original-windows/network-review"
        original = self.database(directory / "original.sqlite3", "original-actor-and-fixed-expiry")
        original_sha = hashlib.sha256(original.read_bytes()).hexdigest()
        for name in ("receipt.json", "capture.raw", "proof.png", "old.sqlite3.previous"):
            self.write(directory / name, b"synthetic original evidence")
        result = self.create()
        names = result["manifest"]["files"]
        key = "hub/state/migration/original-windows/network-review/original.sqlite3"
        self.assertEqual(names[key]["sha256"], original_sha)
        self.assertIn("hub/sqlite-snapshots/migration/original-windows/network-review/original.sqlite3", names)
        self.assertEqual(result["historical_original_databases_preserved"], 1)
        self.assertEqual(result["sqlite_databases_snapshotted"], 5)
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), original_sha)

    def test_raw_capture_outside_explicit_historical_location_fails(self):
        self.write(self.state / "evidence/unapproved.raw", b"synthetic")
        with self.assertRaisesRegex(hub_backup.HubBackupError, "E_HUB_BACKUP_UNCOVERED_STATE"):
            self.create()
        self.assertFalse((self.state / "backups").exists())

    def test_unknown_state_file_is_not_silently_omitted(self):
        self.write(self.state / "unknown.dat", b"synthetic")
        with self.assertRaisesRegex(hub_backup.HubBackupError, "E_HUB_BACKUP_UNCOVERED_STATE"):
            self.create()

    def test_unknown_code_module_fails_instead_of_omission(self):
        self.write(self.code / "unlisted.py", b"# synthetic")
        with self.assertRaisesRegex(hub_backup.HubBackupError, "E_HUB_BACKUP_CODE_SCOPE"):
            self.create()

    def test_backups_and_locks_are_excluded_from_future_backups(self):
        first = self.create()
        self.write(self.state / "daemon.lock", b"")
        second = self.create()
        self.assertNotIn(first["filename"], str(second["manifest"]))
        self.assertGreaterEqual(second["excluded_transient_entries"], 2)

    def test_download_only_accepts_generated_basename_and_private_regular_file(self):
        result = self.create()
        expected = self.state / "backups" / result["filename"]
        self.assertEqual(hub_backup.backup_path(self.hub, result["backup_id"]), expected)
        self.assertEqual(hub_backup.backup_path(self.hub, result["filename"]), expected)
        for name in ("../config.json", str(expected), "A" * 32, result["backup_id"] + "/other"):
            with self.assertRaises(hub_backup.HubBackupError):
                hub_backup.backup_path(self.hub, name)

    def test_snapshot_failure_cleans_temporary_files(self):
        with mock.patch.object(hub_backup, "_snapshot_database", side_effect=RuntimeError("FAKE_PRIVATE_EXCEPTION")):
            with self.assertRaisesRegex(hub_backup.HubBackupError, "E_HUB_BACKUP_FAILED"):
                self.create()
        self.assertFalse(list(self.state.glob(".hub-backup-*")))
        self.assertFalse((self.state / "backups").exists())

    def test_inspection_failure_cannot_claim_verified_backup(self):
        with mock.patch.object(backup, "inspect_backup", side_effect=backup.BackupError("E_GPG_FAILED")):
            with self.assertRaisesRegex(backup.BackupError, "E_GPG_FAILED"):
                self.create()
        self.assertFalse(list(self.state.glob(".hub-backup-*")))

    def test_state_hardlink_is_rejected(self):
        try:
            os.link(self.state / "networks.json", self.root / "network-link")
        except OSError:
            self.skipTest("hardlink creation unavailable")
        with self.assertRaisesRegex(hub_backup.HubBackupError, "E_HUB_BACKUP_FILE"):
            self.create()

    @unittest.skipUnless(sys.platform.startswith("linux") and Path("/usr/bin/gpg").is_file(), "Linux GnuPG integration fixture")
    def test_real_encrypted_hub_backup_and_inspection(self):
        self.create_patch.stop()
        self.inspect_patch.stop()
        result = self.create()
        self.assertTrue(result["integrity_verified"])
        self.assertEqual(result["sqlite_databases_snapshotted"], 4)
        self.assertFalse(result["files_restored"])
        self.assertTrue(hub_backup.backup_path(self.hub, result["filename"]).is_file())


if __name__ == "__main__":
    unittest.main()
