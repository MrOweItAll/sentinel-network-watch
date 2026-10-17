"""Private synthetic backup fixtures; no host configs or real credentials."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sentinel_watch import backup

PASSWORD = "synthetic-only-long-passphrase"


class FakeGpg:
    def __init__(self):
        self.archive = None
        self.calls = []
        self.fail = False
        self.bad_mdc = False

    def __call__(self, command, **options):
        self.calls.append((command, options))
        if self.fail:
            raise RuntimeError("FAKE_PRIVATE_GPG_EXCEPTION")
        if "--decrypt" in command:
            options["stdout"].write(self.archive)
            status = b"[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] " + (b"BADMDC" if self.bad_mdc else b"GOODMDC") + b"\n"
        else:
            self.archive = Path(command[-1]).read_bytes()
            options["stdout"].write(b"SYNTHETIC_CIPHERTEXT:" + hashlib.sha256(self.archive).digest())
            status = b"[GNUPG:] BEGIN_ENCRYPTION 2 9\n[GNUPG:] END_ENCRYPTION\n"
        return SimpleNamespace(returncode=0, stderr=status)


def archive_bytes(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, body in members:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


class BackupFixtures(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            native_mkdir = os.mkdir
            patcher = mock.patch.object(os, "mkdir", side_effect=lambda path, mode=0o777, **kw:
                                        native_mkdir(path, 0o777 if mode == 0o700 else mode, **kw))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix=".test-backup-", dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "backups"
        self.source = self.root / "closed-snapshot.json"
        self.source.write_bytes(b'{"synthetic":"FAKE_PRIVATE_BODY"}\n')
        self.files = {"hub/config.json": self.source}
        self.gpg = FakeGpg()

    def create(self, **options):
        return backup.create_backup(self.files, self.output, PASSWORD, runner=self.gpg, **options)

    def assert_no_plaintext(self):
        self.assertFalse(list(self.output.glob(".backup-*")))
        self.assertFalse(list(self.output.glob(".inspect-*")))
        self.assertFalse(list(self.output.glob("*.tar")))

    def test_manifest_and_encrypted_file_metadata(self):
        result = self.create()
        encrypted = self.output / result["filename"]
        self.assertRegex(result["filename"], r"^[a-f0-9]{32}\.tar\.gpg$")
        self.assertEqual(result["sha256"], hashlib.sha256(encrypted.read_bytes()).hexdigest())
        self.assertEqual(result["manifest"]["files"]["hub/config.json"]["sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertFalse(result["system_backup_complete"])
        self.assertFalse(result["restore_verified"])
        self.assertNotIn("FAKE_PRIVATE_BODY", json.dumps(result))
        self.assertNotIn(PASSWORD, json.dumps(result))
        if os.name == "posix":
            self.assertEqual(encrypted.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assert_no_plaintext()

    def test_password_only_goes_to_anonymous_stdin_pipe(self):
        self.create()
        command, options = self.gpg.calls[0]
        self.assertEqual(options["input"], PASSWORD.encode() + b"\n")
        self.assertEqual(command[command.index("--passphrase-fd") + 1], "0")
        self.assertNotIn(PASSWORD, " ".join(command))
        self.assertNotIn(PASSWORD, json.dumps(options["env"]))
        self.assertIn("--batch", command)
        self.assertIn("--no-tty", command)
        self.assertIn("--no-options", command)
        self.assertIn("--no-symkey-cache", command)
        self.assertEqual(command[command.index("--cipher-algo") + 1], "AES256")
        self.assertEqual(command[command.index("--s2k-mode") + 1], "3")
        self.assertEqual(options["timeout"], 60)

    def test_inspection_verifies_hashes_without_restoring(self):
        result = self.create()
        inspected = backup.inspect_backup(self.output / result["filename"], PASSWORD, runner=self.gpg)
        self.assertTrue(inspected["integrity_verified"])
        self.assertFalse(inspected["files_restored"])
        self.assertEqual(inspected["manifest"], result["manifest"])
        self.assertFalse((self.output / "hub").exists())
        self.assert_no_plaintext()

    def test_weak_or_multiline_passphrases_rejected_before_writes(self):
        for value in ("short", "long-but-newline\nsecret", "x" * 1025, None):
            with self.assertRaisesRegex(backup.BackupError, "E_BACKUP_PASSPHRASE"):
                backup.create_backup(self.files, self.output, value, runner=self.gpg)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.gpg.calls, [])

    def test_unsafe_archive_names_are_rejected(self):
        for name in ("../escape", "/absolute", "a/../b", "a//b", "a\\b", "manifest.json", "C:/file"):
            with self.assertRaises(backup.BackupError):
                backup.create_backup({name: self.source}, self.output, PASSWORD, runner=self.gpg)
        self.assertEqual(self.gpg.calls, [])
        self.assert_no_plaintext()

    def test_directory_sources_are_not_recursed(self):
        with self.assertRaisesRegex(backup.BackupError, "E_SOURCE_FILE"):
            backup.create_backup({"hub/directory": self.root}, self.output, PASSWORD, runner=self.gpg)
        self.assertEqual(self.gpg.calls, [])

    def test_hardlinked_source_is_rejected(self):
        link = self.root / "source-link.json"
        try:
            os.link(self.source, link)
        except OSError:
            self.skipTest("hardlink creation unavailable")
        with self.assertRaisesRegex(backup.BackupError, "E_SOURCE_FILE"):
            self.create()

    def test_symlink_source_is_rejected(self):
        link = self.root / "source-symlink.json"
        try:
            link.symlink_to(self.source)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(backup.BackupError, "E_PATH_LINK"):
            backup.create_backup({"hub/config.json": link}, self.output, PASSWORD, runner=self.gpg)

    def test_file_and_total_limits_fail_before_gpg(self):
        with mock.patch.object(backup, "MAX_TOTAL_BYTES", 1):
            with self.assertRaisesRegex(backup.BackupError, "E_SOURCE_LIMIT"):
                self.create()
        with mock.patch.object(backup, "MAX_FILES", 0):
            with self.assertRaisesRegex(backup.BackupError, "E_SOURCE_LIST"):
                self.create()
        self.assertEqual(self.gpg.calls, [])

    def test_gpg_failure_is_sanitized_and_cleans_plaintext(self):
        self.gpg.fail = True
        with self.assertRaises(backup.BackupError) as error:
            self.create()
        self.assertEqual(str(error.exception), "E_GPG_FAILED")
        self.assertNotIn("FAKE_PRIVATE", str(error.exception))
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertTrue(self.source.exists())

    def test_gpg_timeout_cleans_plaintext(self):
        def timeout(*args, **options):
            raise subprocess.TimeoutExpired("FAKE_PRIVATE_COMMAND", 60)
        with self.assertRaisesRegex(backup.BackupError, "E_GPG_FAILED"):
            backup.create_backup(self.files, self.output, PASSWORD, runner=timeout)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_existing_archive_is_never_replaced_or_removed(self):
        with mock.patch.object(backup.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)):
            first = self.create()
            original = (self.output / first["filename"]).read_bytes()
            with self.assertRaises(backup.BackupError):
                self.create()
        self.assertEqual((self.output / first["filename"]).read_bytes(), original)
        self.assert_no_plaintext()

    def test_bad_integrity_status_is_rejected(self):
        result = self.create()
        self.gpg.bad_mdc = True
        with self.assertRaisesRegex(backup.BackupError, "E_GPG_FAILED"):
            backup.inspect_backup(self.output / result["filename"], PASSWORD, runner=self.gpg)
        self.assert_no_plaintext()

    def test_member_hash_mismatch_is_rejected(self):
        result = self.create()
        manifest = json.dumps(result["manifest"]).encode()
        self.gpg.archive = archive_bytes([("hub/config.json", b"changed"), ("manifest.json", manifest)])
        with self.assertRaisesRegex(backup.BackupError, "E_BACKUP_MANIFEST"):
            backup.inspect_backup(self.output / result["filename"], PASSWORD, runner=self.gpg)
        self.assert_no_plaintext()

    def test_decrypted_traversal_is_not_extracted(self):
        result = self.create()
        self.gpg.archive = archive_bytes([("../escape", b"synthetic")])
        with self.assertRaisesRegex(backup.BackupError, "E_ARCHIVE_NAME"):
            backup.inspect_backup(self.output / result["filename"], PASSWORD, runner=self.gpg)
        self.assertFalse((self.root / "escape").exists())
        self.assert_no_plaintext()

    def test_source_change_during_archive_fails_closed(self):
        original = backup._HashingReader.read
        changed = False
        def racing(reader, count):
            nonlocal changed
            data = original(reader, count)
            if not changed:
                changed = True
                before = self.source.stat()
                os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000))
            return data
        with mock.patch.object(backup._HashingReader, "read", racing):
            with self.assertRaisesRegex(backup.BackupError, "E_SOURCE_CHANGED"):
                self.create()
        self.assertEqual(self.gpg.calls, [])
        self.assert_no_plaintext()

    @unittest.skipUnless(sys.platform.startswith("linux") and Path("/usr/bin/gpg").is_file(), "Linux GnuPG fixture")
    def test_real_gpg_encrypt_inspect_and_wrong_passphrase(self):
        result = backup.create_backup(self.files, self.output, PASSWORD)
        self.assertNotIn(b"FAKE_PRIVATE_BODY", (self.output / result["filename"]).read_bytes())
        verified = backup.inspect_backup(self.output / result["filename"], PASSWORD)
        self.assertTrue(verified["integrity_verified"])
        with self.assertRaisesRegex(backup.BackupError, "E_GPG_FAILED"):
            backup.inspect_backup(self.output / result["filename"], "different-synthetic-long-passphrase")
        self.assert_no_plaintext()


if __name__ == "__main__":
    unittest.main()
