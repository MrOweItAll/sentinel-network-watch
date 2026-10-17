"""Offline installer tests; all writes are inside temporary staging roots."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sentinel_public_installer", ROOT / "install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            native_mkdir = os.mkdir
            patcher = mock.patch.object(os, "mkdir", side_effect=lambda path, mode=0o777, **kw:
                                        native_mkdir(path, 0o777 if mode == 0o700 else mode, **kw))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix=".test-install-", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.prefix = Path(self.temporary.name) / "stage"

    def test_staging_curated_layout_and_no_system_commands(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("system command")):
            report = installer.install(self.prefix)
        self.assertTrue(report["ok"])
        self.assertFalse(report["timers_enabled"])
        self.assertFalse(report["configuration_created"])
        self.assertFalse(report["system_commands_run"])
        for name in installer.MODULES:
            self.assertTrue((self.prefix / "opt/sentinel-network-watch/sentinel_watch" / name).is_file())
        self.assertFalse((self.prefix / "etc/sentinel-alerts/config.json").exists())
        self.assertFalse((self.prefix / "etc/systemd/system/timers.target.wants").exists())
        self.assertEqual(installer.install(self.prefix)["files_installed"], 0)

    def test_staged_launcher_runs_doctor(self):
        installer.install(self.prefix)
        result = subprocess.run([sys.executable, "-B", str(self.prefix / "usr/local/bin/sentinel-network-watch"), "doctor"],
                                capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"])
        self.assertFalse(report["network_contacted"])
        # Exercise lazy imports from the installed package too: doctor alone
        # would not detect a missing module required by a delegated command.
        for arguments in (["alerts", "--help"], ["router", "collect", "--help"],
                          ["review", "--help"], ["windows-snapshot", "--help"]):
            help_result = subprocess.run([sys.executable, "-B", str(self.prefix / "usr/local/bin/sentinel-network-watch"), *arguments],
                                         capture_output=True, text=True)
            self.assertEqual(help_result.returncode, 0, arguments)
        self.assertFalse(list(self.prefix.rglob("__pycache__")))

    def test_conflict_is_preserved_before_any_new_file_write(self):
        target = self.prefix / "etc/systemd/system/sentinel-router.timer"
        target.parent.mkdir(parents=True)
        target.write_text("unmanaged configuration", encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "E_EXISTING_FILE"):
            installer.install(self.prefix)
        self.assertEqual(target.read_text(), "unmanaged configuration")
        self.assertFalse((self.prefix / "opt").exists())

    def test_root_prefix_cannot_bypass_privilege_check(self):
        with self.assertRaisesRegex(installer.InstallError, "E_STAGING_ROOT"):
            installer.install(Path(Path.cwd().anchor))

    def test_normalized_root_prefix_refused(self):
        disguised_root = Path(Path.cwd().anchor) / "unused-staging-path" / ".."
        with self.assertRaisesRegex(installer.InstallError, "E_STAGING_ROOT"):
            installer.install(disguised_root)

    @unittest.skipUnless(os.name == "posix", "POSIX umask semantics")
    def test_permissive_umask_cannot_create_writable_code_ancestors(self):
        original = os.umask(0)
        try:
            installer.install(self.prefix)
            restored = os.umask(0)
            self.assertEqual(restored, 0)
        finally:
            os.umask(original)
        for relative in ("opt", "opt/sentinel-network-watch", "opt/sentinel-network-watch/sentinel_watch",
                         "usr", "usr/local", "usr/local/bin", "etc", "etc/systemd", "etc/systemd/system"):
            self.assertFalse((self.prefix / relative).stat().st_mode & 0o022, relative)
        for relative in ("etc/sentinel-alerts", "etc/sentinel-router", "var/lib/sentinel-alerts", "var/lib/sentinel-router"):
            self.assertEqual((self.prefix / relative).stat().st_mode & 0o777, 0o700)

    def test_public_readonly_source_may_be_hardlinked(self):
        source = Path(self.temporary.name) / "public.py"
        link = Path(self.temporary.name) / "public-copy.py"
        source.write_bytes(b"# synthetic public source\n")
        try:
            os.link(source, link)
        except OSError:
            self.skipTest("hardlink creation unavailable")
        self.assertEqual(installer.source_bytes(source), b"# synthetic public source\n")
        self.assertEqual(source.read_bytes(), link.read_bytes())

    def test_real_install_requires_linux_root_before_writes(self):
        with mock.patch.object(installer.sys, "platform", "win32"):
            with self.assertRaisesRegex(installer.InstallError, "E_LINUX_ROOT_REQUIRED"):
                installer.install()
        with mock.patch.object(installer.sys, "platform", "linux"), mock.patch.object(installer.os, "geteuid", return_value=1000, create=True):
            with self.assertRaisesRegex(installer.InstallError, "E_LINUX_ROOT_REQUIRED"):
                installer.install()

    def test_destination_symlink_refused(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        self.prefix.mkdir()
        try:
            (self.prefix / "opt").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(installer.InstallError, "E_INSTALL_LINK"):
            installer.install(self.prefix)
        self.assertEqual(list(outside.iterdir()), [])

    def test_error_output_is_fixed_code(self):
        output = io.StringIO()
        with mock.patch.object(installer, "install", side_effect=RuntimeError("FAKE_PRIVATE_PATH")), contextlib.redirect_stdout(output):
            self.assertEqual(installer.main(["--prefix", str(self.prefix)]), 1)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "error": "E_INSTALL"})

    def test_invalid_arguments_do_not_echo_values(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as stop:
            installer.main(["--password", "FAKE_SECRET_VALUE"])
        self.assertEqual(stop.exception.code, 2)
        self.assertNotIn("FAKE_SECRET_VALUE", error.getvalue())
        self.assertEqual(json.loads(error.getvalue())["error"], "E_ARGUMENT")


if __name__ == "__main__":
    unittest.main()
