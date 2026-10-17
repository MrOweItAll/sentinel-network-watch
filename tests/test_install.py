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
        self.assertFalse(report["dashboard_auth_created"])
        self.assertFalse(report["hub_service_enabled"])
        self.assertFalse(report["browser_opened"])
        self.assertFalse(report["system_commands_run"])
        for name in installer.MODULES:
            self.assertTrue((self.prefix / "opt/sentinel-network-watch/sentinel_watch" / name).is_file())
        self.assertFalse((self.prefix / "etc/sentinel-alerts/config.json").exists())
        self.assertFalse((self.prefix / "etc/sentinel-hub/config.json").exists())
        self.assertFalse((self.prefix / "etc/sentinel-hub/dashboard-auth.json").exists())
        self.assertTrue((self.prefix / "etc/systemd/system/sentinel-hub.service").is_file())
        self.assertTrue((self.prefix / "usr/share/applications/sentinel-hub.desktop").is_file())
        self.assertFalse((self.prefix / "etc/systemd/system/timers.target.wants").exists())
        self.assertFalse((self.prefix / "etc/systemd/system/multi-user.target.wants").exists())
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
                          ["review", "--help"], ["windows-snapshot", "--help"],
                          ["hub", "--help"], ["hub", "serve", "--help"]):
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
        for relative in ("etc/sentinel-hub", "var/lib/sentinel-hub"):
            self.assertEqual((self.prefix / relative).stat().st_mode & 0o777, 0o700)

    def test_hub_only_preserves_differing_original_units(self):
        originals = {}
        for name in installer.LEGACY_UNITS:
            target = self.prefix / "etc/systemd/system" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            originals[target] = ("existing independently managed " + name).encode()
            target.write_bytes(originals[target])
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("system command")):
            result = installer.install(self.prefix, hub_only=True)
        self.assertTrue(result["hub_only"])
        self.assertFalse(result["legacy_units_included"])
        for target, content in originals.items():
            self.assertEqual(target.read_bytes(), content)
        self.assertTrue((self.prefix / "etc/systemd/system/sentinel-hub.service").is_file())
        self.assertTrue((self.prefix / "var/lib/sentinel-hub").is_dir())
        self.assertFalse((self.prefix / "var/lib/sentinel-alerts").exists())
        self.assertFalse((self.prefix / "var/lib/sentinel-router").exists())
        self.assertEqual(installer.install(self.prefix, hub_only=True)["files_installed"], 0)

    def test_hub_only_conflict_refuses_before_new_writes(self):
        target = self.prefix / "etc/systemd/system/sentinel-hub.service"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"existing hub unit")
        with self.assertRaisesRegex(installer.InstallError, "E_EXISTING_FILE"):
            installer.install(self.prefix, hub_only=True)
        self.assertEqual(target.read_bytes(), b"existing hub unit")
        self.assertFalse((self.prefix / "opt").exists())

    def test_hub_unit_and_desktop_keep_narrow_boundary(self):
        unit = (ROOT / "deploy/sentinel-hub.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/local/bin/sentinel-network-watch hub serve --config /etc/sentinel-hub/config.json", unit)
        self.assertEqual([line for line in unit.splitlines() if line.startswith("ReadWritePaths=")],
                         ["ReadWritePaths=/var/lib/sentinel-hub"])
        self.assertIn("CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE", unit)
        self.assertNotIn("NET_ADMIN", unit)
        self.assertNotIn("NET_RAW", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ProtectProc=default", unit)
        desktop = (ROOT / "deploy/sentinel-hub.desktop").read_text(encoding="utf-8")
        self.assertEqual([line for line in desktop.splitlines() if line.startswith("Exec=")],
                         ["Exec=xdg-open http://127.0.0.1:8765/"])
        self.assertNotIn("sudo", desktop)
        self.assertNotIn("token", desktop.lower())

    def test_hub_example_rejects_unconfigured_network(self):
        source = str(ROOT / "src")
        with mock.patch.object(sys, "path", [source, *sys.path]):
            from sentinel_watch import hub
        example = json.loads((ROOT / "examples/hub.json.example").read_text(encoding="utf-8"))
        with mock.patch.object(hub, "read_private", return_value=example):
            with self.assertRaisesRegex(hub.HubError, "E_HUB_CONFIG"):
                hub.load_config(Path("not-opened-fixture.json"))
        # Isolate the network guard from the other deliberately invalid placeholders.
        example["expected_host_fingerprint"] = "a" * 64
        example["expected_gateway_fingerprint"] = "b" * 64
        with mock.patch.object(hub, "read_private", return_value=example):
            with self.assertRaisesRegex(hub.HubError, "E_HUB_CONFIG"):
                hub.load_config(Path("not-opened-fixture.json"))

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
