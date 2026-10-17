"""Offline CLI dispatch and hidden-configuration fixtures."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import warnings
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sentinel_watch import __version__, cli


class CliTests(unittest.TestCase):
    def setUp(self):
        # Python 3.13+ gives mkdir(0700) a special Windows DACL. The desktop
        # test sandbox is an AppContainer, so inherit its existing fixture ACL.
        # Production POSIX modes and production Windows privacy code are unchanged.
        if os.name == "nt":
            native_mkdir = os.mkdir
            patcher = mock.patch.object(os, "mkdir", side_effect=lambda path, mode=0o777, **kw:
                                        native_mkdir(path, 0o777 if mode == 0o700 else mode, **kw))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix=".test-cli-", dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "config"
        self.path = self.directory / "config.json"

    def test_doctor_never_loads_credentials_or_network_core(self):
        out = io.StringIO()
        with mock.patch.object(cli.importlib, "import_module", side_effect=AssertionError("core import")), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["doctor"]), 0)
        report = json.loads(out.getvalue())
        self.assertFalse(report["network_contacted"])
        self.assertFalse(report["continuous_connection_intake"])

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as stop:
            cli.main(["--version"])
        self.assertEqual(stop.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), __version__)

    def test_delegates_preserve_argument_order(self):
        for command, module in [("alerts", ".alerts"), ("review", ".review"), ("windows-snapshot", ".windows")]:
            child = mock.Mock()
            child.main.return_value = 17
            arguments = ["--case-dir", "EXAMPLE", "status"]
            with mock.patch.object(cli.importlib, "import_module", return_value=child) as load:
                self.assertEqual(cli.main([command, *arguments]), 17)
                load.assert_called_once_with(module, "sentinel_watch")
                child.main.assert_called_once_with(arguments)

    def test_router_collect_uses_durable_handoff_runner(self):
        child = mock.Mock()
        child.main.return_value = 0
        with mock.patch.object(cli.importlib, "import_module", return_value=child) as load:
            self.assertEqual(cli.main(["router", "collect", "--config", "EXAMPLE"]), 0)
            load.assert_called_once_with(".router_runner", "sentinel_watch")
            child.main.assert_called_once_with(["--config", "EXAMPLE"])

    def test_router_status_uses_local_status(self):
        child = mock.Mock()
        child.main.return_value = 0
        with mock.patch.object(cli.importlib, "import_module", return_value=child) as load:
            self.assertEqual(cli.main(["router", "status"]), 0)
            load.assert_called_once_with(".router", "sentinel_watch")
            child.main.assert_called_once_with(["status"])

    def test_hidden_inputs_saved_privately_without_printing(self):
        out = io.StringIO()
        secrets = mock.Mock(side_effect=["FAKE_PRIVATE_TOPIC", "FAKE_PRIVATE_TOKEN"])
        with contextlib.redirect_stdout(out):
            result = cli.initialize_config(self.path, origin_prompt=lambda _: "https://ntfy.example.com", secret_prompt=secrets)
        value = json.loads(self.path.read_text())
        self.assertEqual(value["topic"], "FAKE_PRIVATE_TOPIC")
        self.assertEqual(value["token"], "FAKE_PRIVATE_TOKEN")
        self.assertEqual(value["health_profile"], "outbox")
        self.assertEqual(secrets.call_count, 2)
        self.assertNotIn("FAKE_PRIVATE", out.getvalue())
        self.assertFalse(result["network_contacted"])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_config_never_overwrites_and_does_not_prompt_again(self):
        self.directory.mkdir(mode=0o700)
        self.path.write_text("existing", encoding="utf-8")
        prompt = mock.Mock(side_effect=AssertionError("unexpected prompt"))
        with self.assertRaisesRegex(cli.ConfigError, "E_CONFIG_EXISTS"):
            cli.initialize_config(self.path, origin_prompt=prompt, secret_prompt=prompt)
        self.assertEqual(self.path.read_text(), "existing")

    def test_invalid_config_leaves_no_file(self):
        with self.assertRaisesRegex(cli.ConfigError, "E_CONFIG_VALUE"):
            cli.initialize_config(self.path, origin_prompt=lambda _: "http://ntfy.example.com",
                                  secret_prompt=mock.Mock(side_effect=["topic", "FAKE_PRIVATE_TOKEN"]))
        self.assertFalse(self.path.exists())

    def test_getpass_echo_fallback_fails_closed(self):
        def unavailable(_):
            warnings.warn("synthetic no-TTY warning", cli.getpass.GetPassWarning)
            self.fail("fallback must not read visible input")
        with self.assertRaisesRegex(cli.ConfigError, "E_HIDDEN_INPUT"):
            cli.initialize_config(self.path, origin_prompt=lambda _: "https://ntfy.example.com", secret_prompt=unavailable)
        self.assertFalse(self.path.exists())

    def test_secret_arguments_are_not_supported(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit):
            cli.main(["init-config", "--token", "FAKE_TOKEN"])
        self.assertNotIn("FAKE_TOKEN", error.getvalue())

    def test_init_config_nonlinux_refused_without_prompt(self):
        out = io.StringIO()
        with mock.patch.object(cli.sys, "platform", "win32"), mock.patch.object(cli.getpass, "getpass", side_effect=AssertionError("prompt")), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["init-config"]), 1)
        self.assertEqual(json.loads(out.getvalue())["error"], "E_PRIVILEGE")

    def test_case_creation_reports_no_private_path(self):
        module = mock.Mock()
        out = io.StringIO()
        with mock.patch.dict(sys.modules, {"sentinel_watch.privacy": module}), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["init-case", "--directory", str(self.directory)]), 0)
        module.init_case.assert_called_once_with(self.directory)
        self.assertEqual(json.loads(out.getvalue()), {"ok": True, "case_created": True})


if __name__ == "__main__":
    unittest.main()
