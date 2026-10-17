"""Wrong command arguments must never echo a mistakenly supplied credential."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel_watch import cli


class ArgumentPrivacyTests(unittest.TestCase):
    def test_delegated_parser_errors_redact_values(self):
        marker = 'SYNTHETIC-MISTAKEN-SECRET-ARGUMENT'
        for prefix in (['alerts'], ['review'], ['windows-snapshot'], ['router','collect']):
            with self.subTest(command=prefix):
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    with self.assertRaises(SystemExit) as result:
                        cli.main(prefix + ['--password', marker])
                self.assertEqual(result.exception.code, 2)
                self.assertNotIn(marker, output.getvalue() + errors.getvalue())
                self.assertIn('E_ARGUMENT', errors.getvalue())

    def test_config_refuses_getpass_fallback_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'not-created' / 'config.json'
            with patch.object(cli.sys.stdin, 'isatty', return_value=False), \
                    patch.object(cli.getpass, 'getpass') as prompt:
                with self.assertRaisesRegex(cli.ConfigError, 'E_INTERACTIVE_TERMINAL_REQUIRED'):
                    cli.initialize_config(path)
                prompt.assert_not_called()
                self.assertFalse(path.parent.exists())
