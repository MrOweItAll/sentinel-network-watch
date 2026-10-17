"""Private-case boundary fixtures; no endpoint capture or credentials."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel_watch import privacy


class PrivateCaseTests(unittest.TestCase):
    def test_missing_case_does_not_become_an_implicit_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'not-created'
            with self.assertRaisesRegex(privacy.CaseError, 'E_CASE_MISSING'):
                privacy.verify_case(path)
            self.assertFalse(path.exists())

    def test_symlink_case_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'case'
            target.mkdir()
            alias = Path(folder) / 'alias'
            try:
                alias.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest('symlink privilege unavailable')
            with self.assertRaisesRegex(privacy.CaseError, 'E_CASE_LINK'):
                privacy.verify_case(alias)

    def test_windows_acl_failure_is_not_ignored(self):
        with patch.object(privacy.subprocess, 'run') as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(privacy.CaseError, 'E_CASE_PERMISSIONS'):
                privacy._windows_acl(Path('synthetic-case'))

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions fixture')
    def test_new_case_private_and_existing_broad_case_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            case = privacy.init_case(Path(folder) / 'private')
            self.assertEqual(case.stat().st_mode & 0o777, 0o700)
            case.chmod(0o755)
            with self.assertRaisesRegex(privacy.CaseError, 'E_CASE_PERMISSIONS'):
                privacy.verify_case(case)
