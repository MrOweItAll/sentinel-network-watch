import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import MagicMock, Mock, patch
from sentinel_watch import console
from sentinel_watch.console import ReviewStore, ConsoleError
from sentinel_watch.console_ui import HTML


@unittest.skipUnless(os.name == 'posix', 'POSIX private state boundary')
class ReviewTests(unittest.TestCase):
    def test_history_preserved_and_no_enforcement(self):
        with tempfile.TemporaryDirectory() as folder:
            os.chmod(folder, 0o700)
            store = ReviewStore(Path(folder) / 'reviews.sqlite3')
            result = store.update_review('connection-1', 'recognize', 'Known browser')
            self.assertFalse(result['traffic_changed'])
            store.update_review('connection-1', 'investigate', 'New destination')
            self.assertEqual(store.annotations()['connection-1']['decision'], 'investigate')
            with store.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM review_history').fetchone()[0], 2)

    def test_refuse_shared_directory_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            os.chmod(folder, 0o755)
            with self.assertRaises(ConsoleError):
                ReviewStore(Path(folder) / 'reviews.sqlite3')
            os.chmod(folder, 0o700)
            target = Path(folder) / 'target'; target.write_text('')
            link = Path(folder) / 'reviews.sqlite3'; link.symlink_to(target)
            with self.assertRaises(ConsoleError):
                ReviewStore(link)

    def test_invalid_reviews_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            os.chmod(folder, 0o700)
            store = ReviewStore(Path(folder) / 'reviews.sqlite3')
            for args in [('a', 'block', ''), ('../root', 'recognize', ''), ('a', 'recognize', 'bad\x00note')]:
                with self.assertRaises(ConsoleError):
                    store.update_review(*args)


class UITests(unittest.TestCase):
    def test_scope_and_safe_rendering_are_explicit(self):
        self.assertIn('partial household visibility', HTML)
        self.assertIn('Disconnect: unavailable', HTML)
        self.assertIn('not household totals', HTML)
        self.assertIn('textContent', HTML)
        self.assertNotIn('innerHTML', HTML)
        self.assertNotIn('https://', HTML)
        self.assertIn('__NONCE__', HTML)


class RuntimeWiringTests(unittest.TestCase):
    def test_production_runtime_passes_default_readonly_history_reader(self):
        config = {'bind': '192.0.2.10', 'port': 8443, 'allowed_cidr': '192.0.2.0/24',
                  'auth_path': str(console.STATE / 'dashboard-auth.json')}
        config_path = Mock()
        config_path.lstat.return_value = types.SimpleNamespace(st_mode=0o100644, st_uid=0, st_nlink=1, st_size=200)
        config_path.read_bytes.return_value = json.dumps(config).encode()
        history, store, server = Mock(), Mock(), MagicMock()
        reader = Mock(return_value=history)
        with patch.object(console.os, 'name', 'posix'), patch.object(console.os, 'geteuid', return_value=1000, create=True), \
             patch.object(console, 'Path', return_value=config_path), patch.object(console.ssl, 'SSLContext') as tls, \
             patch.object(console, 'ReviewStore', return_value=store), \
             patch('sentinel_watch.console_server.create_server', return_value=server) as create, \
             patch.dict('sys.modules', {'sentinel_watch.console_history': types.SimpleNamespace(HistoryReader=reader)}):
            console.main(['--config', '/synthetic/config.json'])
        reader.assert_called_once_with()
        create.assert_called_once_with(config, console.snapshot, store, tls.return_value, history_provider=history)
        server.serve_forever.assert_called_once_with(poll_interval=.5)

    def test_bad_root_config_stops_before_history_or_review_storage(self):
        config_path = Mock()
        config_path.lstat.return_value = types.SimpleNamespace(st_mode=0o100644, st_uid=1000, st_nlink=1, st_size=200)
        reader = Mock()
        with patch.object(console.os, 'name', 'posix'), patch.object(console.os, 'geteuid', return_value=1000, create=True), \
             patch.object(console, 'Path', return_value=config_path), patch.object(console, 'ReviewStore') as store, \
             patch('sentinel_watch.console_server.create_server') as create, \
             patch.dict('sys.modules', {'sentinel_watch.console_history': types.SimpleNamespace(HistoryReader=reader)}):
            with self.assertRaisesRegex(ConsoleError, '^E_CONFIG_PERMISSIONS$'):
                console.main(['--config', '/synthetic/config.json'])
        reader.assert_not_called(); store.assert_not_called(); create.assert_not_called()
        config_path.read_bytes.assert_not_called()


if __name__ == '__main__':
    unittest.main()
