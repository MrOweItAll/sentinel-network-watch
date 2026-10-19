import json
import os
from pathlib import Path
import tempfile
import unittest
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


if __name__ == '__main__':
    unittest.main()
