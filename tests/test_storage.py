"""Synthetic SQLite fixtures only. Never opens the actual review queue."""
import contextlib
import hashlib
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel_watch import storage as portable


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).parent/('fixture-portable-'+os.urandom(8).hex())
        self.root.mkdir(mode=0o777)
        self.canonical=self.root/'canonical';self.canonical.mkdir()
        self.runtime=self.root/'runtime';self.runtime.mkdir()
        self.source=self.canonical/'review.sqlite3'
        self.write(self.source,'original',create=True)
        self.before=self.source.read_bytes()
        self.guard=patch.object(socket,'socket',side_effect=AssertionError('offline fixture'))
        self.guard.start()

    def tearDown(self):
        self.guard.stop()
        assert self.root.resolve().parent==Path(__file__).resolve().parent
        assert self.root.name.startswith('fixture-portable-')
        shutil.rmtree(self.root)

    def write(self,path,value,create=False):
        connection=sqlite3.connect(str(path))
        try:
            if create:connection.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,value TEXT)')
            connection.execute('INSERT INTO events(value) VALUES(?)',(value,))
            connection.commit()
        finally:connection.close()

    def values(self,path):
        connection=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
        try:return [r[0] for r in connection.execute('SELECT value FROM events ORDER BY id')]
        finally:connection.close()

    def test_success_preserves_old_bytes_and_publishes_closed_snapshot(self):
        result=portable.operate(self.source,self.runtime,lambda path:self.write(path,'approved'))
        self.assertTrue(result['published'])
        self.assertEqual(self.values(self.source),['original','approved'])
        self.assertEqual(Path(result['preserved_backup']).read_bytes(),self.before)
        self.assertEqual(result['before_sha256'],hashlib.sha256(self.before).hexdigest())
        self.assertEqual(result['after_sha256'],hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertFalse(any(Path(str(self.source)+s).exists() for s in ('-journal','-wal','-shm')))

    def test_hardlinked_source_metadata_allowed_without_guard_weakening(self):
        original=Path.lstat
        def info(path):
            result=original(path)
            if path==self.source:return SimpleNamespace(st_mode=result.st_mode,st_nlink=2,st_file_attributes=0)
            return result
        with patch.object(Path,'lstat',info):
            result=portable.operate(self.source,self.runtime,lambda path:self.write(path,'new'))
        self.assertEqual(Path(result['preserved_backup']).read_bytes(),self.before)

    def test_runtime_hardlink_metadata_rejected_before_mutator(self):
        original=Path.lstat;called=[]
        def info(path):
            result=original(path)
            if path.name=='review-runtime.sqlite3':
                return SimpleNamespace(st_mode=result.st_mode,st_nlink=2,st_file_attributes=0)
            return result
        with patch.object(Path,'lstat',info):
            with self.assertRaisesRegex(portable.PortableError,'E_SINGLE_LINK_REGULAR_FILE_REQUIRED'):
                portable.operate(self.source,self.runtime,lambda path:called.append(True))
        self.assertFalse(called)
        self.assertEqual(self.source.read_bytes(),self.before)

    def test_source_sidecars_rejected_without_publication(self):
        for suffix in ('-journal','-wal','-shm'):
            with self.subTest(suffix=suffix):
                sidecar=Path(str(self.source)+suffix);sidecar.write_bytes(b'fixture')
                try:
                    with self.assertRaisesRegex(portable.PortableError,'E_SQLITE_SIDECAR_PRESENT'):
                        portable.operate(self.source,self.runtime,lambda path:None)
                finally:sidecar.unlink()
        self.assertEqual(self.source.read_bytes(),self.before)

    def test_mutator_failure_is_sanitized_and_preserves_source(self):
        def fail(path):
            self.write(path,'not-published')
            raise RuntimeError('fixture-private-endpoint-do-not-print')
        with self.assertRaisesRegex(portable.PortableError,'^E_MUTATOR_FAILED$'):
            portable.operate(self.source,self.runtime,fail)
        self.assertEqual(self.source.read_bytes(),self.before)
        self.assertTrue((self.runtime/'review-runtime.sqlite3').exists())

    def test_source_change_during_callback_is_not_overwritten(self):
        def race(path):
            self.write(path,'not-published')
            self.write(self.source,'external-writer')
        with self.assertRaisesRegex(portable.PortableError,'E_SOURCE_CHANGED'):
            portable.operate(self.source,self.runtime,race)
        self.assertEqual(self.values(self.source),['original','external-writer'])

    def test_invalid_runtime_database_cannot_replace_source(self):
        def corrupt(path):path.write_bytes(b'not-sqlite')
        with self.assertRaisesRegex(portable.PortableError,'E_SQLITE_INTEGRITY'):
            portable.operate(self.source,self.runtime,corrupt)
        self.assertEqual(self.source.read_bytes(),self.before)

    def test_nonempty_or_overlapping_runtime_rejected(self):
        (self.runtime/'existing').write_bytes(b'fixture')
        with self.assertRaisesRegex(portable.PortableError,'E_RUNTIME_NOT_EMPTY'):
            portable.operate(self.source,self.runtime,lambda path:None)
        with self.assertRaisesRegex(portable.PortableError,'E_RUNTIME_OVERLAPS_CANONICAL'):
            portable.operate(self.source,self.canonical,lambda path:None)

    def test_reparse_source_ancestor_rejected(self):
        original=Path.lstat
        def info(path):
            result=original(path)
            if path==self.canonical:
                return SimpleNamespace(st_mode=result.st_mode,st_nlink=result.st_nlink,st_file_attributes=0x400)
            return result
        with patch.object(Path,'lstat',info):
            with self.assertRaisesRegex(portable.PortableError,'E_PATH_LINK'):
                portable.operate(self.source,self.runtime,lambda path:None)

    def test_publication_failure_retains_source_and_preserved_backup(self):
        with patch.object(portable.os,'replace',side_effect=OSError('fixture-private-error')):
            with self.assertRaisesRegex(portable.PortableError,'^E_PORTABLE_TRANSACTION_FAILED$'):
                portable.operate(self.source,self.runtime,lambda path:self.write(path,'new'))
        self.assertEqual(self.source.read_bytes(),self.before)
        backups=list(self.canonical.glob('*.previous'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_bytes(),self.before)
        self.assertEqual(len(list(self.canonical.glob('*.publish'))),1)

    def test_bounded_lock_blocks_a_second_writer(self):
        lock=self.canonical/'review.sqlite3.portable.lock'
        with portable.FileLock(lock,1):
            with self.assertRaisesRegex(portable.PortableError,'E_WRITER_LOCK_TIMEOUT'):
                portable.operate(self.source,self.runtime,lambda path:None,timeout=0.05)
        self.assertEqual(self.source.read_bytes(),self.before)


if __name__=='__main__':unittest.main()
