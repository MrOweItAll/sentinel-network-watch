"""Transactional working copy for a portable, closed SQLite snapshot.

The caller provides a fresh ACL-protected runtime directory outside its synced
tree. The canonical source can have hard links; it is read only until a closed
replacement is atomically published. No guard in connection_review is changed.
The callback must close its SQLite connections before returning. No stdout.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

MAX_DB_BYTES = 200 * 1024 * 1024


class PortableError(RuntimeError):
    pass


def _path(path, *, directory=False, hardlinks=False):
    path = Path(os.path.abspath(os.fspath(path)))
    for candidate in (*reversed(path.parents), path):
        try:
            info = candidate.lstat()
        except OSError:
            raise PortableError("E_PATH_UNAVAILABLE") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PortableError("E_PATH_LINK")
        if candidate == path:
            if directory:
                if not stat.S_ISDIR(info.st_mode):
                    raise PortableError("E_DIRECTORY_REQUIRED")
            elif not stat.S_ISREG(info.st_mode) or (not hardlinks and info.st_nlink != 1):
                raise PortableError("E_SINGLE_LINK_REGULAR_FILE_REQUIRED")
    return path


def _no_sidecars(path):
    for suffix in ("-journal", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if os.path.lexists(candidate):
            raise PortableError("E_SQLITE_SIDECAR_PRESENT")


def _hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _fingerprint(path, *, hardlinks=False):
    _path(path, hardlinks=hardlinks)
    _no_sidecars(path)
    before = path.stat()
    if before.st_size > MAX_DB_BYTES:
        raise PortableError("E_DATABASE_CAP")
    digest = _hash(path)
    after = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after):
        raise PortableError("E_SOURCE_CHANGED")
    return identity(after), digest


class FileLock:
    """Cooperating writers lock one byte; acquisition has a finite timeout."""
    def __init__(self, path, timeout=10):
        self.path, self.timeout, self.handle = Path(path), timeout, None

    def __enter__(self):
        if os.path.lexists(self.path):
            _path(self.path, hardlinks=True)
        self.handle = self.path.open("a+b")
        _path(self.path, hardlinks=True)
        if self.handle.seek(0, os.SEEK_END) == 0:
            self.handle.write(b"\0"); self.handle.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self.handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self.handle.close(); self.handle = None
                    raise PortableError("E_WRITER_LOCK_TIMEOUT") from None
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))

    def __exit__(self, *_):
        if self.handle:
            try:
                self.handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close(); self.handle = None


@contextlib.contextmanager
def _readonly(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        connection.execute("PRAGMA query_only=ON")
        if connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "delete":
            raise PortableError("E_SQLITE_ROLLBACK_MODE_REQUIRED")
        yield connection
    finally:
        connection.close()


def _integrity(path):
    _no_sidecars(path)
    try:
        with _readonly(path) as connection:
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise PortableError("E_SQLITE_INTEGRITY")
    except sqlite3.Error:
        raise PortableError("E_SQLITE_INTEGRITY") from None
    _no_sidecars(path)


def _copy_exclusive(source, target):
    with source.open("rb") as reader, target.open("xb") as writer:
        while block := reader.read(1024 * 1024):
            writer.write(block)
        writer.flush(); os.fsync(writer.fileno())


def operate(source_db, runtime_dir, mutator, *, timeout=10, lock_factory=FileLock):
    """Apply mutator(runtime_db_path), then publish; retain all prior artifacts.

    Returns only transaction UUID, old/new hashes and preserved-backup path.
    Callback exceptions are sanitized. Idempotent authorization belongs to the
    caller; this helper never decides, renews, ingests or exports relationships.
    """
    if not callable(mutator) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
        raise PortableError("E_ARGUMENT")
    source = _path(source_db, hardlinks=True)
    runtime = _path(runtime_dir, directory=True)
    if source.is_relative_to(runtime) or runtime.is_relative_to(source.parent):
        raise PortableError("E_RUNTIME_OVERLAPS_CANONICAL")
    if any(runtime.iterdir()):
        raise PortableError("E_RUNTIME_NOT_EMPTY")
    transaction = uuid.uuid4().hex
    runtime_db = runtime / "review-runtime.sqlite3"
    stage = source.parent / (source.name + "." + transaction + ".publish")
    backup = source.parent / (source.name + "." + transaction + ".previous")
    try:
        with lock_factory(source.parent / (source.name + ".portable.lock"), timeout):
            baseline = _fingerprint(source, hardlinks=True)
            _integrity(source)
            with runtime_db.open("xb"):
                pass
            _path(runtime_db)
            deadline = time.monotonic() + 60
            def progress(*_):
                if time.monotonic() > deadline:
                    raise PortableError("E_SNAPSHOT_TIMEOUT")
            with _readonly(source) as reader:
                writer = sqlite3.connect(str(runtime_db), timeout=1)
                try:
                    reader.backup(writer, pages=64, progress=progress, sleep=0.01)
                finally:
                    writer.close()
            if _fingerprint(source, hardlinks=True) != baseline:
                raise PortableError("E_SOURCE_CHANGED")
            _integrity(runtime_db)
            _path(runtime_db)
            try:
                mutator(runtime_db)
            except Exception:
                raise PortableError("E_MUTATOR_FAILED") from None
            _path(runtime_db)
            _integrity(runtime_db)
            final = _fingerprint(runtime_db)
            _copy_exclusive(runtime_db, stage)
            _integrity(stage)
            if _hash(stage) != final[1]:
                raise PortableError("E_STAGING_MISMATCH")
            if _fingerprint(source, hardlinks=True) != baseline:
                raise PortableError("E_SOURCE_CHANGED")
            _copy_exclusive(source, backup)
            if _hash(backup) != baseline[1] or _fingerprint(source, hardlinks=True) != baseline:
                raise PortableError("E_SOURCE_CHANGED")
            _no_sidecars(source)
            os.replace(stage, source)
            if _fingerprint(source, hardlinks=True)[1] != final[1]:
                raise PortableError("E_PUBLICATION_VERIFICATION")
            return {"transaction_id": transaction, "before_sha256": baseline[1],
                    "after_sha256": final[1], "preserved_backup": str(backup),
                    "published": True}
    except PortableError:
        raise
    except Exception:
        raise PortableError("E_PORTABLE_TRANSACTION_FAILED") from None
