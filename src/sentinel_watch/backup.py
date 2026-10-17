"""Explicit-allowlist encrypted backups; inspection verifies but never restores.

The trusted caller chooses state/backups, holds Hub.lock, and supplies closed
SQLite backup-API snapshots. No recursive discovery, live DB copying, arbitrary
UI path, command line secret, passphrase file, or extraction API is provided.
GnuPG options: https://gnupg.org/documentation/manuals/gnupg24/gpg.1.html
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import uuid

MAX_FILES = 512
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES + 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
GPG_TIMEOUT = 60


class BackupError(ValueError):
    """Only a fixed code is safe to show in an interface."""


def _need(condition, code):
    if not condition:
        raise BackupError(code)


def _name(name):
    _need(isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,239}", name)), "E_ARCHIVE_NAME")
    _need(not PurePosixPath(name).is_absolute() and all(part not in ("", ".", "..") for part in name.split("/")), "E_ARCHIVE_NAME")
    return name


def _chain(path):
    for item in (path, *path.parents):
        meta = item.lstat()
        _need(not stat.S_ISLNK(meta.st_mode) and not getattr(meta, "st_file_attributes", 0) & 0x400, "E_PATH_LINK")


def _private_directory(path, *, create=False):
    path = Path(os.path.abspath(path))
    if create and not path.exists():
        _chain(path.parent)
        parent = path.parent.stat()
        if os.name == "posix":
            _need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o077, "E_PRIVATE_DIRECTORY")
        path.mkdir(mode=0o700)
    _chain(path)
    meta = path.stat()
    _need(stat.S_ISDIR(meta.st_mode), "E_PRIVATE_DIRECTORY")
    if os.name == "posix":
        _need(meta.st_uid == os.geteuid() and not meta.st_mode & 0o077, "E_PRIVATE_DIRECTORY")
    return path


def _regular(path, maximum=MAX_FILE_BYTES, *, private=False):
    path = Path(os.path.abspath(path))
    _chain(path)
    meta = path.lstat()
    _need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "E_SOURCE_FILE")
    _need(0 <= meta.st_size <= maximum, "E_SOURCE_LIMIT")
    if os.name == "posix":
        _need(meta.st_uid == os.geteuid() and not meta.st_mode & (0o077 if private else 0o022), "E_SOURCE_MODE")
    return path, meta


def _identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns) + ((meta.st_ctime_ns,) if os.name == "posix" else ())


def _password(passphrase):
    _need(isinstance(passphrase, str) and len(passphrase) >= 16 and not any(ord(c) < 32 or ord(c) == 127 for c in passphrase), "E_BACKUP_PASSPHRASE")
    try:
        encoded = passphrase.encode("utf-8")
    except UnicodeError:
        raise BackupError("E_BACKUP_PASSPHRASE") from None
    _need(len(encoded) <= 1024, "E_BACKUP_PASSPHRASE")
    return encoded + b"\n"


def _vetted_gpg(binary):
    path = Path(binary)
    _need(os.name == "posix" and path == Path("/usr/bin/gpg"), "E_GPG_BINARY")
    # /usr/bin/gpg may be a root-controlled distro symlink. Its resolved binary
    # and every parent must be root-owned and not writable by other users.
    for candidate in (path, path.resolve(), *path.resolve().parents):
        meta = candidate.stat()
        _need(meta.st_uid == 0 and not meta.st_mode & 0o022, "E_GPG_BINARY")
    _need(path.is_file() and os.access(path, os.X_OK), "E_GPG_BINARY")


def _gpg(input_path, output, passphrase, temporary, *, decrypt=False, gpg_binary="/usr/bin/gpg", runner=None):
    secret = _password(passphrase)
    if runner is None:
        _vetted_gpg(gpg_binary)
    homedir = temporary / "gnupg"
    homedir.mkdir(mode=0o700)
    command = [str(gpg_binary), "--no-options", "--homedir", str(homedir), "--batch", "--no-tty",
               "--no-autostart", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
               "--no-symkey-cache", "--status-fd", "2", "--output", "-"]
    if decrypt:
        command += ["--max-output", str(MAX_ARCHIVE_BYTES), "--decrypt", str(input_path)]
    else:
        command += ["--rfc4880", "--cipher-algo", "AES256", "--s2k-mode", "3", "--s2k-digest-algo", "SHA256",
                    "--s2k-count", "65011712", "--compress-algo", "none", "--set-filename", "", "--symmetric", str(input_path)]
    try:
        result = (runner or subprocess.run)(command, input=secret, stdout=output, stderr=subprocess.PIPE,
                                            timeout=GPG_TIMEOUT, check=False, close_fds=True,
                                            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        status = result.stderr
        _need(isinstance(status, bytes) and len(status) <= 65536, "E_GPG_FAILED")
        tokens = {line.split()[1] for line in status.splitlines() if line.startswith(b"[GNUPG:] ") and len(line.split()) >= 2}
        bad = {b"BADMDC", b"ERRMDC", b"ERROR", b"FAILURE", b"DECRYPTION_FAILED", b"NODATA"}
        required = {b"DECRYPTION_OKAY", b"GOODMDC"} if decrypt else {b"END_ENCRYPTION"}
        _need(result.returncode == 0 and not tokens & bad and required <= tokens, "E_GPG_FAILED")
    except BackupError:
        raise
    except Exception:
        raise BackupError("E_GPG_FAILED") from None


class _HashingReader:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def read(self, count):
        data = self.stream.read(count)
        self.digest.update(data)
        return data


def _write_archive(source_files, target):
    _need(isinstance(source_files, dict) and 0 < len(source_files) <= MAX_FILES, "E_SOURCE_LIST")
    sources, total = [], 0
    for name, path in sorted(source_files.items()):
        _name(name)
        _need(name != "manifest.json", "E_ARCHIVE_NAME")
        path, meta = _regular(path)
        total += meta.st_size
        _need(total <= MAX_TOTAL_BYTES, "E_SOURCE_LIMIT")
        sources.append((name, path, meta))
    manifest = {"schema": 1, "scope": "explicit_allowlist_only", "system_backup_complete": False, "files": {}}
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, path, meta in sources:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                _need(_identity(os.fstat(stream.fileno())) == _identity(meta), "E_SOURCE_CHANGED")
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = meta.st_size, 0o600, 0
                reader = _HashingReader(stream)
                archive.addfile(info, reader)
                after = os.fstat(stream.fileno())
                _need(after.st_nlink == 1 and _identity(after) == _identity(meta) == _identity(path.lstat()), "E_SOURCE_CHANGED")
                manifest["files"][name] = {"size": meta.st_size, "sha256": reader.digest.hexdigest(), "source_mode": stat.S_IMODE(meta.st_mode)}
        encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        _need(len(encoded) <= MAX_MANIFEST_BYTES, "E_SOURCE_LIMIT")
        info = tarfile.TarInfo("manifest.json")
        info.size, info.mode, info.mtime = len(encoded), 0o600, 0
        archive.addfile(info, io.BytesIO(encoded))
    return manifest


def _hash_file(path, maximum):
    path, before = _regular(path, maximum, private=True)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        _need(_identity(os.fstat(stream.fileno())) == _identity(before), "E_SOURCE_CHANGED")
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
        _need(_identity(os.fstat(stream.fileno())) == _identity(before) == _identity(path.lstat()), "E_SOURCE_CHANGED")
    return digest.hexdigest(), before.st_size


def create_backup(source_files, output_dir, passphrase, *, gpg_binary="/usr/bin/gpg", runner=None):
    """Encrypt only caller-allowlisted files. Caller must lock and snapshot DBs."""
    _password(passphrase)  # Reject before even creating a directory.
    output = None
    published = False
    try:
        directory = _private_directory(output_dir, create=True)
        identifier = uuid.uuid4().hex
        output = directory / (identifier + ".tar.gpg")
        # Plaintext remains inside the private backup directory and is unlinked
        # on all exits. This is not a promise of physical erasure on SSDs.
        with tempfile.TemporaryDirectory(prefix=".backup-", dir=directory) as name:
            temporary = Path(name)
            archive = temporary / "snapshot.tar"
            manifest = _write_archive(source_files, archive)
            ciphertext = temporary / "encrypted.gpg"
            fd = os.open(ciphertext, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as encrypted:
                _gpg(archive, encrypted, passphrase, temporary, gpg_binary=gpg_binary, runner=runner)
                encrypted.flush()
                os.fsync(encrypted.fileno())
            digest, size = _hash_file(ciphertext, MAX_ARCHIVE_BYTES)
            _need(size > 0, "E_GPG_FAILED")
            if os.name == "posix":
                os.link(ciphertext, output)  # Atomic, and refuses an existing name.
                published = True
                ciphertext.unlink()
            else:
                os.rename(ciphertext, output)  # Windows rename does not replace.
                published = True
        if os.name == "posix":
            fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return {"backup_id": identifier, "filename": output.name, "sha256": digest, "bytes": size,
                "manifest": manifest, "scope": "explicit_allowlist_only", "system_backup_complete": False,
                "restore_verified": False}
    except Exception as error:
        if published:
            try:
                output.unlink(missing_ok=True)
            except OSError:
                pass
        if isinstance(error, BackupError):
            raise
        raise BackupError("E_BACKUP_FAILED") from None


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "E_BACKUP_MANIFEST")
        result[key] = value
    return result


def _inspect_archive(path):
    actual, manifest, total = {}, None, 0
    with tarfile.open(path, mode="r|") as archive:
        for count, member in enumerate(archive):
            _need(count <= MAX_FILES and member.isreg() and not set(member.pax_headers) - {"path"}, "E_BACKUP_MANIFEST")
            name = _name(member.name)
            _need(name not in actual and (name != "manifest.json" or manifest is None), "E_BACKUP_MANIFEST")
            _need(0 <= member.size <= (MAX_MANIFEST_BYTES if name == "manifest.json" else MAX_FILE_BYTES), "E_BACKUP_MANIFEST")
            stream = archive.extractfile(member)  # Read regular member bytes only; never extract paths.
            if name == "manifest.json":
                manifest = json.loads(stream.read(MAX_MANIFEST_BYTES + 1), object_pairs_hook=_strict_object)
                continue
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(65536), b""):
                total += len(chunk)
                _need(total <= MAX_TOTAL_BYTES, "E_BACKUP_MANIFEST")
                digest.update(chunk)
            actual[name] = {"size": member.size, "sha256": digest.hexdigest()}
    _need(isinstance(manifest, dict) and set(manifest) == {"schema", "scope", "system_backup_complete", "files"}
          and type(manifest["schema"]) is int and manifest["schema"] == 1 and manifest["scope"] == "explicit_allowlist_only"
          and manifest["system_backup_complete"] is False and isinstance(manifest["files"], dict)
          and 0 < len(actual) <= MAX_FILES and set(manifest["files"]) == set(actual), "E_BACKUP_MANIFEST")
    for name, metadata in manifest["files"].items():
        _need(isinstance(metadata, dict) and set(metadata) == {"size", "sha256", "source_mode"}
              and type(metadata["size"]) is int and metadata["size"] == actual[name]["size"]
              and isinstance(metadata["sha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"]))
              and metadata["sha256"] == actual[name]["sha256"]
              and type(metadata["source_mode"]) is int and 0 <= metadata["source_mode"] <= 0o7777, "E_BACKUP_MANIFEST")
    return manifest


def inspect_backup(archive_path, passphrase, *, gpg_binary="/usr/bin/gpg", runner=None):
    """Verify authenticated decryption and all member hashes; never restore files."""
    _password(passphrase)
    try:
        path, _ = _regular(archive_path, MAX_ARCHIVE_BYTES, private=True)
        _private_directory(path.parent)
        digest, size = _hash_file(path, MAX_ARCHIVE_BYTES)
        with tempfile.TemporaryDirectory(prefix=".inspect-", dir=path.parent) as name:
            temporary = Path(name)
            plaintext = temporary / "inspect.tar"
            fd = os.open(plaintext, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as output:
                _gpg(path, output, passphrase, temporary, decrypt=True, gpg_binary=gpg_binary, runner=runner)
            _regular(plaintext, MAX_ARCHIVE_BYTES, private=True)
            manifest = _inspect_archive(plaintext)
        _need(_hash_file(path, MAX_ARCHIVE_BYTES) == (digest, size), "E_SOURCE_CHANGED")
        return {"filename": path.name, "sha256": digest, "bytes": size, "manifest": manifest,
                "integrity_verified": True, "files_restored": False, "system_backup_complete": False}
    except BackupError:
        raise
    except Exception:
        raise BackupError("E_BACKUP_INSPECT_FAILED") from None
