"""Consistent, explicit-scope local hub backup; no restoration or discovery API."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time

from . import backup

CODE_ROOT = Path(__file__).resolve().parent
CODE_NAMES = ("__init__.py", "__main__.py", "arguments.py", "alerts.py", "backup.py", "cli.py",
              "dashboard.py", "hub.py", "hub_backup.py", "hub_cli.py", "linux.py", "privacy.py",
              "review.py", "router.py", "router_runner.py", "storage.py", "windows.py")
UNIT_PATHS = {"systemd/"+name: Path("/etc/systemd/system")/name for name in
              ("sentinel-hub.service", "sentinel-hub-watchdog.service", "sentinel-hub-watchdog.timer")}
STATE_ROOT_FILES = {"networks.json", "worker-error.json", "status.json", "gaps.json", "migration.json",
                    "migration-manifest.json", "migration-receipt.json", "origin-binding.json",
                    "host-binding.json", "hub-state.json", "watchdog-status.json", "deployment-source.json"}
STATE_ROOT_DIRS = {"networks", "alerts", "imports", "evidence", "receipts", "migration"}
METADATA_SUFFIXES = {".json", ".jsonl", ".csv", ".txt", ".sha256"}
DATABASE_SUFFIXES = {".sqlite3", ".sqlite", ".db"}
MISSING_COMPONENTS = ("adguard_home_runtime_config_state", "legacy_router_runtime_config_state",
                      "legacy_alerts_runtime_config_state", "operating_system_and_host_identity_keys")
MAX_STATE_ENTRIES = 1024
MAX_STATE_DEPTH = 8
SNAPSHOT_SECONDS = 60


class HubBackupError(ValueError):
    pass


def _need(condition, code):
    if not condition:
        raise HubBackupError(code)


def _exists(path):
    return path.exists() or path.is_symlink()


def _state_files(state):
    """Only own state layout; unknown files fail instead of disappearing."""
    found, excluded, entries = [], 0, 0
    stack = [(state, ())]
    while stack:
        directory, relative = stack.pop()
        backup._private_directory(directory)
        _need(len(relative) <= MAX_STATE_DEPTH, "E_HUB_BACKUP_CAP")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                _need(entries <= MAX_STATE_ENTRIES, "E_HUB_BACKUP_CAP")
                path = directory / child.name
                meta = path.lstat()
                _need(not stat.S_ISLNK(meta.st_mode) and not getattr(meta, "st_file_attributes", 0) & 0x400,
                      "E_HUB_BACKUP_LINK")
                pieces = (*relative, child.name)
                rel = Path(*pieces)
                if stat.S_ISDIR(meta.st_mode):
                    backup._private_directory(path)
                    if not relative and child.name == "backups":
                        excluded += 1
                        continue
                    _need(pieces[0] in STATE_ROOT_DIRS, "E_HUB_BACKUP_UNCOVERED_STATE")
                    if pieces[0] == "networks" and len(pieces) == 2:
                        import uuid
                        try:
                            _need(uuid.UUID(child.name).int != 0, "E_HUB_BACKUP_NETWORK_FOLDER")
                        except ValueError:
                            raise HubBackupError("E_HUB_BACKUP_NETWORK_FOLDER") from None
                    stack.append((path, pieces))
                    continue
                _need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "E_HUB_BACKUP_FILE")
                backup._regular(path)
                # These files represent locks, incomplete writes, or SQLite
                # pages which the backup API includes in the closed snapshot.
                if (child.name.endswith((".lock", ".tmp", "-wal", "-shm", "-journal"))):
                    excluded += 1
                    continue
                is_db = path.suffix.lower() in DATABASE_SUFFIXES
                historical_capture = (rel.as_posix().startswith("migration/original-windows/network-review/")
                                      and path.suffix.lower() in {".png", ".raw", ".previous"})
                allowed = is_db or (not relative and child.name in STATE_ROOT_FILES) or (
                    relative and pieces[0] in STATE_ROOT_DIRS and path.suffix.lower() in METADATA_SUFFIXES) or historical_capture
                _need(allowed, "E_HUB_BACKUP_UNCOVERED_STATE")
                found.append((rel.as_posix(), path, is_db))
                _need(len(found) <= backup.MAX_FILES, "E_HUB_BACKUP_CAP")
    return sorted(found), excluded


def _snapshot_database(source, destination, deadline):
    source, before = backup._regular(source)
    with source.open("rb") as stream:
        _need(stream.read(16) == b"SQLite format 3\x00", "E_HUB_BACKUP_DATABASE")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    origin = target = None
    try:
        origin = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=3)
        origin.execute("PRAGMA query_only=ON")
        origin.execute("PRAGMA trusted_schema=OFF")
        page_size = origin.execute("PRAGMA page_size").fetchone()[0]
        target = sqlite3.connect(destination, timeout=3)
        def progress(status, remaining, total):
            _need(time.monotonic() < deadline and total * page_size <= backup.MAX_FILE_BYTES,
                  "E_HUB_BACKUP_CAP")
        origin.backup(target, pages=256, progress=progress, sleep=0.01)
        target.commit()
        target.execute("PRAGMA journal_mode=DELETE")
        target.execute("PRAGMA trusted_schema=OFF")
        target.set_progress_handler(lambda: 1 if time.monotonic() >= deadline else 0, 10000)
        _need(target.execute("PRAGMA quick_check").fetchone() == ("ok",), "E_HUB_BACKUP_DATABASE")
    finally:
        if target is not None:
            target.close()
        if origin is not None:
            origin.close()
    after = source.lstat()
    _need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and after.st_nlink == 1,
          "E_HUB_BACKUP_SOURCE_CHANGED")
    backup._regular(destination)
    _need(not any(_exists(Path(str(destination) + suffix)) for suffix in ("-wal", "-shm", "-journal")),
          "E_HUB_BACKUP_SNAPSHOT_OPEN")


def create_hub_backup(hub, passphrase):
    """Back up all profiles and the hub outbox under the actual hub lock.

    Runtime snapshots are created with SQLite's backup API. Historical closed
    migration DBs retain their exact original bytes as well as an API snapshot.
    This is a local hub backup, not an off-host or whole-system backup.
    """
    backup._password(passphrase)
    try:
        with hub.lock:
            state = backup._private_directory(hub.state)
            files, excluded = _state_files(state)
            source_files = {"hub/config.json": Path(hub.config_path)}
            auth = getattr(hub, "auth_path", None) or hub.config.get("auth_path") or Path(hub.config_path).parent / "dashboard-auth.json"
            source_files["hub/dashboard-auth.json"] = Path(auth)
            notifications = hub.config.get("alerts_config_path")
            if notifications:
                source_files["hub/notifications-config.json"] = Path(notifications)
            for path in source_files.values():
                backup._regular(path, private=True)
            code_count = units = 0
            with os.scandir(CODE_ROOT) as children:
                for child in children:
                    if child.name.endswith(".py"):
                        _need(child.name in CODE_NAMES, "E_HUB_BACKUP_CODE_SCOPE")
            for name in CODE_NAMES:
                path = CODE_ROOT / name
                if _exists(path):
                    source_files["code/sentinel_watch/" + name] = path
                    code_count += 1
            _need(code_count > 0, "E_HUB_BACKUP_CODE")
            for name, path in UNIT_PATHS.items():
                if _exists(path):
                    source_files[name] = path
                    units += 1
            # Prevalidate credential/source allowlists before creating plaintext.
            for path in source_files.values():
                backup._regular(path)
            snapshots = originals = 0
            deadline = time.monotonic() + SNAPSHOT_SECONDS
            with tempfile.TemporaryDirectory(prefix=".hub-backup-", dir=state) as name:
                temporary = Path(name)
                for relative, path, is_db in files:
                    key = "hub/state/" + relative
                    if is_db:
                        destination = temporary / (str(snapshots) + ".sqlite3")
                        _snapshot_database(path, destination, deadline)
                        snapshots += 1
                        if relative.startswith("migration/original-windows/"):
                            _need(not any(_exists(Path(str(path) + suffix)) for suffix in ("-wal", "-shm", "-journal")),
                                  "E_HUB_BACKUP_ORIGINAL_NOT_CLOSED")
                            source_files[key] = path
                            source_files["hub/sqlite-snapshots/" + relative] = destination
                            originals += 1
                        else:
                            source_files[key] = destination
                    else:
                        source_files[key] = path
                    _need(len(source_files) <= backup.MAX_FILES, "E_HUB_BACKUP_CAP")
                output_dir = state / "backups"
                result = backup.create_backup(source_files, output_dir, passphrase)
                verified = backup.inspect_backup(output_dir / result["filename"], passphrase)
                _need(verified.get("integrity_verified") is True and verified["sha256"] == result["sha256"]
                      and verified["manifest"] == result["manifest"], "E_HUB_BACKUP_VERIFY")
            result.update(ok=True, integrity_verified=True, restore_verified=False, files_restored=False,
                          local_only=True, offhost_copy_verified=False, system_backup_complete=False,
                          missing_components=list(MISSING_COMPONENTS), sqlite_databases_snapshotted=snapshots,
                          historical_original_databases_preserved=originals, excluded_transient_entries=excluded,
                          code_modules_included=code_count, hub_units_included=units,
                          notification_config_included=bool(notifications),
                          consistency="sqlite_backup_api_under_hub_lock")
            return result
    except (backup.BackupError, HubBackupError):
        raise
    except Exception:
        raise HubBackupError("E_HUB_BACKUP_FAILED") from None


def backup_path(hub, backup_id_or_filename):
    """Validate one generated filename for authenticated download; never a path."""
    try:
        _need(isinstance(backup_id_or_filename, str) and
              bool(re.fullmatch(r"[0-9a-f]{32}(?:\.tar\.gpg)?", backup_id_or_filename)), "E_HUB_BACKUP_ID")
        name = backup_id_or_filename if backup_id_or_filename.endswith(".tar.gpg") else backup_id_or_filename + ".tar.gpg"
        with hub.lock:
            directory = backup._private_directory(Path(hub.state) / "backups")
            path, meta = backup._regular(directory / name, backup.MAX_ARCHIVE_BYTES, private=True)
            _need(stat.S_IMODE(meta.st_mode) == 0o600 if os.name == "posix" else True, "E_HUB_BACKUP_MODE")
            return path
    except (backup.BackupError, HubBackupError):
        raise
    except Exception:
        raise HubBackupError("E_HUB_BACKUP_DOWNLOAD") from None
