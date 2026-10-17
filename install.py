#!/usr/bin/env python3
"""Copy-only Linux installer, or an unprivileged isolated --prefix staging install."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MODULES = ("__init__.py", "__main__.py", "cli.py", "arguments.py", "alerts.py", "router.py", "router_runner.py",
           "review.py", "storage.py", "windows.py", "privacy.py")
UNITS = ("sentinel-alerts.service", "sentinel-alerts.timer", "sentinel-router.service", "sentinel-router.timer")
EXAMPLES = ("alerts.json.example", "router.json.example", "review-input.json.example")


class InstallError(Exception):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '{"ok": false, "error": "E_ARGUMENT"}\n')


def require(condition, code):
    if not condition:
        raise InstallError(code)


def redirected(meta):
    return stat.S_ISLNK(meta.st_mode) or bool(getattr(meta, "st_file_attributes", 0) & 0x400)


def check_chain(path, boundary, *, root_owned=False):
    require(path == boundary or boundary in path.parents, "E_INSTALL_PATH")
    current = path
    while True:
        if current.exists() or current.is_symlink():
            meta = current.lstat()
            require(not redirected(meta), "E_INSTALL_LINK")
            if current != path:
                require(stat.S_ISDIR(meta.st_mode), "E_INSTALL_PATH")
                if root_owned:
                    require(meta.st_uid == 0 and not meta.st_mode & 0o022, "E_INSTALL_DIRECTORY")
        if current == boundary:
            break
        current = current.parent


def source_bytes(path):
    meta = path.lstat()
    # Read-only public source may be hardlinked by a checkout or sync client.
    # Destination files, which carry installed authority, must remain single-link.
    require(stat.S_ISREG(meta.st_mode) and not redirected(meta), "E_SOURCE_FILE")
    require(meta.st_size <= 2 * 1024 * 1024, "E_SOURCE_SIZE")
    # Windows lstat/fstat can expose different ctime meanings; size/mtime,
    # file identity and a second complete content hash remain checked there.
    identity = lambda item: ((item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
                             + ((item.st_ctime_ns,) if os.name == "posix" else ()))
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(identity(before) == identity(meta), "E_SOURCE_CHANGED")
        data = stream.read(2 * 1024 * 1024 + 1)
        stream.seek(0)
        second = stream.read(2 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    require(identity(before) == identity(after) == identity(path.lstat())
            and len(data) == meta.st_size and hashlib.sha256(data).digest() == hashlib.sha256(second).digest(),
            "E_SOURCE_CHANGED")
    return data


def _install(prefix=None, *, source_root=None):
    require(sys.version_info >= (3, 10), "E_PYTHON_VERSION")
    staged = prefix is not None
    if not staged:
        require(sys.platform.startswith("linux") and getattr(os, "geteuid", lambda: -1)() == 0, "E_LINUX_ROOT_REQUIRED")
    root = Path(os.path.abspath(prefix)) if staged else Path("/")
    require(not staged or root != Path(root.anchor), "E_STAGING_ROOT")
    source = Path(source_root or Path(__file__).resolve().parent)
    for relative in ([Path("src/sentinel_watch") / name for name in MODULES]
                     + [Path("deploy") / name for name in UNITS]
                     + [Path("examples") / name for name in EXAMPLES]):
        check_chain(source / relative, source)
    # Refuse a staged prefix that resolves elsewhere through an existing link.
    for parent in (root, *root.parents):
        if parent.exists() or parent.is_symlink():
            require(not redirected(parent.lstat()), "E_INSTALL_LINK")
    package = root / "opt/sentinel-network-watch/sentinel_watch"
    launcher = (
        "#!/usr/bin/python3\nimport sys\nsys.dont_write_bytecode = True\n"
        "sys.path.insert(0, " + repr(str(package.parent)) + ")\n"
        "from sentinel_watch.cli import main\nraise SystemExit(main())\n"
    ).encode()
    files = [(package / name, source_bytes(source / "src/sentinel_watch" / name), 0o644) for name in MODULES]
    files += [(root / "etc/systemd/system" / name, source_bytes(source / "deploy" / name), 0o644) for name in UNITS]
    files += [(root / "usr/share/sentinel-network-watch/examples" / name,
               source_bytes(source / "examples" / name), 0o644) for name in EXAMPLES]
    files.append((root / "usr/local/bin/sentinel-network-watch", launcher, 0o755))
    private = [root / p for p in ("etc/sentinel-alerts", "etc/sentinel-router", "var/lib/sentinel-alerts", "var/lib/sentinel-router")]
    # Validate the entire destination before the first write. Existing differing files are preserved.
    for path, data, mode in files:
        check_chain(path, root, root_owned=not staged)
        if path.exists():
            meta = path.lstat()
            require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and path.read_bytes() == data, "E_EXISTING_FILE")
            if os.name == "posix":
                require(stat.S_IMODE(meta.st_mode) == mode and (staged or meta.st_uid == 0), "E_EXISTING_MODE")
    for directory in private:
        check_chain(directory, root, root_owned=not staged)
        if directory.exists():
            meta = directory.lstat()
            require(stat.S_ISDIR(meta.st_mode), "E_PRIVATE_DIRECTORY")
            if os.name == "posix":
                require(not meta.st_mode & 0o077 and (staged or meta.st_uid == 0), "E_PRIVATE_DIRECTORY")
    root.mkdir(parents=True, exist_ok=True)
    for directory in private:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    written = 0
    for path, data, mode in files:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if path.exists():
            continue
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            os.chmod(path, mode)
        written += 1
    return {"ok": True, "staged": staged, "files_installed": written,
            "configuration_created": False, "timers_enabled": False, "system_commands_run": False}


def install(prefix=None, *, source_root=None):
    # pathlib creates intermediate parents with the process umask. A root
    # launcher must never import through a newly world/group-writable parent.
    previous = os.umask(0o022) if os.name == "posix" else None
    try:
        return _install(prefix, source_root=source_root)
    finally:
        if previous is not None:
            os.umask(previous)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, help="Copy into an isolated staging root; no root or Linux requirement")
    args = parser.parse_args(argv)
    try:
        result = install(args.prefix)
        print(json.dumps(result, sort_keys=True))
        return 0
    except InstallError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    except Exception:
        print(json.dumps({"ok": False, "error": "E_INSTALL"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
