"""Public command dispatch. Configuration secrets are accepted interactively only."""
from __future__ import annotations

import argparse
import getpass
import importlib
import json
import os
from pathlib import Path
import stat
import sys
import warnings

from . import __version__


class ConfigError(Exception):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # Unknown argument values could contain a mistakenly supplied secret.
        self.exit(2, '{"ok": false, "error": "E_ARGUMENT"}\n')


def _json(value):
    print(json.dumps(value, sort_keys=True))


def _is_link(meta):
    return stat.S_ISLNK(meta.st_mode) or bool(getattr(meta, "st_file_attributes", 0) & 0x400)


def _private_directory(path: Path):
    path = path.absolute()
    # Reject redirection through a symlink/reparse point anywhere in the path.
    for candidate in reversed((path, *path.parents)):
        if candidate.exists() or candidate.is_symlink():
            meta = candidate.lstat()
            if _is_link(meta) or not stat.S_ISDIR(meta.st_mode):
                raise ConfigError("E_CONFIG_PATH")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    meta = path.lstat()
    if os.name == "posix" and (meta.st_uid != os.geteuid() or meta.st_mode & 0o077):
        raise ConfigError("E_CONFIG_PATH")
    return path


def initialize_config(path: Path, *, origin_prompt=None, secret_prompt=None, health_profile="outbox"):
    """Create one private config, never replacing an existing file. Does no networking."""
    from .alerts import Config

    if secret_prompt is None and not sys.stdin.isatty():
        raise ConfigError("E_INTERACTIVE_TERMINAL_REQUIRED")
    origin_prompt = origin_prompt or input
    secret_prompt = secret_prompt or getpass.getpass
    path = Path(path).absolute()
    _private_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise ConfigError("E_CONFIG_EXISTS")
    origin = origin_prompt("ntfy HTTPS origin (for example https://ntfy.example.com): ").strip()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            topic = secret_prompt("ntfy topic (hidden): ").strip()
            token = secret_prompt("ntfy access token (hidden; leave empty if none): ").strip() or None
    except Exception:
        raise ConfigError("E_HIDDEN_INPUT") from None
    config = Config(origin, topic, token, health_profile=health_profile)
    try:
        config.validate()
    except Exception:
        raise ConfigError("E_CONFIG_VALUE") from None
    value = {"base_url": origin, "topic": topic, "health_profile": health_profile}
    if token is not None:
        value["token"] = token
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    fd = None
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except Exception:
        if fd is not None:
            os.close(fd)
        # An incomplete file must not look like a usable configuration.
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ConfigError("E_CONFIG_WRITE") from None
    return {"ok": True, "configured": True, "health_profile": health_profile, "network_contacted": False}


def doctor():
    """Describe capabilities without reading credentials, invoking tools, or networking."""
    linux = sys.platform.startswith("linux")
    windows = sys.platform == "win32"
    return {
        "ok": sys.version_info >= (3, 10),
        "version": __version__,
        "python_supported": sys.version_info >= (3, 10),
        "platform": "linux" if linux else "windows" if windows else "other",
        "linux_root": linux and getattr(os, "geteuid", lambda: -1)() == 0,
        "host_alerts_platform": linux,
        "native_snapshot_platform": windows,
        "manual_review_available": True,
        "network_contacted": False,
        "continuous_connection_intake": False,
    }


def _parser():
    parser = SafeArgumentParser(description="Local observations, manual connection review, and durable ntfy alerts (alpha).")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Offline capability summary; no credential reads or network requests")
    config = sub.add_parser("init-config", help="Create private ntfy config using hidden local prompts")
    config.add_argument("--config", type=Path, default=Path("/etc/sentinel-alerts/config.json"))
    config.add_argument("--health-profile", choices=("outbox", "adguard"), default="outbox")
    case = sub.add_parser("init-case", help="Create a new private folder for manual review")
    case.add_argument("--directory", type=Path, required=True)
    for name, description in (
        ("alerts", "Outbox: status, enqueue-test, tick"),
        ("router", "Optional collector: collect, status"),
        ("review", "Manual queue: explicit --case-dir and --db required"),
        ("windows-snapshot", "Private Windows owner-PID table snapshot"),
    ):
        sub.add_parser(name, help=description, add_help=False)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    delegates = {"alerts": "alerts", "review": "review", "windows-snapshot": "windows"}
    if argv and argv[0] in delegates:
        return importlib.import_module("." + delegates[argv[0]], __package__).main(argv[1:])
    if argv and argv[0] == "router":
        if len(argv) < 2 or argv[1] in ("-h", "--help"):
            print("usage: sentinel-network-watch router {collect,status} [--config FILE] [--state-dir DIRECTORY]")
            print("collect contacts only the explicitly configured supported gateway and hands notices to the alert outbox.")
            return 0 if len(argv) > 1 else 2
        if argv[1] == "collect":
            return importlib.import_module(".router_runner", __package__).main(argv[2:])
        if argv[1] == "status":
            return importlib.import_module(".router", __package__).main(argv[1:])
        _json({"ok": False, "error": "E_ARGUMENT"})
        return 2
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = doctor()
        elif args.command == "init-config":
            if not sys.platform.startswith("linux") or getattr(os, "geteuid", lambda: -1)() != 0:
                raise ConfigError("E_PRIVILEGE")
            result = initialize_config(args.config, health_profile=args.health_profile)
        elif args.command == "init-case":
            from .privacy import init_case
            init_case(args.directory)
            result = {"ok": True, "case_created": True}
        else:
            parser.error("a subcommand is required")
        _json(result)
        return 0 if result["ok"] else 1
    except ConfigError as error:
        _json({"ok": False, "error": str(error)})
        return 1
    except Exception:
        _json({"ok": False, "error": "E_INITIALIZE"})
        return 1
