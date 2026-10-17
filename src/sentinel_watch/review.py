"""Local, exact-endpoint review queue. Decisions never change network policy.

An observation is a sighting, not a session or byte count. Identity is exactly
actor/app/kind/transport/address/port; no application-wide approvals exist.
The caller owns evidence safety, source attribution, and private directory ACLs.
This queue implements endpoint approvals only, not single-session approvals.
"""
from __future__ import annotations

import argparse
from .arguments import SafeArgumentParser
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time

KINDS = {"native_tcp", "router_record", "listener"}
TRANSPORTS = {"TCP", "unknown"}
KEY_FIELDS = ("actor_key", "app_context_key", "kind", "transport",
              "destination_address", "destination_port")
MAX_METADATA_BYTES = 8192
MAX_INPUT_BYTES = 4 * 1024 * 1024
CASE_ROOT = None


class ReviewError(ValueError):
    pass


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _text(value, limit, code):
    if (not isinstance(value, str) or not value or len(value) > limit or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ReviewError(code)
    return value


def _number(value, code):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ReviewError(code)
    return float(value)


def _address(value, kind):
    if value is None and kind == "router_record":
        return None
    value = _text(value, 253, "E_ADDRESS")
    if value == "*" and kind == "listener":
        return value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        # Hostname labels are context, never proof of DNS resolution/ownership.
        name = value.rstrip(".").lower()
        if not name or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
                           for x in name.split(".")):
            raise ReviewError("E_ADDRESS") from None
        return name


def _metadata(value):
    if not isinstance(value, dict) or len(value) > 64:
        raise ReviewError("E_METADATA")
    forbidden = re.compile(r"password|passphrase|secret|token|authorization|credential|command.?line|argv", re.I)
    for key, item in value.items():
        _text(key, 64, "E_METADATA_KEY")
        if forbidden.search(key):
            raise ReviewError("E_METADATA_PRIVATE_FIELD")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise ReviewError("E_METADATA_VALUE")
        if isinstance(item, str) and (len(item) > 2048 or any(ord(c) < 32 for c in item)):
            raise ReviewError("E_METADATA_VALUE")
        if isinstance(item, float) and not math.isfinite(item):
            raise ReviewError("E_METADATA_VALUE")
    encoded = _json(value)
    if len(encoded.encode("ascii")) > MAX_METADATA_BYTES:
        raise ReviewError("E_METADATA_TOO_LARGE")
    return encoded


def validate_path(path, *, project_access=False, must_exist=False):
    path = Path(os.path.abspath(os.fspath(path)))
    if project_access:
        if CASE_ROOT is None:
            raise ReviewError("E_PRIVATE_ROOT_REQUIRED")
        root = Path(os.path.abspath(CASE_ROOT))
        try:
            path.relative_to(root)
        except ValueError:
            raise ReviewError("E_PATH_OUTSIDE_PRIVATE_ROOT") from None
    if not path.parent.is_dir():
        raise ReviewError("E_PARENT_MISSING")
    for candidate in (*reversed(path.parents), path):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if candidate == path and not must_exist:
                continue
            raise ReviewError("E_PATH_MISSING") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ReviewError("E_PATH_LINK")
        if candidate == path and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ReviewError("E_PATH_NOT_PRIVATE_REGULAR_FILE")
    return path


class ReviewQueue:
    def __init__(self, db_path, clock=time.time, *, max_records=50000,
                 max_db_bytes=200 * 1024 * 1024):
        self.path = validate_path(db_path)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                validate_path(sidecar, must_exist=True)
        if (isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1 or
                isinstance(max_db_bytes, bool) or not isinstance(max_db_bytes, int) or max_db_bytes < 4096):
            raise ReviewError("E_CAP_CONFIGURATION")
        self.max_records = max_records
        self.max_db_bytes = max_db_bytes
        self.clock = clock
        self.db = sqlite3.connect(str(self.path), timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS relationships(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relationship_key TEXT UNIQUE NOT NULL,
                actor_key TEXT NOT NULL, app_context_key TEXT NOT NULL,
                kind TEXT NOT NULL, transport TEXT NOT NULL,
                destination_address TEXT, destination_port INTEGER NOT NULL,
                first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                sightings INTEGER NOT NULL, evidence_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS observations(
                observation_id TEXT PRIMARY KEY, record_hash TEXT NOT NULL,
                relationship_id INTEGER NOT NULL REFERENCES relationships(id));
            CREATE TABLE IF NOT EXISTS decisions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relationship_id INTEGER NOT NULL REFERENCES relationships(id),
                relationship_key TEXT NOT NULL, decision TEXT NOT NULL,
                scope TEXT NOT NULL, decided_at REAL NOT NULL, expires_at REAL,
                until_revoked INTEGER NOT NULL);
        """)
        self.db.commit()
        validate_path(self.path, must_exist=True)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _check_capacity(self):
        records = self.db.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        if records > self.max_records or pages * page_size > self.max_db_bytes:
            raise ReviewError("E_QUEUE_CAP")

    def _view(self, row):
        if row is None:
            raise ReviewError("E_ID_NOT_FOUND")
        result = dict(row)
        result["review_id"] = "C%04d" % result.pop("id")
        result["evidence"] = json.loads(result.pop("evidence_json"))
        last = self.db.execute("SELECT * FROM decisions WHERE relationship_id=? ORDER BY id DESC LIMIT 1",
                               (row["id"],)).fetchone()
        complete_endpoint = row["destination_address"] is not None and row["transport"] != "unknown"
        active = (last and (last["until_revoked"] or last["expires_at"] > self.clock()) and
                  (last["decision"] == "reject" or complete_endpoint))
        result["status"] = ("approved" if last["decision"] == "approve" else "not_approved") if active else "pending"
        if not complete_endpoint and result["status"] != "not_approved":
            result["status"] = "pending_more_evidence"
        result["decision"] = None if last is None else {
            "decision": last["decision"], "scope": last["scope"],
            "decided_at": last["decided_at"], "expires_at": last["expires_at"],
            "until_revoked": bool(last["until_revoked"]), "active": bool(active)}
        result["blocking_action"] = False
        return result

    def ingest(self, record):
        if not isinstance(record, dict) or set(record) - set(KEY_FIELDS) - {"evidence", "observation_id", "observed_at"}:
            raise ReviewError("E_RECORD_FIELDS")
        try:
            key = {k: record[k] for k in KEY_FIELDS}
        except KeyError:
            raise ReviewError("E_RECORD_FIELDS") from None
        for k in ("actor_key", "app_context_key"):
            _text(key[k], 512, "E_IDENTITY")
        if key["kind"] not in KINDS or key["transport"] not in TRANSPORTS:
            raise ReviewError("E_KIND_OR_TRANSPORT")
        port = key["destination_port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ReviewError("E_PORT")
        key["destination_address"] = _address(key["destination_address"], key["kind"])
        evidence = _metadata(record.get("evidence", {}))
        observed = _number(record.get("observed_at", self.clock()), "E_OBSERVED_AT")
        identity = _json(key)
        relationship_key = hashlib.sha256(identity.encode("ascii")).hexdigest()
        observation = {**key, "evidence": json.loads(evidence)}
        if "observed_at" in record:
            observation["observed_at"] = observed
        digest = hashlib.sha256(_json(observation).encode("ascii")).hexdigest()
        oid = _text(record.get("observation_id", digest), 512, "E_OBSERVATION_ID")
        with self.db:
            previous = self.db.execute("SELECT * FROM observations WHERE observation_id=?", (oid,)).fetchone()
            if previous:
                if previous["record_hash"] != digest:
                    raise ReviewError("E_OBSERVATION_ID_CONFLICT")
                row = self.db.execute("SELECT * FROM relationships WHERE id=?", (previous["relationship_id"],)).fetchone()
                result = self._view(row)
                result["new_sighting"] = False
                return result
            self.db.execute("""INSERT INTO relationships
                (relationship_key,actor_key,app_context_key,kind,transport,destination_address,
                 destination_port,first_seen,last_seen,sightings,evidence_json)
                VALUES(?,?,?,?,?,?,?,?,?,1,?) ON CONFLICT(relationship_key) DO UPDATE SET
                first_seen=MIN(first_seen,excluded.first_seen),
                last_seen=MAX(last_seen,excluded.last_seen), sightings=sightings+1,
                evidence_json=CASE WHEN excluded.last_seen>=last_seen THEN excluded.evidence_json ELSE evidence_json END""",
                (relationship_key, *(key[k] for k in KEY_FIELDS), observed, observed, evidence))
            row = self.db.execute("SELECT * FROM relationships WHERE relationship_key=?", (relationship_key,)).fetchone()
            self.db.execute("INSERT INTO observations VALUES(?,?,?)", (oid, digest, row["id"]))
            self._check_capacity()
            result = self._view(row)
            result["new_sighting"] = True
            return result

    def _id(self, review_id):
        if not isinstance(review_id, str) or not re.fullmatch(r"C[0-9]{4,}", review_id) or int(review_id[1:]) < 1:
            raise ReviewError("E_REVIEW_ID")
        return int(review_id[1:])

    def read(self, review_id):
        return self._view(self.db.execute("SELECT * FROM relationships WHERE id=?", (self._id(review_id),)).fetchone())

    def decide(self, review_id, decision, *, scope_endpoint=False, expires_seconds=None, until_revoked=False):
        if decision not in ("approve", "reject") or scope_endpoint is not True:
            raise ReviewError("E_EXPLICIT_ENDPOINT_DECISION_REQUIRED")
        if until_revoked is not True and until_revoked is not False:
            raise ReviewError("E_EXPIRY_REQUIRED")
        if until_revoked:
            if expires_seconds is not None:
                raise ReviewError("E_EXPIRY_CONFLICT")
        elif isinstance(expires_seconds, bool) or not isinstance(expires_seconds, int) or not 1 <= expires_seconds <= 86400:
            raise ReviewError("E_EXPIRY_REQUIRED")
        rid = self._id(review_id)
        now = _number(self.clock(), "E_CLOCK")
        with self.db:
            row = self.db.execute("SELECT * FROM relationships WHERE id=?", (rid,)).fetchone()
            if row is None:
                raise ReviewError("E_ID_NOT_FOUND")
            if decision == "approve" and (row["destination_address"] is None or row["transport"] == "unknown"):
                raise ReviewError("E_INCOMPLETE_ENDPOINT")
            self.db.execute("""INSERT INTO decisions
                (relationship_id,relationship_key,decision,scope,decided_at,expires_at,until_revoked)
                VALUES(?,?,?,'endpoint',?,?,?)""",
                (rid, row["relationship_key"], decision, now,
                 None if until_revoked else now + expires_seconds, int(until_revoked)))
            self._check_capacity()
        return self.read(review_id)

    def list_records(self, status=None):
        if status not in (None, "pending", "pending_more_evidence", "approved", "not_approved"):
            raise ReviewError("E_STATUS")
        rows = [self._view(r) for r in self.db.execute("SELECT * FROM relationships ORDER BY id")]
        return rows if status is None else [r for r in rows if r["status"] == status]

    def export_records(self):
        return self.list_records()

    def status(self):
        counts = {k: 0 for k in ("pending", "pending_more_evidence", "approved", "not_approved")}
        for row in self.list_records():
            counts[row["status"]] += 1
        return {"relationships": sum(counts.values()), "counts": counts, "blocking_action": False}


def main(argv=None):
    global CASE_ROOT
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--db", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest")
    ingest.add_argument("--input", required=True)
    read = sub.add_parser("read")
    read.add_argument("--id", required=True)
    sub.add_parser("status")
    export = sub.add_parser("export")
    export.add_argument("--output", required=True)
    decision = sub.add_parser("decide")
    decision.add_argument("--id", required=True)
    decision.add_argument("--decision", choices=("approve", "reject"), required=True)
    decision.add_argument("--scope-endpoint", action="store_true", required=True)
    expiry = decision.add_mutually_exclusive_group(required=True)
    expiry.add_argument("--expires-seconds", type=int)
    expiry.add_argument("--until-revoked", action="store_true")
    args = parser.parse_args(argv)
    try:
        from .privacy import verify_case
        CASE_ROOT = verify_case(args.case_dir)
        path = validate_path(args.db, project_access=True)
        with ReviewQueue(path) as queue:
            if args.command == "ingest":
                source = validate_path(args.input, project_access=True, must_exist=True)
                with source.open("rb") as handle:
                    blob = handle.read(MAX_INPUT_BYTES + 1)
                if len(blob) > MAX_INPUT_BYTES:
                    raise ReviewError("E_INPUT_TOO_LARGE")
                records = json.loads(blob)
                if not isinstance(records, list):
                    raise ReviewError("E_INPUT_LIST_REQUIRED")
                for record in records:
                    queue.ingest(record)
                result = queue.status()
            elif args.command == "status":
                result = queue.status()
            elif args.command == "read":
                # Endpoint/evidence details remain local to the calling terminal.
                result = queue.read(args.id)
            elif args.command == "export":
                target = validate_path(args.output, project_access=True)
                if target == path:
                    raise ReviewError("E_EXPORT_OVERWRITES_DATABASE")
                with target.open("x", encoding="utf-8") as handle:
                    handle.write(_json(queue.export_records()) + "\n")
                result = queue.status()
            else:
                queue.decide(args.id, args.decision, scope_endpoint=args.scope_endpoint,
                             expires_seconds=args.expires_seconds, until_revoked=args.until_revoked)
                result = queue.status()
        print(_json(result))
        return 0
    except ReviewError as error:
        print(_json({"error_code": str(error)}))
    except Exception:
        print(_json({"error_code": "E_LOCAL_OPERATION_FAILED"}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
