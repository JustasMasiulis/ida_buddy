"""Session registry: one JSON file per worker under the per-user state dir.

Security rests on that directory's ACL (per-user %LOCALAPPDATA% on Windows,
0o700 + 0o600 files on POSIX). No ida_* imports; transport is imported lazily
inside ping() so the pure helpers stay importable without a worker running.

Entry schema (all keys str):
    v, id, input_path, idb_path, status, port, token, pid, started_at, logfile

Lifecycle of `status`: pending (CLI claimed, spawning) -> analyzing (worker bound,
open_database running) -> ready (worker serving). The worker is the authoritative
writer once it is up (it knows every field from argv/env), which avoids a
dual-writer race with the spawning CLI.
"""

import os
import re
import sys
import json
import time
import ctypes
import hashlib
from pathlib import Path

from .errors import IdbError

SCHEMA_VERSION = 1

STATUS_PENDING = "pending"
STATUS_ANALYZING = "analyzing"
STATUS_READY = "ready"
STATUS_BUSY = "busy"

_DB_SUFFIXES = (".i64", ".idb")


def state_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        root = Path(base) / "ida-buddy" / "sessions"
    else:
        base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
        root = Path(base) / "ida-buddy" / "sessions"
    root.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
    return root

def _log_dir() -> Path:
    return state_dir().parent / "logs"


def _remove_stale_log(session_id):
    log_path = _log_dir() / f"{session_id}.log"
    try:
        log_path.unlink(missing_ok=True)
    except Exception:
        pass


def _entry_path(session_id) -> Path:
    return state_dir() / f"{session_id}.json"


def normkey(path) -> str:
    """Canonical comparison key for a filesystem path (case-folded on Windows)."""
    return os.path.normcase(os.path.abspath(str(path)))


def session_id(target) -> str:
    """Stable id derived from the path passed to `open` (not the resulting .i64),
    so reopening the same target is idempotent regardless of analysis outcome."""
    key = normkey(target)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(key).name).strip("_") or "db"
    return f"{slug[:32]}-{hashlib.sha1(key.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}"


def candidate_keys(path) -> set:
    """normkeys that should resolve to the same logical DB. IDA names a database
    <input><.i64|.idb> (the FULL input name plus the suffix), so a binary maps to
    <binary>.i64/.idb and a database maps back to its <binary>."""
    p = os.path.abspath(str(path))
    cands = {normkey(p)}
    if p.lower().endswith(_DB_SUFFIXES):
        cands.add(normkey(p[:-4]))
    else:
        for suffix in _DB_SUFFIXES:
            cands.add(normkey(p + suffix))
    return cands


def predicted_db_paths(target) -> list:
    """Where IDA would place the database for `target`: the path itself if it is
    already a .i64/.idb, else <target>.i64 and <target>.idb (bitness unknown)."""
    p = os.path.abspath(str(target))
    if p.lower().endswith(_DB_SUFFIXES):
        return [p]
    return [p + suffix for suffix in _DB_SUFFIXES]


def _serialize(entry) -> bytes:
    return json.dumps(entry, separators=(",", ":")).encode("utf-8")


def _write_atomic(path: Path, entry) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(_serialize(entry))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    if os.name == "posix":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def write(entry) -> dict:
    _write_atomic(_entry_path(entry["id"]), entry)
    return entry


def claim(entry) -> bool:
    """Atomically create a pending entry. Returns False if one already exists
    (a concurrent open of the same target won the race)."""
    path = _entry_path(entry["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as f:
        f.write(_serialize(entry))
    return True


def read(session_id_str):
    return read_path(_entry_path(session_id_str))


def read_path(path):
    try:
        with open(path, "rb") as f:
            entry = json.loads(f.read().decode("utf-8"))
    except (FileNotFoundError, ValueError, UnicodeDecodeError):
        return None
    return entry if isinstance(entry, dict) and "id" in entry else None


def update(session_id_str, **fields) -> dict:
    entry = read(session_id_str) or {"v": SCHEMA_VERSION, "id": session_id_str}
    entry.update(fields)
    return write(entry)


def unregister(session_id_str) -> None:
    try:
        _entry_path(session_id_str).unlink()
    except FileNotFoundError:
        pass


def list_all() -> list:
    out = []
    try:
        names = os.listdir(state_dir())
    except FileNotFoundError:
        return out
    for name in names:
        if name.startswith(".") or not name.endswith(".json"):
            continue
        entry = read_path(state_dir() / name)
        if entry is not None:
            out.append(entry)
    return out


def match(entries, session=None, idb=None) -> list:
    if session is not None:
        return [e for e in entries if e.get("id") == session]
    if idb is not None:
        cands = candidate_keys(idb)
        return [
            e
            for e in entries
            if normkey(e.get("input_path") or "x") in cands
            or normkey(e.get("idb_path") or "x") in cands
        ]
    return list(entries)


def pid_alive(pid) -> bool:
    if not pid:
        return False
    if sys.platform == "win32":
        SYNCHRONIZE = 0x00100000
        WAIT_TIMEOUT = 0x00000102
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(SYNCHRONIZE, False, int(pid))
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def ping(entry, timeout_ms=800):
    """Auth-checked liveness over TCP -> status string, or None if unreachable."""
    from .transport import ZmqClient
    from . import protocol

    port, token = entry.get("port"), entry.get("token")
    if not port or not token:
        return None
    client = ZmqClient(port, token)
    try:
        reply = client.call("ping", {}, timeout_ms=timeout_ms)
    except IdbError:
        return None
    finally:
        client.close()
    if protocol.is_ok(reply):
        result = reply.get("result") or {}
        return result.get("status", STATUS_READY)
    return None


def probe(entry, timeout_ms=800):
    """Best-effort current status: ready/analyzing/busy/pending, or None if dead.
    ping is authoritative; pid is only a fast negative / PID-reuse-aware guard."""
    pid = entry.get("pid")
    if pid and not pid_alive(pid):
        return None
    status = ping(entry, timeout_ms)
    if status:
        return status
    file_status = entry.get("status")
    if file_status in (STATUS_PENDING, STATUS_ANALYZING):
        return file_status
    if pid and pid_alive(pid):
        return STATUS_BUSY
    return None


def cleanup_stale() -> list:
    """Unlink only hard-stale entries (worker pid definitively gone). Conservative
    by design: an alive-but-unreachable worker (mid native call) is left alone.
    Also removes stale log files."""
    removed = []
    for entry in list_all():
        pid = entry.get("pid")
        if pid and not pid_alive(pid):
            sid = entry["id"]
            unregister(sid)
            _remove_stale_log(sid)
            removed.append(sid)
    return removed


def now() -> float:
    return time.time()
