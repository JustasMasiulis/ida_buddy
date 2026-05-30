"""Detached worker launch, readiness polling, and kill-by-PID. No ida_* imports.

The CLI never imports IDA; it spawns `idb.worker.main` as a detached process and
talks to it over RPC. open_or_reuse owns the spawn dance: reuse a healthy worker
for the same target, or claim a pending registry entry (closing the TOCTOU window)
and poll until the worker reports ready, retrying on a port-bind collision.
"""

import os
import sys
import time
import ctypes
import socket
import secrets
import subprocess

from idb import protocol, registry
from idb.errors import IdbError
from idb.transport import ZmqClient

DEFAULT_IDLE_TTL = 1800.0
DEFAULT_OPEN_DEADLINE = 600.0
_RETRIES = 6


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _logs_dir():
    d = registry.state_dir().parent / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _logfile(session_id):
    return str(_logs_dir() / f"{session_id}.log")


def _logtail(path, n=20):
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "r", errors="replace") as f:
            return "".join(f.readlines()[-n:]).rstrip()
    except OSError:
        return ""


def launch_worker(open_path, input_path, session_id, port, token, idle_ttl, save_policy, logfile):
    env = dict(os.environ)
    env["IDB_WORKER_TOKEN"] = token
    argv = [
        sys.executable, "-m", "idb.worker.main",
        "--port", str(port), "--session", session_id,
        "--open", open_path, "--input", os.path.abspath(input_path),
        "--idle-ttl", str(idle_ttl), "--save-policy", save_policy, "--logfile", logfile,
    ]
    creationflags = 0
    extra = {}
    if sys.platform == "win32":
        creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        extra["start_new_session"] = True
    log = open(logfile, "ab")
    try:
        return subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            env=env, creationflags=creationflags, close_fds=True, **extra,
        )
    finally:
        log.close()


def kill_pid(pid) -> bool:
    if not pid:
        return False
    if sys.platform == "win32":
        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not handle:
            return False
        try:
            return bool(kernel32.TerminateProcess(handle, 1))
        finally:
            kernel32.CloseHandle(handle)
    import signal

    try:
        os.kill(int(pid), signal.SIGKILL)
        return True
    except ProcessLookupError:
        return False


def _client(entry):
    return ZmqClient(entry["port"], entry["token"])


def _fetch_summary(entry, timeout_s):
    client = _client(entry)
    try:
        reply = client.call("open_summary", {}, timeout_ms=int(timeout_s * 1000))
    finally:
        client.close()
    if not protocol.is_ok(reply):
        raise IdbError(reply["error"]["code"], reply["error"]["message"])
    return reply["result"]


def _wait_ready(session_id, deadline):
    while time.time() < deadline:
        entry = registry.read(session_id)
        if entry is None:
            raise IdbError(protocol.IDA_ERROR, f"session {session_id} vanished while starting")
        status = registry.probe(entry)
        if status in (registry.STATUS_READY, registry.STATUS_BUSY):
            return entry
        if status is None:
            raise IdbError(protocol.IDA_ERROR,
                           f"worker died while starting\n{_logtail(entry.get('logfile'))}")
        time.sleep(0.2)
    raise IdbError(protocol.TIMEOUT, f"timed out waiting for {session_id} to become ready")


def _poll_ready(session_id, port, token, proc, deadline):
    client = ZmqClient(port, token)
    try:
        while time.time() < deadline:
            rc = proc.poll()
            if rc is not None:
                return False, ("bind" if rc == 3 else f"worker exited rc={rc}")
            try:
                reply = client.call("ping", {}, timeout_ms=800)
                if protocol.is_ok(reply) and reply["result"].get("status") == registry.STATUS_READY:
                    return True, "ready"
            except IdbError:
                pass
            time.sleep(0.2)
        return False, "timeout waiting for ready"
    finally:
        client.close()


def _choose_open_path(target, fresh):
    if fresh:
        return os.path.abspath(target)
    for candidate in registry.predicted_db_paths(target):
        if os.path.exists(candidate):
            return candidate
    return os.path.abspath(target)


def open_or_reuse(target, fresh=False, idle_ttl=DEFAULT_IDLE_TTL,
                  save_policy="save", deadline_s=DEFAULT_OPEN_DEADLINE):
    session_id = registry.session_id(target)
    registry.cleanup_stale()

    existing = registry.read(session_id)
    if existing:
        status = registry.probe(existing)
        if status in (registry.STATUS_READY, registry.STATUS_BUSY):
            if fresh:
                raise IdbError(
                    protocol.IDA_ERROR,
                    f"a worker is already open for {target!r}; close it first "
                    "(open --fresh would clobber the live database)",
                )
            return existing, _fetch_summary(existing, deadline_s)
        if status in (registry.STATUS_PENDING, registry.STATUS_ANALYZING):
            entry = _wait_ready(session_id, time.time() + deadline_s)
            return entry, _fetch_summary(entry, deadline_s)
        registry.unregister(session_id)

    open_path = _choose_open_path(target, fresh)
    token = secrets.token_hex(16)
    logfile = _logfile(session_id)
    claimed = False
    last_reason = None

    for _ in range(_RETRIES):
        port = free_port()
        entry = {
            "v": registry.SCHEMA_VERSION, "id": session_id,
            "input_path": os.path.abspath(target), "status": registry.STATUS_PENDING,
            "port": port, "token": token, "pid": os.getpid(),
            "started_at": registry.now(), "logfile": logfile,
        }
        if not claimed:
            if not registry.claim(entry):
                won = _wait_ready(session_id, time.time() + deadline_s)
                return won, _fetch_summary(won, deadline_s)
            claimed = True
        else:
            registry.write(entry)

        proc = launch_worker(open_path, target, session_id, port, token, idle_ttl, save_policy, logfile)
        ok, reason = _poll_ready(session_id, port, token, proc, time.time() + deadline_s)
        if ok:
            ready = registry.read(session_id)
            return ready, _fetch_summary(ready, deadline_s)
        last_reason = reason
        if reason == "bind":
            continue
        registry.unregister(session_id)
        raise IdbError(protocol.IDA_ERROR, f"worker failed to start: {reason}\n{_logtail(logfile)}")

    registry.unregister(session_id)
    raise IdbError(protocol.IDA_ERROR, f"could not start worker after retries: {last_reason}")
