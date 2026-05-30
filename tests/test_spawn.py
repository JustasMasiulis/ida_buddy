import os
import socket
import subprocess
import sys
import time

import pytest

from idb import registry, spawn

_FAKE = os.path.join(os.path.dirname(__file__), "fake_worker.py")


@pytest.fixture
def tmp_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    return tmp_path


def _launch_fake(port, sid, token, mode="ready", register=False):
    argv = [sys.executable, _FAKE, "--port", str(port), "--session", sid, "--mode", mode]
    if register:
        argv.append("--register")
    env = {**os.environ, "IDB_WORKER_TOKEN": token}
    return subprocess.Popen(argv, env=env)


def _stop(proc):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def test_free_port_returns_usable_port():
    p = spawn.free_port()
    assert isinstance(p, int) and 1024 < p < 65536


def test_poll_ready_success():
    port, sid, token = spawn.free_port(), "fake-ok", "a" * 32
    proc = _launch_fake(port, sid, token, mode="ready")
    try:
        ok, reason = spawn._poll_ready(sid, port, token, proc, time.time() + 15)
        assert ok and reason == "ready"
    finally:
        _stop(proc)


def test_poll_ready_detects_early_exit():
    port, sid, token = spawn.free_port(), "fake-crash", "a" * 32
    proc = _launch_fake(port, sid, token, mode="crash")
    ok, reason = spawn._poll_ready(sid, port, token, proc, time.time() + 15)
    assert not ok and "rc=1" in reason


def test_poll_ready_bind_collision_is_retryable():
    occupy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupy.bind(("127.0.0.1", 0))
    occupy.listen()
    port = occupy.getsockname()[1]
    sid, token = "fake-bind", "a" * 32
    proc = _launch_fake(port, sid, token, mode="ready")  # cannot bind -> exit 3
    try:
        ok, reason = spawn._poll_ready(sid, port, token, proc, time.time() + 15)
        assert not ok and reason == "bind"
    finally:
        _stop(proc)
        occupy.close()


def test_open_or_reuse_reuses_running_worker(tmp_env):
    target = r"C:\fake\thing.exe"
    sid = registry.session_id(target)
    port, token = spawn.free_port(), "b" * 32
    proc = _launch_fake(port, sid, token, mode="ready", register=True)
    try:
        deadline = time.time() + 15
        while time.time() < deadline and (registry.read(sid) or {}).get("status") != registry.STATUS_READY:
            time.sleep(0.1)
        assert (registry.read(sid) or {}).get("status") == registry.STATUS_READY

        entry, summary = spawn.open_or_reuse(target, deadline_s=10)
        assert entry["id"] == sid
        assert summary["input"] == "thing.exe" and summary["format"] == "FAKE"
    finally:
        _stop(proc)
        registry.unregister(sid)


def test_concurrent_claim_is_exclusive(tmp_env):
    sid = "race-1"
    e = {"v": registry.SCHEMA_VERSION, "id": sid, "status": registry.STATUS_PENDING}
    assert registry.claim(e) is True
    assert registry.claim(e) is False  # mid-start file survives a concurrent scan/claim
