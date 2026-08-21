"""Shared environment and teardown helpers for the real-IDA integration suites."""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"


def make_env(workspace):
    """Isolated env for idb subprocesses: private temp dirs and — via
    IDA_NEXUS_STATE_DIR — a private Nexus registry, so tests neither see the
    user's live instances nor leak test workers into their registry."""
    state = workspace / "state"
    tmp = workspace / "tmp"
    state.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(state)
    env["XDG_STATE_HOME"] = str(state)
    env["IDA_NEXUS_STATE_DIR"] = str(state / "nexus")
    env["TEMP"] = str(tmp)
    env["TMP"] = str(tmp)
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) if not old else str(SRC) + os.pathsep + old
    return env


def run_idb(env, *args, timeout=120, check=True):
    target = env.get("IDB_TEST_TARGET")
    prefix = ["--idb", target] if target and args[0] not in {"open", "sessions", "close", "doctor"} else []
    res = subprocess.run(
        [sys.executable, "-m", "idb", *prefix, *map(str, args)],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout,
    )
    if check and res.returncode != 0:
        cmd = " ".join(["python", "-m", "idb", *map(str, args)])
        pytest.fail(f"{cmd} exited {res.returncode}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}")
    return res


def kill_pid(pid):
    if sys.platform == "win32":
        import ctypes

        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not handle:
            return
        try:
            kernel32.TerminateProcess(handle, 1)
        finally:
            kernel32.CloseHandle(handle)
    else:
        import signal

        try:
            os.kill(int(pid), signal.SIGKILL)
        except OSError:
            pass


def shutdown_workers(env):
    """Discard-shutdown every worker in the env's private registry, then kill
    whatever survived so teardown never waits out WORKER_LINGER or races a
    pending autosave."""
    try:
        run_idb(env, "close", "--all", "--no-save", timeout=60, check=False)
    except Exception:
        pass
    kill_workers(env)


def kill_workers(env):
    """Backstop for wedged or leaked workers: read the registry records
    directly and terminate the PIDs."""
    registry_dir = pathlib.Path(env["IDA_NEXUS_STATE_DIR"]) / "instances"
    if not registry_dir.is_dir():
        return
    for record in registry_dir.glob("*.json"):
        try:
            pid = json.loads(record.read_text()).get("pid")
        except (OSError, ValueError):
            continue
        if pid:
            kill_pid(pid)


def remove_workspace(path):
    """rmtree with retries: a shut-down worker releases its database file
    locks asynchronously, so a single rmtree can lose the race on Windows."""
    for _ in range(20):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.isdir(path):
            return
        time.sleep(0.5)
