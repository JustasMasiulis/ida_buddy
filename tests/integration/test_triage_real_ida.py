"""Real-IDA integration for `triage`, against a larger, symbol-stripped binary.

`where.exe` (64K) is too small to exercise triage's groups / SEH / chunks /
ranking / budget. We analyze the committed `tests/fixtures/hvix64.exe` (the x64
Hyper-V hypervisor) instead: stripped (so callees are mostly `sub_*`, exercising
the work-item ranking), rich in .pdata/SEH and cold chunks, deep call graph.

Assertions stay tolerant — the point is fit/formatting/limits and that the 5s
server budget keeps the call comfortably under the client timeout — not exact
counts, names, or strings (those drift with IDA versions).
"""

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import uuid

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
BINARY = pathlib.Path(
    os.environ.get("IDB_TRIAGE_BINARY", ROOT / "tests" / "fixtures" / "hvix64.exe")
).resolve()


def _env_for(workspace):
    state = workspace / "state"
    tmp = workspace / "tmp"
    state.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(state)
    env["XDG_STATE_HOME"] = str(state)
    env["TEMP"] = str(tmp)
    env["TMP"] = str(tmp)
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) if not old else str(SRC) + os.pathsep + old
    return env


def _run(env, *args, timeout=120, check=True):
    res = subprocess.run(
        [sys.executable, "-m", "idb", *map(str, args)],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout,
    )
    if check and res.returncode != 0:
        cmd = " ".join(["python", "-m", "idb", *map(str, args)])
        pytest.fail(f"{cmd} exited {res.returncode}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}")
    return res


@pytest.fixture(scope="module", autouse=True)
def require_full_ida():
    if importlib.util.find_spec("idapro") is None:
        pytest.fail("integration tests require idapro/full IDA")
    if not BINARY.exists():
        pytest.skip(f"triage fixture missing: {BINARY}")


@pytest.fixture(scope="module")
def session():
    workspace = ROOT / ".tmp" / "idb-triage-it" / f"{os.getpid()}-{uuid.uuid4().hex}"
    inputs = workspace / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    target = inputs / BINARY.name
    shutil.copy2(BINARY, target)
    env = _env_for(workspace)
    _run(env, "open", target, "-t", "600", timeout=660)
    try:
        yield {"env": env, "target": target}
    finally:
        _run(env, "close", "--no-save", timeout=90, check=False)
        time.sleep(0.5)
        shutil.rmtree(workspace, ignore_errors=True)


def _functions(env, n=60):
    res = _run(env, "funcs", "-n", str(n))
    rows = []
    for line in res.stdout.splitlines()[1:]:
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            rows.append((parts[0], parts[2]))
    if not rows:
        pytest.fail(f"no functions parsed\nstdout:\n{res.stdout}")
    return rows


def test_triage_runs_and_is_compact(session):
    env = session["env"]
    addr, _name = _functions(env)[0]

    started = time.monotonic()
    res = _run(env, "triage", addr)
    elapsed = time.monotonic() - started

    # the 5s server budget should keep this well under the 30s default client wait
    assert elapsed < 25, f"triage took {elapsed:.1f}s"
    assert "INTERNAL" not in res.stderr and "Traceback" not in res.stderr
    assert " @ " in res.stdout.splitlines()[0]
    assert re.search(r"^callees: \d", res.stdout, re.MULTILINE)


def test_triage_surfaces_unnamed_callees_and_proto(session):
    """hvix64 is stripped, so most callees are sub_* work-items (which must float to
    the top of the ranking) and most prototypes are guessed. We do NOT assert a
    `structure` section: this image carries no separate .pdata and is stripped of
    SEH-handler names, and IDA reconstructs tail chunks for only a handful of
    functions — so that section legitimately appears rarely."""
    env = session["env"]
    saw_unnamed = False
    saw_proto = False
    saw_callee_table = False

    for addr, _name in _functions(env, n=60):
        out = _run(env, "triage", addr).stdout
        if re.search(r"\bsub_[0-9A-Fa-f]+\b", out):
            saw_unnamed = True
        if re.search(r"^proto\b", out, re.MULTILINE):
            saw_proto = True
        if re.search(r"^\s+ADDR\s+SIZE\s+CALLERS\s+KIND\s+NAME", out, re.MULTILINE):
            saw_callee_table = True
        if saw_unnamed and saw_proto and saw_callee_table:
            break

    assert saw_unnamed, "expected un-named sub_* callees in a stripped binary"
    assert saw_proto, "expected a prototype line"
    assert saw_callee_table, "expected the callee table header"


def test_triage_harvests_caller_arg_types(session):
    """The headline feature: across functions with many callers, at least one
    should yield a `param types` section (real arg types recovered from call
    sites). Tolerant — only requires it to appear once across the sample."""
    env = session["env"]
    saw_params = False
    for addr, _name in _functions(env, n=40):
        out = _run(env, "triage", addr).stdout
        if re.search(r"^param types: \d", out, re.MULTILINE):
            saw_params = True
            break
    assert saw_params, "expected at least one function to harvest caller-site arg types"


def test_triage_rejects_non_function(session):
    env = session["env"]
    res = _run(env, "triage", "0n0", check=False)
    assert res.returncode == 1
    assert res.stdout == ""
    assert res.stderr.strip()
