"""Real CLI integration tests focused on actual idb usage.

These tests intentionally run ``python -m idb ...`` subprocesses instead of
calling worker RPCs directly. The goal is to cover the surface users and agents
actually interact with: command aliases, stdout/stderr separation, pagination
prompts, exit codes, and short multi-command workflows.
"""

import importlib.util
import json
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
DEFAULT_BINARY = ROOT / "tests" / "fixtures" / "where.exe"
BINARY = pathlib.Path(os.environ.get("IDB_TEST_BINARY", DEFAULT_BINARY)).resolve()


def _copy_input_tree(dst):
    dst.mkdir(parents=True, exist_ok=True)
    target = dst / BINARY.name
    shutil.copy2(BINARY, target)

    for suffix in (".i64", ".idb"):
        sidecar = pathlib.Path(str(BINARY) + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, dst / (BINARY.name + suffix))
    return target


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
    old_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) if not old_pythonpath else str(SRC) + os.pathsep + old_pythonpath
    return env


def _session_dir(env):
    base = pathlib.Path(env["LOCALAPPDATA"] if sys.platform == "win32" else env["XDG_STATE_HOME"])
    return base / "ida-buddy" / "sessions"


def _run(env, *args, timeout=90, check=True):
    res = subprocess.run(
        [sys.executable, "-m", "idb", *map(str, args)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and res.returncode != 0:
        cmd = " ".join(["python", "-m", "idb", *map(str, args)])
        pytest.fail(
            f"{cmd} exited {res.returncode}\n"
            f"stdout:\n{res.stdout}\n"
            f"stderr:\n{res.stderr}"
        )
    return res


@pytest.fixture(scope="module", autouse=True)
def require_full_ida():
    if importlib.util.find_spec("idapro") is None:
        pytest.fail("integration tests require idapro/full IDA")
    if not BINARY.exists():
        pytest.fail(f"integration test binary is missing: {BINARY}")


@pytest.fixture(scope="module")
def cli_workspace():
    workspace = ROOT / ".tmp" / "idb-cli-it" / f"{os.getpid()}-{uuid.uuid4().hex}"
    target = _copy_input_tree(workspace / "inputs")
    env = _env_for(workspace)
    try:
        yield workspace, target, env
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


@pytest.fixture(scope="module")
def cli_session(cli_workspace):
    _workspace, target, env = cli_workspace
    opened = _run(env, "open", target, "-t", "300", timeout=360)
    try:
        yield {"target": target, "env": env, "open": opened}
    finally:
        _run(env, "close", "--no-save", timeout=90, check=False)
        time.sleep(0.5)


def _first_function(env):
    res = _run(env, "funcs", "-n", "8", "--total")
    assert "ADDR" in res.stdout and "NAME" in res.stdout
    assert "[total " in res.stderr

    for line in res.stdout.splitlines()[1:]:
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            return parts[0], parts[2]
    pytest.fail(f"fixture produced no parseable functions\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}")


def _first_string_text(env):
    res = _run(env, "strings", "-n", "80")
    assert "ADDR" in res.stdout and "STRING" in res.stdout
    for line in res.stdout.splitlines()[1:]:
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and len(parts[2]) >= 4 and parts[2][:8].isprintable():
            return parts[2][:8]
    pytest.skip("fixture has no searchable strings")


def test_open_prints_triage_summary(cli_session):
    target = cli_session["target"]
    res = cli_session["open"]

    assert target.name in res.stdout
    assert "arch" in res.stdout
    assert "base" in res.stdout
    assert "segments" in res.stdout and "functions" in res.stdout
    assert res.stderr.strip() == ""


def test_sessions_lists_live_worker(cli_session):
    env = cli_session["env"]
    target = cli_session["target"]

    res = _run(env, "sessions")

    assert "SESSION" in res.stdout and "STATUS" in res.stdout
    assert target.name in res.stdout
    assert "ready" in res.stdout or "busy" in res.stdout
    assert res.stderr.strip() == ""


def test_sessions_pagination_banner_stays_on_stderr(cli_session):
    env = cli_session["env"]
    sessions = _session_dir(env)
    sessions.mkdir(parents=True, exist_ok=True)
    extra = sessions / "zz-extra.json"
    extra.write_text(
        json.dumps(
            {
                "v": 1,
                "id": "zz-extra",
                "input_path": r"C:\extra\sample.exe",
                "status": "ready",
                "pid": os.getpid(),
                "started_at": time.time(),
            }
        ),
        encoding="utf-8",
    )
    try:
        res = _run(env, "sessions", "-n", "1")
    finally:
        extra.unlink(missing_ok=True)

    assert len(res.stdout.splitlines()) == 2
    assert "[+more; resume with -o 1]" in res.stderr


def test_no_session_error_is_actionable(cli_workspace):
    workspace, _target, _session_env = cli_workspace
    env = _env_for(workspace / "empty-state")

    res = _run(env, "funcs", check=False)

    assert res.returncode == 3
    assert res.stdout == ""
    assert "no running sessions" in res.stderr
    assert "idb open <binary>" in res.stderr


def test_listing_pagination_and_total_contract(cli_session):
    env = cli_session["env"]

    res = _run(env, "funcs", "-n", "2", "--total")

    lines = res.stdout.splitlines()
    assert lines[0].split() == ["ADDR", "SIZE", "NAME"]
    assert len(lines) == 3
    assert "[+more; resume with -o 2]" in res.stderr
    assert "[total " in res.stderr


def test_function_triage_workflow_accepts_copied_addresses(cli_session):
    env = cli_session["env"]
    addr, name = _first_function(env)

    disas = _run(env, "u", addr, "-n", "4")
    assert len([line for line in disas.stdout.splitlines() if line.strip()]) >= 1
    assert re.search(rf"\b{re.escape(addr.lower())}\b", disas.stdout.lower())

    whole = _run(env, "uf", addr)
    assert name in whole.stdout or " @ 0x" in whole.stdout
    assert len(whole.stdout.splitlines()) >= len(disas.stdout.splitlines())

    nearest = _run(env, "ln", addr)
    assert "0x" in nearest.stdout
    assert name in nearest.stdout

    calls = _run(env, "calls", addr)
    assert "callers" in calls.stdout
    assert "callees" in calls.stdout

    xrefs = _run(env, "xref_to", addr, "-n", "3")
    assert xrefs.stdout.strip()
    assert xrefs.stderr == "" or "[+more" in xrefs.stderr


def test_memory_aliases_are_compact_and_parseable(cli_session):
    env = cli_session["env"]
    addr, _name = _first_function(env)

    db = _run(env, "db", addr, "-n", "16")
    db_line = db.stdout.splitlines()[0]
    assert re.match(r"^[0-9a-f]{12}\s{2}", db_line)
    assert "-" in db_line
    assert re.search(r"\s{2}.{1,16}$", db_line)

    dd = _run(env, "dd", addr, "-n", "4")
    dd_line = dd.stdout.splitlines()[0]
    assert re.match(r"^[0-9a-f]{12}\s{2}(?:[0-9a-f]{8}\s*){1,4}$", dd_line)


def test_string_search_workflow_reuses_visible_output(cli_session):
    env = cli_session["env"]
    text = _first_string_text(env)

    search = _run(env, "s", text, "-k", "str", "-n", "20")
    assert search.stdout.strip()
    assert "(no matches)" not in search.stdout

    refs = _run(env, "strrefs", text, "-n", "20")
    assert refs.stdout.strip()


def test_type_workflow_uses_type_names_from_listing(cli_session):
    env = cli_session["env"]

    types = _run(env, "types", "-k", "struct", "-n", "20")
    for line in types.stdout.splitlines()[1:]:
        parts = line.split(maxsplit=3)
        if len(parts) == 4:
            name = parts[3]
            break
    else:
        pytest.skip("fixture has no structs with type info")

    dt = _run(env, "dt", name)
    assert name in dt.stdout
    assert "size" in dt.stdout

    member = _run(env, "member", name, "0")
    assert name in member.stdout
    assert "byte 0" in member.stdout


def test_eval_command_computes_and_resolves(cli_session):
    env = cli_session["env"]

    res = _run(env, "?", "0n42")
    assert res.stdout.strip() == "2a  0n42  '*'  8bit"
    assert res.stderr.strip() == ""

    addr, name = _first_function(env)
    base = int(addr, 16)
    out = _run(env, "?", name, "+", "0n4").stdout.strip()
    assert int(out.split()[0], 16) == base + 4

    bad = _run(env, "?", "definitely_not_a_symbol_zzz", check=False)
    assert bad.returncode == 1
    assert bad.stdout == ""
    assert bad.stderr.strip()


def test_safe_mutation_flow_round_trips_with_undo(cli_session):
    env = cli_session["env"]
    addr, original_name = _first_function(env)
    new_name = "idb_cli_it_" + uuid.uuid4().hex[:8]

    renamed = _run(env, "rename", addr, new_name)
    assert new_name in renamed.stdout

    after = _run(env, "ln", addr)
    assert new_name in after.stdout

    undone = _run(env, "undo")
    assert "undone" in undone.stdout

    restored = _run(env, "ln", addr)
    assert original_name in restored.stdout
