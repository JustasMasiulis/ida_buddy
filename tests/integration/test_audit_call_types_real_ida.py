"""Real-IDA integration for `audit_call_types`, against the stripped hvix64.exe.

hvix64 carries almost no user-set types, so concrete *findings* are rare and we
do NOT assert any: classification correctness is covered by the pure tests. What
this exercises is the engine end-to-end through real Hex-Rays — the global
decompile pass, the ctree call walk, lvar/argument descriptor extraction, the
budget/limit truncation, scope narrowing, and pagination — none of which the pure
tests can reach. Assertions stay tolerant (liveness, header/row shape, bounds).
"""

import importlib.util
import os
import pathlib
import re
import shutil
import time
import uuid

import pytest

from _helpers import ROOT, make_env, remove_workspace, shutdown_workers, run_idb as _run

BINARY = pathlib.Path(
    os.environ.get("IDB_AUDIT_BINARY", ROOT / "tests" / "fixtures" / "hvix64.exe")
).resolve()


@pytest.fixture(scope="module", autouse=True)
def require_full_ida():
    if importlib.util.find_spec("idapro") is None:
        pytest.fail("integration tests require idapro/full IDA")
    if not BINARY.exists():
        pytest.skip(f"audit fixture missing: {BINARY}")


@pytest.fixture(scope="module")
def session():
    workspace = ROOT / ".tmp" / "idb-audit-it" / f"{os.getpid()}-{uuid.uuid4().hex}"
    inputs = workspace / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    target = inputs / BINARY.name
    shutil.copy2(BINARY, target)
    env = make_env(workspace)
    env["IDB_TEST_TARGET"] = str(target)
    _run(env, "open", target, "-t", "600", timeout=660)
    try:
        yield {"env": env, "target": target}
    finally:
        shutdown_workers(env)
        remove_workspace(workspace)


_HEAD = re.compile(r"^audit_call_types\b.*scanned (\d+)\+?/(\d+) funcs\s+(\d+) call sites\s+(\d+) findings",
                   re.MULTILINE)


def _header(out):
    m = _HEAD.search(out)
    assert m, f"missing/!malformed header:\n{out[:400]}"
    return {"scanned": int(m.group(1)), "total": int(m.group(2)),
            "call_sites": int(m.group(3)), "findings": int(m.group(4))}


def test_audit_runs_and_is_bounded(session):
    env = session["env"]
    started = time.monotonic()
    res = _run(env, "audit_call_types", "--budget", "10", "-n", "50", "-t", "120", timeout=180)
    elapsed = time.monotonic() - started

    assert elapsed < 90, f"audit took {elapsed:.1f}s"
    assert "INTERNAL" not in res.stderr and "Traceback" not in res.stderr
    head = _header(res.stdout)
    assert head["scanned"] >= 1 and head["total"] >= head["scanned"]


def test_audit_rows_are_well_formed(session):
    """If anything is flagged, every row must parse; zero findings is legitimate
    on a stripped image, so we only check shape when rows exist."""
    env = session["env"]
    out = _run(env, "audit_call_types", "--budget", "12", "-n", "50", "-t", "120", timeout=180).stdout
    head = _header(out)
    confid = re.findall(r"\b(\d+)% (\d+)s/(\d+)d\b", out)
    if head["findings"]:
        assert confid, f"header claims {head['findings']} findings but none parsed:\n{out}"
        # compact rows: single-char p/l kind, indented under their function with two spaces
        assert re.search(r"  [pl] \S", out), out
    for agree, _sites, _distinct in confid:
        assert 0 <= int(agree) <= 100


def test_scope_narrows_corpus(session):
    env = session["env"]
    full = _header(_run(env, "audit_call_types", "--budget", "8", "-n", "1", "-t", "120", timeout=180).stdout)
    scoped = _header(_run(env, "audit_call_types", "sub_", "--budget", "8", "-n", "1", "-t", "120",
                          timeout=180).stdout)
    assert scoped["total"] <= full["total"]


def test_total_banner(session):
    env = session["env"]
    res = _run(env, "audit_call_types", "--total", "-n", "1", "--budget", "8", "-t", "120", timeout=180)
    head = _header(res.stdout)
    m = re.search(r"\[total (\d+)\]", res.stderr)
    if head["findings"] >= 1:
        assert m, f"expected a [total N] banner on stderr:\n{res.stderr}"
        assert int(m.group(1)) >= 1


def test_kind_and_no_imports_smoke(session):
    env = session["env"]
    for extra in (["--kind", "locals"], ["--kind", "params"], ["--no-imports"]):
        res = _run(env, "audit_call_types", "--budget", "8", "-n", "20", "-t", "120", *extra, timeout=180)
        assert "Traceback" not in res.stderr and "INTERNAL" not in res.stderr
        _header(res.stdout)
