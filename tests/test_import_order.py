"""Bootstrap invariant: no ida_* module is imported before idapro is activated.

Part A needs no IDA (asserts the worker bootstrap is lazy). Part B is gated on
idapro being importable (asserts idapro precedes any ida_* import).
"""

import importlib.util
import subprocess
import sys

import pytest

_HAS_IDAPRO = importlib.util.find_spec("idapro") is not None

_PART_A = r"""
import sys
import idb.worker.main          # module import must NOT pull in IDA
bad = sorted(m for m in sys.modules if m == "idapro" or m.startswith("ida_") or m == "idautils")
print("BAD:" + ",".join(bad))
"""

_PART_B = r"""
import sys
seq = []
sys.addaudithook(lambda event, args: seq.append(args[0]) if event == "import" else None)

import idb.worker.activate as activate
pre = [m for m in sys.modules if m == "idapro" or m.startswith("ida_") or m == "idautils"]
assert not pre, f"ida imported too early: {pre}"

activate.ensure_idalib()
assert "idapro" in sys.modules, "idapro not imported by ensure_idalib"

def is_ida(name):
    return name == "idautils" or name.startswith("ida_")

i_idapro = next((i for i, n in enumerate(seq) if n == "idapro"), None)
i_ida = next((i for i, n in enumerate(seq) if is_ida(n)), None)
assert i_idapro is not None
assert i_ida is None or i_ida > i_idapro, f"ida_* (#{i_ida}) imported before idapro (#{i_idapro})"
print("OK")
"""


def _run(code):
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)


def test_worker_bootstrap_is_lazy():
    res = _run(_PART_A)
    assert res.returncode == 0, res.stderr
    assert "BAD:\n" in res.stdout or res.stdout.strip() == "BAD:", res.stdout


@pytest.mark.skipif(not _HAS_IDAPRO, reason="idapro not installed")
def test_idapro_precedes_ida_modules():
    res = _run(_PART_B)
    assert res.returncode == 0, res.stderr
    assert "OK" in res.stdout, res.stdout
