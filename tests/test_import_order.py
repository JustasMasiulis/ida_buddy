"""Local Nexus client modules must never initialize IDA."""

import os
import pathlib
import subprocess
import sys

_SRC = pathlib.Path(__file__).resolve().parent.parent / "src"

_CODE = r"""
import sys
import idb.cli
import idb.nexus
import idb.worker.remote
bad = sorted(
    name for name in sys.modules
    if name == "idapro" or name.startswith("ida_") or name == "idautils"
)
print("BAD:" + ",".join(bad))
"""


def test_local_cli_and_remote_stub_are_lazy():
    # Pin the subprocess to this repo's src; a bare interpreter would import
    # whatever idb copy happens to be installed for it.
    env = os.environ.copy()
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(_SRC) if not old else str(_SRC) + os.pathsep + old
    result = subprocess.run(
        [sys.executable, "-c", _CODE],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "BAD:"
