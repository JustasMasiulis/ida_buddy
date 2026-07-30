"""Local Code Mode client modules must never initialize IDA."""

import subprocess
import sys


_CODE = r"""
import sys
import idb.cli
import idb.codemode
import idb.worker.remote
bad = sorted(
    name for name in sys.modules
    if name == "idapro" or name.startswith("ida_") or name == "idautils"
)
print("BAD:" + ",".join(bad))
"""


def test_local_cli_and_remote_stub_are_lazy():
    result = subprocess.run(
        [sys.executable, "-c", _CODE],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "BAD:"
