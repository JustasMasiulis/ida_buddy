"""Environment probe. Verifies the things idb needs WITHOUT importing ida_* into
the CLI process: idapro is checked via find_spec + a throwaway subprocess that
actually initializes the kernel and reports the version."""

import os
import sys
import json
import importlib.util
import subprocess
from pathlib import Path

from idb import registry


def _ida_config_path():
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    return Path.home() / ".idapro" / "ida-config.json"


def _check_python():
    return ("python", "OK", f"{sys.version.split()[0]} @ {sys.executable}")


def _check_module(name):
    spec = importlib.util.find_spec(name)
    if spec is None:
        return (name, "MISSING", "pip install " + name)
    try:
        mod = importlib.import_module(name)
        return (name, "OK", getattr(mod, "__version__", "(installed)"))
    except Exception as exc:
        return (name, "ERROR", str(exc))


def _check_idapro():
    if importlib.util.find_spec("idapro") is None:
        return ("idapro", "MISSING",
                "pip install idapro, then run py-activate-idalib.py to activate it")
    code = "import idapro,sys; sys.stdout.write('%d.%d.%d' % idapro.get_library_version())"
    try:
        res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return ("idapro", "ERROR", "kernel init timed out")
    if res.returncode != 0:
        tail = (res.stderr.strip().splitlines() or [""])[-1]
        return ("idapro", "ERROR", tail)
    return ("idapro", "OK", f"IDA library {res.stdout.strip()}")


def _check_ida_config():
    path = _ida_config_path()
    if not path.exists():
        return ("ida-config", "MISSING", f"{path} (run py-activate-idalib.py)")
    try:
        cfg = json.loads(path.read_text())
        return ("ida-config", "OK", cfg.get("Paths", {}).get("ida-install-dir", "(no install dir)"))
    except (ValueError, OSError) as exc:
        return ("ida-config", "ERROR", str(exc))


def _check_sessions():
    try:
        entries = registry.list_all()
    except Exception as exc:
        return ("sessions", "ERROR", str(exc))
    return ("sessions", "OK", f"{len(entries)} registered in {registry.state_dir()}")


def run():
    """Return (rows, ok) where rows are (check, status, detail)."""
    rows = [
        _check_python(),
        _check_idapro(),
        _check_module("zmq"),
        _check_module("msgspec"),
        _check_ida_config(),
        _check_sessions(),
    ]
    ok = all(status != "MISSING" and status != "ERROR" for _, status, _ in rows)
    return rows, ok
