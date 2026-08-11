"""Environment probe for the direct Code Mode CLI.

Verifies what idb actually needs WITHOUT importing ida_* into the CLI process:
spawning a managed worker requires the idapro package and an activated idalib
(ida-config.json), so idapro is probed via a throwaway subprocess that really
initializes the kernel and reports the version.
"""

import importlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


def _ida_config_path():
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    return Path.home() / ".idapro" / "ida-config.json"


def _find_spec(name):
    # find_spec on a dotted name raises when the parent package is absent —
    # precisely the situation doctor exists to report, not crash on.
    try:
        return importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return None


def _check_python():
    return ("python", "OK", f"{sys.version.split()[0]} @ {sys.executable}")


def _check_module(name):
    if _find_spec(name) is None:
        return (name, "MISSING", "install ida-codemode")
    try:
        importlib.import_module(name)
        return (name, "OK", "installed")
    except Exception as exc:
        return (name, "ERROR", str(exc))


def _check_idapro():
    if _find_spec("idapro") is None:
        return ("idapro", "MISSING",
                "pip install idapro, then run py-activate-idalib.py to activate it")
    code = "import idapro,sys; sys.stdout.write('%d.%d.%d' % idapro.get_library_version())"
    try:
        res = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, timeout=90)
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
        return ("ida-config", "OK",
                cfg.get("Paths", {}).get("ida-install-dir", "(no install dir)"))
    except (ValueError, OSError) as exc:
        return ("ida-config", "ERROR", str(exc))


def _check_codemode_registry():
    try:
        from ida_codemode.registry import REGISTRY_DIR, scan_instances

        instances = scan_instances(REGISTRY_DIR)
        ready = sum(item.state.value == "ready" for item in instances)
        return (
            "code-mode",
            "OK",
            f"{ready} ready / {len(instances)} registered in {REGISTRY_DIR}",
        )
    except Exception as exc:
        return ("code-mode", "ERROR", str(exc))


def run():
    """Return ``(rows, ok)`` where rows are ``(check, status, detail)``."""
    rows = [
        _check_python(),
        _check_module("ida_codemode.client"),
        _check_idapro(),
        _check_ida_config(),
        _check_codemode_registry(),
    ]
    ok = all(status not in {"MISSING", "ERROR"} for _, status, _ in rows)
    return rows, ok
