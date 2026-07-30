"""Environment probe for the direct Code Mode CLI."""

import importlib
import importlib.util
import sys


def _check_python():
    return ("python", "OK", f"{sys.version.split()[0]} @ {sys.executable}")


def _check_module(name):
    spec = importlib.util.find_spec(name)
    if spec is None:
        return (name, "MISSING", "install ida-codemode")
    try:
        importlib.import_module(name)
        return (name, "OK", "installed")
    except Exception as exc:
        return (name, "ERROR", str(exc))


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
        _check_codemode_registry(),
    ]
    ok = all(status not in {"MISSING", "ERROR"} for _, status, _ in rows)
    return rows, ok
