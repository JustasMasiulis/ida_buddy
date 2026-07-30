"""IDA-side entry points loaded through Code Mode's ``execute_python`` RPC.

This module deliberately contains no transport code. The CLI's Code Mode request
adds its installed package directory to the remote interpreter's ``sys.path``
and invokes these functions in the registered GUI or idalib instance.
"""

from __future__ import annotations

_INITIALIZED = False


def _load(db, session_id: str = "", target: str = "") -> None:
    global _INITIALIZED

    from idb.worker.handlers import load_all
    from idb.worker.dispatch import CTX

    load_all()
    # Keep the ida-domain object available to ported handlers.  The existing
    # handlers still use IDAPython where ida-domain has no equivalent yet.
    CTX.database = db
    CTX.session_id = session_id
    CTX.target = target
    CTX.ready = True
    if not _INITIALIZED:
        try:
            import ida_hexrays

            ida_hexrays.init_hexrays_plugin()
        except Exception:
            pass
        _INITIALIZED = True


def initialize(db, session_id: str = "", target: str = ""):
    """Load handlers, warm IDA caches, and return the standard open summary."""
    _load(db, session_id, target)

    from idb.worker.handlers import info
    from idb.worker.dispatch import invoke

    info.warmup()
    return invoke("open_summary", {}, ready=True)


def execute(db, command: str, arguments: dict | None = None):
    """Run one ida-buddy handler and return its unencoded RPC envelope."""
    _load(db)

    from idb.worker.dispatch import invoke

    return invoke(command, arguments or {}, ready=True)
