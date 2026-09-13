"""IDA-side entry points loaded through Nexus's ``execute_python`` RPC.

The CLI's Nexus request adds its installed package directory to the remote
interpreter's ``sys.path`` and invokes these functions in the registered GUI or
idalib instance. Envelopes returned from here are bytes-encoded for Nexus's JSON
wire; the CLI decodes them in ``nexus.envelope_from_execution``.
"""

from __future__ import annotations

from idb import protocol

_INITIALIZED = False


def _load(db) -> bool:
    """Register handlers against ``db``. Returns True on the first load in this
    IDA process (handlers cache in ``sys.modules`` for the process lifetime, so
    a reused worker skips re-initialization). Analysis readiness is the CLI's
    job: it drains a worker's analysis and polls a GUI's settled barrier before
    any command reaches here."""
    global _INITIALIZED

    from idb.worker.handlers import load_all

    first = not _INITIALIZED
    if first:
        load_all()
        try:
            from idb.worker import hexcalls

            hexcalls.init()
        except Exception:
            pass
        _INITIALIZED = True

    from idb.worker import idahelp

    idahelp.declare_compact_types()
    return first


def initialize(db, warm: bool = True):
    """Load handlers, warm IDA caches, and return the standard open summary.

    ``warm=False`` (GUI instances) skips the whole-database string prefetch so
    the analyst's main thread is not frozen for the scan. The prefetch is also
    skipped when re-opening an already-loaded worker: its string cache persists
    with the process, so only the summary counts are refreshed.
    """
    first = _load(db)

    from idb.worker.handlers import info
    from idb.worker.dispatch import invoke

    info.warmup(prefetch_strings=warm and first)
    return protocol.encode_bytes(invoke("open_summary"))


def execute(db, command: str, arguments: dict | None = None):
    """Run one ida-buddy handler and return its bytes-encoded RPC envelope."""
    _load(db)

    from idb.worker.dispatch import invoke

    return protocol.encode_bytes(invoke(command, arguments or {}))
