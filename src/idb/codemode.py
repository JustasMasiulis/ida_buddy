"""Client-side adapter for the official IDA Code Mode RPC.

Code Mode executes in IDA's interpreter.  Both ends run on the same host, so we
publish this installation's package parent on the remote ``sys.path`` and call a
small IDA-side entry point.  This keeps the IDA plugin generic and lets GUI and
managed idalib instances use exactly the same handler implementation.
"""

from __future__ import annotations

import base64
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from idb import __version__, protocol
from idb.errors import AMBIGUOUS, NO_SESSION, IdbError

_PACKAGE_PARENT = str(Path(__file__).resolve().parent.parent)

# Keep spawned workers alive this long after the last handle closes (the
# maximum ida-codemode allows) so IDA's in-memory undo history survives
# between CLI invocations.  GUI instances ignore lease keepalive entirely.
WORKER_LINGER = 3600.0

# Deadline for opening/spawning a database, when no explicit -t is given.  A
# cold idalib import + autoanalysis of a large binary can run for minutes.
OPEN_TIMEOUT = 600.0


def _payload(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _preamble(payload: dict[str, Any]) -> str:
    """Bootstrap code: publish our package path, then verify the remote idb
    package matches this CLI.  ``sys.modules`` pins the first-imported version
    for the life of the IDA process, so a version skew after an upgrade can
    only be cured by restarting IDA — surface that instead of BAD_ARGS noise."""
    encoded = _payload(payload)
    return (
        "import base64, json, sys\n"
        f"_idb_path = {_PACKAGE_PARENT!r}\n"
        "if _idb_path not in sys.path:\n"
        "    sys.path.insert(0, _idb_path)\n"
        "import idb as _idb_pkg\n"
        f"if getattr(_idb_pkg, '__version__', '?') != {__version__!r}:\n"
        "    raise RuntimeError(\n"
        "        'IDA holds stale idb modules (%s, CLI is %s); restart IDA or the '\n"
        f"        'idalib worker to reload' % (getattr(_idb_pkg, '__version__', '?'), {__version__!r})\n"
        "    )\n"
        f"_idb_request = json.loads(base64.b64decode({encoded!r}).decode('utf-8'))\n"
    )


def initialize_code(warm: bool = True) -> str:
    """Build Code Mode Python that initializes handlers and returns a summary."""
    return _preamble({"warm": warm}) + (
        "from idb.worker.remote import initialize as _idb_initialize\n"
        "_idb_initialize(db, **_idb_request)"
    )


def execute_code(command: str, arguments: dict[str, Any] | None = None) -> str:
    """Build Code Mode Python for one ida-buddy command."""
    return _preamble({"command": command, "arguments": arguments or {}}) + (
        "from idb.worker.remote import execute as _idb_execute\n"
        "_idb_execute(db, **_idb_request)"
    )


def _entry_path(entry) -> str:
    """Return a path that Code Mode can use to resolve a discovered instance."""
    if entry.exe_path and Path(entry.exe_path).exists():
        return entry.exe_path
    return entry.idb_path


def list_databases() -> list[dict[str, Any]]:
    """Return Code Mode discovery rows in the compact CLI formatter shape."""
    from ida_codemode.registry import scan_instances

    rows = []
    for discovered in scan_instances():
        entry = discovered.entry
        rows.append(
            {
                "id": entry.record_id,
                "status": discovered.state.value,
                "backend": entry.backend,
                "pid": entry.pid,
                "port": entry.port,
                "input_path": _entry_path(entry),
                "idb_path": entry.idb_path,
                "error": discovered.detail,
                "_entry": entry,
            }
        )
    rows.sort(key=lambda row: (row["status"] != "ready", row["input_path"]))
    return rows


def _require_ready(row):
    if row["status"] != "ready":
        raise IdbError(
            protocol.NOT_READY,
            f"Code Mode instance {row['id']} is unavailable: "
            f"{row.get('error') or row['status']}",
        )
    return row["_entry"]


def resolve_target(*, session: str | None, idb: str | None):
    """Resolve CLI selection to the RegistryEntry of a live instance, or to a
    validated path for ``--idb``, which resolves through Code Mode and may
    spawn a worker on demand."""
    if session and idb:
        raise IdbError(protocol.BAD_ARGS, "pass either --session or --idb, not both")
    if idb:
        return validate_path(idb)

    rows = list_databases()
    if session:
        matches = [row for row in rows if row["id"] == session]
        if not matches:
            raise IdbError(NO_SESSION, f"no registered Code Mode instance {session!r}")
        return _require_ready(matches[0])

    ready = [row for row in rows if row["status"] == "ready"]
    if not ready:
        if rows:
            detail = "; ".join(
                f"{row['id']} is {row['status']}"
                + (f" ({row['error']})" if row.get("error") else "")
                for row in rows
            )
            raise IdbError(protocol.NOT_READY, f"no usable Code Mode database: {detail}")
        raise IdbError(
            NO_SESSION,
            "no registered Code Mode database; open one in IDA or run `idb open <path>`",
        )
    if len(ready) > 1:
        raise IdbError(
            AMBIGUOUS,
            f"{len(ready)} registered databases; use -s <record-id> or --idb <path>",
            ready,
        )
    return ready[0]["_entry"]


def validate_path(path: str) -> str:
    """Canonicalize a database/binary path and confirm it exists on disk.
    Shared by ``--idb`` resolution and ``idb open``."""
    from ida_codemode.registry import canonical_path

    if not Path(path).expanduser().is_file():
        raise IdbError(protocol.BAD_ARGS, f"no such file: {path}")
    return canonical_path(path)


def registered_entries():
    """Registry records without health-probing — cheap, but may include a
    record whose process has since exited.  For path/backend selection where
    the subsequent attach surfaces staleness anyway."""
    from ida_codemode.registry import read_records

    return read_records()


def find_registered(path: str):
    """Registry entry owning a path, or None.  Never spawns or health-probes."""
    from ida_codemode.registry import canonical_path

    wanted = os.path.normcase(canonical_path(path))
    for entry in registered_entries():
        candidates = [entry.idb_path]
        if entry.exe_path:
            candidates.append(entry.exe_path)
        if any(wanted == os.path.normcase(candidate) for candidate in candidates):
            return entry
    return None


def open_handle(selection, *, timeout: float, fresh: bool = False,
                linger: float = WORKER_LINGER):
    """Open one official handle; the caller owns and must close it.

    A str selection is a path for ``idb open``/``--idb`` — it may spawn a
    worker.  A RegistryEntry attaches to exactly that instance: no path
    re-resolution, no GUI preference, no chance of spawning a lookalike.
    """
    from ida_codemode.client import ClientError, DatabaseHandle

    if isinstance(selection, str):
        return DatabaseHandle.open(
            selection, timeout=timeout, new_database=fresh, keepalive=linger
        )
    try:
        return DatabaseHandle.attach(selection, keepalive=linger)
    except ClientError as exc:
        raise IdbError(
            protocol.NOT_READY,
            f"Code Mode instance {selection.record_id} refused a lease "
            f"(it may have just exited): {exc}",
        ) from exc


def _transport_error(exc):
    code = protocol.TIMEOUT if "timed out" in str(exc).lower() else protocol.IDA_ERROR
    message = f"{type(exc).__name__}: {exc}"
    # ida_codemode RemoteError carries the remote traceback/stdout/stderr of a
    # failed execute_python in .details — without it a handler crash inside IDA
    # is undiagnosable from the CLI.
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        for key in ("traceback", "stdout", "stderr"):
            text = details.get(key)
            if text:
                message += f"\n--- remote {key} ---\n{str(text).rstrip()}"
    return IdbError(code, message)


def _await_analysis(handle, timeout):
    """Headless workers are ours: block until their analysis finishes (a worker
    opened via `idb open` already waited, so this is usually instant).  A GUI
    mid-initial-analysis instead fails NOT_READY via the non-mutating poll —
    never a silent multi-minute block, never force-enabled auto-analysis in the
    analyst's session."""
    if handle.entry.backend != "gui":
        handle.wait_autoanalysis(timeout)
    elif not handle.poll_autoanalysis().get("complete"):
        raise IdbError(protocol.NOT_READY,
                       f"GUI instance {handle.entry.record_id} is still auto-analyzing")


@contextmanager
def session(selection, *, timeout: float, fresh: bool = False,
            linger: float = WORKER_LINGER, wait: bool = True):
    """Own one handle's whole lifecycle: open/attach, optionally await analysis,
    translate ida_codemode exceptions to IdbError, and always close.  ``wait``
    gates the analysis barrier — lifecycle ops like ``close`` pass ``wait=False``."""
    handle = None
    try:
        handle = open_handle(selection, timeout=timeout, fresh=fresh, linger=linger)
        if wait:
            _await_analysis(handle, timeout)
        yield handle
    except IdbError:
        raise
    except Exception as exc:
        raise _transport_error(exc) from exc
    finally:
        if handle is not None:
            handle.close()


def envelope_from_execution(execution: Any) -> dict[str, Any]:
    if not isinstance(execution, dict) or not isinstance(execution.get("result"), dict):
        raise IdbError(protocol.INTERNAL, "Code Mode execution returned no idb envelope")
    envelope = protocol.decode_bytes(execution["result"])
    if not isinstance(envelope.get("ok"), bool):
        raise IdbError(protocol.INTERNAL, "Code Mode returned an invalid idb envelope")
    return envelope
