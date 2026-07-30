"""Client-side adapter for the official IDA Code Mode RPC.

Code Mode executes in IDA's interpreter.  Both ends run on the same host, so we
publish this installation's package parent on the remote ``sys.path`` and call a
small IDA-side entry point.  This keeps the IDA plugin generic and lets GUI and
managed idalib instances use exactly the same handler implementation.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from idb import protocol
from idb.errors import AMBIGUOUS, NO_SESSION, IdbError

_PACKAGE_PARENT = str(Path(__file__).resolve().parent.parent)


def _payload(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _preamble(payload: dict[str, Any]) -> str:
    encoded = _payload(payload)
    return (
        "import base64, json, sys\n"
        f"_idb_path = {_PACKAGE_PARENT!r}\n"
        "if _idb_path not in sys.path:\n"
        "    sys.path.insert(0, _idb_path)\n"
        f"_idb_request = json.loads(base64.b64decode({encoded!r}).decode('utf-8'))\n"
    )


def initialize_code(session_id: str, target: str) -> str:
    """Build Code Mode Python that initializes handlers and returns a summary."""
    return _preamble({"session_id": session_id, "target": target}) + (
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


def resolve_target(*, session: str | None, idb: str | None) -> str:
    """Resolve CLI selection to a path, allowing ``--idb`` to spawn on demand."""
    if session and idb:
        raise IdbError(protocol.BAD_ARGS, "pass either --session or --idb, not both")
    if idb:
        return str(Path(idb).expanduser().resolve())

    rows = list_databases()
    if session:
        matches = [row for row in rows if row["id"] == session]
        if not matches:
            raise IdbError(NO_SESSION, f"no registered Code Mode instance {session!r}")
        row = matches[0]
        if row["status"] != "ready":
            raise IdbError(
                protocol.NOT_READY,
                f"Code Mode instance {session!r} is unavailable: "
                f"{row.get('error') or row['status']}",
            )
        return row["input_path"]

    ready = [row for row in rows if row["status"] == "ready"]
    if not ready:
        raise IdbError(
            NO_SESSION,
            "no registered Code Mode database; open one in IDA or pass --idb <path>",
        )
    if len(ready) > 1:
        raise IdbError(
            AMBIGUOUS,
            f"{len(ready)} registered databases; use -s <record-id> or --idb <path>",
            ready,
        )
    return ready[0]["input_path"]


def open_handle(path: str, *, timeout: float, fresh: bool = False):
    """Open one official handle; the caller owns and must close it."""
    from ida_codemode.client import DatabaseHandle

    return DatabaseHandle.open(path, timeout=timeout, new_database=fresh)


def envelope_from_execution(execution: Any) -> dict[str, Any]:
    if not isinstance(execution, dict) or not isinstance(execution.get("result"), dict):
        raise IdbError(protocol.INTERNAL, "Code Mode execution returned no idb envelope")
    envelope = execution["result"]
    if not isinstance(envelope.get("ok"), bool):
        raise IdbError(protocol.INTERNAL, "Code Mode returned an invalid idb envelope")
    return envelope
