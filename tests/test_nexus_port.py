import os
from pathlib import Path

import pytest

from idb import nexus, protocol
from idb.errors import AMBIGUOUS, NO_SESSION, IdbError


def test_execute_code_uses_official_runtime_db_and_encoded_arguments():
    code = nexus.execute_code("names", {"pattern": "x'\nraise Nope"})

    assert "_idb_execute(db, **_idb_request)" in code
    assert "raise Nope" not in code
    assert "from idb.worker.remote import execute" in code


def test_preamble_rejects_stale_remote_modules():
    # sys.modules pins the first-imported idb package for the IDA process's
    # lifetime; the preamble must detect the skew and demand a restart.
    code = nexus.execute_code("names", {})
    assert "__version__" in code
    assert "restart IDA" in code


def test_explicit_idb_resolves_to_validated_path(tmp_path: Path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"binary")

    resolved = nexus.resolve_target(session=None, idb=str(target))
    assert os.path.samefile(resolved, target)


def test_explicit_idb_missing_file_is_bad_args(tmp_path: Path):
    with pytest.raises(IdbError) as error:
        nexus.resolve_target(session=None, idb=str(tmp_path / "nope.exe"))

    assert error.value.code == protocol.BAD_ARGS


def _row(record_id, status, entry=None, error=None):
    return {"id": record_id, "status": status, "input_path": f"/tmp/{record_id}",
            "error": error, "_entry": entry if entry is not None else object()}


def test_single_registered_database_is_selected(monkeypatch):
    entry = object()
    monkeypatch.setattr(
        nexus, "list_databases", lambda: [_row("one", "ready", entry)]
    )

    assert nexus.resolve_target(session=None, idb=None) is entry
    assert nexus.resolve_target(session="one", idb=None) is entry


def test_no_registered_database_requires_explicit_target(monkeypatch):
    monkeypatch.setattr(nexus, "list_databases", lambda: [])

    with pytest.raises(IdbError) as error:
        nexus.resolve_target(session=None, idb=None)

    assert error.value.code == NO_SESSION
    assert "idb open" in error.value.message


def test_blocked_instances_report_not_ready_with_probe_detail(monkeypatch):
    rows = [_row("one", "blocked", error="health probe timed out")]
    monkeypatch.setattr(nexus, "list_databases", lambda: rows)

    for kwargs in ({"session": None, "idb": None}, {"session": "one", "idb": None}):
        with pytest.raises(IdbError) as error:
            nexus.resolve_target(**kwargs)
        assert error.value.code == protocol.NOT_READY
        assert "health probe timed out" in error.value.message


def test_multiple_registered_databases_are_ambiguous(monkeypatch):
    rows = [_row("one", "ready"), _row("two", "ready")]
    monkeypatch.setattr(nexus, "list_databases", lambda: rows)

    with pytest.raises(IdbError) as error:
        nexus.resolve_target(session=None, idb=None)

    assert error.value.code == AMBIGUOUS
    assert error.value.data == rows


def test_execution_result_must_contain_idb_envelope():
    envelope = protocol.build_ok({"value": 7})
    assert nexus.envelope_from_execution({"result": envelope}) == envelope

    with pytest.raises(IdbError) as error:
        nexus.envelope_from_execution({"result": None})
    assert error.value.code == protocol.INTERNAL


def test_execution_result_bytes_round_trip():
    envelope = protocol.build_ok(
        {"bytes": b"\x00\x90MZ", "rows": [{"raw": b"\xff"}]}
    )
    wire = protocol.encode_bytes(envelope)
    assert wire != envelope  # bytes were replaced by JSON-safe tags

    decoded = nexus.envelope_from_execution({"result": wire})
    assert decoded["result"]["bytes"] == b"\x00\x90MZ"
    assert decoded["result"]["rows"][0]["raw"] == b"\xff"
