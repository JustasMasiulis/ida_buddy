from pathlib import Path

import pytest

from idb import codemode, protocol
from idb.errors import AMBIGUOUS, NO_SESSION, IdbError


def test_execute_code_uses_official_runtime_db_and_encoded_arguments():
    code = codemode.execute_code("names", {"pattern": "x'\nraise Nope"})

    assert "_idb_execute(db, **_idb_request)" in code
    assert "raise Nope" not in code
    assert "from idb.worker.remote import execute" in code


def test_explicit_idb_resolves_without_a_registered_instance(tmp_path: Path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"binary")

    assert codemode.resolve_target(session=None, idb=str(target)) == str(
        target.resolve()
    )


def test_single_registered_database_is_selected(monkeypatch):
    monkeypatch.setattr(
        codemode,
        "list_databases",
        lambda: [{"id": "one", "status": "ready", "input_path": "/tmp/a"}],
    )

    assert codemode.resolve_target(session=None, idb=None) == "/tmp/a"
    assert codemode.resolve_target(session="one", idb=None) == "/tmp/a"


def test_no_registered_database_requires_explicit_target(monkeypatch):
    monkeypatch.setattr(codemode, "list_databases", lambda: [])

    with pytest.raises(IdbError) as error:
        codemode.resolve_target(session=None, idb=None)

    assert error.value.code == NO_SESSION
    assert "--idb" in error.value.message


def test_multiple_registered_databases_are_ambiguous(monkeypatch):
    rows = [
        {"id": "one", "status": "ready", "input_path": "/tmp/a"},
        {"id": "two", "status": "ready", "input_path": "/tmp/b"},
    ]
    monkeypatch.setattr(codemode, "list_databases", lambda: rows)

    with pytest.raises(IdbError) as error:
        codemode.resolve_target(session=None, idb=None)

    assert error.value.code == AMBIGUOUS
    assert error.value.data == rows


def test_execution_result_must_contain_idb_envelope():
    envelope = protocol.build_ok(0, {"value": 7})
    assert codemode.envelope_from_execution({"result": envelope}) is envelope

    with pytest.raises(IdbError) as error:
        codemode.envelope_from_execution({"result": None})
    assert error.value.code == protocol.INTERNAL
