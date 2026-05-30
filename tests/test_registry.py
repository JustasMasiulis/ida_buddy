import os

import pytest

from idb import registry


@pytest.fixture
def reg_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "state_dir", lambda: tmp_path)
    return tmp_path


def _entry(session_id, **over):
    base = {
        "v": registry.SCHEMA_VERSION,
        "id": session_id,
        "input_path": r"C:\bins\foo.exe",
        "idb_path": r"C:\bins\foo.i64",
        "status": registry.STATUS_READY,
        "port": 51000,
        "token": "abc123",
        "pid": os.getpid(),
        "started_at": 1.0,
    }
    base.update(over)
    return base


def test_session_id_stable_and_slugged():
    a = registry.session_id(r"C:\bins\foo.exe")
    b = registry.session_id(r"c:\bins\FOO.exe" if os.name == "nt" else r"C:\bins\foo.exe")
    assert a == b  # case-folded on Windows, identical path elsewhere
    assert a.startswith("foo.exe-")
    assert registry.session_id(r"C:\bins\bar.exe") != a


def test_candidate_keys_includes_db_siblings():
    cands = registry.candidate_keys(r"C:\bins\foo.exe")
    assert registry.normkey(r"C:\bins\foo.exe") in cands
    assert registry.normkey(r"C:\bins\foo.exe.i64") in cands
    assert registry.normkey(r"C:\bins\foo.exe.idb") in cands
    back = registry.candidate_keys(r"C:\bins\foo.exe.i64")
    assert registry.normkey(r"C:\bins\foo.exe.i64") in back
    assert registry.normkey(r"C:\bins\foo.exe") in back


def test_predicted_db_paths():
    assert registry.predicted_db_paths(r"C:\bins\foo.exe") == [
        os.path.abspath(r"C:\bins\foo.exe.i64"),
        os.path.abspath(r"C:\bins\foo.exe.idb"),
    ]
    assert registry.predicted_db_paths(r"C:\bins\foo.exe.i64") == [os.path.abspath(r"C:\bins\foo.exe.i64")]


def test_claim_is_exclusive(reg_dir):
    sid = "foo-00000000"
    assert registry.claim(_entry(sid, status=registry.STATUS_PENDING, port=None, token=None)) is True
    assert registry.claim(_entry(sid, status=registry.STATUS_PENDING)) is False
    assert registry.read(sid)["status"] == registry.STATUS_PENDING


def test_pending_to_ready_update(reg_dir):
    sid = "foo-00000000"
    registry.claim(_entry(sid, status=registry.STATUS_PENDING, port=None, token=None))
    registry.update(sid, status=registry.STATUS_READY, port=51234, token="tok")
    got = registry.read(sid)
    assert got["status"] == registry.STATUS_READY
    assert got["port"] == 51234 and got["token"] == "tok"


def test_write_read_roundtrip_and_no_temp_left(reg_dir):
    sid = "foo-00000000"
    registry.write(_entry(sid))
    assert registry.read(sid)["port"] == 51000
    leftovers = [n for n in os.listdir(reg_dir) if not n.endswith(".json")]
    assert leftovers == []


def test_read_corrupt_returns_none(reg_dir):
    (reg_dir / "bad.json").write_text("{not json")
    assert registry.read_path(reg_dir / "bad.json") is None
    assert registry.list_all() == []


def test_list_and_match(reg_dir):
    registry.write(_entry("foo-1", input_path=r"C:\bins\foo.exe", idb_path=r"C:\bins\foo.exe.i64"))
    registry.write(_entry("bar-2", input_path=r"C:\bins\bar.exe", idb_path=r"C:\bins\bar.exe.i64"))
    entries = registry.list_all()
    assert len(entries) == 2

    assert [e["id"] for e in registry.match(entries, session="bar-2")] == ["bar-2"]
    assert [e["id"] for e in registry.match(entries, idb=r"C:\bins\foo.exe")] == ["foo-1"]
    assert [e["id"] for e in registry.match(entries, idb=r"C:\bins\foo.exe.i64")] == ["foo-1"]
    assert registry.match(entries, idb=r"C:\bins\nope.exe") == []
    assert len(registry.match(entries)) == 2


def test_pid_alive_self_and_bogus():
    assert registry.pid_alive(os.getpid()) is True
    assert registry.pid_alive(0) is False
    assert registry.pid_alive(0x7FFFFFFE) is False


def test_cleanup_stale_only_dead(reg_dir, monkeypatch):
    registry.write(_entry("dead-1", pid=4242))
    registry.write(_entry("live-2", pid=4243))
    monkeypatch.setattr(registry, "pid_alive", lambda pid: pid == 4243)
    removed = registry.cleanup_stale()
    assert removed == ["dead-1"]
    assert {e["id"] for e in registry.list_all()} == {"live-2"}


def test_probe_states(reg_dir, monkeypatch):
    monkeypatch.setattr(registry, "pid_alive", lambda pid: True)
    monkeypatch.setattr(registry, "ping", lambda entry, timeout_ms=800: "ready")
    assert registry.probe(_entry("a")) == "ready"

    monkeypatch.setattr(registry, "ping", lambda entry, timeout_ms=800: None)
    assert registry.probe(_entry("a", status=registry.STATUS_ANALYZING)) == registry.STATUS_ANALYZING
    assert registry.probe(_entry("a", status=registry.STATUS_READY)) == registry.STATUS_BUSY

    monkeypatch.setattr(registry, "pid_alive", lambda pid: False)
    assert registry.probe(_entry("a", status=registry.STATUS_READY)) is None
