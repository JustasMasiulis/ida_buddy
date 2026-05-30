import argparse

import pytest

from idb import cli, registry
from idb.errors import IdbError, NO_SESSION, AMBIGUOUS


def _ns(**kw):
    base = {"session": None, "idb": None}
    base.update(kw)
    return argparse.Namespace(**base)


def _entry(sid, **over):
    e = {"id": sid, "port": 1, "token": "t", "status": "ready", "input_path": f"C:\\b\\{sid}.exe"}
    e.update(over)
    return e


def _request(argv):
    ns = cli.build_parser().parse_args(argv)
    return cli.build_request(cli.normalize_namespace(ns))


@pytest.fixture(autouse=True)
def _no_cleanup(monkeypatch):
    monkeypatch.setattr(registry, "cleanup_stale", lambda: None)


def test_resolve_zero_raises_no_session(monkeypatch):
    monkeypatch.setattr(registry, "list_all", lambda: [])
    with pytest.raises(IdbError) as ei:
        cli.resolve_session(_ns())
    assert ei.value.code == NO_SESSION


def test_resolve_single_healthy(monkeypatch):
    monkeypatch.setattr(registry, "list_all", lambda: [_entry("a")])
    monkeypatch.setattr(registry, "probe", lambda e: "ready")
    assert cli.resolve_session(_ns())["id"] == "a"


def test_resolve_many_raises_ambiguous(monkeypatch, capsys):
    monkeypatch.setattr(registry, "list_all", lambda: [_entry("a"), _entry("b")])
    monkeypatch.setattr(registry, "probe", lambda e: "ready")
    with pytest.raises(IdbError) as ei:
        cli.resolve_session(_ns())
    assert ei.value.code == AMBIGUOUS
    assert "SESSION" in capsys.readouterr().err  # table dumped to stderr


def test_resolve_by_session_id(monkeypatch):
    monkeypatch.setattr(registry, "list_all", lambda: [_entry("a"), _entry("b")])
    assert cli.resolve_session(_ns(session="b"))["id"] == "b"
    with pytest.raises(IdbError) as ei:
        cli.resolve_session(_ns(session="zzz"))
    assert ei.value.code == NO_SESSION


def test_resolve_by_idb_path(monkeypatch):
    entries = [
        _entry("a", input_path=r"C:\b\foo.exe", idb_path=r"C:\b\foo.exe.i64"),
        _entry("b", input_path=r"C:\b\bar.exe", idb_path=r"C:\b\bar.exe.i64"),
    ]
    monkeypatch.setattr(registry, "list_all", lambda: entries)
    assert cli.resolve_session(_ns(idb=r"C:\b\foo.exe"))["id"] == "a"
    assert cli.resolve_session(_ns(idb=r"C:\b\bar.exe.i64"))["id"] == "b"


def test_sessions_paginates_local_rows(monkeypatch, capsys):
    monkeypatch.setattr(registry, "list_all", lambda: [_entry("a"), _entry("b"), _entry("c")])
    monkeypatch.setattr(registry, "probe", lambda e: "ready")

    assert cli.cmd_sessions(_ns(offset=1, count=1)) == 0

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 2
    assert lines[1].split()[0] == "b"
    assert "[+more; resume with -o 2]" in captured.err


def test_disas_forwards_pagination_flags():
    assert _request(["disas", "0x401000", "-o", "8", "-n", "4"]) == (
        "disas",
        {"target": "0x401000", "offset": 8, "count": 4},
    )


def test_read_forwards_pagination_flags():
    assert _request(["read", "0x401000", "-w", "4", "-o", "8", "-n", "4"]) == (
        "read",
        {"addr": "0x401000", "width": 4, "offset": 8, "count": 4},
    )


def test_read_alias_forwards_pagination_flags_and_width():
    assert _request(["db", "0x401000", "-o", "8", "-n", "4"]) == (
        "read",
        {"addr": "0x401000", "width": 1, "offset": 8, "count": 4},
    )


def test_global_pagination_flags_work_before_command():
    assert _request(["-o", "8", "-n", "4", "db", "0x401000"]) == (
        "read",
        {"addr": "0x401000", "width": 1, "offset": 8, "count": 4},
    )


def test_command_flags_override_globals():
    assert _request(["-o", "8", "-n", "4", "disas", "0x401000", "-n", "2"]) == (
        "disas",
        {"target": "0x401000", "offset": 8, "count": 2},
    )


@pytest.mark.parametrize(
    ("argv", "expected_cmd", "expected_args"),
    [
        (["segments"], "segments", {"offset": 8, "count": 4, "total": False}),
        (["funcs"], "funcs", {"pattern": None, "offset": 8, "count": 4, "total": False}),
        (["imports"], "imports", {"pattern": None, "offset": 8, "count": 4, "total": False}),
        (["exports"], "exports", {"pattern": None, "offset": 8, "count": 4, "total": False}),
        (["strings"], "strings", {"pattern": None, "offset": 8, "count": 4, "total": False}),
        (["names", "CreateFile"], "names", {"pattern": "CreateFile", "offset": 8, "count": 4, "total": False}),
        (["disas", "0x401000"], "disas", {"target": "0x401000", "offset": 8, "count": 4}),
        (["decompile", "sub_401000"], "decompile", {"func": "sub_401000", "offset": 8, "count": 4}),
        (["read", "0x401000"], "read", {"addr": "0x401000", "width": 1, "offset": 8, "count": 4}),
        (["xref_to", "0x401000"], "xref_to", {"addr": "0x401000", "offset": 8, "count": 4}),
        (["xref_from", "0x401000"], "xref_from", {"addr": "0x401000", "offset": 8, "count": 4}),
        (["calls", "sub_401000"], "calls", {"func": "sub_401000", "offset": 8, "count": 4}),
        (
            ["search", "90"],
            "search",
            {"pattern": "90", "kind": "bytes", "offset": 8, "count": 4},
        ),
        (
            ["types", "GUID"],
            "types",
            {"pattern": "GUID", "kind": None, "offset": 8, "count": 4, "total": False},
        ),
        (["type", "GUID"], "type", {"name": "GUID", "offset": 8, "count": 4}),
        (["struct", "GUID"], "struct", {"type": "GUID", "addr": None, "offset": 8, "count": 4}),
        (
            ["member", "GUID", "8"],
            "member",
            {"type": "GUID", "offset": "8", "page_offset": 8, "count": 4},
        ),
        (["frame", "sub_401000"], "frame", {"func": "sub_401000", "offset": 8, "count": 4}),
    ],
)
def test_all_paginated_commands_forward_pagination(argv, expected_cmd, expected_args):
    cmd, args = _request(["-o", "8", "-n", "4", *argv])
    assert cmd == expected_cmd
    assert args == expected_args
