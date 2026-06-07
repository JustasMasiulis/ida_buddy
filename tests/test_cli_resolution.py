import argparse

import pytest

from idb import cli, protocol, registry
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
        (["xrefs", "0x401000"], "xrefs", {"addr": "0x401000", "direction": "to", "offset": 8, "count": 4}),
        (["xref_to", "0x401000"], "xrefs", {"addr": "0x401000", "direction": "to", "offset": 8, "count": 4}),
        (["xref_from", "0x401000"], "xrefs", {"addr": "0x401000", "direction": "from", "offset": 8, "count": 4}),
        (["xrefs", "0x401000", "-d", "both"], "xrefs", {"addr": "0x401000", "direction": "both", "offset": 8, "count": 4}),
        (["calls", "sub_401000"], "calls", {"func": "sub_401000", "depth": 1, "offset": 8, "count": 4}),
        (["calls", "sub_401000", "--depth", "3"], "calls", {"func": "sub_401000", "depth": 3, "offset": 8, "count": 4}),
        (["strrefs", "lic"], "strrefs", {"pattern": "lic", "offset": 8, "count": 4}),
        (["dps", "0x401000"], "pointers", {"addr": "0x401000", "offset": 8, "count": 4}),
        (["dqs", "0x401000"], "pointers", {"addr": "0x401000", "offset": 8, "count": 4}),
        (["uf", "sub_401000"], "disas", {"target": "sub_401000", "offset": 8, "count": 4, "whole": True}),
        (
            ["search", "90"],
            "search",
            {"pattern": "90", "kind": "bytes", "offset": 8, "count": 4},
        ),
        (["s", "90"], "search", {"pattern": "90", "kind": "bytes", "offset": 8, "count": 4}),
        (
            ["types", "GUID"],
            "types",
            {"pattern": "GUID", "kind": None, "size": None, "offset": 8, "count": 4, "total": False},
        ),
        (
            ["types"],
            "types",
            {"pattern": None, "kind": None, "size": None, "offset": 8, "count": 4, "total": False},
        ),
        (
            ["type", "-e"],
            "types",
            {"pattern": None, "kind": None, "size": None, "offset": 8, "count": 4, "total": False},
        ),
        (
            ["type", "-k", "struct"],
            "types",
            {"pattern": None, "kind": "struct", "size": None, "offset": 8, "count": 4, "total": False},
        ),
        (
            ["type", "--size", "0x10"],
            "types",
            {"pattern": None, "kind": None, "size": "0x10", "offset": 8, "count": 4, "total": False},
        ),
        (
            ["type", "IMAGE_*"],
            "types",
            {"pattern": "IMAGE_*", "kind": None, "size": None, "offset": 8, "count": 4, "total": False},
        ),
        (
            ["type", "/^IMAGE/"],
            "types",
            {"pattern": "/^IMAGE/", "kind": None, "size": None, "offset": 8, "count": 4, "total": False},
        ),
        (["type", "GUID"], "type", {"name": "GUID", "addr": None, "offset": 8, "count": 4}),
        (["dt", "GUID"], "type", {"name": "GUID", "addr": None, "offset": 8, "count": 4}),
        (["type", "GUID", "0x1000"], "type", {"name": "GUID", "addr": "0x1000", "offset": 8, "count": 4}),
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


def test_type_pattern_with_addr_is_rejected():
    with pytest.raises(IdbError) as ei:
        _request(["type", "IMAGE_*", "0x1000"])
    assert ei.value.code == protocol.BAD_ARGS


def test_force_utf8_reconfigures_stream():
    captured = {}

    class Stream:
        def reconfigure(self, **kwargs):
            captured.update(kwargs)

    cli._force_utf8(Stream())
    assert captured["encoding"] == "utf-8"


def test_force_utf8_tolerates_stream_without_reconfigure():
    cli._force_utf8(object())


def test_string_struct_aliases_carry_width():
    assert _request(["ds", "0x401000"]) == ("string_struct", {"addr": "0x401000", "wide": False})
    assert _request(["dS", "0x401000"]) == ("string_struct", {"addr": "0x401000", "wide": True})


def test_setlvar_resolution():
    assert _request(["setlvar", "main", "v0", "--name", "x", "--type", "int"]) == (
        "setlvar",
        {"func": "main", "var": "v0", "name": "x", "type": "int"},
    )
    assert _request(["setlvar", "main", "v0", "--name", "x"]) == (
        "setlvar",
        {"func": "main", "var": "v0", "name": "x", "type": None},
    )


def test_set_member_resolution():
    assert _request(["set_member", "Foo", "a", "int", "count"]) == (
        "set_member",
        {"type": "Foo", "member": "a", "new_type": "int", "new_name": "count"},
    )
    assert _request(["set_member", "Foo", "0x4", "int"]) == (
        "set_member",
        {"type": "Foo", "member": "0x4", "new_type": "int", "new_name": None},
    )


def test_insert_member_resolution():
    assert _request(["insert_member", "Foo", "int", "count", "--after", "a"]) == (
        "insert_member",
        {"type": "Foo", "new_type": "int", "name": "count", "before": None, "after": "a"},
    )
    assert _request(["insert_member", "Foo", "int", "count", "--before", "c"]) == (
        "insert_member",
        {"type": "Foo", "new_type": "int", "name": "count", "before": "c", "after": None},
    )
    assert _request(["insert_member", "Foo", "void *", "ctx"]) == (
        "insert_member",
        {"type": "Foo", "new_type": "void *", "name": "ctx", "before": None, "after": None},
    )


def test_del_member_resolution():
    assert _request(["del_member", "Foo", "b"]) == (
        "del_member",
        {"type": "Foo", "member": "b", "leave_gap": False},
    )
    assert _request(["del_member", "Foo", "0x8", "--leave-gap"]) == (
        "del_member",
        {"type": "Foo", "member": "0x8", "leave_gap": True},
    )


def test_setmember_is_no_longer_a_command():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["setmember", "Foo", "a", "int"])


def test_bare_disas_carries_no_whole_flag():
    assert _request(["u", "sub_401000"]) == ("disas", {"target": "sub_401000", "offset": 0, "count": None})
    assert _request(["uf", "sub_401000"]) == (
        "disas",
        {"target": "sub_401000", "offset": 0, "count": None, "whole": True},
    )


def test_op_resolution():
    assert _request(["op", "0x401234", "char"]) == ("op", {"addr": "0x401234", "fmt": "char", "opnum": None})
    assert _request(["op", "0x401234", "enum:Foo", "1"]) == (
        "op",
        {"addr": "0x401234", "fmt": "enum:Foo", "opnum": 1},
    )


def test_triage_resolution_is_unpaginated():
    assert _request(["triage", "sub_401000"]) == ("triage", {"func": "sub_401000"})
    # triage is a fixed composite; pagination flags must not leak into the request
    assert _request(["-o", "8", "-n", "4", "triage", "sub_401000"]) == (
        "triage",
        {"func": "sub_401000"},
    )


def test_eval_question_alias_joins_expr():
    assert _request(["?", "main", "+", "0x10"]) == ("eval", {"expr": "main + 0x10", "width": None})


def test_eval_width_flag():
    assert _request(["eval", "0n42", "-w", "4"]) == ("eval", {"expr": "0n42", "width": 4})


def _close_ns(argv):
    return cli.normalize_namespace(cli.build_parser().parse_args(argv))


def test_close_positional_sets_session(monkeypatch):
    captured = {}

    def fake_resolve(ns):
        captured["session"] = ns.session
        return {"id": ns.session, "port": 1, "token": "t", "pid": 1}

    monkeypatch.setattr(cli, "resolve_session", fake_resolve)
    monkeypatch.setattr(cli, "_close_one", lambda *a, **k: "closed")
    assert cli.cmd_close(_close_ns(["close", "myid"])) == 0
    assert captured["session"] == "myid"


def test_close_matching_s_and_positional_is_allowed(monkeypatch):
    captured = {}

    def fake_resolve(ns):
        captured["session"] = ns.session
        return {"id": ns.session, "port": 1, "token": "t", "pid": 1}

    monkeypatch.setattr(cli, "resolve_session", fake_resolve)
    monkeypatch.setattr(cli, "_close_one", lambda *a, **k: "closed")
    assert cli.cmd_close(_close_ns(["-s", "dup", "close", "dup"])) == 0
    assert captured["session"] == "dup"


def test_close_mismatched_s_and_positional_rejected():
    with pytest.raises(IdbError) as ei:
        cli.cmd_close(_close_ns(["-s", "a", "close", "b"]))
    assert ei.value.code == protocol.BAD_ARGS


def test_close_positional_with_all_rejected():
    with pytest.raises(IdbError) as ei:
        cli.cmd_close(_close_ns(["close", "--all", "x"]))
    assert ei.value.code == protocol.BAD_ARGS


def test_close_kill_reports_failure(monkeypatch):
    entry = {"id": "dead", "port": 1, "token": "t", "pid": 1234}
    unregistered = []
    monkeypatch.setattr(cli.spawn, "kill_pid", lambda pid: False)
    monkeypatch.setattr(registry, "unregister", unregistered.append)

    with pytest.raises(IdbError) as ei:
        cli._close_one(entry, kill=True, save=True)

    assert ei.value.code == protocol.IDA_ERROR
    assert unregistered == []


def test_close_kill_unregisters_after_success(monkeypatch):
    entry = {"id": "dead", "port": 1, "token": "t", "pid": 1234}
    unregistered = []
    monkeypatch.setattr(cli.spawn, "kill_pid", lambda pid: True)
    monkeypatch.setattr(registry, "unregister", unregistered.append)

    assert cli._close_one(entry, kill=True, save=True) == "killed dead (pid 1234)"
    assert unregistered == ["dead"]


def test_help_alias_prints_root_help(capsys):
    assert cli.main(["help"]) == 0
    assert "usage: idb" in capsys.readouterr().out


def test_help_alias_with_command_prints_command_help(capsys):
    assert cli.main(["help", "close"]) == 0
    assert "idb close" in capsys.readouterr().out


def test_help_is_not_a_registered_subcommand():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["help"])


def test_emit_renders_struct_redirect_and_warns_on_stderr(capsys):
    result = {"addr": 0x2000, "wide": False, "length": 3, "maxlen": 4,
              "buffer": 0x3000, "text": "abc", "redirected_to_struct": True}
    reply = protocol.build_ok(1, result, {"warning": "0x2000 is typed ANSI_STRING; use `ds`"})
    assert cli.emit("string", reply, _ns()) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == '2000  ANSI_STRING len=3 max=4 buf=3000  "abc"'
    assert "idb: warning: 0x2000 is typed ANSI_STRING; use `ds`" in captured.err
