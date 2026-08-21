import argparse
from types import SimpleNamespace

import pytest

from idb import cli, protocol
from idb.errors import IdbError


def _ns(**kw):
    base = {
        "session": None,
        "idb": None,
        "timeout": None,
        "offset": 0,
        "count": None,
    }
    base.update(kw)
    return argparse.Namespace(**base)


def _request(argv):
    ns = cli.build_parser().parse_args(argv)
    return cli.build_request(cli.normalize_namespace(ns))


def test_resolve_session_delegates_to_nexus(monkeypatch):
    monkeypatch.setattr(
        cli.nexus,
        "resolve_target",
        lambda *, session, idb: f"{session or idb or 'auto'}",
    )
    assert cli.resolve_session(_ns(session="record")) == "record"
    assert cli.resolve_session(_ns(idb="sample.exe")) == "sample.exe"
    assert cli.resolve_session(_ns()) == "auto"


def test_sessions_paginates_discovered_rows(monkeypatch, capsys):
    rows = [
        {
            "id": name,
            "status": "ready",
            "pid": index,
            "port": index + 10,
            "input_path": f"/{name}",
            "_entry": object(),
        }
        for index, name in enumerate(("a", "b", "c"))
    ]
    monkeypatch.setattr(cli.nexus, "list_databases", lambda: rows)

    assert cli.cmd_sessions(_ns(offset=1, count=1)) == 0

    captured = capsys.readouterr()
    assert captured.out.splitlines()[1].split()[0] == "b"
    assert "[+more; resume with -o 2]" in captured.err


class FakeHandle:
    instance = SimpleNamespace(
        record_id="123-abcdef", backend="gui", port=123, pid=456
    )

    def __init__(self, envelope):
        self.envelope = envelope
        self.closed = False
        self.waited = False
        self.shutdowns = []

    def wait_autoanalysis(self, timeout):
        self.waited = True
        return {"status": "complete", "complete": True}

    def poll_autoanalysis(self):
        return {"status": "complete", "complete": True}

    def shutdown_database(self, *, save):
        self.shutdowns.append(save)
        return {"shutting_down": True, "save": save}

    def execute_python(self, code, timeout):
        return {"result": self.envelope, "stdout": "", "stderr": ""}

    def save_database(self):
        return {"saved": True, "idb_path": "/tmp/sample.i64"}

    def close(self):
        self.closed = True


def test_run_remote_uses_and_releases_one_database_handle(monkeypatch, capsys):
    handle = FakeHandle(protocol.build_ok({"data": []}))
    handle.instance = SimpleNamespace(record_id="1-w", backend="idalib", port=1, pid=2)
    monkeypatch.setattr(cli, "resolve_session", lambda ns: "/tmp/sample")
    monkeypatch.setattr(cli.nexus, "open_handle", lambda *a, **kw: handle)

    assert cli.run_remote(_ns(), "names", {}) == 0

    assert handle.waited and handle.closed
    assert "(no names)" in capsys.readouterr().out


def test_run_remote_never_waits_on_gui_analysis(monkeypatch, capsys):
    # A GUI instance belongs to the analyst: the CLI must not block on (and
    # thereby force-enable) its auto-analysis; the remote dispatcher answers
    # NOT_READY instead.
    handle = FakeHandle(protocol.build_ok({"data": []}))
    monkeypatch.setattr(cli, "resolve_session", lambda ns: "/tmp/sample")
    monkeypatch.setattr(cli.nexus, "open_handle", lambda *a, **kw: handle)

    assert cli.run_remote(_ns(), "names", {}) == 0

    assert not handle.waited and handle.closed


def test_save_uses_official_database_handle(monkeypatch, capsys):
    handle = FakeHandle(protocol.build_ok({}))
    monkeypatch.setattr(cli, "resolve_session", lambda ns: "/tmp/sample")
    monkeypatch.setattr(cli.nexus, "open_handle", lambda *a, **kw: handle)

    assert cli.run_remote(_ns(), "save", {}) == 0

    assert handle.closed
    assert "saved sample.i64" in capsys.readouterr().out


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


def test_help_alias_prints_root_help(capsys):
    assert cli.main(["help"]) == 0
    assert "usage: idb" in capsys.readouterr().out


def test_help_alias_with_command_prints_command_help(capsys):
    assert cli.main(["help", "save"]) == 0
    assert "idb save" in capsys.readouterr().out


def test_help_is_not_a_registered_subcommand():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["help"])


def test_close_shuts_down_and_discards(monkeypatch, capsys):
    entry = SimpleNamespace(record_id="9-w", backend="idalib", port=1, pid=2)
    handle = FakeHandle(protocol.build_ok({}))
    handle.instance = entry
    monkeypatch.setattr(cli, "resolve_session", lambda ns: entry)
    monkeypatch.setattr(cli.nexus, "open_handle", lambda *a, **kw: handle)

    ns = cli.build_parser().parse_args(["close", "--no-save"])
    cli.normalize_namespace(ns)
    assert cli.cmd_close(ns) == 0

    assert handle.shutdowns == [False] and handle.closed
    assert "changes discarded" in capsys.readouterr().err


def test_close_refuses_gui_instances(monkeypatch):
    entry = SimpleNamespace(record_id="9-g", backend="gui", port=1, pid=2)
    monkeypatch.setattr(cli, "resolve_session", lambda ns: entry)

    ns = cli.build_parser().parse_args(["close"])
    cli.normalize_namespace(ns)
    with pytest.raises(IdbError) as error:
        cli.cmd_close(ns)
    assert error.value.code == protocol.BAD_ARGS


def test_emit_renders_struct_redirect_and_warns_on_stderr(capsys):
    result = {"addr": 0x2000, "wide": False, "length": 3, "maxlen": 4,
              "buffer": 0x3000, "text": "abc", "redirected_to_struct": True}
    reply = protocol.build_ok(result, {"warning": "0x2000 is typed ANSI_STRING; use `ds`"})
    assert cli.emit("string", reply, _ns()) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == '2000  ANSI_STRING len=3 max=4 buf=3000  "abc"'
    assert "idb: warning: 0x2000 is typed ANSI_STRING; use `ds`" in captured.err
