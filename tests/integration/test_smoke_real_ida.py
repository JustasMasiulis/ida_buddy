"""Tier-4 smoke tests against a real headless IDA worker.

Gated on idapro being importable and a test binary existing (IDB_TEST_BINARY, or
the bundled tests/fixtures/where.exe). One warm worker is shared across the module
in an isolated registry; each phase appends cases here.
"""

import importlib.util
import os
import shutil
import tempfile
import time

import pytest

from idb import protocol, spawn
from idb.transport import ZmqClient

BINARY = os.environ.get(
    "IDB_TEST_BINARY",
    os.path.join(os.path.dirname(__file__), "..", "fixtures", "where.exe"),
)
_AVAILABLE = importlib.util.find_spec("idapro") is not None and os.path.exists(BINARY)
pytestmark = pytest.mark.skipif(not _AVAILABLE, reason="needs idapro + a test binary")


@pytest.fixture(scope="module")
def client():
    tmp = tempfile.mkdtemp(prefix="idb-it-")
    saved = {k: os.environ.get(k) for k in ("LOCALAPPDATA", "XDG_STATE_HOME")}
    os.environ["LOCALAPPDATA"] = tmp
    os.environ["XDG_STATE_HOME"] = tmp
    entry = None
    try:
        entry, summary = spawn.open_or_reuse(BINARY, deadline_s=300)
        conn = ZmqClient(entry["port"], entry["token"])
        conn.summary = summary
        conn.entry = entry
        yield conn
        conn.close()
    finally:
        if entry is not None:
            killer = ZmqClient(entry["port"], entry["token"])
            try:
                killer.call("shutdown", {"save": False}, timeout_ms=15000)
            except Exception:
                spawn.kill_pid(entry.get("pid"))
            finally:
                killer.close()
            time.sleep(0.5)
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(tmp, ignore_errors=True)


def ok(conn, cmd, args=None, timeout_ms=20000):
    reply = conn.call(cmd, args or {}, timeout_ms=timeout_ms)
    assert protocol.is_ok(reply), reply
    return reply["result"], reply.get("meta")


def test_ping_ready(client):
    result, _ = ok(client, "ping")
    assert result["status"] == "ready"


def test_segments(client):
    result, meta = ok(client, "segments", {"count": 3})
    rows = result["data"]
    assert rows and any(r["perm"] == "r-x" for r in rows)
    assert meta and meta["truncated"] and meta["next_offset"] == 3


def test_save(client):
    result, _ = ok(client, "save", timeout_ms=60000)
    assert os.path.exists(result["saved"])


def _entry_ea(client):
    eps = client.summary.get("entry_points") or []
    if not eps:
        pytest.skip("binary has no entry points")
    return eps[0]["ea"]


def test_disas_function(client):
    result, _ = ok(client, "disas", {"target": hex(_entry_ea(client))})
    assert result["mode"] == "func"
    assert result["func"]["name"]
    assert result["lines"] and all("ea" in ln and ln["text"] for ln in result["lines"])


def test_disas_raw_count_paginates(client):
    result, meta = ok(client, "disas", {"target": hex(_entry_ea(client)), "count": 4})
    assert result["mode"] == "raw"
    assert len(result["lines"]) == 4
    assert meta and meta["truncated"] and meta["next_offset"] == 4


def test_decompile_or_graceful(client):
    reply = client.call("decompile", {"func": hex(_entry_ea(client))}, timeout_ms=60000)
    if protocol.is_ok(reply):
        assert reply["result"]["lines"]
    else:
        assert reply["error"]["code"] == protocol.IDA_ERROR  # no Hex-Rays license


def test_read_bytes_and_clamp(client):
    ea = _entry_ea(client)
    result, _ = ok(client, "read", {"addr": hex(ea), "width": 1, "count": 32})
    assert isinstance(result["bytes"], bytes) and 0 < result["count"] <= 32


def test_read_values(client):
    ea = _entry_ea(client)
    result, _ = ok(client, "read", {"addr": hex(ea), "width": 4, "count": 4})
    assert result["values"] and all(isinstance(v, int) for v in result["values"])


def test_read_unmapped_is_bad_address(client):
    reply = client.call("read", {"addr": "0x1", "width": 1, "count": 8})
    assert not protocol.is_ok(reply) and reply["error"]["code"] == protocol.BAD_ADDRESS


def test_funcs_and_filter(client):
    result, _ = ok(client, "funcs", {"count": 10})
    assert result["data"] and all("name" in r and "ea" in r for r in result["data"])


def test_total_meta(client):
    result, meta = ok(client, "funcs", {"count": 2, "total": True})
    assert len(result["data"]) == 2
    assert meta and meta.get("total") and meta["total"] >= 2


def test_names_nonempty(client):
    result, _ = ok(client, "names", {"count": 10})
    assert result["data"]


def test_strings_nonempty(client):
    result, _ = ok(client, "strings", {"count": 10})
    assert result["data"] and all("text" in r for r in result["data"])


def test_nearest_in_function(client):
    result, _ = ok(client, "nearest", {"addr": hex(_entry_ea(client))})
    assert result["func"] is not None


def test_xref_to_returns_context(client):
    result, _ = ok(client, "xref_to", {"addr": hex(_entry_ea(client))})
    assert isinstance(result["data"], list)
    for row in result["data"]:
        assert {"ea", "kind", "insn"} <= set(row)


def test_calls_structure(client):
    result, _ = ok(client, "calls", {"func": hex(_entry_ea(client))})
    assert isinstance(result["callers"], list) and isinstance(result["callees"], list)


def test_search_bytes_finds_self(client):
    ea = _entry_ea(client)
    data, _ = ok(client, "read", {"addr": hex(ea), "width": 1, "count": 6})
    pattern = " ".join(f"{b:02x}" for b in data["bytes"])
    result, _ = ok(client, "search", {"pattern": pattern, "kind": "bytes", "count": 100})
    assert any(r["ea"] == ea for r in result["data"])


def test_search_str_finds_known(client):
    strs, _ = ok(client, "strings", {"count": 40})
    # an ASCII string has byte-length ~= char-length (wide strings are 2x); only
    # those are findable by an ASCII (single-byte) str search.
    ascii_str = next(
        (s for s in strs["data"]
         if len(s["text"]) >= 4 and s["length"] <= len(s["text"]) + 2 and s["text"][:8].isprintable()),
        None,
    )
    if ascii_str is None:
        pytest.skip("no ASCII string to search for")
    result, _ = ok(client, "search", {"pattern": ascii_str["text"][:8], "kind": "str", "count": 50})
    assert result["data"]


def test_string_and_search_str_handle_utf16(client):
    strs, _ = ok(client, "strings", {"count": 80})
    wide_str = next(
        (s for s in strs["data"]
         if s["text"] and s["length"] >= 2 * (len(s["text"]) + 1) and s["text"][:8].isprintable()),
        None,
    )
    if wide_str is None:
        pytest.skip("no UTF-16 string literal found")

    text, _ = ok(client, "string", {"addr": hex(wide_str["ea"])})
    assert text["encoding"] == "utf16"
    assert text["text"] == wide_str["text"]
    assert text["length"] == wide_str["length"]
    assert text["length"] > len(text["text"])

    result, _ = ok(client, "search", {"pattern": wide_str["text"][:8], "kind": "str", "count": 100})
    assert any(r["ea"] == wide_str["ea"] for r in result["data"])


def test_search_str_utf16_substring_has_no_shifted_hit(client):
    strs, _ = ok(client, "strings", {"count": 80})
    wide_str = next(
        (s for s in strs["data"]
         if len(s["text"]) >= 5 and s["length"] >= 2 * (len(s["text"]) + 1) and s["text"][:8].isprintable()),
        None,
    )
    if wide_str is None:
        pytest.skip("no UTF-16 string literal found")

    pattern = wide_str["text"][1:5]
    result, _ = ok(client, "search", {"pattern": pattern, "kind": "str", "count": 100})
    hits = sorted(r["ea"] for r in result["data"])
    expected = wide_str["ea"] + 2
    assert expected in hits
    assert expected - 1 not in hits
    assert not any(b == a + 1 for a, b in zip(hits, hits[1:]))


def test_types_list(client):
    result, _ = ok(client, "types", {"count": 50})
    assert result["data"] and all("name" in r and "kind" in r for r in result["data"])


def test_type_struct_and_member(client):
    structs, _ = ok(client, "types", {"kind": "struct", "count": 50})
    if not structs["data"]:
        pytest.skip("no structs with type info")
    name = structs["data"][0]["name"]
    typ, _ = ok(client, "type", {"name": name})
    assert typ["kind"] in ("struct", "union")
    if typ.get("members"):
        m, _ = ok(client, "member", {"type": name, "offset": "0"})
        assert m["paths"] and all("path" in p and "type" in p for p in m["paths"])


def test_typeof_function(client):
    result, _ = ok(client, "typeof", {"target": hex(_entry_ea(client))})
    assert result["type"]


def test_frame_or_graceful(client):
    reply = client.call("frame", {"func": hex(_entry_ea(client))}, timeout_ms=20000)
    if protocol.is_ok(reply):
        assert "members" in reply["result"]
    else:
        assert reply["error"]["code"] == protocol.IDA_ERROR


def test_rename_then_undo_restores(client):
    ea = _entry_ea(client)
    before, _ = ok(client, "nearest", {"addr": hex(ea)})
    original = before["func"]["name"] if before.get("func") else before["symbol"]["name"]
    ok(client, "rename", {"addr": hex(ea), "name": "idb_it_renamed"})
    after, _ = ok(client, "nearest", {"addr": hex(ea)})
    assert "idb_it_renamed" in (after.get("func") or after.get("symbol"))["name"]
    ok(client, "undo")
    restored, _ = ok(client, "nearest", {"addr": hex(ea)})
    assert (restored.get("func") or restored.get("symbol"))["name"] == original


def test_patch_then_undo_restores(client):
    ea = _entry_ea(client)
    before, _ = ok(client, "read", {"addr": hex(ea), "width": 1, "count": 2})
    ok(client, "patch", {"addr": hex(ea), "hex": "90 90"})
    patched, _ = ok(client, "read", {"addr": hex(ea), "width": 1, "count": 2})
    assert patched["bytes"] == b"\x90\x90"
    ok(client, "undo")
    restored, _ = ok(client, "read", {"addr": hex(ea), "width": 1, "count": 2})
    assert restored["bytes"] == before["bytes"]


def test_declare_then_setmember(client):
    ok(client, "declare", {"text": "struct IDB_IT { int a; char b; };"})
    typ, _ = ok(client, "type", {"name": "IDB_IT"})
    assert any(m["name"] == "a" for m in typ["members"])
    ok(client, "setmember", {"type": "IDB_IT", "member": "a", "new_type": "unsigned int", "new_name": "aa"})
    typ2, _ = ok(client, "type", {"name": "IDB_IT"})
    assert any(m["name"] == "aa" and m["type"] == "unsigned int" for m in typ2["members"])


def test_enum_create(client):
    ok(client, "enum", {"name": "IDB_ENUM", "members": "X=1,Y=2,Z=7", "bitfield": False})
    typ, _ = ok(client, "type", {"name": "IDB_ENUM"})
    assert {m["name"]: m["value"] for m in typ["members"]} == {"X": 1, "Y": 2, "Z": 7}


def _member_values(typ):
    return {m["name"]: m["value"] for m in typ["members"]}


def test_enum_create_unsigned_high_value(client):
    created, _ = ok(client, "enum", {"name": "IDB_ENUM_HIGH", "members": "HI=0x9c402000", "bitfield": False})
    assert created["name"] == "IDB_ENUM_HIGH"
    assert created["extended"] is False
    assert created["bitfield"] is False
    assert _member_values(created) == {"HI": 0x9C402000}

    typ, _ = ok(client, "type", {"name": "IDB_ENUM_HIGH"})
    assert typ["kind"] == "enum"
    assert typ["size"] == 4
    assert _member_values(typ) == {"HI": 0x9C402000}
    assert _member_values(typ)["HI"] != 0xFFFFFFFF9C402000


def test_type_masks_declared_enum_sign_extension(client):
    ok(client, "declare", {"text": "enum IDB_DECL_HIGH { IDB_DECL_HI = 0x9c402000 };"})
    typ, _ = ok(client, "type", {"name": "IDB_DECL_HIGH"})
    assert typ["kind"] == "enum"
    assert typ["size"] == 4
    assert _member_values(typ) == {"IDB_DECL_HI": 0x9C402000}
    assert _member_values(typ)["IDB_DECL_HI"] != 0xFFFFFFFF9C402000


def test_union_select_live_negative(client):
    if not _has_hexrays(client):
        pytest.skip("no Hex-Rays")
    reply = client.call("union_select", {"addr": hex(_entry_ea(client)), "member": "__no_such_arm__"})
    assert not protocol.is_ok(reply), reply
    err = reply["error"]
    assert err["code"] in (protocol.NOT_FOUND, protocol.IDA_ERROR)
    assert "deferred" not in err["message"]


def test_union_select_roundtrip(client):
    if not _has_hexrays(client):
        pytest.skip("no Hex-Rays")
    addr, arm = os.environ.get("IDB_UNION_ADDR"), os.environ.get("IDB_UNION_MEMBER")
    if not (addr and arm):
        pytest.skip("set IDB_UNION_ADDR + IDB_UNION_MEMBER to a known union usage site")
    res, _ = ok(client, "union_select", {"addr": addr, "member": arm})
    assert res["member"] == arm or str(res["ordinal"]) == arm
    assert res["verified"], res
    ok(client, "undo")


def _has_hexrays(client):
    return protocol.is_ok(client.call("decompile", {"func": hex(_entry_ea(client))}, timeout_ms=60000))


def test_pseudocode_comment(client):
    if not _has_hexrays(client):
        pytest.skip("no Hex-Rays")
    dis, _ = ok(client, "disas", {"target": hex(_entry_ea(client))})
    text = "IDB_PSEUDO_CMT"
    anchored = False
    for ln in dis["lines"][:20]:
        res, _ = ok(client, "comment", {"addr": hex(ln["ea"]), "text": text})
        assert res["disasm"] is True
        if res["pseudocode"]:
            anchored = True
            dec = client.call("decompile", {"func": hex(_entry_ea(client))}, timeout_ms=60000)
            assert text in "\n".join(dec["result"]["lines"])
            break
    assert anchored, "no statement address anchored a pseudocode comment"


def test_settype_local_lvar(client):
    if not _has_hexrays(client):
        pytest.skip("no Hex-Rays")
    import re

    funcs, _ = ok(client, "funcs", {"count": 40})
    chosen = None
    for f in funcs["data"]:
        dec = client.call("decompile", {"func": hex(f["ea"])}, timeout_ms=60000)
        if not protocol.is_ok(dec):
            continue
        for line in dec["result"]["lines"]:  # local decl: "  int v0; // eax"
            m = re.match(r"\s+[\w ]+?\b([A-Za-z_]\w*);\s*//", line)
            if m:
                chosen = (f["ea"], m.group(1))
                break
        if chosen:
            break
    if not chosen:
        pytest.skip("no function with a local variable found")
    target = f"{hex(chosen[0])}:{chosen[1]}"
    ok(client, "settype", {"target": target, "type": "char"})
    res, _ = ok(client, "typeof", {"target": target})
    assert "char" in res["type"]


def test_settype_function_prototype(client):
    ea = _entry_ea(client)
    result, _ = ok(
        client,
        "settype",
        {"target": hex(ea), "type": "int __fastcall(int idb_argc_unique, char **idb_argv_unique)"},
    )
    assert result["ea"] == ea
    assert "int" in result["type"]
    assert "idb_argc_unique" in result["type"] and "idb_argv_unique" in result["type"]
    readback, _ = ok(client, "typeof", {"target": hex(ea)})
    assert "idb_argc_unique" in readback["type"] and "idb_argv_unique" in readback["type"]
    ok(client, "undo")


def test_enum_create_and_extend(client):
    created, _ = ok(client, "enum", {"name": "IDB_EXT", "members": "A=1,B=2", "bitfield": False})
    assert created["extended"] is False
    assert _member_values(created) == {"A": 1, "B": 2}

    after_create, _ = ok(client, "type", {"name": "IDB_EXT"})
    assert _member_values(after_create) == {"A": 1, "B": 2}

    extended, _ = ok(client, "enum", {"name": "IDB_EXT", "members": "C=9"})
    assert extended["extended"] is True
    assert _member_values(extended) == {"C": 9}

    typ, _ = ok(client, "type", {"name": "IDB_EXT"})
    assert _member_values(typ) == {"A": 1, "B": 2, "C": 9}


def test_enum_extend_unsigned_high_value(client):
    created, _ = ok(client, "enum", {"name": "IDB_EXT_HIGH", "members": "A=1", "bitfield": False})
    assert created["extended"] is False
    assert _member_values(created) == {"A": 1}

    after_create, _ = ok(client, "type", {"name": "IDB_EXT_HIGH"})
    assert after_create["kind"] == "enum"
    assert after_create["size"] == 4
    assert _member_values(after_create) == {"A": 1}

    extended, _ = ok(client, "enum", {"name": "IDB_EXT_HIGH", "members": "HI_EXT=0x9c402000"})
    assert extended["extended"] is True
    assert _member_values(extended) == {"HI_EXT": 0x9C402000}

    typ, _ = ok(client, "type", {"name": "IDB_EXT_HIGH"})
    assert typ["kind"] == "enum"
    assert typ["size"] == 4
    assert _member_values(typ) == {"A": 1, "HI_EXT": 0x9C402000}
    assert _member_values(typ)["HI_EXT"] != 0xFFFFFFFF9C402000
