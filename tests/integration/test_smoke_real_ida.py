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


def test_uf_whole_function(client):
    result, _ = ok(client, "disas", {"target": hex(_entry_ea(client)), "whole": True})
    assert result["mode"] == "func"
    assert result["func"]["name"]
    assert result["lines"] and all("ea" in ln and ln["text"] for ln in result["lines"])


def test_bare_disas_is_a_window(client):
    result, _ = ok(client, "disas", {"target": hex(_entry_ea(client))})
    assert result["mode"] == "raw"
    assert result["lines"]


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


def test_pointers_dump(client):
    ea = _entry_ea(client)
    result, _ = ok(client, "pointers", {"addr": hex(ea), "count": 4})
    assert result["width"] in (4, 8)
    assert result["data"] and all("ea" in r and "value" in r for r in result["data"])


def test_string_struct_runs(client):
    # The entry bytes are not a real counted string; this only asserts the handler
    # executes its IDA calls and returns a well-formed envelope.
    result, _ = ok(client, "string_struct", {"addr": hex(_entry_ea(client)), "wide": True})
    assert {"addr", "wide", "length", "maxlen", "buffer", "text"} <= set(result)
    assert result["wide"] is True


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


def test_string_on_non_defined_address(client):
    # Regression: auto-detect `string` on an address that is not a defined string head
    # used to crash with INTERNAL (get_str_type returns the 0xFFFFFFFF sentinel, which
    # overflows get_strlit_contents' int32 strtype). It must now fall back to a C read,
    # yielding either a string or a clean NOT_FOUND — never INTERNAL.
    strs, _ = ok(client, "strings", {"count": 20})
    target = next((s for s in strs["data"] if len(s["text"]) >= 4), None)
    if target is None:
        pytest.skip("no usable string")
    for addr in (target["ea"] + 1, _entry_ea(client)):
        reply = client.call("string", {"addr": hex(addr)})
        assert protocol.is_ok(reply) or reply["error"]["code"] != protocol.INTERNAL, reply


def test_nearest_in_function(client):
    result, _ = ok(client, "nearest", {"addr": hex(_entry_ea(client))})
    assert result["func"] is not None


def test_xrefs_returns_context(client):
    result, _ = ok(client, "xrefs", {"addr": hex(_entry_ea(client))})
    assert isinstance(result["data"], list)
    for row in result["data"]:
        assert {"ea", "kind", "insn"} <= set(row)


def test_xrefs_both_tags_direction(client):
    result, _ = ok(client, "xrefs", {"addr": hex(_entry_ea(client)), "direction": "both"})
    assert isinstance(result["data"], list)
    assert all(r.get("dir") in ("to", "from") for r in result["data"])


def test_calls_structure(client):
    result, _ = ok(client, "calls", {"func": hex(_entry_ea(client))})
    assert isinstance(result["callers"], list) and isinstance(result["callees"], list)


def test_calls_depth_expands_callers(client):
    ea = hex(_entry_ea(client))
    d1, _ = ok(client, "calls", {"func": ea, "depth": 1})
    d2, _ = ok(client, "calls", {"func": ea, "depth": 2})
    assert d2["depth"] == 2
    assert len(d2["callers"]) >= len(d1["callers"])
    assert all(c.get("depth", 1) >= 1 for c in d2["callers"])


def test_strrefs_runs(client):
    strs, _ = ok(client, "strings", {"count": 40})
    target = next((s for s in strs["data"] if len(s["text"]) >= 4 and s["text"][:8].isprintable()), None)
    if target is None:
        pytest.skip("no usable string")
    result, _ = ok(client, "strrefs", {"pattern": target["text"][:6], "count": 50})
    assert isinstance(result["data"], list)
    for row in result["data"]:
        assert {"ea", "kind", "insn", "str_ea"} <= set(row)


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


def test_type_value_overlay(client):
    structs, _ = ok(client, "types", {"kind": "struct", "count": 50})
    if not structs["data"]:
        pytest.skip("no structs with type info")
    name = structs["data"][0]["name"]
    typ, _ = ok(client, "type", {"name": name, "addr": hex(_entry_ea(client))})
    assert typ.get("addr") is not None
    assert all("value" in m for m in typ.get("members", []))


def test_typeof_function(client):
    result, _ = ok(client, "typeof", {"target": hex(_entry_ea(client))})
    assert result["type"]


def test_type_on_address_dispatches_to_typeof(client):
    # `dt <address>` (a non-type-name argument) routes to the typeof path.
    result, _ = ok(client, "type", {"name": hex(_entry_ea(client))})
    assert result.get("target") is not None
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


def _mapped_data_ea(client):
    """A mapped address in a non-executable segment (falls back to the entry EA)."""
    segs, _ = ok(client, "segments", {})
    for s in segs["data"]:
        if "x" not in s["perm"] and protocol.is_ok(
                client.call("read", {"addr": hex(s["start"]), "width": 1, "count": 1})):
            return s["start"]
    return _entry_ea(client)


def test_da_du_redirect_on_counted_string_type(client):
    # da/du over a *_STRING fail the literal read (the small Length/MaximumLength
    # header bytes are not a valid NUL-terminated string), so the worker recovers by
    # detecting the applied type and serving the ds/dS view with a warning. Two structs
    # differing only in Buffer width exercise both arms; wide-ness is derived from that
    # width, not the name. The header bytes below are rejected by IDA's string heuristic.
    ok(client, "declare", {"text": "struct IT_UNI_STRING { unsigned __int16 Length; "
                                    "unsigned __int16 MaximumLength; unsigned __int16 *Buffer; };"})
    ok(client, "declare", {"text": "struct IT_ANSI_STRING { unsigned __int16 Length; "
                                    "unsigned __int16 MaximumLength; char *Buffer; };"})
    ea = _mapped_data_ea(client)
    patched = client.call("patch", {"addr": hex(ea), "hex": "08 00 0a 00 00 00 00 00 00 00 00 00 00 00 00 00"})
    if not protocol.is_ok(patched):
        pytest.skip(f"could not patch scratch bytes at {ea:#x}: {patched}")
    for type_name, wide, enc in (("IT_UNI_STRING", True, "utf16"), ("IT_ANSI_STRING", False, "ascii")):
        applied = client.call("settype", {"target": hex(ea), "type": type_name})
        if not protocol.is_ok(applied):
            pytest.skip(f"could not apply {type_name} at {ea:#x}: {applied}")
        result, meta = ok(client, "string", {"addr": hex(ea), "encoding": enc})
        assert result.get("redirected_to_struct") is True
        assert result["wide"] is wide
        assert {"length", "maxlen", "buffer", "text"} <= set(result)
        assert meta and "counted-string" in (meta.get("warning") or "")


def test_da_du_fallback_to_memory_view(client):
    # No string literal and not a counted-string struct: windbg-style, da/du still dump
    # bytes rather than erroring. Header bytes that fail IDA's string heuristic + a plain
    # int type guarantee both the literal read and the *_STRING probe come up empty.
    ea = _mapped_data_ea(client)
    patched = client.call("patch", {"addr": hex(ea), "hex": "08 00 0a 00 00 00 00 00 00 00 00 00 00 00 00 00"})
    typed = client.call("settype", {"target": hex(ea), "type": "int"})
    if not (protocol.is_ok(patched) and protocol.is_ok(typed)):
        pytest.skip(f"could not stage scratch bytes/type at {ea:#x}")
    for enc in ("ascii", "utf16"):
        result, meta = ok(client, "string", {"addr": hex(ea), "encoding": enc})
        assert result.get("raw_fallback") is True
        assert result["encoding"] == enc
        assert isinstance(result["bytes"], (bytes, bytearray)) and len(result["bytes"]) > 0
        assert meta and "showing" in (meta.get("warning") or "")


def _members_by_off(client, name):
    typ, _ = ok(client, "type", {"name": name})
    return {m["offset"]: (m["name"], m["type"]) for m in typ["members"]}


def test_declare_then_set_member(client):
    ok(client, "declare", {"text": "struct IDB_IT { int a; char b; };"})
    typ, _ = ok(client, "type", {"name": "IDB_IT"})
    assert any(m["name"] == "a" for m in typ["members"])
    ok(client, "set_member", {"type": "IDB_IT", "member": "a", "new_type": "unsigned int", "new_name": "aa"})
    typ2, _ = ok(client, "type", {"name": "IDB_IT"})
    assert any(m["name"] == "aa" and m["type"] == "unsigned int" for m in typ2["members"])


def test_set_member_pure_rename_type_unchanged(client):
    # Regression: renaming a member WITHOUT changing its type used to silently no-op
    # (rename_udm returns TERR_OK but persists nothing unless a real set_udm_type change
    # rides along). Mirrors the exact reported repro, including the typedef indirection.
    ok(client, "declare", {"text": "typedef struct _SM_REPRO { void *old_name; } SM_REPRO;"})
    res, _ = ok(client, "set_member",
                {"type": "SM_REPRO", "member": "old_name", "new_type": "void *", "new_name": "new_name"})
    assert res["name"] == "new_name"
    typ, _ = ok(client, "type", {"name": "SM_REPRO"})
    names = [m["name"] for m in typ["members"]]
    assert "new_name" in names and "old_name" not in names
    # the alias must remain a typedef onto its struct, not be clobbered into one
    assert typ["kind"] in ("struct", "union")


def test_set_member_rename_by_offset(client):
    ok(client, "declare", {"text": "struct SM_OFF { void *first; int second; };"})
    ok(client, "set_member",
       {"type": "SM_OFF", "member": "0x0", "new_type": "void *", "new_name": "renamed_first"})
    typ, _ = ok(client, "type", {"name": "SM_OFF"})
    by_off = {m["offset"]: m["name"] for m in typ["members"]}
    assert by_off[0] == "renamed_first"
    assert any(m["name"] == "second" for m in typ["members"])


def test_insert_member_after_shifts_following(client):
    ok(client, "declare", {"text": "struct INS_AFT { int a; int c; };"})
    res, _ = ok(client, "insert_member",
                {"type": "INS_AFT", "new_type": "int", "name": "b", "before": None, "after": "a"})
    assert res["offset"] == 4
    by_off = _members_by_off(client, "INS_AFT")
    assert by_off[0][0] == "a" and by_off[4][0] == "b" and by_off[8][0] == "c"


def test_insert_member_before_shifts_following(client):
    ok(client, "declare", {"text": "struct INS_BEF { int a; int c; };"})
    ok(client, "insert_member",
       {"type": "INS_BEF", "new_type": "int", "name": "head", "before": "a", "after": None})
    by_off = _members_by_off(client, "INS_BEF")
    assert by_off[0][0] == "head" and by_off[4][0] == "a" and by_off[8][0] == "c"


def test_insert_member_append_by_default(client):
    ok(client, "declare", {"text": "struct INS_APP { int a; };"})
    res, _ = ok(client, "insert_member",
                {"type": "INS_APP", "new_type": "int", "name": "tail", "before": None, "after": None})
    assert res["offset"] == 4
    by_off = _members_by_off(client, "INS_APP")
    assert by_off[4][0] == "tail"


def test_insert_member_append_aligns_pointer(client):
    # A non-fixed (declared) struct repacks by natural C alignment, so an 8-byte pointer
    # after a single int lands at offset 8 (4 bytes of padding), and the returned offset
    # reflects the real post-rebuild placement.
    ok(client, "declare", {"text": "struct INS_PTR { int a; };"})
    res, _ = ok(client, "insert_member",
                {"type": "INS_PTR", "new_type": "void *", "name": "p", "before": None, "after": None})
    assert res["offset"] == 8


def test_del_member_closes_gap(client):
    ok(client, "declare", {"text": "struct DEL_CL { int a; int b; int c; };"})
    ok(client, "del_member", {"type": "DEL_CL", "member": "b", "leave_gap": False})
    by_off = _members_by_off(client, "DEL_CL")
    assert by_off[0][0] == "a" and by_off[4][0] == "c"
    assert all(name != "b" for name, _ in by_off.values())


def test_del_member_leave_gap_keeps_offsets(client):
    ok(client, "declare", {"text": "struct DEL_GAP { int a; int b; int c; };"})
    ok(client, "del_member", {"type": "DEL_GAP", "member": "b", "leave_gap": True})
    by_off = _members_by_off(client, "DEL_GAP")
    assert by_off[0][0] == "a" and by_off[8][0] == "c"
    assert 4 not in by_off


def test_insert_then_del_roundtrips(client):
    ok(client, "declare", {"text": "struct RT_ID { int a; int c; };"})
    ok(client, "insert_member",
       {"type": "RT_ID", "new_type": "int", "name": "b", "before": None, "after": "a"})
    ok(client, "del_member", {"type": "RT_ID", "member": "b", "leave_gap": False})
    by_off = _members_by_off(client, "RT_ID")
    assert by_off[0][0] == "a" and by_off[4][0] == "c" and 8 not in by_off


def test_insert_and_del_member_on_union(client):
    ok(client, "declare", {"text": "union UN_ID { int i; char c; };"})
    ok(client, "insert_member",
       {"type": "UN_ID", "new_type": "void *", "name": "p", "before": None, "after": "i"})
    typ, _ = ok(client, "type", {"name": "UN_ID"})
    assert all(m["offset"] == 0 for m in typ["members"])
    assert any(m["name"] == "p" for m in typ["members"])
    ok(client, "del_member", {"type": "UN_ID", "member": "c", "leave_gap": False})
    typ2, _ = ok(client, "type", {"name": "UN_ID"})
    names = [m["name"] for m in typ2["members"]]
    assert "c" not in names and "p" in names and "i" in names


def test_set_member_consumes_following_members(client):
    # A 16-byte UNICODE_STRING laid over three scalar/pointer fields swallows the two that
    # fall inside its footprint; the field starting exactly at the footprint end survives.
    ok(client, "declare", {"text":
        "struct _US16 { unsigned short Length; unsigned short MaximumLength; wchar_t *Buffer; };"})
    ok(client, "declare", {"text": "struct HASUS { int f0; int f4; void *f8; int f16; };"})
    res, _ = ok(client, "set_member",
                {"type": "HASUS", "member": "f0", "new_type": "_US16", "new_name": "name"})
    assert res["consumed"] == ["f4", "f8"]
    by_off = _members_by_off(client, "HASUS")
    assert by_off[0][0] == "name" and "_US16" in by_off[0][1]
    assert by_off[16][0] == "f16"
    names = {n for n, _ in by_off.values()}
    assert "f4" not in names and "f8" not in names


def test_set_member_partial_consume_keeps_aligned_survivors(client):
    ok(client, "declare", {"text": "struct CONS { int a; int b; int c; int d; };"})
    res, _ = ok(client, "set_member", {"type": "CONS", "member": "a", "new_type": "__int64"})
    assert res["consumed"] == ["b"]
    by_off = _members_by_off(client, "CONS")
    assert by_off[0][0] == "a" and by_off[8][0] == "c" and by_off[12][0] == "d"


def test_set_member_smaller_type_consumes_nothing(client):
    ok(client, "declare", {"text": "struct SHRINK { void *p; int tail; };"})
    res, _ = ok(client, "set_member", {"type": "SHRINK", "member": "p", "new_type": "int"})
    assert res["consumed"] == []
    by_off = _members_by_off(client, "SHRINK")
    assert by_off[0][0] == "p" and any(n == "tail" for n, _ in by_off.values())


def test_set_member_over_leave_gap_absorbs_hole(client):
    # del --leave-gap pins the struct fixed with a hole at [4,8); a set_member whose new
    # type spans that hole absorbs it without disturbing the field at the footprint end.
    ok(client, "declare", {"text": "struct GAPSET { int a; int b; int c; };"})
    ok(client, "del_member", {"type": "GAPSET", "member": "b", "leave_gap": True})
    res, _ = ok(client, "set_member", {"type": "GAPSET", "member": "a", "new_type": "__int64"})
    assert res["consumed"] == []
    by_off = _members_by_off(client, "GAPSET")
    assert by_off[0][0] == "a" and "__int64" in by_off[0][1]
    assert by_off[8][0] == "c"


def test_set_member_misaligned_type_repacks(client):
    # An 8-byte type assigned to a 4-aligned field of a non-fixed struct gets bumped to the
    # next aligned slot by create_udt; the field it overlapped is still consumed.
    ok(client, "declare", {"text": "struct ALN { char pad; int target; int after; };"})
    res, _ = ok(client, "set_member", {"type": "ALN", "member": "target", "new_type": "__int64"})
    assert res["consumed"] == ["after"]
    by_off = _members_by_off(client, "ALN")
    names = {n for n, _ in by_off.values()}
    assert "target" in names and "after" not in names
    target_off = next(off for off, (n, _) in by_off.items() if n == "target")
    assert target_off % 8 == 0


def test_grow_a_fixed_struct_after_leave_gap(client):
    # del --leave-gap pins the struct fixed with a stale total_size; a later insert or a
    # set_member that grows past the old end must bump total_size or create_udt rejects it.
    ok(client, "declare", {"text": "struct GROWFIX { int a; int b; int c; int d; };"})
    ok(client, "del_member", {"type": "GROWFIX", "member": "b", "leave_gap": True})
    ok(client, "insert_member",
       {"type": "GROWFIX", "new_type": "void *", "name": "ins", "before": None, "after": "d"})
    by_off = _members_by_off(client, "GROWFIX")
    assert by_off[16][0] == "ins"
    ok(client, "set_member", {"type": "GROWFIX", "member": "a", "new_type": "char[32]"})
    by_off2 = _members_by_off(client, "GROWFIX")
    assert by_off2[0][0] == "a" and "char[32]" in by_off2[0][1]


def test_set_member_at_gap_offset_is_not_found(client):
    ok(client, "declare", {"text": "struct GAPREF { int a; int b; int c; };"})
    ok(client, "del_member", {"type": "GAPREF", "member": "b", "leave_gap": True})
    reply = client.call("set_member",
                        {"type": "GAPREF", "member": "0x4", "new_type": "int"}, timeout_ms=20000)
    assert not protocol.is_ok(reply)
    assert reply["error"]["code"] == protocol.NOT_FOUND


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


def test_setlvar_rename_and_retype(client):
    if not _has_hexrays(client):
        pytest.skip("no Hex-Rays")
    import re

    funcs, _ = ok(client, "funcs", {"count": 40})
    chosen = None
    for f in funcs["data"]:
        dec = client.call("decompile", {"func": hex(f["ea"])}, timeout_ms=60000)
        if not protocol.is_ok(dec):
            continue
        for line in dec["result"]["lines"]:
            m = re.match(r"\s+[\w ]+?\b([A-Za-z_]\w*);\s*//", line)
            if m:
                chosen = (f["ea"], m.group(1))
                break
        if chosen:
            break
    if not chosen:
        pytest.skip("no function with a local variable found")
    func_hex = hex(chosen[0])
    res, _ = ok(client, "setlvar", {"func": func_hex, "var": chosen[1], "name": "idb_lv", "type": "int"})
    assert res["kind"] == "lvar"
    assert res["name"] == "idb_lv"
    assert "int" in res["type"]
    readback, _ = ok(client, "typeof", {"target": f"{func_hex}:idb_lv"})
    assert "int" in readback["type"]
    ok(client, "undo")


# --- `op` operand-representation tests run LAST on the shared worker: applying an
# operand format forces a re-decompile of the touched function, which can destabilize
# Hex-Rays lvar-name persistence for the local-variable tests above. The op change
# itself is cleanly undoable (verified at the disassembly level); this is only about
# not perturbing earlier tests that share the one analyzed database.

def _find_imm_instruction(client):
    import re

    funcs, _ = ok(client, "funcs", {"count": 80})
    for f in funcs["data"]:
        dis, _ = ok(client, "disas", {"target": hex(f["ea"]), "whole": True})
        for ln in dis["lines"]:
            if re.search(r",\s*[0-9A-Fa-f]+h\b", ln["text"]):
                return ln["ea"]
    return None


def test_op_char_and_undo(client):
    ea = _find_imm_instruction(client)
    if ea is None:
        pytest.skip("no instruction with an immediate operand found")
    res, _ = ok(client, "op", {"addr": hex(ea), "fmt": "char"})
    assert res["disasm"] is True and res["repr"] == "char"
    assert isinstance(res["pseudocode"], bool)
    ok(client, "undo")


def test_op_enum_apply_and_undo(client):
    ea = _find_imm_instruction(client)
    if ea is None:
        pytest.skip("no instruction with an immediate operand found")
    ok(client, "enum", {"name": "IDB_OP_E", "members": "A=1,B=2", "bitfield": False})
    res, _ = ok(client, "op", {"addr": hex(ea), "fmt": "enum:IDB_OP_E"})
    assert res["repr"] == "enum:IDB_OP_E" and res["disasm"] is True
    ok(client, "undo")


def test_op_errors(client):
    bad_addr = client.call("op", {"addr": "0x1", "fmt": "hex"})
    assert not protocol.is_ok(bad_addr) and bad_addr["error"]["code"] == protocol.BAD_ADDRESS
    bad_fmt = client.call("op", {"addr": hex(_entry_ea(client)), "fmt": "bogus"})
    assert not protocol.is_ok(bad_fmt) and bad_fmt["error"]["code"] == protocol.BAD_ARGS
    no_enum = client.call("op", {"addr": hex(_entry_ea(client)), "fmt": "enum:__no_such_enum__"})
    assert not protocol.is_ok(no_enum) and no_enum["error"]["code"] == protocol.NOT_FOUND


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
