from idb.fmt import listing
from idb.fmt import memory as fmt_memory
from idb.fmt import sessions as fmt_sessions
from idb.fmt import xrefs as fmt_xrefs
from idb.fmt import types as fmt_types
from idb.fmt import writes as fmt_writes
from idb.fmt.columns import align

_SUMMARY = {
    "input": "where.exe", "format": "Portable executable for AMD64 (PE)",
    "arch": "metapc", "bitness": 64, "endian": "little", "base": 0x140000000,
    "min_ea": 0x140001000, "max_ea": 0x14000E000, "size": 0xD000,
    "md5": "8066fe09b1f19ba7752896c2fd68b04c", "sha256": "f51f",
    "num_functions": 103, "num_globals": 186, "num_segments": 7,
    "entry_points": [{"ea": 0x140001300, "name": "wmainCRTStartup"}],
}


def test_align_exact():
    out = align([("a", "bb"), ("ccc", "d")], headers=("H1", "H2"))
    assert out == "H1   H2\na    bb\nccc  d"


def test_align_right_alignment():
    out = align([("x", "1"), ("yy", "1000")], aligns=("<", ">"))
    line1, line2 = out.splitlines()
    assert line1 == "x      1"
    assert line2 == "yy  1000"


def test_open_summary_lines():
    out = listing.format_open_summary(_SUMMARY)
    lines = out.splitlines()
    assert lines[0] == "where.exe   Portable executable for AMD64 (PE)"
    assert "arch     metapc 64-bit little-endian" in out
    assert "base     0x140000000   size 0xd000 (53248 bytes)" in out
    assert "md5      8066fe09b1f19ba7752896c2fd68b04c" in out
    assert "segments 7   functions 103   named globals 186" in out
    assert "wmainCRTStartup@0x140001300" in out


def test_segments_table():
    result = {"data": [
        {"name": ".text", "start": 0x1000, "end": 0x2000, "size": 0x1000, "perm": "r-x", "class": "CODE"},
        {"name": ".data", "start": 0x2000, "end": 0x3000, "size": 0x1000, "perm": "rw-", "class": "DATA"},
    ]}
    out = listing.format_segments(result)
    lines = out.splitlines()
    assert lines[0].split() == ["NAME", "START", "END", "SIZE", "PERM", "CLASS"]
    assert lines[1].split() == [".text", "0x1000", "0x2000", "0x1000", "r-x", "CODE"]
    assert lines[2].split() == [".data", "0x2000", "0x3000", "0x1000", "rw-", "DATA"]


def test_sessions_table():
    rows = [{"id": "s1", "status": "ready", "pid": 100, "port": 5000, "input_path": r"C:\b\x.exe"}]
    out = fmt_sessions.format_sessions(rows)
    lines = out.splitlines()
    assert lines[0].split() == ["SESSION", "STATUS", "PID", "PORT", "INPUT"]
    assert lines[1].split() == ["s1", "ready", "100", "5000", r"C:\b\x.exe"]
    assert fmt_sessions.format_sessions([]) == "(no sessions)"


def test_doctor_table():
    rows = [("python", "OK", "3.13"), ("idapro", "MISSING", "install it")]
    out = fmt_sessions.format_doctor(rows)
    assert out.splitlines()[0].split() == ["CHECK", "STATUS", "DETAIL"]
    assert "idapro" in out and "MISSING" in out


def test_hexdump_layout():
    out = fmt_memory.format_read({"addr": 0x401000, "width": 1, "bytes": bytes(range(16))})
    line = out.splitlines()[0]
    assert line.startswith("000000401000  ")
    assert "00 01 02 03 04 05 06 07-08 09 0a 0b 0c 0d 0e 0f" in line
    assert line.endswith("................")


def test_values_layout():
    out = fmt_memory.format_read({"addr": 0x401000, "width": 4, "values": [1, 2, 3, 4]})
    assert "00000001 00000002 00000003 00000004" in out


def test_string_layout():
    out = fmt_memory.format_string({"addr": 0x401000, "encoding": "ascii", "length": 3, "text": "abc"})
    assert out == '0x401000  ascii 3 bytes  "abc"'


def test_nearest_layout():
    out = listing.format_nearest({"addr": 0x401010, "symbol": {"name": "f", "ea": 0x401000, "offset": 0x10},
                                  "func": {"name": "f", "ea": 0x401000, "offset": 0x10}})
    assert "0x401010" in out and "f+0x10" in out and "(in f+0x10)" in out


def test_xrefs_format():
    result = {"data": [{"ea": 0x401204, "kind": "call", "func": "validate_key",
                        "insn": "call sub_401300"}]}
    out = fmt_xrefs.format_xrefs(result)
    assert out == "401204  call    call sub_401300   ; in validate_key"


def test_calls_format():
    result = {"func": "f", "ea": 0x401000,
              "callers": [{"ea": 0x401100, "func": "g", "insn": "call f"}],
              "callees": [{"ea": 0x402000, "name": "h"}]}
    out = fmt_xrefs.format_calls(result)
    assert "callers (1)" in out and "callees (1)" in out
    assert "call f" in out and "h" in out


def test_type_members_format():
    result = {"name": "GUID", "kind": "struct", "size": 16, "is_union": False,
              "members": [{"name": "Data1", "offset": 0, "size": 4, "type": "unsigned int", "bitfield": False}]}
    out = fmt_types.format_type(result)
    assert "struct GUID" in out and "Data1" in out and "unsigned int" in out


def test_member_paths_format():
    result = {"type": "GUID", "offset": 8,
              "paths": [{"path": "Data4[0]", "type": "unsigned __int8", "size": 1}]}
    out = fmt_types.format_member(result)
    assert "Data4[0] : unsigned __int8" in out and "size 0x1" in out


def test_typeof_format():
    out = fmt_types.format_typeof({"target": "g", "type": "int", "kind": "scalar", "size": 4})
    assert out == "g : int  (scalar, 0x4 bytes)"


def test_write_formats():
    assert fmt_writes.format_rename({"ea": 0x401000, "name": "f", "kind": "name"}) == "renamed 0x401000 -> f"
    assert fmt_writes.format_rename({"target": "g:v", "name": "x", "kind": "lvar"}) == "renamed local g:v -> x"
    assert fmt_writes.format_patch({"ea": 0x401000, "count": 2, "bytes": b"\x90\x90"}) == "patched 2 bytes @ 0x401000: 9090"
    assert fmt_writes.format_enum({"name": "E", "members": [{"name": "A", "value": 1}]}) == "enum E: A=1"
    assert fmt_writes.format_undo({"undone": True, "label": "patch"}) == "undone: patch"
    assert fmt_writes.format_settype({"ea": 0x401000, "type": "int *"}) == "0x401000 : int *"
    us = {"ea": 0x401000, "union": "U", "member": "u1", "ordinal": 1, "verified": True}
    assert fmt_writes.format_union_select(us) == "union @ 0x401000: U -> .u1 (arm 1)"
    assert fmt_writes.format_union_select({**us, "verified": False}) == "union @ 0x401000: U -> .u1 (arm 1) (unverified)"


def test_comment_and_extend_formats():
    both = {"ea": 0x401000, "comment": "x", "disasm": True, "pseudocode": True}
    assert fmt_writes.format_comment(both) == "comment @ 0x401000 (disasm+pseudo): x"
    dis_only = {"ea": 0x401000, "comment": "x", "disasm": True, "pseudocode": False}
    assert fmt_writes.format_comment(dis_only) == "comment @ 0x401000 (disasm): x"
    extended = {"name": "E", "extended": True, "members": [{"name": "C", "value": 9}]}
    assert fmt_writes.format_enum(extended) == "enum E extended: C=9"
    assert fmt_writes.format_settype({"target": "f:v", "type": "char"}) == "f:v : char"


def test_generic_renders_bytes_as_hex():
    out = listing.format_generic({"blob": b"\xde\xad", "n": 1})
    assert "dead" in out and '"n": 1' in out
