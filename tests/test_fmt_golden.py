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
    assert lines[1].split() == [".text", "1000", "2000", "1000", "r-x", "CODE"]
    assert lines[2].split() == [".data", "2000", "3000", "1000", "rw-", "DATA"]


def test_listing_tables_use_bare_hex():
    result = {"data": [{"ea": 0x140001300, "size": 0x42, "name": "wmainCRTStartup"}]}
    out = listing.format_funcs(result)
    assert "0x" not in out
    assert out.splitlines()[1].split() == ["140001300", "42", "wmainCRTStartup"]


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


def test_type_dispatches_to_typeof_shape():
    # `dt <address>` returns a typeof-shape result; format_type must delegate.
    out = fmt_types.format_type({"target": "sub_401000", "ea": 0x401000,
                                 "kind": "function", "type": "void __fastcall()", "size": 0})
    assert out == "sub_401000 : void __fastcall()  (function, 0x0 bytes)"


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


def test_pointers_format():
    out = fmt_memory.format_pointers({"addr": 0x1000, "width": 8, "data": [
        {"ea": 0x1000, "value": 0x140001300, "sym": "wmain", "off": 0},
        {"ea": 0x1008, "value": 0x140001350, "sym": "wmain", "off": 0x50},
        {"ea": 0x1010, "value": 0x5, "sym": None, "off": 0},
    ]})
    lines = out.splitlines()
    assert lines[0] == "000000001000  0000000140001300  wmain"
    assert lines[1] == "000000001008  0000000140001350  wmain+0x50"
    assert lines[2] == "000000001010  0000000000000005"
    assert fmt_memory.format_pointers({"addr": 0x1000, "width": 8, "data": []}) == "(no pointers)"


def test_string_struct_format():
    wide = {"addr": 0x2000, "wide": True, "length": 8, "maxlen": 10, "buffer": 0x3000, "text": "kernel32"}
    assert fmt_memory.format_string_struct(wide) == '0x2000  UNICODE_STRING len=8 max=10 buf=0x3000  "kernel32"'
    ansi = {"addr": 0x2000, "wide": False, "length": 3, "maxlen": 4, "buffer": 0x3000, "text": "abc"}
    assert fmt_memory.format_string_struct(ansi) == '0x2000  ANSI_STRING len=3 max=4 buf=0x3000  "abc"'


def test_xrefs_direction_column():
    both = {"data": [
        {"ea": 0x401204, "kind": "call", "func": "f", "insn": "call sub_401300", "dir": "to"},
        {"ea": 0x401300, "kind": "read", "func": "f", "insn": "mov eax, ds:x", "dir": "from"},
    ]}
    lines = fmt_xrefs.format_xrefs(both).splitlines()
    assert lines[0].startswith("to  ") and "401204" in lines[0]
    assert lines[1].startswith("from") and "401300" in lines[1]


def test_calls_depth_indent():
    out = fmt_xrefs.format_calls({"func": "f", "ea": 0x401000, "depth": 2, "callers": [
        {"ea": 0x401100, "func": "g", "insn": "call f", "depth": 1},
        {"ea": 0x401200, "func": "h", "insn": "call g", "depth": 2},
    ], "callees": [{"ea": 0x402000, "name": "puts"}]})
    lines = out.splitlines()
    depth1 = next(l for l in lines if "0x401100" in l)
    depth2 = next(l for l in lines if "0x401200" in l)
    assert (len(depth2) - len(depth2.lstrip())) > (len(depth1) - len(depth1.lstrip()))


def test_strrefs_format():
    out = fmt_xrefs.format_strrefs({"pattern": "lic", "data": [
        {"ea": 0x401500, "kind": "offset", "func": "check",
         "insn": "lea rax, aLicense", "str_ea": 0x9000, "str": "license expired"},
    ]})
    assert "401500" in out and "in check" in out and '"license expired"' in out
    assert fmt_xrefs.format_strrefs({"pattern": "zzz", "data": []}) == "(no refs to strings matching 'zzz')"


def test_type_value_overlay_format():
    result = {"name": "GUID", "kind": "struct", "size": 16, "is_union": False, "addr": 0x6000,
              "members": [{"name": "Data1", "offset": 0, "size": 4, "type": "unsigned int",
                           "bitfield": False, "value": 0xDEADBEEF}]}
    out = fmt_types.format_type(result)
    assert "@ 0x6000" in out and "VALUE" in out and "0xdeadbeef" in out


def test_setlvar_format():
    assert fmt_writes.format_setlvar({"target": "main:counter", "kind": "lvar",
                                      "name": "counter", "type": "int"}) == "main:counter : int"


def test_op_format():
    assert fmt_writes.format_op({"ea": 0x401234, "repr": "char", "opnum": None,
                                 "disasm": True, "pseudocode": True}) == "op @ 0x401234 -> char (disasm+pseudo)"
    assert fmt_writes.format_op({"ea": 0x401234, "repr": "enum:Foo", "opnum": 1,
                                 "disasm": True, "pseudocode": False}) == "op @ 0x401234 op1 -> enum:Foo (disasm)"
