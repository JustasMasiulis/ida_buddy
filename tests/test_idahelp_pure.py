import pytest

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp


def test_parse_addr_forms():
    assert idahelp.parse_addr(0x401000) == 0x401000
    assert idahelp.parse_addr("0x401000") == 0x401000
    assert idahelp.parse_addr("0X401000") == 0x401000
    assert idahelp.parse_addr("0n4096") == 4096
    assert idahelp.parse_addr("401000") == 0x401000  # bare hex (windbg default)
    assert idahelp.parse_addr("deadbeef") == 0xDEADBEEF


@pytest.mark.parametrize("bad", ["xyz", "sub_401000", "0xZZ", ""])
def test_parse_addr_rejects(bad):
    with pytest.raises(IdbError) as ei:
        idahelp.parse_addr(bad)
    assert ei.value.code == protocol.BAD_ADDRESS


@pytest.mark.parametrize("name, ea", [
    ("sub_1400278A0", 0x1400278A0),
    ("sub_1400278a0", 0x1400278A0),
    ("loc_401037", 0x401037),
    ("byte_140003000", 0x140003000),
    ("xmmword_140005000", 0x140005000),
    ("nullsub_3", None),
    ("unknown_libname_12", None),
    ("j_sub_401000", None),
    ("sub_", None),
    ("sub_401000x", None),
    ("MyThing_1234", None),
    ("401000", None),
])
def test_dummy_name_ea(name, ea):
    assert idahelp.dummy_name_ea(name) == ea


def test_paginate_basic():
    assert idahelp.paginate(range(10), 0, 3) == ([0, 1, 2], 3)
    assert idahelp.paginate(range(10), 0, None) == (list(range(10)), None)
    assert idahelp.paginate(range(3), 0, 5) == ([0, 1, 2], None)
    assert idahelp.paginate(range(10), 8, 5) == ([8, 9], None)
    assert idahelp.paginate(range(10), 0, 10) == (list(range(10)), None)
    assert idahelp.paginate(range(11), 0, 10) == (list(range(10)), 10)
    assert idahelp.paginate(range(10), 20, 3) == ([], None)


def test_paginate_resume_cursor():
    items, nxt = idahelp.paginate(range(100), 0, 25)
    assert nxt == 25 and items[-1] == 24
    items2, nxt2 = idahelp.paginate(range(100), nxt, 25)
    assert items2[0] == 25 and nxt2 == 50


def test_name_filter_substring_glob_regex():
    assert idahelp.name_filter(None)("whatever") is True
    sub = idahelp.name_filter("foo")
    assert sub("xFOOy") and not sub("bar")
    glob = idahelp.name_filter("sub_*")
    assert glob("sub_401000") and not glob("main")
    rx = idahelp.name_filter("/^sub_[0-9a-f]+$/")
    assert rx("sub_401000") and not rx("sub_xyz")


def test_page_meta():
    assert idahelp.page_meta([1, 2, 3], None) is None
    assert idahelp.page_meta([1, 2, 3], 3) == {"shown": 3, "truncated": True, "next_offset": 3}
    assert idahelp.page_meta([1, 2, 3], None, total=10) == {"shown": 3, "total": 10}


def test_paged_envelope():
    result, meta = idahelp.paged(lambda: iter(range(10)), 0, 3)
    assert result == {"data": [0, 1, 2]}
    assert meta == {"shown": 3, "truncated": True, "next_offset": 3}


def test_paged_default_cap():
    result, meta = idahelp.paged(lambda: iter(range(5)), 0, None, default=2)
    assert result["data"] == [0, 1] and meta["next_offset"] == 2


def test_paged_total_rebuilds_generator():
    result, meta = idahelp.paged(lambda: iter(range(10)), 0, 3, total=True)
    assert result["data"] == [0, 1, 2]
    assert meta["total"] == 10 and meta["next_offset"] == 3


def test_paged_no_truncation_no_meta():
    result, meta = idahelp.paged(lambda: iter([1, 2]), 0, None)
    assert result == {"data": [1, 2]} and meta is None


def test_paged_known_qty_is_reported_without_a_second_scan():
    calls = []

    def make_gen():
        calls.append(1)
        return iter(range(5))

    result, meta = idahelp.paged(make_gen, 0, 2, total=True, qty=5)
    assert result == {"data": [0, 1]} and meta == {"shown": 2, "truncated": True, "next_offset": 2, "total": 5}
    assert len(calls) == 1  # qty short-circuits the counting pass
    result, meta = idahelp.paged(make_gen, 0, None, qty=5)
    assert result == {"data": [0, 1, 2, 3, 4]} and meta == {"shown": 5, "total": 5}


@pytest.mark.parametrize("text, hex_default, value", [
    ("10", True, 16), ("10", False, 10), ("0x10", False, 16), ("0X10", True, 16),
    ("0n10", True, 10), ("0n10", False, 10), ("ff", True, 255), ("010", False, 10), (7, False, 7),
])
def test_parse_int_prefixes_and_default_base(text, hex_default, value):
    assert idahelp.parse_int(text, hex_default) == value


@pytest.mark.parametrize("bad, hex_default", [
    ("ff", False), ("-1", True), ("1.5", False), ("0x", True), ("0n0x10", False), ("", True), ("0xzz", True),
])
def test_parse_int_rejects_bad_arguments(bad, hex_default):
    with pytest.raises(IdbError) as ei:
        idahelp.parse_int(bad, hex_default, what="thing")
    assert ei.value.code == protocol.BAD_ARGS and "thing must be" in ei.value.message


def test_declare_compact_types_adds_only_missing(monkeypatch):
    import sys
    import types as _types

    defined = {"DWORD", "BYTE"}
    declared = []

    class Tinfo:
        def get_named_type(self, til, name):
            return name in defined

    fake = _types.ModuleType("ida_typeinf")
    fake.tinfo_t = Tinfo
    fake.get_idati = lambda: "idati"
    fake.PT_SIL = 1
    fake.parse_decls = lambda til, text, cb, flags: declared.append(text) or 0
    monkeypatch.setitem(sys.modules, "ida_typeinf", fake)

    idahelp.declare_compact_types()
    assert declared == ["typedef unsigned __int16 WORD;\ntypedef unsigned __int64 QWORD;"]
    defined.update({"WORD", "QWORD"})
    idahelp.declare_compact_types()
    assert len(declared) == 1


class _Lvar:
    def __init__(self, name, is_arg, loc):
        self.name, self.is_arg_var, self.defea, self.location = name, is_arg, 0x1000, loc


def _install_fake_hexrays(monkeypatch, lvars, saved_names):
    import sys
    import types as _types

    class UserVec:
        lvvec = []

    def restore(uv, ea):
        uv.lvvec = [_types.SimpleNamespace(name=name, ll=lv)
                    for lv, name in zip(lvars, saved_names) if name]

    fake = _types.ModuleType("ida_hexrays")
    fake.init_hexrays_plugin = lambda: True
    fake.mark_cfunc_dirty = lambda ea: None
    fake.DecompilationFailure = type("DecompilationFailure", (Exception,), {})
    fake.decompile = lambda ea: _types.SimpleNamespace(get_lvars=lambda: lvars)
    fake.lvar_uservec_t = UserVec
    fake.restore_user_lvar_settings = restore
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake)


def test_hexrays_lvar_resolves_stale_default_names(monkeypatch):
    # Slot layout as Hex-Rays builds it: arguments first, slot i shown as v<i>,
    # the k-th argument as a<k>; slot 4 is an unused, never-shown local and the
    # user renamed slots 1 and 5.
    lvars = [_Lvar("a1", True, 0), _Lvar("idb_arg", True, 1), _Lvar("v2", False, 2),
             _Lvar("v3", False, 3), _Lvar("", False, 4), _Lvar("count", False, 5),
             _Lvar("v6", False, 6)]
    _install_fake_hexrays(monkeypatch, lvars, [None, "idb_arg", None, None, None, "count", None])

    def lookup(var):
        _, lv = idahelp.hexrays_lvar(0x401000, var)
        return lv.name if lv is not None else None

    assert lookup("count") == "count"  # a live name always wins
    assert lookup("v5") == "count"  # stale default name -> the renamed slot
    assert lookup("a2") == "idb_arg"
    assert lookup("v6") == "v6"
    assert lookup("v4") is None  # unused slot was never shown nor renamed
    assert lookup("v1") is None  # slot 1 is an argument, so it was never a v-name
    assert lookup("a3") is None  # only two arguments
    assert lookup("v99") is None
    assert lookup("x") is None
    assert idahelp.stale_lvar_meta("v5", lvars[5]) == {"warning": "'v5' is now named 'count'"}
    assert idahelp.stale_lvar_meta("count", lvars[5]) is None


def test_safe_decompile_reports_hexrays_failure_reason(monkeypatch):
    import sys
    import types as _types

    class Failure:
        code = 0
        errea = -1

        def desc(self):
            return "function frame is wrong"

    def decompile(ea, hf, flags):
        hf.code, hf.errea = -13, ea  # IDA 9 returns None and fills hf instead of raising
        return None

    fake = _types.ModuleType("ida_hexrays")
    fake.hexrays_failure_t = Failure
    fake.DecompilationFailure = type("DecompilationFailure", (Exception,), {})
    fake.mark_cfunc_dirty = lambda ea: None
    fake.decompile = decompile
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake)
    monkeypatch.setitem(sys.modules, "ida_idaapi", _types.SimpleNamespace(BADADDR=-1))

    with pytest.raises(IdbError) as ei:
        idahelp.safe_decompile(0x140146F68)
    assert ei.value.code == protocol.IDA_ERROR
    assert ei.value.message == "decompilation failed at 0x140146f68: function frame is wrong (hexrays code -13)"
