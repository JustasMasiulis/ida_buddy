import importlib
import sys
import types

import pytest

from idb.worker import dispatch


def _module(name, **attrs):
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    return mod


@pytest.fixture
def fake_ida_modules(monkeypatch):
    monkeypatch.setitem(sys.modules, "ida_idaapi", _module("ida_idaapi", BADADDR=-1))
    monkeypatch.setitem(sys.modules, "ida_xref", _module(
        "ida_xref",
        dr_O=1, dr_W=2, dr_R=3, dr_T=4, dr_I=5,
        fl_CF=10, fl_CN=11, fl_JF=12, fl_JN=13, fl_F=14,
    ))
    monkeypatch.setitem(sys.modules, "ida_bytes", _module(
        "ida_bytes",
        BIN_SEARCH_FORWARD=1, BIN_SEARCH_NOSHOW=2,
        next_head=lambda ea, max_ea: -1,
        get_item_size=lambda ea: 1,
        find_bytes=lambda *a, **k: -1,
        find_string=lambda *a, **k: -1,
    ))
    monkeypatch.setitem(sys.modules, "ida_ida", _module(
        "ida_ida", inf_get_max_ea=lambda: 0xFFFFFFFF, inf_get_min_ea=lambda: 0,
    ))
    monkeypatch.setitem(sys.modules, "ida_lines", _module(
        "ida_lines",
        tag_remove=lambda text: text,
        generate_disasm_line=lambda ea, flags=0: "call target",
    ))
    monkeypatch.setitem(sys.modules, "ida_funcs", _module(
        "ida_funcs",
        get_func=lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 1, flags=0),
        get_func_name=lambda ea: f"sub_{ea:x}",
        FUNC_THUNK=0x1,
    ))
    monkeypatch.setitem(sys.modules, "ida_segment", _module(
        "ida_segment", getseg=lambda ea: None, get_segm_name=lambda seg: "?",
    ))
    monkeypatch.setitem(sys.modules, "ida_name", _module("ida_name", get_name=lambda ea: ""))
    monkeypatch.setitem(sys.modules, "ida_search", _module("ida_search", find_imm=lambda *a, **k: -1, SEARCH_DOWN=1))
    monkeypatch.setitem(sys.modules, "idautils", _module(
        "idautils",
        FuncItems=lambda ea: (),
        XrefsTo=lambda ea: (),
        XrefsFrom=lambda ea: (),
        DataRefsTo=lambda ea: (),
        CodeRefsTo=lambda ea, flow: (),
    ))

    loaded = []

    def load(name):
        full = f"idb.worker.handlers.{name}"
        sys.modules.pop(full, None)
        mod = importlib.import_module(full)
        loaded.append(full)
        return mod

    yield load

    for full in loaded:
        sys.modules.pop(full, None)
    for cmd in ("decompile", "disas", "xrefs", "calls", "strrefs", "search"):
        dispatch.HANDLERS.pop(cmd, None)


def test_decompile_defaults_to_bounded_page(fake_ida_modules, monkeypatch):
    disasm = fake_ida_modules("disasm")

    class Func:
        start_ea = 0x401000

    class PseudoLine:
        def __init__(self, line):
            self.line = line

    class Cfunc:
        def get_pseudocode(self):
            return [PseudoLine(f"line {i}") for i in range(130)]

    monkeypatch.setattr(disasm.idahelp, "require_hexrays", lambda msg: None)
    monkeypatch.setattr(disasm.idahelp, "require_func", lambda func: Func())
    monkeypatch.setattr(disasm.idahelp, "safe_decompile", lambda ea: Cfunc())
    monkeypatch.setattr(disasm.ida_funcs, "get_func_name", lambda ea: "main")

    result, meta = disasm.decompile("main")

    assert result["func"] == "main"
    assert len(result["lines"]) == 120
    assert result["lines"][0] == "line 0"
    assert result["lines"][-1] == "line 119"
    assert meta == {"shown": 120, "truncated": True, "next_offset": 120}


def test_calls_defaults_to_bounded_callers(fake_ida_modules, monkeypatch):
    xrefs = fake_ida_modules("xrefs")

    class Func:
        start_ea = 0x401000

    class Xref:
        type = xrefs.ida_xref.fl_CF

        def __init__(self, frm):
            self.frm = frm
            self.to = 0x401000

    monkeypatch.setattr(xrefs.idahelp, "require_func", lambda func: Func())
    monkeypatch.setattr(xrefs.idahelp, "func_name_at", lambda ea: f"caller_{ea:x}")
    monkeypatch.setattr(xrefs.ida_funcs, "get_func_name", lambda ea: "target")
    monkeypatch.setattr(xrefs.idautils, "XrefsTo", lambda ea: (Xref(0x500000 + i) for i in range(250)))
    monkeypatch.setattr(xrefs.idautils, "FuncItems", lambda ea: ())

    result, meta = xrefs.calls("target")

    assert result["func"] == "target"
    assert len(result["callers"]) == 200
    assert result["callees"] == []
    assert result["callers"][0]["ea"] == 0x500000
    assert result["callers"][-1]["ea"] == 0x500000 + 199
    assert meta == {"shown": 200, "truncated": True, "next_offset": 200}
