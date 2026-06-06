"""symbols handlers: funcs, imports, exports, strings, names, nearest."""

import ida_entry
import ida_funcs
import ida_nalt
import idautils

from idb.worker import idahelp
from idb.worker.dispatch import handler

_LIST_DEFAULT = 200


def _cap(count):
    return count if count else _LIST_DEFAULT


def _result(make_gen, offset, count, total=False):
    items, next_offset = idahelp.paginate(make_gen(), offset, _cap(count))
    total_count = sum(1 for _ in make_gen()) if total else None
    return {"data": items}, idahelp.page_meta(items, next_offset, total_count)


@handler("funcs")
def funcs(pattern=None, offset=0, count=None, total=False):
    pred = idahelp.name_filter(pattern)

    def gen():
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea)
            if pred(name):
                f = ida_funcs.get_func(ea)
                yield {"ea": ea, "name": name, "size": (f.end_ea - f.start_ea) if f else 0}

    return _result(gen, offset, count, total)


@handler("names")
def names(pattern=None, offset=0, count=None, total=False):
    pred = idahelp.name_filter(pattern)

    def gen():
        for ea, name in idautils.Names():
            if pred(name):
                yield {"ea": ea, "name": name}

    return _result(gen, offset, count, total)


@handler("strings")
def strings(pattern=None, offset=0, count=None, total=False):
    pred = idahelp.name_filter(pattern)

    def gen():
        for s in idautils.Strings():
            text = str(s)
            if pred(text):
                yield {"ea": s.ea, "length": s.length, "text": text}

    return _result(gen, offset, count, total)


@handler("imports")
def imports(pattern=None, offset=0, count=None, total=False):
    pred = idahelp.name_filter(pattern)

    def gen():
        for i in range(ida_nalt.get_import_module_qty()):
            module = ida_nalt.get_import_module_name(i) or ""
            collected = []

            def cb(ea, name, ordinal):
                collected.append((ea, name or "", ordinal))
                return True

            ida_nalt.enum_import_names(i, cb)
            for ea, name, ordinal in collected:
                if pred(name):
                    yield {"ea": ea, "name": name, "module": module, "ordinal": ordinal}

    return _result(gen, offset, count, total)


@handler("exports")
def exports(pattern=None, offset=0, count=None, total=False):
    pred = idahelp.name_filter(pattern)

    def gen():
        for i in range(ida_entry.get_entry_qty()):
            ordn = ida_entry.get_entry_ordinal(i)
            name = ida_entry.get_entry_name(ordn) or ""
            if pred(name):
                yield {"ea": ida_entry.get_entry(ordn), "name": name, "ordinal": ordn}

    return _result(gen, offset, count, total)


@handler("nearest")
def nearest(addr):
    ea = idahelp.resolve_target(addr)
    symbol = None
    for nea, name in idautils.Names():
        if nea <= ea:
            symbol = {"name": name, "ea": nea, "offset": ea - nea}
        if nea > ea:
            break
    func = None
    f = ida_funcs.get_func(ea)
    if f is not None:
        func = {"name": ida_funcs.get_func_name(f.start_ea), "ea": f.start_ea,
                "offset": ea - f.start_ea}
    if func and symbol and symbol["ea"] < func["ea"]:
        symbol = None  # nearest named symbol sits before the enclosing func -> the func is the real anchor
    return {"addr": ea, "symbol": symbol, "func": func}
