"""xrefs handlers: xref_to, xref_from, calls, search.

Every xref/search row carries the high-value context IDA's UI omits: a compact
kind label, the enclosing function, and the tag-removed disassembly of the
instruction at that address.
"""

import ida_bytes
import ida_ida
import ida_lines
import ida_funcs
import ida_name
import ida_search
import ida_xref
import idautils
from ida_idaapi import BADADDR

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp
from idb.worker.budget import Budget
from idb.worker.dispatch import handler

_KIND = {
    ida_xref.dr_O: "offset", ida_xref.dr_W: "write", ida_xref.dr_R: "read",
    ida_xref.dr_T: "text", ida_xref.dr_I: "info",
    ida_xref.fl_CF: "call", ida_xref.fl_CN: "call",
    ida_xref.fl_JF: "jump", ida_xref.fl_JN: "jump",
    ida_xref.fl_F: "flow",
}
_CALL_TYPES = (ida_xref.fl_CF, ida_xref.fl_CN)
_FWD = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
_DEFAULT = 200


def _kind(xtype):
    return _KIND.get(xtype, "?")


def _insn(ea):
    return ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0))


def _ctx_row(ea, kind):
    return {"ea": ea, "kind": kind, "func": idahelp.func_name_at(ea), "insn": _insn(ea)}


def _find_bytes(pattern, start, end):
    return ida_bytes.find_bytes(pattern, start, range_end=end, flags=_FWD)


def _find_string(pattern, start, end):
    return ida_bytes.find_string(pattern, start, range_end=end, flags=_FWD)


def _next_hit(source, end, budget):
    while source["cur"] < end:
        budget.check()
        ea = source["find"](source["cur"], end)
        if ea == BADADDR or ea >= end:
            source["ea"] = BADADDR
            return
        source["ea"] = ea
        return
    source["ea"] = BADADDR


def _string_search_gen(pattern, start, end, budget):
    text = str(pattern)
    if not text:
        return

    storage_encoding = "utf-16-be" if ida_ida.inf_is_be() else "utf-16-le"
    sources = [{"cur": start, "find": lambda cur, limit: _find_string(text, cur, limit), "ea": BADADDR}]
    hex_pattern = text.encode(storage_encoding).hex(" ")
    sources.append({"cur": start, "find": lambda cur, limit, p=hex_pattern: _find_bytes(p, cur, limit), "ea": BADADDR})

    for source in sources:
        _next_hit(source, end, budget)

    seen = set()
    while True:
        live = [source for source in sources if source["ea"] != BADADDR]
        if not live:
            return
        source = min(live, key=lambda item: item["ea"])
        ea = source["ea"]
        source["cur"] = ea + 1
        _next_hit(source, end, budget)
        if ea in seen:
            continue
        seen.add(ea)
        yield ea


@handler("xref_to")
def xref_to(addr, offset=0, count=None):
    ea = idahelp.resolve_target(addr)
    gen = (_ctx_row(x.frm, _kind(x.type)) for x in idautils.XrefsTo(ea))
    items, next_offset = idahelp.paginate(gen, offset, count if count else _DEFAULT)
    return {"data": items, "target": ea}, idahelp.page_meta(items, next_offset)


@handler("xref_from")
def xref_from(addr, offset=0, count=None):
    ea = idahelp.resolve_target(addr)
    gen = (_ctx_row(x.to, _kind(x.type)) for x in idautils.XrefsFrom(ea))
    items, next_offset = idahelp.paginate(gen, offset, count if count else _DEFAULT)
    return {"data": items, "source": ea}, idahelp.page_meta(items, next_offset)


@handler("calls")
def calls(func, offset=0, count=None):
    ea = idahelp.resolve_target(func)
    f = ida_funcs.get_func(ea)
    if f is None:
        raise IdbError(protocol.NOT_FOUND, f"no function at {func!r}")
    start = f.start_ea

    seen = set()

    def gen():
        for x in idautils.XrefsTo(start):
            if x.type in _CALL_TYPES:
                yield "caller", {"ea": x.frm, "func": idahelp.func_name_at(x.frm), "insn": _insn(x.frm)}

        for item in idautils.FuncItems(start):
            for x in idautils.XrefsFrom(item):
                if x.type in _CALL_TYPES and x.to not in seen:
                    seen.add(x.to)
                    name = idahelp.func_name_at(x.to) or ida_name.get_name(x.to) or ""
                    yield "callee", {"ea": x.to, "name": name, "from": item}

    rows, next_offset = idahelp.paginate(gen(), offset, count)
    callers, callees = [], []
    for kind, row in rows:
        if kind == "caller":
            callers.append(row)
        else:
            callees.append(row)

    return ({"func": ida_funcs.get_func_name(start), "ea": start,
             "callers": callers, "callees": callees},
            idahelp.page_meta(rows, next_offset))

def _search_gen(kind, pattern, start, end, budget):
    if kind == "ref":
        target = idahelp.resolve_target(pattern)
        seen = set()
        for ea in list(idautils.DataRefsTo(target)) + list(idautils.CodeRefsTo(target, 0)):
            if ea not in seen:
                seen.add(ea)
                yield ea
        return
    if kind == "imm":
        value = idahelp.parse_addr(pattern)
        cur = start
        while start <= cur < end:
            budget.check()
            res = ida_search.find_imm(cur, ida_search.SEARCH_DOWN, value)
            ea = res[0] if isinstance(res, (tuple, list)) else res
            if ea is None or ea == BADADDR or ea >= end:
                break
            yield ea
            cur = ea + 1
        return
    if kind == "str":
        yield from _string_search_gen(pattern, start, end, budget)
        return
    find = ida_bytes.find_string if kind == "str" else ida_bytes.find_bytes
    cur = start
    while start <= cur < end:
        budget.check()
        ea = find(pattern, cur, range_end=end, flags=_FWD)
        if ea == BADADDR or ea >= end:
            break
        yield ea
        cur = ea + 1


@handler("search")
def search(pattern, kind="bytes", offset=0, count=None):
    if kind not in ("bytes", "imm", "str", "ref"):
        raise IdbError(protocol.BAD_ARGS, f"unknown search kind {kind!r}")
    start, end = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    gen = (_ctx_row(ea, kind) for ea in _search_gen(kind, pattern, start, end, Budget(20.0)))
    items, next_offset = idahelp.paginate(gen, offset, count if count else _DEFAULT)
    return {"data": items, "kind": kind, "pattern": pattern}, idahelp.page_meta(items, next_offset)
