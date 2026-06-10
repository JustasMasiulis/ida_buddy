"""xrefs handlers: xref_to, xref_from, calls, search.

Every xref/search row carries the high-value context IDA's UI omits: a compact
kind label, the enclosing function, and the tag-removed disassembly of the
instruction at that address.
"""

import itertools
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


def _to_rows(ea, tag):
    for x in idautils.XrefsTo(ea):
        row = _ctx_row(x.frm, _kind(x.type))
        if tag:
            row["dir"] = "to"
        yield row


def _from_rows(ea, tag):
    for x in idautils.XrefsFrom(ea):
        row = _ctx_row(x.to, _kind(x.type))
        if tag:
            row["dir"] = "from"
        yield row


@handler("xrefs")
def xrefs(addr, direction="to", offset=0, count=None):
    ea = idahelp.resolve_target(addr)
    if direction == "to":
        gen = _to_rows(ea, False)
    elif direction == "from":
        gen = _from_rows(ea, False)
    elif direction == "both":
        def gen_both():
            yield from _to_rows(ea, True)
            yield from _from_rows(ea, True)
        gen = gen_both()
    else:
        raise IdbError(protocol.BAD_ARGS, f"direction must be to/from/both, not {direction!r}")
    items, next_offset = idahelp.paginate(gen, offset, count if count else _DEFAULT)
    return {"data": items, "addr": ea, "direction": direction}, idahelp.page_meta(items, next_offset)


_CALLER_CEILING = 2000


@handler("calls")
def calls(func, depth=1, offset=0, count=None):
    f = idahelp.require_func(func)
    start = f.start_ea
    depth = max(1, int(depth))

    def caller_gen():
        visited = {start}
        frontier = [start]
        for level in range(1, depth + 1):
            next_frontier = []
            for target in frontier:
                for x in idautils.XrefsTo(target):
                    if x.type not in _CALL_TYPES:
                        continue
                    yield {"ea": x.frm, "func": idahelp.func_name_at(x.frm),
                           "insn": _insn(x.frm), "depth": level}
                    cf = ida_funcs.get_func(x.frm)
                    if cf is not None and cf.start_ea not in visited and len(visited) < _CALLER_CEILING:
                        visited.add(cf.start_ea)
                        next_frontier.append(cf.start_ea)
            if not next_frontier:
                break
            frontier = next_frontier

    seen = set()
    callees = []
    for item in idautils.FuncItems(start):
        for x in idautils.XrefsFrom(item):
            if x.type in _CALL_TYPES and x.to not in seen:
                seen.add(x.to)
                name = idahelp.func_name_at(x.to) or ida_name.get_name(x.to) or ""
                callees.append({"ea": x.to, "name": name, "from": item})

    callers, next_offset = idahelp.paginate(caller_gen(), offset, count if count else _DEFAULT)
    return ({"func": ida_funcs.get_func_name(start), "ea": start, "depth": depth,
             "callers": callers, "callees": callees},
            idahelp.page_meta(callers, next_offset))


@handler("strrefs")
def strrefs(pattern, offset=0, count=None):
    pred = idahelp.name_filter(pattern)

    def gen():
        for s in idautils.Strings():
            text = str(s)
            if not pred(text):
                continue
            for x in idautils.XrefsTo(s.ea):
                row = _ctx_row(x.frm, _kind(x.type))
                row["str_ea"] = s.ea
                row["str"] = text[:48]
                yield row

    items, next_offset = idahelp.paginate(gen(), offset, count if count else _DEFAULT)
    return {"data": items, "pattern": pattern}, idahelp.page_meta(items, next_offset)

def _search_gen(kind, pattern, start, end, budget):
    if kind == "ref":
        target = idahelp.resolve_target(pattern)
        seen = set()
        try:
            for ea in itertools.chain(idautils.DataRefsTo(target), idautils.CodeRefsTo(target, 0)):
                if ea not in seen:
                    seen.add(ea)
                    yield ea
        except Exception as exc:
            raise IdbError(protocol.IDA_ERROR,
                           f"failed to enumerate xrefs to {target:#x}: {exc}")
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
