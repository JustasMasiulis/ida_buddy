"""triage: a one-call pre-reverse-engineering summary of a single function.

Collapses what an analyst gathers by hand before reading a function — its
callees (worst-named first, since those are the work), the subsystem prefixes
clustered around it in both call-graph directions, its prototype and the actual
argument types seen at call sites, its SEH/chunk structure, and the strings it
touches (including one level of UNICODE_STRING/ANSI_STRING indirection).

A single wall-clock budget (TRIAGE_BUDGET_S) governs the whole run: the cheap
deterministic phases finish in well under a second, and the remainder is spent
decompiling callers to recover argument types. Phases that hit the budget set a
*_truncated flag rather than aborting — the formatter renders that as a `+`.
"""

import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf as T
import ida_xref
import idautils

from idb import triage as pure
from idb.worker import hexcalls, idahelp
from idb.worker.budget import Budget
from idb.worker.dispatch import handler

TRIAGE_BUDGET_S = 5.0
# The cheap phases (callees/chunks/seh/strings) finish in well under a second; the
# rest of the wall-clock is split between the two analyses that decompile or walk
# the graph. Caller arg-harvest is the headline feature, so it gets the lion's
# share; the bidirectional prefix BFS gets a small slice (it is mostly noise on a
# fully-stripped binary anyway). Independent sub-budgets so neither starves.
_GROUP_BUDGET_S = 1.0
_ARG_BUDGET_S = 3.5
_ARG_MAX_DECOMP = 12
_ARG_MAX_SITES = 24

_CALL_TYPES = (ida_xref.fl_CF, ida_xref.fl_CN)
_CALLEE_CAP = 60
_STRING_CAP = 40
_GRAPH_CEILING = 600
_CALLER_CEILING = 4000
_PDATA_REC = 12
_UNW_EHANDLER = 0x1
_UNW_UHANDLER = 0x2
_UNW_CHAININFO = 0x4

_SEH_ROUTINES = frozenset({
    "__C_specific_handler", "__GSHandlerCheck", "__GSHandlerCheck_SEH",
    "_except_handler3", "_except_handler4", "__CxxFrameHandler",
    "__CxxFrameHandler3", "_local_unwind", "RtlUnwindEx",
})


def _callee_name(ea):
    return idahelp.func_name_at(ea) or ida_name.get_name(ea) or ""


def _direct_callees(start):
    """Distinct called functions reached from the body of `start`. A call landing
    in the middle (a tail chunk) of a function is resolved to that function's
    entry, so the displayed address and name always agree and chunk targets of one
    function collapse to a single callee."""
    seen = set()
    out = []
    for item in idautils.FuncItems(start):
        for x in idautils.XrefsFrom(item):
            if x.type not in _CALL_TYPES:
                continue
            cf = ida_funcs.get_func(x.to)
            target = cf.start_ea if cf is not None else x.to
            if target not in seen:
                seen.add(target)
                out.append(target)
                if len(out) >= _CALLEE_CAP:
                    return out
    return out


def _callers(ea, ceiling=_CALLER_CEILING):
    """Distinct enclosing functions that call `ea` (by their start_ea)."""
    seen = set()
    for x in idautils.XrefsTo(ea):
        if x.type not in _CALL_TYPES:
            continue
        cf = ida_funcs.get_func(x.frm)
        start = cf.start_ea if cf is not None else x.frm
        if start not in seen:
            seen.add(start)
            if len(seen) >= ceiling:
                break
    return seen


def _callee_kind(ea, cf):
    if cf is None:
        return "import" if ida_name.get_name(ea) else "data"
    if cf.flags & ida_funcs.FUNC_THUNK:
        return "thunk"
    return "func"


def _callee_row(ea):
    cf = ida_funcs.get_func(ea)
    name = _callee_name(ea)
    return {
        "ea": ea,
        "name": name,
        "size": (cf.end_ea - cf.start_ea) if cf is not None else 0,
        "callers": len(_callers(ea)),
        "kind": _callee_kind(ea, cf),
        "named": bool(name) and not pure.is_dummy_name(name),
    }


def _func_tinfo(start):
    tif = T.tinfo_t()
    if ida_nalt.get_tinfo(tif, start):
        return tif, "tinfo"
    guess = T.tinfo_t()
    if T.guess_tinfo(guess, start) != T.GUESS_FUNC_FAILED:
        return guess, "guessed"
    return None, "none"


def _declared_args(tif):
    """Declared parameter type strings of a function tinfo, or [] if unavailable."""
    if tif is None:
        return []
    fd = T.func_type_data_t()
    if not tif.get_func_details(fd):
        return []
    return [str(fd[i].type) for i in range(fd.size())]


def _chunks(start):
    """Tail chunks of the function (everything but the entry chunk)."""
    out = []
    for chunk_start, _chunk_end in idautils.Chunks(start):
        if chunk_start == start:
            continue
        out.append({"ea": chunk_start, "name": _callee_name(chunk_start)})
    return out


def _pdata_seg():
    for name in (".pdata", "PDATA", ".pdata$"):
        seg = ida_segment.get_segm_by_name(name)
        if seg is not None:
            return seg
    return None


def _pdata_unwind_rva(start):
    """The UNWIND_INFO RVA for the function at `start`, found by binary-searching
    the x64 .pdata RUNTIME_FUNCTION table (3 dwords each: begin/end/unwind RVA,
    sorted by begin) for the entry whose [begin,end) range covers it. None when
    there is no separate .pdata (common in kernel images) or no covering entry."""
    seg = _pdata_seg()
    if seg is None:
        return None
    rva = start - ida_nalt.get_imagebase()
    if rva < 0:
        return None
    lo, hi = 0, (seg.end_ea - seg.start_ea) // _PDATA_REC
    while lo < hi:
        mid = (lo + hi) // 2
        rec = seg.start_ea + mid * _PDATA_REC
        begin = ida_bytes.get_dword(rec)
        end = ida_bytes.get_dword(rec + 4)
        if rva < begin:
            hi = mid
        elif rva >= end:
            lo = mid + 1
        else:
            return ida_bytes.get_dword(rec + 8)
    return None


def _unwind_handler_rva(unwind_rva, depth=0):
    """Walk an x64 UNWIND_INFO and return the exception-handler RVA if it carries
    one. Layout: byte0 = version|flags<<3; byte2 = unwind-code count; the codes
    (2 bytes each, padded to an even count) are followed by either the handler RVA
    (EHANDLER/UHANDLER) or a chained RUNTIME_FUNCTION (CHAININFO), which we follow.
    None when the function has no language handler."""
    if depth > 8 or not unwind_rva:
        return None
    info = ida_nalt.get_imagebase() + unwind_rva
    if not ida_bytes.is_mapped(info):
        return None
    flags = ida_bytes.get_byte(info) >> 3
    count = ida_bytes.get_byte(info + 2)
    after_codes = info + 4 + ((count + 1) & ~1) * 2
    if flags & (_UNW_EHANDLER | _UNW_UHANDLER):
        return ida_bytes.get_dword(after_codes)
    if flags & _UNW_CHAININFO:
        return _unwind_handler_rva(ida_bytes.get_dword(after_codes + 8), depth + 1)
    return None


def _seh(start, func, callee_rows):
    """Exception-handling signal for the function. The reliable source on x64 is
    the .pdata/UNWIND_INFO chain, which names the language handler even when the
    binary is stripped of symbol names AND when the handler is wired through unwind
    data rather than called from the body (the common __try/__except case). Falls
    back to an explicit body call to a known handler routine when there is no
    .pdata. None when no EH evidence is found."""
    try:
        unwind_rva = _pdata_unwind_rva(start)
        if unwind_rva is not None:
            handler_rva = _unwind_handler_rva(unwind_rva)
            if handler_rva:
                handler_ea = ida_nalt.get_imagebase() + handler_rva
                return {"handler": ida_name.get_name(handler_ea) or None,
                        "handler_ea": handler_ea, "via": "unwind",
                        "has_frame": bool(func.flags & ida_funcs.FUNC_FRAME)}
    except Exception:
        pass
    for c in callee_rows:
        if c["name"] in _SEH_ROUTINES:
            return {"handler": c["name"], "handler_ea": c["ea"], "via": "call",
                    "has_frame": bool(func.flags & ida_funcs.FUNC_FRAME)}
    return None


def _strlit(ea):
    strtype = ida_nalt.get_str_type(ea)
    if strtype is None or not 0 <= strtype <= 0x7FFFFFFF:
        return None
    raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
    return raw.decode("utf-8", "replace") if raw else None


def _counted_string(ea):
    """Read a UNICODE_STRING/ANSI_STRING at `ea` ({u16 Length; u16 Max; ptr Buf}),
    following Buffer. Returns (text, kind) or None. Mirrors the string_struct
    handler (memory.py)."""
    ptr = 8 if ida_ida.inf_get_app_bitness() == 64 else 4
    length = ida_bytes.get_word(ea)
    if not 0 < length <= 0x1000:
        return None
    buffer = ida_bytes.get_qword(ea + 8) if ptr == 8 else ida_bytes.get_dword(ea + 4)
    if not ida_bytes.is_mapped(buffer):
        return None
    raw = ida_bytes.get_bytes(buffer, length) or b""
    has_nul = b"\x00" in raw[:2] if len(raw) >= 2 else False
    if has_nul:
        enc = "utf-16-be" if ida_ida.inf_is_be() else "utf-16-le"
        return raw.decode(enc, "replace"), "unicode_string"
    return raw.decode("latin-1", "replace"), "ansi_string"


def _strings(start, budget):
    out = []
    seen = set()
    truncated = False
    for item in idautils.FuncItems(start):
        if budget.expired:
            truncated = True
            break
        for ref in idautils.DataRefsFrom(item):
            if ref in seen:
                continue
            seen.add(ref)
            text = _strlit(ref)
            if text is not None:
                out.append({"from": item, "str_ea": ref, "text": text, "kind": "direct"})
            else:
                indirect = _counted_string(ref)
                if indirect is not None:
                    out.append({"from": item, "str_ea": ref,
                                "text": indirect[0], "kind": indirect[1]})
            if len(out) >= _STRING_CAP:
                return out, True
    return out, truncated


def _graph_prefixes(start, budget):
    """Names reached by a budgeted BFS from `start`, down the callee edge and up
    the caller edge, returned as two prefix-group lists."""
    truncated = [False]

    def walk(seed, expand):
        names = []
        visited = {start}
        frontier = [start]
        while frontier:
            if budget.expired or len(visited) >= _GRAPH_CEILING:
                truncated[0] = True
                break
            nxt = []
            for node in frontier:
                for neigh in expand(node):
                    if neigh in visited:
                        continue
                    visited.add(neigh)
                    name = _callee_name(neigh)
                    if name:
                        names.append(name)
                    nxt.append(neigh)
                    if len(visited) >= _GRAPH_CEILING:
                        break
            frontier = nxt
        return names

    down = walk(start, _direct_callees)
    up = walk(start, lambda ea: _callers(ea, ceiling=64))
    return (pure.group_prefixes(down), pure.group_prefixes(up), truncated[0])


def _harvest_args(start, budget):
    """Decompile callers of `start` (bounded by `budget` and a hard decompile cap)
    and collect the underlying argument types at each call site. Returns
    (arg_types, callers_decompiled, truncated), or (None, 0, False) if Hex-Rays is
    unavailable. A single decompile is ~1s here, so the cap matters as much as the
    clock — we stop once enough sites agree."""
    if not hexcalls.init():
        return None, 0, False
    import ida_hexrays

    callers = sorted(_callers(start))
    sites = []
    done = 0
    stopped_early = False
    for caller in callers:
        if budget.expired or done >= _ARG_MAX_DECOMP or len(sites) >= _ARG_MAX_SITES:
            stopped_early = True
            break
        # A cached caller cfunc is not refreshed when the target's prototype
        # changes, so its call-site arg types go stale. Force a fresh ctree.
        ida_hexrays.mark_cfunc_dirty(caller)
        try:
            cfunc = ida_hexrays.decompile(caller)
        except Exception:
            continue
        if cfunc is None:
            continue
        done += 1
        try:
            sites.extend(hexcalls.call_sites(cfunc, caller, target=start))
        except Exception:
            continue

    # truncated only if callers remain that we never looked at
    truncated = stopped_early and done < len(callers)
    if not sites:
        return ([] if done else None), done, truncated
    return pure.aggregate_arg_types(sites), done, truncated


@handler("triage")
def triage(func):
    budget = Budget(TRIAGE_BUDGET_S)
    f = idahelp.require_func(func)
    start = f.start_ea

    tif, proto_source = _func_tinfo(start)
    proto = str(tif) if tif is not None else None

    callee_eas = _direct_callees(start)
    callee_rows = [_callee_row(t) for t in callee_eas]
    ranked = pure.rank_callees(callee_rows, cap=_CALLEE_CAP)

    chunks = _chunks(start)
    seh = _seh(start, f, callee_rows)
    strings, strings_truncated = _strings(start, budget)
    arg_types, arg_caller_count, arg_truncated = _harvest_args(start, Budget(_ARG_BUDGET_S))
    groups_down, groups_up, groups_truncated = _graph_prefixes(start, Budget(_GROUP_BUDGET_S))
    if arg_types:
        decls = _declared_args(tif)
        # A guessed/overcounted prototype yields trailing pseudo-args ("retaddr",
        # register spills); when the real parameter count is known, keep only those
        # positions and attach each declared type.
        if decls:
            arg_types = [row for row in arg_types if 0 <= row["index"] < len(decls)]
        for row in arg_types:
            idx = row["index"]
            row["decl"] = decls[idx] if 0 <= idx < len(decls) else None

    return {
        "func": ida_funcs.get_func_name(start),
        "ea": start,
        "size": f.end_ea - start,
        "proto": proto,
        "proto_source": proto_source,
        "callee_count": len(callee_eas),
        "callees": ranked,
        "callees_truncated": len(callee_eas) >= _CALLEE_CAP,
        "groups_down": groups_down,
        "groups_up": groups_up,
        "groups_truncated": groups_truncated,
        "chunks": chunks,
        "seh": seh,
        "strings": strings,
        "strings_truncated": strings_truncated,
        "arg_types": arg_types,
        "arg_caller_count": arg_caller_count,
        "arg_types_truncated": arg_truncated,
    }
