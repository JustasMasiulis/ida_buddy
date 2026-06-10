"""disasm handlers: disas (u), decompile (dec). Every listing line is run through
tag_remove so color tags never reach the formatter."""

import ida_bytes
import ida_funcs
import ida_lines
import ida_segment
import ida_ida
import idautils
from ida_idaapi import BADADDR

from idb.worker import idahelp
from idb.worker.dispatch import handler

_FUNC_CAP = 2048
_RAW_DEFAULT = 32
_DECOMP_DEFAULT = 120


def _seg_name(ea):
    s = ida_segment.getseg(ea)
    return ida_segment.get_segm_name(s) if s else "?"


def _func_header(f):
    return {
        "name": ida_funcs.get_func_name(f.start_ea),
        "start": f.start_ea,
        "end": f.end_ea,
        "seg": _seg_name(f.start_ea),
    }


def _line(ea):
    return {
        "ea": ea,
        "text": ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0)),
        "size": ida_bytes.get_item_size(ea),
    }


def _walk(ea):
    cur = ea
    max_ea = ida_ida.inf_get_max_ea()
    while cur != BADADDR and cur < max_ea:
        yield _line(cur)
        nxt = ida_bytes.next_head(cur, max_ea)
        if nxt <= cur:
            break
        cur = nxt


@handler("disas")
def disas(target, count=None, offset=0, whole=False):
    ea = idahelp.resolve_mapped(target)
    f = ida_funcs.get_func(ea)
    if whole and f is not None and count is None:
        gen = (_line(e) for e in idautils.FuncItems(f.start_ea))
        items, next_offset = idahelp.paginate(gen, offset, _FUNC_CAP)
        return ({"mode": "func", "func": _func_header(f), "lines": items},
                idahelp.page_meta(items, next_offset))
    n = count if count else _RAW_DEFAULT
    items, next_offset = idahelp.paginate(_walk(ea), offset, n)
    header = _func_header(f) if f is not None else None
    return ({"mode": "raw", "func": header, "lines": items},
            idahelp.page_meta(items, next_offset))


@handler("decompile")
def decompile(func, offset=0, count=None):
    idahelp.require_hexrays("Hex-Rays decompiler is not available (no license)")
    f = idahelp.require_func(func)
    cfunc = idahelp.safe_decompile(f.start_ea)
    lines = (ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode())
    items, next_offset = idahelp.paginate(lines, offset, count if count else _DECOMP_DEFAULT)
    return ({"func": ida_funcs.get_func_name(f.start_ea), "ea": f.start_ea, "lines": items},
            idahelp.page_meta(items, next_offset))
