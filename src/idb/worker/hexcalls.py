"""Shared Hex-Rays call-site harvesting — the mechanical ctree walk behind both
`triage` (one target's callers) and `audit_call_types` (the whole call graph).

This module is purely descriptive: it turns cexpr_t arguments into plain type
descriptors and yields the calls inside a decompiled function. All judgement
(what counts as a weak type, when types conflict) lives in the pure idb.triage /
idb.audit_call_types modules. ida_* is imported lazily so importing this module
never pulls in IDA on its own; it is only ever loaded after idapro is activated.
"""

import re

from ida_idaapi import BADADDR

_CANON_DROP = re.compile(r"\b(?:const|volatile|struct|union|enum)\b")


def init():
    import ida_hexrays

    return ida_hexrays.init_hexrays_plugin()


def _canon_name(name):
    """Normalize a type-name spelling: drop cv/tag keywords and whitespace, then a
    single leading underscore so the Windows tag/typedef pair `_UNICODE_STRING`
    and `UNICODE_STRING` collapse together."""
    s = re.sub(r"\s+", "", _CANON_DROP.sub(" ", name or ""))
    return s[1:] if s.startswith("_") else s


def _final_name(tinfo):
    return tinfo.get_final_type_name() or tinfo.get_type_name() or str(tinfo)


def _canon(tinfo):
    """A typedef/cv/tag-insensitive identity key: pointer depth plus the final tag
    name of the base. `const UNICODE_STRING *`, `PUNICODE_STRING`, and
    `struct _UNICODE_STRING *` all collapse to `UNICODE_STRING*`, so suggesting one
    in place of another is recognized as the same type. None on failure."""
    try:
        t, depth = tinfo, 0
        while not t.empty() and t.is_ptr() and depth < 12:
            p = t.get_pointed_object()
            if p is None or p.empty():
                break
            t, depth = p, depth + 1
        return _canon_name(_final_name(t)) + "*" * depth
    except Exception:
        return None


def _category(tinfo):
    if tinfo.is_ptr():
        return "ptr"
    if tinfo.is_struct():
        return "struct"
    if tinfo.is_union():
        return "union"
    if tinfo.is_enum():
        return "enum"
    if tinfo.is_func():
        return "func"
    if tinfo.is_array():
        return "array"
    return "scalar"


def _named(name):
    return bool(name) and not name.startswith("$") and "__anon" not in name


def _size(tinfo):
    n = tinfo.get_size()
    return int(n) if isinstance(n, int) and 0 <= n < (1 << 31) else 0


def _signed(tinfo, cat):
    """Tri-state signedness for a scalar (True/False), None when not an integer or
    unknown — so `int` vs `unsigned int` is a real difference but `_FOO *` has no
    sign to compare."""
    if cat != "scalar":
        return None
    try:
        if tinfo.is_signed():
            return True
        if tinfo.is_unsigned():
            return False
    except Exception:
        pass
    return None


def type_desc(tinfo):
    """A small, ida-free-consumable description of a type. `cat` collapses every
    arithmetic/void kind into 'scalar' (we only ever distinguish pointer from
    non-pointer); `named` is true for a real type name, not a $-anonymous one."""
    if tinfo is None or tinfo.empty():
        return {"type": "?", "cat": "scalar", "named": False, "size": 0,
                "signed": None, "pointee": None, "pointee_named": False, "canon": None}
    cat = _category(tinfo)
    pointee, pointee_named = None, False
    if cat == "ptr":
        p = tinfo.get_pointed_object()
        if p is not None and not p.empty():
            pointee = str(p)
            pointee_named = _named(p.get_type_name() or "")
    return {
        "type": str(tinfo),
        "cat": cat,
        "named": _named(tinfo.get_type_name() or ""),
        "size": _size(tinfo),
        "signed": _signed(tinfo, cat),
        "pointee": pointee,
        "pointee_named": pointee_named,
        "canon": _canon(tinfo),
    }


def call_target_ea(call_expr):
    """The ea a cot_call resolves to: the called object's address, peeking through
    a cast of a function pointer. BADADDR for indirect calls we can't resolve."""
    import ida_hexrays

    x = call_expr.x
    if x.op == ida_hexrays.cot_cast:
        x = x.x
    if x.op == ida_hexrays.cot_obj:
        return x.obj_ea
    return BADADDR


def arg_descriptor(arg):
    """Describe one call argument cexpr: its underlying type (looking through an
    implicit cast), a member-access note (@0xNN), and whether the operand is a
    bare local variable (so audit can attribute it to that lvar)."""
    import ida_hexrays

    inner = arg.x if arg.op == ida_hexrays.cot_cast else arg
    tif = inner.type if not inner.type.empty() else arg.type
    desc = type_desc(tif)

    member = None
    probe = inner
    if probe.op == ida_hexrays.cot_ref:
        probe = probe.x
    if probe.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
        member = f"@{probe.m:#x}"
    desc["member"] = member

    desc["is_local"], desc["lvar_idx"] = False, -1
    if inner.op == ida_hexrays.cot_var:
        try:
            desc["lvar_idx"] = inner.v.idx
            desc["is_local"] = True
        except Exception:
            pass
    return desc


def call_sites(cfunc, caller_ea, target=None):
    """Yield every resolvable call inside an already-decompiled cfunc as
    {"target", "caller", "ea", "args": [arg_descriptor + {"index"}]}. With
    `target` set, only calls to that ea are yielded (triage's single-target use).
    get_pseudocode() must run first: treeitems is empty until the ctext is built."""
    import ida_hexrays

    cfunc.get_pseudocode()
    items = cfunc.treeitems
    for i in range(items.size()):
        it = items.at(i)
        if not it.is_expr():
            continue
        e = it.cexpr
        if e.op != ida_hexrays.cot_call:
            continue
        t = call_target_ea(e)
        if t == BADADDR or (target is not None and t != target):
            continue
        call_ea = e.ea if e.ea != BADADDR else caller_ea
        args = []
        for idx in range(e.a.size()):
            try:
                desc = arg_descriptor(e.a[idx])
            except Exception:
                continue
            desc["index"] = idx
            args.append(desc)
        if args:
            yield {"target": t, "caller": caller_ea, "ea": call_ea, "args": args}
