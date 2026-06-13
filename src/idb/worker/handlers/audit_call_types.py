"""audit_call_types: a global call-graph audit of parameter and local types.

The whole database (or a name-scoped slice) is decompiled once. Every call is
walked, propagating types along call edges in two directions:

  * param  — the argument types seen at all of a callee's call sites are compared
             to its declared prototype, flagging parameters that can be made
             concrete or that conflict with what is actually passed.
  * local  — a local variable passed into an authoritative concrete parameter
             (an import/library prototype, or a user-set one) gains that type as
             evidence, flagging locals that can be concretized.

The decompile pass is the cost, so each corpus function is decompiled exactly
once and both directions are harvested from that single ctree walk. A wall-clock
Budget plus a hard decompile cap bound the run; an address-sorted corpus makes a
truncated run a reproducible, resumable prefix. All judgement lives in the pure
idb.audit_call_types module; this handler only gathers IDA facts.
"""

import ida_funcs
import ida_name
import ida_typeinf as T
import idautils

from idb import audit_call_types as pure, protocol
from idb.errors import IdbError
from idb.worker import hexcalls, idahelp
from idb.worker.budget import Budget
from idb.worker.dispatch import handler
from idb.worker.handlers import triage as tri

BUDGET_S = 20.0
DECOMP_LIMIT = 400
FINDINGS_CAP = 2000
FINDINGS_DEFAULT_PAGE = 50


def _kind(ea):
    cf = ida_funcs.get_func(ea)
    if cf is None:
        return "import" if ida_name.get_name(ea) else "data"
    lib = getattr(ida_funcs, "FUNC_LIB", 0)
    if lib and (cf.flags & lib):
        return "lib"
    if cf.flags & ida_funcs.FUNC_THUNK:
        return "thunk"
    return "func"


def _declared(tif):
    """(param type descriptors, param names) for a function tinfo, or ([],[])."""
    if tif is None:
        return [], []
    fd = T.func_type_data_t()
    if not tif.get_func_details(fd):
        return [], []
    descs, names = [], []
    for i in range(fd.size()):
        descs.append(hexcalls.type_desc(fd[i].type))
        try:
            names.append(fd[i].name or "")
        except Exception:
            names.append("")
    return descs, names


def _corpus(scope, want_params, want_locals):
    """(functions to decompile, subject set or None). No scope → whole DB, report
    every callee. Scope → report the name-matched callees: decompile their callers
    (param evidence) and, for local findings, the matched functions themselves."""
    funcs = sorted(idautils.Functions())
    if scope is None:
        return funcs, None
    pred = idahelp.name_filter(scope)
    subject = {ea for ea in funcs if pred(ida_funcs.get_func_name(ea) or "")}
    pool = set(subject) if want_locals else set()
    if want_params:
        for s in subject:
            pool |= tri._callers(s)
    return sorted(pool), subject


def _param_findings(param_buckets, no_imports, decls_for, thr):
    out = []
    for target, sites in param_buckets.items():
        source, descs, names, kindt = decls_for(target)
        if no_imports and kindt in ("import", "lib"):
            continue
        fname = ida_funcs.get_func_name(target) or ida_name.get_name(target) or f"{target:x}"
        rows = pure.aggregate_args_rich(sites)
        total_callers = len(set().union(*(r["callers"] for r in rows))) if rows else 0
        for row in rows:
            i = row["index"]
            decl = descs[i] if 0 <= i < len(descs) else None
            verdict = pure.classify_param(decl, source, row, thr)
            if verdict is None:
                continue
            slot = names[i] if 0 <= i < len(names) and names[i] else f"a{i}"
            verdict.update(kind="param", ea=target, func=fname, func_kind=kindt,
                           proto_source=source, index=i, slot=slot, callers=total_callers)
            out.append(verdict)
    return out


def _local_findings(cfunc, f_ea, evidence, thr):
    out = []
    lvars = cfunc.get_lvars()
    nvars = lvars.size()
    fname = ida_funcs.get_func_name(f_ea) or f"{f_ea:x}"
    for idx, items in evidence.items():
        if not (0 <= idx < nvars):
            continue
        try:
            lv = lvars[idx]
            cur = hexcalls.type_desc(lv.type())
        except Exception:
            continue
        evid = pure.aggregate_evidence(items)
        verdict = pure.classify_local(cur, evid, thr)
        if verdict is None:
            continue
        verdict.update(kind="local", ea=f_ea, func=fname, func_kind="func",
                       proto_source="local", index=None, slot=lv.name or f"v{idx}",
                       callers=evid["n_distinct"])
        out.append(verdict)
    return out


@handler("audit_call_types")
def audit_call_types(scope=None, budget=None, limit=None, min_sites=None, min_callers=None,
                     no_imports=False, kind="all", show_all=False, offset=0, count=None,
                     total=False):
    if not hexcalls.init():
        raise IdbError(protocol.IDA_ERROR, "Hex-Rays decompiler is required for audit_call_types")
    import ida_hexrays

    budget_s = float(budget) if budget else BUDGET_S
    max_decomp = int(limit) if limit else DECOMP_LIMIT
    # --all drops every evidence threshold to its floor (1 site, 1 caller, any
    # agreement); the _worth_suggesting noise filter still governs what is shown.
    # Explicit --min-sites/--min-callers still take precedence over the floor.
    thr = {
        "min_sites": int(min_sites) if min_sites else (1 if show_all else pure.MIN_SITES),
        "min_callers": int(min_callers) if min_callers else (1 if show_all else pure.MIN_CALLERS),
        "min_agree": 0.0 if show_all else pure.MIN_AGREE,
        "min_local_sites": 1 if show_all else pure.MIN_LOCAL_SITES,
    }
    want_params = kind != "locals"
    want_locals = kind != "params"

    corpus, subject = _corpus(scope, want_params, want_locals)
    decl_cache = {}

    def decls_for(ea):
        cached = decl_cache.get(ea)
        if cached is None:
            tif, source = tri._func_tinfo(ea)
            descs, names = _declared(tif)
            cached = (source, descs, names, _kind(ea))
            decl_cache[ea] = cached
        return cached

    bud = Budget(budget_s)
    scanned = call_site_count = 0
    truncated = False
    param_buckets = {}
    findings = []

    for f_ea in corpus:
        if bud.expired or scanned >= max_decomp:
            truncated = True
            break
        f = ida_funcs.get_func(f_ea)
        if f is None or (f.flags & ida_funcs.FUNC_THUNK):
            continue
        # The decompiler cache is not invalidated when a callee's prototype or a
        # referenced struct changes, so a cached cfunc carries stale call-site
        # arg/member types. Force a fresh ctree against current DB state.
        ida_hexrays.mark_cfunc_dirty(f_ea)
        try:
            cfunc = ida_hexrays.decompile(f_ea)
        except Exception:
            continue
        if cfunc is None:
            continue
        scanned += 1

        do_locals = want_locals and (subject is None or f_ea in subject)
        local_evidence = {}
        for site in hexcalls.call_sites(cfunc, f_ea):
            call_site_count += 1
            target = site["target"]
            if want_params and (subject is None or target in subject):
                param_buckets.setdefault(target, []).append(site)
            if do_locals:
                source, descs, _names, target_kind = decls_for(target)
                authoritative = source == "tinfo" or target_kind in ("import", "lib")
                for arg in site["args"]:
                    idx = arg.get("index", -1)
                    if not arg.get("is_local") or not (0 <= idx < len(descs)):
                        continue
                    if authoritative and pure.is_concrete(descs[idx]):
                        local_evidence.setdefault(arg["lvar_idx"], []).append(
                            (descs[idx], site["ea"], target))
        if do_locals and local_evidence:
            findings.extend(_local_findings(cfunc, f_ea, local_evidence, thr))

    if want_params:
        findings.extend(_param_findings(param_buckets, no_imports, decls_for, thr))

    ranked = pure.rank_findings(findings, cap=FINDINGS_CAP)
    count = count if count is not None else FINDINGS_DEFAULT_PAGE
    page, next_off = idahelp.paginate(ranked, offset, count)
    result = {
        "scope": scope,
        "functions_scanned": scanned,
        "functions_total": len(corpus),
        "call_sites": call_site_count,
        "budget_s": budget_s,
        "truncated": truncated,
        "findings": page,
    }
    meta = idahelp.page_meta(page, next_off, total=len(ranked) if total else None)
    if truncated:
        meta = dict(meta or {})
        meta["warning"] = (
            f"scanned {scanned}/{len(corpus)} functions before the {budget_s:g}s budget"
            f" / {max_decomp} decompile limit; narrow with a scope or raise --budget/--limit")
    return result, meta
