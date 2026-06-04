"""Pure heuristics for the `audit_call_types` command. No ida_* imports.

The handler (idb.worker.handlers.audit_call_types) decompiles a budgeted corpus
of functions once, harvesting per-call-site type descriptors from Hex-Rays. This
module turns those descriptors into findings: a parameter or local whose type is
either *concretizable* (declared a generic placeholder, but call sites agree on a
concrete type) or a *mismatch* (declared concrete, but call sites consistently
pass a conflicting type). Keeping the judgement here — what counts as a weak type,
when a difference is a real conflict, how findings rank — makes it Tier-1 testable
without a database.

A type descriptor is the dict produced by hexcalls.type_desc:
    {"type": str, "cat": ptr|struct|union|enum|func|array|scalar, "named": bool,
     "size": int, "signed": bool|None, "pointee": str|None, "pointee_named": bool,
     "canon": str|None}   # typedef/cv/tag-insensitive identity key
"""

import re

MIN_SITES = 3
MIN_CALLERS = 2
MIN_AGREE = 0.80
MIN_LOCAL_SITES = 2
EXAMPLES_CAP = 3

# Hex-Rays placeholder types: what the decompiler emits when it has no better
# idea. A parameter declared as one of these carries no information, so a concrete
# type agreed on by the call sites is a strict improvement.
PLACEHOLDER_TYPES = frozenset({
    "__int64", "unsigned __int64", "__int32", "unsigned __int32", "int",
    "unsigned int", "__int16", "unsigned __int16", "__int8", "unsigned __int8",
    "_QWORD", "_DWORD", "_WORD", "_BYTE", "_OWORD", "__m128i",
    "char", "unsigned char", "signed char", "short", "unsigned short",
    "long", "unsigned long", "long long", "unsigned long long",
    "bool", "_BOOL1", "_BOOL4", "_BOOL8", "void",
    "void *", "__int64 *", "_QWORD *", "char *",
})

# A pointer to one of these points at "some bytes", not a typed object.
_PLACEHOLDER_POINTEE = frozenset({
    "void", "__int64", "unsigned __int64", "_QWORD", "_DWORD", "_WORD", "_BYTE",
    "char", "unsigned char", "int", "unsigned int",
})

_TYPE_KEYS = ("type", "cat", "named", "size", "signed", "pointee", "pointee_named", "canon")

_CV = re.compile(r"\b(?:const|volatile)\b")


def _norm(type_str):
    """A type spelling stripped of cv-qualifiers with collapsed whitespace, so
    `const Foo *` and `Foo *` compare equal — suggesting one for the other is
    noise. Fallback identity when a descriptor carries no canonical key."""
    return re.sub(r"\s+", " ", _CV.sub(" ", type_str or "")).strip()


def _identity(desc):
    """The type's identity for equality: the canonical key (typedef/cv/tag
    insensitive) when present, else the cv-stripped spelling."""
    return desc.get("canon") or _norm(desc.get("type"))


def default_thresholds():
    return {"min_sites": MIN_SITES, "min_callers": MIN_CALLERS,
            "min_agree": MIN_AGREE, "min_local_sites": MIN_LOCAL_SITES}


def _desc(d):
    """Trim a (possibly arg-) descriptor down to the type keys."""
    return {k: d.get(k) for k in _TYPE_KEYS}


def is_weak(desc):
    """True when a type carries no object information worth preserving: a known
    Hex-Rays placeholder, an un-named scalar, or a pointer to untyped bytes."""
    if desc is None:
        return True
    t = desc.get("type")
    if not t or t == "?" or t in PLACEHOLDER_TYPES:
        return True
    cat = desc.get("cat")
    if cat == "scalar":
        return not desc.get("named", False)
    if cat == "ptr":
        pointee = desc.get("pointee")
        if not pointee or pointee in _PLACEHOLDER_POINTEE or not desc.get("pointee_named", False):
            return True
    return False


def is_strong(desc):
    """True when a type names a concrete *object* worth suggesting: a named
    struct/union/enum or a pointer to a named object. Scalar integer typedefs
    (ULONG, DWORD, size_t, NTSTATUS, ...) are deliberately excluded — respelling
    `unsigned int` as `ULONG` recovers no structure, so such a 'concretization'
    is noise. Anonymous compiler-synthesized types ($-prefixed) do not count."""
    if desc is None or is_weak(desc):
        return False
    cat = desc.get("cat")
    if cat in ("struct", "union", "enum"):
        return desc.get("named", False)
    if cat == "ptr":
        return desc.get("pointee_named", False) and desc.get("pointee") not in _PLACEHOLDER_POINTEE
    return False


def is_concrete(desc):
    """Definite enough to drive a *local* retype: structural, or a named scalar
    typedef (size_t, NTSTATUS) — but not a bare placeholder (int, __int64). The
    width/sign check in `_worth_suggesting` then decides if the retype is useful."""
    if is_strong(desc):
        return True
    return bool(desc) and desc.get("cat") == "scalar" and desc.get("named", False) \
        and desc.get("type") not in PLACEHOLDER_TYPES


def _worth_suggesting(have, dom):
    """Whether replacing `have` with `dom` recovers information worth a finding.
    Same underlying type -> no: this catches not just `X* vs const X*` but every
    typedef/tag respelling (`UNICODE_STRING *` vs `PUNICODE_STRING` vs
    `struct _UNICODE_STRING *`, `LARGE_INTEGER *` vs `union _LARGE_INTEGER *`).
    A structural type is always informative. A scalar suggestion counts only when
    `dom` is a real named typedef (size_t, NTSTATUS — not another placeholder)
    AND it changes width or signedness: `_QWORD -> __int64` and `unsigned int ->
    ULONG` recover nothing, but `unsigned int -> size_t` does."""
    if have is None or dom is None:
        return False
    if _identity(dom) == _identity(have):
        return False
    if is_strong(dom):
        return True
    if dom.get("cat") == "scalar" and have.get("cat") == "scalar" and is_concrete(dom):
        return (dom.get("size"), dom.get("signed")) != (have.get("size"), have.get("signed"))
    return False


def _conflict(decl, dom):
    """Severity that two types genuinely disagree, not just differ in spelling.
    pointer-vs-scalar (3) is the loudest signal, a different named pointee (2)
    next, a width or signedness mismatch (1) weakest; 0 means no real conflict."""
    dptr = decl.get("cat") == "ptr"
    mptr = dom.get("cat") == "ptr"
    if dptr != mptr:
        return 3
    if dptr and mptr:
        if (_norm(decl.get("pointee")) != _norm(dom.get("pointee"))
                and decl.get("pointee_named") and dom.get("pointee_named")):
            return 2
        return 0
    ds, ms = decl.get("size") or 0, dom.get("size") or 0
    if ds and ms and ds != ms:
        return 1
    dsign, msign = decl.get("signed"), dom.get("signed")
    return 1 if dsign is not None and msign is not None and dsign != msign else 0


def _actuals(order, counts, descs, max_actuals):
    rows = [{**descs[t], "count": counts[t]} for t in order]
    rows.sort(key=lambda a: (-a["count"], order.index(a["type"])))
    return rows[:max_actuals]


def aggregate_args_rich(sites, max_actuals=4, max_examples=EXAMPLES_CAP):
    """Roll per-call-site argument descriptors up by parameter position, keeping
    each distinct type's full descriptor (so the classifier can reason about
    cat/pointee), its frequency, the distinct callers, and example call sites.

    `sites` is [{"caller", "ea", "args": [desc + {"index"}], ...}]. Returns one
    row per index: {index, n_sites, callers:set, actuals:[desc+count], member,
    examples:[ea]}."""
    by_index = {}
    for site in sites:
        caller = site.get("caller")
        ea = site.get("ea")
        for arg in site.get("args", []):
            idx = arg.get("index")
            slot = by_index.setdefault(idx, {
                "n_sites": 0, "callers": set(), "counts": {}, "order": [],
                "descs": {}, "member": None, "examples": []})
            slot["n_sites"] += 1
            if caller is not None:
                slot["callers"].add(caller)
            t = arg.get("type") or "?"
            if t not in slot["counts"]:
                slot["order"].append(t)
                slot["descs"][t] = _desc(arg)
            slot["counts"][t] = slot["counts"].get(t, 0) + 1
            if slot["member"] is None and arg.get("member"):
                slot["member"] = arg["member"]
            if ea is not None and ea not in slot["examples"] and len(slot["examples"]) < max_examples:
                slot["examples"].append(ea)

    rows = []
    for idx in sorted(by_index):
        slot = by_index[idx]
        rows.append({
            "index": idx,
            "n_sites": slot["n_sites"],
            "callers": slot["callers"],
            "actuals": _actuals(slot["order"], slot["counts"], slot["descs"], max_actuals),
            "member": slot["member"],
            "examples": slot["examples"],
        })
    return rows


def aggregate_evidence(items, max_actuals=4, max_examples=EXAMPLES_CAP):
    """Aggregate the evidence for a single local variable. `items` is
    [(callee_param_desc, site_ea, callee_ea)] — the strong, authoritative
    parameter types the local was passed into. Returns {n_sites, n_distinct,
    actuals:[desc+count], examples:[ea]} where n_distinct is the count of distinct
    callees supplying evidence."""
    counts, order, descs, examples, targets = {}, [], {}, [], set()
    n = 0
    for desc, ea, target in items:
        n += 1
        if target is not None:
            targets.add(target)
        t = desc.get("type") or "?"
        if t not in counts:
            order.append(t)
            descs[t] = _desc(desc)
        counts[t] = counts.get(t, 0) + 1
        if ea is not None and ea not in examples and len(examples) < max_examples:
            examples.append(ea)
    return {"n_sites": n, "n_distinct": len(targets),
            "actuals": _actuals(order, counts, descs, max_actuals), "examples": examples}


def _thin_actuals(actuals):
    return [{"type": a["type"], "count": a["count"]} for a in actuals]


def classify_param(decl_desc, decl_source, agg_row, thresholds=None):
    """Verdict for one declared parameter against the types seen at its call
    sites, or None when there is nothing actionable. Concretize a weak declared
    type that the call sites sharpen; flag a real conflict only against a
    user-set (not guessed) prototype, since a guess cannot be called wrong."""
    if decl_desc is None:
        return None
    th = thresholds or default_thresholds()
    actuals = agg_row.get("actuals") or []
    if not actuals:
        return None
    dom = actuals[0]
    n_sites = agg_row.get("n_sites", 0)
    n_distinct = len(agg_row.get("callers") or ())
    if n_sites < th["min_sites"] or n_distinct < th["min_callers"]:
        return None
    agree = dom["count"] / n_sites
    if agree < th["min_agree"] or not _worth_suggesting(decl_desc, dom):
        return None

    if is_weak(decl_desc):
        cls, severity = "concretize", 0
    else:
        severity = _conflict(decl_desc, dom)
        if severity == 0 or decl_source != "tinfo":
            return None
        cls = "mismatch"

    return {
        "class": cls, "severity": severity, "agree": agree,
        "n_sites": n_sites, "n_distinct": n_distinct,
        "decl": decl_desc.get("type"), "suggest": dom["type"],
        "actuals": _thin_actuals(actuals), "member": agg_row.get("member"),
        "examples": list(agg_row.get("examples") or ()),
    }


def classify_local(cur_desc, evid_agg, thresholds=None):
    """Verdict for one local variable against the authoritative parameter types it
    is passed into, or None. Concretize a weak local; for an already-strong local
    flag only a pointer-vs-scalar conflict — the one local mistype worth a stop."""
    th = thresholds or default_thresholds()
    actuals = evid_agg.get("actuals") or []
    if not actuals:
        return None
    dom = actuals[0]
    n_sites = evid_agg.get("n_sites", 0)
    if n_sites < th["min_local_sites"]:
        return None
    agree = dom["count"] / n_sites
    if agree < th["min_agree"] or not _worth_suggesting(cur_desc, dom):
        return None

    if is_weak(cur_desc):
        cls, severity = "concretize", 0
    else:
        severity = _conflict(cur_desc, dom)
        if severity != 3:
            return None
        cls = "mismatch"

    return {
        "class": cls, "severity": severity, "agree": agree,
        "n_sites": n_sites, "n_distinct": evid_agg.get("n_distinct", 0),
        "decl": cur_desc.get("type"), "suggest": dom["type"],
        "actuals": _thin_actuals(actuals), "member": None,
        "examples": list(evid_agg.get("examples") or ()),
    }


def score(finding):
    sev = finding.get("severity", 0)
    agree = finding.get("agree", 0.0)
    n_distinct = finding.get("n_distinct", 0)
    n_sites = finding.get("n_sites", 0)
    bonus = 500 if finding.get("class") == "mismatch" else 0
    return 1000 * sev + 100 * agree + 5 * min(n_distinct, 20) + min(n_sites, 40) + bonus


def rank_findings(findings, cap=None):
    """Mismatches before concretizations, then by score, then a stable address /
    kind / slot tie-break. Annotates each finding with its score."""
    for f in findings:
        f["score"] = score(f)
    findings.sort(key=lambda f: (
        f.get("class") != "mismatch",
        -f["score"],
        f.get("ea", 0),
        f.get("kind", ""),
        str(f.get("slot", "")),
    ))
    return findings if cap is None else findings[:cap]
