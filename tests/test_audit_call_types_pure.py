from idb import audit_call_types as a


def d(type, cat="scalar", named=False, size=8, signed=None, pointee=None, pointee_named=False,
      canon=None):
    return {"type": type, "cat": cat, "named": named, "size": size, "signed": signed,
            "pointee": pointee, "pointee_named": pointee_named, "canon": canon}


# structural fixtures
KPROC = d("_KPROCESS *", "ptr", pointee="_KPROCESS", pointee_named=True)
EPROC = d("_EPROCESS", "struct", named=True)
ENUMT = d("MyFlags", "enum", named=True)
A_PTR = d("_A *", "ptr", pointee="_A", pointee_named=True)
B_PTR = d("_B *", "ptr", pointee="_B", pointee_named=True)
CONST_A_PTR = d("const _A *", "ptr", pointee="const _A", pointee_named=True)
VOIDP = d("void *", "ptr", pointee="void")
CHARP = d("char *", "ptr", pointee="char")
# scalars: placeholders (weak), named typedefs (concrete but not structural)
QWORD = d("__int64", size=8, signed=True)
RAWQ = d("_QWORD", size=8, signed=False)
UINT = d("unsigned int", size=4, signed=False)
SINT = d("int", size=4, signed=True)
HANDLE = d("HANDLE", "scalar", named=True, size=8, signed=False)
ULONG = d("ULONG", "scalar", named=True, size=4, signed=False)
SIZE_T = d("size_t", "scalar", named=True, size=8, signed=False)


def agg(actuals, n_sites, n_callers, member=None, examples=()):
    return {"index": 0, "n_sites": n_sites, "callers": set(range(n_callers)),
            "actuals": [{**desc, "count": c} for desc, c in actuals],
            "member": member, "examples": list(examples)}


def evid(actuals, n_sites=None, n_distinct=1, examples=()):
    n = n_sites if n_sites is not None else sum(c for _, c in actuals)
    return {"n_sites": n, "n_distinct": n_distinct,
            "actuals": [{**desc, "count": c} for desc, c in actuals], "examples": list(examples)}


def test_is_weak():
    assert a.is_weak(QWORD) and a.is_weak(UINT) and a.is_weak(SINT)
    assert a.is_weak(VOIDP) and a.is_weak(CHARP)
    assert a.is_weak(d("Mystery", "scalar", named=False))
    assert a.is_weak(d("_X *", "ptr", pointee="_X", pointee_named=False))  # unnamed pointee
    assert a.is_weak(None)
    assert not a.is_weak(KPROC) and not a.is_weak(EPROC)
    assert not a.is_weak(HANDLE) and not a.is_weak(ULONG)   # named typedefs aren't weak


def test_is_strong_is_structural_only():
    assert a.is_strong(KPROC) and a.is_strong(EPROC) and a.is_strong(ENUMT)
    assert not a.is_strong(d("$ABC", "struct", named=False))   # anonymous UDT
    assert not a.is_strong(QWORD) and not a.is_strong(VOIDP)
    assert not a.is_strong(HANDLE) and not a.is_strong(ULONG) and not a.is_strong(SIZE_T)
    assert not a.is_strong(None)


def test_is_concrete_admits_named_scalars_not_placeholders():
    assert a.is_concrete(KPROC) and a.is_concrete(EPROC)       # structural
    assert a.is_concrete(ULONG) and a.is_concrete(SIZE_T) and a.is_concrete(HANDLE)
    assert not a.is_concrete(QWORD) and not a.is_concrete(UINT)  # bare placeholders
    assert not a.is_concrete(d("Mystery", "scalar", named=False))
    assert not a.is_concrete(None)


def test_worth_suggesting():
    assert a._worth_suggesting(QWORD, KPROC)              # placeholder -> structural
    assert not a._worth_suggesting(UINT, ULONG)           # unsigned int -> ULONG: same width+sign
    assert a._worth_suggesting(UINT, SIZE_T)              # 4 -> 8: width differs (named typedef)
    assert a._worth_suggesting(SINT, ULONG)               # sign differs to a named typedef
    assert not a._worth_suggesting(SINT, UINT)            # int -> unsigned int: both placeholders
    assert not a._worth_suggesting(RAWQ, QWORD)           # _QWORD -> __int64: placeholder respelling
    assert not a._worth_suggesting(A_PTR, CONST_A_PTR)    # X* vs const X*
    assert not a._worth_suggesting(KPROC, KPROC)          # identical


def test_conflict_severity():
    assert a._conflict(HANDLE, KPROC) == 3           # scalar vs pointer
    assert a._conflict(KPROC, QWORD) == 3
    assert a._conflict(A_PTR, B_PTR) == 2            # different named pointees
    assert a._conflict(A_PTR, CONST_A_PTR) == 0      # same pointee modulo const
    assert a._conflict(SINT, QWORD) == 1            # width 4 vs 8
    assert a._conflict(SINT, UINT) == 1             # same width, sign differs
    assert a._conflict(ULONG, d("DWORD", "scalar", named=True, size=4, signed=False)) == 0


def test_aggregate_args_rich():
    sites = [
        {"caller": 0x100, "ea": 0x111,
         "args": [{**KPROC, "index": 0}, {**QWORD, "index": 1, "member": "@0x20"}]},
        {"caller": 0x200, "ea": 0x222,
         "args": [{**KPROC, "index": 0}, {**QWORD, "index": 1}]},
        {"caller": 0x100, "ea": 0x333, "args": [{**KPROC, "index": 0}]},
    ]
    rows = {r["index"]: r for r in a.aggregate_args_rich(sites)}
    assert rows[0]["n_sites"] == 3 and len(rows[0]["callers"]) == 2
    assert rows[0]["actuals"][0]["type"] == "_KPROCESS *" and rows[0]["actuals"][0]["count"] == 3
    assert rows[0]["actuals"][0]["cat"] == "ptr"          # descriptor survives the roll-up
    assert rows[0]["examples"] == [0x111, 0x222, 0x333]
    assert rows[1]["n_sites"] == 2 and rows[1]["member"] == "@0x20"


def test_aggregate_evidence():
    ev = a.aggregate_evidence([(KPROC, 0x11, 0x900), (KPROC, 0x22, 0x901), (B_PTR, 0x33, 0x900)])
    assert ev["n_sites"] == 3 and ev["n_distinct"] == 2
    assert ev["actuals"][0]["type"] == "_KPROCESS *" and ev["actuals"][0]["count"] == 2
    assert ev["examples"] == [0x11, 0x22, 0x33]


def test_classify_param_concretize_structural():
    row = agg([(KPROC, 7), (QWORD, 1)], n_sites=8, n_callers=4)
    for source in ("guessed", "tinfo"):
        v = a.classify_param(QWORD, source, row)
        assert v["class"] == "concretize" and v["suggest"] == "_KPROCESS *"


def test_classify_param_scalar_useful_when_width_or_sign_differs():
    # unsigned int -> size_t (4 -> 8) is a real width concretization
    v = a.classify_param(UINT, "guessed", agg([(SIZE_T, 8)], 8, 4))
    assert v and v["class"] == "concretize" and v["suggest"] == "size_t"
    # int -> ULONG flags a signedness change to a real typedef
    v = a.classify_param(SINT, "guessed", agg([(ULONG, 8)], 8, 4))
    assert v and v["suggest"] == "ULONG"


def test_classify_param_filters_pure_scalar_alias():
    # unsigned int -> ULONG: identical width and signedness, no information gained
    assert a.classify_param(UINT, "tinfo", agg([(ULONG, 9)], 9, 5)) is None
    assert a.classify_param(UINT, "guessed", agg([(ULONG, 9)], 9, 5)) is None


def test_classify_param_filters_placeholder_respelling():
    # _QWORD -> __int64 / _QWORD -> int: one generic slot spelled as another
    assert a.classify_param(RAWQ, "guessed", agg([(QWORD, 10)], 10, 5)) is None
    assert a.classify_param(RAWQ, "guessed", agg([(SINT, 10)], 10, 5)) is None


def test_classify_param_filters_const_requalification():
    # _A * vs const _A * is the same type modulo const
    assert a.classify_param(A_PTR, "tinfo", agg([(CONST_A_PTR, 9)], 9, 5)) is None


def test_collapses_typedef_aliases_via_canonical_key():
    # same underlying type, different spelling -> identical canonical key -> no finding
    pairs = [
        (d("const UNICODE_STRING *", "ptr", pointee_named=True, canon="UNICODE_STRING*"),
         d("PUNICODE_STRING", "ptr", pointee_named=True, canon="UNICODE_STRING*")),
        (d("union _LARGE_INTEGER *", "ptr", pointee_named=True, canon="LARGE_INTEGER*"),
         d("LARGE_INTEGER *", "ptr", pointee_named=True, canon="LARGE_INTEGER*")),
        (d("UNICODE_STRING *", "ptr", pointee_named=True, canon="UNICODE_STRING*"),
         d("struct _UNICODE_STRING *", "ptr", pointee_named=True, canon="UNICODE_STRING*")),
        (d("const wchar_t *", "ptr", canon="wchar_t*"),
         d("PWSTR", "ptr", pointee_named=True, canon="wchar_t*")),
    ]
    for have, dom in pairs:
        assert not a._worth_suggesting(have, dom)
        assert a.classify_param(have, "tinfo", agg([(dom, 9)], 9, 5)) is None
    # a genuinely different pointee still suggests
    foo = d("_FOO *", "ptr", pointee="_FOO", pointee_named=True, canon="FOO*")
    assert a._worth_suggesting(d("__int64", size=8, signed=True, canon="_int64"), foo)


def test_classify_param_mismatch_is_tinfo_only():
    # declared a struct by value, but a pointer is consistently passed (sev 3)
    row = agg([(KPROC, 6)], n_sites=6, n_callers=3)
    v = a.classify_param(EPROC, "tinfo", row)
    assert v["class"] == "mismatch" and v["severity"] == 3
    assert a.classify_param(EPROC, "guessed", row) is None   # a guess cannot be "wrong"


def test_classify_param_mismatch_different_pointee():
    v = a.classify_param(A_PTR, "tinfo", agg([(B_PTR, 5)], n_sites=5, n_callers=3))
    assert v["class"] == "mismatch" and v["severity"] == 2


def test_classify_param_rejections():
    assert a.classify_param(QWORD, "tinfo", agg([(KPROC, 2)], 2, 2)) is None          # < min_sites
    assert a.classify_param(QWORD, "tinfo", agg([(KPROC, 3)], 3, 1)) is None          # < min_callers
    assert a.classify_param(QWORD, "tinfo", agg([(KPROC, 2), (QWORD, 2)], 4, 3)) is None  # agree .5
    assert a.classify_param(KPROC, "tinfo", agg([(KPROC, 5)], 5, 3)) is None          # dom == decl
    assert a.classify_param(None, "tinfo", agg([(KPROC, 5)], 5, 3)) is None           # beyond arity


def test_classify_param_custom_thresholds():
    thr = {"min_sites": 2, "min_callers": 1, "min_agree": 0.8, "min_local_sites": 2}
    v = a.classify_param(QWORD, "guessed", agg([(KPROC, 2)], 2, 1), thr)
    assert v and v["class"] == "concretize"


def test_dropped_thresholds_still_respect_worth_suggesting():
    """--all floors: a single site / single caller / any agreement is shown, but
    the worth-suggesting noise filter is untouched."""
    drop = {"min_sites": 1, "min_callers": 1, "min_agree": 0.0, "min_local_sites": 1}
    # one site, one caller, structural -> now surfaced
    v = a.classify_param(QWORD, "guessed", agg([(KPROC, 1)], 1, 1), drop)
    assert v and v["class"] == "concretize"
    # a 1-of-3 minority dominant still shows (agreement floor dropped)
    v = a.classify_param(QWORD, "guessed", agg([(KPROC, 1), (RAWQ, 1), (UINT, 1)], 3, 1), drop)
    assert v and v["suggest"] == "_KPROCESS *"
    # noise stays filtered no matter how low the thresholds go
    assert a.classify_param(UINT, "guessed", agg([(ULONG, 1)], 1, 1), drop) is None
    assert a.classify_param(RAWQ, "guessed", agg([(QWORD, 1)], 1, 1), drop) is None
    assert a.classify_param(A_PTR, "tinfo", agg([(CONST_A_PTR, 1)], 1, 1), drop) is None


def test_classify_local():
    e = a.aggregate_evidence([(KPROC, 0x11, 0x900), (KPROC, 0x22, 0x901)])
    v = a.classify_local(QWORD, e)
    assert v["class"] == "concretize" and v["suggest"] == "_KPROCESS *" and v["n_sites"] == 2

    # unsigned int -> size_t (width differs) is a useful local concretization
    sz = a.aggregate_evidence([(SIZE_T, 0x11, 0x900), (SIZE_T, 0x22, 0x901)])
    assert a.classify_local(UINT, sz)["class"] == "concretize"

    one = a.aggregate_evidence([(KPROC, 0x11, 0x900)])
    assert a.classify_local(QWORD, one) is None                       # < min_local_sites

    assert a.classify_local(HANDLE, e)["class"] == "mismatch"         # scalar vs ptr (sev 3)

    diff_pointee = evid([(B_PTR, 2)], n_sites=2)
    assert a.classify_local(A_PTR, diff_pointee) is None             # local mismatch only at sev 3
    assert a.classify_local(A_PTR, evid([(CONST_A_PTR, 2)], n_sites=2)) is None  # const requalify
    assert a.classify_local(KPROC, e) is None                        # dom == cur


def test_classify_local_filters_pure_scalar_alias():
    same = a.aggregate_evidence([(ULONG, 0x1, 0x9), (ULONG, 0x2, 0xA)])
    assert a.classify_local(UINT, same) is None                      # unsigned int -> ULONG: noise


def test_score_and_rank():
    mis = {"class": "mismatch", "severity": 3, "agree": 0.9, "n_distinct": 5,
           "n_sites": 10, "ea": 0x10, "kind": "param", "slot": "a0"}
    con = {"class": "concretize", "severity": 0, "agree": 0.95, "n_distinct": 8,
           "n_sites": 20, "ea": 0x20, "kind": "param", "slot": "a1"}
    ranked = a.rank_findings([con, mis])
    assert ranked[0] is mis                          # mismatches float above concretizations
    assert mis["score"] > con["score"]

    hi = {"class": "mismatch", "severity": 3, "agree": 0.99, "n_distinct": 9,
          "n_sites": 20, "ea": 0x40, "kind": "param", "slot": "y"}
    lo = {"class": "mismatch", "severity": 3, "agree": 0.81, "n_distinct": 2,
          "n_sites": 3, "ea": 0x10, "kind": "param", "slot": "x"}
    assert a.rank_findings([lo, hi])[0] is hi        # within a class, higher score first
    assert len(a.rank_findings([lo, hi], cap=1)) == 1


def test_rank_stable_tie_break_by_address():
    p = {"class": "concretize", "severity": 0, "agree": 0.9, "n_distinct": 3,
         "n_sites": 5, "ea": 0x30, "kind": "param", "slot": "a"}
    q = {"class": "concretize", "severity": 0, "agree": 0.9, "n_distinct": 3,
         "n_sites": 5, "ea": 0x20, "kind": "param", "slot": "a"}
    assert [f["ea"] for f in a.rank_findings([p, q])] == [0x20, 0x30]
