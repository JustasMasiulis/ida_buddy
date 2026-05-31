from idb import triage


def test_split_prefix_camel_and_underscore():
    assert triage.split_prefix("PsLookupProcessByProcessId") == "Ps"
    assert triage.split_prefix("WfpFilter_Add") == "WfpFilter"
    assert triage.split_prefix("sub_140001000") == "sub"
    assert triage.split_prefix("ExAllocatePool2") == "Ex"


def test_split_prefix_strips_decoration():
    assert triage.split_prefix("__imp_NdisReturn") == "imp"
    assert triage.split_prefix("?Foo@@") == "Foo"


def test_split_prefix_degenerate():
    assert triage.split_prefix("") == ""
    assert triage.split_prefix("_") == ""
    assert triage.split_prefix("X") == "X"


def test_group_prefixes_sorted_and_thresholded():
    names = ["PsA", "PsB", "PsC", "WfpFilter_X", "WfpFilter_Y", "Lonely"]
    groups = triage.group_prefixes(names)
    assert groups == [{"prefix": "Ps", "count": 3}, {"prefix": "WfpFilter", "count": 2}]


def test_group_prefixes_respects_min_group():
    assert triage.group_prefixes(["Aa", "Bb"]) == []
    assert triage.group_prefixes(["Wfp_a", "Wfp_b"]) == [{"prefix": "Wfp", "count": 2}]


def test_group_prefixes_empty():
    assert triage.group_prefixes([]) == []


def test_humanize_groups():
    assert triage.humanize_groups([{"prefix": "Ps", "count": 5}]) == ["Ps* (5)"]


def test_is_dummy_name():
    assert triage.is_dummy_name("sub_140001000")
    assert triage.is_dummy_name("nullsub_3")
    assert triage.is_dummy_name("loc_1400ABCD")
    assert not triage.is_dummy_name("WfpRefCount")
    assert not triage.is_dummy_name("")


def _callee(name, size, callers, kind="func", named=None):
    return {"name": name, "size": size, "callers": callers, "kind": kind,
            "named": (not triage.is_dummy_name(name)) if named is None else named}


def test_rank_callees_unnamed_then_small_hot_then_imports():
    callees = [
        _callee("WfpKnown", 0x20, 200),                # named real func
        _callee("ExAllocatePool2", 0, 800, "import"),  # import: last
        _callee("sub_2", 0x40, 3),                     # un-named, larger/colder
        _callee("sub_1", 0x10, 50),                    # un-named, small+hot: first
    ]
    ranked = triage.rank_callees(callees)
    assert [c["name"] for c in ranked] == ["sub_1", "sub_2", "WfpKnown", "ExAllocatePool2"]


def test_rank_callees_cap():
    callees = [_callee(f"sub_{i}", 0x10, i) for i in range(5)]
    assert len(triage.rank_callees(callees, cap=2)) == 2


def test_rank_callees_stable_within_tier():
    a = _callee("sub_a", 0x10, 5)
    b = _callee("sub_b", 0x10, 5)
    assert [c["name"] for c in triage.rank_callees([a, b])] == ["sub_a", "sub_b"]


def test_node_complexity_and_suggested_depth():
    simple = {"size": 0x10, "callees": 0}
    complex_ = {"size": 0x400, "callees": 12}
    chain = [simple, simple, complex_, simple]
    # stays simple for the two cheap leading nodes, stops before the explosion
    assert triage.helper_suggested_depth(chain, budget=0x80) == 2
    assert triage.helper_suggested_depth([], budget=0x80) == 0
    assert triage.helper_suggested_depth([simple], budget=0x80) == 1


def test_aggregate_arg_types_counts_and_member():
    sites = [
        {"args": [{"index": 0, "type": "FOO*", "expr": "a1"},
                  {"index": 1, "type": "BAR*", "expr": "v->Params", "member": "@0x20"}]},
        {"args": [{"index": 0, "type": "FOO*", "expr": "a1"},
                  {"index": 1, "type": "_QWORD", "expr": "0"}]},
    ]
    rows = triage.aggregate_arg_types(sites)
    assert rows[0] == {"index": 0, "actuals": [{"type": "FOO*", "count": 2}], "member": None}
    assert rows[1]["index"] == 1
    assert rows[1]["actuals"] == [{"type": "BAR*", "count": 1}, {"type": "_QWORD", "count": 1}]
    assert rows[1]["member"] == "@0x20"
