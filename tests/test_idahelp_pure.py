import pytest

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp


def test_parse_addr_forms():
    assert idahelp.parse_addr(0x401000) == 0x401000
    assert idahelp.parse_addr("0x401000") == 0x401000
    assert idahelp.parse_addr("0X401000") == 0x401000
    assert idahelp.parse_addr("0n4096") == 4096
    assert idahelp.parse_addr("401000") == 0x401000  # bare hex (windbg default)
    assert idahelp.parse_addr("deadbeef") == 0xDEADBEEF


@pytest.mark.parametrize("bad", ["xyz", "sub_401000", "0xZZ", ""])
def test_parse_addr_rejects(bad):
    with pytest.raises(IdbError) as ei:
        idahelp.parse_addr(bad)
    assert ei.value.code == protocol.BAD_ADDRESS


def test_paginate_basic():
    assert idahelp.paginate(range(10), 0, 3) == ([0, 1, 2], 3)
    assert idahelp.paginate(range(10), 0, None) == (list(range(10)), None)
    assert idahelp.paginate(range(3), 0, 5) == ([0, 1, 2], None)
    assert idahelp.paginate(range(10), 8, 5) == ([8, 9], None)
    assert idahelp.paginate(range(10), 0, 10) == (list(range(10)), None)
    assert idahelp.paginate(range(11), 0, 10) == (list(range(10)), 10)
    assert idahelp.paginate(range(10), 20, 3) == ([], None)


def test_paginate_resume_cursor():
    items, nxt = idahelp.paginate(range(100), 0, 25)
    assert nxt == 25 and items[-1] == 24
    items2, nxt2 = idahelp.paginate(range(100), nxt, 25)
    assert items2[0] == 25 and nxt2 == 50


def test_name_filter_substring_glob_regex():
    assert idahelp.name_filter(None)("whatever") is True
    sub = idahelp.name_filter("foo")
    assert sub("xFOOy") and not sub("bar")
    glob = idahelp.name_filter("sub_*")
    assert glob("sub_401000") and not glob("main")
    rx = idahelp.name_filter("/^sub_[0-9a-f]+$/")
    assert rx("sub_401000") and not rx("sub_xyz")


def test_page_meta():
    assert idahelp.page_meta([1, 2, 3], None) is None
    assert idahelp.page_meta([1, 2, 3], 3) == {"shown": 3, "truncated": True, "next_offset": 3}
    assert idahelp.page_meta([1, 2, 3], None, total=10) == {"shown": 3, "total": 10}


def test_paged_envelope():
    result, meta = idahelp.paged(lambda: iter(range(10)), 0, 3)
    assert result == {"data": [0, 1, 2]}
    assert meta == {"shown": 3, "truncated": True, "next_offset": 3}


def test_paged_default_cap():
    result, meta = idahelp.paged(lambda: iter(range(5)), 0, None, default=2)
    assert result["data"] == [0, 1] and meta["next_offset"] == 2


def test_paged_total_rebuilds_generator():
    result, meta = idahelp.paged(lambda: iter(range(10)), 0, 3, total=True)
    assert result["data"] == [0, 1, 2]
    assert meta["total"] == 10 and meta["next_offset"] == 3


def test_paged_no_truncation_no_meta():
    result, meta = idahelp.paged(lambda: iter([1, 2]), 0, None)
    assert result == {"data": [1, 2]} and meta is None
