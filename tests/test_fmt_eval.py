"""Golden tests for the eval (?) result formatter (pure, no IDA)."""

from idb.fmt import eval as fmt_eval


def _fmt(value, width=None, be=False):
    return fmt_eval.format_eval({"value": str(value), "width": width, "be": be})


def test_confirmed_previews():
    assert _fmt(0x2A) == "2a  0n42  '*'  8bit"
    assert _fmt(0xFF) == "ff  0n255 / 0n-1  8bit"
    assert _fmt(0x6C6C6568) == "6c6c6568  0n1819043176  'hell'  32bit"


def test_negative_value_auto_widths_to_8bit():
    assert _fmt(-1) == "ff  0n255 / 0n-1  8bit"


def test_zero_has_no_ascii():
    assert _fmt(0) == "00  0n0  8bit"


def test_width_override_pins_display_and_masks():
    assert _fmt(-1, width=32) == "ffffffff  0n4294967295 / 0n-1  32bit"


def test_big_endian_reverses_ascii_bytes():
    assert _fmt(0x6C6C6568, be=True) == "6c6c6568  0n1819043176  'lleh'  32bit"


def test_value_beyond_64_bits_grows_width():
    out = _fmt(0xFFFFFFFFFFFFFFFF * 2)   # 0x1fffffffffffffffe, 65 bits
    assert out.endswith("128bit")
    assert len(out.split()[0]) == 32     # hex zero-padded to 128 bits
