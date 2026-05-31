"""Tier-1 tests for the pure expression evaluator (no IDA).

Operands resolve through an injected callable; bare numbers are hex (windbg
default) via parse_addr, so `10` is 0x10 and decimal needs the `0n` prefix.
"""

import pytest

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp
from idb import expr

_NAMES = {"main": 0x401000, "foo": 0x10}


def _resolve(token):
    return _NAMES[token] if token in _NAMES else idahelp.parse_addr(token)


def _eval(text, wrap_bits=64):
    return expr.evaluate(text, _resolve, wrap_bits)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2 + 3", 5),                       # bare 2,3 are hex 0x2,0x3
        ("0n10 + 0n5", 15),
        ("0n2 + 0n3 * 0n4", 14),            # * binds tighter than +
        ("(0n2 + 0n3) * 0n4", 20),
        ("0n10 - 0n3 - 0n2", 5),            # left-associative
        ("-0n5", -5),
        ("- -0n5", 5),
        ("~0", -1),
        ("0xf0 | 0x0f", 0xFF),
        ("0xff & 0x0f", 0x0F),
        ("0xff ^ 0x0f", 0xF0),
        ("1 << 0n8", 0x100),
        ("0x100 >> 0n4", 0x10),
        ("1 << 0n4 + 1", 1 << 5),           # + binds tighter than <<
        ("1 | 0n2 & 0n3", 3),               # & binds tighter than |
        ("0n7 / 0n2", 3),
        ("-0n7 / 0n2", -3),                 # truncate toward zero, not floor
        ("0n7 % 0n3", 1),
        ("-0n7 % 0n3", -1),                 # remainder takes the dividend's sign
        ("main + 0x10", 0x401010),
        ("main - foo", 0x401000 - 0x10),
    ],
)
def test_evaluate_values(text, expected):
    assert _eval(text) == expected


def test_plain_ops_are_exact_but_percent_ops_wrap():
    assert _eval("0xffffffff + 1", 32) == 0x100000000      # plain + never wraps
    assert _eval("0xffffffff +% 1", 32) == 0               # wrap at 32 bits
    assert _eval("0xffffffff +% 1", 64) == 0x100000000     # fits in 64, no wrap
    assert _eval("0xffffffff *% 0xffffffff", 32) == 1       # (2^32-1)^2 mod 2^32
    assert _eval("0 -% 1", 32) == 0xFFFFFFFF


@pytest.mark.parametrize(
    "text",
    ["1 / 0", "1 % 0", "(1 + 2", "1 2", "1 = 2", "* 5", "1 << -1", "1 << 0n9999", "", "   "],
)
def test_evaluate_rejects(text):
    with pytest.raises(IdbError) as ei:
        _eval(text)
    assert ei.value.code == protocol.BAD_ARGS


def test_name_resolution_error_propagates():
    def resolve(_token):
        raise IdbError(protocol.NOT_FOUND, "nope")

    with pytest.raises(IdbError) as ei:
        expr.evaluate("missing + 1", resolve, 64)
    assert ei.value.code == protocol.NOT_FOUND


def test_tokenize_splits_percent_and_remainder():
    assert expr.tokenize("a +% b % c") == ["a", "+%", "b", "%", "c"]
    assert expr.tokenize("a*c%b") == ["a", "*", "c", "%", "b"]
    assert expr.tokenize("a*%b") == ["a", "*%", "b"]
