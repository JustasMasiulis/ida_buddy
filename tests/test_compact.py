"""Unit tests for the shipped output-compaction transforms (no IDA required)."""

import pytest

from idb.fmt.compact import shorten, squash_disas, squash_insn


def test_shorten_width_named_integers():
    assert shorten("__int64 a") == "INT64 a"
    assert shorten("__int32 b; __int8 c") == "INT b; CHAR c"
    assert shorten("signed __int16 v;") == "SHORT v;"


def test_shorten_c_base_and_pseudo_types():
    assert shorten("unsigned int x") == "DWORD x"
    assert shorten("int x; char c; short s;") == "INT x; CHAR c; SHORT s;"
    assert shorten("_DWORD d; _QWORD q; _BYTE b; _WORD w") == "DWORD d; QWORD q; BYTE b; WORD w"


def test_shorten_prefers_longest_key():
    assert shorten("unsigned __int64 x") == "QWORD x"
    assert shorten("unsigned int n") == "DWORD n"


@pytest.mark.parametrize("text", ["a__int64", "__int64_t", "my__int64_field", "_DWORDx"])
def test_shorten_respects_identifier_boundaries(text):
    assert shorten(text) == text


def test_shorten_rewrites_at_punctuation_boundaries():
    assert shorten("(__int64)x") == "(INT64)x"
    assert shorten("f(a, unsigned int b)") == "f(a, DWORD b)"


@pytest.mark.parametrize("text", [
    "__int128 x", "unsigned __int128 z", "signed __int128 w", "_OWORD y",
])
def test_shorten_leaves_128bit_untouched(text):
    assert shorten(text) == text


def test_squash_disas_preserves_gutter_and_collapses_padding():
    line = "fffff80000203390  mov     [rsp+8], r8"
    assert squash_disas(line) == "fffff80000203390 mov [rsp+8], r8"


def test_squash_disas_keeps_address_bytes_intact():
    out = squash_disas("fffff80000203390  push    rbp")
    assert out.split(" ", 1)[0] == "fffff80000203390"


def test_squash_disas_squashes_header_lines():
    assert squash_disas("sub_X  (.text @ 0x401000):") == "sub_X (.text @ 0x401000):"


def test_squash_insn_collapses_operand_padding():
    assert squash_insn("mov     [rsp+8], r8") == "mov [rsp+8], r8"
    assert squash_insn("call    sub_401300") == "call sub_401300"


def test_squash_insn_is_noop_on_already_tight_text():
    assert squash_insn("call sub_401300") == "call sub_401300"
