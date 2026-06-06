"""Output-only token-compaction transforms applied by the formatters.

Both are pure `str -> str` and never touch IDA state or the RPC result dicts — they
run on already-formatted text headed for the user, so the verbose spellings still
round-trip through declare/settype/typeof on the way back in.

`shorten` rewrites width-named/pseudo integer spellings to a single uppercase
Windows-typedef style — BYTE/WORD/DWORD/QWORD (unsigned), CHAR/SHORT/INT/INT64
(signed). Every canonical here is a NATIVE IDA type, so the short form parses back
in. 128-bit (_OWORD / __int128 / OWORD / INT128) is deliberately excluded: it has no
native short form and would not round-trip, so those spellings are left untouched.
"""

import re

WIDTH_INTS = {
    "unsigned __int64": "QWORD", "unsigned __int32": "DWORD",
    "unsigned __int16": "WORD", "unsigned __int8": "BYTE",
    "signed __int64": "INT64", "signed __int32": "INT",
    "signed __int16": "SHORT", "signed __int8": "CHAR",
    "__int64": "INT64", "__int32": "INT", "__int16": "SHORT", "__int8": "CHAR",
}
C_INTS = {"unsigned int": "DWORD", "unsigned short": "WORD", "unsigned char": "BYTE",
          "int": "INT", "short": "SHORT", "char": "CHAR"}
PSEUDO_INTS = {"_QWORD": "QWORD", "_DWORD": "DWORD", "_WORD": "WORD", "_BYTE": "BYTE"}


def compile_subst(*mappings):
    """Build a (pattern, mapping) pair that matches any key at identifier boundaries,
    longest key first so `unsigned __int64` wins over the `__int64` inside it."""
    merged = {}
    for m in mappings:
        merged.update(m)
    keys = sorted(merged, key=len, reverse=True)
    pat = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(re.escape(k) for k in keys) + r")(?![A-Za-z0-9_])")
    return pat, merged


def substitute(compiled, text):
    pat, mapping = compiled
    return pat.sub(lambda m: mapping[m.group(1)], text)


_SHORTEN = compile_subst(WIDTH_INTS, C_INTS, PSEUDO_INTS)


def shorten(text):
    """Rewrite round-trip-safe integer type spellings to their cheapest native form."""
    return substitute(_SHORTEN, text)


_DISAS_GUTTER = re.compile(r"^([0-9a-fA-F]{8,16})  (.*)$")


def _squash_spaces(s):
    """Collapse every interior run of 2+ spaces to one. Leading spaces (no preceding
    non-space) are left intact, so this never eats indentation or a hex gutter."""
    return re.sub(r"(\S)  +", r"\1 ", s)


def squash_insn(text):
    """Squash one instruction cell's operand-alignment padding to single spaces.
    For per-field use in row/table formatters (xrefs/calls/strrefs/search) where the
    surrounding address and direction columns must stay aligned, so only the disasm
    cell is collapsed — never the leading address gutter or indentation."""
    return _squash_spaces(text)


def squash_disas(text):
    """Drop operand-alignment padding and shrink the 2-space gutter separator to one.
    The leading hex address is preserved byte-for-byte, so it still resolves."""
    out = []
    for line in text.split("\n"):
        m = _DISAS_GUTTER.match(line)
        out.append(m.group(1) + " " + _squash_spaces(m.group(2)) if m else _squash_spaces(line))
    return "\n".join(out)


def hx(value):
    """Compact hex for table cells; command arguments accept bare hex."""
    return f"{value:x}" if isinstance(value, int) else str(value)


def hex_width(values, default=8):
    """Widest `%x` rendering across `values` (an iterable of ints), for zero-padding
    a column so every address lines up. `default` is used when `values` is empty."""
    return max((len(f"{v:x}") for v in values), default=default)


def escape_text(text, limit=None, tabs=True):
    """One-line, optionally length-capped echo of free text. Escapes CR and LF (and
    TAB unless `tabs=False`); when `limit` is given and the escaped string exceeds it,
    truncate to `limit-1` chars plus an ellipsis."""
    flat = str(text).replace("\r", "\\r").replace("\n", "\\n")
    if tabs:
        flat = flat.replace("\t", "\\t")
    if limit is not None and len(flat) > limit:
        return flat[: limit - 1] + "…"
    return flat


def count(n, truncated):
    """Render a count, suffixing `+` when the producing phase hit a cap or budget."""
    return f"{n}+" if truncated else str(n)
