"""Pure expression evaluator for the `eval` (`?`) command.

No ida_* imports: operands are resolved through an injected `resolve(token)->int`
callable, so the tokenizer/parser/evaluator are Tier-1 testable. Plain + - * are
exact (arbitrary precision); the Zig wrapping operators +% -% *% mask to
`wrap_bits`. / and % are C-style, truncated toward zero.
"""

import re

from idb import protocol
from idb.errors import IdbError

_TOKEN = re.compile(r"\s*(\+%|-%|\*%|<<|>>|[-+*/%&|^~()]|[A-Za-z0-9_$.?@]+)")

_BP = {
    "|": 1, "^": 2, "&": 3, "<<": 4, ">>": 4,
    "+": 5, "-": 5, "+%": 5, "-%": 5,
    "*": 6, "/": 6, "%": 6, "*%": 6,
}

_MAX_SHIFT = 4096


def _bad(message):
    raise IdbError(protocol.BAD_ARGS, message)


def tokenize(expr):
    tokens, pos = [], 0
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if m is None:
            break
        tokens.append(m.group(1))
        pos = m.end()
    if expr[pos:].strip():
        _bad(f"cannot parse near {expr[pos:].strip()!r}")
    return tokens


def _trunc_div(a, b):
    if b == 0:
        _bad("division by zero")
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _shift(a, count, left):
    if count < 0:
        _bad("negative shift count")
    if count > _MAX_SHIFT:
        _bad(f"shift count {count} too large")
    return (a << count) if left else (a >> count)


def _apply(op, a, b, mask):
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "+%":
        return (a + b) & mask
    if op == "-%":
        return (a - b) & mask
    if op == "*%":
        return (a * b) & mask
    if op == "/":
        return _trunc_div(a, b)
    if op == "%":
        return a - _trunc_div(a, b) * b
    if op == "&":
        return a & b
    if op == "|":
        return a | b
    if op == "^":
        return a ^ b
    if op == "<<":
        return _shift(a, b, True)
    return _shift(a, b, False)


def evaluate(expr, resolve, wrap_bits):
    tokens = tokenize(expr)
    if not tokens:
        _bad("empty expression")
    mask = (1 << wrap_bits) - 1
    i = 0

    def parse_prefix():
        nonlocal i
        if i >= len(tokens):
            _bad("unexpected end of expression")
        tok = tokens[i]
        i += 1
        if tok == "(":
            value = parse(0)
            if i >= len(tokens) or tokens[i] != ")":
                _bad("missing ')'")
            i += 1
            return value
        if tok == "-":
            return -parse_prefix()
        if tok == "~":
            return ~parse_prefix()
        if tok in _BP or tok == ")":
            _bad(f"unexpected operator {tok!r}")
        return resolve(tok)

    def parse(min_bp):
        nonlocal i
        left = parse_prefix()
        while i < len(tokens) and tokens[i] in _BP and _BP[tokens[i]] >= min_bp:
            op = tokens[i]
            i += 1
            left = _apply(op, left, parse(_BP[op] + 1), mask)
        return left

    value = parse(0)
    if i != len(tokens):
        _bad(f"trailing tokens from {tokens[i]!r}")
    return value
