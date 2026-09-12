"""Shared worker helpers.

parse_addr / paginate / name_filter are pure (no ida_*) and Tier-1 testable.
The rest import ida_* lazily, inside the function, so importing this module never
pulls in IDA on its own.
"""

import re
import fnmatch

from idb import protocol
from idb.errors import AMBIGUOUS, IdbError

_SENTINEL = object()


def parse_int(value, hex_default, what="number", code=protocol.BAD_ARGS):
    """The one integer syntax for every numeric argument: `0x` is hex, `0n` is
    decimal, and bare digits follow `hex_default` (True for addresses, byte
    offsets, sizes and immediates; False for counts, indexes and enum values).
    Ints pass through. Negative or malformed text raises `code`."""
    if isinstance(value, int):
        return value
    s = str(value).strip()
    low = s.lower()
    if low.startswith("0x"):
        digits, base = s[2:], 16
    elif low.startswith("0n"):
        digits, base = s[2:], 10
    else:
        digits, base = s, (16 if hex_default else 10)
    if not re.fullmatch(r"[0-9a-fA-F]+" if base == 16 else r"[0-9]+", digits):
        bare = "bare hex" if hex_default else "decimal"
        raise IdbError(code, f"{what} must be {bare}, 0x<hex>, or 0n<decimal>, not {value!r}")
    return int(digits, base)


def parse_addr(value):
    """Numeric address: bare hex (windbg default), 0x hex, or 0n decimal. No symbols."""
    return parse_int(value, hex_default=True, what="address", code=protocol.BAD_ADDRESS)


def paginate(iterable, offset=0, count=None):
    """Apply offset/count WHILE walking an iterator (never build-then-cap).
    Returns (items, next_offset); next_offset is None once the source is
    exhausted within the page, else the offset to resume from."""
    offset = int(offset or 0)
    it = iter(iterable)
    for _ in range(offset):
        if next(it, _SENTINEL) is _SENTINEL:
            return [], None
    if count is None:
        return list(it), None
    items = []
    for _ in range(int(count)):
        value = next(it, _SENTINEL)
        if value is _SENTINEL:
            return items, None
        items.append(value)
    has_more = next(it, _SENTINEL) is not _SENTINEL
    return items, (offset + len(items)) if has_more else None


def page_meta(items, next_offset, total=None):
    """Build envelope meta for a paginated result, or None if nothing was cut."""
    if next_offset is None and total is None:
        return None
    meta = {"shown": len(items)}
    if next_offset is not None:
        meta["truncated"] = True
        meta["next_offset"] = next_offset
    if total is not None:
        meta["total"] = total
    return meta


def name_filter(pattern):
    """Predicate over a name. '/re/' -> regex; '*'/'?' -> glob; else case-
    insensitive substring. None matches everything."""
    if pattern is None:
        return lambda name: True
    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        rx = re.compile(pattern[1:-1], re.IGNORECASE)
        return lambda name: rx.search(name or "") is not None
    if "*" in pattern or "?" in pattern:
        pat = pattern.lower()
        return lambda name: fnmatch.fnmatch((name or "").lower(), pat)
    needle = pattern.lower()
    return lambda name: needle in (name or "").lower()


def import_ea(name):
    """IAT slot of the import called `name` (as shown by `imports`), or BADADDR.
    Imports have no symbol under their bare name: IDA names the slot
    `__imp_<name>` and only user-mode thunks get the bare name."""
    import ida_idaapi
    import ida_name
    import ida_nalt

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "__imp_" + name)
    if ea != ida_idaapi.BADADDR:
        return ea
    found = [ida_idaapi.BADADDR]

    def cb(slot, imp_name, ordinal):
        if imp_name == name:
            found[0] = slot
            return False
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, cb)
        if found[0] != ida_idaapi.BADADDR:
            break
    return found[0]


_AMBIGUOUS_LIST_CAP = 16


def _ambiguous(name, matches):
    lines = [f"{name!r} matches {len(matches)} names; use one of:"]
    lines += [f"  {ea:#x}  {raw}" for ea, raw in matches[:_AMBIGUOUS_LIST_CAP]]
    if len(matches) > _AMBIGUOUS_LIST_CAP:
        lines.append(f"  ... {len(matches) - _AMBIGUOUS_LIST_CAP} more")
    raise IdbError(AMBIGUOUS, "\n".join(lines),
                   [{"ea": ea, "name": raw} for ea, raw in matches])


def scan_names(name):
    """Slow-path lookup over the whole name table, used only after the exact
    lookups miss. Two tiers, each matching `name` against every raw name (with
    any `__imp_` prefix ignored) and its demangled forms: the name-only form
    Hex-Rays prints (`Foo::bar`) and the short form with parameters
    (`Foo::bar(int)`). Tier 1 is exact-case, tier 2 is case-folded; the first
    non-empty tier is used, and it must hold exactly one address or the lookup
    fails with AMBIGUOUS listing every candidate. Returns BADADDR on no match."""
    import ida_idaapi
    import ida_name
    import idautils

    want = name.lower()
    exact = []
    folded = []
    for ea, raw in idautils.Names():
        forms = [raw[len("__imp_"):]] if raw.startswith("__imp_") else [raw]
        for flags in (ida_name.MNG_NODEFINIT, ida_name.MNG_SHORT_FORM):
            demangled = ida_name.demangle_name(raw, flags)
            if demangled:
                forms.append(demangled)
        if name in forms:
            exact.append((ea, raw))
        elif any(form.lower() == want for form in forms):
            folded.append((ea, raw))
    matches = exact or folded
    if not matches:
        return ida_idaapi.BADADDR
    if len(matches) > 1:
        _ambiguous(name, matches)
    return matches[0][0]


def resolve_target(value):
    """ea from int, explicit 0x/0n number, a symbol name, an import name
    (-> its IAT slot), a case-folded or demangled name, or bare-hex fallback."""
    import ida_idaapi
    import ida_name

    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.lower().startswith(("0x", "0n")):
        return parse_addr(s)
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, s)
    if ea == ida_idaapi.BADADDR:
        ea = import_ea(s)
    if ea == ida_idaapi.BADADDR:
        ea = scan_names(s)
    if ea != ida_idaapi.BADADDR:
        return ea
    try:
        return parse_addr(s)
    except IdbError:
        raise IdbError(protocol.NOT_FOUND, f"no symbol or address named {value!r}")


def til():
    import ida_typeinf

    return ida_typeinf.get_idati()


def disasm_at(ea):
    """Tag-free disassembly text at `ea`. IDA produces no line for an unmapped or
    BADADDR address and tag_remove rejects the resulting null, so degrade to a
    marker rather than raising out of the middle of a listing."""
    import ida_bytes
    import ida_lines

    line = ida_lines.generate_disasm_line(ea, 0)
    if line is None:
        return "<unmapped>" if not ida_bytes.is_mapped(ea) else "<no disasm>"
    return ida_lines.tag_remove(line)


def func_name_at(ea):
    import ida_funcs

    f = ida_funcs.get_func(ea)
    return ida_funcs.get_func_name(f.start_ea) if f else None


def require_func(target, msg=None):
    """Resolve `target` to a function, raising NOT_FOUND if there is none. The
    message differs by call site (most say 'no function at X', a few 'no function
    X'), so pass `msg` to keep it byte-identical."""
    import ida_funcs

    ea = resolve_target(target)
    f = ida_funcs.get_func(ea)
    if f is None:
        raise IdbError(protocol.NOT_FOUND, msg or f"no function at {target!r}")
    return f


def require_mapped(ea):
    """Raise BAD_ADDRESS unless `ea` is a mapped address; return it otherwise."""
    import ida_bytes

    if not ida_bytes.is_mapped(ea):
        raise IdbError(protocol.BAD_ADDRESS, f"address {ea:#x} is not mapped")
    return ea


def resolve_mapped(addr, offset=0, width=1):
    """Resolve `addr` (+ offset*width) to a mapped ea or raise BAD_ADDRESS."""
    return require_mapped(resolve_target(addr) + (offset or 0) * width)


def segment_end(ea):
    """End ea of the segment containing `ea`, or the database max ea if none."""
    import ida_segment
    import ida_ida

    seg = ida_segment.getseg(ea)
    return seg.end_ea if seg else ida_ida.inf_get_max_ea()


def require_hexrays(msg):
    """Initialize the Hex-Rays plugin or raise IDA_ERROR with `msg` (which varies
    by call site)."""
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        raise IdbError(protocol.IDA_ERROR, msg)


def safe_decompile(ea):
    """Decompile `ea` fresh (the cache is not invalidated on callee/struct retype),
    raising IDA_ERROR on failure or a null result. Use only at sites whose policy
    is to raise; loop sites that `continue` and `(None, None)` sites stay inline."""
    import ida_hexrays

    ida_hexrays.mark_cfunc_dirty(ea)
    try:
        cfunc = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure as exc:
        raise IdbError(protocol.IDA_ERROR, f"decompilation failed: {exc}")
    if cfunc is None:
        raise IdbError(protocol.IDA_ERROR, "decompilation returned null")
    return cfunc


def paged(make_gen, offset, count, total=False, default=None, qty=None):
    """Paginate a freshly-built generator and wrap it in the listing envelope.
    `qty` is a total the caller already knows in constant time and is always
    reported. Without it, `total` re-runs `make_gen` to count (a full scan), so
    `make_gen` must yield a fresh iterator each call. `default` caps an unset
    `count`."""
    n = count if count else default
    items, next_offset = paginate(make_gen(), offset, n)
    if qty is None and total:
        qty = sum(1 for _ in make_gen())
    return {"data": items}, page_meta(items, next_offset, qty)
