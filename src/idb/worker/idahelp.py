"""Shared worker helpers.

parse_addr / paginate / name_filter are pure (no ida_*) and Tier-1 testable.
The rest import ida_* lazily, inside the function, so importing this module never
pulls in IDA on its own.
"""

import re
import fnmatch

from idb import protocol
from idb.errors import IdbError

_SENTINEL = object()


def parse_addr(value):
    """int | '0x..' hex | '0n..' decimal | bare hex (windbg default). No symbols."""
    if isinstance(value, int):
        return value
    s = str(value).strip()
    try:
        low = s.lower()
        if low.startswith("0x"):
            return int(s, 16)
        if low.startswith("0n"):
            return int(s[2:], 10)
        if re.fullmatch(r"[0-9a-fA-F]+", s):
            return int(s, 16)
    except ValueError:
        pass
    raise IdbError(protocol.BAD_ADDRESS, f"cannot parse address: {value!r}")


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


def resolve_target(value):
    """ea from int, explicit 0x/0n number, a symbol name, or bare-hex fallback."""
    import ida_idaapi
    import ida_name

    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.lower().startswith(("0x", "0n")):
        return parse_addr(s)
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, s)
    if ea != ida_idaapi.BADADDR:
        return ea
    try:
        return parse_addr(s)
    except IdbError:
        raise IdbError(protocol.NOT_FOUND, f"no symbol or address named {value!r}")


def til():
    import ida_typeinf

    return ida_typeinf.get_idati()


def func_name_at(ea):
    import ida_funcs

    f = ida_funcs.get_func(ea)
    return ida_funcs.get_func_name(f.start_ea) if f else None
