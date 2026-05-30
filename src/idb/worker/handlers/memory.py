"""memory handlers: read (db/dw/dd/dq), string (da/du)."""

import ida_bytes
import ida_ida
import ida_nalt
import ida_segment

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp
from idb.worker.dispatch import handler

_GETTERS = {2: ida_bytes.get_word, 4: ida_bytes.get_dword, 8: ida_bytes.get_qword}


def _string_encoding(strtype):
    width = int(strtype or 0) & ida_nalt.STRWIDTH_MASK
    if width == ida_nalt.STRWIDTH_2B:
        return "utf16"
    if width == ida_nalt.STRWIDTH_4B:
        return "utf32"
    return "ascii"


def _string_width(strtype):
    width = int(strtype or 0) & ida_nalt.STRWIDTH_MASK
    if width == ida_nalt.STRWIDTH_2B:
        return 2
    if width == ida_nalt.STRWIDTH_4B:
        return 4
    return 1


def _string_storage_size(ea, strtype, text_bytes):
    flags = ida_bytes.get_full_flags(ea)
    if ida_bytes.is_strlit(flags):
        size = ida_bytes.get_item_size(ea)
        if size > 0:
            return size
    return len(text_bytes) * _string_width(strtype)


@handler("read")
def read(addr, width=1, count=None, offset=0):
    width = width or 1
    if width not in (1, 2, 4, 8):
        raise IdbError(protocol.BAD_ARGS, "width must be 1, 2, 4, or 8")
    ea = idahelp.resolve_target(addr) + (offset or 0) * width
    if not ida_bytes.is_mapped(ea):
        raise IdbError(protocol.BAD_ADDRESS, f"address {ea:#x} is not mapped")
    seg = ida_segment.getseg(ea)
    seg_end = seg.end_ea if seg else ida_ida.inf_get_max_ea()

    if width == 1:
        total = max(0, min(count if count else 64, seg_end - ea))
        data = ida_bytes.get_bytes(ea, total)
        if data is None:
            data = bytes(total)  # BSS / uninitialized -> zeros
        return {"addr": ea, "width": 1, "bytes": data, "count": len(data)}

    getter = _GETTERS[width]
    values, cur = [], ea
    for _ in range(count if count else 16):
        if cur + width > seg_end:
            break
        values.append(int(getter(cur)))
        cur += width
    return {"addr": ea, "width": width, "values": values, "count": len(values),
            "be": ida_ida.inf_is_be()}


@handler("string")
def string(addr, encoding=None):
    ea = idahelp.resolve_target(addr)
    if not ida_bytes.is_mapped(ea):
        raise IdbError(protocol.BAD_ADDRESS, f"address {ea:#x} is not mapped")
    if encoding == "ascii":
        strtype = ida_nalt.STRTYPE_C
    elif encoding == "utf16":
        strtype = ida_nalt.STRTYPE_C_16
    else:
        strtype = ida_nalt.get_str_type(ea)
        if strtype is None or strtype < 0:
            strtype = ida_nalt.STRTYPE_C
        encoding = _string_encoding(strtype)
    raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
    if raw is None:
        raise IdbError(protocol.NOT_FOUND, f"no string literal at {ea:#x}")
    # IDA returns display bytes for string contents, not the raw storage bytes.
    text = raw.decode("utf-8", "replace")
    byte_length = _string_storage_size(ea, strtype, raw)
    return {"addr": ea, "encoding": encoding,
            "bytes": raw, "text": text, "length": byte_length}
