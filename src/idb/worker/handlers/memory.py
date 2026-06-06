"""memory handlers: read (db/dw/dd/dq), string (da/du)."""

import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_nalt
import ida_typeinf
from ida_idaapi import BADADDR

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp
from idb.worker.dispatch import handler

_GETTERS = {2: ida_bytes.get_word, 4: ida_bytes.get_dword, 8: ida_bytes.get_qword}


def _ptr_size():
    return 8 if ida_ida.inf_get_app_bitness() == 64 else 4


def _symbolize(ea):
    name = ida_name.get_name(ea)
    if name:
        return name, 0
    f = ida_funcs.get_func(ea)
    if f is not None:
        return ida_funcs.get_func_name(f.start_ea), ea - f.start_ea
    head = ida_bytes.get_item_head(ea)
    if head != BADADDR and head != ea:
        hname = ida_name.get_name(head)
        if hname:
            return hname, ea - head
    return None, 0


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
    ea = idahelp.resolve_mapped(addr, offset, width)
    seg_end = idahelp.segment_end(ea)

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


def _counted_string_type(ea):
    """ea typed as an NT counted-string struct (UNICODE_STRING / ANSI_STRING /
    OEM_STRING / ...): return (type_name, wide). None otherwise. da/du read a
    NUL-terminated literal, which is garbage over these structs (the first cells
    are Length/MaximumLength/Buffer), so the caller redirects to the ds/dS reader.
    Wide-ness comes from the Buffer element width, not the name, so renamed clones
    are still classified correctly."""
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        return None
    name = tif.get_type_name() or ""
    base = name.lstrip("_").upper()
    if base != "STRING" and not base.endswith("_STRING"):
        return None
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt) or len(udt) < 3:
        return None
    length, maxlen, buffer = udt[0].type, udt[1].type, udt[2].type
    if length.get_size() != 2 or maxlen.get_size() != 2 or not buffer.is_ptr():
        return None
    return name, buffer.get_pointed_object().get_size() == 2


@handler("string")
def string(addr, encoding=None):
    ea = idahelp.resolve_mapped(addr)
    if encoding == "ascii":
        strtype = ida_nalt.STRTYPE_C
    elif encoding == "utf16":
        strtype = ida_nalt.STRTYPE_C_16
    else:
        strtype = ida_nalt.get_str_type(ea)
        # get_str_type returns 0xFFFFFFFF for an address that is not a defined string;
        # that sentinel overflows get_strlit_contents' int32 strtype param, so fall back
        # to a plain C-string read (yielding a clean NOT_FOUND if nothing is there).
        if strtype is None or not 0 <= strtype <= 0x7FFFFFFF:
            strtype = ida_nalt.STRTYPE_C
        encoding = _string_encoding(strtype)
    raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
    if raw is None:
        # The literal read found nothing. A counted-string struct (UNICODE_STRING/
        # ANSI_STRING/...) reliably lands here -- its small Length/MaximumLength header
        # bytes are not a valid NUL-terminated literal -- so recover by serving ds/dS.
        counted = _counted_string_type(ea)
        if counted is not None:
            type_name, wide = counted
            result = string_struct(ea, wide=wide)
            result["redirected_to_struct"] = True
            hint = "dS" if wide else "ds"
            return result, {"warning":
                            f"{ea:#x} is typed {type_name}, a counted-string struct rather "
                            f"than a NUL-terminated literal. Showing its contents -- use "
                            f"`{hint}` to read it directly."}
        # A windbg da/du shows memory whatever the type, so dump 16 bytes with an
        # ascii/utf16 side column rather than failing.
        seg_end = idahelp.segment_end(ea)
        total = max(0, min(16, seg_end - ea))
        data = ida_bytes.get_bytes(ea, total)
        if data is None:
            data = bytes(total)  # BSS / uninitialized -> zeros
        return ({"addr": ea, "encoding": encoding, "bytes": data,
                 "count": len(data), "raw_fallback": True},
                {"warning": f"no string literal at {ea:#x}; showing {len(data)} bytes"})
    # IDA returns display bytes for string contents, not the raw storage bytes.
    text = raw.decode("utf-8", "replace")
    byte_length = _string_storage_size(ea, strtype, raw)
    return {"addr": ea, "encoding": encoding,
            "bytes": raw, "text": text, "length": byte_length}


@handler("pointers")
def pointers(addr, count=None, offset=0):
    width = _ptr_size()
    ea = idahelp.resolve_mapped(addr, offset, width)
    seg_end = idahelp.segment_end(ea)
    getter = _GETTERS[width]
    rows, cur = [], ea
    for _ in range(count if count else 16):
        if cur + width > seg_end:
            break
        value = int(getter(cur))
        sym, off = _symbolize(value) if ida_bytes.is_mapped(value) else (None, 0)
        rows.append({"ea": cur, "value": value, "sym": sym, "off": off})
        cur += width
    return {"addr": ea, "width": width, "data": rows, "count": len(rows)}


@handler("string_struct")
def string_struct(addr, wide=False):
    ea = idahelp.resolve_mapped(addr)
    ptr = _ptr_size()
    length = ida_bytes.get_word(ea)
    maxlen = ida_bytes.get_word(ea + 2)
    buffer = ida_bytes.get_qword(ea + 8) if ptr == 8 else ida_bytes.get_dword(ea + 4)
    text = ""
    if length and ida_bytes.is_mapped(buffer):
        raw = ida_bytes.get_bytes(buffer, length) or b""
        enc = ("utf-16-be" if ida_ida.inf_is_be() else "utf-16-le") if wide else "latin-1"
        text = raw.decode(enc, "replace")
    return {"addr": ea, "wide": wide, "length": length, "maxlen": maxlen,
            "buffer": buffer, "text": text}
