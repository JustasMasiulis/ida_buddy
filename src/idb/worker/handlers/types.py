"""types read handlers: type, types, struct, member, typeof, frame.

Type writes (declare/settype/set_member/insert_member/del_member/enum) and the
Hex-Rays union-arm selector (union-select) live here too.
"""

import ida_bytes
import ida_frame
import ida_funcs
import ida_nalt
import ida_typeinf as T
from ida_idaapi import BADADDR

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp
from idb.worker.dispatch import handler

_LIST_DEFAULT = 300
_INT_MAX = 0x7FFFFFFF
_UINT32_MAX = 0xFFFFFFFF


def _kind(tif):
    if tif.is_union():
        return "union"
    if tif.is_struct():
        return "struct"
    if tif.is_enum():
        return "enum"
    if tif.is_ptr():
        return "pointer"
    if tif.is_func():
        return "function"
    if tif.is_array():
        return "array"
    if tif.is_typeref():
        return "typedef"
    return "scalar"


def _udt_members(tif):
    udt = T.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return []
    out = []
    for m in udt:
        out.append({
            "name": m.name,
            "offset": m.offset // 8,
            "size": m.type.get_size(),
            "type": str(m.type),
            "bitfield": m.is_bitfield(),
        })
    return out


def _enum_members(tif):
    ed = T.enum_type_data_t()
    if not tif.get_enum_details(ed):
        return []
    nbytes = tif.get_size()
    if nbytes <= 0:
        nbytes = ed.calc_nbytes()
    mask = (1 << (max(1, min(int(nbytes), 8)) * 8)) - 1
    return [{"name": e.name, "value": int(e.value) & mask} for e in ed]


def _named(name):
    tif = T.tinfo_t()
    if not tif.get_named_type(idahelp.til(), name):
        raise IdbError(protocol.NOT_FOUND, f"no type named {name!r}")
    return tif


def _parse_int(value):
    s = str(value)
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


@handler("type")
def type_(name, addr=None, offset=0, count=None):
    tif = T.tinfo_t()
    if not tif.get_named_type(idahelp.til(), name):
        # Not a named type: treat the argument as an instance (address / symbol /
        # func:var) and report its type, windbg `dt <address>`-style. An overlay
        # address makes no sense for an instance.
        if addr is not None:
            raise IdbError(protocol.BAD_ARGS,
                           f"{name!r} is not a named type; name a struct/union to overlay {addr!r}")
        return _typeof(name)
    result = {"name": name, "kind": _kind(tif), "size": tif.get_size(), "decl": str(tif)}
    if tif.is_union() or tif.is_struct():
        base = idahelp.resolve_target(addr) if addr is not None else None
        members, next_offset = idahelp.paginate(_udt_members(tif), offset, count)
        if base is not None:
            for m in members:
                m["value"] = _read_value(base + m["offset"], m["size"])
        result["members"] = members
        result["is_union"] = tif.is_union()
        result["addr"] = base
        return result, idahelp.page_meta(members, next_offset)
    if addr is not None:
        raise IdbError(protocol.BAD_ARGS,
                       f"value overlay requires a struct or union, not {result['kind']}")
    if tif.is_enum():
        members, next_offset = idahelp.paginate(_enum_members(tif), offset, count)
        result["members"] = members
        return result, idahelp.page_meta(members, next_offset)
    return result


@handler("types")
def types(pattern=None, kind=None, size=None, offset=0, count=None, total=False):
    name_pred = idahelp.name_filter(pattern)
    want_size = None
    if size is not None:
        try:
            want_size = _parse_int(size)
        except ValueError:
            raise IdbError(protocol.BAD_ARGS, f"--size must be an integer: {size!r}")

    def matches(tif, name):
        if not name or not name_pred(name):
            return None
        k = _kind(tif)
        if kind and k != kind:
            return None
        sz = tif.get_size()
        if want_size is not None and sz != want_size:
            return None
        return k, sz

    filtered = pattern is not None or kind is not None or want_size is not None

    def rows():
        yield from _iter_local_types(matches)
        if filtered:
            yield from _iter_library_types(matches)

    items, next_offset = idahelp.paginate(rows(), offset, count if count else _LIST_DEFAULT)
    total_count = sum(1 for _ in rows()) if total else None
    return {"data": items}, idahelp.page_meta(items, next_offset, total_count)


def _iter_local_types(matches):
    til = idahelp.til()
    for ordn in range(1, T.get_ordinal_limit(til)):
        name = T.get_numbered_type_name(til, ordn)
        if not name:
            continue
        tif = T.tinfo_t()
        if not tif.get_numbered_type(til, ordn):
            continue
        m = matches(tif, name)
        if m is None:
            continue
        kind, size = m
        yield {"name": name, "kind": kind, "size": size, "src": "local"}


def _iter_library_types(matches):
    """Scan idati's loaded base .til files (mssdk, gnulnx, ...) by name. Each base
    is guarded so a malformed til skips rather than aborting the whole listing."""
    root = idahelp.til()
    for i in range(getattr(root, "nbases", 0)):
        try:
            base = root.base(i)
        except Exception:
            continue
        if base is None:
            continue
        src = getattr(base, "name", None) or f"til{i}"
        try:
            name = T.first_named_type(base, T.NTF_TYPE)
            while name:
                tif = T.tinfo_t()
                if tif.get_named_type(base, name):
                    m = matches(tif, name)
                    if m is not None:
                        kind, size = m
                        yield {"name": name, "kind": kind, "size": size, "src": src}
                name = T.next_named_type(base, name, T.NTF_TYPE)
        except Exception:
            continue


def _read_value(ea, size):
    if not ida_bytes.is_mapped(ea):
        return None
    if size == 1:
        return ida_bytes.get_byte(ea)
    if size == 2:
        return ida_bytes.get_word(ea)
    if size == 4:
        return ida_bytes.get_dword(ea)
    if size == 8:
        return ida_bytes.get_qword(ea)
    data = ida_bytes.get_bytes(ea, min(size or 0, 32))
    return data.hex() if data else None


def _join(prefix, name):
    name = name or "<anon>"
    return f"{prefix}.{name}" if prefix else name


def _enter(mtype, off, path, paths, depth):
    t = mtype
    while t.is_array():
        elem = t.get_array_element()
        esize = max(1, elem.get_size())
        path = f"{path}[{off // esize}]"
        off = off % esize
        t = elem
    if t.is_struct() or t.is_union():
        _walk(t, off, path, paths, depth + 1)
    else:
        paths.append({"path": path, "type": str(t), "size": t.get_size(), "offset": off})


def _walk(tif, off, prefix, paths, depth=0):
    if depth > 24:
        return
    if tif.is_union():
        udt = T.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return
        for m in udt:
            if off < max(1, m.type.get_size()):
                _enter(m.type, off, _join(prefix, m.name), paths, depth)
        return
    if tif.is_struct():
        idx = tif.find_udm(off * 8, T.STRMEM_OFFSET | T.STRMEM_SKIP_GAPS)
        if idx < 0:
            return
        _, m = tif.get_udm(idx)
        _enter(m.type, off - m.offset // 8, _join(prefix, m.name), paths, depth)
        return
    paths.append({"path": prefix, "type": str(tif), "size": tif.get_size(), "offset": off})


@handler("member")
def member(type, offset, page_offset=0, count=None):
    off = _parse_int(offset)
    tif = _named(type)
    if not (tif.is_struct() or tif.is_union()):
        raise IdbError(protocol.BAD_ARGS, f"{type!r} is not a struct or union")
    paths = []
    _walk(tif, off, "", paths)
    if not paths:
        raise IdbError(protocol.NOT_FOUND, f"no member spans byte offset {off} of {type!r}")
    items, next_offset = idahelp.paginate(paths, page_offset, count)
    return {"type": type, "offset": off, "paths": items}, idahelp.page_meta(items, next_offset)


def _typeof_lvar(func, var):
    ea = idahelp.resolve_target(func)
    f = ida_funcs.get_func(ea)
    if f is None:
        raise IdbError(protocol.NOT_FOUND, f"no function {func!r}")
    import ida_hexrays

    if ida_hexrays.init_hexrays_plugin():
        try:
            cfunc = ida_hexrays.decompile(f.start_ea)
            for lv in cfunc.get_lvars():
                if lv.name == var:
                    lt = lv.type()
                    return {"target": f"{func}:{var}", "kind": "lvar",
                            "type": str(lt), "size": lt.get_size()}
        except ida_hexrays.DecompilationFailure:
            pass
    ftif = T.tinfo_t()
    if ftif.get_func_frame(f):
        idx = ftif.find_udm(var)
        if idx >= 0:
            _, m = ftif.get_udm(idx)
            return {"target": f"{func}:{var}", "kind": "stack",
                    "type": str(m.type), "size": m.type.get_size()}
    raise IdbError(protocol.NOT_FOUND, f"no local/stack variable {var!r} in {func!r}")


def _typeof(target):
    try:
        ea = idahelp.resolve_target(target)
    except IdbError:
        ea = None
    if ea is None:
        if ":" in target:
            func, _, var = target.partition(":")
            return _typeof_lvar(func, var)
        raise IdbError(protocol.NOT_FOUND, f"cannot resolve {target!r}")

    tif = T.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        return {"target": target, "ea": ea, "kind": _kind(tif),
                "type": str(tif), "size": tif.get_size()}
    guess = T.tinfo_t()
    if T.guess_tinfo(guess, ea) != T.GUESS_FUNC_FAILED:
        return {"target": target, "ea": ea, "kind": _kind(guess),
                "type": str(guess), "size": guess.get_size(), "guessed": True}
    raise IdbError(protocol.NOT_FOUND, f"no type information for {target!r}")


@handler("typeof")
def typeof(target):
    return _typeof(target)


@handler("frame")
def frame(func, offset=0, count=None):
    ea = idahelp.resolve_target(func)
    f = ida_funcs.get_func(ea)
    if f is None:
        raise IdbError(protocol.NOT_FOUND, f"no function at {func!r}")
    ftif = T.tinfo_t()
    if not ftif.get_func_frame(f):
        raise IdbError(protocol.IDA_ERROR, f"no stack frame for {func!r}")
    members, next_offset = idahelp.paginate(_udt_members(ftif), offset, count)
    return ({"func": ida_funcs.get_func_name(f.start_ea), "ea": f.start_ea,
             "size": ftif.get_size(), "members": members},
            idahelp.page_meta(members, next_offset))


def _parse_type(spec):
    til = idahelp.til()
    existing = T.tinfo_t()
    if existing.get_named_type(til, spec):
        return existing

    text = str(spec).strip().rstrip(";").strip()
    candidates = [text + ";", f"{text} _idb;"]
    lparen = text.find("(")
    if lparen > 0 and text[lparen + 1:lparen + 2] not in ("*", "&"):
        candidates.append(f"{text[:lparen].rstrip()} _idb{text[lparen:]};")

    for candidate in candidates:
        tif = T.tinfo_t()
        name = T.parse_decl(tif, til, candidate, T.PT_SIL)
        if name is not None and not tif.empty():
            return tif

    if not text:
        raise IdbError(protocol.BAD_ARGS, f"could not parse type {spec!r}")
    raise IdbError(protocol.BAD_ARGS, f"could not parse type {spec!r}")


@handler("declare", writes=True)
def declare(text):
    errors = T.parse_decls(idahelp.til(), text, None, T.PT_SIL)
    if errors != 0:
        raise IdbError(protocol.IDA_ERROR, f"parse_decls reported {errors} error(s)")
    return {"ok": True, "declared": text.strip()}


def _hexrays_lvar(func_start, var):
    """Decompile func_start and locate the lvar named var. Returns (cfunc, lvar);
    the caller MUST keep cfunc referenced while using lvar (the lvar is owned by it).
    Either element is None when Hex-Rays is unavailable, decompilation fails, or no
    such lvar exists."""
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        return None, None
    try:
        cfunc = ida_hexrays.decompile(func_start)
    except ida_hexrays.DecompilationFailure:
        return None, None
    if cfunc is None:
        return None, None
    for lv in cfunc.get_lvars():
        if lv.name == var:
            return cfunc, lv
    return cfunc, None


def _settype_local(func, var, new_type):
    f = ida_funcs.get_func(idahelp.resolve_target(func))
    if f is None:
        raise IdbError(protocol.NOT_FOUND, f"no function {func!r}")
    import ida_hexrays

    cfunc, lv = _hexrays_lvar(f.start_ea, var)
    if lv is not None:
        lsi = ida_hexrays.lvar_saved_info_t()
        lsi.ll = lv
        lsi.type = new_type
        if ida_hexrays.modify_user_lvar_info(f.start_ea, ida_hexrays.MLI_TYPE, lsi):
            return {"target": f"{func}:{var}", "kind": "lvar", "type": str(new_type)}
    ftif = T.tinfo_t()
    if ftif.get_func_frame(f):
        idx = ftif.find_udm(var)
        if idx >= 0:
            _, m = ftif.get_udm(idx)
            if ida_frame.set_frame_member_type(f, m.offset // 8, new_type):
                return {"target": f"{func}:{var}", "kind": "stack", "type": str(new_type)}
    raise IdbError(protocol.IDA_ERROR, f"could not set type of local {var!r} in {func!r}")


@handler("settype", writes=True)
def settype(target, type):
    new_type = _parse_type(type)
    try:
        ea = idahelp.resolve_target(target)
    except IdbError:
        ea = None
    if ea is None:
        if ":" in target:
            func, _, var = target.partition(":")
            return _settype_local(func, var, new_type)
        raise IdbError(protocol.NOT_FOUND, f"cannot resolve {target!r}")
    if not T.apply_tinfo(ea, new_type, T.TINFO_DEFINITE):
        raise IdbError(protocol.IDA_ERROR, f"apply_tinfo failed at {ea:#x}")
    readback = T.tinfo_t()
    ida_nalt.get_tinfo(readback, ea)
    return {"ea": ea, "type": str(readback) if not readback.empty() else str(new_type)}


@handler("setlvar", writes=True)
def setlvar(func, var, name=None, type=None):
    import ida_hexrays

    if not name and not type:
        raise IdbError(protocol.BAD_ARGS, "setlvar needs --name and/or --type")
    f = ida_funcs.get_func(idahelp.resolve_target(func))
    if f is None:
        raise IdbError(protocol.NOT_FOUND, f"no function {func!r}")
    if not ida_hexrays.init_hexrays_plugin():
        raise IdbError(protocol.IDA_ERROR, "Hex-Rays is required for setlvar")
    cfunc, lv = _hexrays_lvar(f.start_ea, var)
    if lv is None:
        raise IdbError(protocol.NOT_FOUND, f"no local variable {var!r} in {func!r}")

    type_str = str(lv.type())
    if type:
        new_type = _parse_type(type)
        lsi = ida_hexrays.lvar_saved_info_t()
        lsi.ll = lv
        lsi.type = new_type
        if not ida_hexrays.modify_user_lvar_info(f.start_ea, ida_hexrays.MLI_TYPE, lsi):
            raise IdbError(protocol.IDA_ERROR, f"could not set type of {var!r}")
        type_str = str(new_type)

    final_name = var
    if name and name != var:
        if not ida_hexrays.rename_lvar(f.start_ea, var, name):
            raise IdbError(protocol.IDA_ERROR,
                           f"could not rename {var!r} -> {name!r} (name already in use?)")
        final_name = name
    return {"target": f"{func}:{final_name}", "kind": "lvar", "name": final_name, "type": type_str}


def _member_index(tif, member):
    try:
        off = _parse_int(member)
    except ValueError:
        return tif.find_udm(str(member))
    return tif.find_udm(off * 8, T.STRMEM_OFFSET | T.STRMEM_SKIP_GAPS)


# In-place mutators (rename_udm/set_udm_type/del_udm/add_udm) on a get_named_type()
# tinfo silently no-op (return TERR_OK, change nothing) unless a genuine type change
# happens to "prime" the tinfo first. The reliable path for every member edit is to
# pull the full UDT, mutate the member vector, rebuild with create_udt, and replace the
# stored definition with set_named_type(NTF_REPLACE). get_udt_details carries the whole
# layout (explicit offsets, packing, is_fixed, member comments) and mutating the same
# udt object in place preserves all of it, so create_udt reproduces the intended layout.


def _load_writable_udt(type):
    tif = _named(type)
    if not (tif.is_struct() or tif.is_union()):
        raise IdbError(protocol.BAD_ARGS, f"{type!r} is not a struct or union")
    def_name = tif.get_final_type_name()
    target = _named(def_name)
    udt = T.udt_type_data_t()
    if not target.get_udt_details(udt):
        raise IdbError(protocol.IDA_ERROR, f"could not read members of {type!r}")
    return def_name, target, udt, target.get_type_cmt(), bool(target.get_type_rptcmt())


def _save_udt(def_name, udt, is_union, type_cmt, repeatable):
    # A fixed struct carries an explicit total_size; growing the layout (insert, or a
    # set_member whose new type reaches past the old end) leaves it stale and create_udt
    # rejects the type. Grow it to cover the furthest member. Never shrink — a reversed
    # struct may keep intentional trailing padding that a pure rename must preserve.
    if not is_union and udt.size():
        end = max(m.offset // 8 + max(m.type.get_size(), 0) for m in udt)
        if udt.total_size < end:
            udt.total_size = end
        if udt.unpadded_size < end:
            udt.unpadded_size = end
    rebuilt = T.tinfo_t()
    if not rebuilt.create_udt(udt, T.BTF_UNION if is_union else T.BTF_STRUCT):
        raise IdbError(protocol.IDA_ERROR, f"could not rebuild {def_name!r}")
    if type_cmt:
        rebuilt.set_type_cmt(type_cmt, not repeatable)
    code = rebuilt.set_named_type(idahelp.til(), def_name, T.NTF_REPLACE)
    if code != T.TERR_OK:
        raise IdbError(protocol.IDA_ERROR, f"set_named_type failed: {T.tinfo_errstr(code)}")


def _arm_index(target, member, is_union):
    return _union_arm_ordinal(target, member) if is_union else _member_index(target, member)


def _drop_members(udt, first, last):
    """Erase members [first, last] (inclusive) by left-shifting the tail and popping."""
    span = last - first + 1
    count = udt.size()
    for k in range(first, count - span):
        udt[k] = udt[k + span]
    for _ in range(span):
        udt.pop_back()


@handler("set_member", writes=True)
def set_member(type, member, new_type, new_name=None):
    def_name, target, udt, type_cmt, repeatable = _load_writable_udt(type)
    idx = _member_index(target, member)
    if idx < 0:
        raise IdbError(protocol.NOT_FOUND, f"no member {member!r} in {type!r}")
    new_tif = _parse_type(new_type)
    width = new_tif.get_size() * 8
    if width <= 0:
        raise IdbError(protocol.BAD_ARGS, f"cannot size type {new_type!r}")
    udt[idx].type = new_tif
    udt[idx].size = width
    if new_name:
        udt[idx].name = new_name
    # A larger type overwrites the bytes of the members that follow it: consume every
    # later member whose original start falls within the enlarged footprint [start, end).
    # Comparison uses the pre-rebuild offsets, so the overlap is judged against the layout
    # the user is looking at. Unions are unaffected — every arm sits at offset 0.
    consumed = []
    if not target.is_union():
        start = udt[idx].offset
        end = start + width
        last = idx
        while last + 1 < udt.size() and udt[last + 1].offset < end:
            consumed.append(udt[last + 1].name)
            last += 1
        if last > idx:
            _drop_members(udt, idx + 1, last)
    _save_udt(def_name, udt, target.is_union(), type_cmt, repeatable)
    _, m = _named(type).get_udm(idx)
    return {"type": type, "index": idx, "name": m.name,
            "member_type": str(m.type), "consumed": consumed}


@handler("insert_member", writes=True)
def insert_member(type, new_type, name, before=None, after=None):
    if before is not None and after is not None:
        raise IdbError(protocol.BAD_ARGS, "insert_member takes at most one of --before/--after")
    def_name, target, udt, type_cmt, repeatable = _load_writable_udt(type)
    is_union = target.is_union()
    member = T.udm_t()
    member.name = name
    member.type = _parse_type(new_type)
    width = member.type.get_size() * 8
    if width <= 0:
        raise IdbError(protocol.BAD_ARGS, f"cannot size type {new_type!r}")
    member.size = width

    count = udt.size()
    ref = before if before is not None else after
    if ref is None:
        pos = count
        insert_off = 0 if is_union else target.get_size() * 8
    else:
        idx = _arm_index(target, ref, is_union)
        if idx < 0 or idx >= count:
            raise IdbError(protocol.NOT_FOUND, f"no member {ref!r} in {type!r}")
        if before is not None:
            pos = idx
            insert_off = 0 if is_union else udt[idx].offset
        else:
            pos = idx + 1
            insert_off = 0 if is_union else udt[idx].offset + udt[idx].type.get_size() * 8
    member.offset = insert_off
    if not is_union:
        for i in range(count):
            if udt[i].offset >= insert_off:
                udt[i].offset += width
    udt.push_back(member)
    for i in range(count, pos, -1):
        udt[i] = udt[i - 1]
    udt[pos] = member
    _save_udt(def_name, udt, is_union, type_cmt, repeatable)
    _, m = _named(type).get_udm(pos)
    return {"type": type, "index": pos, "name": m.name,
            "member_type": str(m.type), "offset": m.offset // 8}


@handler("del_member", writes=True)
def del_member(type, member, leave_gap=False):
    def_name, target, udt, type_cmt, repeatable = _load_writable_udt(type)
    is_union = target.is_union()
    idx = _arm_index(target, member, is_union)
    count = udt.size()
    if idx < 0 or idx >= count:
        raise IdbError(protocol.NOT_FOUND, f"no member {member!r} in {type!r}")
    removed = udt[idx].name
    width = udt[idx].type.get_size() * 8
    if not is_union and not leave_gap:
        for i in range(idx + 1, count):
            udt[i].offset -= width
    _drop_members(udt, idx, idx)
    # Leaving a gap means the surviving members keep their exact byte offsets. create_udt
    # repacks a non-fixed struct by natural alignment (closing the hole), so pin the layout
    # fixed to honor the explicit offsets and the now-undefined gap bytes.
    if not is_union and leave_gap:
        udt.set_fixed()
    _save_udt(def_name, udt, is_union, type_cmt, repeatable)
    return {"type": type, "removed": removed, "leave_gap": bool(leave_gap)}


def _parse_enum_members(members):
    parsed, nxt = [], 0
    for chunk in members.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            key, raw = chunk.split("=", 1)
            value = int(raw.strip(), 0)
        else:
            key, value = chunk, nxt
        parsed.append({"name": key.strip(), "value": value})
        nxt = value + 1
    if not parsed:
        raise IdbError(protocol.BAD_ARGS, "enum needs at least one k=v member")
    return parsed


def _enum_needs_unsigned(members):
    return all(m["value"] >= 0 for m in members) and any(m["value"] > _INT_MAX for m in members)


def _enum_nbytes(members):
    max_value = max((m["value"] for m in members), default=0)
    min_value = min((m["value"] for m in members), default=0)
    if min_value < -0x80000000 or max_value > _UINT32_MAX:
        return 8
    return 4


@handler("enum", writes=True)
def enum(name, members, bitfield=False):
    parsed = _parse_enum_members(members)
    unsigned = _enum_needs_unsigned(parsed)

    existing = T.tinfo_t()
    if existing.get_named_type(idahelp.til(), name) and existing.is_enum():
        if unsigned:
            existing.set_enum_sign(False)
        for m in parsed:
            try:
                existing.add_edm(m["name"], m["value"])
            except ValueError as exc:
                raise IdbError(protocol.IDA_ERROR, f"add enumerator {m['name']!r} failed: {exc}")
        return {"name": name, "extended": True, "members": parsed}

    ei = T.enum_type_data_t()
    if unsigned:
        ei.taenum_bits |= T.TAENUM_UNSIGNED
    for m in parsed:
        ei.push_back(T.edm_t(m["name"], m["value"]))
    tid = T.create_enum_type(name, ei, _enum_nbytes(parsed), 0, bool(bitfield))
    if tid == BADADDR:
        raise IdbError(protocol.IDA_ERROR, f"create_enum_type failed for {name!r}")
    return {"name": name, "extended": False, "bitfield": bool(bitfield), "members": parsed}


def _union_arm_ordinal(union_tif, member):
    """member as an int (or 0x-int) is the union-arm ordinal directly; otherwise a
    field name resolved via find_udm. Union arms all share offset 0, so a byte-offset
    lookup (as set_member uses) is meaningless here. Returns -1 if not an arm."""
    s = str(member)
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except ValueError:
        return union_tif.find_udm(s)


def _addressable_ea(cfunc, item):
    """Walk up from item to the nearest ctree node carrying a real ea. Union access
    expressions are sometimes unaddressable (BADADDR); the decompiler keys a selection
    on the addressable parent (see IDA's vds17 example)."""
    while item is not None and item.ea == BADADDR:
        item = cfunc.body.find_parent_of(item)
    return item.ea if item is not None else BADADDR


@handler("union_select", writes=True)
def union_select(addr, member):
    import ida_hexrays
    import ida_pro

    ea = idahelp.resolve_target(addr)
    f = ida_funcs.get_func(ea)
    if f is None:
        raise IdbError(protocol.NOT_FOUND, f"no function contains {addr!r}")
    if not ida_hexrays.init_hexrays_plugin():
        raise IdbError(protocol.IDA_ERROR, "Hex-Rays is required for union-select")
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
    except ida_hexrays.DecompilationFailure as exc:
        raise IdbError(protocol.IDA_ERROR, f"decompilation failed: {exc}")
    if cfunc is None:
        raise IdbError(protocol.IDA_ERROR, "decompilation produced no result")
    cfunc.get_pseudocode()

    union_ops = (ida_hexrays.cot_memptr, ida_hexrays.cot_memref)
    cands = []
    items = cfunc.treeitems
    for i in range(items.size()):
        it = items.at(i)
        if not it.is_expr() or it.op not in union_ops:
            continue
        e = it.cexpr
        base = T.remove_pointer(e.x.type)
        if not base.is_union():
            continue
        ordinal = _union_arm_ordinal(base, member)
        cands.append({"it": it, "base": base, "expr_ea": e.ea,
                      "site_ea": e.ea if e.ea != BADADDR else _addressable_ea(cfunc, it),
                      "ordinal": ordinal, "valid": 0 <= ordinal < len(_udt_members(base))})

    if not cands:
        raise IdbError(protocol.NOT_FOUND,
                       f"no union field access in {ida_funcs.get_func_name(f.start_ea)}")

    at_ea = [c for c in cands if ea in (c["expr_ea"], c["site_ea"])]
    if at_ea:
        chosen = next((c for c in at_ea if c["valid"]), None)
        if chosen is None:
            arms = ", ".join(m["name"] for m in _udt_members(at_ea[0]["base"]))
            raise IdbError(protocol.NOT_FOUND,
                           f"union {at_ea[0]['base']} at {ea:#x} has no arm {member!r}; arms: {arms}")
    else:
        matching = [c for c in cands if c["valid"]]
        sites = sorted({c["site_ea"] for c in matching})
        if not matching:
            raise IdbError(protocol.NOT_FOUND, f"no union arm named {member!r} at or near {ea:#x}")
        if len(sites) > 1:
            raise IdbError(protocol.BAD_ARGS,
                           f"arm {member!r} is ambiguous across sites {', '.join(f'{s:#x}' for s in sites)}; "
                           "pass the exact address")
        chosen = matching[0]

    key_ea = chosen["site_ea"]
    if key_ea == BADADDR:
        raise IdbError(protocol.IDA_ERROR, "the union access expression has no addressable location")
    ordinal = chosen["ordinal"]

    path = ida_pro.intvec_t()
    path.push_back(ordinal)
    cfunc.set_user_union_selection(key_ea, path)
    cfunc.save_user_unions()

    _, arm = chosen["base"].get_udm(ordinal)
    union_name = str(chosen["base"])

    ida_hexrays.mark_cfunc_dirty(f.start_ea)
    verified = False
    try:
        cf2 = ida_hexrays.decompile(f.start_ea)
        out = ida_pro.intvec_t()
        if cf2 is not None and cf2.get_user_union_selection(key_ea, out):
            verified = out.size() == 1 and out.at(0) == ordinal
    except ida_hexrays.DecompilationFailure:
        pass

    return {"ea": key_ea, "func": ida_funcs.get_func_name(f.start_ea), "union": union_name,
            "member": arm.name, "ordinal": ordinal, "path": [ordinal], "verified": verified}
