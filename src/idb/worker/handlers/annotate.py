"""annotate handlers: rename, comment, op, patch, undo, redo.

Mutating handlers are registered writes=True so dispatch creates an undo point
before they run. undo/redo are NOT writes (they must not create undo points of
their own) and report honestly: if perform_undo/redo returns false, we surface an
error instead of claiming a revert that did not happen.
"""

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import ida_undo
from ida_idaapi import BADADDR

from idb import protocol
from idb.errors import IdbError
from idb.worker import idahelp
from idb.worker.dispatch import handler


@handler("rename", writes=True)
def rename(addr, name):
    try:
        ea = idahelp.resolve_target(addr)
    except IdbError:
        ea = None
    if ea is None and ":" in addr:
        func, _, var = addr.partition(":")
        f = ida_funcs.get_func(idahelp.resolve_target(func))
        if f is None:
            raise IdbError(protocol.NOT_FOUND, f"no function {func!r}")
        if not ida_hexrays.init_hexrays_plugin():
            raise IdbError(protocol.IDA_ERROR, "Hex-Rays is required to rename a local variable")
        if not ida_hexrays.rename_lvar(f.start_ea, var, name):
            raise IdbError(protocol.IDA_ERROR, f"could not rename local {var!r} (unknown name?)")
        return {"target": addr, "name": name, "kind": "lvar"}
    if ea is None:
        raise IdbError(protocol.NOT_FOUND, f"cannot resolve {addr!r}")
    if not ida_name.set_name(ea, name, ida_name.SN_NOWARN):
        raise IdbError(protocol.IDA_ERROR, f"set_name failed at {ea:#x} (name already in use?)")
    return {"ea": ea, "name": ida_name.get_name(ea), "kind": "name"}


def _set_pseudocode_comment(func_start, ea, text):
    """Attach a Hex-Rays comment at ea. The comment ea must map to a ctree
    statement; we try each statement-level ITP and use refresh_func_ctext to
    apply + detect orphaning on the same cfunc. Returns True if it anchored."""
    if not ida_hexrays.init_hexrays_plugin():
        return False
    # Anchor on a fresh ctree: a cached cfunc can map ea to a stale statement
    # after a referenced struct or callee retype, orphaning the comment.
    ida_hexrays.mark_cfunc_dirty(func_start)
    try:
        cfunc = ida_hexrays.decompile(func_start)
    except ida_hexrays.DecompilationFailure:
        return False
    if cfunc is None:
        return False
    tl = ida_hexrays.treeloc_t()
    tl.ea = ea
    for itp in range(int(ida_hexrays.ITP_SEMI), int(ida_hexrays.ITP_COLON) + 1):
        tl.itp = itp
        cfunc.set_user_cmt(tl, text)
        cfunc.refresh_func_ctext()
        if not cfunc.has_orphan_cmts():
            cfunc.save_user_cmts()
            return True
        cfunc.del_orphan_cmts()
    return False


@handler("comment", writes=True)
def comment(addr, text):
    ea = idahelp.resolve_target(addr)
    if not ida_bytes.set_cmt(ea, text, False):
        raise IdbError(protocol.IDA_ERROR, f"set_cmt failed at {ea:#x}")
    pseudocode = False
    f = ida_funcs.get_func(ea)
    if f is not None:
        pseudocode = _set_pseudocode_comment(f.start_ea, ea, text)
    return {"ea": ea, "comment": text, "disasm": True, "pseudocode": pseudocode}


_OPS = {
    "hex": ida_bytes.op_hex,
    "dec": ida_bytes.op_dec,
    "oct": ida_bytes.op_oct,
    "bin": ida_bytes.op_bin,
    "char": ida_bytes.op_chr,
    "num": ida_bytes.op_num,
}


@handler("op", writes=True)
def op(addr, fmt, opnum=None):
    """Set an operand's display representation. radix/char/num use ida_bytes.op_*;
    `enum:NAME` resolves the enum tid via get_named_type_tid. The disassembly setters
    propagate into the Hex-Rays pseudocode for char/enum/num (the decompiler manages
    its own number radix), so we mark the enclosing function dirty to refresh it."""
    ea = idahelp.resolve_target(addr)
    if not ida_bytes.is_mapped(ea):
        raise IdbError(protocol.BAD_ADDRESS, f"address {ea:#x} is not mapped")
    n = opnum if opnum is not None else ida_bytes.OPND_ALL
    if fmt.startswith("enum:"):
        name = fmt[len("enum:"):]
        if not name:
            raise IdbError(protocol.BAD_ARGS, "enum: needs a type name (enum:NAME)")
        tid = ida_typeinf.get_named_type_tid(name)
        if tid == BADADDR:
            raise IdbError(protocol.NOT_FOUND, f"no enum named {name!r}")
        ok = ida_bytes.op_enum(ea, n, tid, 0)
    elif fmt in _OPS:
        ok = _OPS[fmt](ea, n)
    else:
        raise IdbError(protocol.BAD_ARGS,
                       f"unknown representation {fmt!r} (hex/dec/oct/bin/char/num/enum:NAME)")
    if not ok:
        raise IdbError(protocol.IDA_ERROR,
                       f"could not set representation at {ea:#x} (operand {n}: not a number?)")
    pseudocode = False
    f = ida_funcs.get_func(ea)
    if f is not None and ida_hexrays.init_hexrays_plugin():
        ida_hexrays.mark_cfunc_dirty(f.start_ea)
        pseudocode = True
    return {"ea": ea, "repr": fmt, "opnum": opnum, "disasm": True, "pseudocode": pseudocode}


@handler("patch", writes=True)
def patch(addr, hex):
    ea = idahelp.resolve_target(addr)
    tokens = hex.replace("0x", "").replace(",", " ").split()
    try:
        data = bytes.fromhex("".join(tokens))
    except ValueError:
        raise IdbError(protocol.BAD_ARGS, "patch bytes must be hex (e.g. '90 90' or '9090')")
    if not data:
        raise IdbError(protocol.BAD_ARGS, "empty patch")
    if not ida_bytes.is_mapped(ea):
        raise IdbError(protocol.BAD_ADDRESS, f"address {ea:#x} is not mapped")
    ida_bytes.patch_bytes(ea, data)
    return {"ea": ea, "count": len(data), "bytes": data}


@handler("undo")
def undo():
    label = ""
    try:
        label = ida_undo.get_undo_action_label() or ""
    except Exception:
        pass
    if not ida_undo.perform_undo():
        raise IdbError(protocol.IDA_ERROR, "nothing to undo (or the last action is not undoable in idalib)")
    return {"undone": True, "label": label}


@handler("redo")
def redo():
    if not ida_undo.perform_redo():
        raise IdbError(protocol.IDA_ERROR, "nothing to redo")
    return {"redone": True}
