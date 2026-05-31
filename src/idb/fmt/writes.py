"""Terse confirmations for mutating commands."""


def format_rename(result, ns=None):
    if result.get("kind") == "lvar":
        return f"renamed local {result['target']} -> {result['name']}"
    return f"renamed {result['ea']:#x} -> {result['name']}"


def format_comment(result, ns=None):
    views = "disasm+pseudo" if result.get("pseudocode") else "disasm"
    return f"comment @ {result['ea']:#x} ({views}): {result['comment']}"


def format_op(result, ns=None):
    views = "disasm+pseudo" if result.get("pseudocode") else "disasm"
    where = f" op{result['opnum']}" if result.get("opnum") is not None else ""
    return f"op @ {result['ea']:#x}{where} -> {result['repr']} ({views})"


def format_patch(result, ns=None):
    data = result.get("bytes", b"")
    hexs = data.hex() if isinstance(data, (bytes, bytearray)) else ""
    return f"patched {result['count']} bytes @ {result['ea']:#x}: {hexs}"


def format_undo(result, ns=None):
    label = result.get("label")
    return f"undone{(': ' + label) if label else ''}"


def format_redo(result, ns=None):
    return "redone"


def format_declare(result, ns=None):
    return "declared ok"


def format_settype(result, ns=None):
    where = f"{result['ea']:#x}" if "ea" in result else result.get("target", "?")
    return f"{where} : {result['type']}"


def format_setmember(result, ns=None):
    return f"{result['type']}[{result['index']}] {result['name']} : {result['member_type']}"


def format_setlvar(result, ns=None):
    return f"{result['target']} : {result['type']}"


def format_enum(result, ns=None):
    members = ", ".join(f"{m['name']}={m['value']}" for m in result.get("members", []))
    if result.get("extended"):
        return f"enum {result['name']} extended: {members}"
    tag = " (bitfield)" if result.get("bitfield") else ""
    return f"enum {result['name']}{tag}: {members}"


def format_union_select(result, ns=None):
    tag = "" if result.get("verified", True) else " (unverified)"
    return f"union @ {result['ea']:#x}: {result['union']} -> .{result['member']} (arm {result['ordinal']}){tag}"
