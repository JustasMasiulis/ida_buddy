"""Terse confirmations for mutating commands."""

from .compact import escape_text


def _views(result):
    return "disasm+pseudo" if result.get("pseudocode") else "disasm"


def format_rename(result, ns=None):
    if result.get("kind") == "lvar":
        return f"renamed local {result['target']} -> {result['name']}"
    return f"renamed {result['ea']:x} -> {result['name']}"


def format_comment(result, ns=None):
    return f"comment {result['ea']:x} ({_views(result)}): {escape_text(result['comment'], 60)}"


def format_op(result, ns=None):
    where = f" op{result['opnum']}" if result.get("opnum") is not None else ""
    return f"op {result['ea']:x}{where} -> {escape_text(result['repr'], 60)} ({_views(result)})"


def format_patch(result, ns=None):
    data = result.get("bytes", b"")
    hexs = data.hex() if isinstance(data, (bytes, bytearray)) else ""
    return f"patched {result['count']} bytes @ {result['ea']:x}: {hexs}"


def format_undo(result, ns=None):
    label = result.get("label")
    return f"undone{(': ' + label) if label else ''}"


def format_redo(result, ns=None):
    label = result.get("label")
    return f"redone: {label}" if label else "redone"


def format_declare(result, ns=None):
    return "declared"


def format_settype(result, ns=None):
    where = f"{result['ea']:x}" if "ea" in result else result.get("target", "?")
    return f"set {where} to {result['type']}"


def format_set_member(result, ns=None):
    line = f"set {result['type']}[{result['index']}] {result['name']} to {result['member_type']}"
    consumed = result.get("consumed") or []
    if consumed:
        line += f" (consumed {', '.join(consumed)})"
    return line


def format_insert_member(result, ns=None):
    return (f"inserted {result['type']}[{result['index']}] {result['name']} to "
            f"{result['member_type']} @ +{result['offset']:x}")


def format_del_member(result, ns=None):
    tag = " (gap left)" if result.get("leave_gap") else ""
    return f"removed {result['type']}.{result['removed']}{tag}"


def format_setlvar(result, ns=None):
    return f"set {result['target']} to {result['type']}"


def format_enum(result, ns=None):
    members = ", ".join(f"{m['name']}={m['value']}" for m in result.get("members", []))
    if result.get("extended"):
        return f"enum {result['name']} extended: {members}"
    tag = " (bitfield)" if result.get("bitfield") else ""
    return f"enum {result['name']}{tag}: {members}"


def format_union_select(result, ns=None):
    tag = "" if result.get("verified", True) else " (unverified)"
    return f"union {result['ea']:x}: {result['union']} -> .{result['member']} (arm {result['ordinal']}){tag}"
