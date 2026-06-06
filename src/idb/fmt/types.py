"""type / types / struct / member / typeof / frame formatters."""

from .columns import align
from .compact import shorten


def _members_table(members, with_values=False):
    headers = ["OFF", "SIZE", "TYPE", "NAME"]
    aligns = [">", ">", "<", "<"]
    if with_values:
        headers.insert(2, "VALUE")
        aligns.insert(2, ">")
    rows = []
    for m in members:
        cells = [f"+{m['offset']:x}", f"{m['size']:x}"]
        if with_values:
            v = m.get("value")
            cells.append(f"{v:x}" if isinstance(v, int) else (str(v) if v is not None else "?"))
        name = m["name"] + ("  :bitfield" if m.get("bitfield") else "")
        cells.extend([shorten(m["type"]), name])
        rows.append(tuple(cells))
    return align(rows, headers=tuple(headers), aligns=tuple(aligns))


def format_type(result, ns=None):
    if "target" in result:  # dt dispatched to typeof (an address / symbol / func:var arg)
        return format_typeof(result, ns)
    head = f"{result['kind']} {result['name']}   size {result['size']:#x}"
    if result.get("addr") is not None:
        head += f"   @ {result['addr']:x}"
    members = result.get("members")
    if members is None:
        return f"{head}\n  {shorten(result.get('decl', ''))}"
    if result["kind"] == "enum":
        rows = [(m["name"], f"{m['value']:x}") for m in members]
        return head + "\n" + align(rows, headers=("NAME", "VALUE"), aligns=("<", ">"))
    return head + "\n" + _members_table(members, with_values=result.get("addr") is not None)


def format_types(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no matching types)"
    table = [(r.get("src", "local"), r["kind"], f"{r['size']:x}", r["name"]) for r in rows]
    return align(table, headers=("SRC", "KIND", "SIZE", "NAME"), aligns=("<", "<", ">", "<"))


def format_member(result, ns=None):
    out = [f"{shorten(result['type'])} @ +{result['offset']:x}:"]
    for p in result.get("paths", []):
        out.append(f"  {p['path']} : {shorten(p['type'])}  (size {p['size']:#x})")
    return "\n".join(out)


def format_typeof(result, ns=None):
    guessed = "  (guessed)" if result.get("guessed") else ""
    size = result.get("size")
    has_size = isinstance(size, int) and 0 <= size < 0xFFFFFFFFFFFFFFFF  # functions report -1/BADSIZE
    size_str = f", {size:#x} bytes" if has_size else ""
    return f"{result['target']} is {shorten(result['type'])}  ({result.get('kind', '?')}{size_str}){guessed}"


def format_frame(result, ns=None):
    head = f"frame of {result['func']} @ {result['ea']:x}   size {result['size']:#x}"
    return head + "\n" + _members_table(result.get("members", []))
