"""Open summary / segments formatters, plus a generic fallback used by
commands whose dedicated formatter hasn't landed yet."""

import json

from .columns import align


def _h(value):
    return hex(value) if isinstance(value, int) else str(value)


def format_open_summary(s, ns=None):
    size = s.get("size", 0)
    lines = [
        f"{s.get('input', '?')}   {s.get('format', '')}",
        f"  arch     {s.get('arch')} {s.get('bitness')}-bit {s.get('endian')}-endian",
        f"  base     {_h(s.get('base', 0))}   size {_h(size)} ({size} bytes)",
        f"  range    {_h(s.get('min_ea', 0))} - {_h(s.get('max_ea', 0))}",
    ]
    if s.get("md5"):
        lines.append(f"  md5      {s['md5']}")
    if s.get("sha256"):
        lines.append(f"  sha256   {s['sha256']}")
    lines.append(
        f"  segments {s.get('num_segments')}   functions {s.get('num_functions')}"
        f"   named globals {s.get('num_globals')}"
    )
    eps = s.get("entry_points") or []
    if eps:
        shown = ", ".join(f"{e['name']}@{_h(e['ea'])}" for e in eps[:4])
        more = f" (+{len(eps) - 4} more)" if len(eps) > 4 else ""
        lines.append(f"  entry    {shown}{more}")
    return "\n".join(lines)


def format_segments(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no segments)"
    table = [
        (r["name"], _h(r["start"]), _h(r["end"]), _h(r["size"]), r["perm"], r.get("class", ""))
        for r in rows
    ]
    return align(table, headers=("NAME", "START", "END", "SIZE", "PERM", "CLASS"),
                 aligns=("<", ">", ">", ">", "<", "<"))


def format_saved(result, ns=None):
    return f"saved {result.get('saved')}"


def _oneline(text, limit=100):
    flat = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def format_funcs(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no functions)"
    table = [(_h(r["ea"]), _h(r["size"]), r["name"]) for r in rows]
    return align(table, headers=("ADDR", "SIZE", "NAME"), aligns=(">", ">", "<"))


def format_names(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no names)"
    return align([(_h(r["ea"]), r["name"]) for r in rows], headers=("ADDR", "NAME"),
                 aligns=(">", "<"))


def format_imports(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no imports)"
    table = [(_h(r["ea"]), r.get("module", ""), r["name"]) for r in rows]
    return align(table, headers=("ADDR", "MODULE", "NAME"), aligns=(">", "<", "<"))


def format_exports(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no exports)"
    table = [(_h(r["ea"]), str(r["ordinal"]), r["name"]) for r in rows]
    return align(table, headers=("ADDR", "ORD", "NAME"), aligns=(">", ">", "<"))


def format_strings(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no strings)"
    table = [(_h(r["ea"]), str(r["length"]), _oneline(r["text"])) for r in rows]
    return align(table, headers=("ADDR", "LEN", "STRING"), aligns=(">", ">", "<"))


def format_nearest(result, ns=None):
    parts = [f"{result['addr']:#x}"]
    sym = result.get("symbol")
    if sym:
        parts.append(f"{sym['name']}+{sym['offset']:#x}" if sym["offset"] else sym["name"])
    func = result.get("func")
    if func:
        suffix = f"+{func['offset']:#x}" if func["offset"] else ""
        parts.append(f"(in {func['name']}{suffix})")
    if not sym and not func:
        parts.append("(no nearby symbol)")
    return "   ".join(parts)


def format_generic(result, ns=None):
    def default(o):
        if isinstance(o, (bytes, bytearray)):
            return o.hex()
        return str(o)

    return json.dumps(result, indent=2, default=default)
