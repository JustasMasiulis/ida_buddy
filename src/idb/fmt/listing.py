"""Open summary / segments formatters, plus a generic fallback used by
commands whose dedicated formatter hasn't landed yet."""

import json
import os

from .columns import align
from .compact import escape_text, hx


def format_open_summary(s, ns=None):
    size = s.get("size", 0)
    lines = [
        f"{s.get('input', '?')}   {s.get('format', '')}",
        f"  arch     {s.get('arch')} {s.get('bitness')}-bit {s.get('endian')}-endian",
        f"  base     {hx(s.get('base', 0))}   size {hx(size)} ({size} bytes)",
        f"  range    {hx(s.get('min_ea', 0))} - {hx(s.get('max_ea', 0))}",
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
        shown = ", ".join(f"{e['name']}@{hx(e['ea'])}" for e in eps[:4])
        more = f" (+{len(eps) - 4} more)" if len(eps) > 4 else ""
        lines.append(f"  entry    {shown}{more}")
    return "\n".join(lines)


def format_segments(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no segments)"
    table = [
        (r["name"], hx(r["start"]), hx(r["end"]), hx(r["size"]), r["perm"], r.get("class", ""))
        for r in rows
    ]
    return align(table, headers=("NAME", "START", "END", "SIZE", "PERM", "CLASS"),
                 aligns=("<", ">", ">", ">", "<", "<"))


def format_saved(result, ns=None):
    return f"saved {os.path.basename(result.get('saved') or '')}"


def format_funcs(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no functions)"
    table = [(hx(r["ea"]), hx(r["size"]), r["name"]) for r in rows]
    return align(table, headers=("ADDR", "SIZE", "NAME"), aligns=(">", ">", "<"))


def format_names(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no names)"
    return align([(hx(r["ea"]), r["name"]) for r in rows], headers=("ADDR", "NAME"),
                 aligns=(">", "<"))


def format_imports(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no imports)"
    table = [(hx(r["ea"]), r.get("module", ""), r["name"]) for r in rows]
    return align(table, headers=("ADDR", "MODULE", "NAME"), aligns=(">", "<", "<"))


def format_exports(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no exports)"
    table = [(hx(r["ea"]), str(r["ordinal"]), r["name"]) for r in rows]
    return align(table, headers=("ADDR", "ORD", "NAME"), aligns=(">", ">", "<"))


def format_strings(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no strings)"
    table = [(hx(r["ea"]), str(r["length"]), escape_text(r["text"], 100)) for r in rows]
    return align(table, headers=("ADDR", "LEN", "STRING"), aligns=(">", ">", "<"))


def format_nearest(result, ns=None):
    parts = [f"{result['addr']:x}"]
    sym = result.get("symbol")
    if sym:
        parts.append(f"{sym['name']}+{sym['offset']:x}" if sym["offset"] else sym["name"])
    func = result.get("func")
    if func:
        suffix = f"+{func['offset']:x}" if func["offset"] else ""
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
