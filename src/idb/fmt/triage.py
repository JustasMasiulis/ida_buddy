"""triage formatter — compact, section-per-aspect. Empty sections are omitted;
a trailing `+` on a count means that phase hit its cap or the time budget."""

from .columns import align
from .compact import shorten


def _th(value):
    return f"{value:x}" if isinstance(value, int) else str(value)


def _oneline(text, limit=80):
    flat = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _count(n, truncated):
    return f"{n}+" if truncated else str(n)


def _callees_block(result):
    rows = result.get("callees", [])
    head = f"callees: {_count(result.get('callee_count', len(rows)), result.get('callees_truncated'))}"
    if not rows:
        return head
    table = [(_th(r["ea"]), _th(r["size"]), str(r["callers"]), r["kind"], r["name"]) for r in rows]
    body = align(table, headers=("ADDR", "SIZE", "CALLERS", "KIND", "NAME"),
                 aligns=(">", ">", ">", "<", "<"))
    return head + "\n" + "\n".join("  " + line for line in body.splitlines())


def _groups_line(result):
    down = result.get("groups_down") or []
    up = result.get("groups_up") or []
    if not down and not up:
        return None
    parts = []
    if down:
        parts.append("down: " + ", ".join(f"{g['prefix']}* ({g['count']})" for g in down))
    if up:
        parts.append("up: " + ", ".join(f"{g['prefix']}* ({g['count']})" for g in up))
    line = "groups  " + "   ".join(parts)
    return line + "  +" if result.get("groups_truncated") else line


def _structure_block(result):
    chunks = result.get("chunks") or []
    seh = result.get("seh")
    if not chunks and not seh:
        return None
    out = ["structure"]
    if chunks:
        cells = [f"{c['ea']:x}" + (f" ({c['name']})" if c.get("name") else "") for c in chunks]
        out.append("  chunks: " + ", ".join(cells))
    if seh:
        handler = seh.get("handler") or "?"
        tag = ".pdata unwind" if seh.get("via") == "unwind" else "body call"
        if seh.get("has_frame"):
            tag += ", frame"
        out.append(f"  seh:    {handler}  ({tag})")
    return "\n".join(out)


def _params_block(result):
    rows = result.get("arg_types")
    if not rows:
        return None
    head = (f"param types: {_count(result.get('arg_caller_count', 0), result.get('arg_types_truncated'))} "
            f"callers   (underlying, before implicit casts)")
    out = [head]
    decls = [shorten(r.get("decl") or "") for r in rows]
    decl_w = max((len(d) for d in decls), default=0)
    for r, decl in zip(rows, decls):
        decl = decl.ljust(decl_w)
        actuals = ", ".join(f"{shorten(a['type'])} x{a['count']}" for a in r["actuals"])
        line = f"  a{r['index']}  {decl}  {actuals}".rstrip()
        if r.get("member"):
            line += f"   ; {r['member']}"
        out.append(line)
    return "\n".join(out)


def _strings_block(result):
    rows = result.get("strings", [])
    head = f"strings: {_count(len(rows), result.get('strings_truncated'))}"
    if not rows:
        return None
    width = max((len(f"{r['str_ea']:x}") for r in rows), default=8)
    out = [head]
    for r in rows:
        out.append(f'  {r["str_ea"]:0{width}x}  -> "{_oneline(r["text"])}"   ({r["kind"]})')
    return "\n".join(out)


def format_triage(result, ns=None):
    head = f"{result['func']} @ {result['ea']:x}  size {result['size']:#x}"
    sections = [head]
    if result.get("proto"):
        src = result.get("proto_source")
        suffix = f"  ({src})" if src in ("guessed", "tinfo") else ""
        sections.append(f"proto  {shorten(result['proto'])}{suffix}")

    blocks = [
        _callees_block(result),
        _groups_line(result),
        _structure_block(result),
        _params_block(result),
        _strings_block(result),
    ]
    body = "\n\n".join(b for b in blocks if b)
    return sections[0] + ("\n" + "\n".join(sections[1:]) if len(sections) > 1 else "") + \
        ("\n\n" + body if body else "")
