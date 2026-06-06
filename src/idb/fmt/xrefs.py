"""xref_to / xref_from / calls / search formatters."""

from .compact import hex_width, squash_insn


def _ctx_lines(rows):
    width = hex_width(r["ea"] for r in rows)
    show_dir = any("dir" in r for r in rows)
    out = []
    for r in rows:
        prefix = f"{r.get('dir', ''):<4}  " if show_dir else ""
        line = f"{prefix}{r['ea']:0{width}x}  {squash_insn(r['insn'])}"
        if r.get("func"):
            line += f"   ; in {r['func']}"
        out.append(line.rstrip())
    return out


def format_xrefs(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no xrefs)"
    return "\n".join(_ctx_lines(rows))


def format_search(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no matches)"
    return "\n".join(_ctx_lines(rows))


def format_calls(result, ns=None):
    out = [f"{result['func']}  @ {result['ea']:x}"]
    callers = result.get("callers", [])
    out.append(f"  callers ({len(callers)}):")
    for c in callers:
        indent = "  " * (c.get("depth", 1) - 1)
        where = f"  ; in {c['func']}" if c.get("func") else ""
        out.append(f"    {indent}{c['ea']:x}  {squash_insn(c['insn'])}{where}")
    callees = result.get("callees", [])
    out.append(f"  callees ({len(callees)}):")
    for c in callees:
        out.append(f"    {c['ea']:x}  {c.get('name') or '?'}")
    return "\n".join(out)


def format_strrefs(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return f"(no refs to strings matching {result.get('pattern', '')!r})"
    width = hex_width(r["ea"] for r in rows)
    out = []
    for r in rows:
        line = f"{r['ea']:0{width}x}  {squash_insn(r['insn'])}"
        bits = []
        if r.get("func"):
            bits.append(f"in {r['func']}")
        if r.get("str") is not None:
            bits.append(f'"{r["str"]}"')
        if bits:
            line += "   ; " + "  ".join(bits)
        out.append(line.rstrip())
    return "\n".join(out)
