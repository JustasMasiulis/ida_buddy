"""xref_to / xref_from / calls / search formatters."""


def _addr_width(rows):
    return max((len(f"{r['ea']:x}") for r in rows), default=8)


def _ctx_lines(rows):
    width = _addr_width(rows)
    out = []
    for r in rows:
        line = f"{r['ea']:0{width}x}  {r.get('kind', ''):<6}  {r['insn']}"
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
    out = [f"{result['func']}  @ {result['ea']:#x}"]
    callers = result.get("callers", [])
    out.append(f"  callers ({len(callers)}):")
    for c in callers:
        where = f"  ; in {c['func']}" if c.get("func") else ""
        out.append(f"    {c['ea']:#x}  {c['insn']}{where}")
    callees = result.get("callees", [])
    out.append(f"  callees ({len(callees)}):")
    for c in callees:
        out.append(f"    {c['ea']:#x}  {c.get('name') or '?'}")
    return "\n".join(out)
