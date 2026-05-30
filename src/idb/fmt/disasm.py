"""disas / decompile formatters."""


def _addr_width(lines):
    return max((len(f"{ln['ea']:x}") for ln in lines), default=8)


def format_disas(result, ns=None):
    lines = result.get("lines", [])
    out = []
    f = result.get("func")
    if result.get("mode") == "func" and f:
        out.append(f"{f['name']}  ({f['seg']} @ {f['start']:#x}):")
    width = _addr_width(lines)
    for ln in lines:
        row = f"{ln['ea']:0{width}x}  {ln['text']}"
        if ln.get("comment"):
            row += f"   ; {ln['comment']}"
        out.append(row)
    return "\n".join(out) if out else "(no instructions)"


def format_decompile(result, ns=None):
    head = f"// {result['func']} @ {result['ea']:#x}"
    return head + "\n" + "\n".join(result.get("lines", []))
