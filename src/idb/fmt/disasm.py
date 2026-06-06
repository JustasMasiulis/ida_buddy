"""disas / decompile formatters."""

from .compact import hex_width, shorten, squash_disas


def format_disas(result, ns=None):
    lines = result.get("lines", [])
    out = []
    f = result.get("func")
    if result.get("mode") == "func" and f:
        out.append(f"{f['name']}  ({f['seg']} @ {f['start']:x}):")
    width = hex_width(ln["ea"] for ln in lines)
    for ln in lines:
        row = f"{ln['ea']:0{width}x}  {ln['text']}"
        if ln.get("comment"):
            row += f"   ; {ln['comment']}"
        out.append(row)
    return squash_disas("\n".join(out)) if out else "(no instructions)"


def format_decompile(result, ns=None):
    head = f"// {result['ea']:x}"
    return head + "\n" + shorten("\n".join(result.get("lines", [])))
