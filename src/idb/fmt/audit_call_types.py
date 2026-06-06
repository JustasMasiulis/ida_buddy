"""audit_call_types formatter — compact, no table. Findings split into mismatches
and concretizable; under each function name the findings sit on their own
indented lines:
    <func>
      <p|l> <slot>  <decl> -> <observed, dominant first>  <agree>% <sites>s/<distinct>d
where the first observed type is the suggestion. A trailing `+` on the scanned
count means the scan hit its budget or decompile limit."""

from .compact import shorten


def _count(n, truncated):
    return f"{n}+" if truncated else str(n)


def _value(f):
    kind = "p" if f.get("kind") == "param" else "l"
    actuals = ", ".join(f"{shorten(a['type'])} x{a['count']}" for a in f.get("actuals", []))
    line = (f"{kind} {f.get('slot', '')}  {shorten(f.get('decl') or '?')} -> {actuals}"
            f"  {round(f.get('agree', 0.0) * 100)}% {f.get('n_sites', 0)}s/{f.get('n_distinct', 0)}d")
    if f.get("member"):
        line += f"  ; {f['member']}"
    return line


def _section(title, findings):
    groups = {}
    for f in findings:
        groups.setdefault(f.get("func", ""), []).append(f)
    lines = ["", title, ""]
    for func, items in groups.items():
        lines.append(func)
        lines.extend("  " + _value(it) for it in items)
    return "\n".join(lines)


def format_audit_call_types(result, ns=None):
    head = "audit_call_types"
    if result.get("scope"):
        head += f"  scope={result['scope']}"
    findings = result.get("findings", [])
    head += (f"  scanned {_count(result.get('functions_scanned', 0), result.get('truncated'))}"
             f"/{result.get('functions_total', 0)} funcs  {result.get('call_sites', 0)} call sites"
             f"  {len(findings)} findings")

    out = [head]
    mismatches = [f for f in findings if f.get("class") == "mismatch"]
    concretize = [f for f in findings if f.get("class") == "concretize"]
    if mismatches:
        out.append(_section("mismatches", mismatches))
    if concretize:
        out.append(_section("concretizable", concretize))
    if not mismatches and not concretize:
        out.append("\nno findings")
    return "\n".join(out)
