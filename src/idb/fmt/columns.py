"""Fixed-width column aligner. Pure; the basis for every table formatter."""


def align(rows, headers=None, gap=2, aligns=None):
    rows = [tuple("" if c is None else str(c) for c in r) for r in rows]
    ncol = max((len(r) for r in rows), default=len(headers or ()))
    if headers:
        ncol = max(ncol, len(headers))
    widths = [0] * ncol
    for r in ([tuple(headers)] if headers else []) + rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    spacer = " " * gap

    def render(r):
        out = []
        for i in range(ncol):
            cell = r[i] if i < len(r) else ""
            right = aligns is not None and i < len(aligns) and aligns[i] == ">"
            out.append(f"{cell:>{widths[i]}}" if right else f"{cell:<{widths[i]}}")
        return spacer.join(out).rstrip()

    lines = []
    if headers:
        lines.append(render(tuple(headers)))
    lines.extend(render(r) for r in rows)
    return "\n".join(lines)
