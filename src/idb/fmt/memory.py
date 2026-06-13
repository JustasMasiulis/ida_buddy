"""read (hexdump / grouped values) and string formatters."""

from .compact import escape_text, hex_width

_HEXW = 16 * 3 - 1  # "xx xx ... xx" with one byte's space replaced by the hyphen


def _ascii_gutter(chunk):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def _utf16_gutter(chunk):
    cells = (chunk[i] | (chunk[i + 1] << 8) for i in range(0, len(chunk) - 1, 2))
    return "".join(chr(cp) if 32 <= cp < 127 else "." for cp in cells)


def _hexdump(base, data, gutter=_ascii_gutter):
    offsets = range(0, len(data), 16)
    aw = hex_width((base + off for off in offsets), default=1)
    out = []
    for off in offsets:
        chunk = data[off:off + 16]
        hexs = [f"{b:02x}" for b in chunk]
        left = " ".join(hexs[:8])
        right = " ".join(hexs[8:])
        col = (left + "-" + right) if right else left
        out.append(f"{base + off:0{aw}x}  {col:<{_HEXW}}  {gutter(chunk)}")
    return "\n".join(out) if out else "(no bytes)"


def _values(base, width, values):
    per_row = max(1, 16 // width)
    starts = range(0, len(values), per_row)
    aw = hex_width((base + i * width for i in starts), default=1)
    out = []
    for i in starts:
        row = values[i:i + per_row]
        cells = " ".join(f"{v:0{width * 2}x}" for v in row)
        out.append(f"{base + i * width:0{aw}x}  {cells}")
    return "\n".join(out) if out else "(no values)"


def format_read(result, ns=None):
    if "bytes" in result:
        return _hexdump(result["addr"], result["bytes"])
    return _values(result["addr"], result["width"], result["values"])


def format_string(result, ns=None):
    if result.get("redirected_to_struct"):  # da/du landed on a *_STRING struct
        return format_string_struct(result, ns)
    if result.get("raw_fallback"):  # no string here; windbg-style memory dump
        gutter = _utf16_gutter if result["encoding"] == "utf16" else _ascii_gutter
        return _hexdump(result["addr"], result["bytes"], gutter)
    text = escape_text(result["text"], tabs=False)
    line = f'{result["addr"]:x}  {result["encoding"]} {result["length"]} bytes  "{text}"'
    if result.get("text_truncated"):
        line += "  [+more; use da/du with -o N to resume, or db to hexdump]"
    return line


def format_pointers(result, ns=None):
    rows = result.get("data", [])
    if not rows:
        return "(no pointers)"
    w = result["width"] * 2
    aw = max(len(f"{r['ea']:x}") for r in rows)
    out = []
    for r in rows:
        line = f"{r['ea']:0{aw}x}  {r['value']:0{w}x}"
        if r.get("sym"):
            line += f"  {r['sym']}" + (f"+{r['off']:x}" if r.get("off") else "")
        out.append(line)
    return "\n".join(out)


def format_string_struct(result, ns=None):
    kind = "UNICODE_STRING" if result["wide"] else "ANSI_STRING"
    text = escape_text(result.get("text") or "", tabs=False)
    return (f'{result["addr"]:x}  {kind} len={result["length"]} '
            f'max={result["maxlen"]} buf={result["buffer"]:x}  "{text}"')
