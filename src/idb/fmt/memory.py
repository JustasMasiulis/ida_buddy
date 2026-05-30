"""read (hexdump / grouped values) and string formatters."""

_HEXW = 16 * 3 - 1  # "xx xx ... xx" with one byte's space replaced by the hyphen


def _hexdump(base, data):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = [f"{b:02x}" for b in chunk]
        left = " ".join(hexs[:8])
        right = " ".join(hexs[8:])
        col = (left + "-" + right) if right else left
        gutter = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{base + off:012x}  {col:<{_HEXW}}  {gutter}")
    return "\n".join(out) if out else "(no bytes)"


def _values(base, width, values):
    per_row = max(1, 16 // width)
    out = []
    for i in range(0, len(values), per_row):
        row = values[i:i + per_row]
        cells = " ".join(f"{v:0{width * 2}x}" for v in row)
        out.append(f"{base + i * width:012x}  {cells}")
    return "\n".join(out) if out else "(no values)"


def format_read(result, ns=None):
    if "bytes" in result:
        return _hexdump(result["addr"], result["bytes"])
    return _values(result["addr"], result["width"], result["values"])


def format_string(result, ns=None):
    text = result["text"].replace("\r", "\\r").replace("\n", "\\n")
    return f'{result["addr"]:#x}  {result["encoding"]} {result["length"]} bytes  "{text}"'
