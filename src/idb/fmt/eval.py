"""eval (?) result formatter: unprefixed hex, 0n decimal (signed/unsigned), ascii.

The display width auto-sizes to the smallest of 8/16/32/64/128... bits that holds
the value (or the -w override). hex is zero-padded to that width; the decimal
collapses to one 0n value when signed==unsigned, else shows `0n<u> / 0n<s>`; the
ascii field appears only when the value's significant bytes are all printable.
"""


def _auto_bits(value):
    width = 8
    if value >= 0:
        while value >= (1 << width):
            width <<= 1
    else:
        while value < -(1 << (width - 1)):
            width <<= 1
    return width


def format_eval(result, ns=None):
    value = int(result["value"])
    width = result.get("width") or _auto_bits(value)
    be = result.get("be", False)

    mask = (1 << width) - 1
    unsigned = value & mask
    signed = unsigned - (1 << width) if (unsigned >> (width - 1)) & 1 else unsigned

    parts = [f"{unsigned:0{width // 4}x}"]
    parts.append(f"0n{unsigned}" if unsigned == signed else f"0n{unsigned} / 0n{signed}")

    nbytes = max(1, (unsigned.bit_length() + 7) // 8)
    raw = unsigned.to_bytes(nbytes, "big" if be else "little")
    if all(32 <= b < 127 for b in raw):
        parts.append("'" + raw.decode("latin1") + "'")

    parts.append(f"{width}bit")
    return "  ".join(parts)
