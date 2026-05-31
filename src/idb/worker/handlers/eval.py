"""eval: evaluate an arithmetic/bitwise expression with symbol lookup.

The numeric work lives in the pure idb.expr module; this handler only supplies
the IDA-backed operand resolver (idahelp.resolve_target) and the database word
width / endianness. The result crosses the wire as a decimal string because an
exact product can exceed 64 bits, which the msgpack codec cannot carry.
"""

import ida_ida

from idb import expr as expr_mod
from idb.worker import idahelp
from idb.worker.dispatch import handler


@handler("eval")
def evaluate(expr, width=None):
    wrap_bits = (int(width) * 8) if width else (ida_ida.inf_get_app_bitness() or 64)
    value = expr_mod.evaluate(expr, idahelp.resolve_target, wrap_bits)
    return {
        "expr": expr,
        "value": str(value),
        "width": (int(width) * 8) if width else None,
        "be": bool(ida_ida.inf_is_be()),
    }
