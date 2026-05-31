"""Handler modules register themselves on import via the @handler decorator.

`load_all()` imports every handler module (which is what triggers registration).
It is called from serve.py AFTER idapro is activated, so importing this package
on its own (e.g. during pure tests) does not pull in any ida_* module.
"""


def load_all():
    from . import info, symbols, disasm, memory, xrefs, types, annotate, eval  # noqa: F401
