"""Activate idalib (`import idapro`) BEFORE any ida_* import.

Importing idapro loads idalib.dll and initializes the IDA kernel. DLL resolution
needs the IDA install dir, which idapro derives from ida-config.json (written by
py-activate-idalib.py) or, as a fallback, IDADIR. A bare sys.path prepend does
NOT fix DLL resolution, so on failure we surface the activation hint rather than
guessing. Stdlib-only imports here so this stays loadable in any interpreter."""

_HINT = (
    "idalib (the `idapro` module) failed to import/initialize in this interpreter.\n"
    "idapro installs from PyPI but needs a local IDA install to load its DLLs:\n"
    "  python -m pip install idapro\n"
    '  python "<IDA install dir>\\idalib\\python\\py-activate-idalib.py"   # writes ida-config.json\n'
    "(or set the IDADIR env var to the IDA install dir as a fallback)."
)


def ensure_idalib():
    try:
        import idapro
    except Exception as exc:
        from idb import protocol
        from idb.errors import IdbError

        raise IdbError(protocol.IDA_ERROR, f"{type(exc).__name__}: {exc}\n\n{_HINT}")
    return idapro
