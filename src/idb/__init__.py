"""idb — a windbg-flavored CLI for headless IDA Pro reverse engineering.

The top-level package and everything under it (except worker/handlers and a few
idahelp functions) imports ONLY stdlib + pyzmq + msgspec. ida_* modules are
imported solely inside the worker, and only after idapro has been activated.
"""

__version__ = "0.1.0"
