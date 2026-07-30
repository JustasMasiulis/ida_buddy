"""idb — a windbg-flavored CLI over the official IDA Code Mode RPC.

The local CLI imports no IDA modules. ``worker.handlers`` are loaded inside a
registered GUI or managed idalib process by Code Mode's synchronized
``execute_python`` endpoint.
"""

__version__ = "0.1.0"
