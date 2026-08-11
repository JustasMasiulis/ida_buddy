"""Remote handler registry and in-process invocation.

Code Mode handles authentication, JSON framing, request limits, and serialized
main-thread execution. The dispatcher only validates handler arguments, creates
undo points for mutations, and returns the compact idb result envelope.
"""

import inspect

from idb import protocol
from idb.errors import IdbError

HANDLERS = {}


def handler(name, *, writes=False, always=False):
    def decorate(function):
        function._writes = writes
        function._always = always
        HANDLERS[name] = function
        return function

    return decorate


class Context:
    def __init__(self):
        self.ready = False


CTX = Context()


def _create_undo_point(command):
    import ida_undo

    ida_undo.create_undo_point("idb", command)


def invoke(command, arguments=None):
    """Invoke one registered handler and return an unencoded result envelope."""
    function = HANDLERS.get(command)
    if function is None:
        return protocol.build_error(protocol.UNKNOWN_CMD, f"unknown command: {command!r}")
    if not CTX.ready and not function._always:
        return protocol.build_error(protocol.NOT_READY, "database is still analyzing")
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        return protocol.build_error(protocol.BAD_ARGS, "args is not a map")
    try:
        inspect.signature(function).bind(**arguments)
    except TypeError as exc:
        return protocol.build_error(protocol.BAD_ARGS, f"{command}: {exc}")

    if function._writes:
        try:
            _create_undo_point(command)
        except Exception:
            pass

    try:
        output = function(**arguments)
    except IdbError as exc:
        return exc.to_error()
    except Exception as exc:
        return protocol.build_error(protocol.INTERNAL, f"{type(exc).__name__}: {exc}")

    if isinstance(output, tuple) and len(output) == 2:
        result, meta = output
    else:
        result, meta = output, None
    return protocol.build_ok(result, meta)
