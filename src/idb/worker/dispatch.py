"""Remote handler registry and in-process invocation.

Code Mode handles authentication, JSON framing, request limits, and serialized
main-thread execution. The dispatcher only validates handler arguments, creates
undo points for mutations, and returns the compact idb result envelope.
"""

import inspect

from idb import protocol
from idb.errors import IdbError

HANDLERS = {}


def handler(name, *, writes=False, always=False, budget=None):
    def decorate(function):
        function._writes = writes
        function._always = always
        function._budget = budget
        HANDLERS[name] = function
        return function

    return decorate


class Context:
    def __init__(self):
        self.ready = False
        self.session_id = ""
        self.target = ""
        self.database = None


CTX = Context()


def _create_undo_point(command):
    import ida_undo

    ida_undo.create_undo_point("idb", command)


def invoke(command, arguments=None, *, req_id=0, ready=None):
    """Invoke one registered handler and return an unencoded result envelope."""
    function = HANDLERS.get(command)
    if function is None:
        return protocol.build_error(
            req_id,
            protocol.UNKNOWN_CMD,
            f"unknown command: {command!r}",
        )
    is_ready = CTX.ready if ready is None else bool(ready)
    if not is_ready and not function._always:
        return protocol.build_error(
            req_id,
            protocol.NOT_READY,
            "database is still analyzing",
        )
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        return protocol.build_error(req_id, protocol.BAD_ARGS, "args is not a map")
    try:
        inspect.signature(function).bind(**arguments)
    except TypeError as exc:
        return protocol.build_error(
            req_id,
            protocol.BAD_ARGS,
            f"{command}: {exc}",
        )

    if function._writes:
        try:
            _create_undo_point(command)
        except Exception:
            pass

    try:
        output = function(**arguments)
    except IdbError as exc:
        return exc.to_error(req_id)
    except Exception as exc:
        return protocol.build_error(
            req_id,
            protocol.INTERNAL,
            f"{type(exc).__name__}: {exc}",
        )

    if isinstance(output, tuple) and len(output) == 2:
        result, meta = output
    else:
        result, meta = output, None
    return protocol.build_ok(req_id, result, meta)
