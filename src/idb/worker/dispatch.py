"""@handler registry + request dispatch.

The REP loop is single-threaded and lockstep, so handlers call ida_* directly
(no execute_sync). This module imports no ida_* itself; the only ida call is the
lazy `create_undo_point` before a mutation. Handler return contract:
    result_dict                       -> ok, no envelope meta
    (result_dict, meta_dict|None)     -> ok, meta carries truncation/next_offset
"""

import hmac
import inspect

from idb import protocol
from idb.errors import IdbError

HANDLERS = {}

MAX_REPLY_BYTES = 8 * 1024 * 1024


def handler(name, *, writes=False, always=False, budget=None):
    def deco(fn):
        fn._writes = writes
        fn._always = always
        fn._budget = budget
        HANDLERS[name] = fn
        return fn

    return deco


class Context:
    def __init__(self):
        self.token = ""
        self.ready = False
        self.session_id = ""
        self.target = ""
        self.stop = None
        self.save_override = None


CTX = Context()


def _err(rid, code, message):
    return protocol.encode(protocol.build_error(rid, code, message))


def _create_undo_point(cmd):
    import ida_undo

    ida_undo.create_undo_point("idb", cmd)


def dispatch(raw):
    try:
        msg = protocol.decode(raw)
    except Exception:
        return _err(0, protocol.BAD_REQUEST, "undecodable request")
    if not isinstance(msg, dict):
        return _err(0, protocol.BAD_REQUEST, "request is not a map")
    rid = msg.get("id", 0)
    if msg.get("v") != protocol.PROTOCOL_VERSION:
        return _err(rid, protocol.BAD_REQUEST, f"protocol version mismatch: {msg.get('v')!r}")
    if not hmac.compare_digest(str(msg.get("tok", "")), CTX.token):
        return _err(rid, protocol.UNAUTHORIZED, "bad token")
    cmd = msg.get("cmd")
    fn = HANDLERS.get(cmd)
    if fn is None:
        return _err(rid, protocol.UNKNOWN_CMD, f"unknown command: {cmd!r}")
    if not CTX.ready and not fn._always:
        return _err(rid, protocol.NOT_READY, "worker is still analyzing")
    args = msg.get("args") or {}
    if not isinstance(args, dict):
        return _err(rid, protocol.BAD_ARGS, "args is not a map")
    try:
        inspect.signature(fn).bind(**args)
    except TypeError as exc:
        return _err(rid, protocol.BAD_ARGS, f"{cmd}: {exc}")

    if fn._writes:
        try:
            _create_undo_point(cmd)
        except Exception:
            pass

    try:
        out = fn(**args)
    except IdbError as exc:
        return protocol.encode(exc.to_error(rid))
    except Exception as exc:
        return _err(rid, protocol.INTERNAL, f"{type(exc).__name__}: {exc}")

    if isinstance(out, tuple) and len(out) == 2:
        result, meta = out
    else:
        result, meta = out, None
    return _finalize(rid, result, meta)


def _finalize(rid, result, meta):
    blob = protocol.encode(protocol.build_ok(rid, result, meta))
    if len(blob) <= MAX_REPLY_BYTES:
        return blob
    if isinstance(result, dict) and isinstance(result.get("data"), list) and result["data"]:
        data = result["data"]
        meta = dict(meta or {})
        while data and len(blob) > MAX_REPLY_BYTES:
            del data[-max(1, len(data) // 8):]
            meta.update(truncated=True, shown=len(data), next_offset=len(data))
            blob = protocol.encode(protocol.build_ok(rid, result, meta))
        return blob
    return _err(rid, protocol.INTERNAL, "reply exceeds size cap and cannot be trimmed")
