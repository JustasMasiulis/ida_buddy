"""Small result-envelope contract shared by the CLI and remote handlers.

Code Mode owns transport framing and authentication. This module intentionally
has no codec or networking dependency.
"""

PROTOCOL_VERSION = 1

BAD_REQUEST = "BAD_REQUEST"
UNAUTHORIZED = "UNAUTHORIZED"
UNKNOWN_CMD = "UNKNOWN_CMD"
BAD_ARGS = "BAD_ARGS"
BAD_ADDRESS = "BAD_ADDRESS"
NOT_FOUND = "NOT_FOUND"
IDA_ERROR = "IDA_ERROR"
NOT_READY = "NOT_READY"
TIMEOUT = "TIMEOUT"
INTERNAL = "INTERNAL"


def build_request(req_id, token, cmd, args=None):
    """Legacy envelope helper retained for callers constructing test requests."""
    return {
        "v": PROTOCOL_VERSION,
        "id": req_id,
        "tok": token,
        "cmd": cmd,
        "args": args or {},
    }


def build_ok(req_id, result, meta=None):
    message = {"v": PROTOCOL_VERSION, "id": req_id, "ok": True, "result": result}
    if meta:
        message["meta"] = meta
    return message


def build_error(req_id, code, message, data=None):
    error = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {
        "v": PROTOCOL_VERSION,
        "id": req_id,
        "ok": False,
        "error": error,
    }


def is_ok(reply) -> bool:
    return isinstance(reply, dict) and reply.get("ok") is True
