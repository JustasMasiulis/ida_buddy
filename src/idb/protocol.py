"""Small result-envelope contract shared by the CLI and remote handlers.

Code Mode owns transport framing and authentication, but its wire is JSON and
its fallback serializer destroys ``bytes`` (repr() strings). encode_bytes /
decode_bytes preserve the old msgpack contract — only payloads are ``bytes``,
and they round-trip — by tagging them as ``{"$idb.b64": <base64>}`` dicts.
"""

import base64

BAD_ARGS = "BAD_ARGS"
BAD_ADDRESS = "BAD_ADDRESS"
NOT_FOUND = "NOT_FOUND"
IDA_ERROR = "IDA_ERROR"
NOT_READY = "NOT_READY"
TIMEOUT = "TIMEOUT"
INTERNAL = "INTERNAL"
UNKNOWN_CMD = "UNKNOWN_CMD"

_BYTES_TAG = "$idb.b64"


def build_ok(result, meta=None):
    message = {"ok": True, "result": result}
    if meta:
        message["meta"] = meta
    return message


def build_error(code, message, data=None):
    error = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"ok": False, "error": error}


def is_ok(reply) -> bool:
    return isinstance(reply, dict) and reply.get("ok") is True


def encode_bytes(value):
    """JSON-safe copy of value with every bytes payload tagged.  Copy-on-write:
    a subtree with no bytes is returned unchanged, so the common byte-free
    envelope allocates nothing."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {_BYTES_TAG: base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        changed = None
        for key, item in value.items():
            encoded = encode_bytes(item)
            if encoded is not item:
                if changed is None:
                    changed = dict(value)
                changed[key] = encoded
        return value if changed is None else changed
    if isinstance(value, (list, tuple)):
        changed = None
        for index, item in enumerate(value):
            encoded = encode_bytes(item)
            if encoded is not item:
                if changed is None:
                    changed = list(value)
                changed[index] = encoded
        return value if changed is None else changed
    return value


def decode_bytes(value):
    """Invert encode_bytes. Only an exact ``{"$idb.b64": str}`` dict decodes;
    the key is reserved — handlers must not emit it themselves.  Copy-on-write,
    like encode_bytes."""
    if isinstance(value, dict):
        if len(value) == 1 and isinstance(value.get(_BYTES_TAG), str):
            return base64.b64decode(value[_BYTES_TAG])
        changed = None
        for key, item in value.items():
            decoded = decode_bytes(item)
            if decoded is not item:
                if changed is None:
                    changed = dict(value)
                changed[key] = decoded
        return value if changed is None else changed
    if isinstance(value, list):
        changed = None
        for index, item in enumerate(value):
            decoded = decode_bytes(item)
            if decoded is not item:
                if changed is None:
                    changed = list(value)
                changed[index] = decoded
        return value if changed is None else changed
    return value
