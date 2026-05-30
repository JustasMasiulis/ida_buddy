"""RPC envelope + msgpack codec shared by client and worker.

Contract: text fields are `str`, only payloads are `bytes`; dict keys are `str`.
msgspec.msgpack gives us native 64-bit ints and round-trips `bytes` as msgpack
bin. No ida_* imports here.
"""

import msgspec

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

_encoder = msgspec.msgpack.Encoder()
_decoder = msgspec.msgpack.Decoder()


def encode(obj) -> bytes:
    return _encoder.encode(obj)


def decode(buf):
    return _decoder.decode(buf)


def build_request(req_id, token, cmd, args=None):
    return {"v": PROTOCOL_VERSION, "id": req_id, "tok": token, "cmd": cmd, "args": args or {}}


def build_ok(req_id, result, meta=None):
    msg = {"v": PROTOCOL_VERSION, "id": req_id, "ok": True, "result": result}
    if meta:
        msg["meta"] = meta
    return msg


def build_error(req_id, code, message, data=None):
    err = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"v": PROTOCOL_VERSION, "id": req_id, "ok": False, "error": err}


def is_ok(reply) -> bool:
    return isinstance(reply, dict) and reply.get("ok") is True
