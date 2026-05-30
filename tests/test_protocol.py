from idb import protocol


def _roundtrip(obj):
    return protocol.decode(protocol.encode(obj))


def test_request_roundtrip_and_version():
    req = protocol.build_request(7, "deadbeef", "read", {"addr": 0x401000, "n": 16})
    out = _roundtrip(req)
    assert out == req
    assert out["v"] == protocol.PROTOCOL_VERSION
    assert out["id"] == 7
    assert out["cmd"] == "read"


def test_ok_and_error_shapes():
    ok = protocol.build_ok(1, {"x": 1}, meta={"truncated": True, "next_offset": 50})
    out = _roundtrip(ok)
    assert out["ok"] is True
    assert out["result"] == {"x": 1}
    assert out["meta"]["next_offset"] == 50

    err = protocol.build_error(2, protocol.BAD_ADDRESS, "nope", data={"addr": 0})
    out = _roundtrip(err)
    assert out["ok"] is False
    assert out["error"]["code"] == "BAD_ADDRESS"
    assert out["error"]["message"] == "nope"
    assert out["error"]["data"] == {"addr": 0}
    assert protocol.is_ok(ok) and not protocol.is_ok(err)


def test_no_meta_no_data_keys_when_absent():
    assert "meta" not in protocol.build_ok(1, 5)
    assert "data" not in protocol.build_error(1, protocol.INTERNAL, "boom")


def test_bytes_payload_survives_as_bytes():
    blob = bytes(range(256))
    out = _roundtrip(protocol.build_ok(1, {"bytes": blob, "text": "hello"}))
    assert out["result"]["bytes"] == blob
    assert isinstance(out["result"]["bytes"], bytes)
    assert isinstance(out["result"]["text"], str)


def test_64bit_ints_preserved():
    for value in (0, 0x401000, 0x7FFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF):
        out = _roundtrip(protocol.build_ok(1, {"ea": value}))
        assert out["result"]["ea"] == value


def test_decoded_keys_are_str():
    req = protocol.build_request(1, "t", "x", {"nested": {"a": 1}})
    out = _roundtrip(req)
    assert all(isinstance(k, str) for k in out)
    assert all(isinstance(k, str) for k in out["args"])
    assert all(isinstance(k, str) for k in out["args"]["nested"])
