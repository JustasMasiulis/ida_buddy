from idb import protocol


def test_request_shape_and_version():
    request = protocol.build_request(
        7,
        "deadbeef",
        "read",
        {"addr": 0x401000, "n": 16},
    )
    assert request["v"] == protocol.PROTOCOL_VERSION
    assert request["id"] == 7
    assert request["cmd"] == "read"


def test_ok_and_error_shapes():
    ok = protocol.build_ok(
        1,
        {"x": 1},
        meta={"truncated": True, "next_offset": 50},
    )
    assert ok["ok"] is True
    assert ok["result"] == {"x": 1}
    assert ok["meta"]["next_offset"] == 50

    error = protocol.build_error(
        2,
        protocol.BAD_ADDRESS,
        "nope",
        data={"addr": 0},
    )
    assert error["ok"] is False
    assert error["error"] == {
        "code": "BAD_ADDRESS",
        "message": "nope",
        "data": {"addr": 0},
    }
    assert protocol.is_ok(ok) and not protocol.is_ok(error)


def test_optional_keys_are_absent():
    assert "meta" not in protocol.build_ok(1, 5)
    assert "data" not in protocol.build_error(1, protocol.INTERNAL, "boom").get(
        "error", {}
    )


def test_native_values_are_not_coerced():
    blob = bytes(range(16))
    result = protocol.build_ok(1, {"bytes": blob, "ea": 0xFFFF_FFFF_FFFF_FFFF})
    assert result["result"]["bytes"] is blob
    assert result["result"]["ea"] == 0xFFFF_FFFF_FFFF_FFFF
