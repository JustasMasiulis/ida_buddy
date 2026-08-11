from idb import protocol


def test_ok_and_error_shapes():
    ok = protocol.build_ok(
        {"x": 1},
        meta={"truncated": True, "next_offset": 50},
    )
    assert ok["ok"] is True
    assert ok["result"] == {"x": 1}
    assert ok["meta"]["next_offset"] == 50

    error = protocol.build_error(
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
    assert "meta" not in protocol.build_ok(5)
    assert "data" not in protocol.build_error(protocol.INTERNAL, "boom").get(
        "error", {}
    )


def test_native_values_are_not_coerced():
    blob = bytes(range(16))
    result = protocol.build_ok({"bytes": blob, "ea": 0xFFFF_FFFF_FFFF_FFFF})
    assert result["result"]["bytes"] is blob
    assert result["result"]["ea"] == 0xFFFF_FFFF_FFFF_FFFF


def test_bytes_payload_survives_the_json_wire():
    # Code Mode's serializer turns bytes into repr() strings; our envelope codec
    # must round-trip every payload shape the handlers produce.
    payload = {
        "bytes": bytes(range(256)),
        "rows": [{"raw": b"\x00\x01"}, {"raw": bytearray(b"\x02")}],
        "view": memoryview(b"mv"),
        "text": "unchanged",
        "ea": 0xFFFF_FFFF,
    }
    wire = protocol.encode_bytes(payload)
    import json

    json.dumps(wire)  # the encoded form must be JSON-safe

    out = protocol.decode_bytes(wire)
    assert out["bytes"] == bytes(range(256))
    assert out["rows"][0]["raw"] == b"\x00\x01"
    assert out["rows"][1]["raw"] == b"\x02"
    assert out["view"] == b"mv"
    assert out["text"] == "unchanged"
    assert out["ea"] == 0xFFFF_FFFF


def test_bytes_tag_requires_exact_shape():
    # The tag key is reserved, but only an exact {tag: str} dict decodes;
    # anything wider passes through untouched.
    not_a_tag = {"$idb.b64": "aGk=", "extra": 1}
    assert protocol.decode_bytes(not_a_tag) == not_a_tag
    assert protocol.decode_bytes({"$idb.b64": 5}) == {"$idb.b64": 5}
