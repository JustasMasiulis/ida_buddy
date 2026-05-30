"""Tier-1/2 worker tests that need no IDA: budget + dispatch (error mapping,
meta-tuple contract, size-cap guard). dispatch imports no ida_*; handlers are
registered ad hoc here, so the real (ida-importing) handler modules never load."""

import pytest

from idb import protocol
from idb.errors import IdbError
from idb.worker import dispatch
from idb.worker.budget import Budget


def test_budget_trips_on_pure_loop():
    b = Budget(-1.0)
    with pytest.raises(IdbError) as ei:
        for _ in range(100000):
            b.check()
    assert ei.value.code == protocol.TIMEOUT


def test_budget_none_never_trips():
    b = Budget(None)
    for _ in range(1000):
        b.check()
    assert not b.expired


@pytest.fixture
def ctx():
    dispatch.CTX.token = "secret"
    dispatch.CTX.ready = True
    saved = dict(dispatch.HANDLERS)
    yield
    dispatch.HANDLERS.clear()
    dispatch.HANDLERS.update(saved)


def _call(token, cmd, args):
    raw = protocol.encode(protocol.build_request(1, token, cmd, args))
    return protocol.decode(dispatch.dispatch(raw))


def test_ok_and_meta_tuple(ctx):
    @dispatch.handler("echo")
    def _echo(x):
        return {"x": x}

    @dispatch.handler("pg")
    def _pg():
        return {"data": [1, 2]}, {"truncated": True, "next_offset": 2}

    assert _call("secret", "echo", {"x": 5})["result"]["x"] == 5
    assert _call("secret", "pg", {})["meta"]["next_offset"] == 2


def test_bad_args_from_binding(ctx):
    @dispatch.handler("need")
    def _need(a):
        return {"a": a}

    assert _call("secret", "need", {"b": 1})["error"]["code"] == protocol.BAD_ARGS


def test_unknown_cmd(ctx):
    assert _call("secret", "nope", {})["error"]["code"] == protocol.UNKNOWN_CMD


def test_unauthorized(ctx):
    @dispatch.handler("p")
    def _p():
        return {}

    assert _call("wrong", "p", {})["error"]["code"] == protocol.UNAUTHORIZED


def test_bad_version(ctx):
    raw = protocol.encode({"v": 99, "id": 1, "tok": "secret", "cmd": "x", "args": {}})
    assert protocol.decode(dispatch.dispatch(raw))["error"]["code"] == protocol.BAD_REQUEST


def test_idberror_and_internal(ctx):
    @dispatch.handler("boom")
    def _boom():
        raise IdbError(protocol.NOT_FOUND, "missing")

    @dispatch.handler("crash")
    def _crash():
        raise RuntimeError("oops")

    assert _call("secret", "boom", {})["error"]["code"] == protocol.NOT_FOUND
    assert _call("secret", "crash", {})["error"]["code"] == protocol.INTERNAL


def test_not_ready(ctx):
    dispatch.CTX.ready = False

    @dispatch.handler("q")
    def _q():
        return {}

    assert _call("secret", "q", {})["error"]["code"] == protocol.NOT_READY


def test_writes_handler_runs_without_ida(ctx):
    @dispatch.handler("w", writes=True)
    def _w():
        return {"ok": True}

    # _create_undo_point imports ida_undo, which fails here and is swallowed.
    assert _call("secret", "w", {})["result"]["ok"] is True


def test_finalize_size_cap(monkeypatch):
    monkeypatch.setattr(dispatch, "MAX_REPLY_BYTES", 64)
    reply = protocol.decode(dispatch._finalize(1, {"data": list(range(2000))}, None))
    assert reply["ok"] and reply["meta"]["truncated"]
    assert len(reply["result"]["data"]) < 2000
