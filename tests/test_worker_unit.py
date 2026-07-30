"""Pure tests for budgets and the Code Mode remote dispatcher."""

import pytest

from idb import protocol
from idb.errors import IdbError
from idb.worker import dispatch
from idb.worker.budget import Budget


def test_budget_trips_on_pure_loop():
    budget = Budget(-1.0)
    with pytest.raises(IdbError) as error:
        for _ in range(100000):
            budget.check()
    assert error.value.code == protocol.TIMEOUT


def test_budget_none_never_trips():
    budget = Budget(None)
    for _ in range(1000):
        budget.check()
    assert not budget.expired


@pytest.fixture
def handlers():
    dispatch.CTX.ready = True
    saved = dict(dispatch.HANDLERS)
    yield
    dispatch.HANDLERS.clear()
    dispatch.HANDLERS.update(saved)


def test_ok_and_meta_tuple(handlers):
    @dispatch.handler("echo")
    def echo(value):
        return {"value": value}

    @dispatch.handler("page")
    def page():
        return {"data": [1, 2]}, {"truncated": True, "next_offset": 2}

    assert dispatch.invoke("echo", {"value": 5})["result"] == {"value": 5}
    assert dispatch.invoke("page")["meta"]["next_offset"] == 2


def test_bad_args_and_unknown_command(handlers):
    @dispatch.handler("need")
    def need(value):
        return {"value": value}

    assert dispatch.invoke("need", {"other": 1})["error"]["code"] == protocol.BAD_ARGS
    assert dispatch.invoke("missing")["error"]["code"] == protocol.UNKNOWN_CMD


def test_idb_error_and_internal_error(handlers):
    @dispatch.handler("missing")
    def missing():
        raise IdbError(protocol.NOT_FOUND, "not found")

    @dispatch.handler("crash")
    def crash():
        raise RuntimeError("oops")

    assert dispatch.invoke("missing")["error"]["code"] == protocol.NOT_FOUND
    assert dispatch.invoke("crash")["error"]["code"] == protocol.INTERNAL


def test_not_ready(handlers):
    @dispatch.handler("query")
    def query():
        return {}

    assert dispatch.invoke("query", ready=False)["error"]["code"] == protocol.NOT_READY


def test_write_handler_tolerates_unavailable_undo_api(handlers):
    @dispatch.handler("write", writes=True)
    def write():
        return {"ok": True}

    assert dispatch.invoke("write")["result"]["ok"] is True
