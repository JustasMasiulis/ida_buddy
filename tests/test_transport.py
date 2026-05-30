import hmac
import threading
import time

import pytest
import zmq

from idb import protocol
from idb.errors import IdbError
from idb.transport import ZmqClient, ZmqServer

TOKEN = "00112233445566778899aabbccddeeff"


def _serve(server, stop):
    while not stop.is_set():
        raw = server.recv(timeout_ms=100)
        if raw is None:
            continue
        req = protocol.decode(raw)
        rid = req.get("id")
        if not hmac.compare_digest(str(req.get("tok", "")), TOKEN):
            server.send(protocol.encode(protocol.build_error(rid, protocol.UNAUTHORIZED, "bad token")))
            continue
        cmd = req.get("cmd")
        if cmd == "ping":
            server.send(protocol.encode(protocol.build_ok(rid, {"status": "ready"})))
        elif cmd == "echo":
            server.send(protocol.encode(protocol.build_ok(rid, req.get("args"))))
        elif cmd == "slow":
            time.sleep(0.3)  # outlast the client timeout; late reply lands on a dead peer
            server.send(protocol.encode(protocol.build_ok(rid, {"slow": True})))
        else:
            server.send(protocol.encode(protocol.build_error(rid, protocol.UNKNOWN_CMD, "?")))


@pytest.fixture
def server():
    ctx = zmq.Context()
    srv = ZmqServer(0, ctx=ctx)
    stop = threading.Event()
    thread = threading.Thread(target=_serve, args=(srv, stop), daemon=True)
    thread.start()
    yield srv, ctx
    stop.set()
    thread.join(timeout=2)
    srv.close()
    ctx.term()


def test_ping_roundtrip(server):
    srv, ctx = server
    client = ZmqClient(srv.port, TOKEN, ctx=ctx)
    reply = client.call("ping", {}, timeout_ms=2000)
    assert protocol.is_ok(reply)
    assert reply["result"]["status"] == "ready"
    client.close()


def test_echo_preserves_bytes(server):
    srv, ctx = server
    client = ZmqClient(srv.port, TOKEN, ctx=ctx)
    payload = {"blob": bytes(range(8)), "text": "hi"}
    reply = client.call("echo", payload, timeout_ms=2000)
    assert reply["result"] == payload
    assert isinstance(reply["result"]["blob"], bytes)
    client.close()


def test_bad_token_is_unauthorized(server):
    srv, ctx = server
    client = ZmqClient(srv.port, "deadbeef", ctx=ctx)
    reply = client.call("ping", {}, timeout_ms=2000)
    assert reply["ok"] is False
    assert reply["error"]["code"] == protocol.UNAUTHORIZED
    client.close()


def test_unknown_cmd(server):
    srv, ctx = server
    client = ZmqClient(srv.port, TOKEN, ctx=ctx)
    reply = client.call("nope", {}, timeout_ms=2000)
    assert reply["error"]["code"] == protocol.UNKNOWN_CMD
    client.close()


def test_timeout_then_socket_reset_recovers(server):
    srv, ctx = server
    client = ZmqClient(srv.port, TOKEN, ctx=ctx)
    with pytest.raises(IdbError) as ei:
        client.call("slow", {}, timeout_ms=50)
    assert ei.value.code == protocol.TIMEOUT
    # The REQ socket was reset; a fresh call on a new socket must still work,
    # proving the Poller re-register + LINGER=0 recreation path.
    reply = client.call("ping", {}, timeout_ms=2000)
    assert protocol.is_ok(reply)
    client.close()
