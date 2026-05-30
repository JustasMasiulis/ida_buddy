"""ZeroMQ REQ/REP transport over loopback TCP. No ida_* imports.

Client: one REQ socket, per-call Poller timeout. A timeout leaves the REQ state
machine mid-cycle, so we close the socket (LINGER=0) and recreate it for the next
call. Server: one REP socket, Poller-driven recv so the worker can re-check its
stop flag on each timeout. Strict REQ/REP lockstep: every recv MUST be answered
by exactly one send (the worker always replies, even to malformed requests).
"""

import zmq

from . import protocol
from .errors import IdbError

LOOPBACK = "127.0.0.1"


class ZmqClient:
    def __init__(self, port, token, ctx=None):
        self.port = int(port)
        self.token = token
        self._ctx = ctx or zmq.Context.instance()
        self._sock = None
        self._next_id = 0

    def _connect(self):
        if self._sock is None:
            sock = self._ctx.socket(zmq.REQ)
            sock.setsockopt(zmq.LINGER, 0)
            sock.connect(f"tcp://{LOOPBACK}:{self.port}")
            self._sock = sock
        return self._sock

    def _reset(self):
        if self._sock is not None:
            self._sock.close(linger=0)
            self._sock = None

    def call(self, cmd, args=None, timeout_ms=30000):
        self._next_id += 1
        req = protocol.build_request(self._next_id, self.token, cmd, args)
        sock = self._connect()
        sock.send(protocol.encode(req))
        poller = zmq.Poller()
        poller.register(sock, zmq.POLLIN)
        if not (dict(poller.poll(timeout_ms)).get(sock, 0) & zmq.POLLIN):
            self._reset()
            raise IdbError(protocol.TIMEOUT, f"no reply from worker within {timeout_ms} ms")
        return protocol.decode(sock.recv())

    def close(self):
        self._reset()


class ZmqServer:
    def __init__(self, port, ctx=None):
        self._ctx = ctx or zmq.Context.instance()
        self._sock = self._ctx.socket(zmq.REP)
        self._sock.setsockopt(zmq.LINGER, 0)
        self.port = self._bind(port)
        self._poller = zmq.Poller()
        self._poller.register(self._sock, zmq.POLLIN)

    def _bind(self, port):
        if not port:
            return self._sock.bind_to_random_port(f"tcp://{LOOPBACK}")
        self._sock.bind(f"tcp://{LOOPBACK}:{int(port)}")
        return int(port)

    def recv(self, timeout_ms=500):
        """Raw request bytes, or None on timeout (so the loop can re-check stop)."""
        if not (dict(self._poller.poll(timeout_ms)).get(self._sock, 0) & zmq.POLLIN):
            return None
        return self._sock.recv()

    def send(self, payload):
        self._sock.send(payload)

    def close(self):
        self._sock.close(linger=0)
