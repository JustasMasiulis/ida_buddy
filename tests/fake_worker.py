"""Non-IDA fake worker for spawn/CLI tests. Speaks the idb protocol over ZMQ so
spawn's readiness/reuse logic can be exercised without launching IDA.

Modes: ready (bind + serve), crash (exit 1 immediately). A bind collision exits 3,
matching the real serve.py, so port-retry can be tested by pre-occupying the port.
"""

import argparse
import hmac
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idb import protocol, registry
from idb.transport import ZmqServer

_SUMMARY = {
    "input": "thing.exe", "format": "FAKE", "arch": "metapc", "bitness": 64,
    "endian": "little", "base": 0x140000000, "min_ea": 0x140001000,
    "max_ea": 0x140002000, "size": 0x1000, "md5": None, "sha256": None,
    "num_functions": 1, "num_globals": 0, "num_segments": 1, "entry_points": [],
    "idb_path": r"C:\fake\thing.exe.i64",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--session", required=True)
    ap.add_argument("--mode", default="ready")
    ap.add_argument("--register", action="store_true")
    args = ap.parse_args()
    token = os.environ.get("IDB_WORKER_TOKEN", "")

    if args.mode == "crash":
        sys.exit(1)
    try:
        server = ZmqServer(args.port)
    except Exception:
        sys.exit(3)

    if args.register:
        registry.update(args.session, status=registry.STATUS_READY, port=args.port, token=token,
                        pid=os.getpid(), input_path=r"C:\fake\thing.exe",
                        idb_path=r"C:\fake\thing.exe.i64", started_at=registry.now())

    stop = False
    while not stop:
        raw = server.recv(timeout_ms=200)
        if raw is None:
            continue
        msg = protocol.decode(raw)
        rid = msg.get("id")
        if not hmac.compare_digest(str(msg.get("tok", "")), token):
            server.send(protocol.encode(protocol.build_error(rid, protocol.UNAUTHORIZED, "bad token")))
            continue
        cmd = msg.get("cmd")
        if cmd == "ping":
            server.send(protocol.encode(protocol.build_ok(rid, {"status": "ready", "session": args.session})))
        elif cmd == "open_summary":
            server.send(protocol.encode(protocol.build_ok(rid, dict(_SUMMARY))))
        elif cmd == "shutdown":
            server.send(protocol.encode(protocol.build_ok(rid, {"stopping": True})))
            registry.unregister(args.session)
            stop = True
        else:
            server.send(protocol.encode(protocol.build_error(rid, protocol.UNKNOWN_CMD, "?")))
    server.close()


if __name__ == "__main__":
    main()
