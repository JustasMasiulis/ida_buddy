"""Worker lifecycle: bind -> open -> batch(1) -> warmup -> ready -> REP loop ->
shutdown/save. All on the main thread (idalib is single-threaded), so handlers
call ida_* directly. ida_* imports happen here and below, AFTER idapro activation.
"""

import os
import sys
import signal
import threading
import time

IDLE_TTL_S = 3600

from idb import registry
from idb.errors import IdbError
from idb import protocol
from idb.transport import ZmqServer
from idb.worker import dispatch as dispatch_mod
from idb.worker.dispatch import CTX, dispatch


def _warmup():
    from idb.worker.handlers import load_all

    load_all()
    try:
        import ida_hexrays

        ida_hexrays.init_hexrays_plugin()
    except Exception:
        pass
    from idb.worker.handlers import info

    info.warmup()


def _save_decision(save_policy):
    if CTX.save_override is not None:
        return bool(CTX.save_override)
    return save_policy != "no-save"


def serve(port, token, session_id, open_path, input_path, save_policy, logfile=None):
    import idapro
    import ida_auto
    import idc

    stop = threading.Event()
    try:
        signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
    except AttributeError:
        pass  # SIGTERM not defined on this platform (Windows)
    try:
        server = ZmqServer(port)
    except Exception as exc:
        print(f"bind failed on port {port}: {exc}", file=sys.stderr, flush=True)
        return 3

    CTX.token = token
    CTX.session_id = session_id
    CTX.target = input_path
    CTX.stop = stop
    CTX.ready = False
    CTX.save_override = None

    registry.update(
        session_id,
        status=registry.STATUS_ANALYZING,
        port=server.port,
        token=token,
        pid=os.getpid(),
        input_path=os.path.abspath(input_path),
        started_at=registry.now(),
        logfile=logfile,
    )

    opened = False
    try:
        rc = idapro.open_database(open_path, True)
        if rc != 0:
            raise IdbError(protocol.IDA_ERROR, f"open_database failed rc={rc}")
        opened = True
        ida_auto.auto_wait()
        _warmup()
        registry.update(session_id, status=registry.STATUS_READY, idb_path=idc.get_idb_path())
        CTX.ready = True
        CTX.last_request = time.time()

        while not stop.is_set():
            raw = server.recv(timeout_ms=500)
            if raw is None:
                if time.time() - CTX.last_request > IDLE_TTL_S:
                    print(f"[idb] worker idle for {IDLE_TTL_S}s; shutting down",
                          file=sys.stderr, flush=True)
                    break
                continue
            server.send(dispatch(raw))
            CTX.last_request = time.time()
    except IdbError as exc:
        print(f"worker error: {exc.code}: {exc.message}", file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"worker crashed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    finally:
        # Unregister only AFTER close_database: while a long save is running the
        # entry must stay visible (probe -> busy, pid alive) so a concurrent
        # `idb open` of the same target cannot spawn a second worker over the
        # half-written .i64.
        try:
            if opened:
                save = _save_decision(save_policy)
                try:
                    idapro.close_database(save)
                except Exception as exc:
                    print(f"close_database error: {exc}", file=sys.stderr, flush=True)
        finally:
            registry.unregister(session_id)
            server.close()
    return 0 if opened else 4
