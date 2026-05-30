"""Strict worker bootstrap.

Imports ONLY stdlib until idapro is activated, so the invariant "no ida_* import
before idapro" holds (test_import_order asserts it in a clean process). serve and
everything that touches ida_* are imported lazily, AFTER ensure_idalib().
"""

import argparse
import os
import sys


def _parse_args(argv):
    p = argparse.ArgumentParser(prog="idb-worker", add_help=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--session", required=True)
    p.add_argument("--open", dest="open_path", required=True, help="path passed to open_database")
    p.add_argument("--input", dest="input_path", required=True, help="logical target (for display/identity)")
    p.add_argument("--idle-ttl", type=float, default=1800.0)
    p.add_argument("--save-policy", default="save", choices=("save", "no-save"))
    p.add_argument("--logfile", default=None)
    return p.parse_args(argv)


def main(argv=None):
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    token = os.environ.get("IDB_WORKER_TOKEN", "")

    from idb.worker.activate import ensure_idalib

    ensure_idalib()  # import idapro (kernel init) -> only now may ida_* be imported

    from idb.worker.serve import serve

    return serve(
        port=args.port,
        token=token,
        session_id=args.session,
        open_path=args.open_path,
        input_path=args.input_path,
        idle_ttl=args.idle_ttl,
        save_policy=args.save_policy,
        logfile=args.logfile,
    )


if __name__ == "__main__":
    sys.exit(main())
