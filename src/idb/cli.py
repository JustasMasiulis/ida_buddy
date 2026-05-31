"""idb command-line front end. Imports NO ida_* / idapro — it resolves a session
from the registry files and does one RPC round-trip per invocation.

Windbg-flavored aliases (u, dec, db/dw/dd/dq, da/du, x, ln, dt) are
accepted by argparse, then canonicalized through the ALIASES table so aliases
can carry distinct option defaults (e.g. db vs dq both map to `read` with
different widths).
"""

import argparse
import sys

from idb import __version__, protocol, registry, spawn
from idb import doctor as doctor_mod
from idb.errors import IdbError, exit_code_for, NO_SESSION, AMBIGUOUS
from idb.transport import ZmqClient
from idb.fmt import (
    listing,
    disasm as fmt_disasm,
    memory as fmt_memory,
    xrefs as fmt_xrefs,
    types as fmt_types,
    writes as fmt_writes,
    sessions as fmt_sessions,
)

DEFAULT_TIMEOUT = 30.0

ALIASES = {
    "u": ("disas", {}),
    "uf": ("disas", {"whole": True}),
    "dec": ("decompile", {}),
    "db": ("read", {"width": 1}),
    "dw": ("read", {"width": 2}),
    "dd": ("read", {"width": 4}),
    "dq": ("read", {"width": 8}),
    "da": ("string", {"encoding": "ascii"}),
    "du": ("string", {"encoding": "utf16"}),
    "dps": ("pointers", {}),
    "dqs": ("pointers", {}),
    "ds": ("string_struct", {"wide": False}),
    "dS": ("string_struct", {"wide": True}),
    "x": ("names", {}),
    "ln": ("nearest", {}),
    "dt": ("type", {}),
    "struct": ("type", {}),
    "s": ("search", {}),
    "xref_to": ("xrefs", {"direction": "to"}),
    "xref_from": ("xrefs", {"direction": "from"}),
}

_ALIASES_BY_COMMAND = {}
for _alias, (_command, _defaults) in ALIASES.items():
    _ALIASES_BY_COMMAND.setdefault(_command, []).append(_alias)

FORMATTERS = {
    "open_summary": listing.format_open_summary,
    "segments": listing.format_segments,
    "save": listing.format_saved,
    "disas": fmt_disasm.format_disas,
    "decompile": fmt_disasm.format_decompile,
    "read": fmt_memory.format_read,
    "string": fmt_memory.format_string,
    "pointers": fmt_memory.format_pointers,
    "string_struct": fmt_memory.format_string_struct,
    "funcs": listing.format_funcs,
    "names": listing.format_names,
    "imports": listing.format_imports,
    "exports": listing.format_exports,
    "strings": listing.format_strings,
    "nearest": listing.format_nearest,
    "xrefs": fmt_xrefs.format_xrefs,
    "calls": fmt_xrefs.format_calls,
    "strrefs": fmt_xrefs.format_strrefs,
    "search": fmt_xrefs.format_search,
    "type": fmt_types.format_type,
    "types": fmt_types.format_types,
    "member": fmt_types.format_member,
    "typeof": fmt_types.format_typeof,
    "frame": fmt_types.format_frame,
    "rename": fmt_writes.format_rename,
    "comment": fmt_writes.format_comment,
    "op": fmt_writes.format_op,
    "patch": fmt_writes.format_patch,
    "undo": fmt_writes.format_undo,
    "redo": fmt_writes.format_redo,
    "declare": fmt_writes.format_declare,
    "settype": fmt_writes.format_settype,
    "setmember": fmt_writes.format_setmember,
    "setlvar": fmt_writes.format_setlvar,
    "enum": fmt_writes.format_enum,
    "union_select": fmt_writes.format_union_select,
}

_LIVE = (registry.STATUS_READY, registry.STATUS_BUSY, registry.STATUS_ANALYZING)

_GLOBAL_DEFAULTS = {
    "session": None,
    "idb": None,
    "offset": 0,
    "count": None,
    "timeout": None,
    "total": False,
    "verbose": 0,
}


def _global_flags():
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("-s", "--session", default=argparse.SUPPRESS,
                   help="session id (see `idb sessions`)")
    g.add_argument("--idb", default=argparse.SUPPRESS,
                   help="resolve the session by database/binary path")
    g.add_argument("-o", "--offset", type=int, default=argparse.SUPPRESS,
                   help="pagination offset")
    g.add_argument("-n", "--count", type=int, default=argparse.SUPPRESS,
                   help="item/insn/cell count")
    g.add_argument("-t", "--timeout", type=float, default=argparse.SUPPRESS,
                   help="client wait, seconds")
    g.add_argument("--total", action="store_true", default=argparse.SUPPRESS,
                   help="compute total counts when possible")
    g.add_argument("-v", "--verbose", action="count", default=argparse.SUPPRESS)
    return g


def build_parser():
    root_globals = _global_flags()
    command_globals = _global_flags()
    p = argparse.ArgumentParser(
        prog="idb",
        description="IDA Pro Buddy",
        parents=[root_globals],
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    def cmd(name, **kw):
        aliases = _ALIASES_BY_COMMAND.get(name, ())
        return sub.add_parser(name, parents=[command_globals], aliases=aliases, **kw)

    sp = cmd("open", help="spawn+analyze a binary/db and print a summary")
    sp.add_argument("target")
    sp.add_argument("--fresh", action="store_true", help="re-analyze from the binary")

    cmd("sessions", help="list workers")
    sp = cmd("close", help="shut a worker down")
    sp.add_argument("--no-save", dest="no_save", action="store_true")
    sp.add_argument("--kill", action="store_true", help="TerminateProcess (wedged worker)")
    sp.add_argument("--all", action="store_true")
    cmd("save", help="persist the .i64 now")
    cmd("doctor", help="probe the environment")

    cmd("segments", help="segments + rwx")
    for name, helptext in (("funcs", "functions"), ("imports", "imports"),
                           ("exports", "entry points"), ("strings", "strings")):
        sp = cmd(name, help=helptext)
        sp.add_argument("pattern", nargs="?", default=None)
    sp = cmd("names", help="symbols by pattern (alias: x)")
    sp.add_argument("pattern", nargs="?", default=None)
    sp = cmd("nearest", help="nearest symbol to addr (alias: ln)")
    sp.add_argument("addr")

    sp = cmd("disas", help="disassemble N insns from target (alias: u; uf=whole function)")
    sp.add_argument("target")
    sp = cmd("decompile", help="pseudocode (alias: dec)")
    sp.add_argument("func")
    sp = cmd("read", help="dump cells (aliases: db/dw/dd/dq)")
    sp.add_argument("addr")
    sp.add_argument("-w", "--width", type=int, choices=(1, 2, 4, 8), default=None)
    sp = cmd("string", help="read a string (aliases: da/du)")
    sp.add_argument("addr")
    sp.add_argument("-e", "--encoding", choices=("ascii", "utf16"), default=None)
    sp = cmd("pointers", help="dump pointers + nearest symbol (aliases: dps/dqs)")
    sp.add_argument("addr")
    sp = cmd("string_struct", help="counted string struct (ds=ANSI_STRING, dS=UNICODE_STRING)")
    sp.add_argument("addr")

    sp = cmd("xrefs", help="cross-references to/from addr (aliases: xref_to/xref_from)")
    sp.add_argument("addr")
    sp.add_argument("-d", "--direction", choices=("to", "from", "both"), default=None)
    sp = cmd("calls", help="callers + callees")
    sp.add_argument("func")
    sp.add_argument("--depth", type=int, default=1, help="expand callers upward N levels")
    sp = cmd("strrefs", help="xrefs to strings matching a pattern")
    sp.add_argument("pattern")
    sp = cmd("search", help="search bytes/imm/str/ref (alias: s)")
    sp.add_argument("pattern")
    sp.add_argument("-k", "--kind", choices=("bytes", "imm", "str", "ref"), default="bytes")

    sp = cmd("type", help="type def / value overlay / type-of an address (aliases: dt/struct)")
    sp.add_argument("name")
    sp.add_argument("addr", nargs="?", default=None)
    sp = cmd("types", help="list/search local types")
    sp.add_argument("pattern", nargs="?", default=None)
    sp.add_argument("-k", "--kind", default=None)
    sp = cmd("member", help="member at byte offset (nested path, union arms)")
    sp.add_argument("type")
    sp.add_argument("member_offset", metavar="byte_off")
    sp = cmd("typeof", help="type of a global/local/stack-var/function")
    sp.add_argument("target")
    sp = cmd("frame", help="stack/local variables")
    sp.add_argument("func")

    sp = cmd("rename", help="rename func/global/local/stack [mut]")
    sp.add_argument("addr")
    sp.add_argument("name")
    sp = cmd("comment", help="set a comment [mut]")
    sp.add_argument("addr")
    sp.add_argument("text")
    sp = cmd("op", help="set operand display: hex/dec/oct/bin/char/num/enum:NAME [mut]")
    sp.add_argument("addr")
    sp.add_argument("fmt", metavar="<hex|dec|oct|bin|char|num|enum:NAME>")
    sp.add_argument("opnum", nargs="?", type=int, default=None)
    sp = cmd("declare", help='create types: "<C>" | --file P | @P [mut]')
    sp.add_argument("decl", nargs="?", default=None)
    sp.add_argument("--file", default=None)
    sp = cmd("settype", help="apply a type [mut]")
    sp.add_argument("target")
    sp.add_argument("type")
    sp = cmd("setlvar", help="rename and/or retype a Hex-Rays local in one step [mut]")
    sp.add_argument("func")
    sp.add_argument("var")
    sp.add_argument("--name", default=None)
    sp.add_argument("--type", dest="type", default=None)
    sp = cmd("setmember", help="edit a struct member [mut]")
    sp.add_argument("type")
    sp.add_argument("member")
    sp.add_argument("new_type")
    sp.add_argument("new_name", nargs="?", default=None)
    sp = cmd("enum", help="create/extend an enum [mut]")
    sp.add_argument("name")
    sp.add_argument("members", help="k=v,k=v,...")
    sp.add_argument("--bitfield", action="store_true")
    sp = cmd("patch", help="patch bytes [mut]")
    sp.add_argument("addr")
    sp.add_argument("hex")
    cmd("undo", help="revert last mutation [mut]")
    cmd("redo", help="replay [mut]")
    sp = cmd("union-select", help="choose a union arm at a usage site [mut]")
    sp.add_argument("addr")
    sp.add_argument("member")
    return p


def _read_decl(ns):
    if ns.file:
        with open(ns.file, "r", encoding="utf-8") as f:
            return f.read()
    text = ns.decl
    if text and text.startswith("@"):
        with open(text[1:], "r", encoding="utf-8") as f:
            return f.read()
    if not text:
        raise IdbError(protocol.BAD_ARGS, "declare needs a C declaration, --file PATH, or @PATH")
    return text


def normalize_namespace(ns):
    canonical, implied = ALIASES.get(ns.command, (ns.command, {}))
    ns.command = canonical
    for key, value in implied.items():
        if getattr(ns, key, None) is None:
            setattr(ns, key, value)
    for key, value in _GLOBAL_DEFAULTS.items():
        if not hasattr(ns, key):
            setattr(ns, key, value)
    return ns


def _page(ns):
    return {"offset": ns.offset, "count": ns.count}


def _lpage(ns):
    return {"offset": ns.offset, "count": ns.count, "total": ns.total}


def _paginate_list(items, offset=0, count=None):
    offset = int(offset or 0)
    if offset >= len(items):
        return [], None
    if count is None:
        return items[offset:], None
    end = offset + int(count)
    return items[offset:end], (end if end < len(items) else None)


def build_request(ns):
    c = ns.command
    if c in ("save", "undo", "redo"):
        return c, {}
    if c == "segments":
        return c, _lpage(ns)
    if c in ("funcs", "imports", "exports", "strings", "names"):
        return c, {"pattern": ns.pattern, **_lpage(ns)}
    if c == "nearest":
        return c, {"addr": ns.addr}
    if c == "disas":
        args = {"target": ns.target, **_page(ns)}
        if getattr(ns, "whole", None):
            args["whole"] = True
        return c, args
    if c == "decompile":
        return c, {"func": ns.func, **_page(ns)}
    if c == "read":
        return c, {"addr": ns.addr, "width": ns.width or 1, **_page(ns)}
    if c == "string":
        return c, {"addr": ns.addr, "encoding": ns.encoding}
    if c == "pointers":
        return c, {"addr": ns.addr, **_page(ns)}
    if c == "string_struct":
        return c, {"addr": ns.addr, "wide": bool(getattr(ns, "wide", False))}
    if c == "xrefs":
        return c, {"addr": ns.addr, "direction": ns.direction or "to", **_page(ns)}
    if c == "calls":
        return c, {"func": ns.func, "depth": ns.depth, **_page(ns)}
    if c == "strrefs":
        return c, {"pattern": ns.pattern, **_page(ns)}
    if c == "search":
        return c, {"pattern": ns.pattern, "kind": ns.kind, **_page(ns)}
    if c == "type":
        return c, {"name": ns.name, "addr": ns.addr, **_page(ns)}
    if c == "types":
        return c, {"pattern": ns.pattern, "kind": ns.kind, **_lpage(ns)}
    if c == "member":
        return c, {"type": ns.type, "offset": ns.member_offset, "page_offset": ns.offset, "count": ns.count}
    if c == "typeof":
        return c, {"target": ns.target}
    if c == "frame":
        return c, {"func": ns.func, **_page(ns)}
    if c == "rename":
        return c, {"addr": ns.addr, "name": ns.name}
    if c == "comment":
        return c, {"addr": ns.addr, "text": ns.text}
    if c == "op":
        return c, {"addr": ns.addr, "fmt": ns.fmt, "opnum": ns.opnum}
    if c == "declare":
        return c, {"text": _read_decl(ns)}
    if c == "settype":
        return c, {"target": ns.target, "type": ns.type}
    if c == "setlvar":
        return c, {"func": ns.func, "var": ns.var, "name": ns.name, "type": ns.type}
    if c == "setmember":
        return c, {"type": ns.type, "member": ns.member, "new_type": ns.new_type, "new_name": ns.new_name}
    if c == "enum":
        return c, {"name": ns.name, "members": ns.members, "bitfield": ns.bitfield}
    if c == "patch":
        return c, {"addr": ns.addr, "hex": ns.hex}
    if c == "union-select":
        return "union_select", {"addr": ns.addr, "member": ns.member}
    raise IdbError(protocol.BAD_ARGS, f"unhandled command {c!r}")


def resolve_session(ns):
    registry.cleanup_stale()
    entries = registry.list_all()
    if ns.session:
        matched = registry.match(entries, session=ns.session)
        if not matched:
            raise IdbError(NO_SESSION, f"no session named {ns.session!r}")
        return matched[0]
    if ns.idb:
        matched = registry.match(entries, idb=ns.idb)
        if not matched:
            raise IdbError(NO_SESSION, f"no session for {ns.idb!r}")
        if len(matched) > 1:
            print(fmt_sessions.format_sessions(matched), file=sys.stderr)
            raise IdbError(AMBIGUOUS, f"{len(matched)} sessions match {ns.idb!r}; use -s")
        return matched[0]
    live = [e for e in entries if registry.probe(e) in _LIVE]
    if not live:
        raise IdbError(NO_SESSION, "no running sessions; run `idb open <binary>` first")
    if len(live) == 1:
        return live[0]
    print(fmt_sessions.format_sessions([{**e, "status": registry.probe(e)} for e in live]),
          file=sys.stderr)
    raise IdbError(AMBIGUOUS, f"{len(live)} sessions; disambiguate with -s <id> or --idb <path>")


def _banner(meta):
    parts = []
    if meta.get("truncated"):
        nxt = meta.get("next_offset")
        parts.append(f"[+more; resume with -o {nxt}]" if nxt is not None else "[+more]")
    if meta.get("total") is not None:
        parts.append(f"[total {meta['total']}]")
    return " ".join(parts)


def emit(rpc_cmd, reply, ns):
    if not protocol.is_ok(reply):
        err = reply["error"]
        print(f"idb: {err['code']}: {err['message']}", file=sys.stderr)
        return exit_code_for(err["code"])
    text = FORMATTERS.get(rpc_cmd, listing.format_generic)(reply.get("result"), ns)
    if text:
        print(text)
    meta = reply.get("meta")
    if meta:
        line = _banner(meta)
        if line:
            print(line, file=sys.stderr)
    return 0


def run_remote(ns, rpc_cmd, rpc_args):
    entry = resolve_session(ns)
    client = ZmqClient(entry["port"], entry["token"])
    timeout = ns.timeout if ns.timeout else DEFAULT_TIMEOUT
    try:
        reply = client.call(rpc_cmd, rpc_args, timeout_ms=int(timeout * 1000))
    finally:
        client.close()
    return emit(rpc_cmd, reply, ns)


def cmd_open(ns):
    entry, summary = spawn.open_or_reuse(
        ns.target,
        fresh=ns.fresh,
        deadline_s=ns.timeout if ns.timeout else spawn.DEFAULT_OPEN_DEADLINE,
    )
    print(listing.format_open_summary(summary))
    if ns.verbose:
        print(f"session {entry['id']}  port {entry['port']}  pid {entry['pid']}", file=sys.stderr)
    return 0


def cmd_sessions(ns):
    registry.cleanup_stale()
    rows = [{**e, "status": registry.probe(e) or "dead"} for e in registry.list_all()]
    page, next_offset = _paginate_list(rows, ns.offset, ns.count)
    print(fmt_sessions.format_sessions(page))
    meta = _banner({"shown": len(page), "truncated": True, "next_offset": next_offset}) if next_offset is not None else ""
    if meta:
        print(meta, file=sys.stderr)
    return 0


def _close_one(entry, kill, save, timeout_s=20.0):
    import time

    sid, pid = entry["id"], entry.get("pid")
    if kill:
        spawn.kill_pid(pid)
        registry.unregister(sid)
        return f"killed {sid} (pid {pid})"
    client = ZmqClient(entry["port"], entry["token"])
    try:
        client.call("shutdown", {"save": save}, timeout_ms=15000)
    except IdbError:
        spawn.kill_pid(pid)
        registry.unregister(sid)
        return f"{sid} unreachable; killed"
    finally:
        client.close()
    deadline = time.time() + timeout_s
    while time.time() < deadline and registry.pid_alive(pid):
        time.sleep(0.1)
    registry.unregister(sid)
    return f"closed {sid} (save={save})"


def cmd_close(ns):
    if ns.all:
        targets = registry.list_all()
        if not targets:
            print("no sessions to close", file=sys.stderr)
            return 0
    else:
        targets = [resolve_session(ns)]
    for entry in targets:
        print(_close_one(entry, kill=ns.kill, save=not ns.no_save), file=sys.stderr)
    return 0


def cmd_doctor(ns):
    rows, ok = doctor_mod.run()
    page, next_offset = _paginate_list(rows, ns.offset, ns.count)
    print(fmt_sessions.format_doctor(page))
    meta = _banner({"shown": len(page), "truncated": True, "next_offset": next_offset}) if next_offset is not None else ""
    if meta:
        print(meta, file=sys.stderr)
    return 0 if ok else 1


LIFECYCLE = {
    "open": cmd_open,
    "sessions": cmd_sessions,
    "close": cmd_close,
    "doctor": cmd_doctor,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        build_parser().print_help()
        return 0
    if argv[0] in ("--version", "-V"):
        print(__version__)
        return 0

    try:
        ns = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    normalize_namespace(ns)

    try:
        if ns.command in LIFECYCLE:
            return LIFECYCLE[ns.command](ns)
        rpc_cmd, rpc_args = build_request(ns)
        return run_remote(ns, rpc_cmd, rpc_args)
    except IdbError as exc:
        print(f"idb: {exc.code}: {exc.message}", file=sys.stderr)
        if exc.data:
            print(str(exc.data), file=sys.stderr)
        return exit_code_for(exc.code)


if __name__ == "__main__":
    sys.exit(main())
