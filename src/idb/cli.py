"""idb command-line front end over official IDA Code Mode handles.

Every invocation discovers or opens a registered database, performs one Code
Mode operation, and releases its handle. No idb daemon or cross-process lease is
retained.

Windbg-flavored aliases (u, dec, db/dw/dd/dq, da/du, x, ln, dt) are
accepted by argparse, then canonicalized through the ALIASES table so aliases
can carry distinct option defaults (e.g. db vs dq both map to `read` with
different widths).
"""

import argparse
import sys

from idb import __version__, codemode, protocol
from idb import doctor as doctor_mod
from idb.errors import IdbError, exit_code_for, AMBIGUOUS
from idb.fmt import (
    listing,
    disasm as fmt_disasm,
    memory as fmt_memory,
    xrefs as fmt_xrefs,
    types as fmt_types,
    writes as fmt_writes,
    sessions as fmt_sessions,
    eval as fmt_eval,
    triage as fmt_triage,
    audit_call_types as fmt_audit,
)

DEFAULT_TIMEOUT = 30.0

ALIASES = {
    "?": ("eval", {}),
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
    "types": ("type", {"enumerate": True}),
    "s": ("search", {}),
    "xref_to": ("xrefs", {"direction": "to"}),
    "xref_from": ("xrefs", {"direction": "from"}),
}

_ALIASES_BY_COMMAND = {}
for _alias, (_command, _defaults) in ALIASES.items():
    _ALIASES_BY_COMMAND.setdefault(_command, []).append(_alias)

FORMATTERS = {
    "eval": fmt_eval.format_eval,
    "triage": fmt_triage.format_triage,
    "audit_call_types": fmt_audit.format_audit_call_types,
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
    "set_member": fmt_writes.format_set_member,
    "insert_member": fmt_writes.format_insert_member,
    "del_member": fmt_writes.format_del_member,
    "setlvar": fmt_writes.format_setlvar,
    "enum": fmt_writes.format_enum,
    "union_select": fmt_writes.format_union_select,
}

_GLOBAL_DEFAULTS = {
    "session": None,
    "idb": None,
    "offset": 0,
    "count": None,
    "timeout": None,
    "total": False,
    "verbose": 0,
}


_PAGE_UNITS = {
    "segments": "rows (default: all)",
    "funcs": "rows (default 200)", "imports": "rows (default 200)",
    "exports": "rows (default 200)", "strings": "rows (default 200)",
    "names": "rows (default 200)",
    "disas": "instructions (default 32; whole-func cap 2048)",
    "decompile": "lines (default 120)",
    "read": "cells (default 64 B at width 1, else 16)",
    "pointers": "pointers (default 16)", "xrefs": "rows (default 200)",
    "calls": "callers (default 200)", "strrefs": "rows (default 200)",
    "search": "matches (default 200)", "type": "members (resolve, default 300) / rows (search, default 300)",
    "member": "paths (default 200)", "frame": "variables (default: all)",
    "audit_call_types": "findings (default 50)",
    "string": "text chars (default 4096)",
    "sessions": "rows", "doctor": "rows",
}
_TOTAL_CMDS = frozenset({"segments", "funcs", "imports", "exports", "strings", "names", "type",
                         "audit_call_types"})


def _session_flags():
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("-s", "--session", default=argparse.SUPPRESS,
                   help="session id (see `idb sessions`)")
    g.add_argument("--idb", default=argparse.SUPPRESS,
                   help="resolve the session by database/binary path")
    g.add_argument("-t", "--timeout", type=float, default=argparse.SUPPRESS,
                   help="client wait, seconds")
    g.add_argument("-v", "--verbose", action="count", default=argparse.SUPPRESS,
                   help="more detail on stderr")
    return g


def _global_flags():
    g = _session_flags()
    g.add_argument("-o", "--offset", type=int, default=argparse.SUPPRESS,
                   help="pagination offset")
    g.add_argument("-n", "--count", type=int, default=argparse.SUPPRESS,
                   help="item/insn/cell count")
    g.add_argument("--total", action="store_true", default=argparse.SUPPRESS,
                   help="compute total counts when possible")
    return g


def _add_flags(sp, name):
    paged = name in _PAGE_UNITS
    sp.add_argument("-o", "--offset", type=int, default=argparse.SUPPRESS,
                    help="pagination offset" if paged else argparse.SUPPRESS)
    sp.add_argument("-n", "--count", type=int, default=argparse.SUPPRESS,
                    help=_PAGE_UNITS[name] if paged else argparse.SUPPRESS)
    sp.add_argument("--total", action="store_true", default=argparse.SUPPRESS,
                    help="also report the full count (extra scan)"
                         if name in _TOTAL_CMDS else argparse.SUPPRESS)

_ROOT_DESCRIPTION = (
    "IDA Pro Buddy - drive a registered IDA GUI or managed idalib session from the shell. "
    "Each call opens an official Code Mode DatabaseHandle, performs one operation, and releases "
    "it. Use --idb <path> to spawn/target idalib explicitly; when exactly one registered "
    "database is live it is selected automatically. "
    "WinDbg-style aliases "
    "(u, dec, db/dw/dd/dq, da/du, x, ln, dt, s) are recommended."
)
_ROOT_EPILOG = (
    "conventions:\n"
    "  addresses    0x401000, a name (sub_401000), or an expression\n"
    "  pagination   -o/--offset + -n/--count; a [+more; resume with -o N] hint prints to stderr;\n"
    "               --total adds full counts where supported (see each command's -h)\n"
    "  mutations    [mut] commands modify the database; undo/redo revert them"
)


def build_parser():
    command_globals = _session_flags()
    p = argparse.ArgumentParser(
        prog="idb",
        description=_ROOT_DESCRIPTION,
        epilog=_ROOT_EPILOG,
        parents=[_global_flags()],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    def cmd(name, help=None, ex=None, **kw):
        aliases = _ALIASES_BY_COMMAND.get(name, ())
        epilog = "examples:\n" + "\n".join("  idb " + e for e in ex) if ex else None
        sp = sub.add_parser(name, parents=[command_globals], aliases=aliases, help=help,
                            description=help, epilog=epilog,
                            formatter_class=argparse.RawDescriptionHelpFormatter, **kw)
        _add_flags(sp, name)
        return sp

    sp = cmd("open", help="attach to a registered GUI or managed idalib database",
             ex=(r"open C:\bins\foo.exe", "open foo.exe --fresh"))
    sp.add_argument("target")
    sp.add_argument("--fresh", action="store_true",
                    help="create a new IDB from the input (refuses a live owner)")

    cmd("sessions", help="list registered Code Mode databases", ex=("sessions",))
    cmd("save", help="persist the .i64 now", ex=("save --idb foo.exe",))
    cmd("doctor", help="probe the environment", ex=("doctor",))

    cmd("segments", help="segments + rwx", ex=("segments --total",))
    for name, helptext, example in (
        ("funcs", "functions", "funcs Create -n 50 --total"),
        ("imports", "imports", "imports kernel32"),
        ("exports", "entry points", "exports"),
        ("strings", "strings", "strings lic -n 100"),
    ):
        sp = cmd(name, help=helptext, ex=(example,))
        sp.add_argument("pattern", nargs="?", default=None)
    sp = cmd("names", help="symbols by pattern (alias: x)", ex=("names CreateFile", "x sub_"))
    sp.add_argument("pattern", nargs="?", default=None)
    sp = cmd("nearest", help="nearest symbol to addr (alias: ln)", ex=("nearest 0x401037", "ln 0x401037"))
    sp.add_argument("addr")
    sp = cmd("eval", help="evaluate an arithmetic/bitwise expression (alias: ?)",
             ex=("eval (1<<12) - 1", "? 0x401000 + 8"))
    sp.add_argument("expr", nargs="+", help="expression; prefix with -- if it starts with '-'")
    sp.add_argument("-w", "--width", type=int, choices=(1, 2, 4, 8), default=None,
                    help="byte width for wrapping + signed/display (default: pointer width; auto display)")

    sp = cmd("disas", help="disassemble N insns from target (alias: u; uf=whole function)",
             ex=("disas sub_401000 -n 16", "uf 0x401000"))
    sp.add_argument("target")
    sp = cmd("decompile", help="pseudocode (alias: dec)", ex=("decompile sub_401000", "dec main"))
    sp.add_argument("func")
    sp = cmd("read", help="dump cells (aliases: db/dw/dd/dq)", ex=("read 0x140001000 -n 64", "dq 0x140001000 -n 8"))
    sp.add_argument("addr")
    sp.add_argument("-w", "--width", type=int, choices=(1, 2, 4, 8), default=None)
    sp = cmd("string", help="read a string (aliases: da/du)", ex=("da 0x140003000", "du 0x140003000"))
    sp.add_argument("addr")
    sp.add_argument("-e", "--encoding", choices=("ascii", "utf16"), default=None)
    sp = cmd("pointers", help="dump pointers + nearest symbol (aliases: dps/dqs)",
             ex=("dps 0x140005000 -n 8",))
    sp.add_argument("addr")
    sp = cmd("string_struct", help="counted string struct (ds=ANSI_STRING, dS=UNICODE_STRING)",
             ex=("ds 0x140006000", "dS 0x140006000"))
    sp.add_argument("addr")

    sp = cmd("xrefs", help="cross-references to/from addr (aliases: xref_to/xref_from)",
             ex=("xref_to 0x401000", "xrefs 0x401000 -d both"))
    sp.add_argument("addr")
    sp.add_argument("-d", "--direction", choices=("to", "from", "both"), default=None)
    sp = cmd("calls", help="callers + callees", ex=("calls sub_401000", "calls main --depth 3"))
    sp.add_argument("func")
    sp.add_argument("--depth", type=int, default=1, help="expand callers upward N levels")
    sp = cmd("triage", help="single-function pre-RE summary: callees, groups, SEH, strings",
             ex=("triage sub_401000",))
    sp.add_argument("func")
    sp = cmd("audit_call_types",
             help="global call-graph type audit: params/locals to concretize or that look mislabeled",
             ex=("audit_call_types", "audit_call_types Wfp -n 30", "audit_call_types --kind locals"))
    sp.add_argument("scope", nargs="?", default=None,
                    help="name pattern to narrow the audit (default: whole database)")
    sp.add_argument("--budget", type=float, default=None, help="wall-clock budget, seconds (default 20)")
    sp.add_argument("--limit", type=int, default=None, help="max functions to decompile (default 400)")
    sp.add_argument("--min-sites", dest="min_sites", type=int, default=None,
                    help="min call sites for a param finding (default 3)")
    sp.add_argument("--min-callers", dest="min_callers", type=int, default=None,
                    help="min distinct callers for a param finding (default 2)")
    sp.add_argument("--no-imports", dest="no_imports", action="store_true",
                    help="exclude import/library callees from findings")
    sp.add_argument("--kind", choices=("all", "params", "locals"), default="all",
                    help="which findings to compute (default all)")
    sp.add_argument("--all", dest="show_all", action="store_true",
                    help="drop the evidence thresholds (min sites/callers/agreement); the "
                         "noise filters (alias/const/placeholder respelling) still apply")
    sp = cmd("strrefs", help="xrefs to strings matching a pattern", ex=("strrefs license",))
    sp.add_argument("pattern")
    sp = cmd("search", help="search bytes/imm/str/ref (alias: s)",
             ex=('search "90 90" -k bytes', 's GetProcAddress -k str'))
    sp.add_argument("pattern")
    sp.add_argument("-k", "--kind", choices=("bytes", "imm", "str", "ref"), default="bytes")

    sp = cmd("type",
             help="resolve/overlay a named type, type-of an address, or search types "
                  "(alias: dt; types forces search)",
             ex=("type GUID", "dt _EPROCESS 0x140008000",
                 "types -k struct", "type 'IMAGE_*' --size 0x10", "type -e"))
    sp.add_argument("name", nargs="?", default=None,
                    help="type name to resolve, or a search pattern in list mode")
    sp.add_argument("addr", nargs="?", default=None, help="overlay address (resolve mode only)")
    sp.add_argument("-e", "--enumerate", action="store_true", default=argparse.SUPPRESS,
                    help="list/search types instead of resolving one")
    sp.add_argument("-k", "--kind", default=None,
                    help="filter by kind (struct/union/enum/pointer/function/array/typedef/scalar)")
    sp.add_argument("--size", default=None,
                    help="filter by type size in bytes (hex; prefix 0n for decimal)")
    sp = cmd("member", help="member at byte offset (nested path, union arms)",
             ex=("member _EPROCESS 0x2e0",))
    sp.add_argument("type")
    sp.add_argument("member_offset", metavar="byte_off")
    sp = cmd("typeof", help="type of a global/local/stack-var/function",
             ex=("typeof 0x140008000", "typeof sub_401000:v3"))
    sp.add_argument("target")
    sp = cmd("frame", help="stack/local variables", ex=("frame sub_401000",))
    sp.add_argument("func")

    sp = cmd("rename", help="rename func/global/local/stack [mut]",
             ex=("rename 0x401000 parse_header", "rename sub_401000:v3 count"))
    sp.add_argument("addr")
    sp.add_argument("name")
    sp = cmd("comment", help="set a comment [mut]", ex=('comment 0x401037 "loop start"',))
    sp.add_argument("addr")
    sp.add_argument("text")
    sp = cmd("op", help="set operand display: hex/dec/oct/bin/char/num/enum:NAME [mut]",
             ex=("op 0x401234 dec", "op 0x401234 enum:MyFlags 1"))
    sp.add_argument("addr")
    sp.add_argument("fmt", metavar="<hex|dec|oct|bin|char|num|enum:NAME>")
    sp.add_argument("opnum", nargs="?", type=int, default=None)
    sp = cmd("declare", help='create types: "<C>" | --file P | @P [mut]',
             ex=('declare "struct Foo { int a; char b; };"', "declare @types.h"))
    sp.add_argument("decl", nargs="?", default=None)
    sp.add_argument("--file", default=None)
    sp = cmd("settype", help="apply a type [mut]",
             ex=("settype 0x140008000 GUID", "settype sub_401000:v3 int"))
    sp.add_argument("target")
    sp.add_argument("type")
    sp = cmd("setlvar", help="rename and/or retype a Hex-Rays local in one step [mut]",
             ex=("setlvar main v0 --name count --type int",))
    sp.add_argument("func")
    sp.add_argument("var")
    sp.add_argument("--name", default=None)
    sp.add_argument("--type", dest="type", default=None)
    sp = cmd("set_member", help="retype/rename an existing struct member [mut]",
             ex=("set_member Foo a int count",))
    sp.add_argument("type")
    sp.add_argument("member")
    sp.add_argument("new_type")
    sp.add_argument("new_name", nargs="?", default=None)
    sp = cmd("insert_member", help="add a struct member before/after another, else append [mut]",
             ex=("insert_member Foo int count --after a", "insert_member Foo void *ctx"))
    sp.add_argument("type")
    sp.add_argument("new_type")
    sp.add_argument("name")
    sp.add_argument("--before", default=None)
    sp.add_argument("--after", default=None)
    sp = cmd("del_member", help="remove a struct member, closing the gap [mut]",
             ex=("del_member Foo b", "del_member Foo 0x8 --leave-gap"))
    sp.add_argument("type")
    sp.add_argument("member")
    sp.add_argument("--leave-gap", dest="leave_gap", action="store_true")
    sp = cmd("enum", help="create/extend an enum [mut]", ex=("enum Color r=0,g=1,b=2",))
    sp.add_argument("name")
    sp.add_argument("members", help="k=v,k=v,...")
    sp.add_argument("--bitfield", action="store_true")
    sp = cmd("patch", help="patch bytes [mut]",
             ex=("patch 0x401037 9090", 'patch 0x401037 "90 90"'))
    sp.add_argument("addr")
    sp.add_argument("hex")
    cmd("undo", help="revert last mutation [mut]", ex=("undo",))
    cmd("redo", help="replay [mut]", ex=("redo",))
    sp = cmd("union-select", help="choose a union arm at a usage site [mut]",
             ex=("union-select 0x401037 arm_name",))
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
    if c == "eval":
        return c, {"expr": " ".join(ns.expr), "width": ns.width}
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
        return c, {"addr": ns.addr, "encoding": ns.encoding, **_page(ns)}
    if c == "pointers":
        return c, {"addr": ns.addr, **_page(ns)}
    if c == "string_struct":
        return c, {"addr": ns.addr, "wide": bool(getattr(ns, "wide", False))}
    if c == "xrefs":
        return c, {"addr": ns.addr, "direction": ns.direction or "to", **_page(ns)}
    if c == "calls":
        return c, {"func": ns.func, "depth": ns.depth, **_page(ns)}
    if c == "triage":
        return c, {"func": ns.func}
    if c == "audit_call_types":
        return c, {"scope": ns.scope, "budget": ns.budget, "limit": ns.limit,
                   "min_sites": ns.min_sites, "min_callers": ns.min_callers,
                   "no_imports": bool(getattr(ns, "no_imports", False)),
                   "kind": ns.kind, "show_all": bool(getattr(ns, "show_all", False)),
                   **_lpage(ns)}
    if c == "strrefs":
        return c, {"pattern": ns.pattern, **_page(ns)}
    if c == "search":
        return c, {"pattern": ns.pattern, "kind": ns.kind, **_page(ns)}
    if c == "type":
        pat = ns.name
        list_mode = (bool(getattr(ns, "enumerate", None)) or ns.kind or ns.size
                     or (pat is not None and ("*" in pat or "?" in pat
                         or (len(pat) >= 2 and pat.startswith("/") and pat.endswith("/")))))
        if list_mode:
            if ns.addr is not None:
                raise IdbError(protocol.BAD_ARGS,
                               "type search takes a pattern, not an address; drop the second "
                               "argument or use `type NAME ADDR` to overlay a struct")
            return "types", {"pattern": pat, "kind": ns.kind, "size": ns.size, **_lpage(ns)}
        return "type", {"name": pat, "addr": ns.addr, **_page(ns)}
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
    if c == "set_member":
        return c, {"type": ns.type, "member": ns.member, "new_type": ns.new_type, "new_name": ns.new_name}
    if c == "insert_member":
        return c, {"type": ns.type, "new_type": ns.new_type, "name": ns.name,
                   "before": ns.before, "after": ns.after}
    if c == "del_member":
        return c, {"type": ns.type, "member": ns.member, "leave_gap": ns.leave_gap}
    if c == "enum":
        return c, {"name": ns.name, "members": ns.members, "bitfield": ns.bitfield}
    if c == "patch":
        return c, {"addr": ns.addr, "hex": ns.hex}
    if c == "union-select":
        return "union_select", {"addr": ns.addr, "member": ns.member}
    raise IdbError(protocol.BAD_ARGS, f"unhandled command {c!r}")


def resolve_session(ns):
    """Resolve to a Code Mode path; retained idb sessions no longer exist."""
    try:
        return codemode.resolve_target(session=ns.session, idb=ns.idb)
    except IdbError as exc:
        if exc.code == AMBIGUOUS and isinstance(exc.data, list):
            print(fmt_sessions.format_sessions(exc.data), file=sys.stderr)
            raise IdbError(exc.code, exc.message) from exc
        raise


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
        if meta.get("warning"):
            print(f"idb: warning: {meta['warning']}", file=sys.stderr)
        line = _banner(meta)
        if line:
            print(line, file=sys.stderr)
    return 0


def _transport_error(exc):
    code = protocol.TIMEOUT if "timed out" in str(exc).lower() else protocol.IDA_ERROR
    return IdbError(code, f"{type(exc).__name__}: {exc}")


def run_remote(ns, rpc_cmd, rpc_args):
    target = resolve_session(ns)
    open_timeout = ns.timeout if ns.timeout else 600.0
    execute_timeout = ns.timeout if ns.timeout else DEFAULT_TIMEOUT
    handle = None
    try:
        handle = codemode.open_handle(target, timeout=open_timeout)
        handle.wait_autoanalysis(open_timeout)
        if rpc_cmd == "save":
            saved = handle.save_database()
            reply = protocol.build_ok(0, {"saved": saved["idb_path"]})
        else:
            execution = handle.execute_python(
                codemode.execute_code(rpc_cmd, rpc_args),
                timeout=execute_timeout,
            )
            reply = codemode.envelope_from_execution(execution)
    except IdbError:
        raise
    except Exception as exc:
        raise _transport_error(exc) from exc
    finally:
        if handle is not None:
            handle.close()
    return emit(rpc_cmd, reply, ns)


def cmd_open(ns):
    timeout = ns.timeout if ns.timeout else 600.0
    handle = None
    try:
        handle = codemode.open_handle(ns.target, timeout=timeout, fresh=ns.fresh)
        handle.wait_autoanalysis(timeout)
        execution = handle.execute_python(
            codemode.initialize_code(handle.entry.record_id, ns.target),
            timeout=timeout,
        )
        reply = codemode.envelope_from_execution(execution)
        if ns.verbose:
            entry = handle.entry
            print(
                f"instance {entry.record_id}  backend {entry.backend}  "
                f"port {entry.port}  pid {entry.pid}",
                file=sys.stderr,
            )
    except IdbError:
        raise
    except Exception as exc:
        raise _transport_error(exc) from exc
    finally:
        if handle is not None:
            handle.close()
    return emit("open_summary", reply, ns)


def _emit_paginated(rows, formatter, ns):
    page, next_offset = _paginate_list(rows, ns.offset, ns.count)
    print(formatter(page))
    meta = _banner({"shown": len(page), "truncated": True, "next_offset": next_offset}) if next_offset is not None else ""
    if meta:
        print(meta, file=sys.stderr)


def cmd_sessions(ns):
    rows = codemode.list_databases()
    for row in rows:
        row.pop("_entry", None)
    _emit_paginated(rows, fmt_sessions.format_sessions, ns)
    return 0


def cmd_doctor(ns):
    rows, ok = doctor_mod.run()
    _emit_paginated(rows, fmt_sessions.format_doctor, ns)
    return 0 if ok else 1


LIFECYCLE = {
    "open": cmd_open,
    "sessions": cmd_sessions,
    "doctor": cmd_doctor,
}


def _force_utf8(stream):
    """idb prints arbitrary binary-derived text (strings, comments, type/symbol
    names); the host console encoding (cp1252 on Windows) raises on code points
    outside it. UTF-8 encodes every code point, so the round-trip never crashes."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(encoding="utf-8", errors="backslashreplace")
    except (ValueError, OSError):
        pass


def main(argv=None):
    _force_utf8(sys.stdout)
    _force_utf8(sys.stderr)
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "help":  # hidden alias: `help` -> -h, `help CMD` -> CMD -h
        argv = [argv[1], "-h"] if len(argv) > 1 else ["-h"]
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

    canonical = ALIASES.get(ns.command, (ns.command, {}))[0]
    ignored = []
    if (hasattr(ns, "offset") or hasattr(ns, "count")) and canonical not in _PAGE_UNITS:
        ignored.append("-o/-n")
    if hasattr(ns, "total") and canonical not in _TOTAL_CMDS:
        ignored.append("--total")
    normalize_namespace(ns)
    if ignored:
        print(f"idb: warning: {ns.command} ignores {', '.join(ignored)}", file=sys.stderr)

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
