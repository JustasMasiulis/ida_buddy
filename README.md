# idb — IDA Pro Buddy

A windbg-flavored CLI for interacting with IDA that is optimized for agentic harnesses. `idb` maintains a persistent headless worker per database and tries to minimize token use with compact text output.

```
idb open foo.exe          # spawn + analyze, print a triage summary
idb u sub_401000          # disassemble a function (windbg alias for `disas`)
idb dec sub_401000        # decompile (Hex-Rays)
idb db 0x401000 -n 64     # hexdump 64 bytes
idb x CreateFile          # find symbols by pattern  (alias for `names`)
idb xref_to validate_key  # who references this, with instruction context
idb triage sub_401000     # size up a function before reading it
idb ? sub_401000 + 0x10   # evaluate an expression (alias for `eval`)
idb dt GUID                # inspect a type
idb close                 # save + shut the worker down
```

## Install

This tool requires IDA Pro to be installed and activated globally.

```powershell
# 1. Activate idalib so idapro can locate your IDA install (writes ida-config.json):
python "C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
# 2. Install idb (pulls idapro + pyzmq + msgspec from PyPI):
python -m pip install -e D:\ida_buddy
# 3. Verify the environment:
idb doctor
```

## Commands

Aliases in parens. `[mut]` mutates the database (creates an undo point).

| Command | Meaning |
|---|---|
| `open [--fresh] <path>` | spawn + analyze, print summary |
| `sessions` | list running workers |
| `close [session] [--no-save\|--kill\|--all]` / `save` / `doctor` | lifecycle |
| `segments` | segments + rwx |
| `funcs [pat]` / `names <pat>` (`x`) / `nearest <addr>` (`ln`) | symbols |
| `eval <expr>` (`?`) | arithmetic/bitwise calc + name lookup; `+%`/`-%`/`*%` wrap (`-w` width); result as hex / `0n`-dec (signed+unsigned) / ascii |
| `imports [pat]` / `exports [pat]` / `strings [pat]` | imports / entry points / strings |
| `disas <target>` (`u`, `uf`) | whole function, or `-n N` insns starting at an address target; `-o` is pagination offset, not an address |
| `decompile <func>` (`dec`) | Hex-Rays pseudocode; defaults to 120 lines, resume with `-o` or use `-n`; if output is noisy, improve types or use `triage` to narrow scope first |
| `read <addr>` (`db`/`dw`/`dd`/`dq`) | dump cells (`-w 1\|2\|4\|8`, `-n N`) |
| `pointers <addr>` (`dps`/`dqs`) | dump pointers and nearest symbols |
| `string <addr>` (`da`/`du`) / `string_struct <addr>` (`ds`/`dS`) | raw strings and counted ANSI/UNICODE_STRING-style structs |
| `xref_to <addr>` / `xref_from <addr>` / `xrefs <addr> -d both` | refs + kind + enclosing func + instruction |
| `calls <func>` | callers + callees |
| `triage <func>` | one-call pre-RE summary: ranked callees, prefix groups (both call-graph directions), prototype + caller-site arg types, SEH/chunks, referenced strings |
| `audit_call_types [scope]` | decompile a budgeted corpus and report call-site type mismatches / weak parameter-local types |
| `strrefs <pat>` | find strings by pattern and show xrefs to them |
| `search <pat>` | `-k bytes\|imm\|str\|ref` |
| `type <name> [addr]` (`dt`) / `types [pat]` | resolve a type (local/library), overlay live values at addr, or search both — `-e`, `-k kind`, `--size N` |
| `member <type> <byte_off>` | member at offset — full nested path, all union arms |
| `typeof <target>` | type of a global / function / `func:var` local |
| `frame <func>` | stack / local variables |
| `rename <addr\|func:var> <name>` *(mut)* | rename a name or local |
| `comment <addr> <text>` *(mut)* | set a comment (disassembly + decompiler) |
| `op <addr> <hex\|dec\|oct\|bin\|char\|num\|enum:NAME> [opnum]` *(mut)* | set operand display format |
| `declare ("<C>" \| --file P \| @P)` *(mut)* | create types |
| `settype <target> <type>` / `setlvar <func> <var> [--name N] [--type T]` *(mut)* | apply types / rename and retype Hex-Rays locals |
| `set_member <struct> <off\|name> <type> [newname]` *(mut)* | retype/rename a member; a larger type absorbs the members it now overlaps |
| `insert_member <struct> <type> <name> [--before M\|--after M]` *(mut)* | add a member (shifts following members down); appends if no anchor |
| `del_member <struct> <off\|name> [--leave-gap]` *(mut)* | remove a member, closing the gap (`--leave-gap` keeps offsets fixed) |
| `enum <name> <k=v,...> [--bitfield]` *(mut)* | create or extend an enum |
| `patch <addr> <hex>` *(mut)* | patch bytes |
| `union-select <addr> <member>` *(mut)* | choose a union arm at a Hex-Rays usage site |
| `undo` / `redo` *(mut)* | revert / replay the last mutation |


## Sessions

`idb open` starts or reuses one persistent worker per input path. Commands target
the only running worker by default. Once two or more workers are live, pass a
session id or database/binary path on every command:

```
idb sessions
idb -s foo.exe-1a2b3c4d funcs main
idb --idb C:\bins\foo.exe dec main
idb close foo.exe-1a2b3c4d
idb close --all --no-save
```

If a command fails with `AMBIGUOUS`, rerun it with `-s <session>` from
`idb sessions` or `--idb <path>`. `open --fresh <path>` refuses to clobber a live
worker for that database; close the session first when you want a clean reanalysis.

## Examples

```powershell
# Lifecycle and session targeting
idb doctor
idb open C:\bins\foo.exe
idb open foo.exe --fresh
idb sessions
idb -s foo.exe-1a2b3c4d save
idb close foo.exe-1a2b3c4d

# Database overview and symbols
idb segments --total
idb funcs Create -n 50 --total
idb imports kernel32
idb exports
idb strings lic -n 100
idb names CreateFile
idb x sub_
idb nearest 0x401037
idb ln 0x401037

# Arithmetic and code/data reads
idb eval (1<<12) - 1
idb ? 0x401000 + 8
idb disas sub_401000 -n 16
idb disas 0x401740 -n 32  # start at an address; do not pass the address via -o
idb uf 0x401000
idb decompile sub_401000
idb dec main
idb read 0x140001000 -n 64
idb dq 0x140001000 -n 8
idb dps 0x140005000 -n 8
idb da 0x140003000
idb du 0x140003000
idb ds 0x140006000
idb dS 0x140006000

# References, search, and triage
idb xref_to 0x401000
idb xrefs 0x401000 -d both
idb calls sub_401000
idb calls main --depth 3
idb triage sub_401000
idb audit_call_types
idb audit_call_types Wfp -n 30
idb audit_call_types --kind locals
idb strrefs license
idb search "90 90" -k bytes
idb s GetProcAddress -k str

# Types, frames, and locals
idb type GUID
idb dt _EPROCESS 0x140008000
idb types -k struct
idb type 'IMAGE_*' --size 0x10
idb type -e
idb member _EPROCESS 0x2e0
idb typeof 0x140008000
idb typeof sub_401000:v3
idb frame sub_401000

# Mutations; use undo/redo to recover from the last change
idb rename 0x401000 parse_header
idb rename sub_401000:v3 count
idb comment 0x401037 "loop start"
idb op 0x401234 dec
idb op 0x401234 enum:MyFlags 1
idb declare "struct Foo { int a; char b; };"
idb declare @types.h
idb settype 0x140008000 GUID
idb settype sub_401000:v3 int
idb setlvar main v0 --name count --type int
idb set_member Foo a int count
idb insert_member Foo int count --after a
idb insert_member Foo "void *" ctx
idb del_member Foo b
idb del_member Foo 0x8 --leave-gap
idb enum Color r=0,g=1,b=2
idb patch 0x401037 9090
idb union-select 0x401037 arm_name
idb undo
idb redo
```

Global flags: `-s/--session`, `--idb`, `-o/--offset`, `-n/--count`, `-t/--timeout`,
`--total`, `-v/--verbose`. Addresses are hex by default (windbg style); `0n`
prefixes decimal; a symbol name resolves to its address.

**Data goes to stdout**; banners, errors, and
`[+more]` truncation notices go to **stderr** (never ingested as data).
Sequence-style output paginates with `-o/--offset` + `-n/--count`.
For `disas`, the target itself may be a symbol or address (`idb disas 0x401740 -n 32`).
Use `-o/--offset` only to resume paginated output after a `[+more]` notice.

When decompiler output is dominated by scaffolding, improve known types first
(`type`, `declare`, `settype`, `setlvar`) where possible. Then use `triage <func>`
and focused `disas` windows to inspect only the code that still matters.

### Exit codes

`0` ok · `1` error (IDA/not-found/bad-address/internal) · `2` usage · `3` no
session · `4` ambiguous session · `5` not ready · `6` timeout · `7` unauthorized.

## Testing

```
python -m pytest tests --ignore=tests/integration
python -m pytest tests/integration # runs against a real binary
```
