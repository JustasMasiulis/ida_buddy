# idb — IDA Pro Buddy

A windbg-flavored CLI for interacting with IDA that is optimized for agentic harnesses. `idb` maintains a persistent headless worker per database and tries to minimize token use with compact text output.

```
idb open foo.exe          # spawn + analyze, print a triage summary
idb u sub_401000          # disassemble a function (windbg alias for `disas`)
idb dec sub_401000        # decompile (Hex-Rays)
idb db 0x401000 -n 64     # hexdump 64 bytes
idb x CreateFile          # find symbols by pattern  (alias for `names`)
idb xref_to validate_key  # who references this, with instruction context
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
| `sessions` / `close [--no-save\|--kill\|--all]` / `save` / `doctor` | lifecycle |
| `segments` | segments + rwx |
| `funcs [pat]` / `names <pat>` (`x`) / `nearest <addr>` (`ln`) | symbols |
| `eval <expr>` (`?`) | arithmetic/bitwise calc + name lookup; `+%`/`-%`/`*%` wrap (`-w` width); result as hex / `0n`-dec (signed+unsigned) / ascii |
| `imports [pat]` / `exports [pat]` / `strings [pat]` | imports / entry points / strings |
| `disas <target>` (`u`) | whole function, or `-n N` insns from an address |
| `decompile <func>` (`dec`) | Hex-Rays pseudocode |
| `read <addr>` (`db`/`dw`/`dd`/`dq`) | dump cells (`-w 1\|2\|4\|8`, `-n N`) |
| `string <addr>` (`da`/`du`) | read a string (`-e ascii\|utf16`) |
| `xref_to <addr>` / `xref_from <addr>` | refs + kind + enclosing func + instruction |
| `calls <func>` | callers + callees |
| `search <pat>` | `-k bytes\|imm\|str\|ref` |
| `type <name>` (`dt`) / `types [pat]` | inspect / list local types (`-k kind`) |
| `struct <type> [addr]` | layout (+ live values if addr) |
| `member <type> <byte_off>` | member at offset — full nested path, all union arms |
| `typeof <target>` | type of a global / function / `func:var` local |
| `frame <func>` | stack / local variables |
| `rename <addr\|func:var> <name>` *(mut)* | rename a name or local |
| `comment <addr> <text>` *(mut)* | set a comment (disassembly + decompiler) |
| `declare ("<C>" \| --file P \| @P)` *(mut)* | create types |
| `settype <target> <type>` *(mut)* | apply a type (global / function / `func:var` local) |
| `setmember <struct> <off\|name> <type> [newname]` *(mut)* | edit a struct member |
| `enum <name> <k=v,...> [--bitfield]` *(mut)* | create or extend an enum |
| `patch <addr> <hex>` *(mut)* | patch bytes |
| `union-select <addr> <member>` *(mut)* | choose a union arm at a Hex-Rays usage site |
| `undo` / `redo` *(mut)* | revert / replay the last mutation |

Global flags: `-s/--session`, `--idb`, `-o/--offset`, `-n/--count`, `-t/--timeout`,
`--total`, `-v/--verbose`. Addresses are hex by default (windbg style); `0n`
prefixes decimal; a symbol name resolves to its address.

**Data goes to stdout**; banners, errors, and
`[+more]` truncation notices go to **stderr** (never ingested as data).
Sequence-style output paginates with `-o/--offset` + `-n/--count`.

### Exit codes

`0` ok · `1` error (IDA/not-found/bad-address/internal) · `2` usage · `3` no
session · `4` ambiguous session · `5` not ready · `6` timeout · `7` unauthorized.

## Testing

```
python -m pytest tests --ignore=tests/integration
python -m pytest tests/integration # runs against a real binary
```
