# idb — IDA Pro Buddy

A windbg-flavored CLI for interacting with IDA that is optimized for agentic harnesses. `idb` maintains a persistent headless worker per database and tries to minimize token use with compact text output.

```
idb open foo.exe          # spawn + analyze, print a triage summary
idb u sub_401000          # disassemble a function (windbg alias for `disas`)
idb dec sub_401000        # decompile (Hex-Rays)
idb db 0x401000 -n 64     # hexdump 64 bytes
idb x CreateFile          # find symbols by pattern  (alias for `names`)
idb xref_to validate_key  # who references this, with instruction context
idb t GUID                # inspect a type
idb close                 # save + shut the worker down
```

## Install

idalib needs **install + activation**, then `idb` installs into that same
interpreter (the CLI and the worker share `sys.executable`):

```powershell
cd "C:\Program Files\IDA Professional 9.3\idalib\python"
python -m pip install .\idapro-0.0.7-py3-none-any.whl   # version-matched idapro
python .\py-activate-idalib.py                           # writes %APPDATA%\Hex-Rays\IDA Pro\ida-config.json
python -m pip install -e D:\ida_buddy                    # idb + pyzmq + msgspec
idb doctor                                               # verify the environment
```

`idapro` is intentionally **not** a PyPI dependency of `ida-buddy` — the correct
build ships with the IDA install, not PyPI. `idb doctor` confirms it imports and
reports the kernel version.

> The `idb` console script lands in your user Scripts dir (e.g.
> `%APPDATA%\Python\Python313\Scripts`). If that is not on `PATH`, invoke as
> `python -m idb ...`.

## Model

- **One database per worker.** Multiple sessions = multiple worker processes.
- **Every worker is fully writable.** Read and mutate commands are always
  available; mutating commands create an undo point first (`idb undo` / `idb redo`).
- **Save policy:** `idb save` persists mid-session; `idb close` saves by default;
  `idb close --no-save` discards; `idb close --kill` hard-terminates a wedged
  worker (no save); an idle worker shuts down after its TTL (saving).
- **Sessions** live in per-user registry files (`%LOCALAPPDATA%\ida-buddy`).
  Commands resolve a session by `-s <id>`, `--idb <path>`, or — when exactly one
  worker is healthy — automatically.
- **Stuck command:** `-t` is a *soft* client timeout. Native IDA/Hex-Rays calls
  cannot be interrupted; recover a wedged worker with `idb close --kill`.

## Output

Dense windbg-style text. **Data goes to stdout**; banners, errors, and
`[+more]` truncation notices go to **stderr** (never ingested as data).
Sequence-style output paginates with `-o/--offset` + `-n/--count`.

## Commands

Aliases in parens. `[mut]` mutates the database (creates an undo point).

| Command | Meaning |
|---|---|
| `open [--fresh] [--idle-ttl SEC] <path>` | spawn + analyze, print summary |
| `sessions` (`ps`) / `close [--no-save\|--kill\|--all]` / `save` / `doctor` | lifecycle |
| `segments` (`seg`) | segments + rwx |
| `funcs [pat]` / `names <pat>` (`x`) / `nearest <addr>` (`ln`) | symbols |
| `imports [pat]` / `exports [pat]` / `strings [pat]` | imports / entry points / strings |
| `disas <target>` (`u`) | whole function, or `-n N` insns from an address |
| `decompile <func>` (`dec`) | Hex-Rays pseudocode |
| `read <addr>` (`db`/`dw`/`dd`/`dq`) | dump cells (`-w 1\|2\|4\|8`, `-n N`) |
| `string <addr>` (`da`/`du`) | read a string (`-e ascii\|utf16`) |
| `xref_to <addr>` / `xref_from <addr>` | refs + kind + enclosing func + instruction |
| `calls <func>` | callers + callees |
| `search <pat>` | `-k bytes\|imm\|str\|ref` |
| `type <name>` (`t`) / `types [pat]` | inspect / list local types (`-k kind`) |
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

### Exit codes

`0` ok · `1` error (IDA/not-found/bad-address/internal) · `2` usage · `3` no
session · `4` ambiguous session · `5` not ready · `6` timeout · `7` unauthorized.

## Testing

```
python -m pytest tests --ignore=tests/integration   # Tiers 1–3 (no IDA)
python -m pytest tests/integration                   # Tier 4 (needs idapro + a binary)
```

Tier 4 opens a real worker against `tests/fixtures/where.exe` (override with
`IDB_TEST_BINARY=<path>`); it auto-skips when idapro or the binary is absent.

See `plan.md` for the full design.
