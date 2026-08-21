# IDA Nexus port notes

## Architecture

The custom IDA worker, ZeroMQ transport, idb session registry, and detached CLI
bridge have been removed.

```text
idb invocation
  -> ida_nexus.DatabaseHandle
  -> authenticated Nexus HTTP/SSE
  -> registered IDA GUI or managed idalib worker
  -> execute_python
  -> ida-buddy remote handler
```

Each CLI invocation owns exactly one handle and closes it before exiting. With a
single registered database, discovery selects it automatically. `--idb <path>`
provides stable targeting and allows Nexus to start idalib on demand; `-s`
selects a currently registered Nexus record.

Managed workers are kept alive for `nexus.WORKER_LINGER` (one hour, the
maximum lease keepalive ida-nexus allows) after the last handle closes, so
IDA's in-memory undo history survives between CLI invocations: a bad mutation
is recovered with `idb undo`, not by discarding the session. On shutdown the
worker saves and closes; a later `--idb` command respawns it. GUI databases
remain registered independently of CLI invocations.

Explicit `-s <record-id>` selections attach to that instance's registry entry
directly via `DatabaseHandle.attach` (no path re-resolution), so they can
never land on a lookalike database or spawn a fresh worker. Auto-analysis is
awaited only in managed workers; a GUI instance that is still analyzing
answers NOT_READY through the non-mutating `poll_autoanalysis` endpoint
instead of having auto-analysis force-enabled under the analyst.

`idb close [--no-save]` shuts a managed worker down through Nexus's
`shutdown_database`, so unsaved changes can be discarded without killing the
process. Exact attachment, non-mutating analysis polling, and managed shutdown
require ida-nexus 0.7.0 or later.

Nexus's JSON wire accepts only JSON-compatible values, so remote envelopes are
passed through `protocol.encode_bytes`/`decode_bytes`, which tag raw payloads as
`{"$idb.b64": <base64>}` and restore them client-side.

The remote adapter adds this installation's package parent to IDA's `sys.path`
and calls `idb.worker.remote` through `execute_python`. Both processes therefore
need access to the same local installation, which matches Nexus's loopback,
same-user deployment model.

## API coverage learned

The Nexus RPC/lifecycle surface is sufficient after exposing:

- `DatabaseHandle.wait_autoanalysis()` and
  `DatabaseManager.wait_autoanalysis()`;
- worker launch options needed by fresh/raw database creation;
- robust Windows console-launcher child discovery.

`execute_python`, `save_database`, registry discovery, and handle leases cover
the rest. Windows managed-worker launches use `CREATE_NO_WINDOW`.

The current ida-domain 0.5 surface covers most read operations directly:
metadata, segments, functions, instructions, xrefs, names, imports, entries,
strings, bytes, patching, pseudocode, comments, and common type operations.

A domain-only rewrite is not yet a drop-in replacement for every ida-buddy
handler. Existing public IDAPython imports remain behind Nexus for:

- undo/redo and explicit undo points;
- operand display changes and union-arm selection;
- detailed in-place UDT member mutation;
- complete stack-frame/chunk/SEH inspection;
- lower-level Hex-Rays type auditing and cache control.

Thus the official RPC surface is sufficient for the port, while ida-domain
alone does not yet cover every low-level command.
