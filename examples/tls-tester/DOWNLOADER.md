# Downloader architecture

The TLS Tester download implementation combines NetLib, the public PalmTLS API
10 ABI, and the directly compiled `components/http` source. `DownloadClient`
and `DownloadStore` belong to this example application. They are not shared
libraries or stable PalmTLS APIs.

## Event-loop integration

The application opens PalmTLS before creating a download. It then
calls its private `DownloadClientStart`, advances the opaque job with
`DownloadClientStep` from `nilEvent` handling, and uses
`DownloadClientCancel` to request cancellation. The client opens and closes
NetLib itself for each job.

Each step performs one bounded part of the operation:

```text
storage -> DNS -> nonblocking TCP connect -> cooperative TLS handshake
        -> cooperative request writes -> cooperative reads/HTTP parser feed
        -> validate framing -> flush and mark complete
```

HTTPS uses `PalmTlsLibSessionOpen` with
`PALM_TLS_SESSION_COOPERATIVE`, followed by incremental handshake, write, and
read calls with `PALM_TLS_IO_COOPERATIVE`. HTTP uses the same state machine with
NetLib directly. Short step timeouts keep control returning to the Palm event
loop; the application also enforces a total phase/idle deadline.

The HTTP component provides URL parsing, GET/range request construction,
redirects, and incremental response parsing. Its body callback writes decoded
body bytes to the store, so headers and chunk framing are never persisted.

## Resume and redirect behavior

Incomplete entries retain their byte count plus ETag or Last-Modified. A later
request sends `Range` and `If-Range`. Data is appended only when a `206`
Content-Range begins at the exact stored offset. A `200` safely restarts the
destination, a mismatched `206` fails without appending, and `416` counts as
already complete only when its total matches the stored byte count.

The client follows up to the configured number of absolute or relative
redirects. Each redirect closes the current transport, resolves the new URL,
and restarts the network part of the state machine.

## Storage policy

Each URL maps to a stable hashed Palm database name. Two alternating metadata
records carry generation numbers and checksums; body records are 4 KiB. Body
data has an incremental CRC-32, and metadata is committed every 16 KiB and on
close.

When a VFS volume is available, the store writes beneath
`/PALM/Programs/TLSDownloads`. A Palm record database is the automatic
fallback. The Files screen enumerates saved entries, deletes an individual
entry, selects one for resume, and can export a database-backed download to
VFS.

## Ownership rules

- PalmTLS must stay open until the job finishes.
- The result object, callback context, and selected trust-certificate bytes
  must remain valid for the job's lifetime.
- Only one event-loop step may advance a job at a time.
- Cancellation is observed on the next step and preserves incomplete data.
- A zero total length means progress is indeterminate.
- Filenames and MIME types obtained from HTTP are untrusted metadata.

For the stable shared-library contract, read `library/API.md`. The HTTP source
component is documented in `components/http/README.md`. Smaller compile-checked
examples are under `examples/network`; the complete UI integration is in
`src/main.c`.
