# Palm TLS shared library

PalmTLS is distributed as mutually exclusive Palm OS system-library PRCs for
68K and ARM devices. Each architecture can package one of three protocol
profiles from the same source:

- `PalmTLS68K.prc` supports Palm OS 4+ and runs entirely as 68K code.
- `PalmTLSArm.prc` supports ARM-based Palm OS 5+ devices. Its shared-library
  traps remain 68K-compatible while multiprecision multiply/square, complete
  P-256 scalar multiplication, and SHA-256 compression execute as a native
  ARMlet through `PceNativeCall`.

All profiles install internally as `Palm TLS` with creator `PTLS` and expose only API
10, so they cannot and need not coexist. Install the variant appropriate for
the device, then load it from applications with `SysLibFind` or `SysLibLoad`
and the API in
`include/palm_tls.h`.

The library accepts an already-connected NetLib TCP socket. It provides SNI,
explicit TLS 1.1/TLS 1.2/TLS 1.3 selection, encrypted send/receive, hostname and certificate-date
verification, caller-supplied DER/PEM trust anchors, exact-peer trust, and an
explicitly unverified diagnostic mode. It intentionally does not implement
DNS, TCP connection setup, HTTP parsing, or a built-in root store.

The modern profile is restricted to P-256, SHA-256, AES-128-GCM, the
ECDHE/ECDSA or ECDHE/RSA TLS 1.2 suites, and the P-256/AES-GCM TLS 1.3 profile.
The isolated TLS 1.1 engine instead enables static RSA key exchange,
AES-CBC, SHA-1, and the legacy MD5/SHA-1 PRF. TLS 1.1 is obsolete and should
only be selected to interoperate with a known legacy service. The Palm entropy
adapter is not a modern CSPRNG.
Unverified mode provides encryption but no server authentication and must not
be used for sensitive traffic.

Consumer applications include `include/palm_tls.h`, load creator `PTLS` as a
system library, call `PalmTlsLibOpen`, and pass an already-connected NetLib
socket plus `palmTlsProtocolTls11`, `palmTlsProtocolTls12`, or
`palmTlsProtocolTls13` to
`PalmTlsLibExchange`. PalmTLS provides bounded-buffer and streaming
operations plus incremental sessions:
`PalmTlsLibSessionOpen`, `PalmTlsLibSessionWrite`, `PalmTlsLibSessionRead`, and
`PalmTlsLibSessionClose`, with cooperative handshake/I/O and explicit
cancellation. The streaming operation decrypts
into a reusable 1 KiB library buffer and calls the application's sink once per
chunk, so file size is not limited by the Palm dynamic heap. The sink may write
to VFS, a Palm record database, or a small parser-owned buffer; returning a
nonzero value aborts the request and reports that value as `sinkError`.
The examples under `../examples/network` demonstrate incremental-session
use without depending on a particular application.

PalmTLS includes a deterministic, network-free native-ARM self-test and
per-protocol timings for engine load, P-256 key generation, shared-secret
calculation, and signature verification.

The complete API contract, lifecycle, error model, cooperative state handling,
and cache rules are documented in [API.md](API.md). Small consumers that are
compiled against the Palm SDK are in [../examples/network](../examples/network).
The native boundary, byte order, fallback, and remaining work are documented in
[ARM.md](ARM.md).

Only one TLS session may be active at a time. The selected protocol engine is
kept relocated and initialized after a request, so repeated connections avoid
the resource-copy, relocation, and wolfSSL initialization cost. Opening a
different protocol unloads the idle engine and loads the requested one.
`PALM_TLS_SESSION_ALLOW_RESUME` additionally keeps one resumable session for
the active protocol. A later connection reuses it only when the host name,
verification mode, and trust-anchor fingerprint all match. A different host
replaces the one-entry cache. `PalmTlsLibPurgeCache` releases the engine and
resumption state when no session is active.

Initialize every parameter and result structure to zero, set its `structSize`,
and check both the trap's Palm `Err` return and the result `status`. Applications
must test the capability bits they require. The library permits one active or
opening session. The one-shot exchange calls
remain synchronous; sessions may instead be advanced cooperatively. The
caller still owns DNS, the connected socket, UI event policy, HTTP framing,
output storage, cancellation policy, and cleanup.

For a downloader, the sink must handle short writes and return the VFS or
database error if a chunk cannot be stored. Set `responseLimit` to an explicit
application policy, not available RAM. TLS streams raw HTTP bytes, so a useful
download app must parse the status and headers, decode chunked transfer framing,
follow redirects deliberately, and send `Accept-Encoding: identity` unless it
also implements content decoding. Do not write HTTP headers into the destination
file.

The full PRC contains three compact protocol-specific engines behind the same
API and loads only the selected engine. Compact profiles omit unused engines
entirely. Each included engine is split into four resources:
three code-only segments execute from a temporary resource database while the
final code/data segment remains in dynamic RAM. This keeps every resource below
Palm's 65 KB safety limit while leaving enough dynamic heap for a TLS 1.3
handshake. The relocated resources remain resident until the library closes,
the protocol changes, or the caller purges the cache.

For cooperative operation, open with
`PALM_TLS_SESSION_COOPERATIVE`; if the handshake returns
`palmTlsStatusWouldBlock`, call `PalmTlsLibSessionHandshake` again with a short
timeout. `PALM_TLS_IO_COOPERATIVE` reports the same status instead of turning
an exhausted read/write timeout into a hard failure. The application can
process events between steps and call
`PalmTlsLibSessionCancel` to release an opening or active session immediately.
CPU-heavy public-key work inside one wolfSSL step remains synchronous, but
network waits and the transfer loop are cooperative.

Build and validate with:

```sh
make -C library test
```

The `test` target rebuilds and validates all three profiles sequentially, so a
compact PRC cannot remain stale after shared PalmTLS code changes. The Full
profile is built last to leave the default intermediate resources selected.

The default `full` build and the two compact profiles produce:

```text
PalmTLS68K.prc / PalmTLSArm.prc                 TLS 1.1 + 1.2 + 1.3
PalmTLS68K-Modern.prc / PalmTLSArm-Modern.prc   TLS 1.2 + 1.3
PalmTLS68K-TLS13.prc / PalmTLSArm-TLS13.prc     TLS 1.3 only
```

Build one profile directly with `TLS_PROFILE=tls13`, `modern`, or `full` and
the `test-prc` target.
Current ARM sizes are approximately 237 KiB, 427 KiB, and 608 KiB
respectively. Applications discover the protocols actually packaged through
`PalmTlsLibGetCapabilities`; requesting an omitted protocol is rejected as a
bad parameter. Because every profile has the same Palm database identity,
install exactly one.

The ARM variant accelerates common big-integer multiplication/squaring, the
complete P-256 scalar multiplication used by TLS 1.2 and TLS 1.3 ECDHE/ECDSA,
ECDSA double-scalar verification, SHA-256 compression, and streaming
AES-128-GCM record protection. TLS protocol
control, parsing, networking, and memory management still execute in PACE as
68K code, so this remains a hybrid rather than a fully native wolfSSL port. See
[ARM.md](ARM.md) for ABI, fallback, and offline benchmark details.

End-to-end TLS tests must run the m515 emulator at 8x or faster. Keep the
existing development session at 512x for practical public-site tests. At
real-time speed, the public-key operations can exceed server handshake
deadlines even when the protocol implementation is correct.
