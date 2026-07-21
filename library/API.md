# PalmTLS API

Include `include/palm_tls.h`, locate `PALM_TLS_LIB_NAME`, and load creator
`PALM_TLS_LIB_CREATOR` with type `sysFileTLibrary` if it is not already loaded.
Open the returned reference number before any other operation and balance every
successful open with `PalmTlsLibClose`.

`PalmTlsLibSleep` and `PalmTlsLibWake` are the standard Palm system-library
lifecycle traps. Applications normally let Palm OS invoke them during system
sleep/wake handling rather than using them as request operations.

## Discovery

`PalmTlsLibGetCapabilities` reports only the protocol engines present in the
installed build, plus the available verification modes, streaming, timings,
sessions, engine caching, resumption, and cooperative I/O. Their names and bit
values are defined in the public header. Applications must populate protocol
selectors from these bits and must not assume all three engines are installed.

The network-free `PalmTlsLibRunSelfTest` entry point also exposes ARM self-test
capability flags. Before using native math, the library checks a carry-heavy
256-bit product and imports
a known P-256 public key through the real ASN.1 and on-curve paths in each
installed TLS 1.2/TLS 1.3 engine. A failure disables the ARM hook and leaves the
safe 68K implementation active. Its result includes per-protocol load,
key-generation, shared-secret, and signature-verification timings.

Applications should not select a different code path for the ARM variant. Use
the normal PalmTLS calls and treat the capability as diagnostics. All
architecture/profile PRCs have the same database name and creator, so exactly
one may be installed. Replacing one variant with another does not require relinking the
application.

## Protocol and verification fields

Use one of `palmTlsProtocolTls11`, `palmTlsProtocolTls12`, or
`palmTlsProtocolTls13`. Use one of `palmTlsVerifyNone`,
`palmTlsVerifyExactPeer`, or `palmTlsVerifyCaStore`. For either verified mode,
`trustedPeerP` points to caller-owned DER or PEM bytes and
`trustedPeerLength` gives their exact size. The bytes and hostname must remain
valid until the operation or session ends.

## One-shot APIs

`PalmTlsLibExchange` performs handshake, request write, and response read into a
bounded caller buffer. It is convenient for small synchronous requests. Set
`PalmTlsExchangeParams.structSize` to `PALM_TLS_EXCHANGE_PARAMS_SIZE` and the
result size to `PALM_TLS_EXCHANGE_RESULT_SIZE`.

`PalmTlsLibExchangeStream` performs the same flow but sends decrypted chunks to
a `PalmTlsDataSinkProc`. Set `structSize` to
`PALM_TLS_STREAM_PARAMS_SIZE`; set the result size to
`PALM_TLS_STREAM_RESULT_SIZE`. `responseLimit` is an application policy and
may be smaller than available storage. The callback data is valid only during
the call, and a nonzero callback result aborts the exchange.

Both one-shot operations are synchronous. They are retained for compact clients
but should not run from a UI event handler when responsiveness matters.

## Incremental sessions

Only one session may be opening or active at a time.

1. Zero `PalmTlsSessionOpenParams` and `PalmTlsSessionOpenResult`.
2. Set their `structSize` fields to the corresponding current `*_SIZE`
   constants.
3. Fill `netRefNum`, connected `socket`, `hostnameP`, protocol, verification,
   trust bytes, timeout, and options.
4. Call `PalmTlsLibSessionOpen`.
5. Write all request bytes with `PalmTlsLibSessionWrite`; short successful
   writes are permitted, so advance by `transferred` and continue.
6. Read repeatedly with `PalmTlsLibSessionRead`. A successful zero-byte read
   is clean TLS EOF.
7. Call `PalmTlsLibSessionClose` on success or
   `PalmTlsLibSessionCancel` when abandoning an opening/active operation.

Use `PALM_TLS_SESSION_IO_PARAMS_SIZE`, which includes `options`. Set options to
zero for synchronous I/O.

### Cooperative handshake and I/O

Open with `PALM_TLS_SESSION_COOPERATIVE`. If `SessionOpen` reports
`palmTlsStatusWouldBlock`, retain the returned `sessionId` and call
`PalmTlsLibSessionHandshake` in later event-loop slices. For reads and writes,
set `PALM_TLS_IO_COOPERATIVE`; an expired short step timeout then returns
`WouldBlock` rather than converting the wait to a terminal failure.

`timeoutTicks` is passed to a bounded library step. It is not a replacement for
an application-level total deadline. The reference downloader uses both an
operation timeout and short per-step timeouts.

## Session reuse and engine cache

`PALM_TLS_SESSION_ALLOW_RESUME` enables the library's one-entry TLS resumption
cache. A later session can reuse it only when the protocol engine, hostname,
verification mode, and trust-anchor fingerprint match. Inspect
`PalmTlsSessionOpenResult.sessionReused` rather than assuming reuse.

TLS 1.3 resumption is available in `PalmTLSArm.prc`. The 68K TLS 1.3 engine
intentionally consumes but does not retain post-handshake session tickets: the
wolfSSL ticket-cache path performs an access that is unsafe on the Palm 68000
ABI. TLS 1.3 requests still complete normally, but `sessionReused` remains
false for that architecture/protocol combination. This restriction does not
apply to the ARM build or to the other 68K protocol engines.

The selected protocol engine remains relocated and initialized after a request,
avoiding repeated resource copy, relocation, and wolfSSL initialization. A
different protocol replaces the idle engine. `PalmTlsLibPurgeCache` releases
idle engine and resumption state; it reports busy while a session is active.

## Results and errors

Every session trap returns a Palm `Err` and fills a result. A zero trap error
only means the call crossed the library boundary; inspect `result.status` for
the protocol outcome. Diagnostic fields separate wolfSSL (`tlsError`), NetLib
(`netError`), Palm/platform (`platformError`), and streaming callback
(`sinkError`) failures.

`PalmTlsStatus` includes invalid input, allocation/resource/relocation/setup
failures, handshake/send/receive failures, size and sink failures, busy,
would-block, and cancelled. A terminal failure invalidates the operation; clean
up according to whether the session ID is still owned by the caller.

Timing fields use Palm system ticks. `loadTicks` covers engine preparation,
`handshakeTicks` covers the TLS handshake, and `transferTicks` covers streaming
request/response I/O.

## Offline ARM self-test

Zero a `PalmTlsSelfTestResult`, set `structSize`, and call
`PalmTlsLibRunSelfTest`. The call loads each installed TLS 1.2/TLS 1.3 engine and runs
deterministic P-256 ECDHE key-generation/shared-secret and ECDSA verification
vectors, but performs no DNS, NetLib, socket, or TLS record exchange.
`armStatus` distinguishes an unavailable ARMlet, a passed test, and a rejected
ARMlet. Set `structSize` to `PALM_TLS_SELF_TEST_RESULT_SIZE`. `loadTicks` and
`testTicks` are combined totals; the
`tls12*Ticks` and `tls13*Ticks` fields separate engine load, ECDHE key
generation, ECDHE shared-secret calculation, and ECDSA verification. Palm
system ticks are normally 1/100 second. Applications should continue on the
68K fallback when the result is
`palmTlsStatusSelfTestFailed`.

## Resource and security constraints

The full PRC carries separate reduced TLS 1.1, 1.2, and 1.3 engines; compact
profiles physically omit unselected engines. The library loads only the
selected installed engine. Large engines are split below Palm's resource-size limit;
code-only segments execute from a temporary resource database while writable
state remains in locked dynamic memory.

TLS 1.2/1.3 are restricted to the implemented P-256, SHA-256, AES-128-GCM, and
ECDHE ECDSA/RSA client profiles. TLS 1.1 adds its legacy RSA/AES-CBC/SHA-1
profile. Palm's entropy facilities are not a modern CSPRNG. This library is for
hobbyist interoperability, not high-value secrets.

## Examples

- `examples/network/library_lifecycle.c`: safe load/open/version/close pattern
- `examples/network/cooperative_tls.c`: handshake/write/read state handling
- `examples/network/http_stream.c`: feeds TLS plaintext into the HTTP component
- `apps/tls-tester/src/download_client.c`: full DNS/TCP/TLS/HTTP implementation
