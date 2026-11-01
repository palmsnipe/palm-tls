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
sessions, engine caching, resumption, cooperative I/O, and optional TLS 1.3
phase profiling/context reuse. Their names and bit
values are defined in the public header. Applications must populate protocol
selectors from these bits and must not assume all three engines are installed.

The network-free `PalmTlsLibRunSelfTest` entry point also exposes ARM self-test
capability flags. Before using native math, the library checks a carry-heavy
256-bit product and imports
a known P-256 public key through the real ASN.1 and on-curve paths in each
installed TLS 1.2/TLS 1.3 engine. Startup validation also checks off-curve,
negative/out-of-range coordinates, non-affine Z, and API rejection behavior.
The native hook preserves these checks and the existing caller checks for
infinity, order, and private keys. A failure disables the ARM hook and leaves
the safe 68K implementation active. Its result includes per-protocol load,
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

Up to two sessions using the same TLS protocol may be opening or active at a
time. Calls are still serialized through Palm OS library traps, but separate
session IDs retain independent handshake, socket, and I/O state. A third
overlapping session, or a request for another protocol while either slot is in
use, reports `palmTlsStatusBusy`.

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

`PALM_TLS_SESSION_ALLOW_RESUME` enables a one-entry TLS resumption cache in
each of the two session slots. A later session in that slot can reuse it only
when the protocol engine, hostname, verification mode, and exact trust bytes
match. The library owns a copy of the cached trust bytes; equality is checked
by length and contents, rather than a hash or caller pointer. Inspect
`PalmTlsSessionOpenResult.sessionReused` rather than assuming reuse.

TLS 1.3 resumption is available in `PalmTLSArm.prc`. The 68K TLS 1.3 engine
intentionally consumes but does not retain post-handshake session tickets: the
wolfSSL ticket-cache path performs an access that is unsafe on the Palm 68000
ABI. TLS 1.3 requests still complete normally, but `sessionReused` remains
false for that architecture/protocol combination. This restriction does not
apply to the ARM build or to the other 68K protocol engines.

For TLS 1.3, each slot also retains its configured `WOLFSSL_CTX` and parsed
trust store after normal close. Reuse requires the same hostname, verification
mode, and exact trust bytes. This is independent of
`PALM_TLS_SESSION_ALLOW_RESUME`: a full handshake can reuse its context without
offering a ticket. Every connection still creates a fresh `WOLFSSL`, ephemeral
P-256 key share, I/O bindings, SNI, and hostname check.

`PALM_TLS_SESSION_NO_CONTEXT_REUSE` disables context reuse for that connection
for diagnostic comparisons; it does not disable ticket resumption. TLS 1.1/1.2
continue to create a fresh context per connection. Cancellation and terminal
handshake failures discard the slot's context and resumption state. Normal
close retains the TLS 1.3 context, parsed CAs, and owned trust copy, plus a
separate trust copy when a resumption entry is saved. Up to two slots can retain
these allocations while idle. Use purge or library close to release them.

The selected protocol engine remains relocated and initialized after a request,
avoiding repeated resource copy, relocation, and wolfSSL initialization. A
different protocol replaces the idle engine. `PalmTlsLibPurgeCache` releases
the engine, contexts, trust copies, profiles, and resumption state. If a session is opening or active, purge
cancels it as part of unloading the engine. This makes purge the recovery path
when a caller cannot cleanly close or cancel a session it owns.

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
`handshakeTicks` starts before context creation, trust loading, and TLS 1.3
key-share generation and ends when the TLS handshake completes. This boundary
applies to all protocol engines; earlier releases started after setup and
omitted TLS 1.3 key-share generation. DNS and TCP connection setup are caller
work and are excluded. `transferTicks` covers streaming request/response I/O.

## TLS 1.3 session phase profiling

Check `PALM_TLS_CAP_HANDSHAKE_PROFILE`, then include
`PALM_TLS_SESSION_PROFILE` in `PalmTlsSessionOpenParams.options`. Zero a
`PalmTlsSessionProfile`, set `structSize` to `PALM_TLS_SESSION_PROFILE_SIZE`
(240), and call `PalmTlsLibGetSessionProfile(refNum, sessionId, &profile)`.
The new trap is appended; existing trap offsets and result sizes are unchanged.
TLS 1.1/1.2 do not produce this profile.

Query during an active/opening session or after close/cancel, before its slot
is reused or the engine is purged/replaced. `status` records the last session
operation outcome; `contextReused`, `sessionReused`, and `ticketReady` report
actual state. TLS 1.3 tickets normally arrive after the handshake: read the
server's post-handshake traffic before expecting a saved resumption entry.

`handshake` and `postHandshake` each contain 13 exclusive tick totals and entry
counts indexed by `PalmTlsHandshakePhase`, plus `elapsedTicks` and `complete`.
Nested phases subtract from their parents, so the ticks partition each period:

| Phase | Timed work |
| --- | --- |
| Other | Remaining setup/state-machine work, SSL allocation, SNI, cleanup |
| Context | Fresh wolfSSL context/method creation |
| Trust | Owned trust copy, trust-store/peer loading, verification configuration |
| KeyShare | Fresh client P-256 key-share generation |
| KeyAgreement | Server key-share processing and shared-secret calculation |
| Certificate | TLS certificate-message handling, excluding nested signature checks |
| Signature | Certificate-chain signatures and CertificateVerify authentication |
| Kdf | HKDF extraction and label expansion |
| Finished | Finished generation/verification, excluding nested KDF/record work |
| Record | TLS 1.3 record encryption/decryption |
| Network | Palm socket send/receive callbacks |
| Ticket | NewSessionTicket processing, excluding nested work |
| Idle | Gaps between cooperative/library calls, including application scheduling |

The handshake period uses the same start/end timestamps as `handshakeTicks`.
The post-handshake period starts immediately afterward and includes tickets,
application record I/O, idle time, and close cleanup. `complete == 1` means the
period ended with balanced timing scopes; it does **not** indicate successful
authentication. Inspect `status` and the session operation result. Active
snapshots can have an incomplete current period. A closed profile is immutable.

Convert ticks using `SysTicksPerSecond()`. Zero ticks can mean less than one
tick; use entry counts to distinguish this from unused phases. Measurements
include instrumentation overhead. Profiling is opt-in: inactive hooks do not
read the clock. `PALM_TLS_CAP_CONTEXT_REUSE` separately advertises the TLS 1.3
context cache, which works without enabling profiling.

### Detailed ECDHE profile

When `PALM_TLS_CAP_ECDHE_PROFILE` is present, the same trap also accepts the
288-byte `PalmTlsSessionEcdheProfile` extension:

```c
PalmTlsSessionEcdheProfile detail;
MemSet(&detail, sizeof(detail), 0);
detail.base.structSize = PALM_TLS_SESSION_ECDHE_PROFILE_SIZE;
PalmTlsLibGetSessionProfile(refNum, sessionId, &detail.base);
```

Open with `PALM_TLS_SESSION_PROFILE` as before. The original 240-byte result
is still accepted; no trap offsets or existing structure sizes change.
`detail.ecdhe` contains exclusive ticks and entry counts for other/setup,
peer X9.63 import, public-key validation, scalar multiplication, and affine
mapping. Nested validation is excluded from import. Multiplication includes
native marshaling, public-point table construction/normalization, and the
secret scalar loop; it returns Jacobian coordinates. Mapping includes the
separate conversion to affine coordinates. Other covers curve allocation,
parameter loading, secret serialization, and cleanup.

The detail is active only inside the TLS 1.3 handshake key-agreement phase,
so key generation, certificate verification, and post-handshake work do not
pollute it. Its tick sum and `elapsedTicks` equal
`base.handshake.ticks[palmTlsHsKeyAgreement]`. `complete` means balanced scopes,
not authentication success; it is zero until key-agreement processing ends.
The normal profile's query lifetime, opt-in behavior, clock resolution, and
instrumentation overhead also apply to this extension.

### Cold-start and trust-loading profile

Check `PALM_TLS_CAP_STARTUP_PROFILE` to use the optional 400-byte result:

```c
PalmTlsSessionStartupProfile startup;
MemSet(&startup, sizeof(startup), 0);
startup.session.base.structSize = PALM_TLS_SESSION_STARTUP_PROFILE_SIZE;
PalmTlsLibGetSessionProfile(refNum, sessionId, &startup.session.base);
```

Open with `PALM_TLS_SESSION_PROFILE`. The original 240/288-byte results and
trap offsets are unchanged. `session` contains the earlier ECDHE extension.
`load` separates resource/database setup, resource allocation/copy, relocation,
native initialization/known-answer tests, wolfSSL initialization, per-engine
qualification, and other bookkeeping. Its tick sum and `elapsedTicks` equal
that open's `loadTicks`. Warm opens have zero load ticks and calls; an earlier
connection's load is never attributed to a later session.

`trust` separates other configuration/owned-buffer work, PEM conversion,
certificate decoding, and CA insertion/cleanup. Nested decoding is excluded
from insertion. The cache phase is reserved and currently zero. Full context
reuse avoids trust loading entirely and produces zero trust ticks/calls.
The sum and `elapsedTicks` equal the main handshake's exclusive Trust phase.
All clocks, completeness flags, query lifetime, and instrumentation caveats
from the earlier profiles apply. These details describe successful engine
loads; a failed load may return no session ID to query.

CA certificates use the same public-data Base64 decoder already used for other
public certificates. Private/encrypted key decoding is unchanged. Certificate
parsing, restrictions, signatures, hostname checks, and exact trust identity
remain in the normal verification path; no serialized CA cache is restored.

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

If `PALM_TLS_CAP_VERIFY_PROFILE` is present, callers may instead zero a
`PalmTlsSelfTestProfileResult`, set `base.structSize` to
`PALM_TLS_SELF_TEST_PROFILE_RESULT_SIZE` (188), and pass `&result.base` to the
same trap. The original 52-byte result remains accepted. `tls12Verify` and
`tls13Verify` contain exclusive tick totals and entry counts indexed by
`PalmTlsVerifyPhase`: other/setup/cleanup, signature decoding, range checks,
curve setup, hex import, order arithmetic, point arithmetic, and final reduction
and comparison. Nested phases subtract their time from the parent phase.
`complete == 1` means balanced scopes; all eight tick totals then sum to the
corresponding `base.tls*VerifyTicks`. Zero ticks can mean less than one clock
tick, so use call counts to distinguish a short phase from an unused phase.
Only the positive self-test verification activates profiling; normal TLS calls
take inactive checks without reading the clock. Negative verification vectors
run afterward, outside the timing. Times include instrumentation overhead and
retain the device clock's resolution.

## Resource and security constraints

The full PRC carries separate reduced TLS 1.1, 1.2, and 1.3 engines; compact
profiles physically omit unselected engines. The library loads only the
selected installed engine. Large engines are split below Palm's resource-size limit;
code-only segments execute from a temporary resource database while writable
state remains in locked dynamic memory.

TLS 1.2/1.3 are restricted to the implemented P-256, SHA-256, AES-128-GCM, and
ECDHE ECDSA/RSA client profiles. The ARM TLS 1.3 engine also offers
ChaCha20-Poly1305, ahead of AES-128-GCM. TLS 1.1 adds its legacy RSA/AES-CBC/SHA-1
profile. Palm's entropy facilities are not a modern CSPRNG. This library is for
hobbyist interoperability, not high-value secrets.

## Examples

- `examples/network/library_lifecycle.c`: safe load/open/capability/close pattern
- `examples/network/cooperative_tls.c`: handshake/write/read state handling
- `examples/network/http_stream.c`: feeds TLS plaintext into the HTTP component
- `apps/tls-tester/src/download_client.c`: full DNS/TCP/TLS/HTTP implementation
