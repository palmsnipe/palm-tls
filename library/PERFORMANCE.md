# ARM performance review — November 1, 2026

## Release 0.1.3 to 0.1.4

The common-ABI, profiling-disabled benchmark compares the **published 0.1.3
binary** against the CI-built 0.1.4 release with its ChaCha20 support retained.
Two runs give cold full medians **1510 → 570 ms** (62% less time), warm full
**1320 → 350 ms** (73% less), and resumed **580 → 170 ms** (71% less).
The external API timer includes engine/context/trust/keyshare setup. Both
versions negotiate ChaCha20-Poly1305 and validate the same eight-root trust
bundle. Both releases use the same pinned CI toolchain image. This is 100 MIPS emulator
comparison data, not physical-device timing. See the [raw data and method](bench/baselines/2026-11-01-release-013-014/README.md)
and [release notes](../docs/releases/0.1.4.md). Earlier sections below compare
individual development stages, not published 0.1.3.

## Cold startup and public CA PEM loading

The optional session profile now extends to **400 bytes** and separates cold
engine loading from trust-store processing. The earlier 240/288-byte results,
trap offsets, and handshake boundaries remain unchanged. Seven loader phases
partition `loadTicks`; five trust slots partition the main exclusive Trust
phase. Call counts distinguish sub-tick work from absent work. The reserved
trust-cache slot is currently zero. [API.md](API.md#cold-start-and-trust-loading-profile)
describes the extension.

The profile-only baseline (`995460c` plus the saved support patch) reproduces
the earlier **660 ms** cold total. It identifies two measurable costs: CA PEM
conversion occupies roughly **110–130 ms** of the 150 ms eight-root trust load;
loader relocation takes roughly **50 ms**, native qualification/initialization
50–60 ms, and per-engine rejection-test qualification about **40 ms**. Resource
setup/copy and wolfSSL initialization are below a tick in this fixture.

Three optimizations preserve validation and compatibility:

- CA PEM input now uses wolfSSL's existing public-data Base64 decoder, as
  other public certificates already do. Private/encrypted key decoding keeps
  its constant-time decoder. Certificate parsing and all restrictions remain
  unchanged. Differential tests compare both actual decoders on **33,915**
  valid/malformed/capacity cases, including every byte in each quartet position,
  whitespace, padding, embedded NULs, truncation, random input, and output
  guard bytes.
- Relocation uses aligned 32-bit accesses in its writable scratch buffer,
  replacing two `MemMove` system calls per four-byte relocation. Storage still
  receives its final contents through `DmWrite`. Per-segment bounds reduce
  repeated table scans while retaining support for unsorted tables. The fixed
  linker-bank mapping uses a checked arithmetic lookup with a build-time layout
  assertion. New tests cover all bank boundaries, unsorted entries, alignment,
  overflowing/truncated offsets, bad segments/version, allocation failure,
  write failure, and scratch cleanup.
- Startup qualification restores only the generator's 16 used TFM limbs,
  the one higher limb touched by a negative test, and Z's used limb/sign.
  It avoids repeatedly clearing all 264 limbs. Every positive/rejection case
  and its expected wolfSSL error remains in place; no startup check is removed.

The investigated wolfSSL 5.9.4 certificate-cache serializer does **not** retain
all signer policy fields, including path-length, key-usage, and name-constraint
information. Persisting/restoring it would not preserve the requested trust
rules. That cache remains disabled. The existing exact-byte context/trust-store
reuse remains active; this change speeds normal loading and keeps full
certificate processing rather than introducing a lossy cache format.

Both sides use the same 400-byte profiling application, wolfSSL 5.9.4,
CA/leaf fixture, eight P-256 roots (4,560 PEM bytes), ARMv4T `-Os` target,
supplied Frankenpilot/E3 session, emulator binary, and **100 MIPS**. The baseline
support patch adds profiling only. Final changes are the CA decoder selection,
relocator, and test-vector initialization. No native arithmetic, CPU allowlist,
trust corpus, session-resumption policy, or TLS algorithm changes are mixed in.

Five-sample medians, first run / repeat:

| Case | Profiled baseline | Final |
| --- | ---: | ---: |
| Cold load + full handshake, cached-context configuration | 660 / 660 ms | 580 / 570 ms |
| Cold engine load alone | 150 / 150 ms | 100 / 100 ms |
| Cold full handshake alone | 510 / 510 ms | 470 / 470 ms |
| Warm full handshake, cached context | 360 / 360 ms | 360 / 360 ms |
| Warm resumed handshake, cached context | 170 / 170 ms | 170 / 170 ms |
| Full handshake with context reuse disabled | 510 / 510 ms | 470 / 470 ms |
| Resumed handshake with context reuse disabled | 320 / 320 ms | 290 / 290 ms |

Cold setup improves **12.1–13.6%**. The combined cold median is calculated from
paired load/handshake samples before taking the median; component medians need
not sum to it. Final cold-load samples span 100–110 ms, full-handshake samples
470–480 ms, and paired totals 570–580 ms. Warm cached traffic is unchanged
within the 10 ms clock resolution, as intended.

The final profile reports roughly **70 ms** for PEM conversion, 40 ms for CA
decoding, and zero/sub-tick other/insertion work. Per-engine qualification falls
from about 40 to **10 ms**, and relocation from about 50 to **40 ms**. The
remaining native known-answer tests take 50–60 ms and are retained. These
per-phase medians need not sum exactly to period medians.

Each full run independently confirms **20 full and 10 resumed TLS 1.3**
P-256/AES-128-GCM connections, plus trust ownership/identity, wrong CA/hostname/
mode rejection, purge, cancellation, slot isolation, and TLS 1.2 full/resumed
regressions. A separately launched, unchanged older benchmark app also passes
against the final library using the **240/288-byte profile APIs**. The offline
Palm benchmark passes both **52/188-byte self-test results**. Project/profile/
package checks, the complete wolfSSL patch stack, host arithmetic oracles,
and TI925T/PXA270 arithmetic/control-address traces pass. The new nested trust
profiler and startup result reader have positive/rejection tests.

These are instrumented local emulator measurements with a 100 Hz Palm clock;
DNS/TCP setup is excluded. They do not establish physical Palm or Internet
latency. No attempt is made to hide setup by moving it outside the existing
timing boundary. A rebuild after adding a compile-time assertion changed only
Palm database timestamps; all resources were verified identical and the exact
measured PRC was retained for the final ABI/offline runs.

All existing ARM profiles and both benchmark applications retain the same
single **34,760-byte ARMv4T image**, SHA-256
`10a7c6649b46968ae19bf10259492e95edb8b48a535729977435516639d32ccd`.
There is no additional CPU-specific PRC. The measured final full library SHA-256
is `8007c33fbd8f9fcf1176150278173a3fb8a3db46f5fa687da3f813f0b718cecd`.
Repeated raw samples, loader/trust details, server logs, ABI/offline regressions,
metadata, and the profile-only baseline support patch are in
[bench/baselines/2026-11-01-startup](bench/baselines/2026-11-01-startup).

## Native P-256 public-key validation

Built-in P-256 public-key validation now crosses to the shared ARMlet for the
curve equation. The bridge preserves the original check order and errors:
unsigned X and Y must be below `p`, then Z must be positive affine one, then
`y^2 = x^3 - 3x + b (mod p)` must hold. Negative, oversized, `p`/`p+1`,
non-affine, and off-curve inputs remain rejected. Raw native coordinates are
checked for canonical range **before** Montgomery conversion, so a forbidden
encoding cannot become valid through reduction. The native command writes no
request/output bytes.

There are two narrowly scoped wolfSSL hooks. The built-in P-256
`wc_ecc_point_is_on_curve` path can avoid generic curve loading and modular
arithmetic. The internal equation-only hook requires exact positive `p`,
`a=p-3`, and `b` parameters; it deliberately preserves that function's original
Z-independent contract. It returns only an equation result. Existing callers
still perform their infinity, coordinate, order/subgroup, curve-ID, and
private-key checks. Other domains, disabled/unavailable ARM math, and unknown
native statuses retain the original implementation. Custom indices do not
bypass the public curve-loading path. No verification mode or TLS rule is
weakened, and the public trap/structure ABI is unchanged.

The baseline is the unchanged **`feaadb3`** build. Both sides use identical
wolfSSL 5.9.4 configuration, detailed profiler, trust/leaf fixture, benchmark
application code, emulator/session, ARMv4T `-Os` settings, and **100 MIPS**.
The benchmark application's resources differ only in `armc:1`; the library
also contains the new 68K validation bridges, vendor hooks, and startup tests.
Two fresh session runs per build each contain five samples of six connection
cases and the existing authentication/session regressions.

Five-sample medians, first run / repeat:

| Operation | Baseline | Native validation |
| --- | ---: | ---: |
| Warm full handshake, cached context | 410 / 410 ms | 360 / 350 ms |
| Resumed handshake, cached context | 190 / 190 ms | 170 / 170 ms |
| Full handshake, context reuse disabled | 570 / 570 ms | 510 / 510 ms |
| Resumed handshake, context reuse disabled | 340 / 340 ms | 320 / 320 ms |
| Cold full handshake, after purge | 570 / 570 ms | 510 / 510 ms |
| Cold engine loading, separate from handshake | 130 / 130 ms | 150 / 150 ms |

Warm full handshakes improve **12.2–14.6%** and cached resumed handshakes
**10.5%** in these runs. Warm full final samples span 350–360 ms versus
410–420 ms; cached resumed final samples span 160–170 ms versus 180–190 ms.
The expanded startup tests add a measured 20 ms to cold engine loading.
Cold load plus full handshake therefore moves from about **700 to 660 ms**,
rather than the 60 ms handshake-only saving. Loading is still excluded from
`handshakeTicks`, exactly as in the baseline.

The detailed profile confirms that validation remains active: the peer-point
phase has one entry per handshake but falls from **20 ms to zero measured
ticks**. Total key agreement moves from about **100 to 80 ms**. Full-handshake
certificate handling moves from roughly 40 to 20 ms and the two signature
checks from 190 to 170 ms. This shows that validation also benefits the
certificate paths. Scalar-multiplication, key generation, trust-store identity,
resumption policy, and the selector fix are unchanged. A zero-tick phase means
less than the 10 ms clock resolution, not zero work; per-phase medians need not
sum to median totals. No standalone sub-tick validation latency is claimed.

Each run independently confirms **20 full and 10 resumed TLS 1.3 connections**
using P-256 and `TLS_AES_128_GCM_SHA256`, strict CA/hostname verification, and
the same eight-root, 4,560-byte trust bundle. Owned/exact trust, changed
hostname/mode and bad-CA rejection, purge, cancellation, slot isolation, and
TLS 1.2 full/resumed regressions pass. These are loopback OpenSSL 3.5.9
handshakes on the supplied Frankenpilot/E3 session, including instrumentation
overhead; they do not establish physical Palm or Internet latency.

The new native command is qualified before enabling acceleration with valid,
off-curve, and out-of-range inputs plus unchanged-output checks. Each installed
TLS 1.2/1.3 engine also executes 14 positive/rejection cases and null/invalid
index checks through the real wolfSSL API at startup. A failure disables
acceleration and rechecks through the software path. This qualification uses
an index below `ECC_CUSTOM_IDX` for the invalid-index case: wolfSSL treats
`-1` as the custom-domain sentinel. Full-key infinity/order/private checks
remain in their existing callers rather than being replaced by the fast hook.

Host and **TI925T/PXA270** oracles pass **270 point-validation cases**, including
independently derived curve constants, small-X valid points, negative-Y
partners, random points, perturbed coordinates, canonical boundaries, malformed
headers, request alignment 0–3, and unchanged request/output buffers. The host
bridge test compiles the production bridge together with the actual kernel
and checks negative/wide integers, Z, error precedence, exact domain matching,
disabled/missing engines, and unknown native statuses. All existing AES-GCM,
field, scalar, inversion/map, order, ECDSA, field trace, and secret-scalar trace
checks pass. Project/profile/package checks and actual Palm execution of both
self-test result sizes also pass. The complete vendor patch stack reproduces
the cached source, and the non-ARM archives retain the software validation.

The native image grows **536 bytes**, from 34,224 to **34,760 bytes**, SHA-256
`10a7c6649b46968ae19bf10259492e95edb8b48a535729977435516639d32ccd`.
All existing ARM profiles and both benchmark apps share this one ARMv4T image.
The CPU allowlist and fallback policy are unchanged; no processor-specific PRC
is added. The full ARM library grows 4,056 bytes, including bridges and startup
checks. Its final SHA-256 is
`ec2d255056c5daa394464a65f472fa815cc43e3a18888b880981b4c9801953c5`.

Raw repeated handshake samples, detailed phase counters, public server
configuration/logs, manifests, and the offline ABI regression are saved under
[bench/baselines/2026-11-01-p256-validation](bench/baselines/2026-11-01-p256-validation).

## ECDHE peer-point multiplication with mixed-coordinate additions

The arbitrary-point private-scalar path now batch-normalizes its table of
`Q..15Q` with one field inversion, selects only affine X/Y coordinates with
full-table scans, and uses mixed additions in the fixed 64-window radix-16
loop. Fixed-base key generation, public double-scalar arithmetic, the volatile
selector reads, CPU allowlist, and fallback are preserved.

The loop has a bounded exceptional case that avoids an extra doubling on
every addition. Before addition the accumulator is `16*prefix*Q`. For a valid
nonzero P-256 point of prime order `n`, equality with `digit*Q` requires
`16*prefix = n+digit`: earlier windows are smaller than `n`, and `2n > 2^256`.
Since `n mod 16 = 1`, this can occur only for digit 15 in the final window,
at input scalar `n+30`. The implementation precomputes `30Q` once in the
otherwise unused table-zero slot and selects it without branching. Zero digits
perform a dummy addition and select the old accumulator; opposite and infinity
cases use masks. This helper is specific to the documented fixed-window loop,
not a general complete mixed-addition routine. Scalars zero and `n` still fail
with output unchanged. Tests include `n+30`, values above `n`, sparse/dense
scalars, both coordinate-return modes, and unaligned requests.

An optional **288-byte session profile** extends the existing 240-byte result
without changing it or adding a trap. Its five exclusive phases separate peer
import, validation, scalar multiplication, affine mapping, and remaining
setup/export/cleanup. Nested validation is excluded from import; detail ticks
sum exactly to the enclosing key-agreement phase. Hooks are active only inside
profiled TLS 1.3 handshake key agreement. Existing phase and self-test ABIs
remain valid; [API.md](API.md#detailed-ecdhe-profile) describes the extension.

The baseline is `6adbf09` plus the **same** detailed profiling and benchmark
support, with its original native arithmetic. Both configurations use identical
wolfSSL 5.9.4 archives, trust/leaf fixtures, emulator/session, ARMv4T `-Os`
settings, and **100 MIPS**. Resource comparisons show that both the library and
handshake application PRCs differ **only in `armc:1`**. This comparison isolates
the native kernel; no context-cache or timing-boundary changes are mixed in.

Five-sample medians from two fresh emulator sessions per handshake build:

| Operation | Baseline first / repeat | Optimized first / repeat |
| --- | ---: | ---: |
| Native arbitrary-point affine multiply | 75 ms | 65 / 65 ms |
| Warm full handshake, cached context | 430 / 420 ms | 420 / 410 ms |
| Resumed handshake, cached context | 190 / 200 ms | 190 / 190 ms |
| Full handshake, context reuse disabled | 580 / 580 ms | 570 / 570 ms |
| Resumed handshake, context reuse disabled | 350 / 350 ms | 340 / 340 ms |
| Cold full handshake, after purge | 580 / 580 ms | 570 / 570 ms |
| Warm full key-agreement phase | 110 / 110 ms | 100 / 100 ms |

Both optimized native runs reproduce the **13.3%** improvement, including the
additional table normalization. The native suite batches four operations per
sample; final samples span 62.5–65 ms versus baseline 72.5–75 ms. Fixed-base
multiplication remains 26.25 ms, mapping 3.44 ms, and raw field multiplication
12.82 us. The roughly 10 ms warm-full improvement is reproduced; cached
resumption overlaps the baseline at the 10 ms clock resolution, so a reliable
percentage improvement for that case is not established. Cold engine loading
remains separate at 130–140 ms. Per-phase medians need not sum to total medians.

Detailed warm-full profiles place validation around **20 ms**, multiplication
at **70–80 ms before / 70 ms after**, mapping at 0–10 ms, and other setup at
about 10 ms. These phase samples are coarser than the native batched measurement.
Zero import/mapping ticks mean sub-tick work when entry counts are nonzero.
Each handshake run independently confirms 20 full and 10 resumed TLS 1.3
connections using P-256/AES-128-GCM and the same eight-root, 4,560-byte CA bundle.
Owned trust, bad CA/hostname/mode, purge, cancellation, slot isolation, and real
TLS 1.2 full/resumed regressions all pass. Measurements include profiling
and native-call overhead; they establish emulator behavior, not physical Palm
or Internet latency.

The final image grows **320 bytes**, from 33,904 to **34,224 bytes**, SHA-256
`e8a1178462e295ca8c80e0f541031c9587d5a80b8f1827e6c1782e10beaf9bbd`.
All existing ARM profiles and both benchmark apps share this single ARMv4T
image; no CPU-specific PRC is introduced. A native execution probe observed
3,840 bytes of stack use versus 3,552 for the baseline for a mapped general
multiplication; this is a measured call, not a whole-application stack bound.

Project/package checks, host integer oracles, and the extracted native image
pass on **TI925T and PXA270**: 168 AES-GCM records, 1,881 raw-field chains,
69 inversions/maps, 84 scalar products, 85 double-scalar cases, 432 order
preparations, and 24 valid/tampered ECDSA cases, with request alignment 0–3.
New tests compare complete basic-block and data-address traces for scalars
`1`, `n-1`, a sparse pattern, and `n+30` on the same peer point, with translation
caches flushed and nonempty trace checks. Existing field instruction/address
traces also pass. These preserve tested control/address behavior, without
claiming physical constant-time multiplication on every processor. Profiler
nesting, overflow, idle/inactive checks, slot isolation, and tick wraparound
pass; the vendor patch stack reproduces cleanly and ECC compiles with profiling
disabled. Actual Palm PRCs exercise the extended/old profile APIs and both
self-test result sizes.

Raw data, both handshake repeats, native samples, binary manifests, independent
server logs and the baseline support patch are saved under
[bench/baselines/2026-11-01-ecdhe-mixed](bench/baselines/2026-11-01-ecdhe-mixed).
The final library SHA-256 is
`e6e5c288d4d9a61a26d09613c423086c967210471d4e098f71a1db180bf8f1c1`.

## TLS 1.3 phase profiling and context/trust-store reuse

TLS 1.3 now exposes opt-in, per-session exclusive timings for context creation,
trust loading, client key-share generation, key agreement, certificate handling,
signature checks, HKDF, Finished, records, network callbacks, tickets, idle gaps,
and remaining work. Handshake and post-handshake periods are separate, so
NewSessionTicket processing is visible rather than folded into the handshake.
Each period includes entry counts and a balanced-scope completion flag. The
new 240-byte result uses an appended trap; existing trap offsets and structure
sizes remain unchanged. [API.md](API.md#tls-13-session-phase-profiling) documents
the boundaries and lifetime.

The handshake timer now starts **before context/trust setup and TLS 1.3
key-share generation**. Earlier releases omitted this setup from the timer.
Engine loading remains a separate field; caller DNS/TCP setup is excluded.
Consequently, these figures should not be compared directly with older
handshake timings or the offline crypto self-test.

Each TLS 1.3 slot retains its configured wolfSSL context and parsed trust store
on normal close. Reuse requires the same hostname, verification mode, and exact
owned trust bytes. Resumption uses the same exact-byte identity, replacing the
previous hash-only check. Every connection gets a fresh SSL object, ephemeral
key share, I/O bindings, SNI, and hostname validation. Cancellation/terminal
handshake failure discards cached state; purge and library close free all
retained allocations. TLS 1.1/1.2 retain their fresh-context behavior.

The comparison uses **the same final PalmTLSArm PRC** with context reuse
disabled/enabled through a diagnostic session option. Both sides enable phase
profiling and use wolfSSL 5.9.4; this isolates context reuse rather than
comparing an older, differently timed library. Two independent runs each
contain five samples per case (30 timed connections), through the public
session API and a real local OpenSSL TLS server. The server independently
confirms **20 full and 10 resumed TLS 1.3 connections per run**. Warm full
connections omit the resumption option, so their improvement is not ticket
reuse.

Five-sample medians, reproduced in both runs:

| Connection | Context reuse disabled | Context reuse enabled | Less handshake time |
| --- | ---: | ---: | ---: |
| Cold full, after engine purge | 580 ms | 580 ms | — |
| Warm full, no ticket offered | 580 ms | 420 ms | 27.6% |
| Resumed, warm engine | 350 ms | 200 ms | 42.9% |

Cold engine load is an additional **130 ms** in both modes; warm cases have
zero load time. Within the cached configuration, resumption reduces 420 ms
full handshakes to 200 ms, a **52.4%** reduction. Full samples span 570–580 ms
without context reuse and 420–430 ms with a warm context; cached resumed
samples span 190–200 ms.

The exclusive phases explain the change. The eight-root CA bundle takes
roughly **150–160 ms** to copy/load when a context is created and has **zero
trust-load calls** on a context hit. Full handshakes spend about **40 ms** in
certificate handling and **190 ms** across two signature checks; both phases
have zero calls on resumed handshakes. Fresh key-share generation still takes
40–50 ms and shared-secret processing about 110 ms in both cases. HKDF takes
10–20 ms, with 20 profiled calls on full and 26 on resumed handshakes. Tickets
are processed in the post-handshake period and actually retained for reuse.
Per-phase medians need not sum to the median total.

The fixture has **eight P-256 roots / 4,560 PEM bytes**, a root-signed P-256
leaf, strict CA and hostname verification, and negotiates P-256 with
`TLS_AES_128_GCM_SHA256`. Tests use the supplied Frankenpilot / Tungsten E3
session at **100 MIPS**, loopback native networking, and OpenSSL 3.5.9. These
are real protocol handshakes in an emulator, with instrumentation overhead;
they do not establish physical-device or Internet latency. The Palm clock is
100 Hz: a zero-tick record/network/Finished phase can be shorter than 10 ms,
not cost-free. Trust-store savings depend on the application's CA corpus.

The memory tradeoff is deliberate: each of two slots may retain a wolfSSL
context, parsed CAs, an owned trust copy, and a separate trust copy for its
saved ticket while idle. Heap usage is not quantified by this benchmark.
`PalmTlsLibPurgeCache` or library close releases these allocations. Context
reuse operates without enabling profiling or ticket resumption.

Both emulator runs also pass owned-buffer/exact-byte trust checks, changed
hostname/verification-mode and bad-CA rejection, exact-peer verification,
purge, cancellation during opening, interleaved cooperative slot isolation,
and independently confirmed TLS 1.2 full/resumed handshakes. Host tests check
phase nesting, tick wraparound, disabled hooks, idle accounting and overflow,
plus 70,000 session-ID allocations across wraparound with active/retained IDs.
The complete wolfSSL patch stack reproduces the cached instrumented sources;
the touched sources also compile with profiling disabled. Project/package
checks, existing offline Palm self-test ABIs, and TI925T/PXA270 crypto and
trace oracles pass.

No native arithmetic or CPU dispatch changes are introduced. Every existing
ARM profile and the benchmark retain the same **33,904-byte ARMv4T image**,
SHA-256 `4c8e5b1840f1a1807324ebd307fd89872902df00d65586d0e9ba4a2792a2d743`.
The CPU allowlist and fallback remain unchanged; there is no additional
CPU-specific ARM PRC.

Raw samples, phase counters, public server configuration/logs, binary hashes,
and repeated summaries are saved under
[bench/baselines/2026-11-01-tls13-context](bench/baselines/2026-11-01-tls13-context).
The manifests identify `dd5c977` plus this uncommitted implementation; both
runs use library SHA-256
`5c3aaed2fd8c3c7f42e9296b35110fddd0f95b03e074c793ab44f4188db2e8b0`.
[bench/README.md](bench/README.md#full-and-resumed-tls-13-handshakes) gives the
reproduction command. No private fixture keys, SDKs, ROMs, or session images
are archived.

## Field squaring through the integrated multiplier

`FeSquare(result, value)` now calls `FeMultiply(result, value, value)`.
The integrated multiplier consumes all input limbs before writing its output,
so the existing in-place calls remain valid even when both inputs and the
output alias. The former Comba squarer and its unused column-accumulation
helper are removed. The wide reducer stays available for diagnostics.
`FeSelect`, including both volatile operand reads, is unchanged from `865b973`.

A fresh clean baseline was built from `865b973`; its native image matches that
commit's **33,976-byte** image and SHA-256. Both sides use identical wolfSSL
5.9.4 archives, benchmark workloads, selector fix, ARMv4T `-Os` flags, emulator
binary, supplied Frankenpilot / Tungsten E3 session, and **100 MIPS** setting.
The benchmark PRCs differ only in `armc:1`. This comparison changes no workload,
diagnostic command, public API, CPU allowlist, or fallback path.

Five-sample medians:

| Operation | Comba baseline | Integrated product | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| Raw Montgomery square | 18.92 us | 12.82 us | 12.82 us | 32.3% |
| Native fixed-base affine multiply | 30 ms | 26.25 ms | 26.25 ms | 12.5% |
| Native general-point affine multiply | 87.5 ms | 75 ms | 75 ms | 14.3% |
| Native affine map | 5 ms | 3.44 ms | 3.44 ms | 31.3% |
| Native generator double-scalar operation | 72.5 ms | 60 ms | 60 ms | 17.2% |
| TLS 1.2/1.3 shared-secret calculation | 100 ms | 80 ms | 80 ms | 20.0% |
| TLS 1.2/1.3 complete ECDSA verification | 100 ms | 90 ms | 90 ms | 10.0% |

Both optimized runs reproduce these medians. Raw multiply and wide-reduction
medians remain 12.82 us and 9.16 us. Field measurements use the existing
128-operation chains and count each operation; native call/marshaling overhead
is amortized, not excluded. Integrated timings have 10 ms resolution: optimized
shared-secret and verification samples span 80–90 ms. These are emulator
instruction-budget measurements, not physical-device or network-handshake
performance. Other native workloads remain within timer quantization.

The simpler implementation is retained: the image shrinks **72 bytes**, from
33,976 to **33,904 bytes**. All existing ARM profiles and the benchmark contain
the same single ARMv4T image, SHA-256
`4c8e5b1840f1a1807324ebd307fd89872902df00d65586d0e9ba4a2792a2d743`.
No CPU-specific variant or additional ARM PRC is introduced.

Project/profile/package checks and independent crypto oracles pass, including
1,881 raw-field chains, 85 double-scalar cases, 69 inversions/maps, 64 scalar
products, 432 order preparations, 24 valid/tampered ECDSA cases and 168 AES-GCM
records. The extracted image passes on **TI925T and PXA270** CPU emulation,
including active instruction/data-address trace checks over 20 operand pairs
per field operation. Cloudpilot separately validates actual Palm OS native
calls, both self-test result sizes, ECDSA rejection cases and wolfSSL AES-GCM.
The trace checks preserve the selector fix's tested behavior; they do not
prove physical constant-time execution on every Palm processor.

Raw samples, manifests and both comparisons are saved under
[bench/baselines/2026-11-01-p256-square](bench/baselines/2026-11-01-p256-square).

## P-256 fixed-prime Montgomery reduction and field benchmarks

Both the integrated field multiply and the wide reducer used by squaring now
share `FeCancelP256Digit`. In radix `B=2^32`, the P-256 prime has limbs
`(B-1,B-1,B-1,0,0,0,1,B-1)`. The cancellation multiplier is the low limb
itself. Its first product cancels exactly; the remaining steps use the fixed
zero/unit limbs and `(m<<32)-m` for `m*(B-1)`. This removes the generic
prime-limb scan while preserving the existing Montgomery domain and final
conditional subtraction. Each accumulation fits an unsigned 64-bit word; loop
bounds and addresses do not depend on carries. Apple Clang still chooses
`UMLAL` for some all-ones products; this is portable C, not a new ISA backend.

The audit also caught an existing compiler transformation in `FeSelect`:
Clang replaced mask selection with a conditional pointer and loaded only one
operand. The selector now explicitly reads both operands through volatile
pointers before selecting their values. The final ARM assembly has two fixed
loads and a register selection. An instrumented negative check detects the
original address variation; the final build passes. This fix also preserves
both reads in the private point-table selector. The results below include its
cost, rather than reporting the reduction-only experiment as the final build.

Three new internal diagnostic operations exercise the actual shipped kernels.
Each call chains 128 dependent raw-residue multiplies, squares, or reductions.
The CSV counts all 128 operations, amortizing the native crossing and byte
marshaling. Final residues are checked against independent Node BigInt
arithmetic. These timings include the diagnostic loop and its overhead; they
are not bare instruction-cycle counts. Ordinary wolfSSL calls do not dispatch
these diagnostics, and the public Palm library trap ABI remains unchanged.

The baseline retains `3676d42` arithmetic/selection and adds the same diagnostic
command and workloads as the candidate. The saved `baseline-support.patch`
applies to that commit to reproduce the baseline source. Both builds use
wolfSSL 5.9.4 with the fast hex parser, Apple Clang's shared ARMv4T `-Os` target,
the same emulator binary/session, and **100 MIPS**. The benchmark PRCs differ
only in `armc:1`, so their measurement code is identical.

Five-sample medians from the supplied Frankenpilot / Tungsten E3 session:

| Operation | Baseline | Final | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| Raw Montgomery multiply | 17.70 us | 12.82 us | 12.82 us | 27.6% |
| Raw Montgomery square | 23.80 us | 18.92 us | 18.92 us | 20.5% |
| Raw wide reduction | 14.04 us | 9.16 us | 9.16 us | 34.8% |
| Native fixed-base affine multiply | 33.75 ms | 28.75 ms | 30 ms | 11.1–14.8% |
| Native general-point affine multiply | 105 ms | 87.5 ms | 87.5 ms | 16.7% |
| Native affine map | 6.25 ms | 5 ms | 5 ms | 20.0% |
| Native generator double-scalar operation | 90 ms | 72.5 ms | 72.5 ms | 19.4% |
| TLS 1.2/1.3 shared-secret calculation | 120 ms | 100 ms | 100 ms | 16.7% |
| TLS 1.2 complete ECDSA verification | 110 ms | 100 ms | 100 ms | 9.1% |
| TLS 1.3 complete ECDSA verification | 110 ms | 100 ms | 90 ms | 9.1–18.2% |

Integrated operation timings have 10 ms resolution: final verification
samples span 90–100 ms. The exclusive point phase moves from a 100 ms median
in this fresh baseline to 80 ms (70–80 ms in the repeat). Phase boundaries
and native batch sizes can shift results by one tick; use the raw samples
rather than interpreting sub-tick differences as physical speedups. Other
native algorithms remain within timer quantization. No physical-device or
network-handshake performance is established by these measurements.

The image grows from **33,848 to 33,976 bytes** (+128) for the reduction and
selector changes. Relative to `3676d42`'s 33,340 bytes, the total increase is
636 bytes, including the shared diagnostics. All existing ARM PRC profiles
and the benchmark carry the same single ARMv4T image, SHA-256
`237fa0f6a18472769e586debb5397e363da48bba3754124574281883dea42bc4`.
The CPU allowlist and 68K fallback are preserved; no CPU-specific PRC is added.

Project/profile/package checks pass. Python integer oracles check **1,881 raw
field chains**: zero, limb carry boundaries, values near `p`, random residues,
counts through 255, and wide inputs through `p*R-1`, with request alignment
0–3. Existing 85 double-scalar, 64 scalar-product, 69 inverse/map, 432 order
preparation, 24 valid/tampered ECDSA and 168 AES-GCM cases also pass on host C
and the extracted image on **TI925T and PXA270** CPU emulation. Native trace
checks compare both instruction and data-address sequences across 20 operand
pairs per operation with a fixed public count. Instrumentation flushes cached
translations and requires nonempty traces. These are execution/address checks,
not a proof of physical constant-time multiplication on every processor.
Cloudpilot separately exercises real Palm OS native calls, the original and
extended self-test ABI, ECDSA rejection vectors and wolfSSL AES-GCM checks.

Raw samples, build manifests, the baseline support patch and both comparisons
are in [bench/baselines/2026-11-01-p256-reduction](bench/baselines/2026-11-01-p256-reduction).
The suite now includes **22 native cases and 24 integrated engine/phase rows**;
[bench/README.md](bench/README.md#field-arithmetic-and-reduction-comparison)
defines the raw-field workloads and units.

## Public P-256 double-scalar generator table and mixed additions

The native verification operation `u1*G + u2*Q` now recognizes a generator
operand in either position and uses a generated affine table of **G, 3G, ...
15G** in Montgomery form. This avoids rebuilding that operand's odd-multiple
table on each call. Signed width-5 digits use a complete public-data mixed
addition routine, including equal/opposite and infinity cases. Other operands
retain the existing runtime Jacobian table and complete Jacobian addition.
The private-scalar comb path and constant-time selection remain unchanged.

A fresh baseline uses `a51a749` arithmetic with two added generator-specific
benchmark workloads. Its extracted native image has the same SHA-256 as the
committed **31,728-byte** image. Baseline and candidate share wolfSSL 5.9.4,
the fast hex parser, profiling, compiler/flags, emulator binary, ROM/session,
and **100 MIPS** setting. The benchmark PRCs differ only in `armc:1`; all
benchmark code and other resources are identical. The original `p256_mul2add`
case uses 3G and 5G, so retaining it alone would miss generator dispatch.

Five-sample medians from the supplied Frankenpilot / Tungsten E3 session:

| Operation | Baseline | Optimized | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| Native `u1*G + u2*(5G)` | 92.5 ms | 87.5 ms | 87.5 ms | 5.4% |
| Native `u1*(3G) + u2*G` | 92.5 ms | 85 ms | 85 ms | 8.1% |
| Native `u1*(3G) + u2*(5G)` | 92.5 ms | 92.5 ms | 92.5 ms | 0% |
| TLS 1.2 complete ECDSA verification | 120 ms | 110 ms | 110 ms | 8.3% |
| TLS 1.3 complete ECDSA verification | 120 ms | 110 ms | 110 ms | 8.3% |
| TLS 1.2/1.3 exclusive point phase | 100 ms | 90 ms | 90 ms | 10% |

Native generator cases use four operations per timed sample (2.5 ms effective
resolution). Full verification and its exclusive phases retain 10 ms clock
resolution: candidate verification samples are 110–120 ms, versus baseline
120 ms. Unrelated single-operation phase medians can move by one tick as phase
boundaries shift; these are not evidence of key-generation changes. Other
native workloads remain within timer quantization. These are instruction-
budgeted emulator results, not physical PXA270 cycle/cache measurements or
full network-handshake timings.

The native image grows to **33,340 bytes** (+1,612 / 5.1%), including the
512-byte affine table. It still fits one native resource. Full, modern and
TLS-1.3-only ARM PRCs, and the benchmark, contain exactly the same ARMv4T image
(SHA-256 `b12042281baa6eecf3472e0c5218a5222de2f7cf85620b01ed3b9cd5122e5cfd`).
There are no CPU-specific binaries or dispatch variants; the CPU allowlist,
byte-access request ABI and 68K fallback remain unchanged.

Project/profile/package checks pass. Independent Python affine arithmetic
checks **85 double-scalar cases**, covering every stored odd multiple, signed
digits, either generator operand, two generators, general points, zero scalars,
bit-256 carries, equal/opposite points, and recovery after intermediate
cancellation. Errors must preserve output. The tests run against host C and
the extracted image on both **TI925T and PXA270** CPU emulation, alongside
168 AES-GCM records, 69 inversions/maps, 64 scalar products, 432 order preparations
and 24 valid/tampered ECDSA cases with request alignment offsets 0–3. Cloudpilot
runs additionally pass real Palm OS native calls, both self-test result sizes,
and the integrated ECDSA/AES checks. Older physical Palm models are not booted
by these CPU tests; their instruction compatibility is checked separately.

Raw samples, manifests and both comparisons are in
[bench/baselines/2026-11-01-p256-mul2add](bench/baselines/2026-11-01-p256-mul2add).
The suite now has **19 native cases plus 24 integrated engine/verification
rows**. [bench/README.md](bench/README.md#generator-table-comparison) describes
the workload additions and baseline. Non-generator table normalization remains
a separate experiment: it would add an inversion whose cost must be measured
against the saved additions.

## 16-bit hex import, phase profiling, and wolfSSL 5.9.4

The dependency was pinned to wolfSSL **5.9.2** (`ac01707`). It is now pinned to
**5.9.4**, commit `3c5eead44904df64e6a5a1f4ebdce377d35a849a`, the latest
stable release listed by [wolfSSL](https://www.wolfssl.com/products/wolfssl/)
on November 1, 2026. Its [release notes](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable)
include certificate-verification fixes. The Palm patches were ported and applied
to the new tag; native AES dispatch now follows upstream's argument, tag-size
and key-state checks. The 16-bit hex fast path is still absent upstream.

`mp_read_radix(..., 16)` now packs four hex digits directly into each 16-bit
limb instead of multiplying/adding the accumulating integer for every digit.
It preserves sign, negative-zero normalization, mixed case, arbitrary leading
zeros, trailing whitespace, invalid-input and capacity handling. Other radices
and upstream's 32/64-bit paths retain their implementations. The same fast path
is compiled for both the 68K library and the 68K control layer in the ARM PRC.

The self-test exposes eight exclusive verification phases through an optional
188-byte result on the existing trap, while retaining the original 52-byte
caller ABI. The benchmark checks both sizes. Nested hex parsing is charged to
`hex`, and excluded from its `curve` / `range` parents. Phase entry counts
identify calls too short to occupy a tick. Each sample must have balanced
scopes and phase times summing exactly to its positive verification total.
Profiling is active only around that self-test call; normal TLS calls take
inactive checks without clock reads. DER-signature and changed-message rejection
checks remain outside the timer. Untimed wolfSSL AES-GCM known-answer,
authentication-failure and invalid-tag-size checks validate the upgraded bridge.

Five-sample medians, **100 MIPS cp-uarm**, same supplied Frankenpilot / Tungsten
E3 session, same 100 Hz clock and **31,728-byte ARMv4T native image**:

| Integrated wolfSSL operation | 5.9.4 generic hex | 5.9.4 fast hex | Less elapsed time |
| --- | ---: | ---: | ---: |
| TLS 1.2 ECDSA verification | 220 ms | 120 ms | 45.5% |
| TLS 1.3 ECDSA verification | 220 ms | 120 ms | 45.5% |
| TLS 1.2 public-key generation | 130 ms | 50 ms | 61.5% |
| TLS 1.3 public-key generation | 130 ms | 40 ms | 69.2% |
| TLS 1.2/1.3 shared-secret calculation | 160 ms | 120 ms | 25.0% |

A second five-sample optimized run reproduces every integrated median in this
table. Its hex phase medians swap between 0 and 10 ms across the two protocols,
consistent with 10 ms quantization.

Both comparison builds use the same 5.9.4 dependency patch stack and profiling.
`PALM_TLS_FAST_HEX=0` disables only the fast parser for the baseline; default
bootstrap restores it. The optimized runner additionally checks the legacy
self-test ABI; the optimized library adds the AES regression checks after
recorded ECC operations. These extra validations are outside reported timings.
The earlier unprofiled 5.9.2 library also measured 220 ms verification; it is
retained as an upgrade reference, not the parser-isolation baseline.

Before optimization, seven hex imports per verification account for a median
100–110 ms; afterward their combined measured time is 0–10 ms. Point arithmetic
accounts for about 100–110 ms and is now the dominant phase. A zero phase value
means below clock resolution, not free work. Individual phase medians need not
sum to the median total. Native primitive results remain unchanged within timer
quantization, as expected from the identical native image. All timings include
profiling overhead and are instruction-budgeted emulator results, not physical
PXA270 cache/pipeline measurements or complete TLS handshake timings.

All PRC profiles/package checks, 16,125 differential cases against the real TFM
generic parser with 16-bit limbs, profiler state tests and project checks pass.
The unchanged extracted native image passes independent crypto oracles on both
TI925T and PXA270 CPU emulation. Palm OS execution verifies the actual 16-bit
integer ABI, positive/tampered ECDSA signatures and the AES wrapper tests.
There is still **one ARM PRC per existing protocol profile**, with the same
CPU allowlist, ARMv4T baseline and 68K fallback. No CPU-specific variants were
introduced. These runs do not establish physical-device performance or exercise
network handshakes / full certificate chains.

Raw samples, version/build manifests and comparisons are in
[bench/baselines/2026-11-01-hex-import](bench/baselines/2026-11-01-hex-import).
Reproduction commands are in [bench/README.md](bench/README.md#hex-import-comparison-and-verification-profiles).
The next measured ECC target is the public double-scalar point operation;
separately profile native AES rounds if download throughput is the priority.

## ECDSA order arithmetic follow-up

The compatibility/GHASH/field-inversion work below was committed as
`4c8eb10`. A fresh, clean baseline from that commit was measured before
changing verification arithmetic. The updated library still uses **one
ARMv4T image and one ARM PRC per existing protocol profile**, with the same
CPU allowlist, 68K fallback, byte-safe request ABI and `-Os` default.

`s^-1 mod n`, `e*s^-1 mod n` and `r*s^-1 mod n` now execute together in one
native call. A binary extended-GCD inverse uses public signature data only;
three 8-limb Montgomery multiplications convert its result and produce the
normal-domain scalars. The reducer uses the group order's own constants,
not the field-prime constants. This path does not handle signing nonces or
private-key operations; the secret-scalar paths remain unchanged.

The final `x mod n` replaces generic division with a bounded 68K compare/copy
or subtraction, avoiding an extra native crossing. A 256-bit input is below
`2*n`, so at most one subtraction is necessary. The native bridge handles
wolfSSL's aliased digest/scalar buffers, rejects unsupported inputs before
writing output integers, and propagates native execution errors. The pinned
wolfSSL patch keeps DER parsing, hash truncation, signature range checks,
public-key handling and final comparison in their existing paths. Fault-check
builds (`WOLFSSL_CHECK_VER_FAULTS`) retain the old order-arithmetic path.

### Integrated benchmark

Same Apple Clang 21.0.0, ARMv4T/ARM7TDMI `-Os`, supplied Frankenpilot/E3
session, native `cp-uarm` binary, 100 MIPS setting and five samples per case:

| Case | Before | After | Change |
| --- | ---: | ---: | ---: |
| TLS 1.2 ECDSA verification | 300 ms | 220 ms | 26.7% less time |
| TLS 1.3 ECDSA verification | 300 ms | 220 ms | 26.7% less time |
| Native P-256 double-scalar operation | 92.5 ms | 92.5 ms | Unchanged |
| AES-GCM, 16 KiB encrypt/decrypt | 60 ms | 60 ms | Unchanged |
| Native image | 29,568 bytes | 31,728 bytes | +2,160 bytes / +7.3% |

A second independent run of the same optimized PRCs again measured 220 ms
for both verification phases in all five samples. Its raw results are saved
alongside the first run.

The verification rows time the complete positive wolfSSL verification call,
not just the native order command. They retain 10 ms Palm tick resolution.
Raw samples, manifests and comparisons are saved under
[bench/baselines/2026-11-01-ecdsa-order](bench/baselines/2026-11-01-ecdsa-order).
This does not establish an end-to-end network handshake speedup or physical
PXA270 timings; parsing/setup and other TLS work remain outside this change.

### Correctness and compatibility

The added native command passes 432 independent boundary/random inverse and
product cases, including every power-of-two denominator, `s=n-1`, maximum
digests, reduction at/above `n`, and all four alignment offsets. Eight invalid
signature-scalar pairs are rejected without touching output. Twenty-four
valid/tampered ECDSA math cases check scalar preparation followed by the
existing native double-scalar operation. Python big-integer and affine
arithmetic provide independent expected results.

These run on host C and the exact extracted ARM image under TI925T and PXA270
CPU models, alongside the existing AES-GCM/P-256 tests and negative ISA probe.
The startup KAT checks the new command with `e=2^256-1,r=n-1,s=2`; failure
disables native hooks. The real library self-test also rejects a changed hash
and changed DER signature after its timed positive vector. Fresh-source patch
application, all library profiles, native image attributes and project checks
pass. No processor-specific download or public library ABI change is required.

## Implemented: compatibility, GHASH and inversion

The current build keeps **one ARM implementation in one ARM PRC per existing
protocol profile**. Its native image targets **ARMv4T / ARM7TDMI**, covering
older TI925/ARM925T cores as well as ARM926EJ-S and XScale. The 68K loader checks
the SDK CPU model before making any native call; unknown/older models retain
the 68K implementation. The packager rejects compiler attributes requiring a
newer ISA or floating-point/coprocessor instructions. Self-tests are no longer
being used as a potentially unsafe instruction-set probe.

GHASH now operates on four 32-bit words. A direct four-bit polynomial reduction
replaces repeated byte shifts, and each native call decodes the existing
byte-oriented persistent table into aligned local words. The shared request
format and 512-byte chunk size are unchanged; unaligned requests remain safe.

Field inversion uses a fixed addition chain: **255 squarings and 12 field
multiplications**, replacing 256 and 128. The schedule is independent of the
field value and preserves zero and aliasing behavior. Its Go-derived schedule
is attributed in [THIRD_PARTY.md](../THIRD_PARTY.md), with the BSD license
included in binary artifact packages.

### Staged measurements

All three stages below use the **same ARMv4T target, `-Os`, Apple Clang 21.0.0,
100 MIPS emulator binary, supplied Frankenpilot/E3 session and five samples per
case**. This isolates arithmetic changes from the compatibility fix.

| Case | Compatible baseline | GHASH only | GHASH + inversion | Final reduction |
| --- | ---: | ---: | ---: | ---: |
| AES-GCM encrypt, 16 KiB | 280 ms | 60 ms | 60 ms | 78.6% |
| AES-GCM decrypt, 16 KiB | 280 ms | 60 ms | 60 ms | 78.6% |
| AES-GCM encrypt, 512 bytes | 9.375 ms | 2.109 ms | 2.109 ms | 77.5% |
| P-256 affine map | 8.438 ms | 8.438 ms | 6.250 ms | 25.9% |
| P-256 fixed-base, affine | 35.00 ms | 35.00 ms | 33.75 ms | 3.6% |
| P-256 general point, affine | 110 ms | 110 ms | 105 ms | 4.5% |
| P-256 double-scalar | 95.0 ms | 95.0 ms | 92.5 ms | 2.6% |
| Native image bytes | 29,028 | 29,360 | 29,568 | +540 bytes / +1.9% |

Large-record protection improves from about **57 to 267 KiB/s (4.67x)** in the
emulator. End-to-end HTTP/TLS throughput has not been measured. The public
TLS engine self-test phases remain around 130–140/160/300 ms for key generation,
shared secret and verification; most inversion savings are smaller than their
single-operation 10 ms tick granularity. Do not claim a precise handshake speedup
from those rows. Native cases batch operations to reduce timer quantization.

The compatibility-only stage is essentially unchanged from the original ARMv5TE
baseline at this measurement resolution. Raw samples, binary/compiler/session
hashes and staged comparisons are in
[bench/baselines/2026-11-01-armv4t](bench/baselines/2026-11-01-armv4t).

### Validation and limits

The host and the exact extracted ARM image pass independent oracles for
**168 AES-GCM encrypt/decrypt records, 69 inversions/maps, 64 fixed/general
scalar products and eight double-scalar products**, plus zero/infinity cases.
Tests cover partial blocks, chunk boundaries, AAD lengths through 516 bytes,
random keys/nonces/points and request alignment offsets 0–3. AES answers come
from Node/OpenSSL; P-256 answers use independent Python integer/affine arithmetic.

The same native image passes on Unicorn's **TI925T and PXA270 CPU models**.
A negative instruction probe verifies that `CLZ` traps on TI925T and executes on
PXA270. All library profiles/package checks, CPU allowlist tests, ISA rejection
tests and project checks pass. Cloudpilot runs separately validate real
`PceNativeCall` and TLS 1.2/1.3 engine self-tests. The generated benchmark and
library contain the same single native image.

CPU-model execution validates instruction compatibility and results; it is not
a full Palm OS test on an older TI device. Physical Palm measurements remain
necessary for real cache/pipeline/memory behavior. The release default stays
`-Os`; no processor-specific backend, new public ABI or extra CPU PRC was added.

The next useful experiments after that stage were AES-round profiling, ECDSA's
68K order arithmetic (now implemented above), and measured architecture-crossing/copy costs. These should retain
the ARMv4T baseline and be evaluated individually with the same suite.

## Historical review before these changes

The sections below record the initial ARMv5TE review and compiler experiment.
Its GHASH and inversion recommendations have now been implemented above.

The hybrid boundary is already in the right place for P-256 point operations,
SHA-256 compression and AES-GCM records. Another broad native port should wait
until measurements identify the remaining costs. The added benchmark suite
provides that baseline and already demonstrates a useful compiler tradeoff.

## Measured baseline and compiler experiment

These are five-sample medians from native `cp-uarm` at **100 MIPS**, using the
same supplied `session_os5.img` and emulator binary. This session reports
**Dmitry's Frankenpilot / Tungsten E3, January 12, 2025 ROM**. These are not
the older stock E2 measurements in `ARM.md`. Native code was built with
**Apple Clang 21.0.0 (clang-2100.4.1.1)**, targeting ARMv5TE / ARM926EJ-S.
The only native-code change in this experiment is `-Os` versus `-O2`.

| Case | `-Os` | `-O2` | Less elapsed time |
| --- | ---: | ---: | ---: |
| P-256 fixed-base, affine | 36.25 ms | 20.63 ms | 43.1% |
| P-256 general point, affine | 110 ms | 62.5 ms | 43.2% |
| P-256 Jacobian-to-affine map | 8.44 ms | 5.47 ms | 35.2% |
| P-256 public double-scalar operation | 95 ms | 55 ms | 42.1% |
| SHA-256, eight compression blocks | 332 us | 303 us | 8.8% |
| AES-GCM, 16 KiB encrypt | 280 ms | 240 ms | 14.3% |
| AES-GCM, 16 KiB decrypt | 280 ms | 240 ms | 14.3% |
| TLS 1.2/1.3 shared-secret self-test | 160 ms | 120 ms | 25.0% |
| TLS 1.2/1.3 ECDSA verification self-test | 300 ms | 260 ms | 13.3% |

Native image size increases from **28,944 to 59,104 bytes** (+104%). Keep
`-Os` as the default for now: `-O2` offers real improvements in this emulator,
but consumes most of the single-resource size budget and has not been measured
on physical hardware. The complete raw samples and manifests are in
[bench/baselines/2026-11-01](bench/baselines/2026-11-01).

The benchmark app uses real `PceNativeCall` transitions, checks outputs after
every batch and stops on any error. The engine rows call the existing public
library self-test, including wolfSSL and the production bridge. Engine rows
retain the existing single-operation Palm tick quantization; the native rows
batch operations to improve resolution. The emulator is instruction-budgeted,
not a model of physical caches, memory wait states or pipeline timing.

## Findings and recommended order

1. **Compiler experiments previously could silently use stale native code.**
   [`library/Makefile`](Makefile) did not make `armlet.o` depend on
   `ARM_OPT_FLAGS`, `ARM_CPU_FLAGS`, or compiler selection. Changing a flag could
   leave the prior image in place. This is fixed with a content-sensitive build
   configuration stamp, plus a Makefile dependency. Benchmark runs freeze copies
   of both PRCs before installation and verify that they contain identical ARM
   images, so later builds cannot change an in-progress run's inputs.

2. **Record protection is a strong target for download throughput.**
   [`GhashBlock`](arm/multiply.c) performs 32 nibble steps per 16-byte block;
   each step shifts a 16-byte accumulator four times before a table XOR. AES
   also uses byte-oriented rounds. The baseline sustains about **57 KiB/s** on
   16 KiB records in both directions. Profile GHASH and AES separately next;
   test a word-oriented GHASH accumulator/reduction and measure the native
   call/copy costs before enlarging the exchange buffer. A 16 KiB record
   currently requires 34 calls: START, 32 UPDATEs, FINAL. The benchmark already
   models that schedule and input/output copies. It does not establish which
   share of the measured record time belongs to GHASH versus AES.

3. **ECDSA still has substantial work outside native point multiplication.**
   The pinned wolfSSL `ecc_verify_hash` computes `s^-1 mod n`, `e*w mod n`, and
   `r*w mod n` before the hook added by
   [`wolfssl-palm-armlet-math.patch`](../patches/wolfssl/wolfssl-palm-armlet-math.patch).
   Those operations retain 68K control/reduction/inversion, although the generic
   multiplication hook may accelerate individual products. Measure these stages
   and their crossing counts before moving complete order arithmetic or full
   verification native. The native double-scalar case is 95 ms versus a 300 ms
   full verification self-test at `-Os`; the inputs differ, so this gap is a
   profiling lead, not a precise subtraction of overhead. Include RSA chain
   verification in network-backed measurements: this suite does not cover it.

4. **Field inversion is a bounded optimization with broad P-256 benefit.**
   [`FeInverse`](arm/multiply.c) performs 256 squarings and 128 multiplications
   for the fixed public exponent `p-2`. Replace it experimentally with a verified
   fixed addition chain. Keep the schedule independent of secret values and
   retain mapped/unmapped, general-point and verification tests. Mapping alone
   costs about 8.44 ms; fixed-base raw multiplication costs 27.5 ms, so mapping
   is roughly one quarter of the measured mapped fixed-base operation. This
   puts a practical upper bound on its end-to-end benefit.

5. **Separate cold startup from steady-state work.**
   [`LoadEngine`](src/tls_loader.c) times resource allocation/relocation **and**
   engine initialization, ARM known-answer tests and key decoding. Its `loadTicks`
   is not pure loader overhead. Protocol switching in the self-test deliberately
   reloads engines; real repeated requests can reuse the existing engine and
   session cache. Keep cold load, warm handshake, resumed handshake and transfer
   timings separate. Certificate parsing, RSA, networking and output storage
   remain candidates only after real-request phase measurements identify them.

## Benchmark coverage and validation

The suite measures 17 native workloads: two multiplication sizes; fixed/general
P-256, raw output, mapping and double-scalar addition; one/eight-block SHA-256;
and four AES-GCM record sizes in each direction. Palm runs additionally record
eight engine phases for each of five self-test samples when a full or modern
ARM library is installed. AES-GCM expected outputs come from Node's independent
OpenSSL implementation. All large benchmark buffers live on Palm's heap.

Both historical compiler variants built and passed all library profile/PRC checks and the
existing native math tests. Both benchmark PRCs completed successfully in the
emulator, including TLS 1.2/1.3 self-tests. The project checks, host benchmark
and benchmark-tooling tests also passed. At that initial benchmarking stage,
no cryptographic algorithm or public library ABI was changed.

See [bench/README.md](bench/README.md) for commands, methodology, CSV comparison
and physical-device instructions. Next experiments should change one kernel at
a time, retain the raw samples and source diff, and confirm promising changes
on an ARM Palm before selecting release defaults.
