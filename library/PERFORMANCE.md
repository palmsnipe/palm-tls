# ARM performance review — November 1, 2026

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
