# ARM performance review — November 1, 2026

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
