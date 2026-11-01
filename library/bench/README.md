# ARM performance benchmarks

Run from the repository root. The host and Palm runners use the same workload
and byte-level ARMlet ABI. The primitive suite below requires no network.
The separate TLS handshake suite uses a local server.

```sh
make -C library benchmark
cat library/build/bench/host-summary.csv
make -C library/bench test
```

The host runner compiles `arm/multiply.c` for the host at `-O2`. It is useful
for quick experiments and correctness checks. Its timings do **not** predict
ARM performance, ARM instruction counts, PACE costs, or Palm memory costs.
`HOST_CC` and `HOST_OPT_FLAGS` select its compiler and optimization level.

Build the Palm benchmark app with the existing Palm toolchain and Clang:

```sh
make -C library benchmark-palm test
```

This produces `library/build/bench/PalmTLSBench.prc`. It contains the exact
native image built for the library, checks its content and word alignment,
and executes it with real `PceNativeCall` transitions. Its creator is `Tbch`,
separate from TLS Tester and PalmTLS. It overwrites only its own
`PalmTLS Bench Results` database on each launch. Large scratch buffers are
allocated on the heap.

## Full and resumed TLS 1.3 handshakes

This suite measures actual TLS connections through the public PalmTLS session
API, separately from the offline ECDH/ECDSA self-test. It launches a local
OpenSSL-backed Python server and Cloudpilot with native networking, builds an
application with the matching public CA fixture, and runs two fresh private
copies of the supplied session:

```sh
python3 library/bench/run-handshake.py \
  --emulator /Users/cyril/projects/cloudpilot-emu/src/uarm/cp-uarm \
  --session /Users/cyril/projects/cloudpilot-emu/web/embedded/public/session_os5.img \
  --server-python /opt/homebrew/bin/python3.12 \
  --port 22443 --runs 2 --mips 100 \
  --output library/build/bench/tls13-new-comparison
```

Use a new output directory and a Python whose `ssl.HAS_TLSv1_3` is true; macOS's
system LibreSSL Python may lack TLS 1.3. The fixture generator also needs the
`openssl` executable. Three consecutive loopback ports must be free: TLS 1.3,
a delayed TLS 1.3 endpoint for cooperative tests, and a TLS 1.2 regression
endpoint. No external server or DNS is involved. Fixture certificates cover
2020–2040 to accommodate the supplied Palm clock without changing it.

Each run contains five samples of six cases: cold full, warm full, and resumed
handshakes, each with context reuse disabled/enabled. Both modes use the same
PRC and opt-in profiling. Cold cases purge the engine/cache first; warm full
cases deliberately omit `ALLOW_RESUME`; resumed cases require actual ticket
reuse. The default trust corpus has eight P-256 roots (4,560 PEM bytes), with
a P-256 leaf signed by one root. Connections negotiate TLS 1.3,
P-256, and `TLS_AES_128_GCM_SHA256`. The application reads post-handshake
tickets before closing. `load_ticks` is separate from `handshake_ticks`, whose
boundary includes context/trust setup and key-share generation. Socket setup
is excluded. The 100 Hz Palm clock gives 10 ms resolution.

`results.csv` contains 30 timed rows and 780 exclusive phase rows in comments,
covering handshake and post-handshake periods. Validation requires complete,
balanced profiles, expected context/session reuse, tickets, and signature work
on full handshakes. The independently saved server log must confirm 20 full
and 10 resumed TLS 1.3 connections. Six additional regression groups check
owned/exact trust identity, hostname/verification-mode changes and bad CAs,
purge, opening cancellation, interleaved session isolation, and TLS 1.2
full/resumed connections. Failed regressions fail the run.

```sh
python3 library/bench/handshake_results.py \
  library/build/bench/tls13-new-comparison/run/results.csv \
  --server-log library/build/bench/tls13-new-comparison/run/server-connections.jsonl
```

The driver saves PRC hashes, emulator/session hashes, server configuration,
raw results, server logs, and summaries. It verifies that the fixture's public
trust bytes are embedded in the application before booting. Development-only
private keys remain in the ignored build fixture directory; archive only the
public measurements/metadata. Never archive private keys, SDKs, or ROM/session
images. Final repeated measurements are in
[`baselines/2026-11-01-tls13-context`](baselines/2026-11-01-tls13-context).
These local emulator measurements include profiling overhead and do not
establish physical-device or Internet handshake latency.

### ECDHE mixed-coordinate comparison

The current handshake app requests the optional 288-byte ECDHE profile and
adds 150 `# ecdhe` rows (five exclusive phases × 30 samples). It requires a
complete detail whose sum exactly matches each key-agreement phase. The reader
still accepts earlier results without this extension. The five phases separate
remaining setup/export, import, validation, scalar multiplication, and mapping;
zero ticks retain entry counts at the Palm clock's 10 ms resolution.

For arithmetic comparisons, reuse the *same* fixture so trust bytes, leaf
certificate, ports, and benchmark application code remain identical:

```sh
# After running a baseline with the command above, build the candidate, then:
python3 library/bench/run-handshake.py \
  --emulator /Users/cyril/projects/cloudpilot-emu/src/uarm/cp-uarm \
  --session /Users/cyril/projects/cloudpilot-emu/web/embedded/public/session_os5.img \
  --server-python /opt/homebrew/bin/python3.12 \
  --port 22443 --runs 2 --mips 100 \
  --reuse-fixture library/build/bench/tls13-new-comparison/fixture \
  --output library/build/bench/tls13-candidate
```

The driver copies development fixtures only into the ignored build directory,
requires matching port/anchor count, resets connection logs, and waits for a
new readiness marker written after all three listeners bind. The application
still verifies the embedded trust bytes against the live fixture. TLS keys
and signatures remain fresh per connection.

[`baselines/2026-11-01-ecdhe-mixed`](baselines/2026-11-01-ecdhe-mixed) contains
two runs per handshake configuration, native primitive comparisons, and a
support patch for the instrumented `6adbf09` baseline. Baseline/candidate PRCs
differ only in `armc:1`; the profile and workload code is identical. The native
`p256_general_affine` case batches four operations per sample, giving finer
per-operation resolution than individual handshakes. Preserve the raw tick
samples; a 10 ms handshake difference should not be presented as a precise
sub-tick physical-device speedup.

### Native public-key validation comparison

[`baselines/2026-11-01-p256-validation`](baselines/2026-11-01-p256-validation)
compares the unchanged `feaadb3` baseline with native validation. Use the same
handshake commands and `--reuse-fixture` workflow above. Both sides have the
same profiler and application code; the final library adds native hooks and
stronger startup qualification. There is no diagnostic option that disables
validation. Baseline and candidate both perform all verification checks.

The 288-byte detail retains nonzero validation entry counts even when its
phase is shorter than one tick. Compare full/resumed handshake times separately
from engine load: the stronger startup self-test increases cold loading by
about 20 ms in this run. Raw measurements, repeated runs, server confirmations,
and an offline self-test ABI regression are archived. Development fixture keys
remain only in ignored build directories.

### Cold startup and public CA PEM comparison

The current handshake app requests the optional 400-byte result and adds
`# load` and `# trust` comments: **210 loader rows and 150 trust rows** per
30-connection run, in addition to the earlier phases. Loader details must sum
to each open's `load_ticks`; trust details must sum to the main Trust phase.
Warm sessions must have no loader calls. Earlier result files remain readable.

[`baselines/2026-11-01-startup`](baselines/2026-11-01-startup) includes a patch
adding identical profiling/workloads to `995460c` for the baseline. Both builds
use the exact same eight-root fixture through `--reuse-fixture`. All startup
checks remain enabled. Compare paired `load_ticks + handshake_ticks` samples
for cold totals, rather than adding separately calculated medians. The final
report also records older 240/288-byte profile and 52/188-byte self-test apps
running against the final library.

The measured changes accelerate public CA PEM decoding, relocation, and
startup test-vector reset. Existing parsed-context caching stays enabled.
Serialized certificate-cache persistence remains disabled because the upstream
format omits signer policy fields. No CA is removed and no certificate check
is skipped to obtain the measurements. Private fixture keys, PRCs, SDKs and
session/ROM images stay out of the archived data.

## Repeatable emulator runs

Use a supplied, already initialized OS 5 session. The runner copies it into a
new output directory, freezes copies of the input PRCs, waits for readiness,
installs and launches the benchmark,
observes completion through LCD screenshots, and only then exports databases.
It does not execute CLI-injected Palm OS calls during timed samples. It saves
raw CSV, emulator logs, a completion screenshot, and a metadata manifest with
session, emulator, application and library hashes, Git revision/dirty status,
MIPS setting, and local ARM build flags. The native CLI opens a desktop window.
The runner rejects a benchmark/library pair containing different native images.
Python 3.9+ and Node.js are sufficient; no additional Python packages are needed.

```sh
python3 library/bench/run-emulator.py \
  --emulator /Users/cyril/projects/cloudpilot-emu/src/uarm/cp-uarm \
  --session /Users/cyril/projects/cloudpilot-emu/web/embedded/public/session_os5.img \
  --library library/build/palm/PalmTLSArm.prc \
  --mips 100 --output library/build/bench/baseline

python3 library/bench/results.py library/build/bench/baseline/results.csv
```

The session above currently identifies itself as Dmitry's Frankenpilot / E3
with a January 12, 2025 ROM, rather than the stock E2 used for the older
handshake timings in `ARM.md`. Use the **same session and emulator binary**
for comparisons; check the device/ROM identification in `emulator.log`.
Do not compare those older numbers directly with this session.

For example, compare compiler settings before changing arithmetic:

```sh
make -C library ARM_OPT_FLAGS=-O2 benchmark-palm test
python3 library/bench/run-emulator.py \
  --emulator /Users/cyril/projects/cloudpilot-emu/src/uarm/cp-uarm \
  --session /Users/cyril/projects/cloudpilot-emu/web/embedded/public/session_os5.img \
  --library library/build/palm/PalmTLSArm.prc \
  --mips 100 --output library/build/bench/candidate

python3 library/bench/results.py library/build/bench/candidate/results.csv \
  --baseline library/build/bench/baseline/results.csv

# Restore the normal build afterward.
make -C library ARM_OPT_FLAGS=-Os benchmark-palm test
```

Changing ARM compiler, CPU flags, or optimization flags now invalidates the
ARM object automatically. Build the benchmark **and** library with the same
settings before each run. Keep source changes/patches with the metadata: a
Git revision plus a dirty flag is not a complete source snapshot.

The comparison reports median/minimum/maximum microseconds per operation,
KiB/s where applicable, and percentage change in elapsed time (negative is
faster). It rejects missing cases, incomplete/duplicate samples, incompatible
workload/frequency pairs, and mismatched emulator/session/device/MIPS metadata
when both input directories contain manifests. Use raw `results.csv` inputs
for comparisons so their manifests can be found. If comparing standalone CSVs,
the caller must ensure matching hardware, ROM, compiler, workload and clock
settings. Host and Palm clocks have different frequencies and cannot be mixed.

Current measurements of the ARMv4T compatibility baseline, word-oriented GHASH,
and the combined GHASH/inversion changes are saved under
[`baselines/2026-11-01-armv4t`](baselines/2026-11-01-armv4t). Compare the final
candidate with the compatible, otherwise unchanged baseline using:

```sh
python3 library/bench/results.py \
  library/bench/baselines/2026-11-01-armv4t/optimized/results.csv \
  --baseline library/bench/baselines/2026-11-01-armv4t/compat/results.csv
```

All current ARM builds use the shared ARMv4T integer baseline. The packager
rejects newer CPU instruction attributes even if introduced by `ARM_CPU_FLAGS`.
The earlier `baselines/2026-11-01/os` and `o2` files are historical ARMv5TE
compiler experiments and do not establish compatibility with older devices.

The next ECDSA order-arithmetic measurements are under
[`baselines/2026-11-01-ecdsa-order`](baselines/2026-11-01-ecdsa-order). They use
the same 17 primitive workloads and eight real library phases; the
`tls12_verify` and `tls13_verify` rows measure the complete positive wolfSSL
verification call, including DER parsing, scalar preparation, point math and
final comparison. The order offload is measured through those integrated
rows rather than an isolated native microbenchmark. Modified-message and
modified-signature checks run afterward, outside the recorded positive timing.

## Squaring through multiplication

The `FeMultiply(a, a)` squaring comparison is saved under
[`baselines/2026-11-01-p256-square`](baselines/2026-11-01-p256-square).
The clean `865b973` baseline uses the Comba squarer; the candidate changes
`FeSquare` to use the integrated multiplier and removes the unused Comba
helper. Both retain the selector fix and exactly the same 46 benchmark cases.
No benchmark-support patch or configuration switch is needed for this baseline.
The `p256_field_square` row measures 128 dependent in-place operations per
native call, while integrated ECDH/ECDSA rows check whether that kernel change
improves the real library operations. Both optimized runs use the same native
image in the benchmark and every existing ARM library profile.

## Field-arithmetic and reduction comparison

The suite adds `p256_field_multiply`, `p256_field_square` and
`p256_field_reduce`, bringing the native workload count to 22. Each diagnostic
native call chains **128 dependent operations** through the real field kernels.
The CSV `iterations` field counts field operations, including those 128 steps,
so reported microseconds are per field operation. Native crossings, raw-byte
marshaling and the small chain loop remain included, amortized over 128 steps.
All three cases must be present if any is present; older saved suites remain
readable. The benchmark verifies full final residues with independent Node
BigInt arithmetic.

Inputs and outputs are raw big-endian residues: no conversion is timed.
With `R=2^256`, multiply chains `a <- a*b/R mod p`, square chains
`a <- a*a/R mod p`, and reduction chains `a <- (b*R+a)/R mod p`, where division
means modular multiplication by `R^-1`. The reduction high half satisfies
`b<p`, guaranteeing the required `T<p*R` bound. Every result feeds the next
iteration so redundant calls cannot be removed by the compiler.

The internal `P256_FIELD` command is available in the same native image as the
library; no separate benchmark-only image or CPU-specific PRC is built. Its
public operation/count fields are validated, and invalid inputs preserve the
output. Ordinary wolfSSL operations do not dispatch this diagnostic command.

Measurements are saved under
[`baselines/2026-11-01-p256-reduction`](baselines/2026-11-01-p256-reduction).
Both comparison builds include these diagnostics and identical benchmark code.
Apply the saved `baseline-support.patch` to `3676d42` to reproduce the baseline
source, then run `make -C library benchmark-palm test`. The baseline retains
that commit's field arithmetic and selection. The candidate
specializes both reducers and ensures the selector always reads both operands.
The same emulator/session/build settings are captured in each manifest.

## Generator-table comparison

The double-scalar suite includes the original two-general-point
`p256_mul2add` case plus `p256_mul2add_generator` (`u1*G + u2*(5G)`) and
`p256_mul2add_generator_right` (`u1*(3G) + u2*G`). All use the same fixed 256-bit public
scalars, with full affine outputs checked against independent Python arithmetic.
The generator cases exercise both operand positions and their precomputed
affine table; the original case checks the general Jacobian path. Historical
runs have 17 primitive cases; that comparison has 19, and the field suite above
adds three more. Comparisons require the
same case sets; the CSV validator accepts older runs but requires both new
generator cases if either is present.

Measurements of the generator-table/mixed-addition change are under
[`baselines/2026-11-01-p256-mul2add`](baselines/2026-11-01-p256-mul2add).
The baseline uses `a51a749` native arithmetic with the extended benchmark
workloads; its extracted native image is identical to that commit's image.
The candidate changes only the benchmark's `armc:1` resource. The public
generator-table optimization does not change the private-scalar comb path.

## Native CPU compatibility tests

`make -C library test` checks the CPU allowlist, positive/negative native
packaging cases, and deterministic crypto cases against Node/OpenSSL AES-GCM
and Python big-integer P-256 oracles. It covers full outputs and tags, partial
blocks, AAD lengths 0..516, streaming boundaries, zero/infinity cases, and
request addresses with alignment offsets 0..3.

Order tests additionally compare 432 boundary/random scalar preparations with
Python's modular inverse/products, reject out-of-range `r,s`, and check 24
valid/tampered ECDSA math cases. These include every power-of-two denominator,
digests at/above `n`, maximum 256-bit inputs, and unaligned request addresses.

The independent double-scalar oracle now covers 85 cases: each positive and
negative width-5 generator-table digit, generator operands on either side,
two-generator and two-general-point combinations, equal/opposite points,
zero scalars, bit-256 carries, infinity/error results, and recovery after an
intermediate cancellation. These run against both host C and the extracted
native image, including request addresses with alignment offsets 0–3.

Raw field tests add 1,881 chains against Python integer arithmetic, including
carry-heavy residues, powers-of-two limb edges, values near `p`, random inputs,
counts through 255, and reduction inputs up to `p*R-1`. Native trace tests flush
Unicorn's translated-code cache before adding instrumentation and require
nonempty instruction and data-address traces. For each operation, 20 different
valid operand pairs with the same public count must produce identical traces.
The original selector fails this check; the fixed selector passes on both CPU
models. These checks do not establish physical multiply timing or formal
constant-time behavior on every Palm CPU.

Optional instruction emulation runs the same extracted native image on both
TI925T and PXA270 CPU models. This also checks that an ARMv5 `CLZ` probe traps
on TI925T and succeeds on PXA270, so a permissive CPU model cannot mask the
original compatibility problem:

```sh
python3 -m venv library/build/arm-test-venv
library/build/arm-test-venv/bin/pip install -r library/tests/requirements-arm.txt
make -C library test-arm \
  ARM_TEST_PYTHON="$PWD/library/build/arm-test-venv/bin/python"
```

These CPU tests validate instruction execution, relocation and native results;
they do not boot Palm OS or measure hardware performance. The supplied
Cloudpilot session separately checks real `PceNativeCall` and library engines.

On a physical ARM Palm, install and launch the benchmark, wait for
`Done: results saved`, then back up the results PDB. There is no network
setup. For manual CLI use, `db-export /absolute/path/results.zip` after
completion produces a ZIP understood by:

```sh
python3 library/bench/results.py /absolute/path/results.zip \
  --extract library/build/bench/device.csv
```

## What is measured

Each native case has one checked warmup, adaptive calibration towards 200 ms
on Palm / 50 ms on the host, and five samples at a fixed iteration count.
Calibration stops at 32,768 iterations; very fast cases can therefore have
shorter batches. Timings use unsigned monotonic-clock subtraction and Palm's
reported tick frequency. Request preparation, validation, CSV formatting,
database writes, screenshots, and calibration are outside reported samples.
Return status is checked on every native call; final output is checked after
every batch. A failed case stops the suite and cannot produce a complete report.

| Workload | Measurement and validation |
| --- | --- |
| 256/2048-bit multiplication | Carry-heavy all-ones operands; full product checked against `(2^n - 1)^2`. |
| P-256 fixed/general affine | Dense deterministic scalar; known affine answers. |
| P-256 fixed raw | Same scalar, returning Montgomery/Jacobian coordinates; validated by mapping outside the timer. |
| P-256 map | Precomputed nontrivial Jacobian point; inversion plus affine conversion only. |
| P-256 mul2add | Two dense public scalars and different points, including a width-5 carry; known affine answer. |
| SHA-256 1/8 blocks | Pre-marshalled compression input, one call per operation; `abc` and 512 zero bytes checked with final padding. |
| AES-GCM encrypt/decrypt | 16/512/4096/16384-byte records, 13-byte AAD, zero key and nonce; START, 512-byte UPDATE chunks, FINAL and input/output copies included. |

AES-GCM rebuilds the key schedule and GHASH table once per record, matching
the production bridge. Its full tag and final output chunk checksum are checked
against Node's independent OpenSSL implementation. Each direction deliberately
uses all-zero input; decrypt therefore returns the CTR keystream and its tag
is checked against an independent encryption of that keystream. These are
synthetic benchmark vectors, not keys/nonces for real traffic. Tag comparison
and the entire wolfSSL/PalmTLS bridge are outside this primitive measurement.
SHA-256 throughput counts bytes compressed, including the padded block in the
one-block case, not application payload throughput.

When a full or modern ARM PalmTLS library is installed, the app also records
five calls to the existing public `PalmTlsLibRunSelfTest` API: TLS 1.2/1.3
load, key generation, shared secret, and ECDSA verification. Protocol switching
forces engine loads; those load values include initialization/native self-tests
and are recorded separately. These rows
include the real wolfSSL hooks and marshalling, unlike the native microbenchmarks.
They retain the existing self-test's single-operation 10 ms tick quantization
on a 100 Hz device. Missing/compact profiles are explicitly identified in CSV
comments; a failing installed engine fails the run.

This suite excludes DNS, TCP, certificate-chain parsing and verification,
handshake messages, resumption, HTTP parsing and destination I/O. Use TLS
Tester's request phase timings on a network-capable device for those costs.
The emulator's 100 MIPS model measures an instruction-budgeted guest, not
cycle-accurate ARM hardware or physical memory/cache timing. Confirm promising
changes on a real device before changing release defaults.

## Hex import comparison and verification profiles

The dependency is pinned to wolfSSL 5.9.4 in `config/sources.lock`. To isolate
the 16-bit hex parser change, build both sides from this same source and patch
stack. `PALM_TLS_FAST_HEX=0 JOBS=8 scripts/bootstrap.sh` selects the generic
parser; `JOBS=8 scripts/bootstrap.sh` restores the default fast parser. Rebuild
the library with `make -C library benchmark-palm test` and run the emulator
command above into a different output directory after each bootstrap. This
switch changes the dependency fingerprint and rebuilds all six archives.
The manifest captures version, commit, parser setting and dependency fingerprint.

When the library advertises `PALM_TLS_CAP_VERIFY_PROFILE`, 16 additional
`tls12_verify_phase_*` / `tls13_verify_phase_*` rows partition the existing
positive verification totals. The eight phases are `other`, `signature`,
`range`, `curve`, `hex`, `order`, `point` and `final`. They are exclusive,
including nested curve loads inside range checks and hex imports inside curve
loads. Per-sample `# profile_calls` comments record entry counts. The app and
CSV checker require complete profiles whose phase times sum to each total.
Sub-tick phase values may be zero; native primitive timings must remain positive.
Compare profiled baseline and candidate together: instrumentation overhead and
100 Hz quantization prevent treating these as precise hardware cycle counts.
