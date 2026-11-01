# ARM performance benchmarks

Run from the repository root. The host and Palm runners use the same workload
and byte-level ARMlet ABI. No network is required.

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
