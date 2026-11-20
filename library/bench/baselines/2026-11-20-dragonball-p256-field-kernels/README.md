# Public P-256 field multiplication and squaring on the Palm m515

The baseline is commit `399a550`, which profiles the native signature path
and optimizes its doubling and peer-table setup. The candidate changes the
public field multiplication and squaring kernels. Both builds ran five cold
and five warm X25519 TLS 1.3 handshakes at each speed on the same Palm OS 4.1
m515 CloudpilotEmu session. The benchmark app, AES-128-GCM fixture, P-256
ECDSA certificate, and trust store were identical across runs. Server logs
confirm a single ClientHello and X25519 in every comparison. The handshake
clock starts after TCP setup and the benchmark reports engine load separately.
[Previous signature profile](../2026-11-20-dragonball-signature-profile)

## Results

| CPU speed | Full handshake | Baseline | Candidate | Signature before → after |
|---|---|---:|---:|---:|
| Stock (1×) | Cold | 14.820 s | 14.050 s | 7.420 → 6.650 s |
| Stock (1×) | Warm | 14.590 s | 13.790 s | 7.430 → 6.620 s |
| 16× | Cold | 920 ms | 870 ms | 460 → 420 ms |
| 16× | Warm | 910 ms | 860 ms | 460 → 410 ms |

Values are medians of five samples. The warm signature phase took 10.9%
less time at both speeds. The full warm handshake took 5.5% less time,
saving 800 ms at stock speed and 50 ms at 16×. Each handshake ran the
native P-256 verifier twice. At stock speed, the warm doubling median
fell from 4.810 s to 4.270 s and point additions fell from 1.830 s to
1.590 s. Cold engine load measured 340 ms for both stock runs and
20 ms versus 30 ms at 16×, where one Palm tick is 10 ms.

[Handshake summary](summary.csv) · [Signature phases](signature.csv) ·
[Stock baseline](1x/baseline/results.csv) · [Stock candidate](1x/candidate/results.csv) ·
[16× baseline](16x/baseline/results.csv) · [16× candidate](16x/candidate/results.csv) ·
[Build and session hashes](metadata.json)

## Arithmetic

The public kernels use one Karatsuba split into two eight-limb halves.
Three unrolled half products replace the full-width Comba product. Squaring
also sums the off-diagonal terms before doubling them once per column.
Multiplication uses 192 word products per operation, down from 256.
Squaring uses 108, down from 136. Both assemble the exact product before
the existing Montgomery reducer. The private field routines keep their
fixed arithmetic schedules. [GMP manual, Karatsuba multiplication](https://gmplib.org/gmp-man-5.1.0.pdf)

The full 68K PRC grew by 3,692 bytes, from 667,671 to 671,363 bytes.
Every Palm code resource passed validation. The linked 68000 field
oracle checked 897 products, squares, aliasing cases, and edge values.
It also counted instructions for each kernel over 32 identical inputs.

| Public operation | Baseline median instructions | Candidate median instructions | Reduction |
|---|---:|---:|---:|
| Multiply | 3,371 | 2,967.5 | 12.0% |
| Square | 3,295.5 | 2,725.5 | 17.3% |

These instruction counts use Unicorn on the linked 68K functions. The
handshake and signature latencies use Palm clock ticks on CloudpilotEmu.
[Instruction samples summary](field-instructions.csv)

`make check` passed, along with the linked ECDSA verification, P-256
fixed-base, and P-256 variable-base oracles. The secret-scalar instruction
and data-address trace comparisons passed for both P-256 key paths.

[Handshake reproduction commands](../../README.md#dragonball-tls-13-handshakes)
