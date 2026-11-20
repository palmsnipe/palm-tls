# P-256 signature verification profile on the Palm m515

The profile baseline uses the verifier from `095b589` with the new
signature instrumentation. The candidate uses the same instrumentation
and TLS 1.3 setup. Each cold and warm case has five full handshakes with
X25519, AES-128-GCM, and the same P-256 ECDSA certificate and trust store.
The emulator and Palm OS 4.1 m515 session match the X25519 integration
benchmark. Engine load is measured separately. The server confirmed
one ClientHello for every comparison sample.
[X25519 integration results](../2026-11-20-dragonball-x25519-tls13)

## Baseline signature profile

The warm stock-speed signature median was 7.850 s. Every sample reached the
native P-256 verifier twice. The table reports medians per phase.

| Phase | Stock (1×) | Median calls |
|---|---:|---:|
| Point doubling | 5.030 s | 511 |
| Point addition | 1.860 s | 148 |
| Peer-table setup | 0.660 s | 2 |
| Other signature work | 0.270 s | 2 |
| Peer validation | 0.010 s | 2 |
| Final comparison | 0.010 s | 2 |
| Scalar recoding | 0.000 s | 2 |

The timer is the 100 Hz Palm clock. Per-sample detail adds up to the signature
phase. Medians of individual phases may add to a different value than the
median total. At 16×, many field and point operations finish within one tick,
so short adjacent phases can be charged differently across builds. Stock
speed gives the more interpretable breakdown.

## Results

| CPU speed | Full handshake | Baseline | Candidate | Signature before → after |
|---|---|---:|---:|---:|
| Stock (1×) | Cold | 15.250 s | 14.840 s | 7.860 → 7.430 s |
| Stock (1×) | Warm | 15.000 s | 14.590 s | 7.850 → 7.440 s |
| 16× | Cold | 950 ms | 930 ms | 480 → 460 ms |
| 16× | Warm | 930 ms | 910 ms | 490 → 460 ms |

At stock speed, warm verification took 410 ms less time (5.2%), and the
warm handshake took 410 ms less time (2.7%). Warm doubling fell from
5.030 s to 4.850 s, peer-table setup from 660 ms to 530 ms, and additions
from 1.860 s to 1.810 s. Doubling remains the largest signature cost.
The candidate library PRC is 144 bytes larger than the instrumented baseline.

[Handshake summary](summary.csv) · [Phase timings and counts](signature.csv) ·
[Stock baseline](1x/baseline/results.csv) · [Stock candidate](1x/candidate/results.csv) ·
[16× baseline](16x/baseline/results.csv) · [16× candidate](16x/candidate/results.csv) ·
[Build and session hashes](metadata.json)

## Changes tested

- Public point doubling uses a square to calculate the new Z coordinate,
  reusing the Y and Z squares already computed by the doubling formula.
  [Bernstein's Jacobian doubling formula](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b)
- Public Montgomery reduction skips the intervening limbs when the carry
  stops. Private Montgomery reduction still propagates across the full span.
- Verification batch-normalizes the odd peer multiples selected by the
  signed digits. Key agreement still normalizes the full table.

The linked 68000 oracle passed 111 double-scalar vectors with comparison edge
cases and 120 valid and tampered ECDSA signature cases. Fixed-base and
variable-base regression and instruction/address trace checks also passed.

[Reproduction commands](../../README.md#dragonball-tls-13-handshakes)
