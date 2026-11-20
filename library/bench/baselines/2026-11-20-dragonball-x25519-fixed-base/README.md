# Fixed-base X25519 key generation on the Palm m515

The standalone 68K PRC times the production P-256 paths, the portable
wolfSSL X25519 ladder, and the new fixed-base X25519 key generator in the same
run. The PRC, Palm OS 4.1 m515 session, and CloudpilotEmu binary were identical
at stock speed and 16×. Both ran with the 100 Hz Palm clock. The emulator and
session hashes match the original portable comparison.
[Original measurements](../2026-11-20-dragonball-x25519)

## Results

| Operation | Stock (1×) | 16× |
|---|---:|---:|
| X25519 key generation, fixed-base | 1.800 s | 110 ms |
| X25519 key generation, portable | 8.170 s | 510 ms |
| P-256 key generation | 2.650 s | 160 ms |
| X25519 agreement, portable | 8.170 s | 510 ms |
| P-256 agreement | 7.310 s | 460 ms |
| X25519 fixed-base keygen + portable agreement | 9.980 s | 620 ms |
| X25519 portable keygen + portable agreement | 16.350 s | 1,020 ms |
| P-256 keygen + agreement | 9.960 s | 620 ms |

Each value is the median of five samples. The combined values are medians
of the per-fixture sums. Fixed-base X25519 reduced key generation time by
78% versus portable X25519 and by 31–32% versus P-256. Pairing it with
portable agreement puts X25519 and P-256 at roughly the same combined
latency. Portable agreement accounts for about 82% of the X25519 pair at
stock speed.

[Stock samples](1x.csv) · [16× samples](16x.csv) · [Median and range](summary.csv) ·
[Build and session hashes](metadata.json)

## Implementation and timing

The candidate clamps the X25519 scalar, multiplies the fixed Edwards25519
base point with a six-bit comb, then converts the result to the 32-byte
Montgomery u-coordinate. It uses a 6,144-byte generated table scanned in full
at each step, projective randomization, and paired 68K word multiplies to
balance operand-dependent timing. The field uses sixteen 16-bit limbs with
32-bit carries. Reduction folds each bit-256 carry back in as a multiple of
38 modulo the field prime.
The 68K candidate object has no software wide-multiplication dependency.
Its text and read-only data total 8,422 bytes, including the table.
[RFC 7748, §4.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-4.1) ·
[RFC 8032, §5.1.4](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.4)

All paths use the same five fixtures per curve as the original comparison.
Each output is checked against the expected bytes before a timing is saved.
The fixed-base interval includes scalar clamping and output encoding.
Portable X25519 starts with its blinded scalar prepared. The timers exclude
entropy collection, result checking, and network or TLS work. The candidate
runs only in the benchmark PRC. It has projective blinding and a fixed table
scan, and the portable wolfSSL build also blinds the scalar.

The host differential test matched 402 outputs from 134 scalars and three
projective scales per scalar. It uses an independent Montgomery ladder
checked against the two published X25519 public keys.
[RFC 7748, §6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1)
