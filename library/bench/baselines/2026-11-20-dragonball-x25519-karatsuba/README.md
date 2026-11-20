# Fixed-schedule X25519 Karatsuba on the Palm m515

The baseline is commit `8595557`. Both builds ran the standalone key-exchange
suite and full X25519 TLS 1.3 handshakes at stock speed and 16× on the same
Palm OS 4.1 m515 CloudpilotEmu setup. Each suite boots a fresh copy of the
same m515 image. The suites ran concurrently for each build. The benchmark
records Palm ticks at 100 Hz.

The standalone suite uses five known-answer inputs and checks every public
key and shared secret. It also checks noncanonical peer decoding and
all-zero shared-secret rejection. The handshake suite uses the same PRC,
OpenSSL fixture, P-256 ECDSA certificate and trust store with both libraries.
It measures five cold and five warm TLS 1.3 connections. OpenSSL confirmed
X25519, AES-128-GCM, and one ClientHello per timed handshake. The app also
checks hostname and CA rejection and a full TLS 1.2 handshake. Handshake
timing starts after TCP connection setup and tracks engine load separately.

## Results

| Operation | Stock (1×) before → after | 16× before → after |
|---|---:|---:|
| X25519 key generation | 1.800 → 1.230 s | 110 → 80 ms |
| X25519 agreement | 4.680 → 3.240 s | 290 → 200 ms |
| X25519 key generation + agreement | 6.490 → 4.470 s | 400 → 280 ms |
| Full cold handshake | 14.050 → 12.010 s | 880 → 750 ms |
| Full warm handshake | 13.790 → 11.780 s | 860 → 730 ms |

Values are medians of five samples. The combined key-exchange row takes
the median of per-fixture sums. At stock speed, standalone key generation
took 31.7% less time and agreement took 30.8% less. The warm handshake
saved 2.010 s at stock speed (14.6%) and 130 ms at 16× (15.1%).

[Key-exchange timings and ranges](key-exchange-summary.csv) ·
[Handshake totals and phase timings](handshake-summary.csv) ·
[Stock baseline](1x/baseline) · [Stock candidate](1x/candidate) ·
[16× baseline](16x/baseline) · [16× candidate](16x/candidate) ·
[Build and session hashes](metadata.json)

## Arithmetic and verification

The native kernels use a single Karatsuba split into two eight-limb halves
and share the unrolled Comba schedule with the public 68K P-256 kernels.
The signed difference and product carry paths visit fixed memory locations.
Each secret word product keeps the complementary pair of `MULU.W` source
operands. In the X25519 ladder, multiplication by the public peer coordinate
uses its single-`MULU.W` kernel. The native multiplication and squaring
paths use 192 and 108 word products, down from 256 and 136.
[GMP manual, Karatsuba multiplication](https://gmplib.org/gmp-man-5.1.0.pdf) ·
[RFC 7748, side-channel considerations](https://www.rfc-editor.org/rfc/rfc7748.html#section-5.1)

The linked 68000 oracle passed 1,128 field cases and found identical
instruction and data-address traces across 452 multiplication inputs and
270 squaring inputs, including carry and borrow boundaries. The host oracle
matched 402 fixed-base public keys and 546 variable-base results and
acceptance checks. The full 68K PRC grew by 2,618 bytes. The P-256 code
resource matched the baseline byte for byte.

| Linked 68000 field operation | Baseline instructions | Karatsuba instructions |
|---|---:|---:|
| Multiply | 7,623 | 3,293 |
| Square | 4,639 | 2,657 |

The instruction counts come from Unicorn, with 32 shared inputs per
operation. The latency measurements use the m515 CloudpilotEmu setup.
[Instruction summary](field-instructions.csv)

`make check` and the linked P-256 field regression passed.

[Key-exchange reproduction](../../README.md#dragonball-x25519-and-p-256-key-exchange) ·
[Handshake reproduction](../../README.md#dragonball-tls-13-handshakes)
