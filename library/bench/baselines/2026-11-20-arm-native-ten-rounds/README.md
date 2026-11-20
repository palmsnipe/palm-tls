# Ten native ARM optimization rounds

The starting point is commit `d52861b`, the optimized build from the first
five ARM rounds. This comparison used the same CloudpilotEmu Palm OS 5
session at 100 MIPS, the same OpenSSL fixture with eight CA roots, and
P-256 key exchange. The benchmark measured the whole session open at
100 Hz with profiling disabled. It excludes TCP setup and subsequent
I/O. Cold samples include engine and trust initialization. Individual
rounds use five handshakes per case. Both baseline and final builds use
two runs each for ten handshakes per case, per cipher.

## Handshake results

| TLS 1.3 cipher | Build | Cold | Warm | Resumed |
| --- | --- | ---: | ---: | ---: |
| ChaCha20-Poly1305 | Baseline | 330 ms | 150 ms | 105 ms |
| ChaCha20-Poly1305 | Final | 330 ms | 150 ms | 110 ms |
| AES-256-GCM with SHA-384 | Baseline | 350 ms | 180 ms | 140 ms |
| AES-256-GCM with SHA-384 | Final | 350 ms | 170 ms | 130 ms |

The AES-256-GCM warm and resumed medians fell by one 10 ms tick.
The ChaCha20 resumed medians differ by half a tick when averaging the
two center samples. Its baseline and final ranges were both 100–110 ms.

## Round by round

Rounds 1–3 target SHA-384 and use AES-256-GCM for full-handshake timing.
Rounds 4–10 use ChaCha20. Each trial starts from the latest retained
candidate. The [ChaCha20 reference for round 2](round2-chacha-reference)
provides an end-to-end reference for rounds 4–10.

| Round | Trial | Cold | Warm | Resumed | Result |
| --- | --- | ---: | ---: | ---: | --- |
| 1 | Rotate the SHA-512 working words across groups of eight rounds | 350 ms | 180 ms | 130 ms | Kept. SHA-512 compression used 11.0% fewer ARM instructions |
| 2 | Separate the SHA-512 input and expanded-schedule loops | 350 ms | 170 ms | 130 ms | Kept. 10.8% fewer SHA-512 instructions than round 1 |
| 3 | Expand all 80 SHA-512 schedule words before compression | 350 ms | 180 ms | 130 ms | Added 512 bytes of working stack with little instruction saving |
| 4 | Load aligned SHA input as words and byte-swap | 330 ms | 160 ms | 100 ms | SHA-256 used 1.7% more instructions |
| 5 | Unroll the conditional coordinate selection after mixed addition | 330 ms | 150 ms | 110 ms | Saved less than 0.5% in each targeted kernel |
| 6 | Use a five-bit private P-256 window | 330 ms | 160 ms | 100 ms | Agreement used 6.5% more instructions |
| 7 | Use a three-bit private P-256 window | 330 ms | 150 ms | 110 ms | Agreement used 2.8% more instructions |
| 8 | Use a four-bit public P-256 window | 330 ms | 150 ms | 110 ms | Verification used 1.1% more instructions |
| 9 | Accumulate P-256 square terms by column | 330 ms | 150 ms | 110 ms | The square kernel used 4.0% more instructions |
| 10 | Initialize the first P-256 window directly | 330 ms | 150 ms | 110 ms | Kept. Key generation and agreement used 1.6% and 1.2% fewer instructions |

The six-bit public window passed the math oracle and triggered a Palm OS
fatal alert before the first timed connection. The four-bit variant
completed the emulator workload. The final source keeps the original
five-bit public window. [Six-bit trial screenshot](round8-wide-alert.png)

The three retained changes reduced four-block SHA-512 compression from
56,561 to 44,894 instructions on TI925T, a **20.6% reduction**. The native
image grew from 55,340 to 62,532 bytes. The final PRC resources matched
the normal build byte for byte. `make check`, the TI925T and PXA270
crypto oracles, and the final ARM handshake regressions passed.

[Timing summary and sample ranges](summary.csv) · [Native instruction counts](instructions.csv) ·
[Build and fixture hashes](metadata.json) · [Final regression profile](final-regressions/results.csv)
