# Five ARM TLS 1.3 optimization rounds

Each build ran twice on the same CloudpilotEmu Palm OS 5 session at
100 MIPS. Each run used five cold, five warm and five resumed handshakes
with the same OpenSSL server, P-256 ECDHE and eight CA roots. The benchmark
used profiling-disabled session opens and timed them externally at
100 Hz. Cold times include engine and trust setup. Times exclude TCP
setup and post-handshake I/O. OpenSSL confirmed the cipher, full
handshakes and ticket resumption for every sample.

## ChaCha20-Poly1305 with SHA-256

| Round | Change | Cold | Warm | Resumed |
| --- | --- | ---: | ---: | ---: |
| Baseline | Published v0.1.11 ARM PRC | 370 ms | 230 ms | 130 ms |
| 1 | Update only the negotiated transcript hash after the final ServerHello | 340 ms | 200 ms | 120 ms |
| 2 | Reuse successful issuer signature checks in the same trust context | 340 ms | 160 ms | 120 ms |
| 3 | Trial of Clang `-O2` for the ARMlet | 340 ms | 160 ms | 120 ms |
| 4 | Three interleaved P-256 generator comb tables with `-Os` | 340 ms | 160 ms | 120 ms |
| 5 | Native SHA-384 and SHA-512 compression | 330 ms | 150 ms | 110 ms |

The final medians are 10.8% lower cold, 34.8% lower warm and 15.4% lower
resumed. Round 3 added 13,492 native image bytes with the same median
times, so round 4 continued from round 2 at `-Os`. The interleaved
comb reduced key generation from 545,747 to 475,980 ARM instructions
in the TI925T emulator with the same scalar and generator. Full
handshake medians stayed at the same 10 ms clock resolution. Each
lookup still reads every row of the relevant table.

## AES-256-GCM with SHA-384

| Build | Cold | Warm | Resumed |
| --- | ---: | ---: | ---: |
| Round 4 | 860 ms | 680 ms | 770 ms |
| Round 5 | 350 ms | 180 ms | 140 ms |
| Time reduction | 59.3% | 73.5% | 81.8% |

Both sides of this comparison used the same AES-256-GCM/SHA-384 cipher
and the same server fixture as the ChaCha20 measurements. The wide ARM
engine uses the native SHA-512 compression function for SHA-384 and
SHA-512, including the key schedule. The software path remains
available if native qualification or dispatch fails.

## Validation

The final profile measured a 40 ms median issuer signature check on
cold handshakes and a warm lookup below one timer tick. Live TLS
CertificateVerify ran once per full handshake. The emulator also
checked hostname and unknown CA rejection, context reuse, cancellation,
slot isolation, and full and resumed TLS 1.2. `make check` and the
SHA-384/512 and P-256 oracles passed on the host and on both native CPU
models, TI925T and PXA270. The rebuilt ARM PRC resources matched the
measured PRC byte for byte.

Full and resumed ChaCha20 handshakes also passed with a P-384 leaf and
issuer signed with SHA-384. A P-384-only key exchange fixture exercised
HelloRetryRequest with AES-256-GCM. Both v0.1.11 and the final build completed
the full handshakes and hit OpenSSL's existing `BAD_KEY_SHARE` error on the
resumed connection. [Wide certificate check](wide-cert/results.csv) ·
[HelloRetryRequest baseline](hrr-baseline/server-connections.jsonl) ·
[HelloRetryRequest final build](hrr-final/server-connections.jsonl)

[Summary and ranges](summary.csv) · [Build and fixture hashes](metadata.json) ·
[Final regression profile](final-regressions/results.csv)
