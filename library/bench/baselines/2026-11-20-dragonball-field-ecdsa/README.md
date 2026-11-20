# Palm m515 P-256 verification with fixed-width field arithmetic

The baseline is the frozen [variable-base PRC](../2026-11-20-dragonball-variable-base)
from commit `bef19d3`. The candidate verifies P-256 signatures using the
same 16-limb field and sparse Montgomery cancellation as key agreement.
Verification uses public-only Comba multiply and square loops with early
carry termination. Its double-scalar multiplication uses width-7 signed
digits for the precomputed generator and width-5 digits for the peer.
It checks the projective X coordinate against both possible field
representatives of the signature's r and rejects the point at infinity.

| Run | Cold handshake | Warm handshake | Warm signature phase |
| --- | ---: | ---: | ---: |
| Variable-base baseline | 1,320 ms | 1,300 ms | 620 ms |
| Baseline repeat | 1,320 ms | 1,300 ms | 620 ms |
| Fixed-width verification | 1,170 ms | 1,150 ms | 480 ms |
| Final repeat | 1,170 ms | 1,150 ms | 480 ms |

The signature phase took 22.6% less time, and the warm handshake took
11.5% less time. Warm key agreement also moved from 480 to 460 ms because
it shares the public peer-table preparation. Cold engine load had a 20 ms
median throughout. The full 68K PRC grew from 651,563 to 653,679 bytes
(+0.32%). A preliminary port that used the full carry schedule for public
operands measured 1,340 ms warm and was discarded.

The runs used the same Palm m515 Palm OS 4.1 session, CloudpilotEmu
DragonBall CLI, 16× CPU overclock, benchmark PRC, and local OpenSSL fixture.
Each run measured five cold and five warm full TLS 1.3 handshakes with
P-256, AES-128-GCM, and eight trusted roots. Palm ticks are 10 ms.
The table excludes socket setup and engine load. The server independently
confirmed the ten measured connections and the TLS 1.2 check in every run.
The app also checks hostname and CA rejection.

`make check` passed. The [68000 verifier oracle](../../../tests/p256_verify_68k_test.py)
checked 111 linked double-scalar vectors and projective comparison edge
cases, including equal and opposite points, recovery after cancellation,
and the `r+n` candidate. The wolfSSL API passed 120 valid and tampered
signature cases using the previous oracle with a 100 million instruction
limit. Fixed-base and variable-base oracle and instruction/address trace
regressions also passed.

With Unicorn installed, run the verifier oracle after building the library:

```sh
python3 library/tests/p256_verify_68k_test.py \
  library/build/palm/68k/library-tls13.elf \
  ../palm-toolchain/.toolchain/prefix/bin/m68k-none-elf-nm
```

[Summary CSV](summary.csv) · [Build and input hashes](metadata.json) ·
[Benchmark commands](../../README.md#dragonball-tls-13-handshakes)
