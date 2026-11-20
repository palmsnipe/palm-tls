# Palm m515 variable-base P-256 key agreement

The baseline is the exact measured [fixed-base PRC](../2026-11-20-dragonball-fixed-base)
committed in `2f84add`. The candidate uses four-bit windows for agreement
with a P-256 peer. It checks the affine peer coordinates, batch-normalizes
15 public multiples, scans each table row in every window, and randomizes
the accumulator's projective representation. The backend maps only the
shared X coordinate and serializes all 32 bytes. The shared 68K Montgomery
reducer uses the extend flag to propagate carries on a fixed schedule.

| Run | Cold handshake | Warm handshake | Warm key agreement | Warm key generation |
| --- | ---: | ---: | ---: | ---: |
| Fixed-base baseline | 1,490 ms | 1,480 ms | 630 ms | 190 ms |
| Baseline repeat | 1,500 ms | 1,480 ms | 630 ms | 190 ms |
| Variable-base and reducer | 1,320 ms | 1,300 ms | 470 ms | 170 ms |
| Final repeat | 1,320 ms | 1,310 ms | 470 ms | 170 ms |

Key agreement took 25.4% less time. The warm handshake dropped by 170–180 ms
(11.5–12.2%). Most of the gain came from peer-point multiplication, which
fell from 610 to 450 ms in the warm samples. The shared reducer also saved
20 ms in key generation. The full PRC grew from 647,407 to 651,563 bytes
(+0.64%). Cold engine load had a 20 ms median throughout.

The runs used the same m515 Palm OS 4.1 session, CloudpilotEmu DragonBall CLI,
16× CPU overclock, benchmark PRC, and OpenSSL fixture as the fixed-base
series. Each used five cold and five warm full TLS 1.3 samples with P-256,
AES-128-GCM, and eight trusted roots. The Palm clock has 10 ms resolution.
Handshake timings exclude engine load and socket setup. Each run
also verified a full TLS 1.2 connection and rejection of an untrusted CA
and an incorrect hostname.

`make check` passed. The linked 68000 backend passed 66 variable-base
oracle cases and six invalid-input checks, including a valid finite peer
whose shared X encodes as 32 zero bytes. The fixed-base oracle also
passed all 355 cases. The trace checks used different private scalars and
projective randomizers with the same public peer to compare executed
instructions and memory addresses in Unicorn.

With Unicorn installed, run the agreement oracle after building the full
library:

```sh
python3 library/tests/p256_variable_68k_test.py \
  library/build/palm/68k/library-tls13.elf \
  ../palm-toolchain/.toolchain/prefix/bin/m68k-none-elf-nm
```

[Summary CSV](summary.csv) · [Build and input hashes](metadata.json) ·
[Benchmark commands](../../README.md#dragonball-tls-13-handshakes)
