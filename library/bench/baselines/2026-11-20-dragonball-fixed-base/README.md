# Palm m515 fixed-base P-256 key generation

The baseline is the full 68K PRC built from `e214061`, which includes the
[previous ten rounds](../2026-11-20-dragonball-ecdsa). The candidate uses a
six-tooth comb with 43 rounds and 63 precomputed generator points in the
68K TLS 1.2 and TLS 1.3 engines. It reads every table entry in each round.
The wolfSSL hook draws a fresh projective randomizer after checking the
private scalar, and it uses the generic path for callers without an RNG.
The server's public share goes through the variable-base path.

| Run | Cold handshake | Warm handshake | Warm key generation | Warm key agreement |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 1,930 ms | 1,910 ms | 630 ms | 630 ms |
| Baseline repeat | 1,930 ms | 1,910 ms | 630 ms | 630 ms |
| Fixed-base | 1,500 ms | 1,480 ms | 190 ms | 630 ms |
| Fixed-base repeat | 1,490 ms | 1,470 ms | 180 ms | 630 ms |

Warm key generation fell by 70–71%, and the warm handshake took 22.5–23.0%
less time. Cold engine load had a 20 ms median in all four runs. The full
PRC grew from 633,323 to 647,407 bytes (+2.2%). All library profiles passed
resource size and packaging checks.

The four runs used the same CloudpilotEmu DragonBall CLI, m515 Palm OS 4.1
session, 16× CPU overclock, benchmark PRC, and OpenSSL fixture as the previous
series. Each run took five cold and five warm full TLS 1.3 samples with P-256,
AES-128-GCM, and the same eight trusted roots. The Palm timer has 10 ms
resolution. The table excludes socket setup and engine load. Each run also
verified a full TLS 1.2 connection and rejection of an untrusted CA and an
incorrect hostname.

`make check` passed. The [68000 oracle](../../../tests/p256_fixed_68k_test.py)
compared 355 linked-code results with independent affine arithmetic and
matched the instruction and memory-address traces across four scalar and
projective-randomizer pairs. The word multiplier pairs each 68000 `MULU.W`
with one using the complemented source, so the combined count of set bits
is fixed. The trace test covers instructions and addresses under Unicorn.
[Motorola 68000 timing manual](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf)

With Unicorn installed, run the oracle after building the full library:

```sh
python3 library/tests/p256_fixed_68k_test.py \
  library/build/palm/68k/library-tls13.elf \
  ../palm-toolchain/.toolchain/prefix/bin/m68k-none-elf-nm
```

[Summary CSV](summary.csv) · [Build and input hashes](metadata.json) ·
[Benchmark commands](../../README.md#dragonball-tls-13-handshakes)
