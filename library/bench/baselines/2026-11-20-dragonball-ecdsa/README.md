# Palm m515 P-256 signature verification

The baseline is the frozen round 5 PRC from the
[first DragonBall series](../2026-11-20-dragonball). Its warm TLS 1.3
handshake spent 830 ms on signature verification and 630 ms each on key
generation and agreement. The next five rounds targeted signature
verification. The P-256 verifier uses these routines for public scalars
and public points.

| Round | Cumulative change | Cold handshake | Warm handshake | Warm signature phase |
| --- | --- | ---: | ---: | ---: |
| Baseline | First five rounds | 2,150 ms | 2,130 ms | 830 ms |
| 6 | Recode both scalars in width-4 signed windows and share the doublings | 2,080 ms | 2,060 ms | 770 ms |
| 7 | Add public points directly and handle infinity and equal or opposite points explicitly | 2,050 ms | 2,030 ms | 730 ms |
| 8 | Batch-normalize the precomputed points for mixed affine/Jacobian addition | 1,980 ms | 1,970 ms | 670 ms |
| 9 | Compare the projective X coordinate against the two possible field values of the signature's r | 1,980 ms | 1,960 ms | 660 ms |
| 10 | Double in place using the storage freed by recoding the public scalars | 1,930 ms | 1,910 ms | 610 ms |
| Baseline repeat | Same round 5 PRC | 2,140 ms | 2,130 ms | 830 ms |
| Round 10 repeat | Same round 10 PRC | 1,930 ms | 1,910 ms | 620 ms |

The warm handshake improved by 220 ms (10.3%) in both comparisons. The
cold handshake improved by 210–220 ms (9.8–10.2%). Cold engine load had a
20 ms median throughout. Round 9's standalone timing difference was
within one Palm tick. Key generation and agreement each measured 630 ms
at the end. The full PRC grew from 625,887 to 633,323 bytes (+1.2%).

The same benchmark PRC, emulator, m515 Palm OS 4.1 session, 16× CPU
overclock, and local OpenSSL fixture were used for both series. Each
run used five cold and five warm full TLS 1.3 handshakes, P-256,
AES-128-GCM, and the same eight trusted roots. Palm ticks have 10 ms
resolution. Handshake timings include TLS setup and exclude socket
setup and engine load. The elapsed times apply to this emulator and
local fixture.

Each run passed the bad-CA and wrong-hostname checks. The server logs
confirm ten full TLS 1.3 connections and a successful TLS 1.2 connection
per run. The linked 68000 verifier passed 120 cases based on independent
affine point arithmetic, including valid and tampered signatures, a
zero verification scalar, cancellation to infinity, scalar range
checks, and a valid signature that requires the `r + n` candidate.
`make check` passed, and the normal build reproduced all 18 resources
of the measured PRC byte for byte.

With Unicorn installed, run the oracle after building the full library:

```sh
python3 library/bench/baselines/2026-11-20-dragonball-ecdsa/p256-verify-oracle.py \
  library/build/palm/68k/library-tls13.elf \
  ../palm-toolchain/.toolchain/prefix/bin/m68k-none-elf-nm
```

The width-4 recoding uses the windowed non-adjacent form described in
[Fast Batch Verification of Multiple Signatures](https://iacr.org/archive/pkc2007/44500442/44500442.pdf).

[Summary CSV](summary.csv) · [Build and input hashes](metadata.json) ·
[Reproduction commands](../../README.md#dragonball-tls-13-handshakes)
