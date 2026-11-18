# ARM AES-GCM word-wide record updates

The baseline is the committed **`929c25d`** image. The AES-GCM UPDATE inner
loop previously zeroed a 16-byte block and copied the record one byte at a
time for every 16-byte counter block. Whole blocks now take a word-wide fast
path when the input and output pointers are 4-byte aligned: four word loads,
four XORs with the AES keystream, four word stores to the output, and four
word stores to the GHASH block. Partial blocks and unaligned pointers keep the
byte-wise path.

The AES rounds, GHASH table construction and 32-nibble GHASH block, key
schedule, counter handling, request ABI and chunking are unchanged.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags and 100 Hz clock. The
candidate was reproduced by a second fresh-session run.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| AES-GCM encrypt, 16 bytes | 151.367 us | 146.484 us | 146.484 us | 3.2% |
| AES-GCM encrypt, 512 bytes | 820.312 us | 742.188 us | 742.188 us | 9.5% |
| AES-GCM encrypt, 4096 bytes | 5781.250 us | 5156.250 us | 5156.250 us | 10.8% |
| AES-GCM encrypt, 16384 bytes | 22500.000 us | 20625.000 us | 20625.000 us | 8.3% |
| AES-GCM decrypt, 16 bytes | 151.367 us | 146.484 us | 146.484 us | 3.2% |
| AES-GCM decrypt, 512 bytes | 820.312 us | 742.188 us | 742.188 us | 9.5% |
| AES-GCM decrypt, 4096 bytes | 5781.250 us | 5156.250 us | 5156.250 us | 8.1–10.8% |
| AES-GCM decrypt, 16384 bytes | 22500.000 us | 20625.000 us | 20625.000 us | 8.3% |

Large-record throughput rises from about **711 to 776 KiB/s** (9.1%).

Direct instruction counts for the whole record on PXA270:

| Record size | Baseline | Candidate | Less instructions |
| --- | ---: | ---: | ---: |
| 16 bytes | 11,335 | 11,103 | 2.0% |
| 512 bytes | 76,745 | 70,530 | 8.1% |
| 4096 bytes | 556,415 | 506,989 | 8.9% |
| 16384 bytes | 2,200,994 | 2,003,416 | 9.0% |

The byte-wise zero/copy loops cost about 208 instructions per counter block,
which is roughly 10% of the whole record call. ChaCha20-Poly1305, P-256,
SHA-256 and generic-multiply rows are unchanged.

The native image grows from **48,700 to 48,836 bytes** (+136). Its SHA-256 is
`856d3bc57f5b7ae224cd73bdbebb2d65894fc5f44689f444615d0fce23d20e76`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. The oracle
suite covers aligned and unaligned requests, partial blocks, empty records,
AAD and both key sizes.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
