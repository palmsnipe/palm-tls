# ARM AES key schedule in native words

The baseline is the committed **`555efef`** image. The AES key schedule is now
stored as native little-endian words instead of big-endian bytes, so an
aligned request buffer reads each round-key column with one `LDR` instead of
four `LDB` and three `ORR`. Unaligned request buffers keep the byte-wise reads
and produce the same key words.

`AesExpand` computes the schedule in 32-bit words (RotWord, SubWord, Rcon) and
stores it in native order. `AesEncrypt` has an aligned and a byte-addressed
round loop; both share the final S-box round. The AES T-table, GHASH table,
counter handling, record copy, request ABI and chunking are unchanged.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags and 100 Hz clock. The
candidate was reproduced by a second fresh-session run.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| AES-GCM encrypt, 16 bytes | 141.602 us | 136.719 us | 136.719 us | 3.3–6.7% |
| AES-GCM encrypt, 512 bytes | 742.188 us | 644.531 us | 664.062 us | 10.5–13.2% |
| AES-GCM encrypt, 4096 bytes | 5156.250 us | 4531.250 us | 4531.250 us | 12.1% |
| AES-GCM encrypt, 16384 bytes | 20625.000 us | 17500.000 us | 17500.000 us | 15.2% |
| AES-GCM decrypt, 16 bytes | 141.602 us | 141.602 us | 141.602 us | 3.3% |
| AES-GCM decrypt, 512 bytes | 742.188 us | 644.531 us | 644.531 us | 13.2% |
| AES-GCM decrypt, 4096 bytes | 5156.250 us | 4531.250 us | 4375.000 us | 12.1–14.7% |
| AES-GCM decrypt, 16384 bytes | 20625.000 us | 17500.000 us | 17500.000 us | 15.2% |

Large-record throughput rises from about **776 to 914 KiB/s** (17.8%).

Direct instruction counts for the whole record on PXA270:

| Record size | Baseline | Candidate | Less instructions |
| --- | ---: | ---: | ---: |
| 16 bytes | 11,103 | 10,258 | 7.6% |
| 512 bytes | 70,530 | 61,315 | 13.1% |
| 4096 bytes | 506,989 | 437,294 | 13.7% |
| 16384 bytes | 2,003,416 | 1,726,361 | 13.8% |

`AesEncrypt` falls from about **978 to 739 instructions per 16-byte block**
(24.5%), because the byte-wise round-key reads cost about 28 instructions per
round. ChaCha20-Poly1305, P-256, SHA-256 and generic-multiply rows are
unchanged.

The native image grows from **48,836 to 49,420 bytes** (+584) because the
aligned and byte-addressed round loops are separate. Its SHA-256 is
`d7c32773297156a43ab86486c99d55f34e3e410cab65be7a02a2015ffef58ecc`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. Both round
loops are exercised by the alignment sweep, and AES-128/AES-256 key expansion
is checked against the NIST vectors.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
