# ARM fully unrolled ChaCha20 rounds

The baseline is the committed **`1a12deb`** library image. The ten double-rounds
of `ChaChaBlock` are now fully unrolled. The quarter-round macro, block counter,
state layout, Poly1305 code and request ABI are unchanged.

This round also adds `chacha_encrypt_16/512/4096/16384` rows to the Palm
benchmark. The record is sealed in one native call, as in the production
ChaCha20-Poly1305 path; the benchmark re-copies the 64-byte state before each
call because the ARMlet clears its request copy. AAD is 13 zero bytes and the
plaintext is all-zero.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags and 100 Hz clock. The
baseline run uses the previous library image with the new benchmark rows; the
candidate was reproduced by a second fresh-session run.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| ChaCha20-Poly1305, 16 bytes | 205.078 us | 195.312 us | 195.312 us | 4.8% |
| ChaCha20-Poly1305, 512 bytes | 322.266 us | 312.500 us | 312.500 us | 3.0% |
| ChaCha20-Poly1305, 4096 bytes | 1289.063 us | 1210.938 us | 1171.875 us | 6.1–9.1% |
| ChaCha20-Poly1305, 16384 bytes | 4687.500 us | 4218.750 us | 4218.750 us | 10.0% |

Large-record throughput rises from about **3495 to 3793 KiB/s** (8.5%). The
16 KiB record improves **10.0%** in both candidate runs.

Direct instruction counts for the whole ChaCha20-Poly1305 call on PXA270:

| Record size | Baseline | Candidate | Less instructions |
| --- | ---: | ---: | ---: |
| 16 bytes | 4,981 | 4,655 | 6.5% |
| 512 bytes | 17,468 | 16,001 | 8.4% |
| 4096 bytes | 114,852 | 104,257 | 9.2% |
| 16384 bytes | 448,740 | 406,849 | 9.3% |

ChaCha20-Poly1305 is the preferred TLS 1.3 record cipher on ARM, so this
reduces TLS 1.3 record sealing/opening cost as well as the raw primitive cost.
Existing AES-GCM, P-256, SHA-256 and generic-multiply rows are unchanged.

The native image grows from **45,476 to 48,640 bytes** (+3,164). Its SHA-256 is
`0a46e40e5769b3ac9c3872ab2b1a3a6dc695bfed483c4feb081df7c2636eab4a`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. The host
benchmark also validates the new ChaCha rows against an independent OpenSSL
oracle.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
