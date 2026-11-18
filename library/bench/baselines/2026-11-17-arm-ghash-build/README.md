# ARM 32-bit GHASH table construction

The baseline is the committed **`0bfec21`** image. GHASH table construction now
works on aligned 32-bit words instead of byte arrays. The four H powers are
shifted as words, and each table entry selects its powers with masks instead of
a per-byte conditional branch. The stored table layout, 4-bit reduction table,
AES key expansion, chunking and request ABI are unchanged.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags and 100 Hz clock. The
candidate was reproduced by a second fresh-session run.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| AES-GCM encrypt, 16 bytes | 190.430 us | 151.367 us | 151.367 us | 20.5% |
| AES-GCM decrypt, 16 bytes | 190.430 us | 151.367 us | 151.367 us | 20.5% |
| AES-GCM encrypt, 512 bytes | 820.312 us | 781.250 us | 820.312 us | 4.5–9.1% |
| AES-GCM decrypt, 512 bytes | 820.312 us | 781.250 us | 781.250 us | 4.5–9.1% |
| AES-GCM encrypt, 16384 bytes | 21875.000 us | 21875.000 us | 21875.000 us | unchanged |
| AES-GCM decrypt, 16384 bytes | 21875.000 us | 22500.000 us | 22500.000 us | unchanged |

The gain is concentrated in the per-record setup. Direct instruction counts for
the GCM START command on PXA270 fall from **7,693 to 3,771** (51.0% fewer) for a
16-byte key with no AAD, and from **9,239 to 5,316** (42.5% fewer) with 13 bytes
of AAD. Large records amortize this setup, so their medians stay within the
10 ms clock quantum. ChaCha20-Poly1305, P-256, SHA-256 and generic-multiply rows
are unchanged.

The native image grows from **48,640 to 48,700 bytes** (+60). Its SHA-256 is
`81f0156f913fa8baee713fc2f94faf3085da6f24263770b432baf55bb2af2650`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
