# ARM 32-bit-word generic multiplication and P-256 final-select unroll

The baseline is the committed **`9ad9c8a`** image. (The benchmark metadata
records the pre-cleanup revision `7252579`, which has the same performance
tree.) Two changes are measured together:

- The generic TFM multiplication command now packs pairs of 16-bit digits into
  32-bit words, multiplies in base 2^32, and splits the product back into the
  caller's digit order. The old path performed one 16-bit multiply and two
  byte reads/writes per digit pair.
- The final conditional-subtraction selection in `FeMultiply` is fully
  unrolled, removing loop control from the end of every field multiply.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags, benchmark application code
and 100 Hz clock. The benchmark PRCs differ only in the native image.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| Generic multiply, 256 bits | 56.152 us | 31.738 us | 31.738 us | 43.5% |
| Generic multiply, 2048 bits | 2656.250 us | 1015.625 us | 1015.625 us | 61.8% |
| Raw P-256 field multiply | 6.104 us | 5.951 us | 5.951 us | 2.5% |
| Raw P-256 field square | 6.104 us | 5.951 us | 5.951 us | 2.5% |
| P-256 fixed-base affine multiply | 9062.500 us | 8750.000 us | 8750.000 us | 3.4% |
| P-256 general-point affine multiply | 27500.000 us | 26250.000 us | 26250.000 us | 4.5% |
| P-256 fixed-base raw output | 7500.000 us | 7187.500 us | 7187.500 us | 4.2% |
| P-256 double-scalar, generator left | 25000.000 us | 23750.000 us | 23750.000 us | 5.0% |

The generic 2048-bit multiply drops from about **265,600 to 101,600
instructions** on the extracted PXA270 image, matching the elapsed-time
reduction. The new path uses a 264-word local product buffer; a measured
2048-bit call uses **1,612 bytes of stack**, less than the existing RSA
multiply path. AES-GCM and SHA-256 rows are unchanged.

The native image grows from **36,408 to 36,764 bytes** (+356). Its SHA-256 is
`c517e91b15b243f7cd2db1c89f147c88de7b4d59ca31f8456cb547d5b40996e0`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. The host
suite also compares the new generic multiply against an independent base-2^16
schoolbook reference over **5,000 deterministic random cases**, including odd
lengths, zero operands and leading zero digits. The field control/address and
private-scalar trace checks remain identical.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
