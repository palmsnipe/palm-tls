# ARM P-256 verification micro-unrolls

The baseline is the committed **`62e48d8`** image. Five fixed-size loops in the
P-256 verification path are now fully unrolled:

- `FeCopy`, `FeIsZero` and `FeEqual` copy/compare all eight limbs without loop
  control.
- `PointSetInfinity` zeroes all eight Z limbs directly.
- `ScalarWnaf` shifts the eight-word scalar window directly.

The point formulas, field arithmetic, table contents, request ABI, CPU
allowlist and 68K fallback are unchanged. The unrolls add no value-dependent
control flow or addresses.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags, benchmark application code
and 100 Hz clock. The benchmark PRCs differ only in the native image.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| Raw P-256 field square | 5.951 us | 5.798 us | 5.951 us | 2.6% |
| P-256 fixed-base raw output | 7187.500 us | 7187.500 us | 7187.500 us | 4.2% |
| P-256 double-scalar, generator right | 25000.000 us | 23750.000 us | 23750.000 us | 5.0% |
| P-256 double-scalar minimum sample | 26250.000 us | 25000.000 us | 25000.000 us | 4.8% |
| **TLS 1.3 verification `point` phase** | **30000 us** | **20000 us** | **20000 us** | **33.3%** |

Direct instruction counts for `P256Multiply2AddPoint` on PXA270 fall from
**2,566,046 to 2,441,033**, a **4.9%** reduction. That is enough to move the
TLS 1.3 `point` phase median from **30 ms to 20 ms** in both fresh-session
runs. The TLS 1.2 `point` phase median is 20 ms in the repeat run and 30 ms
with a 20 ms minimum in the first run; the single-call phase rows retain the
10 ms Palm clock quantum.

The native image grows from **44,900 to 45,476 bytes** (+576). Its SHA-256 is
`c68a04745b628f280089a826dfe3cf2899acdd6cfa16c5b9ba1758611c379f18`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; no processor-specific PRC is added.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. The field
control/address trace checks and private-scalar block traces remain identical
across their value sets.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
