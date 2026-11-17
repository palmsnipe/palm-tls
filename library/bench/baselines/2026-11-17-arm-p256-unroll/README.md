# ARM P-256 field-multiply outer-loop unroll

The baseline is the committed **`dc2721c`** native image (AES-GCM T-table and
unrolled GHASH). The candidate adds a full unroll of the eight outer rounds in
`FeMultiply`. Each round now keeps the multiplicand limbs in registers instead
of reloading them from the stack. Field squaring uses the same multiplier, so
the change applies to every P-256 field operation.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags, benchmark application code
and 100 Hz clock. The benchmark PRCs differ only in the native image.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| Raw P-256 field multiply | 7.324 us | 6.104 us | 6.104 us | 16.7% |
| Raw P-256 field square | 7.324 us | 6.104 us | 6.104 us | 16.7% |
| P-256 fixed-base affine multiply | 10000.000 us | 9062.500 us | 9062.500 us | 9.4% |
| P-256 general-point affine multiply | 31250.000 us | 27500.000 us | 27500.000 us | 12.0% |
| P-256 fixed-base raw output | 8437.500 us | 7500.000 us | 7500.000 us | 11.1% |
| P-256 affine map | 1953.125 us | 1640.625 us | 1640.625 us | 16.0% |
| P-256 double-scalar (`u1*G + u2*Q`) | 31250.000 us | 26250.000 us | 26250.000 us | 16.0% |
| P-256 double-scalar, generator left | 28750.000 us | 25000.000 us | 25000.000 us | 13.0% |
| P-256 double-scalar, generator right | 28750.000 us | 25000.000 us | 25000.000 us | 13.0% |

The AES-GCM rows are unchanged, confirming that this change isolates field
arithmetic. The TLS 1.2/1.3 verification rows retain 10 ms clock quantization.
Before the change every `point` phase sample was **3 ticks** (30 ms); after it,
two of five samples are **2 ticks** (20 ms), so the mean falls from **3.0 to
2.6 ticks (13.3% less)** while the median stays at 3 ticks. Those single-call
rows are not used to claim a precise handshake improvement; the batched native
rows above are.

Instruction counts from the extracted image on PXA270:

| Workload | Baseline | Candidate | Less instructions |
| --- | ---: | ---: | ---: |
| `FeMultiply` | 704 | 598 | 15.1% |
| `PointDouble` | 7,443 | 6,587 | 11.5% |
| `P256Multiply2AddPoint` | 2,911,770 | 2,566,046 | 11.9% |

The native image grows from **34,984 to 36,408 bytes** (+1,424). Its SHA-256 is
`7cb372f8739b31391186dcce8bd75cd06b67d6cba54a2a5f663acb887709e48d`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. The field
control/address trace checks remain identical across valid field values, and
the secret-scalar block traces remain identical across private scalars. The
unroll adds no value-dependent control flow or addresses.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
