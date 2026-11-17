# ARM SHA-256 fully unrolled compression rounds

The baseline is the committed **`b5d3f26`** image. The 64-round SHA-256
compression loop is now fully unrolled. Constant round indices remove the
message schedule's circular-buffer masks and the `round < 16` branch, so the
message schedule and round transforms become straight-line code. The block
loop, state update, output encoding and request ABI are unchanged.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags, benchmark application code
and 100 Hz clock. The benchmark PRCs differ only in the native image.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| SHA-256, one 64-byte block | 48.828 us | 35.400 us | 35.400 us | 27.5% |
| SHA-256, eight blocks | 302.734 us | 195.312 us | 195.312 us | 35.5% |

Direct instruction counts for the compression function on PXA270:

| Workload | Baseline | Candidate | Less instructions |
| --- | ---: | ---: | ---: |
| One block | 6,930 | 5,234 | 24.5% |
| Eight blocks | 34,874 | 21,299 | 38.9% |

The candidate also moved the TLS 1.2 verification `point` phase median from
**30 ms to 20 ms** in both runs. The batched P-256 rows are unchanged, so that
shift is not attributed to SHA-256; it may reflect code layout or phase
boundary timing. The TLS 1.3 `point` phase median remains 30 ms.

The native image grows from **36,764 to 44,900 bytes** (+8,136) because the
64 rounds are expanded in place. It remains within the single `armc:1`
resource budget. Its SHA-256 is
`d15c33b245e2c38d2f58091c43f273296dbda10f85c290c623ec43ee6af79937`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. The host
SHA-256 known answers cover one and eight blocks. Field control/address and
private-scalar trace checks remain identical.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
