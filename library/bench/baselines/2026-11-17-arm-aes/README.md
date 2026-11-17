# ARM AES-GCM T-table rounds and unrolled GHASH

The baseline is the committed **`b11f759`** native image. The candidate replaces
the byte-oriented AES round with a 32-bit T-table round and reduces each GHASH
nibble through a 16-entry reduction table inside a fully unrolled block loop.
Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags, benchmark application code,
and 100 Hz Palm clock. The benchmark PRCs differ only in the native image.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| AES-GCM encrypt, 16 bytes | 302.734 us | 185.547 us | 185.547 us | 38.7% |
| AES-GCM decrypt, 16 bytes | 302.734 us | 185.547 us | 185.547 us | 38.7% |
| AES-GCM encrypt, 512 bytes | 2109.375 us | 820.312 us | 820.312 us | 61.1% |
| AES-GCM decrypt, 512 bytes | 2109.375 us | 820.312 us | 820.312 us | 59.3% |
| AES-GCM encrypt, 4096 bytes | 15000.000 us | 5625.000 us | 5625.000 us | 62.5% |
| AES-GCM decrypt, 4096 bytes | 15000.000 us | 5625.000 us | 5625.000 us | 61.5% |
| AES-GCM encrypt, 16384 bytes | 60000.000 us | 22500.000 us | 22500.000 us | 62.5% |
| AES-GCM decrypt, 16384 bytes | 60000.000 us | 22500.000 us | 22500.000 us | 62.5% |

Large-record throughput rises from **266.7 to 711.1 KiB/s** in both directions
(2.67x). The 16-byte case improves **38.7%**; its remaining cost includes the
per-record key expansion and GHASH table setup. P-256, SHA-256 and the engine
self-test medians are unchanged within the existing timer quantization; the
TLS verification rows move by one 10 ms tick between runs and are not evidence
of a P-256 change.

The native image grows from **30,592 to 34,984 bytes** (+4,392). The added
bytes are the 1 KiB AES Te0 table, the 64-byte GHASH reduction table, and the
fully unrolled GHASH block code. The final image SHA-256 is
`50438f7841fb7d7eea52fd9ccaa5e3cf2564b0d0ec61c05ac1a89294d99cfd0d`.
All existing ARM profiles and both benchmark applications contain this one
ARMv4T image; the CPU allowlist and 68K fallback are unchanged.

Correctness checks pass on host C and the extracted image under **TI925T and
PXA270** CPU models: 336 AES-GCM records, 99 ChaCha records, 1,881 raw-field
chains, 69 inversions/maps, 88 scalar products, 181 double-scalar cases, 432
order preparations, 270 point validations, 30 ECDSA valid/tampered cases, 397
Ed25519 field cases and 79 public-key arithmetic cases, with request alignment
offsets 0–3. The AES T-table output matches the former byte implementation on
2,000 host key/block trials. Project/profile/package checks and the native
instruction-attribute rejection tests also pass.

The T-table and reduction table remain secret-indexed lookups, the same access
class as the existing AES S-box. These measurements are emulator
instruction-budget timings, not physical XScale cache/pipeline behavior, and
they do not establish end-to-end network throughput.

Raw results and manifests are in `before/`, `after/` and `repeat/`; the candidate
source diff is `source.patch`.
