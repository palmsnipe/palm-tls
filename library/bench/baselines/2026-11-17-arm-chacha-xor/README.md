# ARM unrolled ChaCha20 record XOR

The baseline is the committed **`45f3c4a`** image. `ChaChaCrypt` previously
walked the 16-word keystream XOR with a four-instruction loop body plus a
counter, branch and address increments: seven instructions per word. The
sixteen words are now fully unrolled, so each word is one load, one XOR and
one store, and the keystream buffer is loaded four words at a time.

The ChaCha double-rounds, Poly1305 code, block counter, state layout and
request ABI are unchanged.

Both runs use the same supplied Frankenpilot / Tungsten E3 session, native
`cp-uarm` binary, **100 MIPS**, ARMv4T `-Os` flags and 100 Hz clock. The
candidate was reproduced by a second fresh-session run.

Five-sample medians, first candidate run / repeat:

| Operation | Baseline | Candidate | Repeat | Less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| ChaCha20-Poly1305, 16 bytes | 195.312 us | 195.312 us | 195.312 us | unchanged |
| ChaCha20-Poly1305, 512 bytes | 312.500 us | 302.734 us | 302.734 us | 3.1% |
| ChaCha20-Poly1305, 4096 bytes | 1171.875 us | 1132.812 us | 1171.875 us | 3.2–6.5% |
| ChaCha20-Poly1305, 16384 bytes | 4218.750 us | 4062.500 us | 4062.500 us | 3.7% |

Large-record throughput rises from about **3793 to 3938 KiB/s** (3.8%). The
16 KiB row improves **3.7%** in both candidate runs.

Direct instruction counts for the whole ChaCha20-Poly1305 call on PXA270:

| Record size | Baseline | Candidate | Less instructions |
| --- | ---: | ---: | ---: |
| 16 bytes | 4,655 | 4,653 | unchanged |
| 512 bytes | 16,001 | 15,583 | 2.6% |
| 4096 bytes | 104,257 | 100,927 | 3.2% |
| 16384 bytes | 406,847 | 393,535 | 3.3% |

`ChaChaCrypt` falls from about **127 to 75 instructions per 64-byte block**;
the remaining work is the 16 loads, 16 XORs, 16 stores and four keystream
loads. The ten double-rounds of `ChaChaBlock` are already fully unrolled and
account for about 60% of the call. AES-GCM, P-256, SHA-256 and
generic-multiply rows are unchanged.

The native image grows from **49,420 to 49,636 bytes** (+216). Its SHA-256 is
`e5bd1779eeaed6bddbf3504148cb5c0219581784746db5670f19b3538cfb29b1`.
All existing ARM profiles and both benchmark apps contain this one ARMv4T
image; the CPU allowlist and 68K fallback are unchanged.

Host C and the extracted image under **TI925T and PXA270** pass 336 AES-GCM
records, 99 ChaCha records, 1,881 raw-field chains, 69 inversions/maps, 88
scalar products, 181 double-scalar cases, 432 order preparations, 270 point
validations, 30 ECDSA valid/tampered cases, 397 Ed25519 field cases and 79
public-key arithmetic cases, with request alignment offsets 0–3. The ChaCha
oracle covers aligned and unaligned records, empty records, AAD and partial
blocks, so the unaligned byte path is still exercised.

These are emulator instruction-budget results, not physical XScale cache or
pipeline measurements. Raw results and manifests are in `before/`, `after/`
and `repeat/`; the candidate source diff is `source.patch`.
