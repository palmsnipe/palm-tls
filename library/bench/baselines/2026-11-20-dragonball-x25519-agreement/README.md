# Variable-base X25519 agreement on the Palm m515

The standalone 68K PRC compares native X25519, portable wolfSSL X25519, and
the optimized PalmTLS P-256 build. Both clock settings use the same PRC and
the same CloudpilotEmu binary and Palm OS 4.1 m515 session as the fixed-base
benchmark. The Palm clock stays at 100 Hz.
[Fixed-base benchmark](../2026-11-20-dragonball-x25519-fixed-base)

## Results

| Operation | Stock (1×) | 16× |
|---|---:|---:|
| X25519 agreement, native 68K | 4.680 s | 290 ms |
| X25519 agreement, portable | 8.180 s | 510 ms |
| P-256 agreement | 7.310 s | 460 ms |
| X25519 fixed-base keygen + native agreement | 6.490 s | 400 ms |
| X25519 portable keygen + portable agreement | 16.350 s | 1,020 ms |
| P-256 keygen + agreement | 9.960 s | 620 ms |

Values are medians of five samples. The combined rows sum key generation
and agreement for each fixture before taking the median. Native agreement
took about 43% less time than portable X25519 and 36–37% less than P-256.
The native X25519 pair took about 35% less time than the P-256 pair.

[Stock samples](1x.csv) · [16× samples](16x.csv) · [Median and range](summary.csv) ·
[Build and session hashes](metadata.json)

## Implementation and timing

The native agreement path uses the RFC 7748 Montgomery ladder with the
same sixteen 16-bit limbs, carry folding, squaring, and inversion as the
fixed-base key generator. It multiplies by the public peer coordinate with
a single native word multiply per limb product and handles the ladder
constant 121665 with one word multiply and a shifted-limb contribution.
Products of secret operands keep the balanced pair of word multiplies.
The complete native object occupies 9,640 bytes of text and read-only
data, up 1,218 bytes from the fixed-base object.
[RFC 7748, §5](https://www.rfc-editor.org/rfc/rfc7748.html#section-5)

The ladder uses projective scaling and masked scalar transitions. The GCC
16.1.0 build was inspected to confirm the compiled conditional swap uses
masked XORs with only a loop branch. Both X25519 agreement paths receive
the same peer, scalar, projective scale, and swap-mask fixtures. Native
timing includes scalar clamping and preparation, peer decoding, the ladder,
and the all-zero check. The portable path starts with the clamped scalar and
mask prepared, and includes the all-zero check. All timings exclude entropy,
result comparison, and TLS.

The app checks six operations on five fixtures each, including the RFC
Alice/Bob shared secret. It also accepts the noncanonical encoding of the
base point, rejects a low-order input, and tests both with the high bit
set. Those two checks are outside the timed samples. The host differential
test matched 402 fixed-base outputs and 546 variable-base outputs and
acceptance decisions, including the RFC vectors, arbitrary peer inputs,
and noncanonical encodings under three scale and mask settings.
[RFC 7748, §5.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2) ·
[RFC 7748, §6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1)
