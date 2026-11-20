# 68K X25519 versus P-256 on the Palm m515

The same standalone PRC ran at stock CPU speed and 16× in the CloudpilotEmu
DragonBall CLI. Both runs used a 100 Hz Palm clock and the same emulator and
Palm OS 4.1 m515 session as the earlier work.
[68K P-256 verification benchmark](../2026-11-20-dragonball-field-ecdsa)

| CPU speed | Curve | Key generation | Agreement | Combined |
|---|---|---:|---:|---:|
| Stock (1×) | P-256 | 2.650 s | 7.310 s | 9.960 s |
| Stock (1×) | X25519 | 8.180 s | 8.180 s | 16.350 s |
| 16× | P-256 | 0.160 s | 0.460 s | 0.620 s |
| 16× | X25519 | 0.510 s | 0.510 s | 1.020 s |

Portable X25519 took about 64% longer for the pair at both speeds. Key
generation accounts for most of the gap. The compiled X25519 field uses
software 64-bit multiplication, and its base-point path uses the full
Montgomery ladder. Those are the two areas to measure first in a 68K-tuned
implementation.

[Stock samples](1x.csv) · [16× samples](16x.csv) · [Median and range](summary.csv) ·
[Build and session hashes](metadata.json)

## Method

- P-256 uses the production fixed-base key generation and variable-base
  agreement in revision `ce35fee`, with projective blinding. The keygen
  interval ends after serialization of the 65-byte uncompressed public key.
  The agreement interval includes peer validation and ends with the 32-byte
  shared secret.
- X25519 uses the pinned wolfSSL 5.9.4 portable C Montgomery ladder with its
  default scalar and projective blinding. It uses the same ladder for the base
  point and the peer point. Keygen produces a 32-byte public key. Agreement
  includes checking the 32-byte shared secret for an all-zero result.
- Both curves start with prepared scalars, peer keys, and deterministic
  blinding inputs. The timed interval excludes random byte generation, input
  preparation, result comparison, and TLS. Node's OpenSSL backend generated the
  expected outputs except for the first X25519 fixture, which uses the
  published Alice/Bob example. [RFC 7748, §6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1)
- Each operation has five distinct fixtures per CPU setting. The app alternates
  which curve runs first by fixture and checks each result byte for byte before
  recording the timing. The raw CSVs contain Palm ticks. The combined median is
  calculated by adding key generation and agreement for each fixture, then
  taking the median.
