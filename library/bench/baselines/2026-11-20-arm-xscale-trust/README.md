# Cold trust setup on PXA255 and PXA270

The Tungsten E2 and Palm TX used the same saved CloudpilotEmu sessions
as the [previous XScale benchmark](../2026-11-20-arm-xscale/README.md).
Both ran at 100 MIPS. The baseline was `917dd98`. The local TLS 1.3
server used the same eight-root PEM bundle, P-256, and ChaCha20-Poly1305.
OpenSSL confirmed the negotiated group, cipher, and ticket resumption.

## Profiled cold open

| Phase | Tungsten E2 | Palm TX |
| --- | ---: | ---: |
| Engine load | 80 → 70 ms | 80 → 80 ms |
| Trust setup | **80 → 70 ms** | **80 → 70 ms** |
| Signature verification | 70 → 70 ms | 70 → 70 ms |
| P-256 key generation | 30 → 30 ms | 30 → 30 ms |
| P-256 key agreement | 35 → 35 ms | 30 → 30 ms |

Trust setup tied with engine loading for the largest cold-open phase.
The parser decodes the subject once when the issuer and subject have
identical DER encodings and no separate issuer metadata is needed.
Trust import captures the validation time at entry and reuses the Palm OS
UTC conversion for equal timestamps. Every anchor still goes through the
existing date checks. The time snapshot ends when the import returns.

## Unprofiled handshake medians

| Session | Cold full | Warm full | Resumed |
| --- | ---: | ---: | ---: |
| Tungsten E2 · PXA255 | **330 → 320 ms** | 140 → 140 ms | 90 → 90 ms |
| Palm TX · PXA270 | **340 → 330 ms** | 140 → 140 ms | 90 → 90 ms |

The primary comparison uses 15 unprofiled samples per case and build
across three fresh emulator sessions. The phase comparison uses 10
profiled samples per case and build across two sessions. The timer has
10 ms resolution and includes cold engine and trust setup. TCP
connection setup and application I/O occur outside the timer.

Name reuse alone measured 330 ms cold on both devices in 10 samples
per device. The main comparison uses the build with both changes. Its
packaged resources match the build produced by the standard toolchain.
`make check` and the emulator handshake regression suite passed.
Both devices also rejected an expired anchor and a not-yet-valid anchor
for the same server, then connected with the valid bundle.

[Timing summary](summary.csv) · [Individual samples](samples.csv) ·
[Phase profiles](profile-summary.csv) · [Build and fixture hashes](metadata.json)
