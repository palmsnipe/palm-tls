# ARM cold and resumed handshake recovery

The shipped v0.1.10 ARM library and the build at `5848798` were both
rerun on the same CloudpilotEmu Palm OS 5 session at 100 MIPS. Every build
used P-256 key exchange, ChaCha20-Poly1305, the same certificate and the
same eight-root trust bundle. Medians use ten unprofiled samples per
case across two fresh sessions. The 100 Hz timer covers SessionOpen
and its continuations, including cold engine load and trust setup.
It excludes TCP setup and subsequent application I/O.

## Handshake medians

| Build | Cold full | Warm full | Resumed |
| --- | ---: | ---: | ---: |
| Published v0.1.10 | 310 ms | 170 ms | 100 ms |
| Starting build | 330 ms | 150 ms | 110 ms |
| Single-pass relocations | 320 ms | 150 ms | 100 ms |
| Relocations and native HKDF | **300 ms** | **140 ms** | **90 ms** |

The final cold range was 300–310 ms, compared with 310–320 ms on v0.1.10.
The final resumed range was 80–90 ms, compared with 100 ms on v0.1.10.
OpenSSL independently confirmed the full handshakes and ticket resumption.

## Profile and changes

| Profiled phase | Starting build | Final |
| --- | ---: | ---: |
| Cold engine load | 60 ms | 50 ms |
| Cold relocation within engine load | 40 ms | 20 ms |
| Cold trust setup | 80 ms | 80 ms |
| Resumed key derivation | 30 ms | 10 ms |

The loader applies each consecutive run of same-segment relocations
in one pass. It relocates the writable segment in memory and still
uses `DmWrite` for storage resources. Bounds, alignment, and allocation
and write failure handling remain in the loader.

The ARM TLS 1.3 engine sends short HKDF-SHA256 extracts and single-block
expansions to the ARMlet in one call. The ARMlet reuses native SHA-256
compression. The bridge clears the copied key, message and digest and
uses the software HKDF for unsupported requests or native failures.
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#section-2)

The final build passed the ARM emulator regression suite and an
AES-256-GCM/SHA-384 smoke run. Independent host, TI925T and PXA270
crypto oracles checked HMAC-SHA256 on both sides of the padding boundary.
`make check` and the loader bounds and error tests passed. The shared loader
also passed the DragonBall m515 handshake regression at 16×.

[Timing summary and sample ranges](summary.csv) · [Profile summary](profile-summary.csv) ·
[Build and fixture hashes](metadata.json)
