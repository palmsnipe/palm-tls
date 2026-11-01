# Published 0.1.3 versus the 0.1.4 release candidate

## Final CI-built release verification

`ci-014-run1` and `ci-014-run2` repeat the same benchmark with the exact uploaded
GitHub Actions release asset from run **41349839326**, source/tag
`629ff27cd7ae7762a0cb2c3a30577b13eeea2236`. Both give medians **570 ms cold,
350 ms warm full, 170 ms resumed**. The published 0.1.3 baseline remains
1510/1320/580 ms: **62%, 73%, 71% less time**, respectively. Both versions now
use binaries from the same pinned GitHub CI toolchain image; the candidate
measurements below were local builds and are preserved separately.

Final PalmTLSArm.prc SHA-256:
`b44a1c08163d469e41c1e8ea63e8f3b239b4a042fca8f935269715261dc3db01`.
All three ARM protocol profiles share the same 38,224-byte native image:
`0de4dab953f66382ae925aea71c72b86056af326c3064d05571030e866027ac4`.
The exact CI native image also passes the independent crypto oracle suite on
both TI925T and PXA270 CPU models; see `ci-native-validation.txt`.
Every packaged/uploaded binary and ZIP was checked against the CI checksums
and GitHub release asset digests. The two final runs independently confirm
20 full and 10 resumed TLS 1.3 / ChaCha20-Poly1305 connections.

## Local candidate comparison

Two independent private-session runs per version, five samples per case per
run. Both runs reproduce cold medians **1510 → 570 ms**, warm full **1320 →
350 ms**, and resumed **580 → 160/170 ms**. All 60 server records independently
confirm TLS 1.3 / TLS_CHACHA20_POLY1305_SHA256: 40 full and 20 resumed connections.

The baseline is the actual GitHub v0.1.3 PalmTLSArm.prc, SHA-256
`748c7e900f7aa7ee61817e5dfe624e90136f6955f241f407350b25a5ada42063`.
The candidate includes the merged 0.1.3 ChaCha contribution and wolfSSL 5.9.4.
Its complete PRC/native digests, source, and compiler are in each manifest.
The old release was built by GitHub CI; the candidate by local Apple Clang.
These compare release implementations, not isolated algorithms/compiler effects.

The same `release.c` 68K code and public 0.1.3 ABI exercise both libraries, with
profiling disabled. Only the unused benchmark armc resource changes to match
the tested library for provenance. `bind-release-image.py` performs that copy.

The external 100 Hz Palm clock brackets SessionOpen and cooperative Handshake
continuations, including lazy engine load, trust/context setup and keyshare.
Old internal handshakeTicks omit setup, so they are diagnostic only. Cold
samples follow PurgeCache; warm full disables resumption; resumed enables it
and must report actual reuse. The first cold handshake receives a ticket
through a checked encrypted request/response before the subsequent samples.
Every connection validates the hostname and the same eight-root 4560-byte trust
bundle; no authentication checks are disabled. Only DNS/TCP setup, ticket read,
application I/O and cleanup are outside the timed interval.

cp-uarm uses the supplied OS5 Frankenpilot/E3 session at 100 MIPS and native
loopback NetLib redirection. This is not physical Palm/PXA270 or Internet timing.
The native image is additionally instruction-tested on TI925T and PXA270 models.
No SDK, ROM, session image, private key or executable is archived here.

To repeat, start `handshake-server.py` with eight anchors and Python/OpenSSL
with TLS 1.3, copy its generated `handshake_vectors.inc` into `library/build/bench`,
build `make -C library/bench release-bench`, then bind the benchmark's image to
each tested library. Use `run-emulator.py --release --network --prc APP
--library LIB --handshake-fixture FIXTURE --emulator CP_UARM --session SESSION
--output NEW_DIRECTORY`. Keep the same server/fixture for all versions and run
serially. `release_results.load`, `summarize`, and `validate_server` validate the
export and independent server log. The fixture certificates expire in 2040.
