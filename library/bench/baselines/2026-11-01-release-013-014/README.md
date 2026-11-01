# Published 0.1.3 versus the 0.1.4 release candidate

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
