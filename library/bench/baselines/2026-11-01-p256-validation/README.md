# Native P-256 public-key validation — 2026-11-01

`handshake/{baseline,baseline-repeat}` uses unchanged `feaadb3`.
`handshake/{optimized,repeat}` uses the final native validation implementation,
including stronger startup qualification. Both use identical detailed profiling,
application code, trust/leaf fixture, session/emulator and 100 MIPS. Only the
benchmark application's `armc:1` resource differs; the library also needs new
68K bridges and vendor hooks. `offline/` records the final native/integrated
self-test run, including both existing result sizes.

Reproduce the baseline by building `feaadb3` and running `run-handshake.py` as
shown in `library/bench/README.md`. Build the final source and rerun using
`--reuse-fixture` pointing to the first run's fixture and the same port/anchors.
Each run contains 30 timed connections, balanced main/ECDHE profiles, six
regression groups, and server confirmation of 20 full / 10 resumed TLS 1.3
connections. No validation is disabled to create the comparison.

Baseline native image: 34,224 bytes,
`e8a1178462e295ca8c80e0f541031c9587d5a80b8f1827e6c1782e10beaf9bbd`.
Final native image: 34,760 bytes,
`10a7c6649b46968ae19bf10259492e95edb8b48a535729977435516639d32ccd`.
Final library:
`ec2d255056c5daa394464a65f472fa815cc43e3a18888b880981b4c9801953c5`.
Manifests identify `feaadb3` plus uncommitted final changes for the candidate.

The Palm clock is 100 Hz; zero-tick validation still has an entry count and
performs the curve check. Load is separate from handshake time and includes
the stronger startup tests. These are local emulator measurements, not physical
Palm or Internet latency. See `library/PERFORMANCE.md` for results, validation
coverage, and limits. No private fixture keys, PRCs, SDKs, ROMs, or session
images are archived.
