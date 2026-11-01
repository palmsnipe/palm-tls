# Cold startup and trust loading — 2026-11-01

`handshake/{baseline,baseline-repeat}` uses `995460c` plus
`baseline-support.patch`, which adds the 400-byte loader/trust profiler and
benchmark support. It retains the old relocation, CA decoder selection, and
startup-vector initialization. Build dependencies after applying the patch.
`handshake/{optimized,repeat}` uses the final optimizations with identical
profiling/application code and the same eight-root fixture.

Follow `library/bench/README.md` and use `--reuse-fixture` with identical
port/anchors when switching builds. Each run contains 30 timed connections,
780 main phase rows, 150 ECDHE rows, 210 loader rows and 150 trust rows, with
six regression groups and independent server confirmation of 20 full and
10 resumed TLS 1.3 connections. All validation remains enabled.

`handshake/legacy-profile` runs an unchanged older app using the 240/288-byte
profile APIs against the final library. `offline` executes both 52/188-byte
self-test APIs and the existing native math workloads. Its native image is
unchanged at 34,760 bytes:
`10a7c6649b46968ae19bf10259492e95edb8b48a535729977435516639d32ccd`.
Final library:
`8007c33fbd8f9fcf1176150278173a3fb8a3db46f5fa687da3f813f0b718cecd`.
Manifests identify `995460c` plus uncommitted profiling/optimization changes.

The Palm clock is 100 Hz. Paired cold totals have medians 660/660 ms before
and 580/570 ms after; medians of individual phases/components need not sum.
Measurements include profiling overhead on the supplied Frankenpilot/E3
session at 100 MIPS. They exclude caller DNS/TCP setup and do not establish
physical-device or Internet latency. No serialized CA cache is restored;
certificate restrictions and the required trust set remain intact.

No private keys, SDKs, PRCs, ROMs or session images are archived.
