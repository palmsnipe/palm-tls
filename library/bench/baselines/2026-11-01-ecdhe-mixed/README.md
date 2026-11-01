# ECDHE mixed-coordinate comparison — 2026-11-01

`handshake/{baseline,baseline-repeat}` contains the old native kernel with the
new detailed profiler; `handshake/{optimized,repeat}` contains the final mixed
kernel with identical profiling/application code. Both repeats use the same
public CA/leaf fixture. Each run has 30 timed connections, 780 main phase rows,
150 ECDHE rows, six regression groups, and independent server confirmation.
`native/` contains the offline native and integrated self-test measurements.

Apply `baseline-support.patch` to `6adbf09`, run `JOBS=8 scripts/bootstrap.sh`,
and build/run the commands in `library/bench/README.md` to reproduce the
instrumented baseline. Apply the final change in `library/arm/multiply.c` for
the optimized build, keeping fixtures and all other code/settings unchanged.
The support patch includes the additional vendor patch and profiler tests.

Manifests record `6adbf09` plus uncommitted benchmark/profiling/kernel changes.
Native baseline image: 33,904 bytes,
`4c8e5b1840f1a1807324ebd307fd89872902df00d65586d0e9ba4a2792a2d743`.
Final image: 34,224 bytes,
`e8a1178462e295ca8c80e0f541031c9587d5a80b8f1827e6c1782e10beaf9bbd`.
Both library and handshake PRCs differ only in `armc:1`.

All data uses the supplied Frankenpilot/E3 OS 5 session at 100 MIPS and the
same Cloudpilot binary. Timings include profiling, use a 100 Hz Palm clock,
and do not establish physical-device or Internet latency. See
`library/PERFORMANCE.md` for boundaries, range/exception handling, validation,
and the retained result's measured limits. Private development keys, ROMs,
session images, PRCs, and SDKs are excluded.
