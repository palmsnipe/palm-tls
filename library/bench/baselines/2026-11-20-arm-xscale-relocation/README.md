# Storage-backed engine relocation on XScale

Grouping relocations by target bank at build time saved 10 ms on the median
cold TLS 1.3 open on both boards (3.1%). The baseline is the committed
[storage-backed loader](../2026-11-20-arm-xscale-loader/README.md) at
`84c45a3`. Both builds were run again on the same Tungsten E2 and Palm TX
CloudpilotEmu sessions at 100 MIPS.

| Median, baseline → grouped | Tungsten E2 (PXA255) | Palm TX (PXA270) |
| --- | ---: | ---: |
| Cold relocation phase | 20 → 10 ms | 20 → 10 ms |
| Cold engine load | 70 → 70 ms | 80 → 70 ms |
| Cold full handshake, including engine load | 320 → 310 ms | 320 → 310 ms |
| Warm full handshake | 140 → 140 ms | 140 → 140 ms |
| Resumed handshake | 90 → 90 ms | 90 → 90 ms |

The open and engine-load medians use 15 unprofiled samples per case, build,
and board over three fresh sessions. A cold sample purges the cached engine
before opening TLS. The open timer starts after TCP connects and ends when TLS
is ready for application I/O. The server confirmed P-256, ChaCha20-Poly1305,
and the expected full or resumed connection against the same eight-root fixture.

The relocation phase includes copying the source, fixing pointers, and writing
the result to storage. Its timings come from two separate profiled sessions per
build and board, with 20 cold opens across the cache-on and cache-off workloads.
The Palm timer advances in 10 ms steps. Across all 20 opens, mean relocation
time fell from 20.5 to 12.0 ms on the E2 and from 21.0 to 12.0 ms on the TX.

## Heap and image size

The ARM TLS 1.3 loader applies the same 4,136 fixups. The build groups them
into 25 source/target bank pairs and stores their halfword offsets. The
relocation resource shrank from 24,820 to 8,396 bytes. The engine segments
and native crypto image are byte-identical. Both loaders allocate at most
one segment of relocation scratch, 63,052 bytes for this engine, and release
it before the handshake.

A separate test app reserved dynamic memory until 539,992 bytes were free.
Each build completed five cold, five warm, and five resumed handshakes per
board. The app confirmed the work database on every cold open and sampled
free heap after TLS opened, before application I/O. The two builds produced
identical free-heap readings at every corresponding sample, including
458,776 bytes on the first cold E2 open and 458,736 bytes on the TX.

The old and new generators produced the same relocation sites across all
seven engine builds, including the ARM browser profile. The package validator
checks each grouped target against its linked pointer. The host loader test
compares the resulting segment bytes, allocation behavior, and storage writes
for both formats. `make check`, the ARM handshake regression suite on both
boards, and the m515 TLS 1.3 and TLS 1.2 regressions at 16× passed.

[Timing summary](summary.csv) · [Unprofiled opens](samples.csv) ·
[Cold loader samples](loader-samples.csv) · [Heap measurements](heap-samples.csv) ·
[Binary and fixture hashes](metadata.json)
