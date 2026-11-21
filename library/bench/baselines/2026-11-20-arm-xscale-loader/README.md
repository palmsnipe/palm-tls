# Cold engine loading on PXA255 and PXA270

The comparison starts from `c3eb3bf`, the [XScale trust setup
build](../2026-11-20-arm-xscale-trust/README.md). It uses the same
Tungsten E2 and Palm TX CloudpilotEmu sessions at 100 MIPS and the
same TLS 1.3 fixture with eight trusted roots, P-256, and
ChaCha20-Poly1305. OpenSSL confirmed the cipher, group, and ticket
resumption.

## Cold TLS 1.3 handshake medians

| Session | Baseline | Heap experiment | Revised storage loader |
| --- | ---: | ---: | ---: |
| Tungsten E2 · PXA255 | 320 ms | 290 ms | 320 ms |
| Palm TX · PXA270 | 320 ms | 290 ms | 320 ms |

Each median uses 15 samples per case and build from three fresh
sessions. The timer has 10 ms resolution. Cold-open times include
engine loading, trust setup, and the TLS handshake. TCP setup and
application I/O are outside the timer. All three builds recorded
140 ms warm-full and 90 ms resumed medians on both devices.

The separate phase profiles include 10 samples per case and build
from two fresh sessions. The experimental heap-backed loader brought
the 30 ms work-database setup phase below one timer tick.

## Memory use

The heap experiment held about 236 KiB of additional dynamic memory
until unload. Its free-memory check covered the load itself. An app
could need that space later, after parsing a page or allocating an
image.

The revised loader keeps the read-only engine segments in storage.
For each segment, it loads and relocates the source in one temporary
segment-sized buffer and writes the result to storage once. The
writable data segment is initialized directly in the heap. The
largest temporary buffer for the measured build is 63,052 bytes,
freed before the handshake starts. The host test covers both grouped
and ungrouped relocation tables, relocation bounds, and failure
handling.

With 539,992 bytes of free heap before each test run, the revised
build completed five cold, five warm, and five resumed handshakes
on each emulator. `make check`, the ARM handshake regressions, and
the m515 TLS 1.3 and TLS 1.2 regression at 16× passed.

[Timing summary](summary.csv) · [Individual samples](samples.csv) ·
[Loader phase profiles](profile-summary.csv) · [Build and fixture hashes](metadata.json)
