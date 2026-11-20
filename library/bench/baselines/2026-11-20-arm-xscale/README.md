# Five XScale optimization rounds

The starting build was `bfc43d5`. CloudpilotEmu ran the same eight-root
TLS 1.3 fixture on a saved Tungsten E2 session (PXA255) and a saved
Palm TX session (PXA270). Each used P-256 and ChaCha20-Poly1305 at
100 MIPS. OpenSSL confirmed the group, cipher, and ticket resumption.
[Palm Developer Guide, hardware feature matrix](https://device.report/m/82681e9073223ef85a08e7bf44e5b7fe5d64287ef4124c1ac90ab5d9fd83243c.pdf)

| Round | Trial | Change from its reference | Decision |
| --- | --- | --- | --- |
| 1 | Eight-round SHA-256 loop | 5,808 fewer image bytes and 26.4% more SHA-256 instructions | Rejected |
| 2 | Word stores for aligned secret buffers | 8.5% fewer HMAC-SHA256 instructions | Retained |
| 3 | Paired loads in P-256 field addition and subtraction | 0.6% fewer P-256 verification instructions | Retained |
| 4 | Hand-written private P-256 table scan | 4.2% more fixed-base key generation instructions | Rejected |
| 5 | Word-wide preparation of HMAC pads | 4.8% fewer HMAC-SHA256 instructions | Retained |

Each trial starts from the last retained code. The combined build uses
12.8% fewer HMAC-SHA256 instructions, 1.6% fewer SHA-512 compression
instructions, and 0.4% fewer P-256 key agreement instructions. The ARM
resource grew from 63,300 to 63,420 bytes and retains the common ARMv4T
instruction set. Unicorn counts translated instructions on the same test
vectors for both XScale CPU models. The counts measure instruction work
and the handshake measurements include Palm OS scheduling and network waits.

## TLS 1.3 handshake medians at 100 MIPS

| CloudpilotEmu session | Cold full | Warm full | Resumed |
| --- | ---: | ---: | ---: |
| Tungsten E2, PXA255 | 330 → 330 ms | 140 → 140 ms | 80 → 90 ms |
| Palm TX, PXA270 | 340 → 340 ms | 140 → 140 ms | 90 → 90 ms |
| Frankenpilot, prior benchmark session | 300 → 300 ms | 140 → 140 ms | 90 → 85 ms |

The E2 and TX baseline and final totals each use 20 samples per case
across four fresh sessions. The intermediate builds and the Frankenpilot
comparison use 10 per case. Each sample has 10 ms resolution. The timer
covers the cooperative session open, including cold engine and trust
setup. TCP setup and application I/O occur outside the timer.

E2 resumption spanned 80–90 ms in both builds at 100 MIPS. The median
shift changed direction at 50 MIPS, from 180 ms to 170 ms, with both
builds spanning 170–180 ms in that control. The two speeds produced
equal cold and warm medians within each comparison. The full handshake
tests establish no consistent latency gain.

`make check` and the independent crypto oracles on TI925T, PXA255, and
PXA270 passed, including the private P-256 instruction and address trace
checks and ChaCha key clearing at all four request alignments. The regular
Palm build matched the round-five resource contents. The final TX
session also completed five samples per handshake case with
AES-256-GCM/SHA-384.

[Instruction counts](instructions.csv) · [Handshake summary](summary.csv) ·
[Individual timing samples](samples.csv) · [Build and fixture hashes](metadata.json)
