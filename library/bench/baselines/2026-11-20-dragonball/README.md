# Palm m515 arithmetic and initialization

Five cumulative changes reduced the TLS 1.3 handshake median by 70 ms for
both cold and warm contexts. The baseline and final medians repeated in
independent runs. Cold time including engine load fell from 2,230 to 2,160 ms.

| Build | Change since previous build | Cold handshake | Warm handshake |
| --- | --- | ---: | ---: |
| Baseline | `43c4356` | 2,210 ms | 2,200 ms |
| 1 | Reuse the unrolled 68K digit-clear loop for TFM initialization and cleanup | 2,190 ms | 2,170 ms |
| 2 | Process two Comba products per loop branch, with an odd-count prefix | 2,180 ms | 2,170 ms |
| 3 | Unroll four carry steps per branch in 256-bit modular add and subtract, and select two digits at a time | 2,180 ms | 2,150 ms |
| 4 | Split conditional integer copies into their common prefix and zero-extended tails | 2,150 ms | 2,120 ms |
| 5 | Initialize fixed-size TFM points once and copy into fresh integers directly | 2,140 ms | 2,130 ms |
| Baseline repeat | Same baseline PRC | 2,210 ms | 2,200 ms |
| Round 4 repeat | Same round 4 PRC | 2,140 ms | 2,130 ms |
| Round 5 repeat | Same round 5 PRC | 2,140 ms | 2,130 ms |

Round 2's difference was at most one Palm tick in the handshake medians.
Rounds 4 and 5 had the same medians on repeat. Round 5 eliminates duplicate
initialization and makes the full PRC 240 bytes smaller than round 4. The
final PRC is 625,887 bytes, 100 bytes larger than the baseline.

Every run used CloudpilotEmu's DragonBall CLI, the same Palm m515 English
Palm OS 4.1 session, and 16× CPU overclock. Five paired cold/warm samples
used TLS 1.3, P-256, AES-128-GCM and the same eight-root CA bundle. The 100 Hz
clock gives 10 ms resolution. Timings include TLS setup and exclude socket
setup. Warm samples reuse the context and perform full handshakes. These
timings apply to the overclocked emulator and this local TLS fixture.

The benchmark checks bad CA and hostname rejection. Each server log confirms
the ten timed TLS 1.3 connections and one successful TLS 1.2 regression.
The project checks and all library profile packaging checks passed. The
normal build reproduced all 18 measured PRC resources byte for byte.

The linked 68000 code passed 6,990 independent Python integer checks under
Unicorn 2.1.4. The vectors cover in-place operands, empty and odd Comba
columns, full carry and borrow chains, zero extension, and both conditional
copy flags. With Unicorn installed, run the oracle from the repository root
after building the library:

```sh
python3 library/bench/baselines/2026-11-20-dragonball/tfm-oracle.py \
  library/build/palm/68k/library-tls13.elf \
  ../palm-toolchain/.toolchain/prefix/bin/m68k-none-elf-nm
```

[Summary CSV](summary.csv) · [Build and input hashes](metadata.json) ·
[Reproduction commands](../../README.md#dragonball-tls-13-handshakes)
