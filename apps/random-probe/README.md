# Palm Random Probe

Build and validate the diagnostic PRC from the PalmTLS checkout.

```sh
make -C apps/random-probe test
```

Install `apps/random-probe/build/PalmRandomProbe.prc` into internal memory and
launch **Palm Random Probe**. No network, seed file, or other app is needed.

1. Photograph the full report. Tap **OK** and launch the probe twice more.
2. If the report says `already open` or `timing missed`, record that result.
   If convenient, repeat once immediately after an ordinary soft reset,
   before opening any other apps.
3. Report the photos or transcribe the displayed lines. Mention which run
   followed a soft reset and whether the TX has custom firmware or a third-party
   cryptographic provider installed.

The `Code` line gives the byte length and CRC-32 of the installed CPM
library's ARM resource (`amdc` ID 0). This identifies which firmware code to
compare with the trace. The `RNG` line shows the error and length of two
32-byte calls under one open. `One open` compares those blocks. `Same sec`
compares the first blocks from separate successful opens within one clock
second. `Next sec` compares against the first block from an open in the
following second. The app waits for normal clock ticks and wipes samples after
comparing them. If CPM is already open, the probe skips sampling and leaves
the existing open alone.

`Same sec MATCH` shows that fresh opens repeated their first block. Differing
blocks do not establish that a generator has an unpredictable seed.
Qualifying a source for TLS requires evidence of where its entropy comes from
and how it behaves when restarted. The probe never supplies bytes to PalmTLS.

See the [Tungsten E2 firmware trace](tungsten-e2.md) for the stock Garnet 5.4.7
provider's clock-based initialization and the emulator comparison.
The [Palm TX trace](palm-tx.md) identifies the same initialization path in the
examined Garnet 5.4.9 image.
