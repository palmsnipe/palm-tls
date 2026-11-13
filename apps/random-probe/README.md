# Palm Random Probe

Build and validate the diagnostic PRC from the PalmTLS checkout.

```sh
make -C apps/random-probe test
```

Install `apps/random-probe/build/PalmRandomProbe.prc` on the target Palm and
launch **Palm Random Probe**. Record the handheld model and firmware revision
along with a photo or transcription of the report. Repeat after a cold power
cycle if the device supports one. The probe displays Palm OS feature values,
the number of CPM providers, and the provider's ID and name when CPM lists
exactly one. It calls `CPMLibGenerateRandomBytes` twice for 32 bytes each. On the
`RNG` line, each pair shows a hexadecimal error code followed by the returned
length in bytes. The probe clears both blocks and displays only whether they
match.

This checks API availability, request success, and block length. Qualifying a
provider for production requires evidence about its entropy source and how it
seeds and reseeds across boots. Two differing output blocks only show that the
API returned different bytes on those calls. Use the provider's design
documentation or an assessment of its noise source. The diagnostic PRC does
not participate in identity generation or TLS.

See the [Tungsten E2 firmware trace](tungsten-e2.md) for the stock Garnet 5.4.7
provider's clock-based initialization and the emulator comparison.
