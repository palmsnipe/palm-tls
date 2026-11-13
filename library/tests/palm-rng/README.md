# CloudpilotEmu random generator checks

Build the probe and all three TLS 1.3 library variants.

```sh
make -C library/tests/palm-rng test
make -C library TLS_PROFILE=tls13 test-prc
make -C library TLS_PROFILE=tls13 PALM_TLS_TEST_RANDOM=1 test-prc
make -C library TLS_PROFILE=tls13 PALM_TLS_TEST_RANDOM=seedless test-prc
```

In separate copies of a Tungsten E2 session, install the
`library/tests/palm-rng/build/PalmTlsRngTest.prc` and one
`PalmTLSArm-TLS13.prc` at a time. Launch **PalmTLS RNG Test**.

| PRC directory under `library/build` | Expected status |
| --- | --- |
| `insecure-test-random/palm` | PASS: seeded identity uses DRBG |
| `seedless-test/palm` | PASS: identity and TLS refuse no seed |
| `palm` | PASS: identity and TLS refuse no seed |

The seeded check compares the exported Ed25519 private key to the first
32 bytes of an independently calculated HMAC-DRBG stream. It also checks
that a second identity generated during the same library open uses a
different private key. The seedless checks call both public entry points
directly and expect `palmTlsStatusRandomUnavailable`.

The seeded probe also attempts a connection to a loopback listener on port
19444 when cp-uarm is started with native networking. The host check below
reads the ClientHello random and compares it to the same DRBG stream. Start
it before launching the probe with the seeded PRC installed.

```sh
python3 library/tests/palm-rng/check-client-hello.py
```

For the complete seeded TLS handshake, use the seeded PRC as `EMU_TLS_PRC` in
PalmSyncthing's `make test-emulator`. The test pairs with stock Syncthing
and checks both downloaded folders on a disposable FAT image.
