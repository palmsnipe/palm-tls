# Certificate signature cache on the Palm m515

The 68K TLS 1.3 engine keeps four successful ECDSA/SHA-256 issuer
signature checks per certificate manager. The SHA-256 key covers the
exact signed certificate bytes, issuer public key and signature with
their lengths. The normal verifier handles misses, including any
lookup hash failure. The cache is cleared when PalmTLS destroys the
context, including on a cache purge. Each connection still selects
the issuer, checks the certificate path, dates and hostname, and
verifies the live TLS 1.3 `CertificateVerify`.
[X.509 path validation](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3) ·
[TLS 1.3 CertificateVerify](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3)

The cache adds 130 bytes of fields per certificate manager. The full
68K PRC grew by 604 bytes, from 674,477 to 675,081 bytes.

## Measurement

The baseline is `e6f04df`. Both builds used the same CloudpilotEmu
binary, Palm OS 4.1 m515 session, benchmark PRC, and local OpenSSL
fixture with eight CA roots and one P-256 ECDSA leaf. Each build and
speed has five cold and five warm full TLS 1.3 handshakes. Cold
samples purge the engine and trust context first. The corresponding
warm sample reuses the context. The server confirmed X25519,
AES-128-GCM, one ClientHello, and full handshakes for every measured
connection. Times exclude TCP setup and engine load. The Palm clock
runs at 100 Hz, giving 10 ms resolution.

| CPU speed | Full handshake | Baseline median | Cache median | Change |
|---|---|---:|---:|---:|
| Stock (1×) | Cold | 12.020 s | 12.060 s | 40 ms slower |
| Stock (1×) | Warm | 11.770 s | 8.460 s | 3.310 s faster (28.1%) |
| 16× | Cold | 750 ms | 750 ms | 0 ms |
| 16× | Warm | 730 ms | 530 ms | 200 ms faster (27.4%) |

The median warm issuer signature scope dropped from 3.320 s to 20 ms
at stock speed and from 200 ms to below the 10 ms timer resolution at
16×. Median live `CertificateVerify` was 3.310 s at stock and 210 ms
at 16× on both warm builds.

[Summary and sample ranges](summary.csv) · [Build and fixture hashes](metadata.json)

- Stock speed [baseline](1x/baseline/results.csv) ·
  [cache](1x/cache/results.csv)
- 16× [baseline](16x/baseline/results.csv) ·
  [cache](16x/cache/results.csv)

## Verification

The native P-256 verifier ran twice on each baseline and cache-enabled
cold handshake and once on every cache-enabled warm handshake. The
issuer signature scope still measures cache-key hashing and lookup on a
hit. The live signature scope ran once per sample. The benchmark also
checked hostname and unknown CA rejection and a full TLS 1.2 handshake.
The host cache test exercised context isolation, changed certificate
bytes, signature and issuer key, signature failures, hash failure and
eviction.

[Reproduction commands](../../README.md#dragonball-tls-13-handshakes)
