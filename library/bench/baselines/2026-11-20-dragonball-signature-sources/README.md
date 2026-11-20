# Certificate and live signature timing on the Palm m515

The measurement starts from commit `81baebe`. Signature source timers
partition the existing Signature phase into wolfSSL's `ConfirmSignature`
call for the issuer's certificate signature and
`DoTls13CertificateVerify` for the live handshake proof.
The profile stores the exclusive ticks and call count for each source.
[TLS 1.3 CertificateVerify](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3)

Each speed uses five cold and five warm full TLS 1.3 handshakes.
Both speeds use the same Palm OS 4.1 m515 image, CloudpilotEmu binary,
benchmark and library PRCs, and local OpenSSL fixture. The fixture has
the same P-256 ECDSA leaf and eight trust anchors as the Karatsuba run.
OpenSSL confirmed X25519, AES-128-GCM, and one ClientHello per measured
connection. The Palm clock runs at 100 Hz. The timers start after TCP setup
and report engine load separately.
[Karatsuba comparison](../2026-11-20-dragonball-x25519-karatsuba)

## Measured timings

| CPU speed | Full handshake | Issuer certificate signature | Live CertificateVerify | Full handshake time |
|---|---|---:|---:|---:|
| Stock (1×) | Cold | 3.330 s | 3.300 s | 12.010 s |
| Stock (1×) | Warm | 3.320 s | 3.280 s | 11.740 s |
| 16× | Cold | 210 ms | 200 ms | 750 ms |
| 16× | Warm | 210 ms | 210 ms | 730 ms |

Each value is the median of five samples. Each full handshake entered both
signature scopes once. The two scopes accounted for all signature ticks in
each sample. Individual medians can round differently from the median of
the sum.

[Summary and sample ranges](summary.csv) · [Stock samples](1x/results.csv) ·
[16× samples](16x/results.csv) · [Run and fixture hashes](metadata.json)

## Cache estimate

The gross cache-hit estimate subtracts only the certificate signature scope
from each warm handshake sample and takes the median of those projected
times. The measured scope includes certificate-signature preparation as
well as the cryptographic check. The estimate is an upper bound before
cache-key hashing and lookup time.

| CPU speed | Measured warm handshake | Ideal cache hit | Gross saving |
|---|---:|---:|---:|
| Stock (1×) | 11.740 s | 8.420 s | 3.320 s (28.3%) |
| 16× | 730 ms | 520 ms | 210 ms (28.8%) |

A bounded cache could reuse a successful cryptographic check for exactly the
same signed certificate bytes, signature, signature algorithm and parameters,
and selected issuer public key. Use the normal hostname, validity, and
trust-path checks on each connection. The live `CertificateVerify`
continues to prove possession of the leaf private key for the fresh
handshake transcript. [X.509 path validation](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1) ·
[TLS 1.3 CertificateVerify](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3)

`make check` passed. To print the split, pass `--signature-sources` to
`handshake_results.py` when reading the captured CSV.
[Reproduction commands](../../README.md#dragonball-tls-13-handshakes)
