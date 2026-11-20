# Native X25519 and P-256 TLS 1.3 handshakes on the m515

The 68K TLS 1.3 engine generates its initial X25519 key share using the
fixed-base comb and computes the shared secret with the native 16-bit
Montgomery ladder. P-256 remains available as a key exchange group and
for ECDSA certificate verification. The engine obtains the blinding inputs
from wolfSSL's configured RNG. The X25519 routines live in the read-only
TLS 1.3 code segment. [Native agreement benchmark](../2026-11-20-dragonball-x25519-agreement)

## Results

| CPU speed | Full TLS 1.3 handshake | P-256 | Native X25519 | Time saved |
|---|---|---:|---:|---:|
| Stock (1×) | Cold | 18.740 s | 15.240 s | 18.7% |
| Stock (1×) | Warm | 18.520 s | 14.990 s | 19.1% |
| 16× | Cold | 1,160 ms | 950 ms | 18.1% |
| 16× | Warm | 1,150 ms | 930 ms | 19.1% |

Values are medians of five handshakes. At stock speed the warm key-share
phase fell from 2.670 s to 1.810 s, and key agreement fell from 7.350 s to
4.680 s. The signature phase took 7.830 s on the warm X25519 runs.

The X25519-first production PRC also completed all ten connections to the
P-256-only fixture at 16×. Each successful handshake negotiated P-256 after
two ClientHellos. The retry medians were 1,280 ms cold and 1,260 ms warm.

[Stock P-256 samples](1x/p256/results.csv) · [Stock X25519 samples](1x/x25519/results.csv) ·
[16× P-256 samples](16x/p256/results.csv) · [16× X25519 samples](16x/x25519/results.csv) ·
[Retry server log](16x/x25519-retry/server-connections.jsonl) ·
[Summary and phase timings](summary.csv) · [Build and session hashes](metadata.json)

## Method

- Both builds link the same wolfSSL archive and 68K implementations. The
  benchmark control selects P-256 for the initial key share. The production
  build selects X25519. The two library resource payloads differ by one byte
  in the initial group ID.
- Both runs use the same Palm OS 4.1 m515 session, CloudpilotEmu DragonBall
  binary, benchmark PRC, localhost endpoint and OpenSSL fixture. The fixture
  uses the same P-256 ECDSA certificate, eight trust anchors and
  TLS_AES_128_GCM_SHA256. Only its offered key exchange group changes.
- Each group and clock setting has five cold and five warm full handshakes.
  The benchmark purges the library cache before each cold connection. The
  warm connection reuses the TLS context and trust store and still performs
  fresh key agreement and certificate verification. Times use the Palm
  clock at 10 ms resolution. Engine load is reported separately, and
  socket setup takes place before the timer.
- The server reads the negotiated group from ServerHello and confirms a
  single ClientHello for every comparison sample. The separate P-256
  fallback test uses the production X25519 build against a P-256-only
  server and verifies the second ClientHello. Every run exercises hostname
  and CA rejection and a full TLS 1.2 handshake.
  [TLS 1.3 key share and retries](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8)

[Reproduction commands](../../README.md#dragonball-tls-13-handshakes)
