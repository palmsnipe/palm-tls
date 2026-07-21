# TLS Tester trust certificates

TLS Tester embeds these three issuing-CA certificates as DER resources:

| File | Subject | Expires | SHA-256 fingerprint | Source |
| --- | --- | --- | --- | --- |
| `gts-wr2.der` | Google Trust Services WR2 | 2029-02-20 | `E6:FE:22:BF:45:E4:F0:D3:B8:5C:59:E0:2C:0F:49:54:18:E1:EB:8D:32:10:F7:88:D4:8C:D5:E1:CB:54:7C:D4` | [Google Trust Services](https://pki.goog/repo/certs/wr2.pem) |
| `gts-we1.der` | Google Trust Services WE1 | 2029-02-20 | `A2:87:FF:AB:76:2C:C6:9A:26:D4:82:03:7E:DF:70:1F:65:3C:E8:99:02:5C:62:A7:E5:CB:88:BB:9B:41:9C:BB` | [Google Trust Services](https://pki.goog/repo/certs/we1.pem) |
| `letsencrypt-yr2.der` | Let's Encrypt YR2 | 2028-09-02 | `23:8B:85:A0:09:9C:65:B9:70:47:7D:57:24:F1:A1:D4:75:CE:50:58:CF:FE:4E:FA:87:33:89:9B:DB:86:3C:47` | [Let's Encrypt](https://letsencrypt.org/certs/gen-y/int-yr2.pem) |

Only these files are required by `resources/app.rcp` and the Makefile. Keeping
them in the repository makes builds offline and pins the exact trust material
embedded in a PRC. They are not a general Palm OS trust store: the user must
choose the issuer profile matching the test server's served chain.

Run `../tools/update-trust-store.sh` from this directory, or the documented
command from the repository root, to refresh them. The script downloads leaf
certificates into a temporary directory and verifies the expected Google,
Cloudflare, and Let's Encrypt chains before replacing these DER files. Review
fingerprints, validity dates, and documentation whenever they change.
