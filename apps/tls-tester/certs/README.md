# TLS Tester trust certificates

TLS Tester embeds these three issuing-CA certificates as DER resources:

| File | Subject | Expires | SHA-256 fingerprint | Source |
| --- | --- | --- | --- | --- |
| `gts-we2.der` | Google Trust Services WE2 | 2029-02-20 | `54:F8:CA:85:8B:CC:75:91:F2:8D:8D:C3:77:2E:9B:C5:81:71:7F:3A:23:A2:88:BF:D4:05:93:9C:36:20:8D:E5` | [Google Trust Services](https://pki.goog/repo/certs/we2.pem) |
| `gts-we1.der` | Google Trust Services WE1 | 2029-02-20 | `A2:87:FF:AB:76:2C:C6:9A:26:D4:82:03:7E:DF:70:1F:65:3C:E8:99:02:5C:62:A7:E5:CB:88:BB:9B:41:9C:BB` | [Google Trust Services](https://pki.goog/repo/certs/we1.pem) |
| `letsencrypt-yr1.der` | Let's Encrypt YR1 | 2028-09-02 | `13:94:96:34:D9:9C:D6:FD:6A:A8:0B:C0:34:FE:FA:CC:EB:19:69:FE:EF:98:65:86:71:3E:CD:BB:05:75:8D:3F` | [Let's Encrypt](https://letsencrypt.org/certs/gen-y/int-yr1.pem) |

These are the issuers currently served for the app's three test hosts:
`google.com` (WE2), `www.cloudflare.com` (WE1), and
`valid-isrgrootx1.letsencrypt.org` (YR1).

Only these files are required by `resources/app.rcp` and the Makefile. Keeping
them in the repository makes builds offline and pins the exact trust material
embedded in a PRC. They are not a general Palm OS trust store: the user must
choose the issuer profile matching the test server's served chain.

Run `../tools/update-trust-store.sh` from this directory, or the documented
command from the repository root, to refresh them. The script downloads leaf
certificates into a temporary directory and verifies the expected Google,
Cloudflare, and Let's Encrypt chains before replacing these DER files. Review
fingerprints, validity dates, and documentation whenever they change.

Google moved its public sites from WR2 to WE2, and Let's Encrypt's
`valid-isrgrootx1.letsencrypt.org` test host moved from YR2 to YR1; the earlier
`gts-wr2.der` and `letsencrypt-yr2.der` files were retired for that reason.
The Let's Encrypt ECDSA generation-Y chain signs with SHA-384, which the
`full` profile does not enable, so the test host uses the RSA YR1 intermediate
and SHA-256 signatures. A provider can change its chain before an issuer
certificate expires, so rerun the refresh script when a verification test
starts failing with `ASN_NO_SIGNER_E` (`-188`).
