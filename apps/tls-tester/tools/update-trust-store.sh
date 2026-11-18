#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
CERT_DIR="$APP_ROOT/certs"
TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT

fetch_pem() {
    local name="$1" url="$2" expected="$3"
    curl --retry 4 --retry-all-errors -fsSL "$url" -o "$TEMP/$name.pem"
    openssl x509 -in "$TEMP/$name.pem" -noout -subject | grep -F "$expected" >/dev/null
}

fetch_leaf() {
    local name="$1" host="$2"
    openssl s_client -connect "$host:443" -servername "$host" -showcerts \
        </dev/null 2>/dev/null | awk '
            /-----BEGIN CERTIFICATE-----/ { if (++count == 1) capture=1 }
            capture { print }
            /-----END CERTIFICATE-----/ { if (capture) exit }
        ' >"$TEMP/$name.pem"
    openssl x509 -in "$TEMP/$name.pem" -noout -checkend 86400 >/dev/null
}

# Google now serves its public sites from WE2; WE1 is still the issuer for the
# Cloudflare-hosted test site. Let's Encrypt's ECDSA generation-Y chain signs
# with SHA-384, which the full profile does not enable, so the test host uses
# the RSA YR1 intermediate and SHA-256 signatures.
fetch_pem gts-we2 https://pki.goog/repo/certs/we2.pem "CN=WE2"
fetch_pem gts-we1 https://pki.goog/repo/certs/we1.pem "CN=WE1"
fetch_pem le-yr1 https://letsencrypt.org/certs/gen-y/int-yr1.pem "CN=YR1"
fetch_leaf google-leaf google.com
fetch_leaf cloudflare-leaf www.cloudflare.com
fetch_leaf letsencrypt-leaf valid-isrgrootx1.letsencrypt.org

openssl verify -partial_chain -trusted "$TEMP/gts-we2.pem" "$TEMP/google-leaf.pem" >/dev/null
openssl verify -partial_chain -trusted "$TEMP/gts-we1.pem" "$TEMP/cloudflare-leaf.pem" >/dev/null
openssl verify -partial_chain -trusted "$TEMP/le-yr1.pem" "$TEMP/letsencrypt-leaf.pem" >/dev/null

mkdir -p "$CERT_DIR"
openssl x509 -in "$TEMP/gts-we2.pem" -outform DER >"$CERT_DIR/gts-we2.der"
openssl x509 -in "$TEMP/gts-we1.pem" -outform DER >"$CERT_DIR/gts-we1.der"
openssl x509 -in "$TEMP/le-yr1.pem" -outform DER >"$CERT_DIR/letsencrypt-yr1.der"

echo "Updated the three TLS Tester issuer certificates in $CERT_DIR"
for certificate in gts-we2 gts-we1 letsencrypt-yr1; do
    openssl x509 -inform DER -in "$CERT_DIR/$certificate.der" \
        -noout -subject -dates -fingerprint -sha256
done
