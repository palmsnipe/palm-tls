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

fetch_pem gts-wr2 https://pki.goog/repo/certs/wr2.pem "CN=WR2"
fetch_pem gts-we1 https://pki.goog/repo/certs/we1.pem "CN=WE1"
fetch_pem le-yr2 https://letsencrypt.org/certs/gen-y/int-yr2.pem "CN=YR2"
fetch_leaf google-leaf google.com
fetch_leaf cloudflare-leaf api.hattiwatt.com
fetch_leaf letsencrypt-leaf valid-isrgrootx1.letsencrypt.org

openssl verify -partial_chain -trusted "$TEMP/gts-wr2.pem" "$TEMP/google-leaf.pem" >/dev/null
openssl verify -partial_chain -trusted "$TEMP/gts-we1.pem" "$TEMP/cloudflare-leaf.pem" >/dev/null
openssl verify -partial_chain -trusted "$TEMP/le-yr2.pem" "$TEMP/letsencrypt-leaf.pem" >/dev/null

mkdir -p "$CERT_DIR"
openssl x509 -in "$TEMP/gts-wr2.pem" -outform DER >"$CERT_DIR/gts-wr2.der"
openssl x509 -in "$TEMP/gts-we1.pem" -outform DER >"$CERT_DIR/gts-we1.der"
openssl x509 -in "$TEMP/le-yr2.pem" -outform DER >"$CERT_DIR/letsencrypt-yr2.der"

echo "Updated the three TLS Tester issuer certificates in $CERT_DIR"
for certificate in gts-wr2 gts-we1 letsencrypt-yr2; do
    openssl x509 -inform DER -in "$CERT_DIR/$certificate.der" \
        -noout -subject -dates -fingerprint -sha256
done
