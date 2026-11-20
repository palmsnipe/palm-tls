#!/usr/bin/env python3
"""Exercise the actual wolfSSL certificate signature cache with a verifier stub."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

vendor = Path(__file__).resolve().parents[2] / '.palm-tls/src/wolfssl'
source = (vendor / 'wolfcrypt/src/asn.c').read_text()
start = source.index('static int PalmCertSignatureKey(')
end = source.index('\n\n\n#ifndef IGNORE_NAME_CONSTRAINTS', start)
cache = '#ifdef PALM_WOLFSSL_CERT_SIGNATURE_CACHE\n' + source[start:end]
header = (vendor / 'wolfssl/internal.h').read_text()
size = header.index('#define PALM_CERT_SIGNATURE_CACHE_SIZE ')
fields = header.index('    byte            palmCertSignatures[')
manager = (header[size:header.index('\n', size)] + '\ntypedef struct {\n' +
           header[fields:header.index('#endif', fields)] + '} WOLFSSL_CERT_MANAGER;')

with tempfile.TemporaryDirectory() as directory:
    build = Path(directory)
    unit = build / 'test.c'
    unit.write_text('''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#define PALM_WOLFSSL_CERT_SIGNATURE_CACHE
#define WC_SHA256_DIGEST_SIZE 32
#define XMEMCMP memcmp
#define XMEMCPY memcpy
typedef uint8_t byte;
typedef uint32_t word32;
typedef struct { int state; } SignatureCtx;
enum { SIG_STATE_BEGIN, ECDSAk, CTC_SHA256wECDSA };
''' + manager + '''
/* Keep the exact hash input for these short vectors and inject hash failure. */
typedef struct { byte input[WC_SHA256_DIGEST_SIZE]; word32 length; } wc_Sha256;
static int hashError, verifyResult, verifies;
static int wc_InitSha256(wc_Sha256* sha) {
    memset(sha, 0, sizeof(*sha));
    return 0;
}
static int wc_Sha256Update(wc_Sha256* sha, const byte* in, word32 length) {
    assert(sha->length + length <= sizeof(sha->input));
    memcpy(sha->input + sha->length, in, length);
    sha->length += length;
    return hashError;
}
static int wc_Sha256Final(wc_Sha256* sha, byte* out) {
    memcpy(out, sha->input, sizeof(sha->input));
    return 0;
}
static void wc_Sha256Free(wc_Sha256* sha) { (void)sha; }
static int PalmRaw_ConfirmSignature(SignatureCtx* ctx, const byte* tbs,
    word32 tbsSz, const byte* key, word32 keySz, word32 keyOID, const byte* sig,
    word32 sigSz, word32 sigOID, const byte* params, word32 paramsSz, byte* rsa) {
    (void)ctx; (void)tbs; (void)tbsSz; (void)key; (void)keySz; (void)keyOID;
    (void)sig; (void)sigSz; (void)sigOID; (void)params; (void)paramsSz; (void)rsa;
    ++verifies;
    return verifyResult;
}
''' + cache + '''
static SignatureCtx ctx;
static const byte tbs[] = {1, 2}, key[] = {3, 4}, sig[] = {5, 6};
static int verify(WOLFSSL_CERT_MANAGER* cm, const byte* tbsP,
    const byte* keyP, const byte* sigP) {
    return ConfirmSignatureWithCache(&ctx, tbsP, sizeof(tbs), keyP, sizeof(key),
        ECDSAk, sigP, sizeof(sig), CTC_SHA256wECDSA, NULL, 0, NULL, cm);
}
int main(void) {
    WOLFSSL_CERT_MANAGER a = {0}, b = {0};
    byte changed[] = {9, 9};
    const byte sameStream[] = {1, 2, 3, 4, 5, 6};
    int i;
    assert(verify(&a, tbs, key, sig) == 0 && verifies == 1);
    assert(verify(&a, tbs, key, sig) == 0 && verifies == 1);
    assert(verify(&b, tbs, key, sig) == 0 && verifies == 2);
    verifyResult = -1;
    assert(verify(&a, changed, key, sig) == -1 && verifies == 3);
    assert(verify(&a, tbs, changed, sig) == -1 && verifies == 4);
    assert(verify(&a, tbs, key, changed) == -1 && verifies == 5);
    assert(verify(&a, tbs, key, changed) == -1 && verifies == 6);
    assert(ConfirmSignatureWithCache(&ctx, sameStream, 1, sameStream + 1, 3,
        ECDSAk, sig, sizeof(sig), CTC_SHA256wECDSA, NULL, 0, NULL, &a) == -1);
    assert(ConfirmSignatureWithCache(&ctx, tbs, sizeof(tbs), key, sizeof(key),
        ECDSAk, sig, sizeof(sig), CTC_SHA256wECDSA + 1, NULL, 0, NULL, &a) == -1);
    assert(ConfirmSignatureWithCache(&ctx, tbs, sizeof(tbs), key, sizeof(key),
        ECDSAk, sig, sizeof(sig), CTC_SHA256wECDSA, changed, 2, NULL, &a) == -1);
    hashError = -2;
    assert(verify(&a, tbs, key, sig) == -1 && verifies == 10);
    assert(a.palmCertSignatureCount == 1);
    hashError = verifyResult = 0;
    for (i = 0; i < PALM_CERT_SIGNATURE_CACHE_SIZE; ++i) {
        changed[0] = (byte)i;
        assert(verify(&a, changed, key, sig) == 0);
    }
    assert(a.palmCertSignatureCount == PALM_CERT_SIGNATURE_CACHE_SIZE);
    verifyResult = -1;
    assert(verify(&a, tbs, key, sig) == -1);
    assert(verify(&a, changed, key, sig) == 0);
    assert(verify(&b, tbs, key, sig) == 0);
    return 0;
}
''')
    executable = build / 'test'
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c17', '-Wall', '-Wextra', '-Werror', str(unit), '-o', str(executable)
    ], check=True)
    subprocess.run([executable], check=True)
    print('Certificate signature cache identity, isolation, failure and eviction passed')
