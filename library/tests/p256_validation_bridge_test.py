#!/usr/bin/env python3
"""Exercise the production validation bridge against the actual native kernel."""
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

from crypto_oracle_test import G, P

root = Path(__file__).resolve().parents[1]
source = (root / 'src/tls_armlet.c').read_text()
bridge = source[source.index('/* Exact domain checks'):source.index('int PalmTlsArmletP256Multiply(')]
errors = (root.parent / '.palm-tls/src/wolfssl/wolfssl/wolfcrypt/error-crypt.h').read_text()
defines = '\n'.join('#define ' + name + ' ' + re.search(r'\b' + name + r'\s*=\s*(-?\d+)', errors).group(1)
                    for name in ('IS_POINT_E', 'ECC_OUT_OF_RANGE_E', 'ECC_BAD_ARG_E'))


def array(name, number):
    return 'static const UInt16 ' + name + '[16] = {' + ','.join(str((number >> (16*i)) & 65535) for i in range(16)) + '};\n'


with tempfile.TemporaryDirectory() as directory:
    build = Path(directory)
    unit = build / 'test.c'
    unit.write_text('''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "armlet_abi.h"
typedef uint8_t UInt8;
typedef uint16_t UInt16;
typedef int16_t Int16;
typedef uint32_t UInt32;
typedef int Boolean;
typedef struct { int used, sign; UInt16 dp[264]; } fp_int;
typedef fp_int mp_int;
typedef struct { fp_int *x, *y, *z; } ecc_point;
typedef struct {
    UInt8 version, leftUsed, rightUsed, command;
    UInt8 left[528], right[528], output[528];
} PalmTlsArmletMultiplyRequest;
#define FP_ZPOS 0
#define FP_NEG 1
#define FP_EQ 0
#define MP_OKAY 0
#define false 0
#define true 1
#define MemSet(p,n,v) memset(p,v,n)
static Boolean gArmletEnabled = true;
static void *gArmletEntryP = (void *)1;
static PalmTlsArmletMultiplyRequest storage;
static PalmTlsArmletMultiplyRequest *gRequestP = &storage;
static UInt32 forcedStatus;
static int calls;
extern UInt32 PalmTlsArmletEntry(const void *, void *, void *);
static UInt32 PceNativeCall(void *entry, void *request) {
    assert(entry); calls++;
    return forcedStatus ? forcedStatus : PalmTlsArmletEntry(0,request,0);
}
static int fp_cmp_d(fp_int *a, UInt16 b) {
    if (a->sign == FP_NEG || !a->used) return -1;
    if (a->used > 1) return 1;
    return a->dp[0] == b ? FP_EQ : a->dp[0] < b ? -1 : 1;
}
''' + defines + '\n' + bridge + '\n' +
        array('gx', G[0]) + array('gy', G[1]) + array('prime', P) +
        array('af', P-3) + array('bf', (G[1]**2-G[0]**3+3*G[0]) % P) + '''
static void load(fp_int *value, const UInt16 *digits) {
    memset(value,0,sizeof(*value)); value->used=16;
    memcpy(value->dp,digits,32);
}
int main(void) {
    fp_int x,y,z,a,b,p;
    ecc_point point={&x,&y,&z};
    int result=123, before, i;
    load(&x,gx); load(&y,gy); memset(&z,0,sizeof(z)); z.used=1;z.dp[0]=1;
    load(&a,af);load(&b,bf);load(&p,prime);
    memset(&storage,0xa5,sizeof(storage));
    assert(PalmTlsArmletP256Validate(&point,&result) && result==MP_OKAY && calls==1);
    for(i=0;i<528;i++) assert(storage.output[i]==0xa5);
    y.dp[0]^=1;
    assert(PalmTlsArmletP256Validate(&point,&result) && result==IS_POINT_E);
    load(&y,gy);before=calls;
    /* Bounds precede affine/curve checks, including negative zero and 257 bits. */
    x.sign=FP_NEG;z.dp[0]=2;
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_OUT_OF_RANGE_E);
    x.used=0;
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_OUT_OF_RANGE_E);
    load(&x,prime);
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_OUT_OF_RANGE_E);
    x.used=17;x.dp[16]=1;
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_OUT_OF_RANGE_E);
    load(&x,gx);load(&y,prime);
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_OUT_OF_RANGE_E);
    load(&y,gy);y.sign=FP_NEG;
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_OUT_OF_RANGE_E);
    load(&y,gy);
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_BAD_ARG_E);
    z.dp[0]=1;z.sign=FP_NEG;
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_BAD_ARG_E);
    z.sign=FP_ZPOS;z.used=0;
    assert(PalmTlsArmletP256Validate(&point,&result) && result==ECC_BAD_ARG_E);
    assert(calls==before);z.used=1;
    /* The equation-only hook deliberately ignores Z, matching _ecc_is_point. */
    z.dp[0]=2;
    assert(PalmTlsArmletP256IsPoint(&point,&a,&b,&p,&result) && result==MP_OKAY);
    z.dp[0]=1;before=calls;result=123;
    a.dp[0]^=1;
    assert(!PalmTlsArmletP256IsPoint(&point,&a,&b,&p,&result));load(&a,af);
    b.dp[0]^=1;
    assert(!PalmTlsArmletP256IsPoint(&point,&a,&b,&p,&result));load(&b,bf);
    p.dp[0]^=1;
    assert(!PalmTlsArmletP256IsPoint(&point,&a,&b,&p,&result));load(&p,prime);
    x.sign=FP_NEG;
    assert(!PalmTlsArmletP256IsPoint(&point,&a,&b,&p,&result));load(&x,gx);
    assert(result==123 && calls==before);
    /* Disabled/missing engines and unknown native statuses always fall back. */
    gArmletEnabled=false;
    assert(!PalmTlsArmletP256Validate(&point,&result));
    assert(!PalmTlsArmletP256IsPoint(&point,&a,&b,&p,&result));
    gArmletEnabled=true;gArmletEntryP=0;
    assert(!PalmTlsArmletP256Validate(&point,&result));gArmletEntryP=(void *)1;
    gRequestP=0;
    assert(!PalmTlsArmletP256Validate(&point,&result));gRequestP=&storage;
    assert(!PalmTlsArmletP256Validate(0,&result));
    assert(!PalmTlsArmletP256Validate(&point,0));
    assert(result==123 && calls==before);
    forcedStatus=PALM_TLS_ARMLET_ERROR;
    assert(!PalmTlsArmletP256Validate(&point,&result) && result==123);
    forcedStatus=PALM_TLS_ARMLET_P256_OUT_OF_RANGE;
    assert(!PalmTlsArmletP256IsPoint(&point,&a,&b,&p,&result) && result==123);
    return 0;
}
''')
    binary = build / 'test'
    subprocess.run(shlex.split(os.environ.get('CC','cc')) + [
        '-std=c17','-O2','-Wall','-Wextra','-Werror','-DPALM_ARMLET_HOST_TEST',
        '-I'+str(root/'arm'),'-I'+str(root/'build/generated'),
        str(unit),str(root/'arm/multiply.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('P-256 bridge bounds, sign, Z, equation, domain and fallback checks passed')
