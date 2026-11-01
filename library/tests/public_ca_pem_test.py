#!/usr/bin/env python3
"""Differential-test wolfSSL's actual public/constant-time Base64 decoders."""
import base64
import ctypes
import os
import random
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
vendor = root / '.palm-tls/src/wolfssl'
source = (vendor / 'wolfcrypt/src/coding.c').read_text()
body = source[source.index('static WC_INLINE byte Base64_Char2Val_CT('):
              source.index('#endif /* WOLFSSL_BASE64_DECODE */')]
errors = (vendor / 'wolfssl/wolfcrypt/error-crypt.h').read_text()
defines = '\n'.join('#define '+name+' '+re.search(r'\b'+name+r'\s*=\s*(-?\d+)',errors).group(1)
                    for name in ('BUFFER_E','BAD_FUNC_ARG','ASN_INPUT_E'))
with tempfile.TemporaryDirectory() as directory:
    build = Path(directory)
    unit = build / 'decode.c'
    unit.write_text('''
#include <stdint.h>
#include <stddef.h>
typedef uint8_t byte;
typedef uint32_t word32;
#define WC_INLINE inline
#define WC_OCTET(x) ((byte)(x))
#define ALIGN64 __attribute__((aligned(64)))
#define WOLFSSL_MSG(x) ((void)0)
#define WC_NO_ERR_TRACE(x) (x)
enum { BAD=255, PAD='=', BASE64_MIN=0x2b };
''' + defines + '\n' + body)
    library = build / 'decode.so'
    subprocess.run(shlex.split(os.environ.get('CC','cc')) + [
        '-std=c17','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',
        str(unit),'-o',str(library)],check=True)
    lib = ctypes.CDLL(str(library))
    decoders = [lib.Base64_Decode, lib.Base64_Decode_nonCT]
    for decoder in decoders:
        decoder.argtypes = [ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_uint32)]
        decoder.restype = ctypes.c_int
    def decode(fn, data, capacity):
        output = (ctypes.c_ubyte * max(1,capacity+8))(*([0xa5]*max(1,capacity+8)))
        length = ctypes.c_uint32(capacity)
        status = fn(data,len(data),output,ctypes.byref(length))
        assert bytes(output)[capacity:] == b'\xa5'*8, 'decoder overwrote output capacity'
        return status,length.value,bytes(output)
    vectors = [b'',b' ',b'\r\n',b'A',b'AAAA',b'AA==',b'AAA=',b'A===',b'====',
               b'AA=A',b'AA==junk',b'AA==\r',b'AA==\r\n',b'AA==\n  ',b'AA==\0junk']
    for position in range(4):
        for character in range(256):
            value=bytearray(b'QUJD');value[position]=character;vectors.append(bytes(value))
    rng=random.Random(0x50454d)
    alphabet=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \r\n\t\0!'
    vectors += [bytes(rng.choice(alphabet) for _ in range(rng.randrange(160))) for _ in range(4000)]
    for size in (1,2,3,16,32,65,256,1024,4096):
        encoded=base64.b64encode(bytes(rng.randrange(256) for _ in range(size)))
        vectors += [encoded, b'\r\n'.join(encoded[i:i+64] for i in range(0,len(encoded),64))]
    cases=0
    for data in vectors:
        for capacity in sorted({0,1,2,3,len(data)//2,len(data),len(data)+1}):
            results=[decode(fn,data,capacity) for fn in decoders]
            assert results[0] == results[1], (data[:80],capacity,results)
            cases += 1
    print('Public CA PEM decoder equivalence passed:',cases,'valid/malformed/capacity cases')
