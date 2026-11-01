#!/usr/bin/env python3
"""Compare the patched real TFM parser with its generic 16-bit implementation.

Host types explicitly model Palm's 16-bit limbs / 32-bit products. End-to-end
Palm benchmarks additionally execute curve imports with the real 16-bit int ABI.
"""
import argparse
import ctypes
import os
import random
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

SETTINGS = "#define MP_16BIT\n#define WC_16BIT_CPU\n#define USE_FAST_MATH\n#define HAVE_ECC\n#define TFM_ECC256\n#define WOLFSSL_NO_ASM\n#define NO_ASM\n#define NO_RSA\n#define NO_DSA\n#define NO_DH\n#define NO_PWDBASED\n#define SINGLE_THREADED\n#define NO_FILESYSTEM\n#define NO_DEV_RANDOM\n#define WOLFSSL_NO_SOCK\n#define PALM_WOLFSSL_FAST_HEX\n/* Model Palm's integer storage on a host whose int is 32 bits. */\n#include <stdint.h>\n#define WOLFSSL_BIGINT_TYPES\n#define SIZEOF_FP_DIGIT 2\ntypedef uint16_t fp_digit;\ntypedef uint32_t fp_word;\ntypedef int32_t fp_sword;\n"
WRAPPER = '#include <stdlib.h>\n#include <wolfssl/wolfcrypt/tfm.h>\nvoid* wolfSSL_Malloc(size_t n) { return malloc(n); }\nvoid wolfSSL_Free(void* p) { free(p); }\nvoid mp_reverse(unsigned char* p, int n) { int i; for(i=0;i<n/2;i++) { unsigned char c=p[i];p[i]=p[n-1-i];p[n-1-i]=c; } }\nint hex_test(const char* s,int radix,unsigned short* out,int* used,int* sign) {\n fp_int a; int r=mp_read_radix(&a,s,radix); int i; *used=a.used; *sign=a.sign;\n for(i=0;i<FP_SIZE;i++) out[i]=a.dp[i]; return r;\n}\nint hex_capacity(void) {return FP_SIZE;}\nint hex_digit_bits(void) {return DIGIT_BIT;}\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('../.palm-tls/src/wolfssl'))
    args = parser.parse_args()
    source = args.source.resolve()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'wrapper.c').write_text(WRAPPER)
        libs = []
        for name, settings in [('fast', SETTINGS), ('generic', SETTINGS.replace(
                '#define PALM_WOLFSSL_FAST_HEX', '/* generic reference */'))]:
            build = root / name
            build.mkdir()
            (build / 'user_settings.h').write_text(settings)
            output = build / ('tfm.dylib' if sys.platform == 'darwin' else 'tfm.so')
            command = shlex.split(os.environ.get('CC', 'cc')) + [
                '-shared', '-fPIC', '-O1', '-DWOLFSSL_USER_SETTINGS',
                '-I' + str(build), '-I' + str(source),
                str(source / 'wolfcrypt/src/tfm.c'), str(root / 'wrapper.c'),
                '-o', str(output)]
            result = subprocess.run(command, text=True, capture_output=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            lib = ctypes.CDLL(str(output))
            lib.hex_test.argtypes = [ctypes.c_char_p, ctypes.c_int,
                ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int)]
            assert lib.hex_digit_bits() == 16
            libs.append(lib)
        capacity = libs[0].hex_capacity()
        assert capacity == libs[1].hex_capacity()
        def run(lib, text, radix):
            digits = (ctypes.c_ushort * capacity)()
            used, sign = ctypes.c_int(), ctypes.c_int()
            status = lib.hex_test(text.encode(), radix, digits,
                                 ctypes.byref(used), ctypes.byref(sign))
            return (status, tuple(digits)[:used.value], sign.value) if status == 0 else (status,)
        rng = random.Random(5)
        inputs = ['', '-', '0', '-0', '  ', ' 1', '0 1', '000AbCd \t\n',
            '-000a', '0x12', '+1', '1\r', '1\v', '0' * 40000,
            '-' + '0' * 40000 + 'abc']
        inputs += ['F' * n for n in (1, 3, 4, 5, 63, 64, 65,
                    capacity * 4 - 1, capacity * 4, capacity * 4 + 1)]
        inputs += [''.join(rng.choice('0123456789abcdefABCDEF -\t\n\rxz+')
                   for _ in range(rng.randrange(300))) for _ in range(3000)]
        inputs += ['0' * rng.randrange(100) + ''.join(rng.choice('0123456789abcdef')
                   for _ in range(rng.randrange(capacity * 4 + 5))) for _ in range(200)]
        for radix in (2, 10, 16, 36, 64):
            for text in inputs:
                fast, generic = [run(lib, text, radix) for lib in libs]
                assert fast == generic, (radix, repr(text[:40]), len(text), fast, generic)
        print(f'16-bit TFM hex differential tests passed: {len(inputs) * 5} cases')

if __name__ == '__main__':
    main()
