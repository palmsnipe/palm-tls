"""Compare the C comb with the RFC 7748 Montgomery ladder using host arithmetic."""
import ctypes
import hashlib
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

P = (1 << 255) - 19
ALICE = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
ALICE_PUBLIC = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
BOB = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
BOB_PUBLIC = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')


def reference(scalar):
    n = (int.from_bytes(scalar, 'little') & ((1 << 254) - 8)) | (1 << 254)
    x2, z2, x3, z3, swap = 1, 0, 9, 1, 0
    for bit in range(254, -1, -1):
        current = (n >> bit) & 1
        if swap ^ current:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = current
        a, b, c, d = x2 + z2, x2 - z2, x3 + z3, x3 - z3
        aa, bb = a * a % P, b * b % P
        e, da, cb = aa - bb, d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, 9 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')


def check(library):
    keygen = ctypes.CDLL(str(library)).PalmTlsX25519FixedBase
    buffer = ctypes.c_uint8 * 32
    keygen.argtypes = (buffer, buffer, buffer)
    keygen.restype = None
    assert reference(ALICE) == ALICE_PUBLIC and reference(BOB) == BOB_PUBLIC
    scalars = [ALICE, BOB, bytes(32), b'\xff' * 32, b'\x55' * 32, b'\xaa' * 32]
    scalars.extend(hashlib.sha256(f'X25519 check {i}'.encode()).digest() for i in range(128))
    for index, scalar in enumerate(scalars):
        expected = reference(scalar)
        seed = hashlib.sha256(b'scale ' + scalar).digest()
        scale = int.from_bytes(seed, 'little') % (P - 1) + 1
        for randomizer in (1, P - 1, scale):
            output = buffer()
            keygen(output, buffer.from_buffer_copy(scalar),
                   buffer.from_buffer_copy(randomizer.to_bytes(32, 'little')))
            if bytes(output) != expected:
                raise ValueError(f'wrong public key for fixture {index}, scale {randomizer}')
    print(f'Matched {len(scalars) * 3} fixed-base X25519 outputs')


def main():
    source = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as directory:
        build = Path(directory)
        subprocess.run(['node', str(source / 'generate-x25519-comb.mjs'),
                        str(build / 'x25519_comb.inc')], check=True)
        library = build / 'x25519-fixed-base.so'
        cc = shlex.split(os.environ.get('HOST_CC', 'cc'))
        subprocess.run([*cc, '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        '-I', str(build), str(source / 'x25519-fixed-base.c'),
                        '-o', str(library)], check=True)
        check(library)


if __name__ == '__main__':
    main()
