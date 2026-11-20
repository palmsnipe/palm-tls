"""Compare both native X25519 paths with the RFC 7748 reference ladder."""
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
SHARED = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
BASE = (9).to_bytes(32, 'little')
AGREEMENT_VECTORS = (
    (ALICE, BOB_PUBLIC, SHARED),
    (BOB, ALICE_PUBLIC, SHARED),
    (
        bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'),
        bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'),
        bytes.fromhex('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'),
    ),
    (
        bytes.fromhex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'),
        bytes.fromhex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'),
        bytes.fromhex('95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957'),
    ),
)


def reference(scalar, peer=BASE):
    n = (int.from_bytes(scalar, 'little') & ((1 << 254) - 8)) | (1 << 254)
    u = int.from_bytes(peer, 'little') & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, u, 1, 0
    for bit in range(254, -1, -1):
        current = (n >> bit) & 1
        if swap ^ current:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = current
        a, b, c, d = x2 + z2, x2 - z2, x3 + z3, x3 - z3
        aa, bb = a * a % P, b * b % P
        e, da, cb = aa - bb, d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, u * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')


def check(library):
    module = ctypes.CDLL(str(library))
    keygen = module.PalmTlsX25519FixedBase
    agree = module.PalmTlsX25519Agree
    buffer = ctypes.c_uint8 * 32
    keygen.argtypes = (buffer, buffer, buffer)
    keygen.restype = None
    agree.argtypes = (buffer, buffer, buffer, buffer, buffer)
    agree.restype = ctypes.c_bool
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

    fixtures = list(AGREEMENT_VECTORS)
    for scalar, peer, expected in AGREEMENT_VECTORS:
        assert reference(scalar, peer) == expected
    for scalar in scalars:
        peer = hashlib.sha256(b'peer ' + scalar).digest()
        fixtures.append((scalar, peer, reference(scalar, peer)))
    for value in (0, 1, P - 1, *range(P, P + 19)):
        for high_bit in (0, 1 << 255):
            peer = (value | high_bit).to_bytes(32, 'little')
            canonical_peer = (value % P).to_bytes(32, 'little')
            expected = reference(ALICE, canonical_peer)
            if value % P in (0, 1, P - 1):
                assert expected == bytes(32)
            fixtures.append((ALICE, peer, expected))
    for index, (scalar, peer, expected) in enumerate(fixtures):
        seed = hashlib.sha256(b'scale ' + scalar + peer).digest()
        scale = int.from_bytes(seed, 'little') % (P - 1) + 1
        random_mask = hashlib.sha256(b'mask ' + scalar + peer).digest()
        for randomizer, mask in ((1, bytes(32)), (P - 1, b'\xff' * 32), (scale, random_mask)):
            output = buffer()
            accepted = agree(output, buffer.from_buffer_copy(scalar), buffer.from_buffer_copy(peer),
                             buffer.from_buffer_copy(randomizer.to_bytes(32, 'little')),
                             buffer.from_buffer_copy(mask))
            if bytes(output) != expected or accepted != any(expected):
                raise ValueError(f'wrong agreement result for fixture {index}, scale {randomizer}')
    print(f'Matched {len(fixtures) * 3} variable-base X25519 outputs and acceptance results')


def main():
    library_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as directory:
        build = Path(directory)
        subprocess.run(['node', str(library_root / 'tools/generate-x25519-comb.mjs'),
                        str(build / 'x25519_comb.inc')], check=True)
        library = build / 'x25519-68k.so'
        cc = shlex.split(os.environ.get('HOST_CC', 'cc'))
        subprocess.run([*cc, '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        '-I', str(build), str(library_root / 'src/tls_x25519_68k.c'),
                        '-o', str(library)], check=True)
        check(library)


if __name__ == '__main__':
    main()
