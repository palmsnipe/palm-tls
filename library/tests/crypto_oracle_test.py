#!/usr/bin/env python3
"""Check host C or the extracted ARM image against independent crypto oracles."""
import argparse
import ctypes
import json
import random
import subprocess
from pathlib import Path

HEADER, DIGITS = 4, 528
LEFT, RIGHT, OUTPUT = 4, 532, 1060
REQUEST_SIZE, SUCCESS, ERROR = 1588, 256, 0xffffffff
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


class Host:
    def __init__(self, path):
        self.library = ctypes.CDLL(str(path.resolve()))
        self.entry = self.library.PalmTlsArmletEntry
        self.entry.argtypes = [ctypes.c_void_p] * 3
        self.entry.restype = ctypes.c_uint32
        self.inverse = self.library.PalmTlsArmletTestInverse
        self.inverse.argtypes = [ctypes.c_void_p] * 2
        self.inverse.restype = None

    def invoke(self, request, skew=0):
        storage = bytearray(skew) + request
        buffer = (ctypes.c_ubyte * len(storage)).from_buffer(storage)
        result = self.entry(None, ctypes.addressof(buffer) + skew, None)
        request[:] = storage[skew:]
        return result


class Arm:
    CODE, DATA, STACK, STOP = 0x100000, 0x200000, 0x300000, 0x400000

    def __init__(self, path, cpu):
        import unicorn as uc
        from unicorn import arm_const as regs
        self.regs = regs
        self.machine = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM | uc.UC_MODE_LITTLE_ENDIAN)
        model = regs.UC_CPU_ARM_TI925T if cpu == 'ti925t' else regs.UC_CPU_ARM_PXA270
        self.machine.ctl_set_cpu_model(model)
        for address, length in [(self.CODE, 0x10000), (self.DATA, 0x10000),
                                (self.STACK, 0x10000), (self.STOP, 0x1000)]:
            self.machine.mem_map(address, length)
        # Verify that the selected model really distinguishes the old ISA:
        # CLZ r0,r0 is unavailable on TI925T and available on PXA270.
        self.machine.mem_write(self.CODE, bytes.fromhex('100f6fe1'))
        try:
            self.machine.emu_start(self.CODE, self.CODE + 4, count=1)
        except uc.UcError as error:
            if cpu != 'ti925t' or error.errno != uc.UC_ERR_INSN_INVALID:
                raise
        else:
            if cpu == 'ti925t':
                raise RuntimeError('CPU model failed the ARMv4T negative instruction probe')
        image = path.read_bytes()
        if len(image) > 0x10000:
            raise ValueError('ARM image exceeds test code mapping')
        self.machine.mem_write(self.CODE, image)
        self.machine.ctl_remove_cache(self.CODE, self.CODE + 0x10000)

    def invoke(self, request, skew=0):
        machine, regs = self.machine, self.regs
        machine.mem_write(self.DATA + skew, bytes(request))
        for register, value in [(regs.UC_ARM_REG_R0, 0), (regs.UC_ARM_REG_R1, self.DATA + skew),
                                (regs.UC_ARM_REG_R2, 0), (regs.UC_ARM_REG_SP, self.STACK + 0x10000),
                                (regs.UC_ARM_REG_LR, self.STOP)]:
            machine.reg_write(register, value)
        machine.emu_start(self.CODE, self.STOP, timeout=10_000_000, count=50_000_000)
        if machine.reg_read(regs.UC_ARM_REG_PC) != self.STOP:
            raise RuntimeError('ARMlet did not return within the execution limit')
        request[:] = machine.mem_read(self.DATA + skew, len(request))
        return machine.reg_read(regs.UC_ARM_REG_R0)


def integer(value):
    return value.to_bytes(32, 'big')


def point(value):
    return integer(value[0]) + integer(value[1])


def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0: return None
    slope = ((3 * x * x - 3) * pow(2 * y, -1, P) if a == b else
             (v - y) * pow(u - x, -1, P)) % P
    result_x = (slope * slope - x - u) % P
    return result_x, (slope * (x - result_x) - y) % P


def multiply(scalar, base):
    result = None
    while scalar:
        if scalar & 1: result = add(result, base)
        base = add(base, base)
        scalar >>= 1
    return result


def request(command):
    data = bytearray(REQUEST_SIZE)
    data[0], data[3] = 1, command
    return data


def aes(backend, rng):
    vectors = []
    # Cross block, chunk and AAD boundaries, including empty records and the
    # maximum AAD representable by the existing request ABI.
    for aad_size in (0, 1, 13, 16, 20, 31, 516):
        for size in (0, 1, 15, 16, 17, 31, 32, 511, 512, 513, 4096, 16384):
            make = lambda length: bytes(rng.getrandbits(8) for _ in range(length)).hex()
            vectors.append(dict(key=make(16), nonce=make(12), aad=make(aad_size), plaintext=make(size)))
    expected = json.loads(subprocess.check_output(['node', str(Path(__file__).with_name('aes_oracle.mjs'))],
                                                 input=json.dumps(vectors).encode()))
    for index, vector in enumerate(expected):
        for decrypt in (False, True):
            data = bytearray([0xa5]) * REQUEST_SIZE
            data[0], data[3] = 1, 3
            aad = bytes.fromhex(vector['aad'])
            data[LEFT:LEFT + 4] = bytes([0, len(aad) >> 8, len(aad) & 255, decrypt])
            data[LEFT + 4:LEFT + 20] = bytes.fromhex(vector['key'])
            nonce = bytes.fromhex(vector['nonce'])
            data[RIGHT:RIGHT + len(nonce + aad)] = nonce + aad
            skew = index % 4
            assert backend.invoke(data, skew) == SUCCESS, ('GCM start', index)
            source = bytes.fromhex(vector['ciphertext' if decrypt else 'plaintext'])
            output = bytearray()
            # Non-final updates must end at a block boundary, as in the bridge.
            chunk = (16, 32, 128, 512)[index % 4]
            for offset in range(0, len(source), chunk):
                part = source[offset:offset + chunk]
                data[LEFT:LEFT + 3] = bytes([1, len(part) >> 8, len(part) & 255])
                data[RIGHT:RIGHT + len(part)] = part
                assert backend.invoke(data, skew) == SUCCESS, ('GCM update', index)
                output.extend(data[OUTPUT:OUTPUT + len(part)])
            data[LEFT:LEFT + 3] = b'\x02\0\0'
            assert backend.invoke(data, skew) == SUCCESS, ('GCM final', index)
            assert output.hex() == vector['plaintext' if decrypt else 'ciphertext'], ('GCM output', index)
            assert data[OUTPUT:OUTPUT + 16].hex() == vector['tag'], ('GCM tag', index)
    return len(expected) * 2


def p256(backend, rng):
    # Mapping constructed Montgomery/Jacobian points exercises inversion of
    # arbitrary nonzero z in the *extracted* ARM code, not only host C.
    values = [1, 2, 3, P - 2, P - 1] + [rng.randrange(1, P) for _ in range(64)]
    montgomery = 2**256 % P
    for index, z in enumerate(values):
        data = request(5)
        coordinates = (G[0] * z * z % P, G[1] * z * z * z % P, z)
        data[RIGHT:RIGHT + 96] = b''.join(integer(c * montgomery % P) for c in coordinates)
        assert backend.invoke(data, index % 4) == SUCCESS, ('P256 map', index)
        assert data[OUTPUT:OUTPUT + 64] == point(G), ('P256 inverse/map', index)
        if isinstance(backend, Host):
            actual = ctypes.create_string_buffer(32)
            backend.inverse(integer(z), actual)
            assert actual.raw == integer(pow(z, -1, P)), ('P256 inverse oracle', index)
    data = request(5)
    assert backend.invoke(data) == ERROR, 'zero Jacobian z must fail'
    if isinstance(backend, Host):
        actual = ctypes.create_string_buffer(32)
        backend.inverse(integer(0), actual)
        assert actual.raw == integer(0), 'zero inverse convention'
    scalars = [1, 2, 3, N - 1] + [rng.randrange(1, N) for _ in range(12)]
    q = multiply(7, G)
    for base in (G, q):
        data = request(1)
        data[1] = 1
        data[RIGHT:RIGHT + 64] = point(base)
        assert backend.invoke(data) == ERROR, 'zero scalar must return infinity/error'
    for index, scalar in enumerate(scalars):
        for base in (G, q):
            expected = point(multiply(scalar, base))
            for mapped in (False, True):
                data = request(1)
                data[1] = mapped
                data[LEFT:LEFT + 32] = integer(scalar)
                data[RIGHT:RIGHT + 64] = point(base)
                assert backend.invoke(data, index % 4) == SUCCESS, ('P256 multiply', index)
                if not mapped:
                    data[RIGHT:RIGHT + 96] = data[OUTPUT:OUTPUT + 96]
                    data[3] = 5
                    assert backend.invoke(data, index % 4) == SUCCESS
                assert data[OUTPUT:OUTPUT + 64] == expected, ('P256 affine oracle', index)
    for index in range(8):
        a, b = rng.randrange(1, N), rng.randrange(1, N)
        data = request(4)
        data[LEFT:LEFT + 64] = integer(a) + integer(b)
        data[RIGHT:RIGHT + 128] = point(G) + point(q)
        assert backend.invoke(data, index % 4) == SUCCESS
        assert data[OUTPUT:OUTPUT + 64] == point(add(multiply(a, G), multiply(b, q)))
    data = request(4)
    data[LEFT:LEFT + 64] = integer(1) + integer(N - 1)
    data[RIGHT:RIGHT + 128] = point(G) + point(G)
    assert backend.invoke(data) == ERROR, 'cancelling double-scalar sum must return infinity/error'
    return len(values), len(scalars) * 4, 8


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--host-library', type=Path)
    source.add_argument('--arm-image', type=Path)
    parser.add_argument('--cpu', choices=['ti925t', 'pxa270'], default='ti925t')
    args = parser.parse_args()
    backend = Host(args.host_library) if args.host_library else Arm(args.arm_image, args.cpu)
    rng = random.Random(0x50414c4d)
    records = aes(backend, rng)
    inverses, multiplies, verifies = p256(backend, rng)
    print(f'Crypto oracles passed ({args.cpu if args.arm_image else "host"}): '
          f'{records} AES-GCM records, {inverses} inversions/maps, '
          f'{multiplies} scalar products, {verifies} double-scalar products; alignment offsets 0..3')


if __name__ == '__main__':
    main()
