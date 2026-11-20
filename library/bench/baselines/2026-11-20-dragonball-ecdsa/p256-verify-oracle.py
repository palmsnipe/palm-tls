# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise linked m68000 ECDSA verification against independent affine math."""
import random
import struct
import subprocess
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_M68K, UC_HOOK_CODE, UC_MODE_BIG_ENDIAN
from unicorn.m68k_const import (
    UC_CPU_M68K_M68000, UC_M68K_REG_A0, UC_M68K_REG_A7, UC_M68K_REG_D0,
    UC_M68K_REG_PC,
)

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def add(first, second):
    if first is None:
        return second
    if second is None:
        return first
    x, y = first
    xx, yy = second
    if x == xx and (y + yy) % P == 0:
        return None
    slope = ((3*x*x-3) * pow(2*y, -1, P) if x == xx else
             (yy-y) * pow(xx-x, -1, P)) % P
    result_x = (slope*slope - x - xx) % P
    return result_x, (slope*(x-result_x)-y) % P


def mul(k, point=G):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def der(r, s):
    def integer(value):
        data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
        if data[0] & 128:
            data = b'\0' + data
        return bytes((2, len(data))) + data
    pair = integer(r) + integer(s)
    return bytes((48, len(pair))) + pair


class Engine:
    STOP = 0x100000
    KEY = 0x103002
    BUFFER = 0x105002
    STACK = 0x1ff000
    HEAP = 0x110002

    def __init__(self, elf, nm):
        self.symbols = {}
        for line in subprocess.check_output([nm, elf], text=True).splitlines():
            fields = line.split()
            if len(fields) == 3:
                self.symbols[fields[2]] = int(fields[0], 16)
        image = Path(elf).read_bytes()
        start = struct.unpack_from('>I', image, 28)[0]
        step, count = struct.unpack_from('>HH', image, 42)
        self.cpu = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        self.cpu.ctl_set_cpu_model(UC_CPU_M68K_M68000)
        for i in range(count):
            kind, offset, address, _, length, memsize, _, _ = struct.unpack_from(
                '>8I', image, start + i*step)
            if kind == 1:
                self.cpu.mem_map(address, (memsize+4095) & ~4095)
                self.cpu.mem_write(address, image[offset:offset+length])
        self.cpu.mem_map(self.STOP, 0x100000)
        self.top = self.HEAP
        self.live = set()
        # PALM heap adapters call OS traps. Provide a checked test heap so
        # the linked version of the verifier runs without a Palm OS boot.
        for name, hook in [('WolfPalmMalloc', self.alloc), ('WolfPalmFree', self.free)]:
            address = self.symbols[name]
            self.cpu.mem_write(address, b'\x4e\x75')  # RTS
            self.cpu.hook_add(UC_HOOK_CODE, hook, begin=address, end=address)

    def arg(self):
        address = self.cpu.reg_read(UC_M68K_REG_A7)
        return struct.unpack('>I', self.cpu.mem_read(address + 4, 4))[0]

    def alloc(self, cpu, address, size, _):
        length = self.arg()
        result = self.top
        self.top += (length + 1) & ~1
        assert length > 0 and self.top < self.STACK - 0x10000
        self.live.add(result)
        cpu.reg_write(UC_M68K_REG_A0, result)
        cpu.reg_write(UC_M68K_REG_D0, result)

    def free(self, cpu, address, size, _):
        pointer = self.arg()
        if pointer:
            self.live.remove(pointer)
        if not self.live:
            self.top = self.HEAP

    def call(self, symbol, *args):
        self.cpu.reg_write(UC_M68K_REG_A7, self.STACK)
        self.cpu.mem_write(self.STACK, struct.pack('>'+'I'*(len(args)+1), self.STOP, *args))
        self.cpu.emu_start(self.symbols[symbol], self.STOP, count=20_000_000)
        assert self.cpu.reg_read(UC_M68K_REG_PC) == self.STOP, symbol
        return self.cpu.reg_read(UC_M68K_REG_D0) & 65535

    def verify(self, point, digest, r, s, expected):
        raw_key = b'\x04' + b''.join(v.to_bytes(32, 'big') for v in point)
        self.cpu.mem_write(self.BUFFER, raw_key)
        assert self.call('wc_ecc_init', self.KEY) == 0
        assert self.call('wc_ecc_import_x963', self.BUFFER, len(raw_key), self.KEY) == 0
        encoded = der(r, s)
        sig_ptr, hash_ptr, result_ptr = (self.BUFFER+i for i in (0x100, 0x200, 0x300))
        self.cpu.mem_write(sig_ptr, encoded)
        self.cpu.mem_write(hash_ptr, digest.to_bytes(32, 'big'))
        self.cpu.mem_write(result_ptr, b'\x00\x00')
        status = self.call('wc_ecc_verify_hash', sig_ptr, len(encoded), hash_ptr, 32,
                           result_ptr, self.KEY)
        result = self.cpu.mem_read(result_ptr, 2) == b'\x00\x01'
        assert result == expected and (not expected or status == 0), (digest, r, s, status, result)
        self.call('wc_ecc_free', self.KEY)
        assert not self.live


def main():
    engine = Engine(*sys.argv[1:])
    rng = random.Random(68)
    cases = []
    for private in [1, N-1, 2, 3, *(rng.randrange(1, N) for _ in range(24))]:
        for digest in [N, rng.getrandbits(256)]:
            nonce = rng.randrange(1, N)
            r = mul(nonce)[0] % N
            s = pow(nonce, -1, N) * (digest + r*private) % N
            key = mul(private)
            cases.extend([(key, digest, r, s, True),
                          (key, digest ^ 1, r, s, False)])
    # Choose an ephemeral point with x = N + r. Solve Q = r^-1(sR - eG)
    # so verification must find the second projective X candidate.
    for r in range(1, 100):
        x = N+r
        squared = (x*x*x - 3*x + B) % P
        y = pow(squared, (P+1)//4, P)
        if y*y % P == squared:
            digest, s = 5, 7
            key = mul(pow(r, -1, N), add(mul(s, (x, y)), mul(N-digest)))
            cases.extend([(key, digest, r, s, True), (key, digest, r+1, s, False)])
            break
    else:
        raise AssertionError('no r+n test point')
    # eG + rQ cancels, and r/s boundaries must be rejected.
    cases.extend([(G, N-5, 5, 7, False), (G, 0, 1, 1, False), (G, 3, 0, 1, False),
                  (G, 3, N, 1, False), (G, 3, 1, 0, False), (G, 3, 1, N, False)])
    for case in cases:
        engine.verify(*case)
    print(f'{len(cases)} linked ECDSA signature cases passed')


if __name__ == '__main__':
    main()
