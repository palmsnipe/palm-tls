#!/usr/bin/env python3
"""Verify linked 68000 ECDH, including rejection and secret-independent traces."""
import argparse
import random
import struct
from pathlib import Path

import unicorn as uc
from unicorn import m68k_const as regs

from crypto_oracle_test import G, N, P, multiply
from p256_fixed_68k_test import INTEGER, M68k

B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
PRIVATE_ERROR, POINT_ERROR, INFINITY_ERROR = -216, -214, -215


class Agreement(M68k):
    ORDER = 0x103002
    PRIME = 0x104002
    SCRATCH = 0x105002
    OUTPUT = 0x106002
    HEAP = 0x108000

    def __init__(self, elf, nm):
        super().__init__(elf, nm)
        self.field_input(self.ORDER, N)
        self.field_input(self.PRIME, P)
        self.top = self.HEAP
        self.allocations = set()
        # The public table's inversion uses wolfSSL, with Palm heap calls
        # supplied by a bounded test heap in this CPU-only session.
        for function, hook in (('WolfPalmMalloc', self.allocate), ('WolfPalmFree', self.release)):
            address = self.symbols[function]
            self.cpu.mem_write(address, b'\x4e\x75')  # RTS
            self.cpu.hook_add(uc.UC_HOOK_CODE, hook, begin=address, end=address)

    def stack_argument(self):
        stack = self.cpu.reg_read(regs.UC_M68K_REG_A7)
        return struct.unpack('>I', self.cpu.mem_read(stack + 4, 4))[0]

    def allocate(self, cpu, address, size, data):
        length = self.stack_argument()
        allocation = self.top
        self.top += (length + 1) & ~1
        assert length > 0 and self.top < self.STACK - 0x10000
        self.allocations.add(allocation)
        cpu.reg_write(regs.UC_M68K_REG_A0, allocation)
        cpu.reg_write(regs.UC_M68K_REG_D0, allocation)

    def release(self, cpu, address, size, data):
        pointer = self.stack_argument()
        if pointer:
            self.allocations.remove(pointer)
        if not self.allocations:
            self.top = self.HEAP

    def agree(self, scalar, peer, randomizer, expected_error=0, trace=False):
        self.field_input(self.SCALAR, scalar)
        self.field_input(self.POINT, peer[0])
        self.field_input(self.POINT + INTEGER.size, peer[1])
        self.field_input(self.POINT + 2 * INTEGER.size, 1)
        original_peer = bytes(self.cpu.mem_read(self.POINT, 3 * INTEGER.size))
        self.field_input(self.SCRATCH + 2 * INTEGER.size, randomizer)
        self.cpu.mem_write(self.OUTPUT - 2, b'OK' + b'\xa5' * 32 + b'OK')
        status, events = self.invoke('PalmTlsP256Agree',
            (self.SCALAR, self.POINT, self.ORDER, self.PRIME, self.SCRATCH, self.OUTPUT), trace)
        assert status == (expected_error & 65535)
        assert self.field_output(self.SCALAR) == scalar
        assert self.cpu.mem_read(self.POINT, len(original_peer)) == original_peer
        assert not self.allocations
        output = self.cpu.mem_read(self.OUTPUT - 2, 36)
        assert output[:2] == output[-2:] == b'OK'
        if expected_error:
            assert output[2:-2] == b'\xa5' * 32
        else:
            assert output[2:-2] == multiply(scalar, peer)[0].to_bytes(32, 'big')
        return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('nm', type=Path)
    args = parser.parse_args()
    agreement = Agreement(args.elf, args.nm)
    rng = random.Random(25668)
    scalars = (1, 2, 15, 16, 1 << 255, N - 2, N - 1,
               *(1 << bit for bit in range(0, 256, 15)),
               *(rng.randrange(1, N) for _ in range(40)))
    for index, scalar in enumerate(scalars):
        peer = multiply(rng.randrange(1, N), G)
        agreement.agree(scalar, peer, (1, P - 1, rng.randrange(1, P))[index % 3])

    y = pow(B, (P + 1) // 4, P)
    assert y * y % P == B
    agreement.agree(1, (0, y), 7)  # A finite point can produce 32 zero output bytes.

    malformed = ((0, G, PRIVATE_ERROR), (N, G, PRIVATE_ERROR),
                 (1, (0, 0), INFINITY_ERROR), (1, (1, 1), POINT_ERROR),
                 (1, (P, G[1]), POINT_ERROR), (1, (G[0], P), POINT_ERROR))
    for scalar, peer, error in malformed:
        agreement.agree(scalar, peer, 5, expected_error=error)
    print(f'{len(scalars) + 1} linked variable-base cases and {len(malformed)} rejections passed',
          flush=True)

    # Hold the peer fixed: its public inversion may have a different trace
    # for different peer points. Vary both private scalar and projective scale.
    traces = [agreement.agree(scalar, G, blind, trace=True)
              for scalar, blind in ((1, 1), (N - 1, P - 1), (1 << 255, 7))]
    assert traces[0][0] > 0 and traces[0][1] > 0 and len(set(traces)) == 1, traces
    print(f'Three identical traces, {traces[0][0]} instructions and {traces[0][1]} data accesses')


if __name__ == '__main__':
    main()
