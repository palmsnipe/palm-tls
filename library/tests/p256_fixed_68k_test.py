#!/usr/bin/env python3
"""Check the linked 68000 generator multiply and compare its execution traces."""
import argparse
import hashlib
import random
import struct
import subprocess
from pathlib import Path

import unicorn as uc
from unicorn import m68k_const as regs

from crypto_oracle_test import G, N, P, multiply

INTEGER = struct.Struct('>HH264H')  # TFM used, sign, and little-endian limbs


class M68k:
    STOP = 0x100000
    SCALAR = 0x101002
    POINT = 0x102002
    STACK = 0x120000

    def __init__(self, elf, nm):
        symbols = subprocess.check_output([str(nm), str(elf)], text=True)
        self.symbols = {}
        for line in symbols.splitlines():
            fields = line.split()
            if len(fields) == 3:
                self.symbols[fields[2]] = int(fields[0], 16)
        self.cpu = uc.Uc(uc.UC_ARCH_M68K, uc.UC_MODE_BIG_ENDIAN)
        self.cpu.ctl_set_cpu_model(regs.UC_CPU_M68K_M68000)

        image = elf.read_bytes()
        start = struct.unpack_from('>I', image, 28)[0]
        step, count = struct.unpack_from('>HH', image, 42)
        for i in range(count):
            kind, offset, address, _, size, memory, _, _ = struct.unpack_from(
                '>8I', image, start + i * step)
            if kind == 1:  # PT_LOAD
                self.cpu.mem_map(address, (memory + 4095) & ~4095)
                self.cpu.mem_write(address, image[offset:offset + size])
        self.cpu.mem_map(self.STOP, self.STACK - self.STOP + 4096)

    def field_input(self, address, value):
        limbs = [(value >> (16 * i)) & 0xffff for i in range(264)]
        used = (value.bit_length() + 15) // 16
        self.cpu.mem_write(address, INTEGER.pack(used, 0, *limbs))

    def field_output(self, address):
        used, sign, *limbs = INTEGER.unpack(self.cpu.mem_read(address, INTEGER.size))
        value = sum(limb << (16 * i) for i, limb in enumerate(limbs[:used]))
        assert sign == 0 and used == (value.bit_length() + 15) // 16
        assert not any(limbs[used:])
        return value

    def invoke(self, name, args, trace):
        cpu = self.cpu
        cpu.reg_write(regs.UC_M68K_REG_A7, self.STACK)
        cpu.mem_write(self.STACK, struct.pack(f'>{len(args) + 1}I', self.STOP, *args))

        hooks = []
        instructions = 0
        accesses = 0
        digest = hashlib.sha256()
        if trace:
            def instruction(_, address, size, __):
                nonlocal instructions
                instructions += 1
                digest.update(struct.pack('>BIB', 0, address, size))

            def memory(_, access, address, size, value, __):
                nonlocal accesses
                accesses += 1
                digest.update(struct.pack('>BIB', access, address, size))

            # Flush decoded code so new hooks cover previously executed paths.
            cpu.ctl_flush_tb()
            hooks.append(cpu.hook_add(uc.UC_HOOK_CODE, instruction))
            hooks.append(cpu.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, memory))
        try:
            cpu.emu_start(self.symbols[name], self.STOP, count=100_000_000)
            assert cpu.reg_read(regs.UC_M68K_REG_PC) == self.STOP
        finally:
            for hook in hooks:
                cpu.hook_del(hook)
            if hooks:
                cpu.ctl_flush_tb()

        status = cpu.reg_read(regs.UC_M68K_REG_D0) & 65535
        return status, (instructions, accesses, digest.hexdigest())

    def run(self, scalar, blind, trace=False):
        cpu = self.cpu
        self.field_input(self.SCALAR, scalar)
        cpu.mem_write(self.POINT - 2, b'OK' + b'\xa5' * (3 * INTEGER.size) + b'OK')
        z = self.POINT + 2 * INTEGER.size
        self.field_input(z, blind)  # Production passes the output Z as the blinding input.
        _, trace_result = self.invoke('PalmTlsP256MakePublic', (self.SCALAR, z, self.POINT), trace)
        assert self.field_output(self.SCALAR) == scalar
        assert self.field_output(z) == 1
        assert cpu.mem_read(self.POINT - 2, 2) == b'OK'
        assert cpu.mem_read(z + INTEGER.size, 2) == b'OK'
        coordinates = self.field_output(self.POINT), self.field_output(self.POINT + INTEGER.size)
        return coordinates, trace_result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('nm', type=Path)
    args = parser.parse_args()
    m68k = M68k(args.elf, args.nm)
    rng = random.Random(68000)
    scalars = {1, 2, N - 2, N - 1, *(1 << bit for bit in range(256))}
    # Hit all six-tooth combinations and every native word boundary.
    scalars.update(sum(1 << (43 * tooth) for tooth in range(6) if digit & (1 << tooth))
                   for digit in range(1, 64))
    scalars.update(rng.randrange(1, N) for _ in range(40))
    for index, scalar in enumerate(sorted(scalars)):
        blind = (1, P - 1, rng.randrange(1, P))[index % 3]
        coordinates, _ = m68k.run(scalar, blind)
        assert coordinates == multiply(scalar, G), f'mismatch for scalar {scalar:x}'
    print(f'{len(scalars)} linked 68000 fixed-base cases passed', flush=True)

    traces = []
    for scalar, blind in ((1, 1), (1 << 255, P - 1), (N - 1, 2),
                          (rng.randrange(1, N), rng.randrange(1, P))):
        coordinates, trace = m68k.run(scalar, blind, trace=True)
        assert coordinates == multiply(scalar, G)
        traces.append(trace)
    assert traces[0][0] > 0 and traces[0][1] > 0 and len(set(traces)) == 1, traces
    print(f'Four identical traces, {traces[0][0]} instructions and {traces[0][1]} data accesses')


if __name__ == '__main__':
    main()
