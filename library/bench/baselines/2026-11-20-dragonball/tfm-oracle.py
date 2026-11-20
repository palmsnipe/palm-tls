# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the linked 68000 TFM functions with Python integer arithmetic."""
import random
import struct
import subprocess
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN
from unicorn.m68k_const import (
    UC_CPU_M68K_M68000, UC_M68K_REG_A7, UC_M68K_REG_D0, UC_M68K_REG_PC,
)

elf = Path(sys.argv[1])
nm_output = subprocess.check_output([sys.argv[2], str(elf)], text=True)
symbols = {}
for line in nm_output.splitlines():
    parts = line.split()
    if len(parts) == 3:
        symbols[parts[2]] = int(parts[0], 16)
data = elf.read_bytes()
phoff = struct.unpack_from('>I', data, 28)[0]
phsize, phnum = struct.unpack_from('>HH', data, 42)
machine = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
machine.ctl_set_cpu_model(UC_CPU_M68K_M68000)
for i in range(phnum):
    kind, offset, vaddr, _, size, memsize, _, _ = struct.unpack_from('>8I', data, phoff + phsize*i)
    if kind == 1:
        machine.mem_map(vaddr, (memsize + 4095) & ~4095)
        machine.mem_write(vaddr, data[offset:offset+size])
workspace = 0x100000
machine.mem_map(workspace, 0x10000)
stop, stack = workspace, workspace + 0xc000
# A 68000 long operand requires only even alignment, which this ABI uses.
a, b, c, d = (workspace + v for v in (0x1002, 0x2002, 0x3002, 0x4002))
layout = '>HH264H'
width = struct.calcsize(layout)

def put(addr, value):
    num = abs(value)
    used = (num.bit_length() + 15) // 16
    words = [(num >> (16*i)) & 65535 for i in range(used)]
    machine.mem_write(addr-2, b'OK' + struct.pack(layout, used, int(value < 0), *words, *([0]*(264-used))) + b'OK')

def check(addr, expected):
    raw = bytes(machine.mem_read(addr-2, width+4))
    assert raw[:2] == raw[-2:] == b'OK'
    used, sign, *limbs = struct.unpack(layout, raw[2:-2])
    value = sum(word << (16*i) for i, word in enumerate(limbs[:used]))
    assert ((-value if sign else value) == expected and
            used == (value.bit_length()+15)//16 and
            not any(limbs[used:]) and (used or sign == 0)), (used, sign, value, expected)

def call(name, args, status=True):
    machine.reg_write(UC_M68K_REG_A7, stack)
    machine.mem_write(stack, struct.pack('>I', stop) + args)
    machine.emu_start(symbols[name], stop, count=100000)
    assert machine.reg_read(UC_M68K_REG_PC) == stop, name
    if status:
        assert machine.reg_read(UC_M68K_REG_D0) & 65535 == 0, name

rng = random.Random(68)
p256 = (1 << 256) - (1 << 224) + (1 << 192) + (1 << 96) - 1
total=0
for p in [p256, (1<<256)-1, (1<<240)+1, (1<<255)+1]:
    edges = [0,1,65535,65536,p//2,p//2+1,p-2,p-1]
    cases = [(x,y) for x in edges for y in edges]
    cases.extend((rng.randrange(p),rng.randrange(p)) for _ in range(64))
    for x,y in cases:
        for out in [a,b,d]:
            for name, expected in [('fp_addmod_ct',(x+y)%p), ('fp_submod_ct',(x-y)%p)]:
                put(a, x)
                put(b, y)
                put(c, p)
                # Both inputs are zero-extended. Give d a cleared starting tail
                # as required by upstream's modular routines.
                put(d,0)
                call(name, struct.pack('>IIII', a, b, c, out))
                check(out, expected)
                total += 1
for bits_x in range(0,257,16):
    for bits_y in range(0,257,16):
        for x,y in [(rng.getrandbits(bits_x),-rng.getrandbits(bits_y)),
                    ((1<<bits_x)-1,(1<<bits_y)-1)]:
            for out in [a,b,d]:
                put(a, x)
                put(b, y)
                put(d, (1 << 1023) - 1)
                call('fp_mul_comba', struct.pack('>III', a, b, out))
                check(out, x * y)
                total += 1
    for x in [0,rng.getrandbits(bits_x),-(1<<bits_x)+1,(1<<bits_x)-1]:
        for out in [a,d]:
            put(a, x)
            put(d, (1 << 1023) - 1)
            call('fp_sqr_comba', struct.pack('>II', a, out))
            check(out, x * x)
            total += 1
for _ in range(512):
    x = rng.getrandbits(rng.randrange(257))
    y = -rng.getrandbits(rng.randrange(257))
    for flag in (0, 1):
        put(a, x)
        put(b, y)
        call('mp_cond_copy', struct.pack('>IHI', a, flag, b))
        check(b, x if flag else y)
        total += 1
    put(a, x)
    put(b, y)
    call('fp_init_copy', struct.pack('>II', a, b), status=False)
    check(a, y)
    call('fp_zero', struct.pack('>I', a), status=False)
    check(a, 0)
    total += 2
print(f'{total} linked M68000 checks passed')
