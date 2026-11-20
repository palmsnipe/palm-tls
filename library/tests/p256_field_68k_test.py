#!/usr/bin/env python3
"""Check the linked public P-256 field kernels against Python integers."""
import argparse
import itertools
import random
import statistics
import struct
from pathlib import Path

from crypto_oracle_test import P
from p256_fixed_68k_test import M68k

LIMBS = struct.Struct('>16H')
MONTGOMERY_INVERSE = pow(1 << 256, -1, P)
OPERATIONS = {'multiply': 'FeMultiplyPublic', 'square': 'FeSquarePublic'}


def encode(value):
    return LIMBS.pack(*((value >> (16 * i)) & 0xffff for i in range(16)))


def check(cpu, operation, a, b=None, alias=None, trace=False):
    left, right, output = 0x101002, 0x102002, 0x103002
    emulator = cpu.cpu
    emulator.mem_write(left - 2, b'OK' + encode(a) + b'OK')
    if b is not None:
        emulator.mem_write(right - 2, b'OK' + encode(b) + b'OK')
    if alias == 'left':
        output = left
    elif alias == 'right':
        output = right
    else:
        emulator.mem_write(output - 2, b'OK' + b'\xa5' * LIMBS.size + b'OK')
    args = (output, left, right) if operation == 'multiply' else (output, left)
    _, (instructions, _, _) = cpu.invoke(OPERATIONS[operation], args, trace)
    data = emulator.mem_read(output - 2, LIMBS.size + 4)
    expected = (a * (a if b is None else b) * MONTGOMERY_INVERSE) % P
    assert data == b'OK' + encode(expected) + b'OK', (operation, hex(a), b, alias)
    if output != left:
        assert emulator.mem_read(left, LIMBS.size) == encode(a)
    if b is not None and output != right:
        assert emulator.mem_read(right, LIMBS.size) == encode(b)
    return instructions


def verify(cpu):
    half = 1 << 128
    edges = (0, 1, 2, (1 << 16) - 1, half - 1, half, half + 1,
             2 * half - 1, half * (half // 2 - 1) + (half - 1), P - 2, P - 1)
    rng = random.Random(68128)
    products = list(itertools.product(edges, repeat=2))
    products.extend((rng.randrange(P), rng.randrange(P)) for _ in range(256))
    squares = (*edges, *(rng.randrange(P) for _ in range(256)))
    for a, b in products:
        check(cpu, 'multiply', a, b)
    for a in squares:
        check(cpu, 'square', a)
    for a, b in itertools.product(edges, repeat=2):
        check(cpu, 'multiply', a, b, alias='left')
        check(cpu, 'multiply', a, b, alias='right')
    for a in edges:
        check(cpu, 'square', a, alias='left')
    return len(products) + len(squares) + 2 * len(edges)**2 + len(edges)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('nm', type=Path)
    parser.add_argument('--baseline', type=Path, help='compare instructions on 32 identical fixtures')
    args = parser.parse_args()
    candidate = M68k(args.elf, args.nm)
    print(f'# {verify(candidate)} linked field cases passed')
    if args.baseline:
        baseline = M68k(args.baseline, args.nm)
        rng = random.Random(68016)
        pairs = [(rng.randrange(P), rng.randrange(P)) for _ in range(32)]
        print('variant,operation,median_instructions,min_instructions,max_instructions')
        for name, cpu in (('baseline', baseline), ('candidate', candidate)):
            for operation in OPERATIONS:
                counts = [check(cpu, operation, a, b if operation == 'multiply' else None,
                                trace=True) for a, b in pairs]
                print(f'{name},{operation},{statistics.median(counts):g},{min(counts)},{max(counts)}')


if __name__ == '__main__':
    main()
