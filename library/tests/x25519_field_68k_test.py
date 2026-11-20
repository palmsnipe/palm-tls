#!/usr/bin/env python3
"""Verify X25519 field results and instruction/address traces on the linked 68000 code."""
import argparse
import itertools
import random
import statistics
import struct
from pathlib import Path

from p256_fixed_68k_test import M68k

P = (1 << 255) - 19
LIMIT = 1 << 256
WORDS = struct.Struct('>16H')
OPERATIONS = {'multiply': 'FieldMultiply', 'square': 'FieldSquare'}


def encode(value):
    return WORDS.pack(*((value >> (16 * i)) & 0xffff for i in range(16)))


def check(machine, operation, a, b=None, alias=None, trace=False):
    left, right, output = 0x101002, 0x102002, 0x103002
    memory = machine.cpu
    memory.mem_write(left - 2, b'OK' + encode(a) + b'OK')
    if b is not None:
        memory.mem_write(right - 2, b'OK' + encode(b) + b'OK')
    if alias == 'left':
        output = left
    elif alias == 'right':
        output = right
    else:
        memory.mem_write(output - 2, b'OK' + b'\xa5' * WORDS.size + b'OK')
    args = (output, left, right) if operation == 'multiply' else (output, left)
    _, result = machine.invoke(OPERATIONS[operation], args, trace)
    data = memory.mem_read(output - 2, WORDS.size + 4)
    value = sum(word << (16 * i) for i, word in enumerate(WORDS.unpack(data[2:-2])))
    assert data[:2] == data[-2:] == b'OK'
    assert value % P == a * (a if b is None else b) % P, (operation, hex(a), b, alias)
    if output != left:
        assert memory.mem_read(left, WORDS.size) == encode(a)
    if b is not None and output != right:
        assert memory.mem_read(right, WORDS.size) == encode(b)
    return result


def verify(machine):
    half = 1 << 128
    edges = (0, 1, 2, 0xffff, half - 1, half, half + 1, 2 * half - 1,
             (half - 1) * half, P - 1, P, P + 1, 1 << 255, LIMIT - 1)
    rng = random.Random(6825519)
    edge_pairs = list(itertools.product(edges, repeat=2))
    products = edge_pairs + [(rng.randrange(LIMIT), rng.randrange(LIMIT)) for _ in range(256)]
    squares = (*edges, *(rng.randrange(LIMIT) for _ in range(256)))
    for a, b in products:
        check(machine, 'multiply', a, b)
    for a in squares:
        check(machine, 'square', a)
    for a, b in edge_pairs:
        check(machine, 'multiply', a, b, alias='left')
        check(machine, 'multiply', a, b, alias='right')
    for a in edges:
        check(machine, 'square', a, alias='left')

    for operation in OPERATIONS:
        fixtures = products if operation == 'multiply' else [(a, None) for a in squares]
        traces = {check(machine, operation, a, b, trace=True) for a, b in fixtures}
        assert len(traces) == 1, f'{operation} has input-dependent traces'
        instructions, accesses, _ = traces.pop()
        print(f'# {operation}: {len(fixtures)} identical traces, '
              f'{instructions} instructions and {accesses} data accesses')
    return len(products) + len(squares) + 2 * len(edge_pairs) + len(edges)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('nm', type=Path)
    parser.add_argument('--baseline', type=Path, help='compare instructions on 32 shared fixtures')
    args = parser.parse_args()
    candidate = M68k(args.elf, args.nm)
    print(f'# {verify(candidate)} linked field cases passed')
    if args.baseline:
        baseline = M68k(args.baseline, args.nm)
        rng = random.Random(68255)
        pairs = [(rng.randrange(LIMIT), rng.randrange(LIMIT)) for _ in range(32)]
        print('variant,operation,median_instructions,min_instructions,max_instructions')
        for label, machine in (('baseline', baseline), ('candidate', candidate)):
            for operation in OPERATIONS:
                counts = [check(machine, operation, a, b if operation == 'multiply' else None,
                                trace=True)[0] for a, b in pairs]
                print(f'{label},{operation},{statistics.median(counts):g},{min(counts)},{max(counts)}')


if __name__ == '__main__':
    main()
