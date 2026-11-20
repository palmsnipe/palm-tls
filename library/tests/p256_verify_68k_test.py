#!/usr/bin/env python3
"""Check the linked 68000 public double-scalar and projective comparison paths."""
import argparse
import random
from pathlib import Path

from crypto_oracle_test import G, N, P, add, multiply
from p256_fixed_68k_test import INTEGER
from p256_variable_68k_test import Agreement, B, INFINITY_ERROR, POINT_ERROR


class Verifier(Agreement):
    PEER_SCALAR = 0x107002
    R = 0x107402

    def verify(self, left, peer, right, r, want, error=0):
        self.field_input(self.SCALAR, left)
        self.field_input(self.PEER_SCALAR, right)
        self.field_input(self.R, r)
        for i, coordinate in enumerate((*peer, 1)):
            self.field_input(self.POINT + i * INTEGER.size, coordinate)
        self.cpu.mem_write(self.OUTPUT, b'OK\x00\x02OK')
        status, _ = self.invoke('PalmTlsP256Verify',
            (self.SCALAR, self.POINT, self.PEER_SCALAR, self.R, self.ORDER,
             self.PRIME, self.SCRATCH, self.OUTPUT + 2), False)
        assert status == (error & 65535)
        assert self.cpu.mem_read(self.OUTPUT, 6) == b'OK' + bytes((0, int(want))) + b'OK'
        assert not self.allocations


def test_vectors(verifier):
    rng = random.Random(68067)
    minus_g = (G[0], P - G[1])
    vectors = [(1, G, 1),                     # Equal operands.
               (1, minus_g, 1),               # Cancellation to infinity.
               (129, minus_g, 128),           # Cancellation, then recovery.
               (0, G, 1), (1, G, 0), (0, G, 0),
               (N - 1, multiply(5, G), N - 1)]
    # Force each signed odd generator digit and each signed peer digit.
    for digit in range(1, 64, 2):
        vectors.extend([(digit, G, 0), (128 - digit, G, 0)])
    peer = multiply(7, G)
    for digit in range(1, 16, 2):
        vectors.extend([(0, peer, digit), (0, peer, 32 - digit)])
    vectors.extend((rng.randrange(1, N), multiply(rng.randrange(1, N), G),
                    rng.randrange(1, N)) for _ in range(24))
    for left, peer, right in vectors:
        result = add(multiply(left, G), multiply(right, peer))
        if result is None:
            verifier.verify(left, peer, right, 1, False)
        else:
            r = result[0] % N
            verifier.verify(left, peer, right, r, True)
            verifier.verify(left, peer, right, r % (N - 1) + 1, False)

    for x in range(N + 1, N + 100):
        square = (x**3 - 3*x + B) % P
        y = pow(square, (P + 1) // 4, P)
        if y*y % P == square:
            verifier.verify(0, (x, y), 1, x - N, True)
            break
    else:
        raise AssertionError('no valid r+n test point')
    verifier.verify(1, (1, 1), 1, 1, False, POINT_ERROR)
    verifier.verify(1, (0, 0), 1, 1, False, INFINITY_ERROR)
    print(f'{len(vectors)} linked double-scalar vectors and projective comparison edge cases passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('nm', type=Path)
    args = parser.parse_args()
    test_vectors(Verifier(args.elf, args.nm))


if __name__ == '__main__':
    main()
