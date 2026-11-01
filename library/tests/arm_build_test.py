#!/usr/bin/env python3
"""Ensure the native packager fails closed on incompatible build artifacts."""
import argparse
import shlex
import struct
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default='clang')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='palm-tls-isa-') as directory:
        directory = Path(directory)
        source = directory / 'probe.c'
        source.write_text('__attribute__((section(".text.armlet"),used))\n'
                          'unsigned int Entry(void *state, void *data, void *callback)\n'
                          '{ return *(volatile unsigned int *)data; }\n')

        def compile(name, *flags):
            result = directory / (name + '.o')
            subprocess.run(shlex.split(args.cc) + ['--target=armv4t-none-eabi', '-marm', '-Os',
                '-ffreestanding', '-fpic', '-ffunction-sections'] + list(flags) +
                ['-c', str(source), '-o', str(result)], check=True, capture_output=True)
            return result

        def extract(path, error=None):
            result = subprocess.run(['node', str(root / 'tools/extract-armlet.mjs'), str(path),
                                     str(path.with_suffix('.bin'))], capture_output=True, text=True)
            if error:
                assert result.returncode != 0 and error in result.stderr, result.stderr
            else:
                assert result.returncode == 0, result.stderr
                assert path.with_suffix('.bin').stat().st_size > 0

        baseline = compile('v4t', '-mcpu=arm7tdmi', '-march=armv4t')
        extract(baseline)
        # Use explicit incompatible architectures so this test does not depend
        # on compiler-version-specific precedence between -mcpu and -march.
        extract(compile('xscale', '-mcpu=xscale', '-march=armv5te'), 'outside the ARMv4T')
        extract(compile('v5te', '-mcpu=arm926ej-s', '-march=armv5te'), 'outside the ARMv4T')
        data = baseline.read_bytes()
        missing = directory / 'missing.o'
        missing.write_bytes(data.replace(b'.ARM.attributes\0', b'.BAD.attributes\0'))
        extract(missing, 'missing ARM build attributes')
        broken = bytearray(data)
        sections, count, names = struct.unpack_from('<I', data, 32)[0], struct.unpack_from('<H', data, 48)[0], struct.unpack_from('<H', data, 50)[0]
        names_offset = struct.unpack_from('<I', data, sections + names * 40 + 16)[0]
        for i in range(count):
            name = struct.unpack_from('<I', data, sections + i * 40)[0] + names_offset
            if data[name:name + 16] == b'.ARM.attributes\0':
                offset = struct.unpack_from('<I', data, sections + i * 40 + 16)[0]
                broken[offset] = 0
                break
        else:
            raise AssertionError('probe compiler did not emit ARM attributes')
        malformed = directory / 'malformed.o'
        malformed.write_bytes(broken)
        extract(malformed, 'invalid ARM build attributes')
    print('ARM packager ISA checks passed: ARMv4T accepted; XScale/ARMv5TE/missing/malformed attributes rejected')


if __name__ == '__main__':
    main()
