#!/usr/bin/env python3
"""Copy a benchmark PRC with the tested library's native resource for provenance.

The common-ABI benchmark calls library traps; its native resource is never
executed directly. The runner requires matching images to prevent stale builds.
"""
import argparse
import importlib.util
import struct
from pathlib import Path


def bind(app, library):
    spec = importlib.util.spec_from_file_location('runner', Path(__file__).with_name('run-emulator.py'))
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    data = app.read_bytes()
    count = struct.unpack_from('>H', data, 76)[0]
    entries = [struct.unpack_from('>4sHI', data, 78+i*10) for i in range(count)]
    output = bytearray(data[:entries[0][2]])
    found = 0
    for i, (kind, number, start) in enumerate(entries):
        end = entries[i+1][2] if i+1<count else len(data)
        blob = data[start:end]
        if kind == b'armc' and number == 1:
            if len(output)%4: raise ValueError('native resource is not aligned')
            blob = runner.native_image(library)
            found += 1
        struct.pack_into('>I', output, 84+i*10, len(output))
        output.extend(blob)
    if found != 1: raise ValueError('expected one armc:1 resource')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app',type=Path)
    parser.add_argument('library',type=Path)
    parser.add_argument('output',type=Path)
    args = parser.parse_args()
    args.output.write_bytes(bind(args.app,args.library))
