#!/usr/bin/env python3
"""Extract Palm benchmark records and summarize or compare checked CSV files."""
import argparse
import csv
import statistics
import struct
import zipfile
from pathlib import Path

EXPECTED_CASES = {
    'multiply_256', 'multiply_2048', 'p256_fixed_affine', 'p256_general_affine',
    'p256_fixed_raw', 'p256_map', 'p256_mul2add', 'sha256_1_block', 'sha256_8_blocks',
    *(f'gcm_{direction}_{size}' for direction in ('encrypt', 'decrypt')
      for size in (16, 512, 4096, 16384)),
}
VERIFY_PHASES = ('other', 'signature', 'range', 'curve', 'hex', 'order', 'point', 'final')
PROFILE_CASES = {f'{protocol}_verify_phase_{phase}'
                 for protocol in ('tls12', 'tls13') for phase in VERIFY_PHASES}
GENERATOR_CASES = {'p256_mul2add_generator', 'p256_mul2add_generator_right'}


def extract(archive):
    with zipfile.ZipFile(archive) as backup:
        matches = []
        for name in backup.namelist():
            if name.endswith('/'):
                continue
            data = backup.read(name)
            if len(data) >= 78 and data[:32].split(b'\0')[0] == b'PalmTLS Bench Results':
                matches.append(data)
    if len(matches) != 1:
        raise ValueError('expected exactly one PalmTLS Bench Results database')
    data = matches[0]
    if data[60:68] != b'DATATbch' or struct.unpack_from('>H', data, 32)[0] & 1:
        raise ValueError('unexpected results database identity or format')
    count = struct.unpack_from('>H', data, 76)[0]
    table_end = 78 + count * 8
    if table_end > len(data):
        raise ValueError('truncated record table')
    offsets = [struct.unpack_from('>I', data, 78 + i * 8)[0] for i in range(count)]
    if not offsets or offsets[0] < table_end or offsets != sorted(set(offsets)):
        raise ValueError('invalid record offsets')
    offsets.append(len(data))
    text = b''.join(data[a:b] for a, b in zip(offsets, offsets[1:])).decode('ascii')
    if not text.endswith('# complete v1\n') or '# FAILED' in text:
        raise ValueError('benchmark is incomplete or failed')
    return text


def load(text):
    grouped = {}
    lines = [line for line in text.splitlines() if not line.startswith('#')]
    for row in csv.DictReader(lines):
        name = row.pop('case')
        values = {key: int(value) for key, value in row.items()}
        if set(values) != {'sample', 'iterations', 'elapsed', 'frequency', 'bytes_per_op'}:
            raise ValueError('unexpected CSV schema')
        if min(values.values()) < 0 or values['iterations'] == 0 or values['frequency'] == 0:
            raise ValueError(f'invalid timing for {name}')
        if values['elapsed'] == 0 and not (name.endswith('_load') or name in PROFILE_CASES):
            raise ValueError(f'timing below clock resolution for {name}')
        grouped.setdefault(name, []).append(values)
    for name, rows in grouped.items():
        if sorted(row['sample'] for row in rows) != list(range(5)):
            raise ValueError(f'{name} must have five distinct samples')
        if len({(r['frequency'], r['bytes_per_op'], r['iterations']) for r in rows}) != 1:
            raise ValueError(f'inconsistent samples for {name}')
    if not EXPECTED_CASES.issubset(grouped):
        raise ValueError('missing benchmark cases')
    # Historical runs have neither generator-specific case. New runs must
    # contain both, so a truncated generator comparison cannot pass as complete.
    if GENERATOR_CASES.intersection(grouped) and not GENERATOR_CASES.issubset(grouped):
        raise ValueError('missing generator benchmark case')
    for protocol in ('tls12', 'tls13'):
        names = [f'{protocol}_verify_phase_{phase}' for phase in VERIFY_PHASES]
        if any(name in grouped for name in names):
            if not all(name in grouped for name in names) or f'{protocol}_verify' not in grouped:
                raise ValueError('incomplete verification profile')
            for total in grouped[f'{protocol}_verify']:
                phases = [next(row for row in grouped[name] if row['sample'] == total['sample'])
                          for name in names]
                if any(row['frequency'] != total['frequency'] or row['iterations'] != 1
                       or row['bytes_per_op'] != 0 for row in phases):
                    raise ValueError('invalid verification phase workload')
                if sum(row['elapsed'] for row in phases) != total['elapsed']:
                    raise ValueError('verification phases do not sum to total')
    return grouped


def summarize(grouped, baseline=None):
    if baseline is not None and grouped.keys() != baseline.keys():
        raise ValueError('baseline and candidate must contain the same cases')
    print('case,median_us_per_op,min_us_per_op,max_us_per_op,KiB_per_s' +
          (',change_percent' if baseline else ''))
    for name, rows in grouped.items():
        samples = [r['elapsed'] * 1e6 / r['frequency'] / r['iterations'] for r in rows]
        median = statistics.median(samples)
        size = rows[0]['bytes_per_op']
        throughput = f'{size * 1e6 / median / 1024:.3f}' if size and median else ''
        line = f'{name},{median:.3f},{min(samples):.3f},{max(samples):.3f},{throughput}'
        if baseline is not None:
            other = baseline[name]
            if (rows[0]['frequency'], size) != (other[0]['frequency'], other[0]['bytes_per_op']):
                raise ValueError('cannot compare different clock frequencies or workloads')
            old = statistics.median(r['elapsed'] * 1e6 / r['frequency'] / r['iterations'] for r in other)
            line += f',{(median / old - 1) * 100:+.2f}' if old else ','
        print(line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='raw CSV or cp-uarm db-export ZIP')
    parser.add_argument('--extract', type=Path, help='write raw CSV from a ZIP')
    parser.add_argument('--baseline', type=Path, help='raw CSV; negative change means faster')
    args = parser.parse_args()
    text = extract(args.input) if zipfile.is_zipfile(args.input) else args.input.read_text()
    grouped = load(text)
    if args.extract:
        args.extract.write_text(text)
    baseline = load(args.baseline.read_text()) if args.baseline else None
    if args.baseline:
        import json
        files = [path.parent / 'metadata.json' for path in (args.input, args.baseline)]
        if all(path.exists() for path in files):
            candidate_meta, baseline_meta = [json.loads(path.read_text()) for path in files]
            for key in ('benchmark_version', 'mips', 'device', 'session_sha256', 'emulator_sha256'):
                if candidate_meta.get(key) != baseline_meta.get(key):
                    raise ValueError(f'cannot compare different {key}')
    summarize(grouped, baseline)


if __name__ == '__main__':
    main()
