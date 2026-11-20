"""Validate and summarize standalone 68K key exchange timings."""
import argparse
import csv
import statistics
from pathlib import Path

from results import extract_records

CASES = ('p256_keygen', 'p256_agreement', 'x25519_keygen', 'x25519_agreement')
FIXED_CASE = 'x25519_fixed_keygen'
NATIVE_AGREEMENT = 'x25519_native_agreement'
COLUMNS = ('case', 'sample', 'ticks', 'frequency')
VERSIONS = {
    '# complete key-exchange-v1': CASES,
    '# complete key-exchange-v2': CASES + (FIXED_CASE,),
    '# complete key-exchange-v3': CASES + (FIXED_CASE, NATIVE_AGREEMENT),
}


def extract(archive):
    return extract_records(archive, 'PalmTLS KX Results', b'Tkxb')


def load(text):
    lines = text.splitlines()
    if not lines or lines[-1] not in VERSIONS:
        raise ValueError('incomplete key exchange benchmark')
    cases = VERSIONS[lines[-1]]
    reader = csv.DictReader(lines[:-1])
    if tuple(reader.fieldnames or ()) != COLUMNS:
        raise ValueError('unexpected key exchange columns')
    rows = {}
    for row in reader:
        name = row['case']
        sample, ticks, frequency = (int(row[column]) for column in COLUMNS[1:])
        if None in row or name not in cases or (name, sample) in rows or min(ticks, frequency) <= 0:
            raise ValueError('invalid key exchange sample')
        rows[name, sample] = (ticks, frequency)
    if rows.keys() != {(name, sample) for name in cases for sample in range(5)}:
        raise ValueError('missing or unexpected key exchange samples')
    if len({frequency for _, frequency in rows.values()}) != 1:
        raise ValueError('inconsistent key exchange clocks')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    rows = load(parser.parse_args().input.read_text())
    print('case,median_ms,min_ms,max_ms')
    for name in dict.fromkeys(case for case, _ in rows):
        samples = [1000 * ticks / frequency for (case, _), (ticks, frequency) in rows.items()
                   if case == name]
        print(f'{name},{statistics.median(samples):.1f},{min(samples):.1f},{max(samples):.1f}')


if __name__ == '__main__':
    main()
