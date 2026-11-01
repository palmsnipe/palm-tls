"""Strict reader for the common-ABI release comparison."""
import csv
import statistics
import struct
import zipfile

def extract(archive, allow_failed=False):
    with zipfile.ZipFile(archive) as backup:
        matches=[backup.read(name) for name in backup.namelist()
                 if not name.endswith('/') and backup.read(name)[:32].split(b'\0')[0]
                 == b'PalmTLS Handshake Results']
    if len(matches)!=1: raise ValueError('expected one handshake results database')
    data=matches[0]
    if data[60:68]!=b'DATAThsb': raise ValueError('invalid handshake database identity')
    count=struct.unpack_from('>H',data,76)[0]
    offsets=[struct.unpack_from('>I',data,78+i*8)[0] for i in range(count)]
    if not offsets or offsets[0]<78+count*8 or offsets!=sorted(set(offsets)):
        raise ValueError('invalid handshake record table')
    offsets.append(len(data))
    text=b''.join(data[a:b] for a,b in zip(offsets,offsets[1:])).decode('ascii')
    if not allow_failed and not text.endswith('# complete release-v1\n'):
        raise ValueError('handshake benchmark incomplete')
    return text


def load(text):
    if not text.endswith('# complete release-v1\n'): raise ValueError('incomplete benchmark')
    rows = list(csv.DictReader(line for line in text.splitlines() if not line.startswith('#')))
    expected = {(name, sample) for name in ('cold_full','warm_full','resumed') for sample in range(5)}
    actual = set()
    for row in rows:
        if set(row) != {'case','sample','frequency','open_ticks','load_ticks','reported_handshake_ticks','session_reused'}:
            raise ValueError('unexpected schema')
        key = row['case'], int(row['sample'])
        if key in actual: raise ValueError('duplicate sample')
        actual.add(key)
        if int(row['frequency']) <= 0 or any(int(row[k]) < 0 for k in row if k != 'case'):
            raise ValueError('invalid measurement')
        if int(row['session_reused']) != (row['case'] == 'resumed'):
            raise ValueError('unexpected resumption')
        if row['case'] != 'cold_full' and int(row['load_ticks']):
            raise ValueError('warm engine reloaded')
    if actual != expected or len({row['frequency'] for row in rows}) != 1:
        raise ValueError('missing samples or inconsistent clock')
    return rows


def summarize(text):
    rows = load(text)
    return {name: {'median_ms': statistics.median(values), 'min_ms': min(values), 'max_ms': max(values)}
        for name in ('cold_full','warm_full','resumed')
        for values in [[1000*int(r['open_ticks'])/int(r['frequency']) for r in rows if r['case']==name]]}


def validate_server(path):
    import json
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if len(rows) != 15 or any(r.get('request') != 'release-probe\n' or r.get('version') != 'TLSv1.3' for r in rows):
        raise ValueError('unexpected server connections')
    if sum(r['resumed'] for r in rows) != 5 or len({r['cipher'] for r in rows}) != 1:
        raise ValueError('server did not confirm full/resumed counts and one cipher')
    return rows[0]['cipher']
