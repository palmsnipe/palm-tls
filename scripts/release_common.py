"""Offline validation shared by candidate building, benchmarks and promotion."""
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/build-artifacts.yml'
PRCS = ('PalmTLS68K.prc', 'PalmTLS68K-Modern.prc', 'PalmTLS68K-TLS13.prc',
        'PalmTLSArm.prc', 'PalmTLSArm-Modern.prc', 'PalmTLSArm-TLS13.prc', 'TlsTester.prc')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha(path.read_bytes())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def command(args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, text=True,
                          capture_output=True, **kwargs).stdout.strip()


def version(value):
    require(bool(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value)),
            f'invalid release version: {value}')
    return value


def versions(root=ROOT):
    values = []
    for name, variable in (('library/app.mk', 'LIB_VERSION'), ('apps/tls-tester/app.mk', 'APP_VERSION')):
        matches = re.findall(rf'^{variable} := (.+)$', (root / name).read_text(), re.M)
        require(len(matches) == 1, f'missing or duplicate {variable}')
        values.append(version(matches[0]))
    require(values[0] == values[1], 'library and TLS Tester versions differ')
    return values[0]


def clean_commit(root=ROOT):
    require(not command(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root),
            'commit all changes before creating a release candidate')
    return command(['git', 'rev-parse', 'HEAD'], cwd=root)


def preflight(root=ROOT):
    commit = clean_commit(root)
    selected = versions(root)
    require(not command(['git', 'tag', '--list', f'v{selected}'], cwd=root),
            f'v{selected} already exists; prepare a new version, never move a release tag')
    notes = root / f'docs/releases/{selected}.md'
    require(notes.is_file() and len(notes.read_text().strip()) > 40, 'write the release notes first')
    require(not re.search(r'\b(TODO|TBD|FIXME)\b', notes.read_text()), 'finish the release-note placeholders')
    return selected, commit


def safe_path(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts and '\\' not in name,
            f'unsafe relative path: {name}')
    require(str(path) == name, f'noncanonical path: {name}')
    return path


def files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), f'symlinks are not release inputs: {path}')
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def verify_files(root, expected, manifest):
    for name, value in expected.items():
        safe_path(name)
        require(bool(re.fullmatch('[a-f0-9]{64}', value)), f'invalid SHA-256 for {name}')
    actual = files(root)
    actual.pop(manifest, None)
    require(actual == expected, f'{root}: missing, extra or changed files')


def resources(data):
    require(len(data) >= 78, 'truncated PRC header')
    count = struct.unpack_from('>H', data, 76)[0]
    require(count > 0 and 78 + count * 10 <= len(data), 'truncated PRC resource table')
    entries = [struct.unpack_from('>4sHI', data, 78 + i * 10) for i in range(count)]
    result = {}
    for i, (kind, number, start) in enumerate(entries):
        end = entries[i + 1][2] if i + 1 < count else len(data)
        require(78 + count * 10 <= start < end <= len(data), 'invalid PRC resource bounds/order')
        require((kind, number) not in result, 'duplicate PRC resource')
        if kind == b'armc':
            require(start % 4 == 0, 'unaligned ARM resource')
        result[kind, number] = data[start:end]
    return result


def prc_version(data):
    entries = resources(data)
    value = entries.get((b'tver', 1), entries.get((b'tver', 1000), b'')).split(b'\0')[0].decode('ascii')
    return version(value)


def native(data):
    image = resources(data).get((b'armc', 1))
    require(image is not None and 0 < len(image) <= 65536, 'missing or oversized native ARM image')
    return image


def verify_zip(data, selected, expected=None):
    """Validate paths and the ZIP's complete internal checksum manifest."""
    import io
    prefix = f'PalmTLS-{selected}/'
    contents = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            require(entry.filename.startswith(prefix), 'unexpected release ZIP root')
            safe_path(entry.filename.rstrip('/'))
            require((entry.external_attr >> 16) & 0o170000 != 0o120000, 'symlink in release ZIP')
            if entry.is_dir():
                continue
            name = entry.filename[len(prefix):]
            require(name not in contents, 'duplicate ZIP member')
            contents[name] = archive.read(entry)
    require('SHA256SUMS' in contents, 'release ZIP has no checksums')
    sums = {}
    for line in contents['SHA256SUMS'].decode().splitlines():
        checksum, name = line.split(None, 1)
        name = name.removeprefix('./')
        safe_path(name)
        require(name not in sums, 'duplicate checksum entry')
        sums[name] = checksum
    require({k: sha(v) for k, v in contents.items() if k != 'SHA256SUMS'} == sums,
            'release ZIP checksum coverage or content mismatch')
    if expected is not None:
        require({k: sha(v) for k, v in contents.items()} == expected, 'ZIP differs from packaged dist')
    return contents


def verify_candidate(root):
    manifest = json.loads((root / 'candidate.json').read_text())
    require(manifest['format'] == 1, 'unsupported candidate format')
    selected = version(manifest['version'])
    require(bool(re.fullmatch('[a-f0-9]{40}', manifest['commit'])), 'invalid candidate commit')
    require(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', manifest['repository'])), 'invalid repository')
    require(type(manifest['run_id']) is int and manifest['run_id'] > 0 and
            type(manifest['run_attempt']) is int and manifest['run_attempt'] > 0, 'invalid workflow run')
    expected_names = {f'assets/{name}' for name in PRCS + (f'PalmTLS-{selected}.zip',)}
    expected_names |= {'notes.md', 'validation/ti925t.log', 'validation/pxa270.log'}
    require(set(manifest['files']) == expected_names, 'unexpected candidate file list')
    verify_files(root, manifest['files'], 'candidate.json')
    for cpu in ('ti925t', 'pxa270'):
        require(f'Crypto oracles passed ({cpu}):' in (root / f'validation/{cpu}.log').read_text(),
                f'missing {cpu} native validation')
    contents = verify_zip((root / f'assets/PalmTLS-{selected}.zip').read_bytes(), selected)
    require(f'PalmTLS commit: {manifest["commit"]}\n' in contents['SOURCE.txt'].decode(), 'wrong source commit')
    require(bool(re.fullmatch(r'.+@sha256:[a-f0-9]{64}', manifest['toolchain_image'])), 'toolchain image is not pinned')
    require(f'Toolchain image: {manifest["toolchain_image"]}\n' in contents['SOURCE.txt'].decode(), 'wrong toolchain image')
    require(bool(re.fullmatch('[a-f0-9]{40}', manifest['wolfssl_commit'])), 'invalid wolfSSL commit')
    require(f'WOLFSSL_COMMIT="{manifest["wolfssl_commit"]}"' in contents['SOURCE.txt'].decode(), 'wrong wolfSSL source')
    images = []
    for name in PRCS:
        data = (root / 'assets' / name).read_bytes()
        packaged = ('tls-tester/' if name == 'TlsTester.prc' else 'library/') + name
        require(data == contents[packaged], f'{name} differs from binary ZIP')
        require(prc_version(data) == selected, f'{name} version differs from candidate')
        if name.startswith('PalmTLSArm'):
            images.append(native(data))
    require(all(image == images[0] for image in images), 'ARM profiles have different native images')
    require(sha(images[0]) == manifest['arm_image_sha256'] and len(images[0]) == manifest['arm_image_bytes'],
            'native image differs from candidate manifest')
    return manifest


def deterministic_zip(path, members):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(members.items()):
            safe_path(name)
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
