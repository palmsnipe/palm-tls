"""Run and verify public benchmark evidence; keep ROMs, keys and PRCs private."""
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from release_common import (ROOT, digest, files, prc_version, require,
                            verify_candidate, verify_files, write_json)

BENCH = ROOT / 'library/bench'
sys.path.insert(0, str(BENCH))
from release_results import load, validate_server  # noqa: E402
from handshake_results import load as load_regressions, validate_server as validate_regressions_server

PUBLIC = ('results.csv', 'server-connections.jsonl', 'metadata.json', 'server.json')
RUNS = tuple(f'{kind}-{index}' for kind in ('baseline', 'candidate') for index in (1, 2)) + ('regressions',)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def measurements(root, candidate):
    """Recompute the table from raw samples and independent server records."""
    import statistics
    groups = {'baseline': {}, 'candidate': {}}
    ciphers, fingerprints = set(), set()
    libraries = {}
    for kind in groups:
        for index in (1, 2):
            run = root / f'{kind}-{index}'
            rows = load((run / 'results.csv').read_text())
            ciphers.add(validate_server(run / 'server-connections.jsonl'))
            meta = json.loads((run / 'metadata.json').read_text())
            server = json.loads((run / 'server.json').read_text())
            require(meta['benchmark_type'] == 'tls_release', 'profiling must be disabled for release comparison')
            fingerprints.add((meta['mips'], meta['device'], meta['session_sha256'], meta['emulator_sha256'],
                              server['trust_sha256'], server['leaf_sha256'], server['trust_anchor_count'],
                              server['trust_bytes'], rows[0]['frequency']))
            require(meta['mips'] > 0 and server['trust_anchor_count'] == 8, 'invalid release fixture')
            libraries.setdefault(kind, set()).add(meta['library_sha256'])
            if kind == 'candidate':
                require(meta['library_sha256'] == candidate['files']['assets/PalmTLSArm.prc'], 'wrong tested candidate PRC')
                require(meta['arm_image_sha256'] == candidate['arm_image_sha256'], 'wrong tested native image')
            for row in rows:
                groups[kind].setdefault(row['case'], []).append(1000 * int(row['open_ticks']) / int(row['frequency']))
            server_rows = [json.loads(line) for line in (run / 'server-connections.jsonl').read_text().splitlines()]
            require([r['resumed'] for r in server_rows] == [False, False, True] * 5,
                    'server resumption order differs from the benchmark')
    require(len(ciphers) == 1 and next(iter(ciphers)) in
            ('TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256'), 'versions negotiated different/unsupported ciphers')
    require(len(fingerprints) == 1, 'versions used different clocks, devices, emulator, session or trust fixtures')
    require(all(len(values) == 1 for values in libraries.values()), 'library changed between repeated runs')
    table = {}
    for case in ('cold_full', 'warm_full', 'resumed'):
        before, after = (statistics.median(groups[kind][case]) for kind in ('baseline', 'candidate'))
        require(before > 0 and after > 0, 'handshake duration must be measurable')
        table[case] = dict(baseline_ms=before, candidate_ms=after,
                           time_reduction_percent=100 * (1 - after / before), speedup=before / after)
    return table, next(iter(ciphers)), next(iter(libraries['baseline']))


def performance(selected, baseline, table, cipher, mips):
    lines = ['## Measured handshake performance', '',
             f'| TLS 1.3 handshake | {baseline} | {selected} | Time reduction |',
             '| --- | ---: | ---: | ---: |']
    for case, label in (('cold_full', 'Cold full, including engine/trust setup'),
                        ('warm_full', 'Warm full'), ('resumed', 'Resumed')):
        row = table[case]
        lines.append(f'| {label} | {row["baseline_ms"]:g} ms | {row["candidate_ms"]:g} ms | '
                     f'{row["time_reduction_percent"]:.1f}% |')
    lines += ['', f'Medians of ten samples per case (two private-session runs per version), cp-uarm at {mips} MIPS. '
              f'Both versions negotiated `{cipher}` and verified the same certificate against eight trust anchors. '
              'Profiling was disabled. An external Palm clock includes complete SessionOpen/Handshake setup; '
              'DNS/TCP setup and subsequent I/O are excluded. These are emulator measurements, '
              'not physical-device or Internet latency promises.', '']
    return '\n'.join(lines)


def verify_evidence(root, candidate_root):
    candidate = verify_candidate(candidate_root)
    value = json.loads((root / 'evidence.json').read_text())
    require(value['format'] == 1 and value['candidate_sha256'] == digest(candidate_root / 'candidate.json'),
            'evidence belongs to a different candidate')
    require(set(value['files']) == {f'{run}/{name}' for run in RUNS for name in PUBLIC},
            'unexpected public evidence files')
    verify_files(root, value['files'], 'evidence.json')
    load_regressions((root / 'regressions/results.csv').read_text())
    regression_cipher = validate_regressions_server(root / 'regressions/server-connections.jsonl')
    regression_meta = json.loads((root / 'regressions/metadata.json').read_text())
    require(regression_meta['library_sha256'] == candidate['files']['assets/PalmTLSArm.prc'] and
            regression_meta['arm_image_sha256'] == candidate['arm_image_sha256'], 'regressions tested another library')
    table, cipher, baseline_sha = measurements(root, candidate)
    require(value['table'] == table and value['cipher'] == cipher and value['baseline_sha256'] == baseline_sha,
            'benchmark summary differs from raw evidence')
    require(regression_cipher == cipher, 'regressions negotiated a different cipher')
    require(value['version'] == candidate['version'], 'evidence version differs')
    from release_common import version
    version(value['baseline_version'])
    require(tuple(map(int, value['baseline_version'].split('.'))) < tuple(map(int, candidate['version'].split('.'))),
            'baseline must be an earlier release')
    meta = json.loads((root / 'candidate-1/metadata.json').read_text())
    require(value['performance_markdown'] == performance(candidate['version'], value['baseline_version'],
                                                        table, cipher, meta['mips']), 'performance notes differ')
    return value


def collect(work, output, candidate_root, baseline_version):
    """Only explicitly allowed, validated public files leave the private workspace."""
    candidate = verify_candidate(candidate_root)
    require(not output.exists(), 'evidence output already exists')
    output.mkdir(parents=True)
    for name in RUNS:
        (output / name).mkdir()
        for item in PUBLIC:
            shutil.copyfile(work / name / item, output / name / item)
    table, cipher, baseline_sha = measurements(output, candidate)
    meta = json.loads((output / 'candidate-1/metadata.json').read_text())
    value = dict(format=1, version=candidate['version'], candidate_sha256=digest(candidate_root / 'candidate.json'),
                 baseline_version=baseline_version, baseline_sha256=baseline_sha, cipher=cipher, table=table,
                 performance_markdown=performance(candidate['version'], baseline_version, table, cipher, meta['mips']),
                 files=files(output))
    write_json(output / 'evidence.json', value)
    verify_evidence(output, candidate_root)
    return value


def run_regressions(work, fixture, args, candidate):
    runner = module('regression_runner', BENCH / 'run-emulator.py')
    binder = module('regression_binder', BENCH / 'bind-release-image.py')
    with (work / 'regression-build.log').open('w') as log:
        subprocess.run(['make', '-C', str(BENCH), 'handshake'], check=True, stdout=log, stderr=subprocess.STDOUT)
    prc = work / 'candidate-regressions.prc'
    prc.write_bytes(binder.bind(ROOT / 'library/build/bench/PalmTLSHandshakeBench.prc', work / 'candidate.prc'))
    run = work / 'regressions'
    runner.run(SimpleNamespace(output=run, session=args.session, emulator=args.emulator,
        library=work / 'candidate.prc', prc=prc, mips=args.mips, device='auto', timeout=1200,
        network=True, handshake=True, release=False, handshake_fixture=fixture))
    meta = json.loads((run / 'metadata.json').read_text())
    meta['local_arm_build_config'] = None
    meta['wolfssl'] = None
    meta['library_provenance'] = candidate
    write_json(run / 'metadata.json', meta)
    load_regressions((run / 'results.csv').read_text())
    validate_regressions_server(run / 'server-connections.jsonl')


def benchmark(args):
    candidate = verify_candidate(args.candidate)
    baseline_version = prc_version(args.baseline_prc.read_bytes())
    require(tuple(map(int, baseline_version.split('.'))) < tuple(map(int, candidate['version'].split('.'))),
            'baseline must be an earlier release')
    require(not args.output.exists() and 0 < args.port < 65533 and args.mips > 0, 'invalid output, port or MIPS')
    private = ROOT / 'library/build/release-checks'
    private.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='candidate-', dir=private))
    fixture = work / 'fixture'
    # Freeze supplied binaries before doing any builds or starting the server.
    for kind, path in (('baseline', args.baseline_prc), ('candidate', args.candidate / 'assets/PalmTLSArm.prc')):
        shutil.copyfile(path, work / f'{kind}.prc')
    runner = module('release_runner', BENCH / 'run-emulator.py')
    binder = module('release_binder', BENCH / 'bind-release-image.py')
    print(f'Private work directory (contains ROM/session copies and fixture keys): {work}', flush=True)
    with (work / 'server.log').open('w') as log:
        server = subprocess.Popen([args.server_python, str(BENCH / 'handshake-server.py'),
                                   '--directory', str(fixture), '--port', str(args.port), '--anchors', '8'],
                                  stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 60
            while not (fixture / 'ready').exists():
                require(server.poll() is None, f'fixture server failed; see {work / "server.log"}')
                require(time.monotonic() < deadline, 'fixture server did not become ready')
                time.sleep(0.1)
            (ROOT / 'library/build/bench').mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture / 'handshake_vectors.inc', ROOT / 'library/build/bench/handshake_vectors.inc')
            with (work / 'build.log').open('w') as build_log:
                subprocess.run(['make', '-C', str(BENCH), 'release-bench'], check=True,
                               stdout=build_log, stderr=subprocess.STDOUT)
            for kind in ('baseline', 'candidate'):
                prc = work / f'{kind}-benchmark.prc'
                prc.write_bytes(binder.bind(ROOT / 'library/build/bench/PalmTLSReleaseBench.prc', work / f'{kind}.prc'))
                for index in (1, 2):
                    run = work / f'{kind}-{index}'
                    runner.run(SimpleNamespace(output=run, session=args.session, emulator=args.emulator,
                        library=work / f'{kind}.prc', prc=prc, mips=args.mips, device='auto', timeout=900,
                        network=True, handshake=True, release=True, handshake_fixture=fixture))
                    # The runner's local dependency/compiler fields do not describe an imported PRC.
                    meta = json.loads((run / 'metadata.json').read_text())
                    meta['benchmark_source_revision'] = meta.pop('git_revision')
                    meta['benchmark_source_dirty'] = meta.pop('git_dirty')
                    meta['local_arm_build_config'] = None
                    meta['wolfssl'] = None
                    meta['library_version'] = baseline_version if kind == 'baseline' else candidate['version']
                    meta['library_provenance'] = 'supplied previous-release PRC' if kind == 'baseline' else candidate
                    write_json(run / 'metadata.json', meta)
            run_regressions(work, fixture, args, candidate)
            result = collect(work, args.output, args.candidate, baseline_version)
            print(result['performance_markdown'])
            print(f'Verified public evidence: {args.output}')
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
