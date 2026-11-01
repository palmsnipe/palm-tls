#!/usr/bin/env python3
"""Prepare, validate and promote PalmTLS release candidates without rebuilding."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from release_common import (ROOT, WORKFLOW, PRCS, clean_commit, command, deterministic_zip,
                            digest, files, native, preflight, require, sha, verify_candidate,
                            verify_zip, version, versions, write_json)


def prepare(selected):
    version(selected)
    clean_commit()
    require(tuple(map(int, selected.split('.'))) > tuple(map(int, versions().split('.'))),
            'new version must be greater than the current version')
    notes = ROOT / f'docs/releases/{selected}.md'
    require(not notes.exists(), f'{notes} already exists')
    require(not command(['git', 'tag', '--list', f'v{selected}'], cwd=ROOT), 'version tag already exists')
    for name, variable in (('library/app.mk', 'LIB_VERSION'), ('apps/tls-tester/app.mk', 'APP_VERSION')):
        path = ROOT / name
        path.write_text(re.sub(rf'^{variable} := .+$', f'{variable} := {selected}', path.read_text(), flags=re.M))
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text(f'PalmTLS {selected}\n\n## Changes\n\n- TODO: describe the user-visible changes.\n\n'
                     'Install exactly one library PRC for your device and protocol profile. '
                     'TLS Tester is optional. Performance evidence and corresponding-source '
                     'links are added by the release tooling.\n')
    print(f'Updated both versions; finish {notes.relative_to(ROOT)} and commit before building.')


def bundle(args):
    selected, commit = preflight()
    require(not args.output.exists(), 'candidate output already exists')
    expected = files(args.dist)
    archive = args.assets / f'PalmTLS-{selected}.zip'
    verify_zip(archive.read_bytes(), selected, expected)
    require(set(files(args.assets)) == set(PRCS + (archive.name,)), 'unexpected release assets')
    require(args.run_id > 0 and args.run_attempt > 0, 'CI run ID and attempt are required')
    require(args.toolchain_image and '@sha256:' in args.toolchain_image, 'pin the candidate toolchain image')
    wolf = re.search(r'^WOLFSSL_COMMIT="([a-f0-9]{40})"$', (ROOT / 'config/sources.lock').read_text(), re.M)
    require(wolf is not None, 'missing pinned wolfSSL commit')
    require(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo)), 'invalid repository')
    args.output.mkdir(parents=True)
    shutil.copytree(args.assets, args.output / 'assets')
    (args.output / 'validation').mkdir()
    for cpu, log in (('ti925t', args.ti925t_log), ('pxa270', args.pxa270_log)):
        shutil.copyfile(log, args.output / f'validation/{cpu}.log')
    url = f'https://github.com/{args.repo}'
    notes = (ROOT / f'docs/releases/{selected}.md').read_text().rstrip()
    notes += (f'\n\n## Corresponding source\n\n'
              f'- [PalmTLS {selected}]({url}/tree/v{selected})\n'
              f'- [Exact wolfSSL source](https://github.com/wolfSSL/wolfssl/tree/{wolf[1]})\n'
              f'- [Palm patches]({url}/tree/v{selected}/patches/wolfssl)\n'
              f'- [Build scripts]({url}/tree/v{selected}/scripts)\n')
    (args.output / 'notes.md').write_text(notes)
    image = native((args.output / 'assets/PalmTLSArm.prc').read_bytes())
    manifest = dict(format=1, version=selected, commit=commit, repository=args.repo,
                    run_id=args.run_id, run_attempt=args.run_attempt,
                    toolchain_image=args.toolchain_image, wolfssl_commit=wolf[1],
                    arm_image_sha256=sha(image), arm_image_bytes=len(image), files=files(args.output))
    write_json(args.output / 'candidate.json', manifest)
    verify_candidate(args.output)
    print(f'Verified candidate {selected} at {commit}: {args.output}')


def gh(*args, payload=None, missing=False):
    result = subprocess.run(['gh', *map(str, args)], text=True, capture_output=True,
                            input=json.dumps(payload) if payload is not None else None)
    if result.returncode:
        if missing and 'HTTP 404' in result.stderr:
            return None
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'GitHub command failed')
    return result.stdout


def api(repo, endpoint, payload=None, missing=False):
    args = ['api', f'repos/{repo}/{endpoint}']
    if payload is not None:
        args += ['--method', 'POST', '--input', '-']
    result = gh(*args, payload=payload, missing=missing)
    return json.loads(result) if result is not None else None


def checked_run(repo, run_id):
    run = api(repo, f'actions/runs/{run_id}')
    require(run['status'] == 'completed' and run['conclusion'] == 'success', 'candidate CI run did not succeed')
    require(run['event'] == 'workflow_dispatch' and run['path'].split('@')[0] == WORKFLOW,
            'candidate must come from the trusted manual build workflow')
    require(run['head_repository']['full_name'] == repo, 'candidate run belongs to another repository')
    return run


def fetch(repo, run_id, output):
    require(not output.exists(), 'download output already exists')
    run = checked_run(repo, run_id)
    artifact = f'palm-tls-candidate-{run["head_sha"]}-{run_id}-{run["run_attempt"]}'
    gh('run', 'download', run_id, '--repo', repo, '--name', artifact, '--dir', output)
    manifest = verify_candidate(output)
    require((manifest['repository'], manifest['commit'], manifest['run_id'], manifest['run_attempt']) ==
            (repo, run['head_sha'], int(run_id), run['run_attempt']), 'candidate provenance differs from GitHub run')
    return manifest


def tag_commit(repo, tag):
    ref = api(repo, f'git/ref/tags/{tag}', missing=True)
    if ref is None:
        return None
    target = ref['object']
    for _ in range(8):
        if target['type'] == 'commit':
            return target['sha']
        require(target['type'] == 'tag', 'release tag does not point to a commit')
        target = api(repo, f'git/tags/{target["sha"]}')['object']
    raise ValueError('release tag nesting exceeds limit')


def check_assets(release, expected, complete=False):
    actual = {}
    for asset in release['assets']:
        name = asset['name']
        require(name not in actual and name in expected, f'unexpected or duplicate release asset: {name}')
        require(asset['state'] == 'uploaded', f'incomplete upload: {name}')
        require(asset.get('digest') in (None, 'sha256:' + expected[name]), f'existing asset differs: {name}')
        actual[name] = asset
    if complete:
        require(set(actual) == set(expected), 'release is missing assets')
    return actual


def publish(args):
    from release_benchmark import verify_evidence
    candidate = verify_candidate(args.candidate)
    evidence = verify_evidence(args.evidence, args.candidate)
    repo = candidate['repository']
    tag = 'v' + candidate['version']
    # Re-download the trusted immutable CI artifact before any remote mutation.
    with tempfile.TemporaryDirectory(prefix='palm-tls-promote-') as temporary:
        staging = Path(temporary)
        original = staging / 'original'
        fetch(repo, candidate['run_id'], original)
        require(digest(original / 'candidate.json') == digest(args.candidate / 'candidate.json'),
                'local candidate differs from the trusted CI artifact')
        snapshot = staging / 'evidence'
        shutil.copytree(args.evidence, snapshot, symlinks=True)
        evidence = verify_evidence(snapshot, original)
        baseline = api(repo, f'releases/tags/v{evidence["baseline_version"]}')
        require(not baseline['draft'], 'benchmark baseline is not a published release')
        baseline_assets = [asset for asset in baseline['assets'] if asset['name'] == 'PalmTLSArm.prc']
        require(len(baseline_assets) == 1, 'published baseline has no unique ARM library asset')
        baseline_digest = baseline_assets[0].get('digest')
        if baseline_digest is not None:
            require(baseline_digest == 'sha256:' + evidence['baseline_sha256'],
                    'benchmark baseline differs from the published release asset')
        else:
            baseline_dir = staging / 'baseline'
            gh('release', 'download', 'v' + evidence['baseline_version'], '--repo', repo,
               '--pattern', 'PalmTLSArm.prc', '--dir', baseline_dir)
            require(digest(baseline_dir / 'PalmTLSArm.prc') == evidence['baseline_sha256'],
                    'benchmark baseline differs from the published release asset')
        target = tag_commit(repo, tag)
        require(target in (None, candidate['commit']), f'{tag} points to another commit; it will never be moved')
        output = staging / 'assets'
        shutil.copytree(original / 'assets', output)
        members = {f'evidence/{name}': (snapshot / name).read_bytes() for name in files(snapshot)}
        for cpu in ('ti925t', 'pxa270'):
            members[f'validation/{cpu}.log'] = (original / f'validation/{cpu}.log').read_bytes()
        deterministic_zip(output / f'PalmTLS-{candidate["version"]}-benchmarks.zip', members)
        release_manifest = dict(candidate=candidate, evidence_sha256=digest(snapshot / 'evidence.json'),
                                release_assets=files(output))
        write_json(output / 'release-manifest.json', release_manifest)
        (output / 'SHA256SUMS').write_text(''.join(f'{value}  {name}\n' for name, value in files(output).items()))
        expected = files(output)
        body = (original / 'notes.md').read_text().rstrip() + '\n\n' + evidence['performance_markdown']
        body += (f'\nValidated candidate: [{candidate["commit"][:12]}]'
                 f'(https://github.com/{repo}/actions/runs/{candidate["run_id"]}). '
                 'The benchmark ZIP contains the raw measurements and CPU-model validation logs. '
                 'SHA256SUMS covers every download asset except itself.\n')
        notes = staging / 'notes.md'
        notes.write_text(body)
        release = api(repo, f'releases/tags/{tag}', missing=True)
        actual = check_assets(release, expected) if release else {}
        if not args.draft_only and (release is None or release['draft']):
            latest = api(repo, 'releases/latest', missing=True)
            if latest is not None:
                latest_version = version(latest['tag_name'].removeprefix('v'))
                require(tuple(map(int, candidate['version'].split('.'))) > tuple(map(int, latest_version.split('.'))),
                        'candidate is not newer than the latest published release')
        if release and not release['draft']:
            require(target == candidate['commit'], 'published release source does not match')
            check_assets(release, expected, complete=True)
            require(release['body'].strip() == body.strip(), 'published release notes differ; refusing to edit')
        else:
            if target is None:
                obj = api(repo, 'git/tags', dict(tag=tag, message=f'PalmTLS {candidate["version"]}',
                                               object=candidate['commit'], type='commit'))
                api(repo, 'git/refs', dict(ref=f'refs/tags/{tag}', sha=obj['sha']))
            if release is None:
                gh('release', 'create', tag, '--repo', repo, '--verify-tag', '--draft',
                   '--title', f'PalmTLS {candidate["version"]}', '--notes-file', notes)
            else:
                gh('release', 'edit', tag, '--repo', repo, '--notes-file', notes)
            missing = [output / name for name in expected if name not in actual]
            if missing:
                gh('release', 'upload', tag, *missing, '--repo', repo)
        uploaded = api(repo, f'releases/tags/{tag}')
        check_assets(uploaded, expected, complete=True)
        downloads = staging / 'downloads'
        gh('release', 'download', tag, '--repo', repo, '--dir', downloads)
        require(files(downloads) == expected, 'downloaded assets differ from the verified release inputs')
        if uploaded['draft'] and not args.draft_only:
            gh('release', 'edit', tag, '--repo', repo, '--draft=false', '--latest')
        final = api(repo, f'releases/tags/{tag}')
        require(args.draft_only or not final['draft'], 'release is still a draft')
        print(final['html_url'])


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest='command', required=True)
    prepare_parser = commands.add_parser('prepare', help='bump both versions and create a notes template')
    prepare_parser.add_argument('version')
    commands.add_parser('preflight', help='require a clean commit, finished notes and an unused local tag')
    build = commands.add_parser('bundle', help='package the already-built CI candidate')
    build.add_argument('--dist', type=Path, default=ROOT / 'dist')
    build.add_argument('--assets', type=Path, default=ROOT / 'release-assets')
    build.add_argument('--output', type=Path, default=ROOT / 'release-candidate')
    build.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY', 'palmsnipe/palm-tls'))
    build.add_argument('--run-id', type=int, default=int(os.environ.get('GITHUB_RUN_ID', '0')))
    build.add_argument('--run-attempt', type=int, default=int(os.environ.get('GITHUB_RUN_ATTEMPT', '1')))
    build.add_argument('--toolchain-image', default=os.environ.get('PALM_TOOLCHAIN_IMAGE', ''))
    build.add_argument('--ti925t-log', type=Path, required=True)
    build.add_argument('--pxa270-log', type=Path, required=True)
    download = commands.add_parser('fetch', help='download and verify one successful candidate run')
    download.add_argument('--repo', default='palmsnipe/palm-tls')
    download.add_argument('--run-id', type=int, required=True)
    download.add_argument('--output', type=Path, default=ROOT / 'release-candidate')
    verify = commands.add_parser('verify', help='verify a candidate offline')
    verify.add_argument('candidate', type=Path)
    benchmark = commands.add_parser('benchmark', help='measure the candidate and previous release in private sessions')
    benchmark.add_argument('--candidate', type=Path, required=True)
    benchmark.add_argument('--baseline-prc', type=Path, required=True)
    benchmark.add_argument('--emulator', type=Path, required=True)
    benchmark.add_argument('--session', type=Path, required=True)
    benchmark.add_argument('--server-python', default=sys.executable)
    benchmark.add_argument('--output', type=Path, default=ROOT / 'release-evidence')
    benchmark.add_argument('--port', type=int, default=19443)
    benchmark.add_argument('--mips', type=int, default=100)
    promote = commands.add_parser('publish', help='verify evidence, create an immutable tag, upload and publish')
    promote.add_argument('--candidate', type=Path, required=True)
    promote.add_argument('--evidence', type=Path, required=True)
    promote.add_argument('--draft-only', action='store_true', help='verify uploads and leave the release as a draft')
    return result


def main():
    args = parser().parse_args()
    try:
        if args.command == 'prepare':
            prepare(args.version)
        elif args.command == 'preflight':
            selected, commit = preflight()
            print(f'Release candidate {selected}: {commit}')
        elif args.command == 'bundle':
            bundle(args)
        elif args.command == 'fetch':
            fetch(args.repo, args.run_id, args.output)
            print(args.output)
        elif args.command == 'verify':
            candidate = verify_candidate(args.candidate)
            print(f'Verified {candidate["version"]}: {candidate["commit"]}')
        elif args.command == 'benchmark':
            from release_benchmark import benchmark
            benchmark(args)
        elif args.command == 'publish':
            publish(args)
    except (ValueError, RuntimeError, KeyError, OSError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        print(f'Release stopped: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
