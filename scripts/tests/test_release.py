"""Exercise release integrity and interrupted promotion without contacting GitHub."""
import copy
import json
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release
import release_benchmark as benchmark
from release_common import (PRCS, digest, files, native, preflight, sha, verify_candidate,
                            verify_zip, write_json, deterministic_zip)

COMMIT = 'c' * 40
WOLF = 'd' * 40


def prc(selected='0.1.5', arm=False, tester=False):
    entries = [(b'armc' if arm else b'code', 1, b'ARMv4T00'),
               (b'tver', 1000 if tester else 1, selected.encode() + b'\0')]
    result = bytearray(100)
    result[:8] = b'Test PRC'
    result[60:68] = b'applTlsT' if tester else b'librPTLS'
    struct.pack_into('>H', result, 76, len(entries))
    for i, (kind, number, value) in enumerate(entries):
        struct.pack_into('>4sHI', result, 78 + 10*i, kind, number, len(result))
        result.extend(value)
    return bytes(result)


def candidate_fixture(root):
    root.mkdir()
    (root / 'assets').mkdir()
    (root / 'validation').mkdir()
    contents = {'SOURCE.txt': (f'PalmTLS commit: {COMMIT}\nToolchain image: image@sha256:{"1"*64}\n'
                               f'WOLFSSL_COMMIT="{WOLF}"\n').encode()}
    for name in PRCS:
        value = prc(arm=name.startswith('PalmTLSArm'), tester=name == 'TlsTester.prc')
        (root / 'assets' / name).write_bytes(value)
        contents[('tls-tester/' if name == 'TlsTester.prc' else 'library/') + name] = value
    contents['SHA256SUMS'] = ''.join(f'{sha(value)}  ./{name}\n' for name, value in sorted(contents.items())).encode()
    deterministic_zip(root / 'assets/PalmTLS-0.1.5.zip', {'PalmTLS-0.1.5/' + k: v for k,v in contents.items()})
    for cpu in ('ti925t', 'pxa270'):
        (root / f'validation/{cpu}.log').write_text(f'Crypto oracles passed ({cpu}): test vectors\n')
    (root / 'notes.md').write_text('Release notes for the fully validated candidate.\n')
    image = native((root / 'assets/PalmTLSArm.prc').read_bytes())
    manifest = dict(format=1, version='0.1.5', commit=COMMIT, repository='owner/repo', run_id=123,
                    run_attempt=1, toolchain_image='image@sha256:'+'1'*64, wolfssl_commit=WOLF,
                    arm_image_sha256=sha(image), arm_image_bytes=len(image), files=files(root))
    write_json(root / 'candidate.json', manifest)
    verify_candidate(root)
    return manifest


def evidence_fixture(work, output, candidate):
    manifest = verify_candidate(candidate)
    for kind in ('baseline', 'candidate'):
        for index in (1,2):
            run = work / f'{kind}-{index}'
            run.mkdir(parents=True)
            text = 'case,sample,frequency,open_ticks,load_ticks,reported_handshake_ticks,session_reused\n'
            server = []
            for sample in range(5):
                for name in ('cold_full','warm_full','resumed'):
                    text += f'{name},{sample},100,{100 if kind=="baseline" else 50},0,40,{int(name=="resumed")}\n'
                    server.append(dict(version='TLSv1.3', resumed=name=='resumed',
                                       cipher='TLS_CHACHA20_POLY1305_SHA256', request='release-probe\n'))
            (run / 'results.csv').write_text(text+'# complete release-v1\n')
            (run / 'server-connections.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in server))
            meta = dict(benchmark_type='tls_release', mips=100, device='auto', session_sha256='1'*64,
                        emulator_sha256='2'*64, arm_image_sha256=manifest['arm_image_sha256'],
                        library_sha256=manifest['files']['assets/PalmTLSArm.prc'] if kind=='candidate' else '3'*64)
            write_json(run / 'metadata.json', meta)
            write_json(run / 'server.json', dict(trust_sha256='4'*64, leaf_sha256='5'*64,
                                                  trust_anchor_count=8, trust_bytes=4560))
            (run / 'private.key').write_text('must never be exported')
    from test_handshake_results import fixture as regression_fixture
    run = work / 'regressions'
    run.mkdir()
    (run / 'results.csv').write_text(regression_fixture())
    server = [dict(version='TLSv1.3', resumed=i%3==2,
                   cipher='TLS_CHACHA20_POLY1305_SHA256',request='probe\n') for i in range(30)]
    server += [dict(version='TLSv1.2',resumed=resumed,request='check\n') for resumed in (False,True)]
    (run / 'server-connections.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in server))
    for name in ('metadata.json','server.json'):
        shutil.copyfile(work / 'candidate-1' / name,run / name)
    return benchmark.collect(work, output, candidate, '0.1.4')


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = self.root / 'candidate'
        self.manifest = candidate_fixture(self.candidate)


class CandidateTests(Fixture):
    def test_verified(self):
        self.assertEqual(verify_candidate(self.candidate)['commit'], COMMIT)

    def test_changed_extra_missing_and_symlink_inputs(self):
        original = (self.candidate / 'assets/PalmTLSArm.prc').read_bytes()
        for mutation in ('changed','extra','missing','symlink'):
            with self.subTest(mutation=mutation):
                target = self.candidate / 'assets/PalmTLSArm.prc'
                if mutation=='changed': target.write_bytes(original+b'changed')
                if mutation=='extra': (self.candidate / 'secret.key').write_bytes(b'no')
                if mutation=='missing': target.unlink()
                if mutation=='symlink':
                    target.unlink(); target.symlink_to(self.candidate / 'assets/PalmTLSArm-Modern.prc')
                with self.assertRaises(ValueError): verify_candidate(self.candidate)
                if target.is_symlink(): target.unlink()
                target.write_bytes(original)
                (self.candidate / 'secret.key').unlink(missing_ok=True)

    def test_mismatched_native_images_even_with_updated_outer_hash(self):
        path = self.candidate / 'assets/PalmTLSArm-Modern.prc'
        path.write_bytes(prc(arm=True).replace(b'ARMv4T00',b'ARMv5000'))
        manifest = self.manifest.copy()
        manifest['files'] = files(self.candidate)
        manifest['files'].pop('candidate.json')
        write_json(self.candidate / 'candidate.json',manifest)
        with self.assertRaises(ValueError): verify_candidate(self.candidate)

    def test_failed_cpu_log_even_with_updated_manifest(self):
        path=self.candidate / 'validation/ti925t.log'
        path.write_text('Traceback: unsupported instruction\n')
        value=self.manifest.copy();value['files']=dict(value['files'])
        value['files']['validation/ti925t.log']=digest(path)
        write_json(self.candidate / 'candidate.json',value)
        with self.assertRaises(ValueError):verify_candidate(self.candidate)

    def test_zip_traversal_duplicate_and_corruption(self):
        archive = self.root / 'bad.zip'
        for name in ('PalmTLS-0.1.5/../secret.key','outside.txt'):
            with zipfile.ZipFile(archive,'w') as z: z.writestr(name,b'x')
            with self.assertRaises(ValueError): verify_zip(archive.read_bytes(),'0.1.5')
        data=(self.candidate / 'assets/PalmTLS-0.1.5.zip').read_bytes()
        with self.assertRaises(ValueError): verify_zip(data,'0.1.5',{'wrong':'0'*64})

    def test_preflight_rejects_dirty_notes_versions_and_existing_tag(self):
        (self.root / 'library').mkdir(); (self.root / 'apps/tls-tester').mkdir(parents=True)
        (self.root / 'docs/releases').mkdir(parents=True)
        for path,key in (('library/app.mk','LIB_VERSION'),('apps/tls-tester/app.mk','APP_VERSION')):
            (self.root / path).write_text(f'{key} := 0.1.5\n')
        notes=self.root / 'docs/releases/0.1.5.md'
        notes.write_text('A complete release description with user-visible changes and instructions.\n')
        with patch('release_common.command',side_effect=['',COMMIT,'']):
            self.assertEqual(preflight(self.root),('0.1.5',COMMIT))
        with patch('release_common.command',return_value=' M changed'):
            with self.assertRaises(ValueError): preflight(self.root)
        with patch('release_common.command',side_effect=['',COMMIT,'v0.1.5']):
            with self.assertRaises(ValueError): preflight(self.root)
        notes.write_text('TODO: finish this release description before building anything.\n')
        with patch('release_common.command',side_effect=['',COMMIT,'']):
            with self.assertRaises(ValueError): preflight(self.root)
        (self.root / 'apps/tls-tester/app.mk').write_text('APP_VERSION := 0.1.4\n')
        with patch('release_common.command',side_effect=['',COMMIT]):
            with self.assertRaises(ValueError): preflight(self.root)


class EvidenceTests(Fixture):
    def setUp(self):
        super().setUp()
        self.evidence = self.root / 'evidence'
        evidence_fixture(self.root / 'private', self.evidence, self.candidate)

    def test_summary_and_export_allowlist(self):
        result=benchmark.verify_evidence(self.evidence,self.candidate)
        self.assertEqual(result['table']['cold_full']['time_reduction_percent'],50)
        self.assertFalse(list(self.evidence.rglob('*.key')))
        self.assertIn('not physical-device',result['performance_markdown'])

    def test_wrong_candidate_and_forged_summary(self):
        path=self.evidence / 'evidence.json'
        value=json.loads(path.read_text())
        value['candidate_sha256']='0'*64; write_json(path,value)
        with self.assertRaises(ValueError): benchmark.verify_evidence(self.evidence,self.candidate)
        value['candidate_sha256']=digest(self.candidate / 'candidate.json')
        value['table']['resumed']['candidate_ms']=1;write_json(path,value)
        with self.assertRaises(ValueError): benchmark.verify_evidence(self.evidence,self.candidate)

    def test_different_cipher_and_environment_rejected_after_rehash(self):
        for field, target in (('cipher','server-connections.jsonl'),('mips','metadata.json')):
            with self.subTest(field=field):
                path=self.evidence / 'candidate-2' / target
                original=path.read_text()
                path.write_text(original.replace('CHACHA20_POLY1305','AES_128_GCM') if field=='cipher'
                                else original.replace('"mips": 100','"mips": 200'))
                value=json.loads((self.evidence / 'evidence.json').read_text())
                value['files'][f'candidate-2/{target}']=digest(path)
                write_json(self.evidence / 'evidence.json',value)
                with self.assertRaises(ValueError): benchmark.verify_evidence(self.evidence,self.candidate)
                path.write_text(original)


class FakeGitHub:
    def __init__(self,candidate):
        self.candidate=candidate
        self.release=None
        self.target=None
        self.uploads={}
        self.mutations=[]
        self.corrupt_download=False
        self.interrupt_upload=False

    def fetch(self,repo,run_id,output):
        shutil.copytree(self.candidate,output)
        return verify_candidate(output)

    def api(self,repo,endpoint,payload=None,missing=False):
        if endpoint=='releases/latest':return dict(tag_name='v0.1.4')
        if endpoint=='releases/tags/v0.1.4':
            return dict(draft=False,assets=[dict(name='PalmTLSArm.prc',digest='sha256:'+'3'*64)])
        if endpoint.startswith('git/ref/'):
            return {'object':dict(type='commit',sha=self.target)} if self.target else None
        if endpoint=='git/tags':
            self.mutations.append('tag-object');return dict(sha='a'*40)
        if endpoint=='git/refs':
            self.mutations.append('tag-ref');self.target=COMMIT;return {}
        if endpoint=='releases/tags/v0.1.5':
            return self.release_data() if self.release and not self.release['draft'] else None
        raise AssertionError(endpoint)

    def release_data(self):
        result=copy.deepcopy(self.release)
        result['assets']=[dict(name=name,state='uploaded',digest='sha256:'+sha(data))
                          for name,data in self.uploads.items()]
        return result

    def gh(self,*args,**kwargs):
        if args[0]=='api':
            assert args == ('api','repos/owner/repo/releases?per_page=100','--paginate','--slurp')
            return json.dumps([[dict(tag_name='v0.1.4')], [self.release_data()] if self.release else []])
        operation=args[1]
        if operation=='create':
            self.mutations.append('create-release')
            self.release=dict(tag_name=args[2],draft=True,body=Path(args[args.index('--notes-file')+1]).read_text(),
                              html_url='https://github.com/owner/repo/releases/tag/v0.1.5')
        elif operation=='edit':
            self.mutations.append('edit-release')
            if '--notes-file' in args:self.release['body']=Path(args[args.index('--notes-file')+1]).read_text()
            if '--draft=false' in args:self.release['draft']=False
        elif operation=='upload':
            for path in args[3:args.index('--repo')]:
                self.mutations.append('upload:'+path.name)
                if path.name in self.uploads:raise AssertionError('existing asset overwritten')
                self.uploads[path.name]=path.read_bytes()
                if self.interrupt_upload:
                    self.interrupt_upload=False
                    raise RuntimeError('simulated interrupted upload')
        elif operation=='download':
            output=Path(args[args.index('--dir')+1]);output.mkdir()
            for name,data in self.uploads.items():
                (output / name).write_bytes(data+(b'corrupted' if self.corrupt_download else b''))
        else:raise AssertionError(args)
        return ''


class PromotionTests(Fixture):
    def setUp(self):
        super().setUp()
        quiet=patch('builtins.print');quiet.start();self.addCleanup(quiet.stop)
        self.evidence = self.root / 'evidence'
        evidence_fixture(self.root / 'private', self.evidence, self.candidate)
        self.remote=FakeGitHub(self.candidate)
        for method in ('fetch','api','gh'):
            manager=patch.object(release,method,getattr(self.remote,method))
            manager.start();self.addCleanup(manager.stop)
        self.args=SimpleNamespace(candidate=self.candidate,evidence=self.evidence,draft_only=False)

    def test_promotes_once_and_rerun_is_read_only(self):
        release.publish(self.args)
        self.assertFalse(self.remote.release['draft'])
        self.assertIn('SHA256SUMS',self.remote.uploads)
        before=list(self.remote.mutations)
        release.publish(self.args)
        self.assertEqual(self.remote.mutations,before)

    def test_different_tag_is_never_moved(self):
        self.remote.target='b'*40
        with self.assertRaises(ValueError):release.publish(self.args)
        self.assertEqual(self.remote.mutations,[])

    def test_unpublished_baseline_is_rejected_before_any_mutation(self):
        original=self.remote.api
        def api(repo,endpoint,**kwargs):
            value=original(repo,endpoint,**kwargs)
            if endpoint=='releases/tags/v0.1.4':value['draft']=True
            return value
        with patch.object(release,'api',side_effect=api):
            with self.assertRaises(ValueError):release.publish(self.args)
        self.assertEqual(self.remote.mutations,[])

    def test_baseline_digest_must_match_the_published_asset(self):
        original=self.remote.api
        def api(repo,endpoint,**kwargs):
            value=original(repo,endpoint,**kwargs)
            if endpoint=='releases/tags/v0.1.4':value['assets'][0]['digest']='sha256:'+'0'*64
            return value
        with patch.object(release,'api',side_effect=api):
            with self.assertRaises(ValueError):release.publish(self.args)
        self.assertEqual(self.remote.mutations,[])

    def test_older_candidate_cannot_replace_latest_release(self):
        original=self.remote.api
        def api(repo,endpoint,**kwargs):
            return dict(tag_name='v0.1.6') if endpoint=='releases/latest' else original(repo,endpoint,**kwargs)
        with patch.object(release,'api',side_effect=api):
            with self.assertRaises(ValueError):release.publish(self.args)
        self.assertEqual(self.remote.mutations,[])

    def test_modified_candidate_cannot_replace_the_trusted_ci_bundle(self):
        changed=json.loads((self.candidate / 'candidate.json').read_text())
        def fetch(repo,run_id,output):
            shutil.copytree(self.candidate,output)
            write_json(output / 'candidate.json',dict(changed,run_id=456))
        with patch.object(release,'fetch',side_effect=fetch):
            with self.assertRaises(ValueError):release.publish(self.args)
        self.assertEqual(self.remote.mutations,[])

    def test_interrupted_upload_resumes_without_replacing_assets(self):
        self.remote.interrupt_upload=True
        with self.assertRaises(RuntimeError):release.publish(self.args)
        self.assertTrue(self.remote.release['draft'])
        release.publish(self.args)
        self.assertFalse(self.remote.release['draft'])
        self.assertEqual(self.remote.mutations.count('tag-ref'),1)

    def test_bad_download_prevents_publication(self):
        self.remote.corrupt_download=True
        with self.assertRaises(ValueError):release.publish(self.args)
        self.assertTrue(self.remote.release['draft'])

    def test_conflicting_existing_asset_is_not_overwritten(self):
        self.args.draft_only=True;release.publish(self.args)
        self.remote.uploads['PalmTLSArm.prc']=b'wrong'
        before=list(self.remote.mutations)
        with self.assertRaises(ValueError):release.publish(self.args)
        self.assertEqual(self.remote.mutations,before)


class GitHubRunTests(unittest.TestCase):
    def test_failed_or_untrusted_run_is_rejected(self):
        valid=dict(status='completed',conclusion='success',event='workflow_dispatch',
                   path='.github/workflows/build-artifacts.yml',head_repository=dict(full_name='owner/repo'))
        for key,value in (('conclusion','failure'),('event','pull_request'),('path','another.yml'),
                          ('head_repository',dict(full_name='someone/fork'))):
            with self.subTest(key=key),patch.object(release,'api',return_value=dict(valid,**{key:value})):
                with self.assertRaises(ValueError):release.checked_run('owner/repo',123)

    def test_authentication_failure_is_not_treated_as_a_missing_release(self):
        failed=SimpleNamespace(returncode=1,stderr='HTTP 403: access denied',stdout='')
        with patch.object(release.subprocess,'run',return_value=failed):
            with self.assertRaises(RuntimeError):release.gh('api','test',missing=True)
        failed.stderr='gh: Not Found (HTTP 404)'
        with patch.object(release.subprocess,'run',return_value=failed):
            self.assertIsNone(release.gh('api','test',missing=True))


class FetchTests(Fixture):
    def test_successful_run_download_and_provenance_mismatch(self):
        run=dict(head_sha=COMMIT,run_attempt=1)
        def download(*args,**kwargs):
            self.assertEqual(args[args.index('--name')+1],f'palm-tls-candidate-{run["head_sha"]}-123-1')
            shutil.copytree(self.candidate,Path(args[args.index('--dir')+1]))
        with patch.object(release,'checked_run',return_value=run),patch.object(release,'gh',side_effect=download):
            self.assertEqual(release.fetch('owner/repo',123,self.root / 'download')['commit'],COMMIT)
            run['head_sha']='a'*40
            with self.assertRaises(ValueError):release.fetch('owner/repo',123,self.root / 'wrong-download')


if __name__=='__main__':unittest.main()
