#!/usr/bin/env python3
"""Build and run checked fresh/resumed TLS 1.3 comparisons against localhost."""
import argparse
import hashlib
import json
import runpy
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace


def main():
    root=Path(__file__).resolve().parents[2]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--emulator',type=Path,required=True)
    p.add_argument('--session',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True,help='new directory, includes development-only fixture keys')
    p.add_argument('--server-python',default=sys.executable,help='Python with TLS 1.3 / OpenSSL support')
    p.add_argument('--port',type=int,default=19443)
    p.add_argument('--reuse-fixture',type=Path,help='copy an existing fixture unchanged; requires the same port')
    p.add_argument('--anchors',type=int,default=8)
    p.add_argument('--mips',type=int,default=100)
    p.add_argument('--runs',type=int,default=2)
    args=p.parse_args()
    if not (0<args.port<65533 and 0<args.anchors<33 and 0<args.runs<6 and args.mips>0):
        p.error('invalid port, anchors, runs or MIPS')
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    fixture=output/'fixture'
    server_options=[]
    if args.reuse_fixture:
        previous=json.loads((args.reuse_fixture/'server.json').read_text())
        if previous['port']!=args.port or previous['trust_anchor_count']!=args.anchors:
            p.error('reused fixture must have the same port and anchor count')
        shutil.copytree(args.reuse_fixture,fixture)
        # Each invocation needs a fresh log and readiness marker.
        (fixture/'connections.jsonl').unlink(missing_ok=True)
        (fixture/'ready').unlink(missing_ok=True)
        server_options=['--reuse-fixtures']
    log=(output/'server.log').open('w')
    process=subprocess.Popen([args.server_python,str(root/'library/bench/handshake-server.py'),
        '--directory',str(fixture),'--port',str(args.port),'--anchors',str(args.anchors)]+server_options,stdout=log,stderr=log)
    try:
        deadline=time.monotonic()+60
        while not (fixture/'ready').exists():
            if process.poll() is not None: raise RuntimeError('TLS fixture failed; see server.log')
            if time.monotonic()>deadline: raise TimeoutError('TLS fixture not ready')
            time.sleep(0.1)
        metadata=json.loads((fixture/'server.json').read_text())
        assert hashlib.sha256((fixture/'trust.pem').read_bytes()).hexdigest()==metadata['trust_sha256']
        subprocess.run(['make','-C',str(root/'library'),'benchmark-palm','test'],check=True,
                       stdout=(output/'build.log').open('w'),stderr=subprocess.STDOUT)
        shutil.copyfile(fixture/'handshake_vectors.inc',root/'library/build/bench/handshake_vectors.inc')
        subprocess.run(['make','-C',str(root/'library/bench'),'handshake'],check=True,
                       stdout=(output/'app-build.log').open('w'),stderr=subprocess.STDOUT)
        runner=runpy.run_path(str(root/'library/bench/run-emulator.py'))['run']
        for index in range(args.runs):
            run=output/('run' if index==0 else f'repeat{index}')
            runner(SimpleNamespace(output=run,session=args.session,emulator=args.emulator,
                library=root/'library/build/palm/PalmTLSArm.prc',prc=root/'library/build/bench/PalmTLSHandshakeBench.prc',
                mips=args.mips,device='auto',timeout=1200,network=True,handshake=True,handshake_fixture=fixture))
            summary=subprocess.check_output([sys.executable,str(root/'library/bench/handshake_results.py'),
                str(run/'results.csv'),'--server-log',str(run/'server-connections.jsonl')],text=True)
            (run/'summary.csv').write_text(summary)
            print(summary,flush=True)
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill();process.wait()
        log.close()

if __name__=='__main__': main()
