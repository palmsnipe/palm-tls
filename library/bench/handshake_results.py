"""Validate real TLS 1.3 benchmark profiles and summarize fresh/resumed runs."""
import argparse
import csv
import json
import statistics
import struct
import zipfile
from pathlib import Path

PHASES=('other','context','trust','keyshare','key_agreement','certificate',
        'signature','kdf','finished','record','network','ticket','idle')
ECDHE_PHASES=('other','import','validate','multiply','map')
LOAD_PHASES=('setup','copy','relocate','native','wolf','qualify','other')
TRUST_PHASES=('other','pem','decode','store','cache')
CASES={f'{cache}_{kind}' for cache in ('nocache','cache')
       for kind in ('full_cold','full_warm','resumed')}
REGRESSIONS={'owned_exact_trust','hostname_mode_and_bad_ca','purge',
             'cancel_opening','cooperative_slot_isolation','tls12_full_and_resumed'}
FIELDS={'sample','load_ticks','handshake_ticks','post_ticks','context_reused',
        'session_reused','ticket_ready','frequency'}


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
    if not allow_failed and not text.endswith('# complete handshake-v1\n'):
        raise ValueError('handshake benchmark incomplete')
    return text


def load(text):
    grouped={}
    profiles={}
    for row in csv.DictReader(line for line in text.splitlines() if not line.startswith('#')):
        name=row.pop('case');values={k:int(v) for k,v in row.items()}
        if set(values)!=FIELDS: raise ValueError('unexpected handshake schema')
        if name not in CASES or any(v<0 for v in values.values()) or not values['frequency']:
            raise ValueError('invalid handshake row')
        key=(name,values['sample'])
        if key in grouped: raise ValueError('duplicate handshake row')
        cached=name.startswith('cache_') and not name.endswith('full_cold')
        resumed=name.endswith('_resumed')
        if bool(values['context_reused'])!=cached or bool(values['session_reused'])!=resumed:
            raise ValueError('unexpected context/session reuse')
        if resumed and not values['ticket_ready']: raise ValueError('resumed connection has no ticket')
        if any(values[key] not in (0,1) for key in ('context_reused','session_reused','ticket_ready')):
            raise ValueError('invalid handshake flags')
        grouped[key]=values
    if set(grouped)!={(name,sample) for name in CASES for sample in range(5)}:
        raise ValueError('missing handshake samples')
    regressions=set()
    for line in text.splitlines():
        if line.startswith('# regression,'):
            _,name,result=line.split(',')
            if name in regressions or name not in REGRESSIONS or result!='passed':
                raise ValueError('invalid regression result')
            regressions.add(name)
        if line.startswith('# phase,'):
            _,name,sample,period,phase,ticks,calls=line.split(',')
            key=(name,int(sample),int(period),phase)
            if key in profiles or phase not in PHASES or int(period) not in (0,1):
                raise ValueError('invalid/duplicate handshake phase')
            if min(int(ticks),int(calls))<0: raise ValueError('negative phase')
            profiles[key]=(int(ticks),int(calls))
    if regressions!=REGRESSIONS: raise ValueError('missing handshake regression checks')
    if len(profiles)!=len(grouped)*2*len(PHASES): raise ValueError('unexpected phase rows')
    if len({r['frequency'] for r in grouped.values()})!=1:
        raise ValueError('inconsistent handshake clocks')
    for (name,sample),row in grouped.items():
        for period,column in ((0,'handshake_ticks'),(1,'post_ticks')):
            entries=[profiles.get((name,sample,period,phase)) for phase in PHASES]
            if any(entry is None for entry in entries) or sum(e[0] for e in entries)!=row[column]:
                raise ValueError('incomplete or unbalanced handshake phases')
        # A cached context does no trust parsing; a full handshake must perform
        # key agreement and signature verification, while a resumed one skips certificates.
        if row['context_reused'] and profiles[name,sample,0,'trust'][1]:
            raise ValueError('cached context reparsed trust')
        if not name.endswith('_full_cold') and row['load_ticks']:
            raise ValueError('warm connection unexpectedly reloaded the engine')
        if not profiles[name,sample,0,'keyshare'][1]: raise ValueError('missing keyshare timing')
        if not name.endswith('_resumed') and not profiles[name,sample,0,'signature'][1]:
            raise ValueError('full handshake did not verify a signature')
        if name.endswith('_resumed') and profiles[name,sample,0,'certificate'][1]:
            raise ValueError('resumed handshake processed a certificate')
    load_ecdhe(text, grouped, profiles)
    load_startup(text, grouped, profiles)
    return grouped,profiles


def load_ecdhe(text, rows, profiles):
    detailed={}
    for line in text.splitlines():
        if not line.startswith('# ecdhe,'): continue
        _,name,sample,phase,ticks,calls=line.split(',')
        key=(name,int(sample),phase)
        if key in detailed or phase not in ECDHE_PHASES or min(int(ticks),int(calls))<0:
            raise ValueError('invalid/duplicate ECDHE phase')
        detailed[key]=(int(ticks),int(calls))
    if not detailed: return detailed  # Historical 240-byte profiles remain readable.
    expected={(name,sample,phase) for name,sample in rows for phase in ECDHE_PHASES}
    if set(detailed)!=expected: raise ValueError('incomplete ECDHE phases')
    for name,sample in rows:
        if sum(detailed[name,sample,p][0] for p in ECDHE_PHASES)!=profiles[name,sample,0,'key_agreement'][0]:
            raise ValueError('ECDHE phases do not partition key agreement')
        if any(not detailed[name,sample,p][1] for p in ECDHE_PHASES):
            raise ValueError('ECDHE subphase was not exercised')
    return detailed


def load_startup(text, rows, profiles):
    result={}
    for kind,phases in (('load',LOAD_PHASES),('trust',TRUST_PHASES)):
        data={}
        for line in text.splitlines():
            if not line.startswith('# '+kind+','): continue
            _,case,sample,phase,ticks,calls=line.split(',');key=(case,int(sample),phase)
            if key in data or phase not in phases or min(int(ticks),int(calls))<0:
                raise ValueError('invalid/duplicate startup detail')
            data[key]=(int(ticks),int(calls))
        if data:
            if set(data)!={(case,sample,phase) for case,sample in rows for phase in phases}:
                raise ValueError('incomplete startup details')
            for case,sample in rows:
                expected=rows[case,sample]['load_ticks'] if kind=='load' else profiles[case,sample,0,'trust'][0]
                if sum(data[case,sample,phase][0] for phase in phases)!=expected:
                    raise ValueError('startup detail sum mismatch')
                if kind=='load' and not case.endswith('full_cold') and any(data[case,sample,phase][1] for phase in phases):
                    raise ValueError('warm open has loader calls')
            result[kind]=data
    if result and set(result)!={'load','trust'}: raise ValueError('partial startup extension')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path)
    p.add_argument('--server-log',type=Path)
    args=p.parse_args()
    rows,profiles=load(args.input.read_text())
    print('case,median_handshake_ms,min_ms,max_ms,median_load_ms')
    for case in sorted(CASES):
        samples=[r for (name,_),r in rows.items() if name==case]
        ms=[r['handshake_ticks']*1000/r['frequency'] for r in samples]
        loads=[r['load_ticks']*1000/r['frequency'] for r in samples]
        print(f'{case},{statistics.median(ms):.1f},{min(ms):.1f},{max(ms):.1f},{statistics.median(loads):.1f}')
    if args.server_log:
        server=[json.loads(line) for line in args.server_log.read_text().splitlines()]
        successful=[r for r in server if r.get('request')=='probe\n']
        assert len(successful)==30 and sum(r['resumed'] for r in successful)==10
        assert all(r['version']=='TLSv1.3' and r['cipher']=='TLS_AES_128_GCM_SHA256' for r in successful)
        legacy=[r for r in server if r.get('version')=='TLSv1.2' and r.get('request')=='check\n']
        assert len(legacy)==2 and sum(r['resumed'] for r in legacy)==1
        print('# server independently confirmed 20 full and 10 resumed TLS 1.3 connections')

if __name__=='__main__': main()
