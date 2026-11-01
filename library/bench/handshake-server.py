#!/usr/bin/env python3
"""Local TLS 1.3 benchmark fixtures and independently logged server results."""
import argparse
import hashlib
import json
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from pathlib import Path


def fixtures(directory, port, anchors):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'index').write_text('')
    (directory / 'serial').write_text('1000\n')
    config = directory / 'ca.cnf'
    config.write_text(f'''[ca]
default_ca=issuer
[issuer]
database={directory}/index
serial={directory}/serial
new_certs_dir={directory}
default_md=sha256
policy=policy
unique_subject=no
[policy]
commonName=supplied
[root]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyAgreement
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''')
    def run(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)
    def request(name, subject):
        run('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', directory / f'{name}.key')
        run('req', '-new', '-key', directory / f'{name}.key', '-subj', '/CN=' + subject,
            '-out', directory / f'{name}.csr')
    def sign(name, ca, extension, selfsign=False):
        args=['ca','-batch','-notext','-config',config,'-keyfile',directory/f'{ca}.key',
              '-startdate','20200101000000Z','-enddate','20400101000000Z',
              '-extensions',extension,'-in',directory/f'{name}.csr','-out',directory/f'{name}.pem']
        if selfsign: args += ['-selfsign']
        else: args += ['-cert',directory/f'{ca}.pem']
        run(*args)
    for i in range(anchors + 1):
        request(f'root{i}', f'PalmTLS Benchmark Root {i}')
        sign(f'root{i}', f'root{i}', 'root', True)
    request('server', 'localhost')
    sign('server','root0','leaf')
    bundle=b''.join((directory/f'root{i}.pem').read_bytes() for i in range(anchors))
    (directory/'trust.pem').write_bytes(bundle)
    run('x509','-in',directory/'server.pem','-outform','DER','-out',directory/'server.der')
    def array(name, data):
        return f'static const unsigned char {name}[] = {{'+','.join(map(str,data))+'};\n'
    header=f'#define HANDSHAKE_PORT {port}\n#define HANDSHAKE_SLOW_PORT {port + 1}\n#define HANDSHAKE_TLS12_PORT {port + 2}\n'
    header+=array('kHandshakeTrust',bundle)
    header+=array('kHandshakeWrongTrust',(directory/f'root{anchors}.pem').read_bytes())
    header+=array('kHandshakeLeaf',(directory/'server.der').read_bytes())
    (directory/'handshake_vectors.inc').write_text(header)
    return {'trust_anchor_count':anchors,'trust_bytes':len(bundle),
            'trust_sha256':hashlib.sha256(bundle).hexdigest(),
            'leaf_sha256':hashlib.sha256((directory/'server.der').read_bytes()).hexdigest()}


def serve(args):
    directory=args.directory.resolve()
    if args.reuse_fixtures:
        metadata=json.loads((directory/'server.json').read_text())
        if hashlib.sha256((directory/'trust.pem').read_bytes()).hexdigest()!=metadata['trust_sha256']:
            raise ValueError('fixture trust hash mismatch')
    else:
        metadata=fixtures(directory,args.port,args.anchors)
    def make_context(version):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=context.maximum_version=version
        context.set_ecdh_curve('prime256v1')
        context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256')
        context.num_tickets=2
        context.load_cert_chain(directory/'server.pem',directory/'server.key')
        return context
    context=make_context(ssl.TLSVersion.TLSv1_3)
    legacy_context=make_context(ssl.TLSVersion.TLSv1_2)
    lock=threading.Lock()
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            row={}
            try:
                self.request.settimeout(180)
                if self.server.slow:
                    # Delay after ClientHello arrives, so context/keygen time
                    # cannot consume the delay before the client starts I/O.
                    self.request.recv(1,socket.MSG_PEEK)
                    time.sleep(0.15)
                with self.server.context.wrap_socket(self.request,server_side=True) as connection:
                    row.update(version=connection.version(),resumed=connection.session_reused,
                               cipher=connection.cipher()[0])
                    request=connection.recv(256)
                    row['request']=request.decode('ascii',errors='replace')
                    if request: connection.sendall(b'OK\n')
            except (OSError,ssl.SSLError) as error: row['error']=str(error)
            with lock:
                with (directory/'connections.jsonl').open('a') as output:
                    output.write(json.dumps(row)+'\n')
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True
        daemon_threads=True
    with Server(('127.0.0.1',args.port),Handler) as server, \
            Server(('127.0.0.1',args.port+1),Handler) as slow, \
            Server(('127.0.0.1',args.port+2),Handler) as legacy:
        server.slow=False
        slow.slow=True
        legacy.slow=False
        server.context=slow.context=context
        legacy.context=legacy_context
        threading.Thread(target=slow.serve_forever,daemon=True).start()
        threading.Thread(target=legacy.serve_forever,daemon=True).start()
        metadata.update(port=server.server_address[1],openssl=ssl.OPENSSL_VERSION)
        (directory/'server.json').write_text(json.dumps(metadata,indent=2)+'\n')
        print(json.dumps(metadata),flush=True)
        server.serve_forever()

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory',type=Path,required=True)
    p.add_argument('--port',type=int,default=18443)
    p.add_argument('--anchors',type=int,default=8)
    p.add_argument('--reuse-fixtures',action='store_true')
    if not ssl.HAS_TLSv1_3:
        p.error('requires a Python build with TLS 1.3 support (OpenSSL 1.1.1+)')
    serve(p.parse_args())
