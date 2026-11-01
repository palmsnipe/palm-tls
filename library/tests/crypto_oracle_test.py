#!/usr/bin/env python3
"""Check host C or the extracted ARM image against independent crypto oracles."""
import argparse
import ctypes
import json
import random
import subprocess
from pathlib import Path

HEADER, DIGITS = 4, 528
LEFT, RIGHT, OUTPUT = 4, 532, 1060
REQUEST_SIZE, SUCCESS, ERROR = 1588, 256, 0xffffffff
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


class Host:
    def __init__(self, path):
        self.library = ctypes.CDLL(str(path.resolve()))
        self.entry = self.library.PalmTlsArmletEntry
        self.entry.argtypes = [ctypes.c_void_p] * 3
        self.entry.restype = ctypes.c_uint32
        self.inverse = self.library.PalmTlsArmletTestInverse
        self.inverse.argtypes = [ctypes.c_void_p] * 2
        self.inverse.restype = None

    def invoke(self, request, skew=0):
        storage = bytearray(skew) + request
        buffer = (ctypes.c_ubyte * len(storage)).from_buffer(storage)
        result = self.entry(None, ctypes.addressof(buffer) + skew, None)
        request[:] = storage[skew:]
        return result


class Arm:
    CODE, DATA, STACK, STOP = 0x100000, 0x200000, 0x300000, 0x400000

    def __init__(self, path, cpu):
        import unicorn as uc
        from unicorn import arm_const as regs
        self.regs = regs
        self.machine = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM | uc.UC_MODE_LITTLE_ENDIAN)
        model = regs.UC_CPU_ARM_TI925T if cpu == 'ti925t' else regs.UC_CPU_ARM_PXA270
        self.machine.ctl_set_cpu_model(model)
        for address, length in [(self.CODE, 0x10000), (self.DATA, 0x10000),
                                (self.STACK, 0x10000), (self.STOP, 0x1000)]:
            self.machine.mem_map(address, length)
        # Verify that the selected model really distinguishes the old ISA:
        # CLZ r0,r0 is unavailable on TI925T and available on PXA270.
        self.machine.mem_write(self.CODE, bytes.fromhex('100f6fe1'))
        try:
            self.machine.emu_start(self.CODE, self.CODE + 4, count=1)
        except uc.UcError as error:
            if cpu != 'ti925t' or error.errno != uc.UC_ERR_INSN_INVALID:
                raise
        else:
            if cpu == 'ti925t':
                raise RuntimeError('CPU model failed the ARMv4T negative instruction probe')
        image = path.read_bytes()
        if len(image) > 0x10000:
            raise ValueError('ARM image exceeds test code mapping')
        self.machine.mem_write(self.CODE, image)
        self.machine.ctl_remove_cache(self.CODE, self.CODE + 0x10000)

    def invoke(self, request, skew=0):
        machine, regs = self.machine, self.regs
        machine.mem_write(self.DATA + skew, bytes(request))
        for register, value in [(regs.UC_ARM_REG_R0, 0), (regs.UC_ARM_REG_R1, self.DATA + skew),
                                (regs.UC_ARM_REG_R2, 0), (regs.UC_ARM_REG_SP, self.STACK + 0x10000),
                                (regs.UC_ARM_REG_LR, self.STOP)]:
            machine.reg_write(register, value)
        machine.emu_start(self.CODE, self.STOP, timeout=10_000_000, count=50_000_000)
        if machine.reg_read(regs.UC_ARM_REG_PC) != self.STOP:
            raise RuntimeError('ARMlet did not return within the execution limit')
        request[:] = machine.mem_read(self.DATA + skew, len(request))
        return machine.reg_read(regs.UC_ARM_REG_R0)


def integer(value):
    return value.to_bytes(32, 'big')


def point(value):
    return integer(value[0]) + integer(value[1])


def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0: return None
    slope = ((3 * x * x - 3) * pow(2 * y, -1, P) if a == b else
             (v - y) * pow(u - x, -1, P)) % P
    result_x = (slope * slope - x - u) % P
    return result_x, (slope * (x - result_x) - y) % P


def multiply(scalar, base):
    result = None
    while scalar:
        if scalar & 1: result = add(result, base)
        base = add(base, base)
        scalar >>= 1
    return result


def request(command):
    data = bytearray(REQUEST_SIZE)
    data[0], data[3] = 1, command
    return data


def aes(backend, rng):
    vectors = []
    # Cross block, chunk and AAD boundaries, including empty records and the
    # maximum AAD representable by the existing request ABI.
    for aad_size in (0, 1, 13, 16, 20, 31, 516):
        for size in (0, 1, 15, 16, 17, 31, 32, 511, 512, 513, 4096, 16384):
            make = lambda length: bytes(rng.getrandbits(8) for _ in range(length)).hex()
            vectors.append(dict(key=make(16), nonce=make(12), aad=make(aad_size), plaintext=make(size)))
    expected = json.loads(subprocess.check_output(['node', str(Path(__file__).with_name('aes_oracle.mjs'))],
                                                 input=json.dumps(vectors).encode()))
    for index, vector in enumerate(expected):
        for decrypt in (False, True):
            data = bytearray([0xa5]) * REQUEST_SIZE
            data[0], data[3] = 1, 3
            aad = bytes.fromhex(vector['aad'])
            data[LEFT:LEFT + 4] = bytes([0, len(aad) >> 8, len(aad) & 255, decrypt])
            data[LEFT + 4:LEFT + 20] = bytes.fromhex(vector['key'])
            nonce = bytes.fromhex(vector['nonce'])
            data[RIGHT:RIGHT + len(nonce + aad)] = nonce + aad
            skew = index % 4
            assert backend.invoke(data, skew) == SUCCESS, ('GCM start', index)
            source = bytes.fromhex(vector['ciphertext' if decrypt else 'plaintext'])
            output = bytearray()
            # Non-final updates must end at a block boundary, as in the bridge.
            chunk = (16, 32, 128, 512)[index % 4]
            for offset in range(0, len(source), chunk):
                part = source[offset:offset + chunk]
                data[LEFT:LEFT + 3] = bytes([1, len(part) >> 8, len(part) & 255])
                data[RIGHT:RIGHT + len(part)] = part
                assert backend.invoke(data, skew) == SUCCESS, ('GCM update', index)
                output.extend(data[OUTPUT:OUTPUT + len(part)])
            data[LEFT:LEFT + 3] = b'\x02\0\0'
            assert backend.invoke(data, skew) == SUCCESS, ('GCM final', index)
            assert output.hex() == vector['plaintext' if decrypt else 'ciphertext'], ('GCM output', index)
            assert data[OUTPUT:OUTPUT + 16].hex() == vector['tag'], ('GCM tag', index)
    return len(expected) * 2


def field_request(operation, a, b, count=1):
    data = request(7)
    data[1], data[2] = operation, count
    data[LEFT:LEFT + 32], data[RIGHT:RIGHT + 32] = integer(a), integer(b)
    data[OUTPUT:OUTPUT + 32] = b'\xa5' * 32
    return data


def field_arithmetic(backend):
    r = 1 << 256
    inverse_r = pow(r, -1, P)
    edges = [0, 1, 2, P - 1, P - 2, P - 3,
             int('aaaaaaaa' * 8, 16), int('55555555' * 8, 16)]
    for bit in (31, 32, 63, 64, 95, 96, 127, 128, 191, 192, 223, 224, 255):
        edges += [(1 << bit) - 1, 1 << bit, (1 << bit) + 1]
    rng = random.Random(0x524544554345)
    pairs = [(a, b) for a in edges[:8] for b in edges[:8]]
    pairs += [(a, edges[(index * 7 + 3) % len(edges)]) for index, a in enumerate(edges)]
    pairs += [(rng.randrange(P), rng.randrange(P)) for _ in range(512)]
    cases = 0
    for operation in range(3):
        vectors = [(a, b, 1) for a, b in pairs]
        vectors += [(P - 1, P - 2, count) for count in (2, 128, 255)]
        if operation == 2:
            # T < p*R is the Montgomery reducer's domain; its low half need
            # not be canonical. Include T=p*R-1 and the 256-bit carry edges.
            vectors += [(r - 1, b, 1) for b in (0, 1, P - 1)]
        for index, (a, b, count) in enumerate(vectors):
            expected = a
            for _ in range(count):
                expected = ((expected * b * inverse_r) if operation == 0 else
                            (expected * expected * inverse_r) if operation == 1 else
                            (expected * inverse_r + b)) % P
            data = field_request(operation, a, b, count)
            assert backend.invoke(data, index % 4) == SUCCESS, ('field status', operation, index)
            assert data[OUTPUT:OUTPUT + 32] == integer(expected), ('field oracle', operation, index)
            cases += 1
    for operation, a, b, count in ((3, 0, 0, 1), (0, 0, 0, 0),
            (0, P, 1, 1), (0, 1, P, 1), (1, P, 0, 1), (2, 0, P, 1)):
        data = field_request(operation, a, b, count)
        assert backend.invoke(data) == ERROR, 'invalid raw-field request accepted'
        assert data[OUTPUT:OUTPUT + 32] == b'\xa5' * 32, 'field error modified output'
    if isinstance(backend, Arm):
        field_traces(backend)
    return cases


def field_traces(backend):
    # Instruction and data-address traces must be independent of valid field
    # values for a fixed public operation/count. This is not a proof about
    # operand-dependent timing on physical ARM processors.
    import hashlib
    import unicorn as uc
    trace = None
    events = [0, 0]
    def instruction(machine, address, size, context):
        events[0] += 1
        trace.update(b'I' + address.to_bytes(4, 'little'))
    def memory(machine, access, address, size, value, context):
        events[1] += 1
        trace.update(bytes([access, size]) + address.to_bytes(4, 'little'))
    machine = backend.machine
    hooks = [machine.hook_add(uc.UC_HOOK_CODE, instruction),
             machine.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, memory)]
    machine.ctl_remove_cache(backend.CODE, backend.CODE + 0x10000)
    try:
        for operation in range(3):
            reference = None
            trace_rng = random.Random(0x53454c454354)
            vectors = [(0, 0), (1, 1), (P - 1, P - 2),
                       (int('aaaaaaaa' * 8, 16), int('55555555' * 8, 16))]
            vectors += [(trace_rng.randrange(P), trace_rng.randrange(P)) for _ in range(16)]
            for a, b in vectors:
                trace = hashlib.sha256()
                events[:] = [0, 0]
                data = field_request(operation, a, b, 2)
                assert backend.invoke(data) == SUCCESS
                assert all(events), 'trace hooks did not record execution'
                digest = trace.digest()
                if reference is None:
                    reference = digest
                assert digest == reference, ('field control/address trace varies', operation)
    finally:
        for hook in hooks:
            machine.hook_del(hook)
        machine.ctl_remove_cache(backend.CODE, backend.CODE + 0x10000)


def secret_scalar_traces(backend):
    """Compare complete general-point control/data-address traces for valid keys."""
    import hashlib
    import unicorn as uc
    digest = None
    events = [0, 0]
    def block(machine, address, size, context):
        events[0] += 1
        digest.update(b'B' + address.to_bytes(4,'little') + size.to_bytes(4,'little'))
    def memory(machine, access, address, size, value, context):
        events[1] += 1
        digest.update(bytes([access,size]) + address.to_bytes(4,'little'))
    machine=backend.machine
    hooks=[machine.hook_add(uc.UC_HOOK_BLOCK,block),
           machine.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,memory)]
    machine.ctl_remove_cache(backend.CODE,backend.CODE+0x10000)
    try:
        reference=None
        for scalar in (1, N-1, int('10'*32,16), N+30):
            digest=hashlib.sha256();events[:]=[0,0]
            data=request(1)
            data[LEFT:LEFT+32]=integer(scalar)
            data[RIGHT:RIGHT+64]=point(multiply(7,G))
            assert backend.invoke(data)==SUCCESS
            assert all(events), 'secret trace hooks did not execute'
            current=digest.digest()
            if reference is None: reference=current
            assert current==reference, 'secret scalar control/address trace varies'
    finally:
        for hook in hooks: machine.hook_del(hook)
        machine.ctl_remove_cache(backend.CODE,backend.CODE+0x10000)


def p256_validation(backend, rng):
    # Derive B independently from the standard generator rather than sharing
    # the production Montgomery constant. Include small-X valid points so a
    # zero coordinate is not incorrectly treated as point-at-infinity.
    b=(G[1]**2-G[0]**3+3*G[0]) % P
    values=[G,(G[0],P-G[1]),(0,0),(1,1),(P-1,P-1)]
    for x in (0,1,2,3,P-1,P-2):
        rhs=(x**3-3*x+b)%P;y=pow(rhs,(P+1)//4,P)
        if y*y%P==rhs: values.extend(((x,y),(x,P-y)))
    for scalar in range(1,65):
        value=multiply(scalar,G);values.append(value)
        encoded=bytearray(point(value));encoded[scalar%64]^=1
        values.append((int.from_bytes(encoded[:32],'big'),int.from_bytes(encoded[32:],'big')))
    values += [(rng.randrange(P),rng.randrange(P)) for _ in range(128)]
    values += [(P,G[1]),(G[0],P),(P+1,G[1]),(G[0],P+1),
               (2**256-1,G[1]),(G[0],2**256-1),(P,P)]
    for index,(x,y) in enumerate(values):
        expected=258 if x>=P or y>=P else (SUCCESS if (y*y-x*x*x+3*x-b)%P==0 else 257)
        data=request(8);data[RIGHT:RIGHT+64]=integer(x)+integer(y)
        data[OUTPUT:]=b'\xa5'*(REQUEST_SIZE-OUTPUT)
        original=bytes(data)
        assert backend.invoke(data,index%4)==expected,('P256 validation',index,x,y)
        assert data==original,'validation modified request/output'
    for first,second,version in ((1,0,1),(0,1,1),(255,255,1),(0,0,0)):
        data=request(8);data[1],data[2],data[0]=first,second,version
        data[RIGHT:RIGHT+64]=point(G);original=bytes(data)
        assert backend.invoke(data)==ERROR,'invalid validation header accepted'
        assert data==original,'invalid validation request modified memory'
    return len(values)


def p256(backend, rng):
    # Mapping constructed Montgomery/Jacobian points exercises inversion of
    # arbitrary nonzero z in the *extracted* ARM code, not only host C.
    values = [1, 2, 3, P - 2, P - 1] + [rng.randrange(1, P) for _ in range(64)]
    montgomery = 2**256 % P
    for index, z in enumerate(values):
        data = request(5)
        coordinates = (G[0] * z * z % P, G[1] * z * z * z % P, z)
        data[RIGHT:RIGHT + 96] = b''.join(integer(c * montgomery % P) for c in coordinates)
        assert backend.invoke(data, index % 4) == SUCCESS, ('P256 map', index)
        assert data[OUTPUT:OUTPUT + 64] == point(G), ('P256 inverse/map', index)
        if isinstance(backend, Host):
            actual = ctypes.create_string_buffer(32)
            backend.inverse(integer(z), actual)
            assert actual.raw == integer(pow(z, -1, P)), ('P256 inverse oracle', index)
    data = request(5)
    assert backend.invoke(data) == ERROR, 'zero Jacobian z must fail'
    if isinstance(backend, Host):
        actual = ctypes.create_string_buffer(32)
        backend.inverse(integer(0), actual)
        assert actual.raw == integer(0), 'zero inverse convention'
    # N+30 reaches an equal-point addition in the final radix-16 window.
    # Sparse/dense digits exercise infinity and zero-window selection.
    scalars = [1, 2, 3, N - 1, N + 1, N + 30, 2**256 - 1,
               2**252, int('10' * 32, 16)] + [rng.randrange(1, N) for _ in range(12)]
    q = multiply(7, G)
    for base in (G, q):
        data = request(1)
        data[1] = 1
        data[RIGHT:RIGHT + 64] = point(base)
        assert backend.invoke(data) == ERROR, 'zero scalar must return infinity/error'
        for mapped in (False, True):
            data=request(1);data[1]=mapped
            data[LEFT:LEFT+32]=integer(N)
            data[RIGHT:RIGHT+64]=point(base)
            data[OUTPUT:OUTPUT+96]=b'\xa5'*96
            assert backend.invoke(data)==ERROR, 'order scalar must return infinity/error'
            assert data[OUTPUT:OUTPUT+96]==b'\xa5'*96, 'infinity modified output'
    for index, scalar in enumerate(scalars):
        for base in (G, q):
            expected = point(multiply(scalar, base))
            for mapped in (False, True):
                data = request(1)
                data[1] = mapped
                data[LEFT:LEFT + 32] = integer(scalar)
                data[RIGHT:RIGHT + 64] = point(base)
                assert backend.invoke(data, index % 4) == SUCCESS, ('P256 multiply', index)
                if not mapped:
                    data[RIGHT:RIGHT + 96] = data[OUTPUT:OUTPUT + 96]
                    data[3] = 5
                    assert backend.invoke(data, index % 4) == SUCCESS
                assert data[OUTPUT:OUTPUT + 64] == expected, ('P256 affine oracle', index)
    vectors = [(rng.randrange(1, N), rng.randrange(1, N), G, q)
               for _ in range(8)]
    # Exercise every stored odd multiple and every negative width-5 digit,
    # with the generator in either operand position. All values are public.
    table_scalars = list(range(1, 16, 2)) + list(range(17, 32, 2))
    for scalar in table_scalars:
        vectors += [(scalar, 0, G, q), (0, scalar, q, G)]
    minus_g = (G[0], -G[1] % P)
    minus_q = (q[0], -q[1] % P)
    other = multiply(3, G)
    vectors += [
        (1, 1, G, G), (1, N - 1, G, G), (N - 1, 1, G, G),
        (0, 0, G, G), (N, N, G, G), (1, 1, G, minus_g),
        (1, 1, minus_g, G), (1, 2, G, minus_g), (2, 1, minus_g, G),
        # Cancel at bit 5, then recover from infinity at the low nonzero digit.
        (32, 33, minus_g, G), (33, 32, G, minus_g),
        (1, 1, q, q), (1, 1, q, minus_q), (0, 0, q, other),
        (0, 1, G, q), (1, 0, q, G), (1, 1, q, other),
    ]
    for left, right in ((G, q), (q, G), (G, G), (q, other)):
        for a, b in ((2**256 - 1, 1), (1, 2**256 - 1), (N - 1, N - 1)):
            vectors.append((a, b, left, right))
    generic_rng = random.Random(0x4d49584544)
    for left, right in ((q, G), (q, other)):
        vectors += [(generic_rng.randrange(1, N), generic_rng.randrange(1, N),
                     left, right) for _ in range(8)]
    for index, (a, b, left, right) in enumerate(vectors):
        expected = add(multiply(a, left), multiply(b, right))
        data = request(4)
        data[LEFT:LEFT + 64] = integer(a) + integer(b)
        data[RIGHT:RIGHT + 128] = point(left) + point(right)
        data[OUTPUT:OUTPUT + 64] = b'\xa5' * 64
        status = backend.invoke(data, index % 4)
        if expected is None:
            assert status == ERROR, ('infinite double-scalar sum accepted', index)
            assert data[OUTPUT:OUTPUT + 64] == b'\xa5' * 64, 'error modified output'
        else:
            assert status == SUCCESS, ('double-scalar status', index)
            assert data[OUTPUT:OUTPUT + 64] == point(expected), ('double-scalar oracle', index)
    return len(values), len(scalars) * 4, len(vectors)


def order_scalars(backend, rng):
    edges = (1, 2, 3, N - 2, N - 1, 2**255, 2**128, 2**32 - 1)
    vectors = [(e, edges[i], s) for e in (0, 1, N - 1, N, N + 1, 2**256 - 1)
               for i, s in enumerate(edges)]
    vectors += [(2**256 - 1, N - 1, 1 << bit) for bit in range(256)]
    vectors += [(rng.getrandbits(256), rng.randrange(1, N), rng.randrange(1, N))
                for _ in range(128)]
    for index, (e, r, s) in enumerate(vectors):
        data = request(6)
        data[LEFT:LEFT + 96] = integer(e) + integer(r) + integer(s)
        assert backend.invoke(data, index % 4) == SUCCESS, ('order scalars', index)
        inverse = pow(s, -1, N)
        expected = integer(e * inverse % N) + integer(r * inverse % N) + integer(inverse)
        assert data[OUTPUT:OUTPUT + 96] == expected, ('order oracle', index)
    for r, s in ((0, 1), (1, 0), (N, 1), (1, N), (N + 1, 1), (1, N + 1),
                 (2**256 - 1, 1), (1, 2**256 - 1)):
        data = request(6)
        data[LEFT:LEFT + 96] = integer(1) + integer(r) + integer(s)
        data[OUTPUT:OUTPUT + 96] = b'\xa5' * 96
        assert backend.invoke(data) == ERROR, 'out-of-range signature scalar accepted'
        assert data[OUTPUT:OUTPUT + 96] == b'\xa5' * 96, 'invalid scalar modified output'
    return len(vectors)


def ecdsa_math(backend, rng):
    for index in range(8):
        private, nonce = rng.randrange(1, N), rng.randrange(1, N)
        digest = rng.getrandbits(256)
        public = multiply(private, G)
        r = multiply(nonce, G)[0] % N
        s = ((digest + private * r) * pow(nonce, -1, N)) % N
        assert r and s
        for changed_digest, changed_r, valid in ((digest, r, True),
                (digest ^ 1, r, False), (digest, r % (N - 1) + 1, False)):
            data = request(6)
            data[LEFT:LEFT + 96] = integer(changed_digest) + integer(changed_r) + integer(s)
            assert backend.invoke(data, index % 4) == SUCCESS
            scalars = bytes(data[OUTPUT:OUTPUT + 64])
            data = request(4)
            data[LEFT:LEFT + 64] = scalars
            data[RIGHT:RIGHT + 128] = point(G) + point(public)
            status = backend.invoke(data, index % 4)
            accepted = status == SUCCESS and int.from_bytes(data[OUTPUT:OUTPUT + 32], 'big') % N == changed_r
            assert accepted == valid, ('ECDSA math', index, valid)
    return 24


def chacha(backend, rng):
    vectors = []
    for size in (0,1,15,16,17,63,64,65,511,1024,16384):
        for aad in (0,13,32):
            make = lambda n: bytes(rng.getrandbits(8) for _ in range(n)).hex()
            vectors.append(dict(key=make(32),nonce=make(12),aad=make(aad),plaintext=make(size)))
    expected = json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('chacha_oracle.mjs'))],
        input=json.dumps(vectors).encode()))
    memory = bytearray(0xe000)
    if isinstance(backend, Host):
        storage = (ctypes.c_ubyte * len(memory)).from_buffer(memory)
        ctypes.c_void_p.in_dll(backend.library,'PalmTlsArmletHostMemory').value = ctypes.addressof(storage)
        base = 0
    else:
        base = backend.DATA + 0x2000
    for i,v in enumerate(expected):
        size = len(bytes.fromhex(v['plaintext'])); skew = i%4
        inp,out,aad = skew,0x5000+skew,0xa000+skew
        for decrypt,tamper in ((0,False),(1,False),(1,True)):
            data = request(9)
            put = lambda off,value: data.__setitem__(slice(LEFT+off,LEFT+off+4),value.to_bytes(4,'big'))
            data[LEFT] = decrypt
            state = b'expand 32-byte k'+bytes.fromhex(v['key'])+bytes(4)+bytes.fromhex(v['nonce'])
            for j in range(16): put(4+j*4,int.from_bytes(state[j*4:j*4+4],'little'))
            for off,value in ((68,base+inp),(72,base+out),(76,size),(80,base+aad),(84,len(bytes.fromhex(v['aad'])))):
                put(off,value)
            data[LEFT+88:LEFT+104] = bytes.fromhex(v['tag'])
            if tamper: data[LEFT+88] ^= 1
            memory[:] = bytes([0xa5])*len(memory)
            source = bytes.fromhex(v['ciphertext' if decrypt else 'plaintext'])
            memory[inp:inp+size] = source
            a = bytes.fromhex(v['aad']); memory[aad:aad+len(a)] = a
            if isinstance(backend,Arm): backend.machine.mem_write(base,bytes(memory))
            result = backend.invoke(data,skew)
            if isinstance(backend,Arm): memory[:] = backend.machine.mem_read(base,len(memory))
            assert result == (257 if tamper else SUCCESS), ('ChaCha status',i,decrypt,tamper)
            assert data[LEFT+4:LEFT+68] == bytes(64), 'ChaCha copied key not erased'
            if tamper:
                assert memory[out:out+size] == bytes([0xa5])*size, 'unauthenticated plaintext released'
            else:
                assert memory[out:out+size].hex() == v['plaintext' if decrypt else 'ciphertext'], ('ChaCha output',i)
                assert data[LEFT+88:LEFT+104].hex() == v['tag'], ('ChaCha tag',i)
    return len(expected)*3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--host-library', type=Path)
    source.add_argument('--arm-image', type=Path)
    parser.add_argument('--cpu', choices=['ti925t', 'pxa270'], default='ti925t')
    args = parser.parse_args()
    backend = Host(args.host_library) if args.host_library else Arm(args.arm_image, args.cpu)
    rng = random.Random(0x50414c4d)
    chacha_records = chacha(backend, rng)
    records = aes(backend, rng)
    fields = field_arithmetic(backend)
    inverses, multiplies, verifies = p256(backend, rng)
    validations = p256_validation(backend, rng)
    orders = order_scalars(backend, rng)
    signatures = ecdsa_math(backend, rng)
    if isinstance(backend, Arm): secret_scalar_traces(backend)
    print(f'Crypto oracles passed ({args.cpu if args.arm_image else "host"}): '
          f'{chacha_records} ChaCha records, {records} AES-GCM records, {fields} raw-field chains, {inverses} inversions/maps, '
          f'{multiplies} scalar products, {verifies} double-scalar cases, '
          f'{orders} order preparations, {validations} point validations, '
          f'{signatures} ECDSA valid/tampered cases; alignment offsets 0..3')


if __name__ == '__main__':
    main()
