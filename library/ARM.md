# Palm OS 5 ARM variant

`PalmTLSArm.prc` is a hybrid Palm OS 5 build. Palm applications and system
library dispatch remain 68K code, preserving the `PTLS` API used by Palm OS 4+
consumers. Hot multiprecision multiplication/squaring, P-256 scalar
multiplication and projective mapping, SHA-256 compression, and AES-128-GCM
record protection execute in a native ARMlet through the SDK's
`PceNativeCall` trap.

## Runtime path

1. PalmTLS detects an ARM processor from `sysFtrNumProcessorID`.
2. The selected TLS engine locks the `armc:1` resource and allocates one reusable
   request buffer.
3. wolfSSL's TFM `fp_mul`/`fp_sqr`, P-256 scalar multiplication, SHA-256
   compression, and AES-128-GCM hooks marshal operands through that buffer.
4. The ARMlet performs carry-safe bignum multiplication, SHA-256's 64-round
   compression function, P-256 Montgomery/Jacobian scalar multiplication and
   Jacobian-to-affine mapping, or streaming AES-GCM encryption/decryption and
   authentication.
5. Before normal use, bignum multiplication, mapped and unmapped P-256
   generator multiplication (including native affine mapping), SHA-256 of
   `abc`, and a NIST AES-GCM vector run as native known-answer tests without
   networking.
6. If any test fails, the ARM hook is disabled and the unchanged 68K TFM/SHA
   implementation is used as a fallback.

The buffer is reused because allocating once per multiply would erase much of
the native-code benefit and fragment Palm's dynamic heap. PalmTLS allows only
one active session, so the buffer does not need per-operation locking.

## Build and ABI

Xcode Clang compiles a roughly 29 KB freestanding ARMv5TE code image, including
the generated fixed-base P-256 table. The
ARMlet linker resolves internal calls and PC-relative constants, rejects
unsupported or external relocations, packages the result as `armc:1`, and
verifies that the resource is word-aligned and present only in the ARM PRC.
`PalmTLS68K.prc` contains no native resource.

The ARMlet reads cross-architecture data byte-by-byte because Palm memory uses
the 68K big-endian representation while native ARM is little-endian. Compile-
time assertions bind the bridge to the current 16-bit TFM digit size and 264
digit capacity.

## Scope

The ARM variant moves each complete P-256 operation across the architecture
boundary as one call. General points use a constant-time 4-bit window. Standard
generator multiplication uses a generated fixed-base 8-way comb table,
reducing public-key generation from 256 to 32 point doublings while keeping
constant-time table selection. ECDHE key generation and shared-secret
calculation therefore use native ARM P-256 math. Field squaring uses a
fixed-column Comba schedule with
36 limb multiplications rather than sending equal operands through the generic
64-multiplication path. ECDSA verification dispatches its complete
`u1*G + u2*Q` operation as one native call. Its public scalars use an interleaved
width-5 signed-digit representation, sharing one 257-doubling schedule and
averaging about 86 additions. The ECDHE single-scalar paths remain constant-time;
the variable-time verifier is safe here because the signature, digest, and
public key are not secrets. Keeping the Jacobian additions and final affine
conversion native avoids the generic 68K projective addition and inversion,
which otherwise trigger hundreds of architecture crossings. When wolfSSL
requests an unmapped single-scalar result, the ARMlet returns its
Montgomery-domain Jacobian coordinates directly. wolfSSL's following
`ecc_map_ex` call sends that same point back for inversion and affine conversion
in one native call, instead of performing every field multiplication across the
68K/ARM boundary. The bridge records the exact pending point, so ordinary
P-256 points in wolfSSL's normal representation cannot be mistaken for raw
ARMlet coordinates.

SHA-256 compression also runs natively, batching as many as eight consecutive
64-byte blocks into one ARM call. Short transcript hashes still use a single
block, while certificate and record-sized inputs avoid most architecture-crossing
overhead. AES-128-GCM keeps its counter, expanded AES-128 key, and a 4-bit GHASH
table across bounded 512-byte native calls. Key expansion and table construction
therefore happen once per record instead of once per chunk, and GHASH processes
four bits per step instead of one. The state still fits in the existing 528-byte
request operand, supports TLS records of any size, and does not allocate a large
exchange buffer. Protocol control, certificate parsing, memory management, and
NetLib callbacks still run through PACE. Unsupported AES key or nonce shapes
automatically retain wolfSSL's unchanged 68K implementation.

TLS Tester exposes cold engine-load and handshake timings from the shared
library alongside NetLib, DNS, TCP, and HTTP phases. If `TLS` dominates after
the P-256 work moved to ARM, the next candidates are SHA-256 transcript hashing
and certificate parsing. If `HTTP` dominates for larger transfers, AES-GCM and
SHA-256 record processing should move next. A large `Load` value is a loader
and relocation problem rather than a cryptographic one and should be measured
only on the first request.

## Validation

`make -C library test` checks known multiplication vectors, carry-heavy
64-bit and 256-bit operands, three complete P-256 scalar-multiplication vectors
(including explicit fixed-base and general-path dispatch checks), native P-256
Jacobian-to-affine mapping, double-scalar-add vectors covering signed digits and
a bit-256 carry,
single-block and eight-block SHA-256 compression vectors, NIST AES-GCM encrypt
and decrypt vectors, and a multi-update AES-GCM vector with AAD, the linked
position-independent ARM image, PRC resource identity/alignment, and both Palm
library layouts. On Palm OS 5, TLS Tester
calls API 10's `PalmTlsLibRunSelfTest` during startup and displays a pass or
failure result. This invokes the real ARMlet through `PceNativeCall` and runs
deterministic P-256 ECDHE key-generation/shared-secret and ECDSA verification
vectors in each installed TLS 1.2/TLS 1.3 engine. It does not open NetLib or
require a network-capable Cloudpilot build.

The offline result can be checked on any ARM Cloudpilot ROM. End-to-end TLS and
timing still require a network-capable target, so the physical-device test
remains necessary after the offline test passes.

The original benchmark ran at the E2's normal 100 MIPS speed. The native
`cp-uarm` baseline completed the combined TLS 1.2 and TLS 1.3 workload in 5,645
Palm ticks (56.45 seconds). Moving ECDSA double-scalar-add and the other initial
hot paths to ARM reduced it to 2,927 ticks (29.27 seconds). Correctly routing
the 16-bit fast-math build's single-scalar P-256 entry point to ARM, together
with the generated 8-way fixed-base comb, reduced the same workload to 222
ticks (2.22 seconds): TLS 1.2 key generation/shared secret/verification took
37/41/27 ticks, and TLS 1.3 took 39/41/26 ticks. This offline measurement
still performed the final single-scalar Jacobian-to-affine conversion through
many small 68K/ARM calls. Moving the complete conversion into one ARMlet call
reduced three consecutive runs to 116 ticks (1.16 seconds); a guarded follow-up
run took 118 ticks. A representative run measured TLS 1.2 at 10/15/26 ticks and
TLS 1.3 at 11/15/27 ticks. This is about a 47% reduction in the combined
workload without changing the ARMlet's `-Os` build or emulator speed.
The offline workload excludes DNS, TCP connection, certificate parsing, server
latency, and TLS record transfer. Those costs must be evaluated using TLS Tester's real-request
phase timings on a network-capable device.
