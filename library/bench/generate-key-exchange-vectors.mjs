// SPDX-License-Identifier: GPL-3.0-or-later
import { createECDH, createHash, createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const hex = value => Buffer.from(value, 'hex');
const seed = label => createHash('sha256').update(`PalmTLS KX bench v1 ${label}`).digest();
const asC = bytes => '{' + Array.from(bytes, byte => '0x' + byte.toString(16).padStart(2, '0')).join(',') + '}';
const privateX = raw => createPrivateKey({
    key: Buffer.concat([hex('302e020100300506032b656e04220420'), raw]),
    type: 'pkcs8',
    format: 'der',
});
const publicX = key => createPublicKey(key).export({ type: 'spki', format: 'der' }).subarray(-32);

const rfcAlice = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
const rfcBobPublic = hex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
const rfcAlicePublic = hex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
const rfcSecret = hex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');

const p256 = [], x25519 = [];
for (let sample = 0; sample < 5; sample++) {
    const scalar = seed(`P-256 ${sample}`);
    const peerScalar = seed(`P-256 peer ${sample}`);
    const blindKeygen = seed(`P-256 keygen scale ${sample}`);
    const blindAgree = seed(`P-256 agreement scale ${sample}`);
    // The high bit clears the P-256 order and field bounds for fixture inputs.
    for (const value of [scalar, peerScalar, blindKeygen, blindAgree]) value[0] &= 0x7f;
    const key = createECDH('prime256v1');
    const peer = createECDH('prime256v1');
    key.setPrivateKey(scalar);
    peer.setPrivateKey(peerScalar);
    p256.push([scalar, peer.getPublicKey().subarray(1), key.getPublicKey(),
        key.computeSecret(peer.getPublicKey()), blindKeygen, blindAgree]);

    const xBlinding = ['keygen mask', 'keygen scale', 'agreement mask', 'agreement scale']
        .map(label => seed(`X25519 ${label} ${sample}`));
    for (const value of xBlinding) value[31] &= 0x3f;
    if (sample === 0) {
        x25519.push([rfcAlice, rfcBobPublic, rfcAlicePublic, rfcSecret, ...xBlinding]);
    } else {
        const raw = seed(`X25519 ${sample}`);
        const key = privateX(raw);
        const peer = privateX(seed(`X25519 peer ${sample}`));
        const shared = diffieHellman({ privateKey: key, publicKey: createPublicKey(peer) });
        x25519.push([raw, publicX(peer), publicX(key), shared, ...xBlinding]);
    }
}

const table = rows => rows.map(row => '    {\n' +
    row.map(field => '        ' + asC(field) + ',').join('\n') + '\n    },').join('\n');
writeFileSync(process.argv[2], `/* Generated public test fixtures. */
static const UInt8 kP256Prime[32] = ${asC(hex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'))};
static const UInt8 kP256Order[32] = ${asC(hex('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'))};
static const P256Fixture kP256Fixtures[] = {
${table(p256)}
};
static const X25519Fixture kX25519Fixtures[] = {
${table(x25519)}
};
`);
