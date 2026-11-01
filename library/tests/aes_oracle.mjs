// SPDX-License-Identifier: GPL-3.0-or-later
// Independent OpenSSL AES-GCM oracle; all input is deterministic test data.
import { createCipheriv } from 'node:crypto';
import { readFileSync } from 'node:fs';
const vectors = JSON.parse(readFileSync(0, 'utf8'));
for (const vector of vectors) {
    const bytes = name => Buffer.from(vector[name], 'hex');
    const cipher = createCipheriv('aes-128-gcm', bytes('key'), bytes('nonce'));
    cipher.setAAD(bytes('aad'));
    vector.ciphertext = Buffer.concat([cipher.update(bytes('plaintext')), cipher.final()]).toString('hex');
    vector.tag = cipher.getAuthTag().toString('hex');
}
process.stdout.write(JSON.stringify(vectors));
