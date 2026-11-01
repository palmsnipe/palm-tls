import { readFileSync } from 'node:fs';
const prc = readFileSync(process.argv[2]);
const native = readFileSync(process.argv[3]);
const count = prc.readUInt16BE(76);
let found = false;
for (let i = 0; i < count; i++) {
    const entry = 78 + i * 10;
    if (prc.toString('ascii', entry, entry + 4) !== 'armc' ||
        prc.readUInt16BE(entry + 4) !== 1) continue;
    const start = prc.readUInt32BE(entry + 6);
    const end = i + 1 < count ? prc.readUInt32BE(entry + 16) : prc.length;
    if (start % 4 || !prc.subarray(start, end).equals(native))
        throw new Error('ARMlet must be word-aligned and match the library image');
    found = true;
}
if (!found) throw new Error('missing armc:1');
