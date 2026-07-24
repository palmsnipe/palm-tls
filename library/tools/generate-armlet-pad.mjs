import { statSync, writeFileSync } from 'node:fs';

const [output, ...resources] = process.argv.slice(2);
if (!output || resources.length === 0 || resources.length % 5 !== 0) {
  throw new Error('usage: generate-armlet-pad.mjs OUTPUT TLS_RESOURCE...');
}

/* Palm resource databases use a 78-byte header, ten bytes per resource entry,
 * and a two-byte gap before resource data. The ARM PRC contains libr:0, tver:1,
 * the selected five-resource protocol engines, PadR:1, and armc:1. build-prc
 * sorts PadR and Tls resources before armc, so their sizes determine armc
 * alignment. */
const resourceCount = 4 + resources.length;
const dataOffset = 80 + resourceCount * 10;
const tlsBytes = resources.reduce((sum, file) => sum + statSync(file).size, 0);
let padding = (4 - ((dataOffset + tlsBytes) % 4)) % 4;
if (padding === 0) padding = 4;
writeFileSync(output, Buffer.alloc(padding, 0x50));
console.log(`Generated ${padding}-byte ARMlet alignment resource for ${resources.length / 5} protocol engine(s)`);
