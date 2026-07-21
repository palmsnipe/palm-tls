import { readFileSync } from 'node:fs';
const [file] = process.argv.slice(2);
if (!file) throw new Error('usage: validate_library.mjs FILE');
const data = readFileSync(file);
if (data.length < 88) throw new Error('library PRC is truncated');
const text = (start, length) => data.subarray(start, start + length)
  .toString('latin1').split('\0', 1)[0];
const name = text(0, 32);
const type = data.subarray(60, 64).toString('latin1');
const creator = data.subarray(64, 68).toString('latin1');
const count = data.readUInt16BE(76);
if (name !== 'Palm HTTP' || type !== 'libr' || creator !== 'PHTP')
  throw new Error(`unexpected identity ${name}, ${type}/${creator}`);
let found = false;
for (let i = 0; i < count; i += 1) {
  const offset = 78 + i * 10;
  const resourceType = data.subarray(offset, offset + 4).toString('latin1');
  const id = data.readUInt16BE(offset + 4);
  const bodyOffset = data.readUInt32BE(offset + 6);
  if (bodyOffset < 78 + count * 10 || bodyOffset >= data.length)
    throw new Error(`invalid resource offset ${resourceType}:${id}`);
  if (resourceType === 'libr' && id === 0) found = true;
}
if (!found) throw new Error('missing libr:0');
console.log(`Validated ${file}: ${name}, ${type}/${creator}, ${count} resources`);
