import { readFileSync } from 'node:fs';

const [file, variant = '68k', profile = 'full'] = process.argv.slice(2);
if (!file) throw new Error('usage: validate_library.mjs FILE [68k|arm] [tls13|modern|full]');
const selectedProtocols = {
  tls13: [13],
  modern: [12, 13],
  full: [11, 12, 13],
}[profile];
if (!selectedProtocols) throw new Error(`unknown profile ${profile}`);
const data = readFileSync(file);
if (data.length < 78) throw new Error('PRC is shorter than its database header');
const text = (start, length) => data.subarray(start, start + length)
  .toString('latin1').split('\0', 1)[0];
const name = text(0, 32);
const type = data.subarray(60, 64).toString('latin1');
const creator = data.subarray(64, 68).toString('latin1');
const count = data.readUInt16BE(76);
if (name !== 'Palm TLS' || type !== 'libr' || creator !== 'PTLS') {
  throw new Error(`unexpected identity ${name}, ${type}/${creator}`);
}
const resources = [];
const identities = new Set();
for (let i = 0; i < count; i += 1) {
  const offset = 78 + i * 10;
  const resource = {
    type: data.subarray(offset, offset + 4).toString('latin1'),
    id: data.readUInt16BE(offset + 4),
    offset: data.readUInt32BE(offset + 6),
  };
  const identity = `${resource.type}:${resource.id}`;
  if (identities.has(identity)) throw new Error(`duplicate resource ${identity}`);
  identities.add(identity);
  resources.push(resource);
}
const protocolResources = {
  11: [['TlsC', 21], ['TlsC', 22], ['TlsC', 23], ['TlsC', 24], ['TlsR', 3]],
  12: [['TlsC', 1], ['TlsC', 2], ['TlsC', 3], ['TlsC', 4], ['TlsR', 1]],
  13: [['TlsC', 11], ['TlsC', 12], ['TlsC', 13], ['TlsC', 14], ['TlsR', 2]],
};
const requiredResources = [['libr', 0],
  ...selectedProtocols.flatMap((protocol) => protocolResources[protocol])];
for (const required of requiredResources) {
  if (!resources.some(({ type: resourceType, id }) =>
    resourceType === required[0] && id === required[1])) {
    throw new Error(`missing resource ${required[0]}:${required[1]}`);
  }
}
for (const protocol of [11, 12, 13].filter((item) =>
  !selectedProtocols.includes(item))) {
  for (const forbidden of protocolResources[protocol]) {
    if (resources.some(({ type: resourceType, id }) =>
      resourceType === forbidden[0] && id === forbidden[1])) {
      throw new Error(`unexpected resource ${forbidden[0]}:${forbidden[1]}`);
    }
  }
}
const hasArmlet = resources.some(({ type: resourceType, id }) =>
  resourceType === 'armc' && id === 1);
if (variant === 'arm' && !hasArmlet) throw new Error('ARM variant has no armc:1');
if (variant !== 'arm' && hasArmlet)
  throw new Error('68K variant unexpectedly contains armc:1');
if (variant === 'arm') {
  const armlet = resources.find(({ type: resourceType, id }) =>
    resourceType === 'armc' && id === 1);
  if (armlet.offset % 4 !== 0) throw new Error('ARMlet resource is not word-aligned');
}
const ordered = [...resources].sort((a, b) => a.offset - b.offset);
for (let i = 0; i < ordered.length; i += 1) {
  const end = i + 1 < ordered.length ? ordered[i + 1].offset : data.length;
  if (ordered[i].offset < 78 + count * 10 ||
      ordered[i].offset >= end || end > data.length) {
    throw new Error(`invalid resource offset for ${ordered[i].type}:${ordered[i].id}`);
  }
  ordered[i].size = end - ordered[i].offset;
  if (ordered[i].type === 'TlsC' &&
      (ordered[i].size === 0 || ordered[i].size >= 65000))
    throw new Error(`${ordered[i].type}:${ordered[i].id} has unsafe size ${ordered[i].size}`);
}

const resource = (type, id) => ordered.find((entry) =>
  entry.type === type && entry.id === id);
for (const engine of [
  { protocol: 12, reloc: 1, segments: [1, 2, 3, 4] },
  { protocol: 13, reloc: 2, segments: [11, 12, 13, 14] },
  { protocol: 11, reloc: 3, segments: [21, 22, 23, 24] },
].filter(({ protocol }) => selectedProtocols.includes(protocol))) {
  const reloc = resource('TlsR', engine.reloc);
  const body = data.subarray(reloc.offset, reloc.offset + reloc.size);
  if (body.length < 4 || body.readUInt16BE(0) !== 1)
    throw new Error(`invalid relocation header TlsR:${engine.reloc}`);
  const relocCount = body.readUInt16BE(2);
  if (body.length !== 4 + relocCount * 6)
    throw new Error(`invalid relocation length TlsR:${engine.reloc}`);
  const seen = new Set();
  for (let index = 0; index < relocCount; index += 1) {
    const entryOffset = 4 + index * 6;
    const segment = body.readUInt16BE(entryOffset);
    const sourceOffset = body.readUInt32BE(entryOffset + 2);
    if (segment >= engine.segments.length)
      throw new Error(`invalid source segment ${segment} in TlsR:${engine.reloc}`);
    const key = `${segment}:${sourceOffset}`;
    if (seen.has(key)) throw new Error(`duplicate relocation ${key} in TlsR:${engine.reloc}`);
    seen.add(key);
    const code = resource('TlsC', engine.segments[segment]);
    if (sourceOffset + 4 > code.size)
      throw new Error(`relocation ${key} exceeds TlsC:${code.id}`);
  }
}
console.log(`Validated ${file}: ${name}, ${type}/${creator}, ${count} resources, ${profile} profile`);
