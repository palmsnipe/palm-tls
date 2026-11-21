import { readFileSync } from 'node:fs';

const [file, variant = '68k', profile = 'full', expectedVersion,
  expectedDbVersion, seedMode = 'no-test-seed'] = process.argv.slice(2);
if (!file || !expectedVersion || !expectedDbVersion) {
  throw new Error(
    'usage: validate_library.mjs FILE [68k|arm] [tls13|modern|full|browser] VERSION DB_VERSION [test-seed|no-test-seed]',
  );
}
const selectedProtocols = {
  tls13: [13],
  modern: [12, 13],
  full: [11, 12, 13],
  browser: [14],
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
const dbVersion = data.readUInt16BE(34);
if (name !== 'Palm TLS' || type !== 'libr' || creator !== 'PTLS') {
  throw new Error(`unexpected identity ${name}, ${type}/${creator}`);
}
if (dbVersion !== Number(expectedDbVersion)) {
  throw new Error(`database version ${dbVersion} != ${expectedDbVersion}`);
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
  13: [['TlsC', 11], ['TlsC', 12], ['TlsC', 13], ['TlsC', 14], ['TlsC', 15], ['TlsR', 2]],
  14: [['TlsC', 31], ['TlsC', 32], ['TlsC', 33], ['TlsC', 34], ['TlsC', 35], ['TlsR', 4]],
};
const requiredResources = [['libr', 0], ['tver', 1],
  ...selectedProtocols.flatMap((protocol) => protocolResources[protocol])];
for (const required of requiredResources) {
  if (!resources.some(({ type: resourceType, id }) =>
    resourceType === required[0] && id === required[1])) {
    throw new Error(`missing resource ${required[0]}:${required[1]}`);
  }
}
for (const protocol of [11, 12, 13, 14].filter((item) =>
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
const seedIndex = ordered.findIndex(({ type: resourceType }) => resourceType === 'tRng');
if (seedMode === 'test-seed') {
  if (seedIndex === -1 || ordered[seedIndex].id !== 1) {
    throw new Error('missing deterministic test seed resource');
  }
  const start = ordered[seedIndex].offset;
  const end = ordered[seedIndex + 1]?.offset ?? data.length;
  const seed = data.subarray(start, end);
  if (seed.length !== 48 || !seed.every((byte, index) => byte === index)) {
    throw new Error('invalid deterministic test seed');
  }
} else if (seedMode !== 'no-test-seed' || seedIndex !== -1) {
  throw new Error('unexpected test seed resource or invalid seed mode');
}
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
const versionResource = resource('tver', 1);
const version = data.subarray(
  versionResource.offset,
  versionResource.offset + versionResource.size,
).toString('latin1').split('\0', 1)[0];
if (version !== expectedVersion) {
  throw new Error(`version resource ${JSON.stringify(version)} != ${JSON.stringify(expectedVersion)}`);
}
for (const engine of [
  { protocol: 12, reloc: 1, segments: [1, 2, 3, 4] },
  { protocol: 13, reloc: 2, segments: [11, 12, 13, 14, 15] },
  { protocol: 11, reloc: 3, segments: [21, 22, 23, 24] },
  { protocol: 14, reloc: 4, segments: [31, 32, 33, 34, 35] },
].filter(({ protocol }) => selectedProtocols.includes(protocol))) {
  const reloc = resource('TlsR', engine.reloc);
  const body = data.subarray(reloc.offset, reloc.offset + reloc.size);
  const invalid = message => { throw new Error(`${message} in TlsR:${engine.reloc}`); };
  if (body.length < 4) invalid('missing relocation header');
  const version = body.readUInt16BE(0);
  const count = body.readUInt16BE(2);
  const seen = new Set();
  function checkOffset(source, offset, target) {
    const code = resource('TlsC', engine.segments[source]);
    if (!code || (offset & 1) || offset + 4 > code.size)
      invalid(`invalid source ${source}:${offset}`);
    if (seen.has(`${source}:${offset}`) || seen.has(`${source}:${offset - 2}`) ||
        seen.has(`${source}:${offset + 2}`)) invalid(`overlapping relocation ${source}:${offset}`);
    seen.add(`${source}:${offset}`);
    if (target !== undefined && data.readUInt16BE(code.offset + offset) !== (0x11 + target) * 256)
      invalid(`linked word at ${source}:${offset} does not address bank ${target}`);
  }
  if (version === 1) {
    if (body.length !== 4 + count * 6) invalid('invalid legacy relocation length');
    for (let i = 4; i < body.length; i += 6)
      checkOffset(body.readUInt16BE(i), body.readUInt32BE(i + 2));
  } else if (version === 2) {
    if (body.length !== 4 + count * 2) invalid('invalid grouped relocation length');
    let cursor = 4;
    while (cursor < body.length) {
      if (body.length - cursor < 4) invalid('truncated source header');
      const source = body.readUInt16BE(cursor);
      const end = cursor + 4 + 2 * body.readUInt16BE(cursor + 2);
      if (source >= engine.segments.length || end === cursor + 4 || end > body.length) invalid('invalid source block');
      cursor += 4;
      while (cursor < end) {
        if (end - cursor < 4) invalid('truncated target header');
        const target = body.readUInt16BE(cursor);
        const entries = body.readUInt16BE(cursor + 2);
        cursor += 4;
        if (target >= engine.segments.length || !entries || cursor + 2 * entries > end)
          invalid('invalid target group');
        for (let i = 0; i < entries; i++, cursor += 2)
          checkOffset(source, 2 * body.readUInt16BE(cursor), target);
      }
    }
  } else {
    invalid(`unsupported version ${version}`);
  }
}
console.log(`Validated ${file}: ${name}, ${type}/${creator}, ${count} resources, ${profile} profile`);
