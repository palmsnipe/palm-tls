import { readFileSync, writeFileSync } from 'node:fs';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('usage: extract-armlet.mjs INPUT.o OUTPUT.bin');
const elf = readFileSync(input);
if (elf.length < 52 || elf[0] !== 0x7f || elf.subarray(1, 4).toString() !== 'ELF' ||
    elf[4] !== 1 || elf[5] !== 1 || elf.readUInt16LE(16) !== 1 ||
    elf.readUInt16LE(18) !== 40)
  throw new Error('expected a little-endian ELF32 ARM relocatable object');

const sectionOffset = elf.readUInt32LE(32);
const sectionSize = elf.readUInt16LE(46);
const sectionCount = elf.readUInt16LE(48);
const namesIndex = elf.readUInt16LE(50);
const readSection = (index) => {
  const offset = sectionOffset + index * sectionSize;
  if (offset + 40 > elf.length) throw new Error('truncated section table');
  return {
    index,
    nameOffset: elf.readUInt32LE(offset),
    type: elf.readUInt32LE(offset + 4),
    flags: elf.readUInt32LE(offset + 8),
    offset: elf.readUInt32LE(offset + 16),
    size: elf.readUInt32LE(offset + 20),
    link: elf.readUInt32LE(offset + 24),
    info: elf.readUInt32LE(offset + 28),
    alignment: elf.readUInt32LE(offset + 32) || 1,
    entrySize: elf.readUInt32LE(offset + 36),
  };
};
const rawSections = Array.from({ length: sectionCount }, (_, index) => readSection(index));
const names = rawSections[namesIndex];
const namesData = elf.subarray(names.offset, names.offset + names.size);
const stringAt = (data, offset) => data.subarray(offset).toString().split('\0', 1)[0];
const sections = rawSections.map((value) => ({
  ...value,
  name: stringAt(namesData, value.nameOffset),
}));

/* The ARMlet entry must be byte zero. Helpers and immutable constants follow;
 * each receives a resource-relative address used while applying relocations. */
const included = sections.filter(({ size, name }) => size !== 0 &&
  (name === '.text.armlet' || (name.startsWith('.text.') && name !== '.text.armlet') ||
   name === '.text' || name.startsWith('.rodata')));
included.sort((left, right) => {
  const rank = ({ name }) => name === '.text.armlet' ? 0 : name.startsWith('.text') ? 1 : 2;
  return rank(left) - rank(right) || left.index - right.index;
});
if (included[0]?.name !== '.text.armlet') throw new Error('missing .text.armlet entry section');

const align = (value, boundary) => (value + boundary - 1) & ~(boundary - 1);
let bodySize = 0;
for (const section of included) {
  bodySize = align(bodySize, section.alignment);
  section.outputOffset = bodySize;
  bodySize += section.size;
}
const body = Buffer.alloc(bodySize);
for (const section of included) {
  const source = elf.subarray(section.offset, section.offset + section.size);
  if (source.length !== section.size) throw new Error(`truncated ${section.name}`);
  source.copy(body, section.outputOffset);
}
const includedByIndex = new Map(included.map((section) => [section.index, section]));

const symbolTable = sections.find(({ type }) => type === 2);
if (!symbolTable || symbolTable.entrySize !== 16) throw new Error('missing ELF32 symbol table');
const symbolNames = sections[symbolTable.link];
const symbolNameData = elf.subarray(symbolNames.offset, symbolNames.offset + symbolNames.size);
const symbolCount = symbolTable.size / symbolTable.entrySize;
const symbols = Array.from({ length: symbolCount }, (_, index) => {
  const offset = symbolTable.offset + index * 16;
  return {
    name: stringAt(symbolNameData, elf.readUInt32LE(offset)),
    value: elf.readUInt32LE(offset + 4),
    sectionIndex: elf.readUInt16LE(offset + 14),
  };
});

const symbolAddress = (symbol) => {
  const section = includedByIndex.get(symbol.sectionIndex);
  if (!section)
    throw new Error(`relocation references excluded or undefined symbol ${symbol.name || '<section>'}`);
  return section.outputOffset + symbol.value;
};
let relocationCount = 0;
for (const relocationSection of sections.filter(({ type }) => type === 9)) {
  const target = includedByIndex.get(relocationSection.info);
  if (!target) continue;
  if (relocationSection.entrySize !== 8)
    throw new Error(`unexpected relocation size in ${relocationSection.name}`);
  for (let entry = 0; entry < relocationSection.size; entry += 8) {
    const sourceOffset = relocationSection.offset + entry;
    const relocationOffset = elf.readUInt32LE(sourceOffset);
    const info = elf.readUInt32LE(sourceOffset + 4);
    const type = info & 0xff;
    const symbol = symbols[info >>> 8];
    const place = target.outputOffset + relocationOffset;
    const address = symbolAddress(symbol);
    if (place + 4 > body.length) throw new Error(`relocation outside ${target.name}`);
    if (type === 28 || type === 29) { // R_ARM_CALL / R_ARM_JUMP24
      const instruction = body.readUInt32LE(place);
      const displacement = address - place - 8;
      if ((displacement & 3) !== 0 || displacement < -0x02000000 || displacement >= 0x02000000)
        throw new Error(`ARM branch out of range for ${symbol.name}`);
      body.writeUInt32LE(((instruction & 0xff000000) |
        ((displacement >> 2) & 0x00ffffff)) >>> 0, place);
    } else if (type === 3) { // R_ARM_REL32: S + A - P
      const addend = body.readInt32LE(place);
      body.writeUInt32LE((address + addend - place) >>> 0, place);
    } else {
      throw new Error(`unsupported ARM relocation ${type} for ${symbol.name || '<section>'}`);
    }
    relocationCount++;
  }
}

writeFileSync(output, body);
console.log(`Linked ${body.length} bytes of position-independent ARM code (${relocationCount} relocations)`);
