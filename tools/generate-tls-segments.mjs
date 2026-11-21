import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const [elf, output, readelf = "m68k-none-elf-readelf"] = process.argv.slice(2);
if (!elf || !output) {
  throw new Error("usage: generate-tls-segments.mjs ELF OUTPUT [READELF]");
}

const image = readFileSync(elf);
const sectionText = execFileSync(readelf, ["-SW", elf], { encoding: "utf8" });
const sections = new Map();
for (const line of sectionText.split("\n")) {
  const match = line.match(/^\s*\[\s*\d+\]\s+(\.tls(?:2|3|4a?|5|6))\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)/);
  if (match) {
    sections.set(match[1], {
      address: Number.parseInt(match[2], 16),
      fileOffset: Number.parseInt(match[3], 16),
      size: Number.parseInt(match[4], 16),
    });
  }
}
const segmentForSection = (name) => Number(name[4]) - 2;
const hasFourthSegment = sections.has(".tls5");
const hasFifthSegment = sections.has(".tls6");
const segmentCount = hasFifthSegment ? 5 : hasFourthSegment ? 4 : 3;
const segmentBases = Array(segmentCount).fill(Infinity);
const segmentEnds = Array(segmentCount).fill(0);
for (const [name, section] of sections) {
  const segment = segmentForSection(name);
  segmentBases[segment] = Math.min(segmentBases[segment], section.address);
  segmentEnds[segment] = Math.max(segmentEnds[segment], section.address + section.size);
}

const requiredSections = hasFourthSegment
  ? [".tls2", ".tls3", ".tls4a", ".tls5"]
  : [".tls2", ".tls3", ".tls4"];
if (hasFifthSegment) requiredSections.push(".tls6");
for (const name of requiredSections) {
  if (!sections.has(name)) throw new Error(`missing ${name} in ${elf}`);
}
for (let segment = 0; segment < segmentBases.length; segment++) {
  const size = segmentEnds[segment] - segmentBases[segment];
  if (size > 65000)
    throw new Error(`TLS segment ${segment + 2} is ${size} bytes; Palm resources must remain below 65000`);
}

const relocText = execFileSync(readelf, ["-rW", elf], { encoding: "utf8" });
let current = null;
const entries = [];
for (const line of relocText.split("\n")) {
  const heading = line.match(/^Relocation section '(?:\.rela|\.rel)(\.tls(?:2|3|4a?|5|6))'/);
  if (heading) {
    current = heading[1];
    continue;
  }
  if (line.startsWith("Relocation section ")) {
    current = null;
    continue;
  }
  if (!current || !line.includes("R_68K_32")) continue;
  const match = line.trim().match(/^([0-9a-fA-F]+)/);
  if (!match) continue;
  const targetMatch = line.trim().match(
    /^[0-9a-fA-F]+\s+\S+\s+R_68K_32\s+([0-9a-fA-F]+)/);
  if (!targetMatch) throw new Error(`cannot parse TLS relocation target: ${line.trim()}`);
  const target = Number.parseInt(targetMatch[1], 16);
  const topBank = hasFifthSegment ? 0x15010000 : 0x14010000;
  const targetsEngine = target >= 0x11000000 && target < topBank;
  if (hasFourthSegment && !targetsEngine) {
    throw new Error(
      `TLS relocation targets non-engine address 0x${target.toString(16)}: ${line.trim()}`,
    );
  }
  const section = sections.get(current);
  const address = Number.parseInt(match[1], 16);
  if (address < section.address || address + 4 > section.address + section.size) {
    throw new Error(`relocation outside ${current}: ${line.trim()}`);
  }
  const segment = segmentForSection(current);
  const offset = address - segmentBases[segment];
  if (offset & 1) throw new Error(`unaligned relocation in ${current}: ${offset}`);
  // The final linked word includes the ELF addend. The symbol alone can
  // identify a different bank or an absolute value that needs no relocation.
  const linked = image.readUInt32BE(section.fileOffset + address - section.address);
  const targetBank = segmentBases.findIndex(base => linked >= base && linked - base < 0x10000);
  if (targetBank >= 0) entries.push({ segment, offset, targetBank });
}

const unique = [...new Map(entries.map(entry => [`${entry.segment}:${entry.offset}`, entry])).values()]
  .sort((a, b) => a.segment - b.segment || a.offset - b.offset);
// V2 stores a word count, followed by [source, payload words] blocks.
// Each payload holds [target, count, halfword offsets...] groups.
const words = [];
for (let source = 0; source < segmentCount; source++) {
  const offsets = Array.from({ length: segmentCount }, () => []);
  let last = -4;
  for (const entry of unique.filter(entry => entry.segment === source)) {
    if (entry.offset < last + 4) throw new Error(`overlapping relocation in bank ${source}`);
    offsets[entry.targetBank].push(entry.offset / 2);
    last = entry.offset;
  }
  const payload = [];
  offsets.forEach((group, target) => {
    if (group.length) payload.push(target, group.length, ...group);
  });
  if (payload.length) words.push(source, payload.length, ...payload);
}
if (words.length > 0xffff) throw new Error("relocation table too large");
const data = Buffer.alloc(4 + 2 * words.length);
data.writeUInt16BE(2, 0);
data.writeUInt16BE(words.length, 2);
words.forEach((word, i) => data.writeUInt16BE(word, 4 + 2 * i));
writeFileSync(output, data);
console.log(`Generated ${unique.length} relocations for ${segmentCount} TLS resources`);
