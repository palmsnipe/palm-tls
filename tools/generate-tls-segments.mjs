import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const [elf, output, readelf = "m68k-none-elf-readelf"] = process.argv.slice(2);
if (!elf || !output) {
  throw new Error("usage: generate-tls-segments.mjs ELF OUTPUT [READELF]");
}

const sectionText = execFileSync(readelf, ["-SW", elf], { encoding: "utf8" });
const sections = new Map();
for (const line of sectionText.split("\n")) {
  const match = line.match(/^\s*\[\s*\d+\]\s+(\.tls(?:2|3|4a?|5))\s+\S+\s+([0-9a-fA-F]+)\s+\S+\s+([0-9a-fA-F]+)/);
  if (match) {
    sections.set(match[1], {
      address: Number.parseInt(match[2], 16),
      size: Number.parseInt(match[3], 16),
    });
  }
}
const segmentForSection = (name) => name === ".tls2" ? 0 : name === ".tls3" ? 1 : name === ".tls5" ? 3 : 2;
const hasFourthSegment = sections.has(".tls5");
const segmentCount = hasFourthSegment ? 4 : 3;
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
  const heading = line.match(/^Relocation section '(?:\.rela|\.rel)(\.tls(?:2|3|4a?|5))'/);
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
  const targetsEngine = target >= 0x11000000 && target < 0x14010000;
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
  entries.push({ segment, offset: address - segmentBases[segment] });
}

const unique = [...new Map(entries.map((entry) => [`${entry.segment}:${entry.offset}`, entry])).values()]
  .sort((a, b) => a.segment - b.segment || a.offset - b.offset);
if (unique.length > 0xffff) throw new Error("too many TLS relocations");

const data = Buffer.alloc(4 + unique.length * 6);
data.writeUInt16BE(1, 0);
data.writeUInt16BE(unique.length, 2);
unique.forEach((entry, index) => {
  const offset = 4 + index * 6;
  data.writeUInt16BE(entry.segment, offset);
  data.writeUInt32BE(entry.offset, offset + 2);
});
writeFileSync(output, data);
console.log(`Generated ${unique.length} relocations for ${segmentCount} TLS resources`);
