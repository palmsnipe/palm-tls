/* Validate the compiler's instruction-set contract before packaging native
 * code. ARMv4T is shared by older TI/ARM9 devices and newer XScale devices. */
export function checkArmAttributes(elf, section) {
  if (!section) throw new Error('missing ARM build attributes');
  const bytes = elf.subarray(section.offset, section.offset + section.size);
  if (bytes.length !== section.size || bytes[0] !== 0x41)
    throw new Error('invalid ARM build attributes');
  let architecture, arm, fp = 0, simd = 0, wmmx = 0;
  const uleb = (cursor, end) => {
    let value = 0, shift = 0, byte;
    do {
      if (cursor.pos >= end || shift > 28) throw new Error('invalid ARM attribute integer');
      byte = bytes[cursor.pos++];
      value += (byte & 127) * 2 ** shift;
      shift += 7;
    } while (byte & 128);
    return value;
  };
  const string = (cursor, end) => {
    const start = cursor.pos;
    while (cursor.pos < end && bytes[cursor.pos]) cursor.pos++;
    if (cursor.pos >= end) throw new Error('unterminated ARM attribute string');
    return bytes.toString('ascii', start, cursor.pos++);
  };
  for (let vendor = 1; vendor < bytes.length;) {
    if (vendor + 4 > bytes.length) throw new Error('truncated ARM attribute vendor');
    const end = vendor + bytes.readUInt32LE(vendor);
    const cursor = { pos: vendor + 4 };
    if (end <= cursor.pos || end > bytes.length) throw new Error('invalid ARM attribute vendor');
    const name = string(cursor, end);
    if (name === 'aeabi') {
      while (cursor.pos < end) {
        const start = cursor.pos;
        const scope = uleb(cursor, end);
        if (cursor.pos + 4 > end) throw new Error('truncated ARM attribute scope');
        const scopeEnd = start + bytes.readUInt32LE(cursor.pos);
        cursor.pos += 4;
        if (scopeEnd < cursor.pos || scopeEnd > end) throw new Error('invalid ARM attribute scope');
        if (scope === 1) {
          while (cursor.pos < scopeEnd) {
            const tag = uleb(cursor, scopeEnd);
            if (tag === 4 || tag === 5 || (tag >= 32 && tag % 2)) {
              string(cursor, scopeEnd);
            } else {
              const value = uleb(cursor, scopeEnd);
              if (tag === 6) architecture = value;
              if (tag === 8) arm = value;
              if (tag === 10) fp = value;
              if (tag === 11) wmmx = value;
              if (tag === 12) simd = value;
              if (tag === 32) string(cursor, scopeEnd);
            }
          }
        }
        cursor.pos = scopeEnd;
      }
    }
    vendor = end;
  }
  // AEABI CPU architecture 2 is ARMv4T. Do not rely on the target triple:
  // -mcpu or function attributes can otherwise silently raise the minimum.
  if (architecture === undefined || architecture > 2 || arm !== 1 || fp || simd || wmmx)
    throw new Error('ARMlet requires instructions outside the ARMv4T integer baseline');
}
