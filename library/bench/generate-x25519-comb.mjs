// SPDX-License-Identifier: GPL-3.0-or-later
import { writeFileSync } from 'node:fs';

// Edwards25519 affine base point and parameter from RFC 7748 §4.1.
const prime = (1n << 255n) - 19n;
const d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const base = [
    15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    46316835694926478169428394003475163141307993866256225615783033603165251855960n,
];
const identity = [0n, 1n];
const width = Number(process.argv[3] ?? 6);
if (!Number.isInteger(width) || width < 2 || width > 7) throw new Error('invalid comb width');
const rows = Math.ceil(255 / width);
const mod = value => ((value % prime) + prime) % prime;

function inverse(value) {
    let result = 1n;
    for (let exponent = prime - 2n; exponent; exponent >>= 1n) {
        if (exponent & 1n) result = mod(result * value);
        value = mod(value * value);
    }
    return result;
}

function add([x1, y1], [x2, y2]) {
    const product = mod(d * x1 * x2 * y1 * y2);
    return [
        mod((x1 * y2 + x2 * y1) * inverse(1n + product)),
        mod((y1 * y2 + x1 * x2) * inverse(1n - product)),
    ];
}

if (mod((1n + base[1]) * inverse(1n - base[1])) !== 9n)
    throw new Error('Edwards base point does not map to the X25519 base point');

const teeth = [base];
for (let tooth = 1; tooth < width; tooth++) {
    let point = teeth[tooth - 1];
    for (let row = 0; row < rows; row++) point = add(point, point);
    teeth.push(point);
}

function limbs(value) {
    const words = Array.from({ length: 16 }, (_, i) =>
        '0x' + ((value >> BigInt(16 * i)) & 0xffffn).toString(16).padStart(4, '0'));
    return '{{' + words.join(', ') + '}}';
}

const table = [identity];
for (let digit = 1; digit < (1 << width); digit++) {
    const bit = digit & -digit;
    table.push(add(table[digit ^ bit], teeth[Math.log2(bit)]));
}
const entries = table.map(([x, y]) => {
    return [mod(y + x), mod(y - x), mod(2n * d * x * y)].map(limbs).join(',\n        ');
});
writeFileSync(process.argv[2], `/* Generated Edwards25519 fixed-base comb, including the identity. */
enum { COMB_WIDTH = ${width}, COMB_ROWS = ${rows} };
static const AffineNiels kComb[1 << COMB_WIDTH] = {
    {
        ${entries.join('\n    },\n    {\n        ')}
    },
};
`);
