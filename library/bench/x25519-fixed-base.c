/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "x25519-fixed-base.h"
#include <string.h>

typedef uint16_t u16;
typedef uint32_t u32;

enum { LIMBS = 16 };
typedef struct { u16 limb[LIMBS]; } Field;
typedef struct { Field plus, minus, xy2d; } AffineNiels;
typedef struct { Field x, y, z, t; } EdwardsPoint;

#include "x25519_comb.inc"

static const Field kPrime = {{
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff
}};

/* Like the P-256 private field path, use two 68000 MULU instructions
 * whose source words have a total of 16 set bits. */
static inline __attribute__((always_inline)) u32 MultiplyWord(u16 left, u16 right)
{
#ifdef __m68k__
    u32 result = left, padding = left;
    u16 complement = (u16)~right;
    __asm__ volatile(
        "mulu.w %[right],%[result]\n\t"
        "mulu.w %[complement],%[padding]"
        : [result] "+&d"(result), [padding] "+&d"(padding)
        : [right] "d"(right), [complement] "d"(complement) : "cc");
    return result;
#else
    return (u32)left * right;
#endif
}

static inline __attribute__((always_inline)) void Accumulate(u32 *low, u16 *high, u32 product)
{
#ifdef __m68k__
    __asm__("add.l %[product],%[low]\n\taddx.w %[zero],%[high]"
        : [low] "+&d"(*low), [high] "+&d"(*high)
        : [product] "d"(product), [zero] "d"((u16)0) : "cc");
#else
    u32 sum = *low + product;
    *high += (u16)(sum < *low);
    *low = sum;
#endif
}

/* Internal field elements occupy 256 bits. Fold carries at bit 256 using
 * 2^256 = 38 (mod p). The second pass handles at most one carry or borrow.
 * If the first pass wrapped, its new value is within 1444 of the other
 * end of the range, so the second pass cannot wrap again. */
static u16 AddWord(Field *out, u32 carry)
{
    for (unsigned i = 0; i < LIMBS; i++) {
        carry += out->limb[i];
        out->limb[i] = (u16)carry;
        carry >>= 16;
    }
    return (u16)carry;
}

static u16 SubtractWord(Field *out, u32 borrow)
{
    for (unsigned i = 0; i < LIMBS; i++) {
        u32 word = (u32)out->limb[i] - borrow;
        out->limb[i] = (u16)word;
        borrow = word >> 31;
    }
    return (u16)borrow;
}

static void FoldCarry(Field *out, u16 carry)
{
    carry = AddWord(out, 38U * carry);
    AddWord(out, 38U * carry);
}

static void FieldAdd(Field *out, const Field *left, const Field *right)
{
    u32 carry = 0;
    for (unsigned i = 0; i < LIMBS; i++) {
        u32 word = (u32)left->limb[i] + right->limb[i] + carry;
        out->limb[i] = (u16)word;
        carry = word >> 16;
    }
    FoldCarry(out, (u16)carry);
}

static void FieldSubtract(Field *out, const Field *left, const Field *right)
{
    u32 borrow = 0;
    for (unsigned i = 0; i < LIMBS; i++) {
        u32 word = (u32)left->limb[i] - right->limb[i] - borrow;
        out->limb[i] = (u16)word;
        borrow = word >> 31;
    }
    borrow = SubtractWord(out, 38U * borrow);
    SubtractWord(out, 38U * borrow);
}

static void ReduceProduct(Field *out, const u16 product[2 * LIMBS])
{
    u32 carry = 0;
    for (unsigned i = 0; i < LIMBS; i++) {
        u32 word = (u32)product[i] + 38UL * product[i + LIMBS] + carry;
        out->limb[i] = (u16)word;
        carry = word >> 16;
    }
    FoldCarry(out, (u16)carry);
}

static void FieldMultiply(Field *out, const Field *left, const Field *right)
{
    u16 product[2 * LIMBS] = {0};
    for (unsigned i = 0; i < LIMBS; i++) {
        u32 carry = 0;
        for (unsigned j = 0; j < LIMBS; j++) {
            u32 word = MultiplyWord(left->limb[i], right->limb[j]) + product[i + j] + carry;
            product[i + j] = (u16)word;
            carry = word >> 16;
        }
        product[i + LIMBS] = (u16)carry;
    }
    ReduceProduct(out, product);
}

static void FieldSquare(Field *out, const Field *value)
{
    u16 product[2 * LIMBS];
    u32 low = 0;
    for (unsigned column = 0; column < 2 * LIMBS - 1; column++) {
        u16 high = 0;
        unsigned first = column < LIMBS ? 0 : column - (LIMBS - 1);
        for (unsigned i = first; i < column - i; i++) {
            u32 word = MultiplyWord(value->limb[i], value->limb[column - i]);
            Accumulate(&low, &high, word);
            Accumulate(&low, &high, word);
        }
        if ((column & 1U) == 0) {
            u16 diagonal = value->limb[column / 2];
            Accumulate(&low, &high, MultiplyWord(diagonal, diagonal));
        }
        product[column] = (u16)low;
        low = (low >> 16) | ((u32)high << 16);
    }
    product[2 * LIMBS - 1] = (u16)low;
    ReduceProduct(out, product);
}

static void SquareTimes(Field *out, const Field *in, unsigned count)
{
    FieldSquare(out, in);
    for (unsigned i = 1; i < count; i++) FieldSquare(out, out);
}

static void FieldInvert(Field *out, const Field *value)
{
    Field a, b, c, d;
    FieldSquare(&a, value);
    SquareTimes(&b, &a, 2);
    FieldMultiply(&b, &b, value);
    FieldMultiply(&a, &a, &b);         /* z^11 */
    FieldSquare(&c, &a);
    FieldMultiply(&b, &b, &c);         /* z^(2^5-1) */
    SquareTimes(&c, &b, 5);
    FieldMultiply(&b, &c, &b);         /* z^(2^10-1) */
    SquareTimes(&c, &b, 10);
    FieldMultiply(&c, &c, &b);         /* z^(2^20-1) */
    SquareTimes(&d, &c, 20);
    FieldMultiply(&c, &d, &c);
    SquareTimes(&c, &c, 10);
    FieldMultiply(&b, &c, &b);         /* z^(2^50-1) */
    SquareTimes(&c, &b, 50);
    FieldMultiply(&c, &c, &b);
    SquareTimes(&d, &c, 100);
    FieldMultiply(&c, &d, &c);
    SquareTimes(&c, &c, 50);
    FieldMultiply(&b, &c, &b);         /* z^(2^250-1) */
    SquareTimes(&b, &b, 5);
    FieldMultiply(out, &b, &a);        /* z^(2^255-21) */
}

static void DecodeField(Field *out, const uint8_t input[32])
{
    for (unsigned i = 0; i < LIMBS; i++)
        out->limb[i] = input[2 * i] | ((u16)input[2 * i + 1] << 8);
}

static void EncodeField(uint8_t output[32], Field *value)
{
    /* Two folds at bit 255 leave a value below 2^255, then subtract p once. */
    for (unsigned i = 0; i < 2; i++) {
        u16 high = value->limb[LIMBS - 1] >> 15;
        value->limb[LIMBS - 1] &= 0x7fff;
        AddWord(value, 19U * high);
    }
    Field reduced;
    u32 borrow = 0;
    for (unsigned i = 0; i < LIMBS; i++) {
        u32 word = (u32)value->limb[i] - kPrime.limb[i] - borrow;
        reduced.limb[i] = (u16)word;
        borrow = word >> 31;
    }
    u16 keep = (u16)(0U - borrow);
    for (unsigned i = 0; i < LIMBS; i++) {
        u16 word = (value->limb[i] & keep) | (reduced.limb[i] & (u16)~keep);
        output[2 * i] = (uint8_t)word;
        output[2 * i + 1] = (uint8_t)(word >> 8);
    }
}

/* RFC 8032 §5.1.4 doubling for a = -1. */
static void Double(EdwardsPoint *point)
{
    Field a, b, c, e, f, g, h;
    FieldSquare(&a, &point->x);
    FieldSquare(&b, &point->y);
    FieldSquare(&c, &point->z);
    FieldAdd(&c, &c, &c);
    FieldAdd(&e, &point->x, &point->y);
    FieldSquare(&e, &e);
    FieldAdd(&h, &a, &b);
    FieldSubtract(&e, &e, &h);
    static const Field zero = {{0}};
    FieldSubtract(&h, &zero, &h);
    FieldSubtract(&g, &b, &a);
    FieldSubtract(&f, &g, &c);
    FieldMultiply(&point->x, &e, &f);
    FieldMultiply(&point->y, &g, &h);
    FieldMultiply(&point->z, &f, &g);
    FieldMultiply(&point->t, &e, &h);
}

/* RFC 8032 §5.1.4 addition with the affine point's terms precomputed. T is
 * next used after doubling, so computing it here would be redundant. */
static void AddMixed(EdwardsPoint *point, const AffineNiels *q)
{
    Field a, b, c, d, e, f, g, h;
    FieldSubtract(&a, &point->y, &point->x);
    FieldMultiply(&a, &a, &q->minus);
    FieldAdd(&b, &point->y, &point->x);
    FieldMultiply(&b, &b, &q->plus);
    FieldMultiply(&c, &point->t, &q->xy2d);
    FieldAdd(&d, &point->z, &point->z);
    FieldSubtract(&e, &b, &a);
    FieldSubtract(&f, &d, &c);
    FieldAdd(&g, &d, &c);
    FieldAdd(&h, &b, &a);
    FieldMultiply(&point->x, &e, &f);
    FieldMultiply(&point->y, &g, &h);
    FieldMultiply(&point->z, &f, &g);
}

static void Select(AffineNiels *out, u16 digit)
{
    /* Volatile loads keep the whole table scan, even for the identity. */
    const volatile AffineNiels *table = kComb;
    memset(out, 0, sizeof(*out));
    for (u16 row = 0; row < (1U << COMB_WIDTH); row++) {
        u16 difference = row ^ digit;
        u16 mask = (u16)(((u16)(difference | (u16)(0U - difference)) >> 15) - 1U);
        for (unsigned i = 0; i < LIMBS; i++) {
            out->plus.limb[i] |= table[row].plus.limb[i] & mask;
            out->minus.limb[i] |= table[row].minus.limb[i] & mask;
            out->xy2d.limb[i] |= table[row].xy2d.limb[i] & mask;
        }
    }
}

void PalmTlsX25519FixedBase(uint8_t output[32], const uint8_t scalar[32],
    const uint8_t projectiveScale[32])
{
    struct {
        uint8_t scalar[32];
        EdwardsPoint point;
        AffineNiels addend;
    } work = {0};

    memcpy(work.scalar, scalar, sizeof(work.scalar));
    work.scalar[0] &= 248;
    work.scalar[31] = (work.scalar[31] & 127) | 64;
    /* Start at the Edwards identity scaled by the supplied randomizer. */
    DecodeField(&work.point.z, projectiveScale);
    work.point.y = work.point.z;
    for (int row = COMB_ROWS - 1; row >= 0; row--) {
        u16 digit = 0;
        for (unsigned tooth = 0; tooth < COMB_WIDTH; tooth++) {
            unsigned bit = (unsigned)row + tooth * COMB_ROWS;
            if (bit < 255)
                digit |= ((work.scalar[bit / 8] >> (bit % 8)) & 1U) << tooth;
        }
        Double(&work.point);
        Select(&work.addend, digit);
        AddMixed(&work.point, &work.addend);
    }

    /* Convert Edwards y = Y/Z to the Montgomery u = (Z+Y)/(Z-Y). */
    FieldSubtract(&work.point.x, &work.point.z, &work.point.y);
    FieldInvert(&work.point.x, &work.point.x);
    FieldAdd(&work.point.y, &work.point.z, &work.point.y);
    FieldMultiply(&work.point.y, &work.point.y, &work.point.x);
    EncodeField(output, &work.point.y);

    volatile uint8_t *bytes = (volatile uint8_t *)&work;
    for (unsigned i = 0; i < sizeof(work); i++) bytes[i] = 0;
}
