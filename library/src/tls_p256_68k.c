/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/ecc.h>

typedef uint16_t u16;
typedef uint32_t u32;

enum { FIELD_LIMBS = 16 };
typedef struct { u16 v[FIELD_LIMBS]; } Fe256;
typedef struct { Fe256 x, y; } Affine256;
typedef struct { Fe256 x, y, z; } Point256;

_Static_assert(sizeof(mp_digit) == 2 && FP_SIZE >= FIELD_LIMBS,
    "fixed-base P-256 requires the 16-bit TFM layout");

#include "p256_comb_68k.inc"

static const Fe256 kPrime = {{
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0,
    0, 0, 0, 0, 1, 0, 0xffff, 0xffff
}};
static const Fe256 kOne = {{1}};

static void FeCopy(Fe256 *out, const Fe256 *value)
{
    *out = *value;
}

static u16 IsZero(u16 value)
{
    return (u16)(((u16)(value | (u16)(0U - value)) >> 15) ^ 1U);
}

static u16 FeIsZero(const Fe256 *value)
{
    u16 combined = 0;
    for (unsigned i = 0; i < FIELD_LIMBS; ++i)
        combined |= value->v[i];
    return IsZero(combined);
}

/* Subtract p and select the canonical value from an input below 2p. */
static void FeReduce(Fe256 *out, const u16 *input, u16 high)
{
    Fe256 reduced;
    u32 borrow = 0;
    for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
        u32 word = (u32)input[i] - kPrime.v[i] - borrow;
        reduced.v[i] = (u16)word;
        borrow = word >> 31;
    }
    u16 keep = (u16)(0U - (borrow & (high ^ 1U)));
    for (unsigned i = 0; i < FIELD_LIMBS; ++i)
        out->v[i] = (input[i] & keep) | (reduced.v[i] & (u16)~keep);
}

static void FeAdd(Fe256 *out, const Fe256 *left, const Fe256 *right)
{
    u32 carry = 0;
    for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
        u32 word = (u32)left->v[i] + right->v[i] + carry;
        out->v[i] = (u16)word;
        carry = word >> 16;
    }
    FeReduce(out, out->v, (u16)carry);
}

static void FeSubtract(Fe256 *out, const Fe256 *left, const Fe256 *right)
{
    u32 borrow = 0;
    for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
        u32 word = (u32)left->v[i] - right->v[i] - borrow;
        out->v[i] = (u16)word;
        borrow = word >> 31;
    }
    u16 mask = (u16)(0U - borrow);
    u32 carry = 0;
    for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
        u32 word = (u32)out->v[i] + (kPrime.v[i] & mask) + carry;
        out->v[i] = (u16)word;
        carry = word >> 16;
    }
}

/* A 68000 word multiply takes longer for each set bit of the source.
 * Multiplying its complement brings the combined set-bit count to 16. */
static inline __attribute__((always_inline)) u32 MultiplyWord(u16 left, u16 right)
{
    u16 complement = (u16)~right;
    u32 product = left;
    u32 padding = left;
    __asm__ volatile(
        "mulu.w %[right],%[product]\n\t"
        "mulu.w %[complement],%[padding]"
        : [product] "+&d"(product), [padding] "+&d"(padding)
        : [right] "d"(right), [complement] "d"(complement) : "cc");
    return product;
}

/* For radix R=2^256, p=R-2^224+2^192+2^96-1. The current low word m
 * cancels against -m. Apply the two positive terms, the negative term,
 * and finally add the high word using a fixed count for each row. */
static void FeMontgomeryReduce(Fe256 *out, u16 *product)
{
    for (unsigned row = 0; row < FIELD_LIMBS; ++row) {
        u16 *t = product + row;
        u32 m = t[0];
        u32 sum = (u32)t[6] + m;
        t[6] = (u16)sum;
        for (unsigned i = 7; i < 12; ++i) {
            sum = (u32)t[i] + (sum >> 16);
            t[i] = (u16)sum;
        }
        sum = (u32)t[12] + m + (sum >> 16);
        t[12] = (u16)sum;
        sum = (u32)t[13] + (sum >> 16);
        t[13] = (u16)sum;
        u32 difference = (u32)t[14] + (sum >> 16) - m;
        t[14] = (u16)difference;
        difference = (u32)t[15] - (difference >> 31);
        t[15] = (u16)difference;
        u32 carry = m - (difference >> 31);
        for (unsigned i = row + FIELD_LIMBS; i <= 2 * FIELD_LIMBS; ++i) {
            sum = (u32)product[i] + carry;
            product[i] = (u16)sum;
            carry = sum >> 16;
        }
    }
    FeReduce(out, product + FIELD_LIMBS, product[2 * FIELD_LIMBS]);
}

static void FeMultiply(Fe256 *out, const Fe256 *left, const Fe256 *right)
{
    u16 product[2 * FIELD_LIMBS + 1] = {0};
    for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
        u32 carry = 0;
        for (unsigned j = 0; j < FIELD_LIMBS; ++j) {
            u32 word = MultiplyWord(left->v[i], right->v[j]) + product[i+j] + carry;
            product[i+j] = (u16)word;
            carry = word >> 16;
        }
        product[i + FIELD_LIMBS] = (u16)carry;
    }
    FeMontgomeryReduce(out, product);
}

/* Off-diagonal terms occur twice in the square. Accumulate each once
 * using the low 32 bits and an extend word, then add the diagonal. */
static void FeSquare(Fe256 *out, const Fe256 *value)
{
    u16 product[2 * FIELD_LIMBS + 1];
    u32 low = 0;
    u16 high = 0;
    for (unsigned column = 0; column < 2 * FIELD_LIMBS - 1; ++column) {
        unsigned first = column < FIELD_LIMBS ? 0 : column - (FIELD_LIMBS - 1);
        for (unsigned i = first; i < column - i; ++i) {
            u32 word = MultiplyWord(value->v[i], value->v[column - i]);
            __asm__(
                "add.l %[word],%[low]\n\t"
                "addx.w %[zero],%[high]\n\t"
                "add.l %[word],%[low]\n\t"
                "addx.w %[zero],%[high]"
                : [low] "+&d"(low), [high] "+&d"(high)
                : [word] "d"(word), [zero] "d"((u16)0) : "cc");
        }
        if ((column & 1U) == 0) {
            u16 limb = value->v[column / 2];
            u32 word = MultiplyWord(limb, limb);
            __asm__("add.l %[word],%[low]\n\taddx.w %[zero],%[high]"
                : [low] "+&d"(low), [high] "+&d"(high)
                : [word] "d"(word), [zero] "d"((u16)0) : "cc");
        }
        product[column] = (u16)low;
        low = (low >> 16) | ((u32)high << 16);
        high = 0;
    }
    product[2 * FIELD_LIMBS - 1] = (u16)low;
    product[2 * FIELD_LIMBS] = 0;
    FeMontgomeryReduce(out, product);
}

#include "p256_inverse.inc"

/* Double in Jacobian coordinates for a=-3. The output can alias the input. */
static void PointDouble(Point256 *point)
{
    Fe256 delta, gamma, beta, alpha, temporary;
    FeSquare(&delta, &point->z);
    FeSquare(&gamma, &point->y);
    FeMultiply(&beta, &point->x, &gamma);
    FeSubtract(&temporary, &point->x, &delta);
    FeAdd(&delta, &point->x, &delta);
    FeMultiply(&temporary, &temporary, &delta);
    FeAdd(&alpha, &temporary, &temporary);
    FeAdd(&alpha, &alpha, &temporary);

    /* Z' = 2YZ, X' = alpha^2 - 8 beta, Y' = alpha(4 beta - X') - 8 gamma^2. */
    FeMultiply(&point->z, &point->y, &point->z);
    FeAdd(&point->z, &point->z, &point->z);
    FeAdd(&beta, &beta, &beta);
    FeAdd(&beta, &beta, &beta);
    FeSquare(&point->x, &alpha);
    FeSubtract(&point->x, &point->x, &beta);
    FeSubtract(&point->x, &point->x, &beta);
    FeSubtract(&temporary, &beta, &point->x);
    FeMultiply(&point->y, &alpha, &temporary);
    FeSquare(&temporary, &gamma);
    for (unsigned i = 0; i < 3; ++i)
        FeAdd(&temporary, &temporary, &temporary);
    FeSubtract(&point->y, &point->y, &temporary);
}

static void SelectMixed(Fe256 *out, const volatile Fe256 *sum,
    const volatile Fe256 *initial, u16 keep, u16 add, u16 start)
{
    for (unsigned i = 0; i < FIELD_LIMBS; ++i)
        out->v[i] = (out->v[i] & keep) | (sum->v[i] & add) | (initial->v[i] & start);
}

/* Mixed affine/Jacobian addition. The comb's processed bits and the new
 * digit occupy disjoint positions, and their sum is below the group order.
 * Finite operands of a real addition can therefore neither match nor cancel.
 * Select a blinded affine representation when starting from infinity. */
static void PointAddComb(Point256 *point, const Affine256 *affine, u16 apply,
    const Fe256 *blind, const Fe256 *blind2, const Fe256 *blind3)
{
    Point256 sum;
    Fe256 z2, h, r, h2, h3, v, temporary;
    u16 start = (u16)(0U - (apply & FeIsZero(&point->z)));
    u16 keep = (u16)(apply - 1U);
    u16 add = (u16)~(keep | start);
    FeSquare(&z2, &point->z);
    FeMultiply(&h, &affine->x, &z2);
    FeMultiply(&temporary, &point->z, &z2);
    FeMultiply(&r, &affine->y, &temporary);
    FeSubtract(&h, &h, &point->x);
    FeSubtract(&r, &r, &point->y);
    FeSquare(&h2, &h);
    FeMultiply(&h3, &h, &h2);
    FeMultiply(&v, &point->x, &h2);
    FeSquare(&sum.x, &r);
    FeSubtract(&sum.x, &sum.x, &h3);
    FeSubtract(&sum.x, &sum.x, &v);
    FeSubtract(&sum.x, &sum.x, &v);
    FeSubtract(&temporary, &v, &sum.x);
    FeMultiply(&sum.y, &r, &temporary);
    FeMultiply(&temporary, &point->y, &h3);
    FeSubtract(&sum.y, &sum.y, &temporary);
    FeMultiply(&sum.z, &point->z, &h);

    FeMultiply(&h, &affine->x, blind2);
    FeMultiply(&r, &affine->y, blind3);
    SelectMixed(&point->x, &sum.x, &h, keep, add, start);
    SelectMixed(&point->y, &sum.y, &r, keep, add, start);
    SelectMixed(&point->z, &sum.z, blind, keep, add, start);
}

static void SelectGenerator(Affine256 *selected, u16 digit)
{
    const volatile Affine256 *table = kGeneratorComb;
    memset(selected, 0, sizeof(*selected));
    digit |= IsZero(digit); /* G is the dummy operand for digit zero. */
    for (u16 row = 1; row <= P256_COMB_DIGITS; ++row) {
        u16 mask = (u16)(0U - IsZero(row ^ digit));
        for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
            selected->x.v[i] |= table[row - 1].x.v[i] & mask;
            selected->y.v[i] |= table[row - 1].y.v[i] & mask;
        }
    }
}

static void StoreCoordinate(mp_int *out, const Fe256 *value)
{
    u16 used = 0;
    memset(out, 0, sizeof(*out));
    for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
        out->dp[i] = value->v[i];
        u16 mask = (u16)(IsZero(value->v[i]) - 1U);
        used ^= (used ^ (i + 1)) & mask;
    }
    out->used = (int)used;
}

/* wolfSSL supplies a scalar in [1,n-1] and a random nonzero field element.
 * The caller may supply pub->z as the blinding input. */
void PalmTlsP256MakePublic(const mp_int *scalar, const mp_int *randomizer,
    ecc_point *pub)
{
    struct {
        Point256 point;
        Affine256 selected;
        Fe256 blind, squared, cubed, inverse;
    } work;

    memset(&work.point, 0, sizeof(work.point));
    for (unsigned i = 0; i < FIELD_LIMBS; ++i)
        work.blind.v[i] = randomizer->dp[i];
    FeMultiply(&work.blind, &work.blind, &kMontgomerySquare);
    FeSquare(&work.squared, &work.blind);
    FeMultiply(&work.cubed, &work.squared, &work.blind);

    for (int window = P256_COMB_WINDOWS - 1; window >= 0; --window) {
        u16 digit = 0;
        for (unsigned tooth = 0; tooth < P256_COMB_WIDTH; ++tooth) {
            unsigned bit = (unsigned)window + tooth * P256_COMB_WINDOWS;
            if (bit < 256)
                digit |= ((scalar->dp[bit / 16] >> (bit % 16)) & 1U) << tooth;
        }
        PointDouble(&work.point);
        SelectGenerator(&work.selected, digit);
        PointAddComb(&work.point, &work.selected, IsZero(digit) ^ 1U,
            &work.blind, &work.squared, &work.cubed);
    }

    FeInverse(&work.inverse, &work.point.z);
    FeSquare(&work.squared, &work.inverse);
    FeMultiply(&work.cubed, &work.squared, &work.inverse);
    FeMultiply(&work.point.x, &work.point.x, &work.squared);
    FeMultiply(&work.point.y, &work.point.y, &work.cubed);
    FeMultiply(&work.point.x, &work.point.x, &kOne);
    FeMultiply(&work.point.y, &work.point.y, &kOne);
    StoreCoordinate(pub->x, &work.point.x);
    StoreCoordinate(pub->y, &work.point.y);
    StoreCoordinate(pub->z, &kOne);

    volatile unsigned char *scratch = (volatile unsigned char *)&work;
    for (unsigned i = 0; i < sizeof(work); ++i)
        scratch[i] = 0;
}
