/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "tls_handshake_profile.h"

typedef mp_digit u16;
typedef uint32_t u32;

enum { FIELD_LIMBS = 16 };
typedef struct { u16 v[FIELD_LIMBS]; } Fe256;
typedef struct { Fe256 x, y; } Affine256;
typedef struct { Fe256 x, y, z; } Point256;
typedef struct { Fe256 z, z2, z3; } ProjectiveScale;

_Static_assert(sizeof(mp_digit) == 2 && FP_SIZE >= FIELD_LIMBS,
    "fixed-base P-256 requires the 16-bit TFM layout");

#include "p256_comb_68k.inc"

static const Fe256 kPrime = {{
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0,
    0, 0, 0, 0, 1, 0, 0xffff, 0xffff
}};
static const Fe256 kOne = {{1}};
static const Fe256 kMontgomeryOne = {{
    1, 0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xfffe, 0xffff, 0, 0
}};
/* The coefficient b in Montgomery form. */
static const Fe256 kCurveB = {{
    0xbddf, 0x29c4, 0xdf62, 0xd89c, 0x3090, 0x7884, 0x05cd, 0xacf0,
    0x2ed6, 0xf721, 0x20ab, 0xe5a2, 0x4834, 0x0487, 0x061d, 0xdc30
}};

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

/* For radix R=2^256, p=R-2^224+2^192+2^96-1. The low word m
 * cancels against -m. Add the terms at words 6 and 12, subtract the
 * term at word 14, and return the contribution at word 16. */
static inline __attribute__((always_inline)) u16 CancelMontgomeryWord(u16 *row)
{
    u16 m = row[0];
    u16 *next = row + 7;
    u16 carry = 0;
    u16 word;
    u32 tail;

    __asm__ volatile(
        "add.w %[m],-2(%[next])\n\t"
        ".rept 5\n\t"
        "move.w (%[next]),%[word]\n\t"
        "addx.w %[carry],%[word]\n\t"
        "move.w %[word],(%[next])+\n\t"
        ".endr\n\t"
        "move.w (%[next]),%[word]\n\t"
        "addx.w %[m],%[word]\n\t"
        "move.w %[word],(%[next])+\n\t"
        "move.w (%[next]),%[word]\n\t"
        "addx.w %[carry],%[word]\n\t"
        "move.w %[word],(%[next])\n\t"
        "addx.w %[carry],%[carry]"
        : [next] "+&a"(next), [carry] "+&d"(carry), [word] "=&d"(word)
        : [m] "d"(m) : "cc", "memory");

    /* A carry from the positive terms implies m is nonzero. The last
     * two limbs fit in one long after swapping their order. */
    u32 amount = (u32)(m - carry);
    __asm__ volatile(
        "move.l 28(%[row]),%[tail]\n\t"
        "swap %[tail]\n\t"
        "sub.l %[amount],%[tail]\n\t"
        "subx.w %[zero],%[m]\n\t"
        "swap %[tail]\n\t"
        "move.l %[tail],28(%[row])"
        : [tail] "=&d"(tail), [m] "+&d"(m)
        : [row] "a"(row), [amount] "d"(amount), [zero] "d"((u16)0)
        : "cc", "memory");
    return m;
}

static void FeMontgomeryReduce(Fe256 *out, u16 *product)
{
    for (unsigned row = 0; row < FIELD_LIMBS; ++row) {
        u16 carry = CancelMontgomeryWord(product + row);
        u16 *next = product + row + FIELD_LIMBS;
        u16 count = FIELD_LIMBS - row - 1;
        u16 word;
        /* Propagate through the entire public suffix. MOVE and DBRA
         * preserve X between words of the addition. */
        __asm__ volatile(
            "add.w %[carry],(%[next])+\n\t"
            "1: move.w (%[next]),%[word]\n\t"
            "addx.w %[zero],%[word]\n\t"
            "move.w %[word],(%[next])+\n\t"
            "dbra %[count],1b"
            : [next] "+&a"(next), [count] "+&d"(count), [word] "=&d"(word)
            : [carry] "d"(carry), [zero] "d"((u16)0) : "cc", "memory");
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

/* Mixed affine/Jacobian sum for distinct, non-opposite finite points.
 * The masked caller also runs the formula when handling zero digits. */
static void PointMixedSum(Point256 *sum, const Point256 *point,
    const Affine256 *affine)
{
    Fe256 z2, h, r, h2, h3, v, temporary;
    FeSquare(&z2, &point->z);
    FeMultiply(&h, &affine->x, &z2);
    FeMultiply(&temporary, &point->z, &z2);
    FeMultiply(&r, &affine->y, &temporary);
    FeSubtract(&h, &h, &point->x);
    FeSubtract(&r, &r, &point->y);
    FeSquare(&h2, &h);
    FeMultiply(&h3, &h, &h2);
    FeMultiply(&v, &point->x, &h2);
    FeSquare(&sum->x, &r);
    FeSubtract(&sum->x, &sum->x, &h3);
    FeSubtract(&sum->x, &sum->x, &v);
    FeSubtract(&sum->x, &sum->x, &v);
    FeSubtract(&temporary, &v, &sum->x);
    FeMultiply(&sum->y, &r, &temporary);
    FeMultiply(&temporary, &point->y, &h3);
    FeSubtract(&sum->y, &sum->y, &temporary);
    FeMultiply(&sum->z, &point->z, &h);
}

/* The processed scalar bits and the new digit occupy disjoint positions
 * in either schedule. Their sum is below the group order, so real finite
 * additions can neither double nor cancel. Starting from infinity uses
 * the same formula and selects the blinded table point instead. */
static void PointAddDigit(Point256 *point, const Affine256 *affine, u16 apply,
    const ProjectiveScale *scale)
{
    Point256 sum;
    Fe256 x, y;
    u16 start = (u16)(0U - (apply & FeIsZero(&point->z)));
    u16 keep = (u16)(apply - 1U);
    u16 add = (u16)~(keep | start);
    PointMixedSum(&sum, point, affine);
    FeMultiply(&x, &affine->x, &scale->z2);
    FeMultiply(&y, &affine->y, &scale->z3);
    SelectMixed(&point->x, &sum.x, &x, keep, add, start);
    SelectMixed(&point->y, &sum.y, &y, keep, add, start);
    SelectMixed(&point->z, &sum.z, &scale->z, keep, add, start);
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

static void LoadMontgomery(Fe256 *out, const mp_int *value)
{
    for (unsigned i = 0; i < FIELD_LIMBS; ++i)
        out->v[i] = value->dp[i];
    FeMultiply(out, out, &kMontgomerySquare);
}

static void PrepareScale(ProjectiveScale *scale, const mp_int *randomizer)
{
    LoadMontgomery(&scale->z, randomizer);
    FeSquare(&scale->z2, &scale->z);
    FeMultiply(&scale->z3, &scale->z2, &scale->z);
}

static void ClearSecret(void *memory, unsigned size)
{
    volatile unsigned char *bytes = memory;
    for (unsigned i = 0; i < size; ++i)
        bytes[i] = 0;
}

/* wolfSSL supplies a scalar in [1,n-1] and a random nonzero field element.
 * The caller may supply pub->z as the blinding input. */
void PalmTlsP256MakePublic(const mp_int *scalar, const mp_int *randomizer,
    ecc_point *pub)
{
    struct {
        Point256 point;
        Affine256 selected;
        ProjectiveScale scale;
        Fe256 squared, cubed, inverse;
    } work;

    memset(&work.point, 0, sizeof(work.point));
    PrepareScale(&work.scale, randomizer);

    for (int window = P256_COMB_WINDOWS - 1; window >= 0; --window) {
        u16 digit = 0;
        for (unsigned tooth = 0; tooth < P256_COMB_WIDTH; ++tooth) {
            unsigned bit = (unsigned)window + tooth * P256_COMB_WINDOWS;
            if (bit < 256)
                digit |= ((scalar->dp[bit / 16] >> (bit % 16)) & 1U) << tooth;
        }
        PointDouble(&work.point);
        SelectGenerator(&work.selected, digit);
        PointAddDigit(&work.point, &work.selected, IsZero(digit) ^ 1U, &work.scale);
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

    ClearSecret(&work, sizeof(work));
}

enum { WINDOW_BITS = 4, WINDOW_POINTS = (1 << WINDOW_BITS) - 1 };

static u16 IsCanonical(const mp_int *value, const u16 *limit)
{
    u32 borrow = 0;
    for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
        u32 word = (u32)value->dp[i] - limit[i] - borrow;
        borrow = word >> 31;
    }
    return (u16)borrow & (value->sign == MP_ZPOS) & (value->used <= FIELD_LIMBS);
}

static int LoadPeer(Affine256 *affine, const ecc_point *peer)
{
    Fe256 lhs, rhs, term;
    if (!IsCanonical(peer->x, kPrime.v) || !IsCanonical(peer->y, kPrime.v))
        return IS_POINT_E;
    if (peer->x->used == 0 && peer->y->used == 0)
        return ECC_INF_E;

    LoadMontgomery(&affine->x, peer->x);
    LoadMontgomery(&affine->y, peer->y);
    FeSquare(&lhs, &affine->y);
    FeSquare(&term, &affine->x);
    FeMultiply(&rhs, &term, &affine->x);
    FeSubtract(&rhs, &rhs, &affine->x);
    FeSubtract(&rhs, &rhs, &affine->x);
    FeSubtract(&rhs, &rhs, &affine->x);
    FeAdd(&rhs, &rhs, &kCurveB);
    FeSubtract(&term, &lhs, &rhs);
    /* P-256 has cofactor one, so a finite curve point has order n. */
    return FeIsZero(&term) ? MP_OKAY : IS_POINT_E;
}

/* All inputs here are public. Batch normalization uses one ordinary
 * inversion via wolfSSL, then all secret arithmetic uses fixed schedules. */
static int BuildPeerTable(Point256 *table, const Affine256 *peer,
    mp_int *inverse, mp_int *modulus)
{
    Fe256 products[WINDOW_POINTS - 1];
    Fe256 reciprocal;
    table[0] = (Point256){peer->x, peer->y, kMontgomeryOne};
    for (unsigned i = 1; i < WINDOW_POINTS; i += 2) {
        table[i] = table[i / 2];
        PointDouble(&table[i]);
        PointMixedSum(&table[i + 1], &table[i], peer);
    }
    products[0] = table[1].z;
    for (unsigned i = 1; i < WINDOW_POINTS - 1; ++i)
        FeMultiply(&products[i], &products[i - 1], &table[i + 1].z);

    FeMultiply(&reciprocal, &products[WINDOW_POINTS - 2], &kOne);
    StoreCoordinate(inverse, &reciprocal);
    int err = mp_invmod(inverse, modulus, inverse);
    if (err != MP_OKAY)
        return err;
    LoadMontgomery(&reciprocal, inverse);
    for (int i = WINDOW_POINTS - 1; i > 0; --i) {
        Fe256 zInverse = reciprocal;
        Fe256 power;
        if (i > 1) {
            FeMultiply(&zInverse, &reciprocal, &products[i - 2]);
            FeMultiply(&reciprocal, &reciprocal, &table[i].z);
        }
        FeSquare(&power, &zInverse);
        FeMultiply(&table[i].x, &table[i].x, &power);
        FeMultiply(&power, &power, &zInverse);
        FeMultiply(&table[i].y, &table[i].y, &power);
    }
    return MP_OKAY;
}

static void SelectPeer(Affine256 *selected, const volatile Point256 *table,
    u16 digit)
{
    memset(selected, 0, sizeof(*selected));
    digit |= IsZero(digit);
    for (u16 row = 1; row <= WINDOW_POINTS; ++row) {
        u16 mask = (u16)(0U - IsZero(row ^ digit));
        for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
            selected->x.v[i] |= table[row - 1].x.v[i] & mask;
            selected->y.v[i] |= table[row - 1].y.v[i] & mask;
        }
    }
}

/* The wolfSSL caller supplies an affine peer, fresh randomizer in scratch->z,
 * and room for 32 output bytes. The finite shared point contributes only X. */
int PalmTlsP256Agree(const mp_int *scalar, const ecc_point *peer,
    const mp_int *order, mp_int *modulus, ecc_point *scratch, byte *out)
{
    Point256 table[WINDOW_POINTS];
    struct {
        Affine256 selected;
        Point256 point;
        ProjectiveScale scale;
        Fe256 inverse;
    } work;

    if (!IsCanonical(scalar, order->dp) || scalar->used == 0)
        return ECC_PRIV_KEY_E;

    PalmTlsEcdheProfileEnter(palmTlsEcdheValidate);
    int err = LoadPeer(&work.selected, peer);
    PalmTlsEcdheProfileLeave();
    if (err != MP_OKAY)
        return err;

    PalmTlsEcdheProfileEnter(palmTlsEcdheMultiply);
    err = BuildPeerTable(table, &work.selected, scratch->x, modulus);
    if (err != MP_OKAY) {
        PalmTlsEcdheProfileLeave();
        return err;
    }
    PrepareScale(&work.scale, scratch->z);
    memset(&work.point, 0, sizeof(work.point));
    for (int window = FIELD_LIMBS * 16 / WINDOW_BITS - 1; window >= 0; --window) {
        u16 digit = (scalar->dp[window / 4] >> (WINDOW_BITS * (window % 4))) & WINDOW_POINTS;
        for (unsigned i = 0; i < WINDOW_BITS; ++i)
            PointDouble(&work.point);
        SelectPeer(&work.selected, table, digit);
        PointAddDigit(&work.point, &work.selected, IsZero(digit) ^ 1U, &work.scale);
    }
    PalmTlsEcdheProfileLeave();

    PalmTlsEcdheProfileEnter(palmTlsEcdheMap);
    if (FeIsZero(&work.point.z)) {
        err = ECC_INF_E;
    }
    else {
        FeInverse(&work.inverse, &work.point.z);
        FeSquare(&work.inverse, &work.inverse);
        FeMultiply(&work.inverse, &work.inverse, &kOne);
        FeMultiply(&work.point.x, &work.point.x, &work.inverse);
        for (unsigned i = 0; i < FIELD_LIMBS; ++i) {
            u16 digit = work.point.x.v[FIELD_LIMBS - 1 - i];
            out[2 * i] = (byte)(digit >> 8);
            out[2 * i + 1] = (byte)digit;
        }
    }
    ClearSecret(&work, sizeof(work));
    PalmTlsEcdheProfileLeave();
    return err;
}
