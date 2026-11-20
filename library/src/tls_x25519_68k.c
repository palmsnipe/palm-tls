/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "tls_x25519_68k.h"
#include <string.h>

#ifdef __m68k__
#include "palm_comba_68k.h"
#endif

#ifdef PALM_WOLFSSL_68K_X25519
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include "tls_handshake_profile.h"
#endif

typedef uint16_t u16;
typedef uint32_t u32;

enum { LIMBS = 16, HALF_LIMBS = LIMBS / 2 };
_Static_assert(HALF_LIMBS == 8, "68K Comba kernels use eight-word halves");
typedef struct { u16 limb[LIMBS]; } Field;
typedef struct { Field plus, minus, xy2d; } AffineNiels;
typedef struct { Field x, y, z, t; } EdwardsPoint;

#include "x25519_comb.inc"

static const Field kPrime = {{
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff
}};

static inline __attribute__((always_inline)) u16 WordMask(u16 bit)
{
    u16 mask = (u16)(0U - bit);
#ifdef __m68k__
    /* Keep GCC from turning a masked assignment into a branch. */
    __asm__("" : "+d"(mask));
#endif
    return mask;
}

/* MULU timing depends on the source word. Use the public operand there. */
static inline __attribute__((always_inline)) u32 MultiplyPublicWord(u16 left, u16 right)
{
#ifdef __m68k__
    u32 result = left;
    __asm__("mulu.w %1,%0" : "+d"(result) : "d"(right) : "cc");
    return result;
#else
    return (u32)left * right;
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

#ifdef __m68k__
/* The two MULU source words are complementary. Their combined popcount
 * is fixed, which balances the operand-dependent 68000 multiply time. */
#define HALF_ADD_SECRET_PRODUCT \
    "move.w (2*.Lword%=)(%[left]),%[term]\n\t" \
    "move.w %[term],%[padding]\n\t" \
    "move.w (2*(.Lcolumn%= - .Lword%=))(%[right]),%[source]\n\t" \
    "mulu.w %[source],%[term]\n\t" \
    "not.w %[source]\n\t" \
    "mulu.w %[source],%[padding]\n\t" \
    PALM_COMBA_8_ACCUMULATE

static void MultiplyHalf(u16 *out, const u16 *left, const u16 *right)
{
    u32 low = 0, term, padding;
    u16 high, source;
    __asm__ volatile(PALM_COMBA_8_MULTIPLY(HALF_ADD_SECRET_PRODUCT)
        : [out] "+&a"(out), [low] "+&d"(low), [high] "=&d"(high), [term] "=&d"(term),
          [padding] "=&d"(padding), [source] "=&d"(source)
        : [left] "a"(left), [right] "a"(right), [zero] "d"((u16)0) : "cc", "memory");
}

static void SquareHalf(u16 *out, const u16 *value)
{
    u32 low, carry = 0, term, padding;
    u16 high, source;
    __asm__ volatile(PALM_COMBA_8_SQUARE(HALF_ADD_SECRET_PRODUCT)
        : [out] "+&a"(out), [carry] "+&d"(carry), [low] "=&d"(low), [high] "=&d"(high),
          [term] "=&d"(term), [padding] "=&d"(padding), [source] "=&d"(source)
        : [left] "a"(value), [right] "a"(value), [zero] "d"((u16)0) : "cc", "memory");
}
#undef HALF_ADD_SECRET_PRODUCT
#else
static void MultiplyHalf(u16 *out, const u16 *left, const u16 *right)
{
    memset(out, 0, LIMBS * sizeof(*out));
    for (unsigned i = 0; i < HALF_LIMBS; i++) {
        u32 carry = 0;
        for (unsigned j = 0; j < HALF_LIMBS; j++) {
            u32 word = (u32)left[i] * right[j] + out[i + j] + carry;
            out[i + j] = (u16)word;
            carry = word >> 16;
        }
        out[i + HALF_LIMBS] = (u16)carry;
    }
}

static void SquareHalf(u16 *out, const u16 *value)
{
    MultiplyHalf(out, value, value);
}
#endif

/* Store |low - high| and return the borrow. Taking the magnitude always
 * visits all eight words, even when the halves are equal. */
static u16 HalfDifference(u16 *out, const Field *value)
{
    u32 borrow = 0;
    for (unsigned i = 0; i < HALF_LIMBS; i++) {
        u32 word = (u32)value->limb[i] - value->limb[i + HALF_LIMBS] - borrow;
        out[i] = (u16)word;
        borrow = word >> 31;
    }
    u16 mask = WordMask((u16)borrow);
    u32 carry = borrow;
    for (unsigned i = 0; i < HALF_LIMBS; i++) {
        carry += out[i] ^ mask;
        out[i] = (u16)carry;
        carry >>= 16;
    }
    return (u16)borrow;
}

/* The middle coefficient is lowProduct + highProduct minus the signed
 * difference product. It can take 257 bits. Add it at bit 128 and carry
 * through the rest of the product on a fixed schedule. */
static void CombineHalfProducts(u16 product[2 * LIMBS], u16 middle[LIMBS + 1], u16 subtract)
{
    u16 mask = WordMask(subtract);
    int32_t carry = 0;
    for (unsigned i = 0; i < LIMBS; i++) {
        int32_t term = (int32_t)(middle[i] ^ mask) - mask;
        int32_t word = (int32_t)product[i] + product[i + LIMBS] + term + carry;
        middle[i] = (u16)word;
        carry = word >> 16;
    }
    middle[LIMBS] = (u16)carry;

    u32 carryWord = 0;
    u16 *dest = product + HALF_LIMBS;
    for (unsigned i = 0; i <= LIMBS; i++) {
        carryWord += (u32)dest[i] + middle[i];
        dest[i] = (u16)carryWord;
        carryWord >>= 16;
    }
    for (unsigned i = LIMBS + 1; i < 2 * LIMBS - HALF_LIMBS; i++) {
        carryWord += dest[i];
        dest[i] = (u16)carryWord;
        carryWord >>= 16;
    }
}

static void FieldMultiply(Field *out, const Field *left, const Field *right)
{
    u16 product[2 * LIMBS], middle[LIMBS + 1];
    u16 leftDiff[HALF_LIMBS], rightDiff[HALF_LIMBS];
    u16 leftBorrow = HalfDifference(leftDiff, left);
    u16 rightBorrow = HalfDifference(rightDiff, right);
    MultiplyHalf(product, left->limb, right->limb);
    MultiplyHalf(product + LIMBS, left->limb + HALF_LIMBS, right->limb + HALF_LIMBS);
    MultiplyHalf(middle, leftDiff, rightDiff);
    CombineHalfProducts(product, middle, (u16)(1U ^ leftBorrow ^ rightBorrow));
    ReduceProduct(out, product);
}

/* The peer coordinate supplies the public multiplier word in the ladder. */
static void FieldMultiplyByPublic(Field *out, const Field *left, const Field *right)
{
    u16 product[2 * LIMBS] = {0};
    for (unsigned i = 0; i < LIMBS; i++) {
        u32 carry = 0;
        for (unsigned j = 0; j < LIMBS; j++) {
            u32 word = MultiplyPublicWord(left->limb[i], right->limb[j]) +
                product[i + j] + carry;
            product[i + j] = (u16)word;
            carry = word >> 16;
        }
        product[i + LIMBS] = (u16)carry;
    }
    ReduceProduct(out, product);
}

static void FieldSquare(Field *out, const Field *value)
{
    u16 product[2 * LIMBS], middle[LIMBS + 1], difference[HALF_LIMBS];
    HalfDifference(difference, value);
    SquareHalf(product, value->limb);
    SquareHalf(product + LIMBS, value->limb + HALF_LIMBS);
    SquareHalf(middle, difference);
    CombineHalfProducts(product, middle, 1);
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

static void ClampScalar(uint8_t output[32], const uint8_t input[32])
{
    memcpy(output, input, 32);
    output[0] &= 248;
    output[31] = (output[31] & 127) | 64;
}

static void ClearWork(void *work, unsigned size)
{
    volatile uint8_t *bytes = work;
    for (unsigned i = 0; i < size; i++) bytes[i] = 0;
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

    ClampScalar(work.scalar, scalar);
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

    ClearWork(&work, sizeof(work));
}

typedef struct { Field x, z; } MontgomeryPoint;

/* a24 = 121665 = 2^16 + 56129. The shifted term requires just the
 * previous limb. The final carry can occupy 17 bits. */
static void FieldMultiplyA24(Field *out, const Field *input)
{
    u32 carry = 0;
    u16 previous = 0;
    for (unsigned i = 0; i < LIMBS; i++) {
        u16 limb = input->limb[i];
        u32 word = (u32)limb * 56129U + previous + carry;
        out->limb[i] = (u16)word;
        carry = word >> 16;
        previous = limb;
    }
    u16 overflow = AddWord(out, (carry + previous) * 38UL);
    AddWord(out, 38U * overflow);
}

static void SwapPoints(MontgomeryPoint *left, MontgomeryPoint *right, u16 bit)
{
    u16 mask = WordMask(bit);
    for (unsigned i = 0; i < LIMBS; i++) {
        u16 x = (left->x.limb[i] ^ right->x.limb[i]) & mask;
        u16 z = (left->z.limb[i] ^ right->z.limb[i]) & mask;
        left->x.limb[i] ^= x;
        right->x.limb[i] ^= x;
        left->z.limb[i] ^= z;
        right->z.limb[i] ^= z;
    }
}

/* RFC 7748 §5 differential addition and doubling. The peer coordinate
 * is the fixed difference of the two ladder points throughout. */
static void LadderStep(MontgomeryPoint *left, MontgomeryPoint *right, const Field *peer)
{
    Field a, b, c, d;
    FieldAdd(&a, &left->x, &left->z);
    FieldSubtract(&b, &left->x, &left->z);
    FieldAdd(&c, &right->x, &right->z);
    FieldSubtract(&d, &right->x, &right->z);
    FieldMultiply(&d, &d, &a);                      /* DA */
    FieldMultiply(&c, &c, &b);                      /* CB */
    FieldAdd(&right->x, &d, &c);
    FieldSubtract(&right->z, &d, &c);
    FieldSquare(&right->x, &right->x);
    FieldSquare(&right->z, &right->z);
    FieldMultiplyByPublic(&right->z, &right->z, peer);
    FieldSquare(&a, &a);                            /* AA */
    FieldSquare(&b, &b);                            /* BB */
    FieldMultiply(&left->x, &a, &b);
    FieldSubtract(&b, &a, &b);                      /* E */
    FieldMultiplyA24(&d, &b);
    FieldAdd(&d, &a, &d);
    FieldMultiply(&left->z, &b, &d);
}

/* As in the portable ladder, store k XOR (2*k) XOR mask. The transitions
 * between scalar bits are masked, and each iteration ends with the mask
 * used by the following iteration already applied to the point order. */
static void MaskTransitions(uint8_t scalar[32], const uint8_t mask[32])
{
    u16 carry = 0;
    for (unsigned i = 0; i < 32; i++) {
        uint8_t byte = scalar[i];
        scalar[i] = byte ^ (uint8_t)((byte << 1) | carry) ^ mask[i];
        carry = byte >> 7;
    }
}

static u16 ScalarBit(const uint8_t bytes[32], unsigned bit)
{
    return (bytes[bit >> 3] >> (bit & 7U)) & 1U;
}

bool PalmTlsX25519Agree(uint8_t output[32], const uint8_t scalar[32],
    const uint8_t peer[32], const uint8_t projectiveScale[32], const uint8_t swapMask[32])
{
    struct {
        uint8_t scalar[32];
        MontgomeryPoint left, right;
        Field peer;
    } work;

    ClampScalar(work.scalar, scalar);
    MaskTransitions(work.scalar, swapMask);
    DecodeField(&work.peer, peer);
    work.peer.limb[LIMBS - 1] &= 0x7fff;

#ifdef PALM_WOLFSSL_68K_X25519
    PalmTlsEcdheProfileEnter(palmTlsEcdheMultiply);
#endif
    /* Scaled infinity (1:0) and scaled peer (u:1). */
    memset(&work.left.z, 0, sizeof(work.left.z));
    DecodeField(&work.right.z, projectiveScale);
    work.left.x = work.right.z;
    FieldMultiplyByPublic(&work.right.x, &work.right.z, &work.peer);
    SwapPoints(&work.left, &work.right, ScalarBit(swapMask, 255));
    for (unsigned bit = 255; bit != 0; bit--) {
        SwapPoints(&work.left, &work.right, ScalarBit(work.scalar, bit));
        LadderStep(&work.left, &work.right, &work.peer);
        SwapPoints(&work.left, &work.right, ScalarBit(swapMask, bit - 1));
    }
    SwapPoints(&work.left, &work.right, ScalarBit(work.scalar, 0));
#ifdef PALM_WOLFSSL_68K_X25519
    PalmTlsEcdheProfileLeave();
    PalmTlsEcdheProfileEnter(palmTlsEcdheMap);
#endif
    FieldInvert(&work.left.z, &work.left.z);
    FieldMultiply(&work.left.x, &work.left.x, &work.left.z);
    EncodeField(output, &work.left.x);
#ifdef PALM_WOLFSSL_68K_X25519
    PalmTlsEcdheProfileLeave();
#endif
    ClearWork(&work, sizeof(work));

    uint8_t nonzero = 0;
    for (unsigned i = 0; i < 32; i++) nonzero |= output[i];
    return nonzero != 0;
}

#ifdef PALM_WOLFSSL_68K_X25519
/* Reserve 253 random bits for the scale. Setting bit 253 and clearing
 * the two higher bits guarantees a nonzero field element below p. */
static int RandomBlinding(WC_RNG *rng, uint8_t *bytes, unsigned size)
{
    int ret = wc_RNG_GenerateBlock(rng, bytes, size);
    if (ret == 0)
        bytes[31] = (bytes[31] & 0x1f) | 0x20;
    return ret;
}

int PalmTlsX25519MakePublic(uint8_t *publicKey, const uint8_t *scalar, WC_RNG *rng)
{
    uint8_t scale[32];
    int ret = RandomBlinding(rng, scale, sizeof(scale));
    if (ret == 0)
        PalmTlsX25519FixedBase(publicKey, scalar, scale);
    ClearWork(scale, sizeof(scale));
    return ret;
}

int PalmTlsX25519SharedSecret(uint8_t *out, const uint8_t *scalar, const uint8_t *peer,
    WC_RNG *rng)
{
    uint8_t blinding[64];
    int ret = RandomBlinding(rng, blinding, sizeof(blinding));
    if (ret == 0 && !PalmTlsX25519Agree(out, scalar, peer, blinding, blinding + 32))
        ret = ECC_OUT_OF_RANGE_E;
    ClearWork(blinding, sizeof(blinding));
    return ret;
}
#endif
