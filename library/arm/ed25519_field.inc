/* Field arithmetic for the ten-limb ref10 representation used by wolfSSL.
 * Limb weights alternate 26 and 25 bits. Arithmetic here follows the same
 * bounded signed input and output representation as fe_mul, fe_sq and fe_sq2.
 * Loop counts and array indices depend only on the public operation. */

typedef signed int EdLimb;
typedef signed long long EdWide;

static inline EdWide EdProduct(EdLimb left, EdLimb right)
{
#ifdef PALM_ARMLET_HOST_TEST
    return (EdWide)left * right;
#else
    /* Force a full-width Rs on ARMv4 cores with early multiply termination.
     * An unscaled ref10 limb stays well within +/- 2^30. Remove the bias after
     * multiplication using a shift in unsigned arithmetic. */
    EdLimb biased = right + (1 << 30);
    u32 low, high;
    __asm__("smull %0, %1, %2, %3"
        : "=&r"(low), "=&r"(high) : "r"(left), "r"(biased));
    return (EdWide)((((u64)high << 32) | low) - ((u64)left << 30));
#endif
}

static inline void EdCarry(EdWide *limbs, u32 index, u32 next, u32 bits,
                           EdLimb factor)
{
    EdWide carry = (limbs[index] + (1U << (bits - 1))) >> bits;
    limbs[index] -= (EdWide)((u64)carry << bits);
    limbs[next] += carry * factor;
}

static u32 Ed25519Field(const volatile u8 *leftP, const volatile u8 *rightP,
                         volatile u8 *outputP, u32 operation, u32 reserved)
{
    EdLimb left[10], right[10];
    EdWide limbs[10];
    u32 square = operation != PALM_TLS_ARMLET_ED25519_MUL;
    if (operation > PALM_TLS_ARMLET_ED25519_SQUARE_DOUBLE || reserved)
        return PALM_TLS_ARMLET_ERROR;

    for (u32 i = 0; i < 10; ++i) {
        limbs[i] = 0;
        left[i] = (EdLimb)ReadBigEndian32(leftP + i * 4);
        right[i] = square ? left[i] : (EdLimb)ReadBigEndian32(rightP + i * 4);
    }
    for (u32 i = 0; i < 10; ++i) {
        for (u32 j = square ? i : 0; j < 10; ++j) {
            u32 index = i + j;
            EdWide product = EdProduct(left[i], right[j]);
            if ((i & j & 1) != 0) product += product;
            if (index >= 10) {
                index -= 10;
                /* Scale the wide product: callers may supply loose limbs. */
                product *= 19; /* 2^255 == 19 in the field. */
            }
            if (square && i != j) product += product;
            limbs[index] += product;
        }
    }
    if (operation == PALM_TLS_ARMLET_ED25519_SQUARE_DOUBLE)
        for (u32 i = 0; i < 10; ++i) limbs[i] += limbs[i];

    /* Match ref10's carry sequence, including its centered output bounds. */
    EdCarry(limbs, 0, 1, 26, 1);
    EdCarry(limbs, 4, 5, 26, 1);
    EdCarry(limbs, 1, 2, 25, 1);
    EdCarry(limbs, 5, 6, 25, 1);
    EdCarry(limbs, 2, 3, 26, 1);
    EdCarry(limbs, 6, 7, 26, 1);
    EdCarry(limbs, 3, 4, 25, 1);
    EdCarry(limbs, 7, 8, 25, 1);
    EdCarry(limbs, 4, 5, 26, 1);
    EdCarry(limbs, 8, 9, 26, 1);
    EdCarry(limbs, 9, 0, 25, 19);
    EdCarry(limbs, 0, 1, 26, 1);
    for (u32 i = 0; i < 10; ++i)
        WriteBigEndian32(outputP + i * 4, (u32)limbs[i]);
    return PALM_TLS_ARMLET_SUCCESS;
}
