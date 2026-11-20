/* SPDX-License-Identifier: GPL-3.0-or-later */
static void FeSquareN(Fe256 *resultP, const Fe256 *valueP, u32 count)
{
    /* All callers supply a public, nonzero constant count. FeSquare permits
     * aliasing, including the in-place steps below. */
    FeSquare(resultP, valueP);
    while (--count != 0) FeSquare(resultP, resultP);
}

static void FeInverse(Fe256 *resultP, const Fe256 *valueP)
{
    Fe256 power7, temporary, saved;
    /* Fixed p-2 chain: 255 squarings and 12 multiplications. The schedule
     * follows Go's p256Inverse (Copyright 2015 The Go Authors, BSD-3-Clause;
     * see p256-inverse.LICENSE and THIRD_PARTY.md). All counts and control
     * flow are independent of the field value. Zero maps to zero as before.
     *
     * Retain a^(2^15-1), then a^((2^32-1)*2^15). Their product
     * gives a^(2^47-1). The final exponent is
     * ((((2^32-1)*2^32+1)*2^143+(2^47-1))*2^47+(2^47-1))*4+1
     * = 2^256-2^224+2^192+2^96-3 = p-2. */
    FeSquare(&power7, valueP);
    FeMultiply(&power7, &power7, valueP);                 /* a^3 */
    FeSquare(&power7, &power7);
    FeMultiply(&power7, &power7, valueP);                 /* a^7 */
    FeSquareN(&temporary, &power7, 3);
    FeMultiply(&temporary, &temporary, &power7);          /* a^(2^6-1) */
    FeSquareN(&saved, &temporary, 6);
    FeMultiply(&temporary, &temporary, &saved);           /* a^(2^12-1) */
    FeSquareN(&temporary, &temporary, 3);
    FeMultiply(&power7, &power7, &temporary);             /* a^(2^15-1) */
    FeSquare(&temporary, &power7);
    FeMultiply(&temporary, &temporary, valueP);           /* a^(2^16-1) */
    FeSquareN(&saved, &temporary, 16);
    FeMultiply(&temporary, &temporary, &saved);           /* a^(2^32-1) */
    FeSquareN(&temporary, &temporary, 15);
    FeMultiply(&saved, &temporary, &power7);              /* a^(2^47-1) */
    FeSquareN(&temporary, &temporary, 17);
    FeMultiply(&temporary, &temporary, valueP);
    FeSquareN(&temporary, &temporary, 143);
    FeMultiply(&temporary, &temporary, &saved);
    FeSquareN(&temporary, &temporary, 47);
    FeMultiply(&temporary, &temporary, &saved);
    FeSquareN(&temporary, &temporary, 2);
    FeMultiply(resultP, &temporary, valueP);
}
