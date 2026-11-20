/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PALM_COMBA_68K_H
#define PALM_COMBA_68K_H

/* The assembler expands the eight-word Comba columns. A word product
 * uses .Lword and .Lcolumn to choose its operands and advances .Lword
 * after adding the product to the 48-bit accumulator. */
#define PALM_COMBA_8_COLUMNS \
    ".set .Lcolumn%=,0\n\t" \
    ".rept 15\n\t" \
    ".set .Lfirst%=,0\n\t" \
    ".if .Lcolumn%= > 7\n\t" \
    ".set .Lfirst%=,.Lcolumn%= - 7\n\t" \
    ".endif\n\t" \
    ".set .Lword%=,.Lfirst%=\n\t" \
    "moveq #0,%[high]\n\t"
#define PALM_COMBA_8_ACCUMULATE \
    "add.l %[term],%[low]\n\taddx.w %[zero],%[high]\n\t" \
    ".set .Lword%=,.Lword%= + 1\n\t"
#define PALM_COMBA_8_STORE_COLUMN \
    "move.w %[low],(%[out])+\n\t" \
    "move.w %[high],%[low]\n\tswap %[low]\n\t"

#define PALM_COMBA_8_MULTIPLY(WORD_PRODUCT) \
    PALM_COMBA_8_COLUMNS \
    ".rept .Lcolumn%= - 2*.Lfirst%= + 1\n\t" \
    WORD_PRODUCT \
    ".endr\n\t" \
    PALM_COMBA_8_STORE_COLUMN \
    ".set .Lcolumn%=,.Lcolumn%= + 1\n\t" \
    ".endr\n\t" \
    "move.w %[low],(%[out])"

/* Sum the off-diagonal terms, double the sum, then add the carry and
 * the diagonal. Keeping the carry separate avoids doubling it. */
#define PALM_COMBA_8_SQUARE(WORD_PRODUCT) \
    PALM_COMBA_8_COLUMNS \
    "moveq #0,%[low]\n\t" \
    ".rept (.Lcolumn%= + 1)/2 - .Lfirst%=\n\t" \
    WORD_PRODUCT \
    ".endr\n\t" \
    ".if (.Lcolumn%= + 1)/2 > .Lfirst%=\n\t" \
    "add.l %[low],%[low]\n\taddx.w %[high],%[high]\n\t" \
    ".endif\n\t" \
    "add.l %[carry],%[low]\n\taddx.w %[zero],%[high]\n\t" \
    ".if (.Lcolumn%= & 1) == 0\n\t" \
    WORD_PRODUCT \
    ".endif\n\t" \
    PALM_COMBA_8_STORE_COLUMN \
    "move.l %[low],%[carry]\n\t" \
    ".set .Lcolumn%=,.Lcolumn%= + 1\n\t" \
    ".endr\n\t" \
    "move.w %[carry],(%[out])"

#endif
