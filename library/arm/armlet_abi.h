#ifndef PALM_TLS_ARMLET_ABI_H
#define PALM_TLS_ARMLET_ABI_H

#define PALM_TLS_ARMLET_VERSION 1
#define PALM_TLS_ARMLET_COMMAND_MULTIPLY 0
#define PALM_TLS_ARMLET_COMMAND_P256_MUL 1
#define PALM_TLS_ARMLET_COMMAND_SHA256_TRANSFORM 2
#define PALM_TLS_ARMLET_COMMAND_AES_GCM 3
#define PALM_TLS_ARMLET_COMMAND_P256_MUL2ADD 4
#define PALM_TLS_ARMLET_COMMAND_P256_MAP 5
#define PALM_TLS_ARMLET_COMMAND_P256_ORDER 6
#define PALM_TLS_ARMLET_COMMAND_P256_FIELD 7
/* Checked diagnostics: request[1] selects multiply/square/reduce; request[2]
 * is a public iteration count in [1,255]. Inputs/output are raw big-endian
 * limbs, without Montgomery conversion. Multiply chains a <- a*b/R mod p;
 * square chains a <- a*a/R mod p; reduce chains a <- (b*R+a)/R mod p.
 * Multiply requires a,b<p; square requires a<p and ignores b. Reduction
 * requires b<p, while its low half a may be any 256-bit value (T<p*R).
 * No production wolfSSL operation dispatches this diagnostic command. */
#define PALM_TLS_ARMLET_FIELD_MULTIPLY 0
#define PALM_TLS_ARMLET_FIELD_SQUARE 1
#define PALM_TLS_ARMLET_FIELD_REDUCE 2
/* ORDER input: left = e || r || s (three unsigned big-endian 32-byte values).
 * Output = u1 || u2 || s^-1 mod n in the same format. r,s must be in [1,n).
 * This variable-time command is for public ECDSA verification values only. */
#define PALM_TLS_ARMLET_SHA256_MAX_BLOCKS 8
#define PALM_TLS_ARMLET_AES_GCM_START 0
#define PALM_TLS_ARMLET_AES_GCM_UPDATE 1
#define PALM_TLS_ARMLET_AES_GCM_FINAL 2
#define PALM_TLS_ARMLET_AES_GCM_CHUNK 512
#define PALM_TLS_ARMLET_MAX_DIGITS 264
#define PALM_TLS_ARMLET_HEADER_SIZE 4
#define PALM_TLS_ARMLET_DIGIT_BYTES (PALM_TLS_ARMLET_MAX_DIGITS * 2)
#define PALM_TLS_ARMLET_LEFT_OFFSET PALM_TLS_ARMLET_HEADER_SIZE
#define PALM_TLS_ARMLET_RIGHT_OFFSET \
    (PALM_TLS_ARMLET_LEFT_OFFSET + PALM_TLS_ARMLET_DIGIT_BYTES)
#define PALM_TLS_ARMLET_OUTPUT_OFFSET \
    (PALM_TLS_ARMLET_RIGHT_OFFSET + PALM_TLS_ARMLET_DIGIT_BYTES)
#define PALM_TLS_ARMLET_ERROR 0xffffffffUL
#define PALM_TLS_ARMLET_SUCCESS 0x100UL
#define PALM_TLS_ARMLET_P256_SUCCESS PALM_TLS_ARMLET_SUCCESS

#endif
