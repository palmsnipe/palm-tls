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
#define PALM_TLS_ARMLET_COMMAND_P256_VALIDATE 8
/* VALIDATE: right = canonical unsigned big-endian x || y (64 bytes).
 * Header bytes 1/2 must be zero. No output bytes are written. The bridge
 * separately enforces signed-integer bounds and affine z == 1. */
#define PALM_TLS_ARMLET_P256_INVALID_POINT 0x101UL
#define PALM_TLS_ARMLET_P256_OUT_OF_RANGE 0x102UL
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
#define PALM_TLS_ARMLET_COMMAND_CHACHA_POLY 9
#define PALM_TLS_ARMLET_SHA256_MAX_BLOCKS 8
/* ChaCha20-Poly1305 seals or opens a whole record in one call. The left
 * operand holds these fields; the record and AAD stay in the caller's
 * buffers, passed as big-endian addresses. state is wolfSSL's ChaCha X[16],
 * as big-endian words; its block counter is ignored. The request's state
 * copy is erased before this command returns, including on errors. */
#define PALM_TLS_ARMLET_CHACHA_DECRYPT_OFFSET 0
#define PALM_TLS_ARMLET_CHACHA_STATE_OFFSET 4
#define PALM_TLS_ARMLET_CHACHA_INPUT_OFFSET 68
#define PALM_TLS_ARMLET_CHACHA_OUTPUT_OFFSET 72
#define PALM_TLS_ARMLET_CHACHA_LENGTH_OFFSET 76
#define PALM_TLS_ARMLET_CHACHA_AAD_OFFSET 80
#define PALM_TLS_ARMLET_CHACHA_AAD_LENGTH_OFFSET 84
#define PALM_TLS_ARMLET_CHACHA_TAG_OFFSET 88
#define PALM_TLS_ARMLET_CHACHA_MAX_LENGTH 0x10000UL
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
/* Opening a record whose tag does not match; the output is untouched. */
#define PALM_TLS_ARMLET_AUTH_FAILED 0x101UL

#endif
