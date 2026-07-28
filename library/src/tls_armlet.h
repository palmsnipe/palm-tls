#ifndef PALM_TLS_ARMLET_H
#define PALM_TLS_ARMLET_H

#include <wolfssl/wolfcrypt/tfm.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>

void PalmTlsArmletInitialize(void);
void PalmTlsArmletShutdown(void);
UInt16 PalmTlsArmletGetStatus(void);
void PalmTlsArmletDisable(void);
int PalmTlsArmletMultiply(fp_int *leftP, fp_int *rightP, fp_int *outputP);
#ifdef HAVE_ECC
int PalmTlsArmletP256Multiply(const mp_int *scalarP, const ecc_point *pointP,
                             ecc_point *resultP, mp_int *modulusP, int map);
int PalmTlsArmletP256Map(ecc_point *pointP, mp_int *modulusP);
int PalmTlsArmletP256Multiply2Add(const ecc_point *leftPointP,
                                 const mp_int *leftScalarP,
                                 const ecc_point *rightPointP,
                                 const mp_int *rightScalarP,
                                 ecc_point *resultP, mp_int *modulusP);
#endif
int PalmTlsArmletSha256Transform(word32 *digestP, const byte *blockP,
                                word32 blockCount);
void PalmTlsArmletAesGcmSetKey(Aes *aesP, const byte *keyP, word32 length);
void PalmTlsArmletAesGcmFree(Aes *aesP);
int PalmTlsArmletAesGcmCrypt(Aes *aesP, byte *outputP, const byte *inputP,
                            word32 length, const byte *ivP, word32 ivLength,
                            byte *tagP, word32 tagLength, const byte *aadP,
                            word32 aadLength, int decrypt, int *resultP);

#endif
