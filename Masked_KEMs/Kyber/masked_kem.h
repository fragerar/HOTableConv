#ifndef MKEM_H
#define MKEM_H


#include "params.h"
#include "polyvec.h"
int masked_crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const masked_polyvec* skpv, const unsigned char* pk, const unsigned char* pkh, const unsigned char* masked_z);

#endif