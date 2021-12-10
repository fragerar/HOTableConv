#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "gadgets.h"

#define gen_matrix KYBER_NAMESPACE(_gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define indcpa_keypair KYBER_NAMESPACE(_indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#define indcpa_enc KYBER_NAMESPACE(_indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);
void indcpa_enc_no_compress(uint16_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_masked_enc(uint8_t masked_c[KYBER_INDCPA_BYTES * (KYBER_MASKING_ORDER + 1)],
                       const uint8_t masked_m[KYBER_INDCPA_MSGBYTES * (KYBER_MASKING_ORDER + 1)],
                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)]);

void indcpa_masked_enc_no_compress(Masked ct[KYBER_N*(KYBER_K+1)],
                       const uint8_t masked_m[KYBER_INDCPA_MSGBYTES * (KYBER_MASKING_ORDER + 1)],
                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)]);
#define indcpa_dec KYBER_NAMESPACE(_indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);
void indcpa_masked_dec(uint8_t m[KYBER_INDCPA_MSGBYTES*(KYBER_MASKING_ORDER+1)],
                       const uint8_t c[KYBER_INDCPA_BYTES],
                       const masked_polyvec* skpv);
void unpack_sk(polyvec *sk,
                      const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]);

void unpack_ciphertext(polyvec *b,
                              poly *v,
                              const uint8_t c[KYBER_INDCPA_BYTES]);
#endif

