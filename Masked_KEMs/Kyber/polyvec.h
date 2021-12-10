#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

typedef struct{
    poly vec[KYBER_K];
} polyvec;

typedef struct {
    masked_poly vec_shares[KYBER_K];
} masked_polyvec;

#define polyvec_compress KYBER_NAMESPACE(_polyvec_compress)
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], polyvec *a);
#define polyvec_decompress KYBER_NAMESPACE(_polyvec_decompress)
void polyvec_decompress(polyvec *r,
                        const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

#define polyvec_tobytes KYBER_NAMESPACE(_polyvec_tobytes)
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], polyvec *a);
#define polyvec_frombytes KYBER_NAMESPACE(_polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);
void polyvec_masked_frombytes(masked_polyvec* masked_r,
                              const uint8_t a[KYBER_POLYVECBYTES * (KYBER_MASKING_ORDER + 1)]);
#define polyvec_ntt KYBER_NAMESPACE(_polyvec_ntt)
void polyvec_ntt(polyvec *r);
void polyvec_masked_ntt(masked_polyvec* masked_r);
#define polyvec_invntt_tomont KYBER_NAMESPACE(_polyvec_invntt_tomont)
void polyvec_invntt_tomont(polyvec *r);
void polyvec_masked_invntt_tomont(masked_polyvec* masked_r);
#define polyvec_pointwise_acc_montgomery \
        KYBER_NAMESPACE(_polyvec_pointwise_acc_montgomery)
void polyvec_pointwise_acc_montgomery(poly *r,
                                      const polyvec *a,
                                      const polyvec *b);
void polyvec_halfmasked_pointwise_acc_montgomery(masked_poly* masked_r,
                                       const polyvec* a,
                                       const masked_polyvec* masked_b);
void polyvec_masked_pointwise_acc_montgomery(masked_poly* masked_r,
                                             const masked_polyvec* masked_a,
                                             const masked_polyvec* masked_b);
#define polyvec_reduce KYBER_NAMESPACE(_polyvec_reduce)
void polyvec_reduce(polyvec *r);
void polyvec_masked_reduce(masked_polyvec* masked_r);
#define polyvec_csubq KYBER_NAMESPACE(_polyvec_csubq)
void polyvec_csubq(polyvec *r);

#define polyvec_add KYBER_NAMESPACE(_polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);
void polyvec_masked_add(masked_polyvec* masked_r,
                        const masked_polyvec* masked_a,
                        const masked_polyvec* masked_b);
#endif
