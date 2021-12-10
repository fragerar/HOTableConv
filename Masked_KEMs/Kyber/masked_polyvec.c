#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"
/*************************************************
* Name:        polyvec_masked_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_masked_ntt(masked_polyvec* masked_r)
{
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_masked_ntt(&(masked_r->vec_shares[i]));
}
/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_masked_invntt_tomont(masked_polyvec* masked_r)
{
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_masked_invntt_tomont(&(masked_r->vec_shares[i]));
}
/*************************************************
* Name:        polyvec_halfmasked_pointwise_acc_montgomery
*
* Description: Pointwise multiply elements of a and b, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_halfmasked_pointwise_acc_montgomery(masked_poly* masked_r,
                                                 const polyvec* a,
                                                 const masked_polyvec* masked_b)
{
    unsigned int i;
    masked_poly masked_t;

    poly_halfmasked_basemul_montgomery(masked_r, &a->vec[0], &(masked_b->vec_shares[0]));
    for (i = 1; i < KYBER_K; i++) {
        poly_halfmasked_basemul_montgomery(&masked_t,
                                           &a->vec[i],
                                           &(masked_b->vec_shares[i]));
        poly_masked_add(masked_r, masked_r, &masked_t);
    }

    poly_masked_reduce(masked_r);
}

/*************************************************
* Name:        polyvec_masked_pointwise_acc_montgomery
*
* Description: Pointwise multiply elements of a and b, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_masked_pointwise_acc_montgomery(masked_poly* masked_r,
                                             const masked_polyvec* masked_a,
                                             const masked_polyvec* masked_b)
{
    unsigned int i;
    masked_poly masked_t;

    poly_masked_basemul_montgomery(masked_r,
                                   &(masked_a->vec_shares[0]),
                                   &(masked_b->vec_shares[0]));
    for (i = 1; i < KYBER_K; i++) {
        poly_masked_basemul_montgomery(&masked_t,
                                       &(masked_a->vec_shares[i]),
                                       &(masked_b->vec_shares[i]));
        poly_masked_add(masked_r, masked_r, &masked_t);
    }

    poly_masked_reduce(masked_r);
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
*                                  (of length KYBER_POLYVECBYTES)
**************************************************/
void polyvec_masked_frombytes(masked_polyvec* masked_r,
                              const uint8_t a[KYBER_POLYVECBYTES * (KYBER_MASKING_ORDER + 1)])
{
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_masked_frombytes(&(masked_r->vec_shares[i]),
                              a + i * KYBER_POLYBYTES * (KYBER_MASKING_ORDER + 1));
}
/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_masked_add(masked_polyvec* masked_r,
                        const masked_polyvec* masked_a,
                        const masked_polyvec* masked_b)
{
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_masked_add(&(masked_r->vec_shares[i]),
                        &(masked_a->vec_shares[i]),
                        &(masked_b->vec_shares[i]));
}
/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void polyvec_masked_reduce(masked_polyvec* masked_r)
{
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_masked_reduce(&masked_r->vec_shares[i]);
}


