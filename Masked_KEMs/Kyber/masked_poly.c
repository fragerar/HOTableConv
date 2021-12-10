#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "cbd.h"
#include "symmetric.h"
#include "gadgets.h"
/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void poly_masked_ntt(masked_poly* masked_r)
{
    unsigned int m;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        ntt(((masked_r->poly_shares)[m]).coeffs);
        poly_reduce(&((masked_r->poly_shares)[m]));
    }
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void poly_masked_invntt_tomont(masked_poly* masked_r)
{
    unsigned int m;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        invntt(((masked_r->poly_shares)[m]).coeffs);
    }
    
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_masked_basemul_montgomery(masked_poly* masked_r,
                                    const masked_poly* masked_a,
                                    const masked_poly* masked_b)
{
    unsigned int m, i;
    poly* r;
    const poly* a;
    const poly* b;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        a = &((masked_a->poly_shares)[m]);
        b = &((masked_b->poly_shares)[m]);
        for (i = 0; i < KYBER_N / 4; i++) {
            basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i]);
            basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2],
                -zetas[64 + i]);
        }
    }
    
}
/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_halfmasked_basemul_montgomery(masked_poly* masked_r,
                                        const poly* a,
                                        const masked_poly* masked_b)
{
    unsigned int m, i;
    poly* r;
    const poly* b;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        b = &((masked_b->poly_shares)[m]);
        for (i = 0; i < KYBER_N / 4; i++) {
            basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i]);
            basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2],
                -zetas[64 + i]);
        }
    }

}
/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_masked_tomont(masked_poly* masked_r)
{
    unsigned int i,m;
    const int16_t f = (1ULL << 32) % KYBER_Q;
    poly* r;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        for (i = 0; i < KYBER_N; i++)
            r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
    
    
    
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_masked_reduce(masked_poly* masked_r)
{
    unsigned int i,m;
    poly* r;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        for (i = 0; i < KYBER_N; i++)
            r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }    
}

/*************************************************
* Name:        poly_csubq
*
* Description: Applies conditional subtraction of q to each coefficient
*              of a polynomial. For details of conditional subtraction
*              of q see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_masked_csubq(masked_poly* masked_r)
{
    unsigned int i,m;
    poly* r;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        for (i = 0; i < KYBER_N; i++)
            r->coeffs[i] = csubq(r->coeffs[i]);
    }
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_masked_add(masked_poly* masked_r,
                     const masked_poly* masked_a,
                     const masked_poly* masked_b)
{
    unsigned int i,m;
    poly* r;
    const poly* a;
    const poly* b;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        a = &((masked_a->poly_shares)[m]);
        b = &((masked_b->poly_shares)[m]);
        for (i = 0; i < KYBER_N; i++)
            r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_masked_sub(masked_poly* masked_r,
                    const masked_poly* masked_a,
                    const masked_poly* masked_b)
{
    unsigned int i, m;
    poly* r;
    const poly* a;
    const poly* b;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        a = &((masked_a->poly_shares)[m]);
        b = &((masked_b->poly_shares)[m]);
        for (i = 0; i < KYBER_N; i++)
            r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_halfmasked_sub(masked_poly* masked_r,
                         const poly* a,
                         const masked_poly* masked_b)
{
    unsigned int i, m;
    poly* r;
    const poly* b;
    r = &((masked_r->poly_shares)[0]);
    b = &((masked_b->poly_shares)[0]);
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    for (m = 1; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        b = &((masked_b->poly_shares)[m]);
        for (i = 0; i < KYBER_N; i++)
            r->coeffs[i] = -b->coeffs[i];
    }
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - poly *a:      pointer to input polynomial
**************************************************/
void poly_masked_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES*(KYBER_MASKING_ORDER+1)],
                       masked_poly* masked_a)
{

    Masked ar;
    Masked bo;
    for(int i=0; i < KYBER_INDCPA_MSGBYTES*(KYBER_MASKING_ORDER+1); ++i) msg[i] = 0;
    for(int i=0; i < KYBER_N/8; ++i){
      for(int j=0; j < 8; ++j){
        for(int k=0; k < KYBER_MASKING_ORDER+1; ++k) ar.shares[k] = (masked_a->poly_shares[k]).coeffs[8*i+j];
        kyber_decryption(&ar, &bo);
        for(int k=0; k < KYBER_MASKING_ORDER+1; ++k) msg[i+k*(KYBER_INDCPA_MSGBYTES)] |= ((bo.shares[k])&1)<<j; 
      }
    }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of KYBER_POLYBYTES bytes)
**************************************************/
void poly_masked_frombytes(masked_poly* masked_r,
                           const uint8_t a[KYBER_POLYBYTES*(KYBER_MASKING_ORDER+1)])
{
    unsigned int i,m;
    poly* r;
    for (m = 0; m < (KYBER_MASKING_ORDER + 1); m++)
    {
        r = &((masked_r->poly_shares)[m]);
        for (i = 0; i < KYBER_N / 2; i++) {
            r->coeffs[2 * i]     = ((a[3 * i + m * KYBER_POLYBYTES + 0] >> 0) |
                                   ((uint16_t)a[3 * i + m * KYBER_POLYBYTES + 1] << 8)) & 0xFFF;
            r->coeffs[2 * i + 1] = ((a[3 * i + m * KYBER_POLYBYTES + 1] >> 4) |
                                   ((uint16_t)a[3 * i + m * KYBER_POLYBYTES + 2] << 4)) & 0xFFF;
        }
    }
}
/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void poly_masked_frommsg(masked_poly* masked_r,
                         const uint8_t msg[KYBER_INDCPA_MSGBYTES * (KYBER_MASKING_ORDER + 1)])
{
    encode_message(msg, masked_r);
}