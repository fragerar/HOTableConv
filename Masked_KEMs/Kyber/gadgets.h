#ifndef GADGETS_H
#define GADGETS_H

#include <stdint.h>
#include <stdio.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "random.h"

typedef struct Masked {int shares[KYBER_MASKING_ORDER+1];} Masked;


void convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q);
void linear_arithmetic_refresh(Masked* x, unsigned q);
void linear_boolean_refresh(Masked* x, unsigned k);
void boolean_refresh(Masked* x, unsigned k);
void arithmetic_refresh(Masked* x, unsigned q); 
void convert_2_l_to_1bit_bool(Masked* x, Masked* b, unsigned l);



/* Kyber gadgets */

void CBD(Masked* a, Masked* b, Masked* y, int eta);
void encode_message(const uint8_t m[(KYBER_N/8)*(KYBER_MASKING_ORDER+1)], masked_poly* y);
void masked_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES*(KYBER_MASKING_ORDER+1)], uint8_t nonce);
void masked_hash_h(uint8_t h_masked[32 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen);
void masked_hash_g(uint8_t h_masked[64 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen);
void masked_kdf(uint8_t h_masked[32 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen);

void masked_poly_getnoise_eta1(masked_poly* a, const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)], uint8_t nonce);
void masked_poly_getnoise_eta2(masked_poly* a, const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)], uint8_t nonce);


void modulus_switch(Masked* x, unsigned q, unsigned shift);
void kyber_decryption(Masked* x, Masked* b);


/* PolyComp */
int kyber_poly_comp_hybrid(Masked* masked_poly, uint16_t* poly);


/* DEBUG */


void print_masked_arith(Masked* x, int q);
void print_masked_bool(Masked* y);
void print_A_table(Masked* t, unsigned p, unsigned q);
void print_masked_poly_arith(masked_poly* x, int q);
void print_masked_poly_bool(masked_poly* x);
void print_masked_arith_poly(Masked* x, const unsigned SIZE);
void print_masked_bool_poly(Masked* x, const unsigned SIZE);
void print_bitstring(uint8_t* bs, int size);
void unmask_bitstring(uint8_t* bs, int size);




#endif