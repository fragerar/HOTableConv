#ifndef GADGETS_H
#define GADGETS_H

#include <stdint.h>
#include "SABER_params.h"


#ifndef MASKING_ORDER
#define MASKING_ORDER 5
#endif

typedef struct Masked {uint16_t shares[MASKING_ORDER+1];} Masked;

void masked_indcpa_kem_enc(const uint8_t masked_m[SABER_KEYBYTES*(MASKING_ORDER+1)], const uint8_t seed_sp[SABER_NOISE_SEEDBYTES], const uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t ciphertext[SABER_BYTES_CCA_DEC]);
void masked_indcpa_kem_dec(const Masked s[SABER_L][SABER_N], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t m[SABER_KEYBYTES], uint16_t b[SABER_L][SABER_N], uint16_t cm[SABER_N]);
void masked_indcca_dec(uint8_t k[SABER_KEYBYTES*(MASKING_ORDER+1)], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t z[SABER_KEYBYTES], uint8_t pkh[32], uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], Masked masked_s[SABER_L][SABER_N]);


void masked_inner_product(const uint16_t b[SABER_L][SABER_N], const Masked s[SABER_L][SABER_N], Masked res[SABER_N]);
void masked_matrix_vector_mul(const uint16_t A[SABER_L][SABER_L][SABER_N], const Masked s[SABER_L][SABER_N], Masked res[SABER_L][SABER_N], int16_t transpose);
void masked_BS2POLmsg(const uint8_t masked_m[SABER_KEYBYTES*(MASKING_ORDER+1)], Masked data[SABER_N]);

void masked_poly_shift3(Masked poly[SABER_N], int k);
void masked_poly_shift6(Masked poly[SABER_N], int k);
void masked_gen_secret(Masked s[SABER_L][SABER_N], const uint8_t masked_coins[SABER_NOISE_SEEDBYTES*(MASKING_ORDER+1)]);
void masked_poly_decrypt(Masked poly[SABER_N]);


void optimized_convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q);

void shift(Masked* z, Masked* a, unsigned k);
void masked_shift(Masked* x, Masked* y, unsigned k, unsigned l);
void triple_shift(Masked* z, Masked* a, unsigned k);
void saber_decryption(Masked* x, Masked* b);


/* PolyComp*/
void convert_A2B_CGV14(Masked* x, Masked* y, unsigned k1, unsigned k2);
void convert_B2A_CGV14(Masked* x, Masked* y, unsigned k);
void poly_zero_test_table(Masked* poly, Masked* b, const unsigned SIZE);
void poly_zero_test_AB(Masked* poly, Masked* b, int q, const unsigned SIZE);
int saber_ct_zero_test(Masked* masked_poly);
void bool_poly_zero_test_AB(Masked* poly, Masked* b, int k, int logk, const unsigned SIZE);
int saber_ct_zero_test_boolean(Masked* masked_poly);


void convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q);
void sec_mult(Masked* a, Masked* b, Masked* c, unsigned q);
void sec_and(Masked* a, Masked* b, Masked* res, int k);
void arithmetic_refresh(Masked* x, unsigned q);
void boolean_refresh(Masked* x, unsigned k);
void linear_arithmetic_refresh(Masked* x, unsigned q);
void linear_boolean_refresh(Masked* x, unsigned k);
void exponential_B2A(Masked* x, Masked *y);
void print_masked_arith(Masked* x, int q);
void print_masked_bool(Masked* y);
void print_masked_arith_poly(Masked x[SABER_N], int q);
void print_masked_bool_poly(Masked x[SABER_N]);
void unmask_bitstring(uint8_t* bs, int size);


#endif