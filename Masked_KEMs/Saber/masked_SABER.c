#include <string.h>
#include <stdint.h>
#include "SABER_indcpa.h"
#include "poly.h"
#include "pack_unpack.h"
#include "poly_mul.h"
#include "rng.h"
#include "fips202.h"
#include "SABER_params.h"

#include "gadgets.h"


#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))


void masked_indcpa_kem_dec(const Masked masked_s[SABER_L][SABER_N], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t m[SABER_KEYBYTES*(MASKING_ORDER+1)], uint16_t b[SABER_L][SABER_N], uint16_t cm[SABER_N])
{

	Masked masked_v[SABER_N];
	int i;
	BS2POLVECp(ciphertext, b);
	masked_inner_product(b, masked_s, masked_v);
	BS2POLT(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, cm);


	for (i = 0; i < SABER_N; i++)
	{
		masked_v[i].shares[0] = (masked_v[i].shares[0] + h2 - (cm[i] << (SABER_EP - SABER_ET)))%(1<<SABER_EP);
	}

  masked_poly_decrypt(masked_v);

  uint16_t v[SABER_N];
  for(int i=0; i < SABER_N; ++i){
    v[i] = masked_v[i].shares[0];
    for(int j=1; j < MASKING_ORDER+1; ++j) v[i] = (v[i] ^ masked_v[i].shares[j]);
  }
  
	memset(m, 0, SABER_KEYBYTES*(MASKING_ORDER+1));
	for (int j = 0; j < SABER_KEYBYTES; j++)
	{
		for (i = 0; i < 8; i++)
		{
			for(int k=0; k < MASKING_ORDER+1; ++k) m[j+k*SABER_KEYBYTES] = m[j+k*SABER_KEYBYTES] | (((masked_v[j * 8 + i].shares[k]) & 0x01) << i);
		}
	}
}


void masked_indcpa_kem_enc_masked_output(const uint8_t masked_m[SABER_KEYBYTES*(MASKING_ORDER+1)], const uint8_t masked_seed_sp[SABER_NOISE_SEEDBYTES*(MASKING_ORDER+1)], const uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], Masked masked_bp[SABER_L][SABER_N], Masked masked_vp[SABER_N])
{
	uint16_t A[SABER_L][SABER_L][SABER_N];
	Masked masked_sp[SABER_L][SABER_N];
	Masked masked_mp[SABER_N];
	uint16_t b[SABER_L][SABER_N];
	int i, j;
	const uint8_t *seed_A = pk + SABER_POLYVECCOMPRESSEDBYTES;

	GenMatrix(A, seed_A);  
  
  masked_gen_secret(masked_sp, masked_seed_sp);

  masked_matrix_vector_mul(A, masked_sp, masked_bp, 0);
  

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			masked_bp[i][j].shares[0] = (masked_bp[i][j].shares[0] + h1)%(SABER_Q);
		}
	}


	BS2POLVECp(pk, b);

  masked_inner_product(b, masked_sp, masked_vp);

  masked_BS2POLmsg(masked_m, masked_mp);

	for (i = 0; i < SABER_N; i++)
	{
    for(int j=0; j < MASKING_ORDER+1; ++j) masked_vp[i].shares[j] = (masked_vp[i].shares[j]-masked_mp[i].shares[j])%(1<<SABER_EP); 
		masked_vp[i].shares[0] = (masked_vp[i].shares[0] + h1)%(1<<SABER_EP); 
	}
}


void masked_indcca_dec(uint8_t k[SABER_KEYBYTES*(MASKING_ORDER+1)], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t z[SABER_KEYBYTES], uint8_t pkh[32], uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], Masked masked_s[SABER_L][SABER_N]){

  uint8_t buf[2*SABER_KEYBYTES*(MASKING_ORDER+1)];
  uint8_t m[SABER_KEYBYTES*(MASKING_ORDER+1)]; 
  uint8_t kr[64*(MASKING_ORDER+1)];
  uint8_t masked_seed[32*(MASKING_ORDER+1)];
  uint16_t b[SABER_L][SABER_N]; Masked masked_bp[SABER_L][SABER_N]; 
  uint16_t cm[SABER_N]; Masked masked_cm[SABER_N];
  int zero_bit;
  masked_indcpa_kem_dec(masked_s, ciphertext, m, b, cm); 
  Masked cmp[(SABER_L+1)*SABER_N];


  for(int i=0; i < 32; ++i){
    buf[i     ] =  m[i];
    buf[i + 32] = pkh[i];
  }
  
  for(int k=1; k < MASKING_ORDER+1; ++k){
    for(int i=0; i < 32; ++i){
      buf[i + k*64   ] = m[i + k*32];
      buf[i + k*64+32] = 0;
    }
  }  

  sha3_512_masked(kr, buf, 64);

  for(int k=0; k < MASKING_ORDER+1; ++k){
    for(int i=0; i < 32; ++i){
      masked_seed[i + k*32] = kr[i + 32 + k*64];
    }
  }

  masked_indcpa_kem_enc_masked_output(m, masked_seed, pk, masked_bp, masked_cm);
  
  for(int i=0; i < SABER_L; ++i){
    for(int j=0; j < SABER_N; ++j){
      convert_A2B_CGV14(&(masked_bp[i][j]), cmp + i*SABER_N + j, 13, 13);
      for(int k=0; k < MASKING_ORDER+1; ++k) cmp[i*SABER_N + j].shares[k] = (cmp[i*SABER_N + j].shares[k] >> 3)&(1023);
      cmp[i*SABER_N + j].shares[0] = (cmp[i*SABER_N + j].shares[0] ^ b[i][j])&((1<<10)-1); 
    }
  }
  for(int i=0; i < SABER_N; ++i){
    convert_A2B_CGV14(&(masked_cm[i]), cmp + SABER_L*SABER_N + i, 10, 10);
    for(int k=0; k < MASKING_ORDER+1; ++k) cmp[SABER_L*SABER_N + i].shares[k] = (cmp[SABER_L*SABER_N + i].shares[k] >> 6)&15;
    cmp[SABER_L*SABER_N + i].shares[0] = (cmp[SABER_L*SABER_N + i].shares[0] ^ cm[i])&((1<<4)-1);  
  }

  zero_bit=saber_ct_zero_test_boolean(cmp);
  
  sha3_256(kr + 32, ciphertext, SABER_BYTES_CCA_DEC);
  for(int k=1; k < MASKING_ORDER+1; ++k){
    for(int i=0; i < 32; ++i){
      kr[i + 32 + k*64] = 0;
    }
  }

  for(int i=0; i < 32; ++i) kr[i+32] ^= (zero_bit-1) & (kr[i+32] ^ z[i]); // if zero_bit == 1 replace h(c) by z

  sha3_256_masked(k, kr, 64);
}

