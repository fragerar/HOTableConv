#include "gadgets.h"

#include "symmetric.h"

#include <math.h>

void encode_message(const uint8_t m[(KYBER_N/8)*(KYBER_MASKING_ORDER+1)], masked_poly* y){
  /* m is a boolean masking of the message*/
  
  Masked t1,t2;
  for(int i=0; i < KYBER_N/8; ++i){
    for(int j=0; j < 8; ++j){
      for(int k=0; k < KYBER_MASKING_ORDER+1; ++k) t1.shares[k] = (m[i+k*(KYBER_N/8)]>>j)&1; 
      convert_B2A(&t1, &t2, 1, KYBER_Q);
      for(int k=0; k < KYBER_MASKING_ORDER+1; ++k) (y->poly_shares[k]).coeffs[i*8+j] = (t2.shares[k]*((KYBER_Q+1)/2))%KYBER_Q;
    }
  }
}


void CBD(Masked* a, Masked* b, Masked* y, int eta){
  Masked h_a, h_b;
  Masked t1, t2;

  for(int j=0; j < KYBER_MASKING_ORDER+1; ++j) t1.shares[j] = (a->shares[j])&1;
  convert_B2A(&t1, &h_a, 1, KYBER_Q);
  for(int i=1; i < eta; ++i){
    for(int j=0; j < KYBER_MASKING_ORDER+1; ++j) t1.shares[j] = (a->shares[j] >> i)&1;
    convert_B2A(&t1, &t2, 1, KYBER_Q);
    for(int j=0; j < KYBER_MASKING_ORDER+1; ++j) h_a.shares[j] = (h_a.shares[j] + t2.shares[j])%KYBER_Q;
  }

  for(int j=0; j < KYBER_MASKING_ORDER+1; ++j) t1.shares[j] = (b->shares[j])&1;
  convert_B2A(&t1, &h_b, 1, KYBER_Q);
  for(int i=1; i < eta; ++i){
    for(int j=0; j < KYBER_MASKING_ORDER+1; ++j) t1.shares[j] = (b->shares[j] >> i)&1;
    convert_B2A(&t1, &t2, 1, KYBER_Q);
    for(int j=0; j < KYBER_MASKING_ORDER+1; ++j) h_b.shares[j] = (h_b.shares[j] + t2.shares[j])%KYBER_Q;
  }

  for(int i =0; i < KYBER_MASKING_ORDER+1; ++i){
    y->shares[i] = (h_a.shares[i] - h_b.shares[i])%KYBER_Q;
  }
}


void masked_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES*(KYBER_MASKING_ORDER+1)], uint8_t nonce){
  unsigned int i, j;
  uint8_t extkey[(KYBER_SYMBYTES+1)*(KYBER_MASKING_ORDER+1)];

  for(i = 0; i < KYBER_MASKING_ORDER+1; ++i){
    for(j=0; j<KYBER_SYMBYTES; j++)
      extkey[j+i*(KYBER_SYMBYTES+1)] = key[j+i*(KYBER_SYMBYTES)];
    extkey[(KYBER_SYMBYTES)+i*(KYBER_SYMBYTES+1)] = 0;
  }
  extkey[KYBER_SYMBYTES] = nonce;
  shake256_masked(out, outlen, extkey, KYBER_SYMBYTES+1);
}

void masked_hash_h(uint8_t h_masked[32 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen){
  sha3_256_masked(h_masked, in_masked, inlen);
}
void masked_hash_g(uint8_t h_masked[64 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen){
  sha3_512_masked(h_masked, in_masked, inlen);
}

void masked_kdf(uint8_t h_masked[32 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen){
  shake256_masked(h_masked, 32, in_masked, inlen);
}


void masked_poly_getnoise_eta1(masked_poly* a, const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)], uint8_t nonce){
#if KYBER_ETA1 == 3
  Masked a1, a2, a3, a4, b1, b2, b3, b4, y1, y2, y3, y4;
  uint8_t buf[(KYBER_ETA1*KYBER_N/4) * (KYBER_MASKING_ORDER + 1)];
  masked_prf(buf, KYBER_ETA1*KYBER_N/4, masked_coins, nonce);

  uint32_t t;
  
  for(int i=0; i < KYBER_N; i+=4){
    
    for(int j = 0; j < KYBER_MASKING_ORDER+1; ++j){
      t = (((uint32_t)buf[3*i/4+2+j*(KYBER_ETA1*KYBER_N/4)])<<16) | (((uint32_t)buf[3*i/4+1 + j*(KYBER_ETA1*KYBER_N/4)])<<8) | ((uint32_t)buf[3*i/4 + j*(KYBER_ETA1*KYBER_N/4)]);

      a1.shares[j] = ((t>> 0)&7);
      b1.shares[j] = ((t>> 3)&7);
      a2.shares[j] = ((t>> 6)&7);
      b2.shares[j] = ((t>> 9)&7);
      a3.shares[j] = ((t>>12)&7);
      b3.shares[j] = ((t>>15)&7);
      a4.shares[j] = ((t>>18)&7);
      b4.shares[j] = ((t>>21)&7);
    }
    CBD(&a1, &b1, &y1, KYBER_ETA1);
    CBD(&a2, &b2, &y2, KYBER_ETA1);
    CBD(&a3, &b3, &y3, KYBER_ETA1);
    CBD(&a4, &b4, &y4, KYBER_ETA1);

    for(int j = 0; j < KYBER_MASKING_ORDER+1; ++j) {
      (a->poly_shares[j]).coeffs[i+0] = y1.shares[j];
      (a->poly_shares[j]).coeffs[i+1] = y2.shares[j];
      (a->poly_shares[j]).coeffs[i+2] = y3.shares[j];
      (a->poly_shares[j]).coeffs[i+3] = y4.shares[j];
    }
  }
#else
  masked_poly_getnoise_eta2(a, masked_coins, nonce);
#endif
}


void masked_poly_getnoise_eta2(masked_poly* a, const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)], uint8_t nonce){
#if KYBER_ETA2 == 2
  Masked a1, a2, a3, a4, a5, a6, a7, a8, b1, b2, b3, b4, b5, b6, b7, b8, y1, y2, y3, y4, y5, y6, y7, y8;
  uint8_t buf[(KYBER_ETA2*KYBER_N/4) * (KYBER_MASKING_ORDER + 1)];
  masked_prf(buf, KYBER_ETA1*KYBER_N/4, masked_coins, nonce);


  uint32_t t;
  
  for(int i=0; i < KYBER_N; i+=8){
    
    for(int j = 0; j < KYBER_MASKING_ORDER+1; ++j){
      t = (((uint32_t)buf[i/2+3 + j*(KYBER_ETA2*KYBER_N/4)])<<24)
        | (((uint32_t)buf[i/2+2 + j*(KYBER_ETA2*KYBER_N/4)])<<16)
        | (((uint32_t)buf[i/2+1 + j*(KYBER_ETA2*KYBER_N/4)])<<8) 
        |  ((uint32_t)buf[i/2+0 + j*(KYBER_ETA2*KYBER_N/4)]);

      a1.shares[j] = ((t>> 0)&3); b1.shares[j] = ((t>> 2)&3);
      a2.shares[j] = ((t>> 4)&3); b2.shares[j] = ((t>> 6)&3);
      a3.shares[j] = ((t>> 8)&3); b3.shares[j] = ((t>>10)&3);
      a4.shares[j] = ((t>>12)&3); b4.shares[j] = ((t>>14)&3);

      a5.shares[j] = ((t>>16)&3); b5.shares[j] = ((t>>18)&3);
      a6.shares[j] = ((t>>20)&3); b6.shares[j] = ((t>>22)&3);
      a7.shares[j] = ((t>>24)&3); b7.shares[j] = ((t>>26)&3);
      a8.shares[j] = ((t>>28)&3); b8.shares[j] = ((t>>30)&3);
    }
    CBD(&a1, &b1, &y1, KYBER_ETA2);
    CBD(&a2, &b2, &y2, KYBER_ETA2);
    CBD(&a3, &b3, &y3, KYBER_ETA2);
    CBD(&a4, &b4, &y4, KYBER_ETA2);

    CBD(&a5, &b5, &y5, KYBER_ETA2);
    CBD(&a6, &b6, &y6, KYBER_ETA2);
    CBD(&a7, &b7, &y7, KYBER_ETA2);
    CBD(&a8, &b8, &y8, KYBER_ETA2);

    for(int j = 0; j < KYBER_MASKING_ORDER+1; ++j) {
      (a->poly_shares[j]).coeffs[i+0] = y1.shares[j];
      (a->poly_shares[j]).coeffs[i+1] = y2.shares[j];
      (a->poly_shares[j]).coeffs[i+2] = y3.shares[j];
      (a->poly_shares[j]).coeffs[i+3] = y4.shares[j];
      (a->poly_shares[j]).coeffs[i+4] = y5.shares[j];
      (a->poly_shares[j]).coeffs[i+5] = y6.shares[j];
      (a->poly_shares[j]).coeffs[i+6] = y7.shares[j];
      (a->poly_shares[j]).coeffs[i+7] = y8.shares[j];
    }
  }
#else
#endif
}


void modulus_switch(Masked* x, unsigned q, unsigned shift){
  /* 
   * Modulus switch between Z_q and Z_{2^shift} 
   * round((x<<shift)/q) = ((x<<(shift+1) + q1)//(2*q)
   * No overflow should appear for the values we use in the paper
   */
  int64_t temp;
  for(int i =0; i < KYBER_MASKING_ORDER+1; ++i) {
    temp = (int64_t)(x->shares[i]) << (shift+1);
    temp = (temp+q)/(2*q);
    x->shares[i] = (int)temp&((1<<shift)-1);
  }
}


unsigned switch_table[9] =  {6, 7, 7, 7, 8, 8, 8, 8, 8}; // Value of \ell in the paper

void kyber_decryption(Masked* x, Masked* b){
  unsigned l = switch_table[KYBER_MASKING_ORDER-1];
  modulus_switch(x, KYBER_Q, l);
  convert_2_l_to_1bit_bool(x, b, l);
}