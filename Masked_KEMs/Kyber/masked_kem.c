#include "params.h"
#include "rng.h"
#include "masked_kem.h"
#include "symmetric.h"
#include "verify.h"
#include "indcpa.h"
#include "gadgets.h"


static unsigned mswitch(unsigned x, unsigned q_start, unsigned q_end){
  return (2*q_end*x+q_start)/(2*q_start);
}

static unsigned compress(unsigned x, unsigned q, unsigned d){
  return mswitch(x, q, 1<<d)%(1<<d);
}


int masked_crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const masked_polyvec* skpv, const unsigned char* pk, const unsigned char* pkh, const unsigned char* masked_z){

  size_t i;
  int check;
  uint8_t buf[2*KYBER_SYMBYTES*(KYBER_MASKING_ORDER+1)];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES*(KYBER_MASKING_ORDER+1)];
  Masked mct[KYBER_N*(KYBER_K+1)];
  uint8_t m[KYBER_INDCPA_MSGBYTES*(KYBER_MASKING_ORDER+1)];

  uint16_t poly_ct[KYBER_N*(KYBER_K+1)];
  uint8_t masked_coins[32*(KYBER_MASKING_ORDER+1)];

  polyvec bp;
  poly v;

  indcpa_masked_dec(m, ct, skpv);   

  for(i=0; i < 32; ++i){
    buf[i     ] =  m[i];
    buf[i + 32] = pkh[i];
  }
  
  for(int k=1; k < KYBER_MASKING_ORDER+1; ++k){
    for(i=0; i < 32; ++i){
      buf[i + k*64   ] = m[i + k*32];
      buf[i + k*64+32] = 0;
    }
  }  

  masked_hash_g(kr, buf, 2*KYBER_SYMBYTES);


  for(int k=0; k < KYBER_MASKING_ORDER+1; ++k){
    for(i=0; i < 32; ++i){
      masked_coins[i + k*32] = kr[i + 32 + k*64];
    }
  }

  indcpa_masked_enc_no_compress(mct, m, pk, masked_coins);

  unpack_ciphertext(&bp, &v, ct);
  for(i=0; i < KYBER_K; ++i){
    for(int j=0; j < KYBER_N; ++j){
      poly_ct[i*KYBER_N + j] = compress((bp.vec[i]).coeffs[j], KYBER_Q, 10);
    }
  } 
  for(i=0; i < KYBER_N; ++i) poly_ct[KYBER_K*KYBER_N + i] = compress(v.coeffs[i], KYBER_Q, 4);

  check = kyber_poly_comp_hybrid(mct, poly_ct);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  for(int k=1; k < KYBER_MASKING_ORDER+1; ++k){
    for(i=0; i < 32; ++i){
      kr[i + 32 + k*64] = 0;
    }
  }

  /* Overwrite pre-k with z on re-encryption failure */
  if (!check){
    for(i = 0; i < KYBER_SYMBYTES; ++i){
      for(int j=0; j < KYBER_MASKING_ORDER+1; ++j){
        kr[j*(2*KYBER_SYMBYTES) + i] = masked_z[j*(KYBER_SYMBYTES) + i];
      }
    }
  }

  /* hash concatenation of pre-k and H(c) to k */
  masked_kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}