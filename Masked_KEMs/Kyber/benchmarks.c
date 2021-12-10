#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include "params.h"
#include "indcpa.h"
#include "gadgets.h"
#include "fips202.h"
#include "kem.h"
#include "masked_kem.h"
#include "cpucycles.h"


#define ITER 100


uint64_t start, stop;

static void mask_bs(uint8_t* bs, uint8_t* obs, int size){
  uint8_t r;
  for(int i=0; i < size; ++i) obs[i] = bs[i];
  for(int k=1; k < KYBER_MASKING_ORDER+1; ++k){
    for(int i=0; i < size; ++i){
      r = (uint8_t)rand();
      obs[k*(size)+i]  = r;
      obs[                   i] ^= r;
    }
  }
}

void benchmark_ind_CCA_unmasked(){
  printf("Benchmarks unmasked CCA Dec\n");
  unsigned char pk[KYBER_PUBLICKEYBYTES], sk[KYBER_SECRETKEYBYTES];
  uint8_t c[KYBER_INDCPA_BYTES];
  uint8_t ss[32], ss2[32];

  crypto_kem_keypair(pk, sk);

  crypto_kem_enc(c, ss, pk);
  start = cpucycles();
  for(int i=0; i < 10*ITER; ++i){
    crypto_kem_dec(ss2, c, sk);  
  }
  stop = cpucycles();  
  printf("Avg speed unmasked INDCCA_DEC: %f cycles.\n", (double)(stop-start)/(10*ITER));
}

void benchmark_ind_CCA(){
  printf("Benchmarks CCA Dec\n");
  unsigned char pk[KYBER_PUBLICKEYBYTES], sk[KYBER_SECRETKEYBYTES];
  uint8_t c[KYBER_INDCPA_BYTES];
  uint8_t ss[32], ss3[32*(KYBER_MASKING_ORDER+1)];
  masked_polyvec mskpv;
  polyvec skpv;
  uint8_t masked_z[KYBER_SYMBYTES*(KYBER_MASKING_ORDER+1)];


  crypto_kem_keypair(pk, sk);

  unpack_sk(&skpv, sk);
  for(int i=0; i < KYBER_K; ++i){
    for(int j=0; j < KYBER_N; ++j){
      ((mskpv.vec_shares[i]).poly_shares[0]).coeffs[j] = skpv.vec[i].coeffs[j];
    }
  }

  for(int k=1; k < KYBER_MASKING_ORDER+1; ++k){
    for(int i=0; i < KYBER_K; ++i){
      for(int j=0; j < KYBER_N; ++j){
        ((mskpv.vec_shares[i]).poly_shares[k]).coeffs[j] = 0;
      }
    }
  }

  mask_bs(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, masked_z, KYBER_SYMBYTES);

  crypto_kem_enc(c, ss, pk);

  start = cpucycles();
  for(int i=0; i < ITER; ++i){
    masked_crypto_kem_dec(ss3, c, &mskpv, pk, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, masked_z);
  }
  stop = cpucycles();  
  printf("Avg speed INDCCA_DEC: %f cycles.\n", (double)(stop-start)/ITER);
}


int main(){
  printf("Benchmarks at order %i\n", KYBER_MASKING_ORDER);
  //benchmark_ind_CCA_unmasked();
  benchmark_ind_CCA();
}




