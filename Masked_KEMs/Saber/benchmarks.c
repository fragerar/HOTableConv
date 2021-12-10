#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#include "gadgets.h"
#include "cpucycles.h"
#include "random.h"
#include "SABER_indcpa.h"
#include "SABER_params.h"
#include "api.h"
#include "pack_unpack.h"

#ifndef ITER
#define ITER 1000
#endif

uint64_t start, stop;

void benchmark_unmasked(){

  uint8_t k[SABER_KEYBYTES],k2[SABER_KEYBYTES];
  uint8_t ciphertext[SABER_BYTES_CCA_DEC];
  uint8_t pk[SABER_PUBLICKEYBYTES];
  uint8_t sk[SABER_SECRETKEYBYTES];


  crypto_kem_keypair(pk, sk);
  crypto_kem_enc(ciphertext, k, pk);

  
  start = cpucycles();
  for(int i=0; i < 10*ITER; i++) crypto_kem_dec(k2, ciphertext, sk);
  stop = cpucycles();
  printf("Avg speed unmasked decaps: %f cycles.\n", (double)(stop-start)/(10*ITER));

}

void benchmark_decaps(){
  uint8_t k[SABER_KEYBYTES];
  uint8_t mk[SABER_KEYBYTES*(MASKING_ORDER+1)];
  uint8_t ciphertext[SABER_BYTES_CCA_DEC];
  uint8_t z[SABER_KEYBYTES];
  uint8_t pkh[32];
  uint8_t pk[SABER_PUBLICKEYBYTES];
  uint8_t sk[SABER_SECRETKEYBYTES];
	uint16_t s[SABER_L][SABER_N];
  uint16_t r;
  Masked masked_s[SABER_L][SABER_N];

  crypto_kem_keypair(pk, sk);

 	BS2POLVECq(sk, s);

  for(int i=0; i < 32; ++i){
    pkh[i] = sk[SABER_SECRETKEYBYTES - 64 + i];
    z[i]   = sk[SABER_SECRETKEYBYTES - 32 + i];
  }

  for(int i=0; i < SABER_L; ++i){
    for(int j=0; j < SABER_N; ++j){
      masked_s[i][j].shares[0] = s[i][j];
      for(int k=1; k < MASKING_ORDER+1; ++k) {
        r = rand16(); 
        masked_s[i][j].shares[0] = (masked_s[i][j].shares[0] + SABER_Q - r)%SABER_Q;
        masked_s[i][j].shares[k] = r;
      }
    }
  }
  crypto_kem_enc(ciphertext, k, pk);


  start = cpucycles();
  for(int i=0; i < ITER; i++) masked_indcca_dec(mk, ciphertext, z, pkh, pk, masked_s);
  stop = cpucycles();
  printf("Avg speed decaps: %f cycles.\n", (double)(stop-start)/ITER);
}


int main(){
  printf("Order: %i, rng mode: %i\n", MASKING_ORDER, RNG_MODE);
  //benchmark_unmasked();
  benchmark_decaps();
  printf("\n");
  return 0;
}
