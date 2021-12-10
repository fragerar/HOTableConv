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


static void test_CCA_dec(){
  printf("Test CCA Dec\n");
  unsigned char pk[KYBER_PUBLICKEYBYTES], sk[KYBER_SECRETKEYBYTES];
  uint8_t c[KYBER_INDCPA_BYTES];

  uint8_t ss[32], ss2[32], ss3[32*(KYBER_MASKING_ORDER+1)];
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

  crypto_kem_dec(ss2, c, sk);
  printf("SharedSecret unmasked: "); print_bitstring(ss2, KYBER_SYMBYTES);
  masked_crypto_kem_dec(ss3, c, &mskpv, pk, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, masked_z);

  printf("SharedSecret   masked: "); unmask_bitstring(ss3, KYBER_SYMBYTES);

}

int main()
{
  srand(time(0));
  test_CCA_dec(); 

}
