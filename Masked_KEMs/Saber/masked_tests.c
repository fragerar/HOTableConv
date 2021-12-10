#include "gadgets.h"
#include "api.h"
#include "poly.h"
#include "poly_mul.h"
#include "random.h"
#include "SABER_indcpa.h"
#include "pack_unpack.h"

#include "fips202.h"

void table_convert_1bit_BA_table(Masked* x, Masked* y){
  uint32_t T[MASKING_ORDER+1];
  uint32_t reduction_mask = 0x1FFF1FFF;
  uint32_t r;

  T[0] = 0x00010000;
  for(int i=1; i < MASKING_ORDER+1; ++i) T[i] = 0;

  for(int i=0; i < MASKING_ORDER; ++i){
    for(int j=0; j < MASKING_ORDER+1; ++j){
      T[j] = (T[j] >> (16*(x->shares[i]))) | (T[j] << (16*(x->shares[i])));
    }
    for(int j=0; j < MASKING_ORDER+1; ++j){
      r = rand32()&reduction_mask;
      T[j] = (T[j] + r)&reduction_mask;
      T[MASKING_ORDER] = (T[MASKING_ORDER] + SABER_Q - r)&reduction_mask;
    }
  }
  for(int i=0; i < MASKING_ORDER+1; ++i){
    y->shares[i] = (T[i] >> (16*(x->shares[MASKING_ORDER])))&0x1FFF;
  }
  linear_arithmetic_refresh(y, SABER_Q);
}

void random_masked_poly_mod_q(Masked poly[SABER_N]){
  for(int i = 0; i < SABER_N; ++i){
    for(int j = 0; j < MASKING_ORDER+1; ++j){
      poly[i].shares[j] = rand16()%(1<<SABER_EQ);
    }
  }
}

void random_masked_poly_mod_p(Masked poly[SABER_N]){
  for(int i = 0; i < SABER_N; ++i){
    for(int j = 0; j < MASKING_ORDER+1; ++j){
      poly[i].shares[j] = rand16()%(1<<SABER_EP);
    }
  }
}

void print_poly(uint16_t poly[SABER_N], int q){
  for(int i = 0; i < 10; ++i){
    printf("%u ", poly[i]%q);
  }
  printf("\n");
}

void unmask_arith(Masked m_poly[SABER_N], uint16_t poly[SABER_N], int Q){
  uint16_t acc;
  for(int i=0; i < SABER_N; ++i){
    acc = 0;
    for(int j=0; j < MASKING_ORDER+1; ++j){
      acc += m_poly[i].shares[j];
    }
    poly[i] = acc%Q;
  }
} 

void test_gen_secret(){
  Masked masked_s[SABER_L][SABER_N];
  uint16_t s[SABER_L][SABER_N];
  uint16_t comp[SABER_L][SABER_N];
  uint8_t r;
  uint8_t seed_sp[SABER_NOISE_SEEDBYTES];
  uint8_t masked_seed_sp[SABER_NOISE_SEEDBYTES*(MASKING_ORDER+1)];
  for(int i=0; i < SABER_NOISE_SEEDBYTES; ++i){
    seed_sp[i] = (uint8_t) rand16();
    masked_seed_sp[i] = seed_sp[i];
    for(int j=1; j < MASKING_ORDER+1; ++j){
      r = (uint8_t) rand16();
      masked_seed_sp[i+j*(SABER_NOISE_SEEDBYTES)] = r;
      masked_seed_sp[i] ^= r;
    }
  }


  masked_gen_secret(masked_s, masked_seed_sp);
  GenSecret(s, seed_sp);

  for(int i=0; i < SABER_L; ++i){
    for(int j=0; j < SABER_N; ++j){
      comp[i][j] = masked_s[i][j].shares[0];
      s[i][j] = s[i][j]%SABER_Q;
      for(int k=1; k < MASKING_ORDER+1; ++k){
        comp[i][j] = (comp[i][j] + masked_s[i][j].shares[k])%SABER_Q;
      }
    }
  }

  for(int i=0; i < SABER_L; ++i){
    for(int j=0; j < SABER_N; ++j){
      if (s[i][j] != comp[i][j]){
        printf("Test gen secret failed (%i, %i, %u, %u)\n", i, j, s[i][j], comp[i][j]);
        return;
      }
    }
  }

  printf("Test gen secret OK\n");

}


void test_shake128(){
  int SIZE_IN  = 100;
  int SIZE_OUT = 200;
  uint8_t r;
  uint8_t buf[SIZE_IN];
  uint8_t masked_buf[SIZE_IN*(MASKING_ORDER+1)];
  uint8_t digest[SIZE_OUT];
  uint8_t masked_digest[SIZE_OUT*(MASKING_ORDER+1)];

  uint8_t comp[SIZE_OUT];

  for(int i=0; i < SIZE_IN; ++i) buf[i] = (uint8_t)rand16();

  for(int i=0; i < SIZE_IN; ++i){
    masked_buf[i] = buf[i];
    for(int j=1; j < MASKING_ORDER+1; ++j){
      r = (uint8_t)rand16();
      masked_buf[i + j*SIZE_IN]  = r;
      masked_buf[i            ] ^= r;
    }
  }

  shake128(digest, SIZE_OUT, buf, SIZE_IN);
  shake128_masked(masked_digest, SIZE_OUT, masked_buf, SIZE_IN);

  for(int i=0; i < SIZE_OUT; ++i){
    comp[i] = masked_digest[i];
    for(int j=1; j < MASKING_ORDER+1; ++j){
      comp[i] ^= masked_digest[i + j*SIZE_OUT];
    }
    if (comp[i] != digest[i]){
      printf("Test shake128 failed (%i, %X, %X)\n", i, comp[i], digest[i]);
      return;
    }
  } 
  printf("Test shake128 OK\n");
}

void test_sha256(){
  int SIZE_IN = 123;
  uint8_t r;
  uint8_t buf[SIZE_IN];
  uint8_t masked_buf[SIZE_IN*(MASKING_ORDER+1)];
  uint8_t digest[32];
  uint8_t masked_digest[32*(MASKING_ORDER+1)];

  uint8_t comp[32];

  for(int i=0; i < SIZE_IN; ++i) buf[i] = (uint8_t)rand16();

  for(int i=0; i < SIZE_IN; ++i){
    masked_buf[i] = buf[i];
    for(int j=1; j < MASKING_ORDER+1; ++j){
      r = (uint8_t)rand16();
      masked_buf[i + j*SIZE_IN]  = r;
      masked_buf[i            ] ^= r;
    }
  }

  sha3_256(digest, buf, SIZE_IN);
  sha3_256_masked(masked_digest, masked_buf, SIZE_IN);

  for(int i=0; i < 32; ++i){
    comp[i] = masked_digest[i];
    for(int j=1; j < MASKING_ORDER+1; ++j){
      comp[i] ^= masked_digest[i + j*32];
    }
    if (comp[i] != digest[i]){
      printf("Test sha256 failed (%i, %X, %X)\n", i, comp[i], digest[i]);
      return;
    }
  } 
  printf("Test sha256 OK\n");

}


void test_sha512(){
  int SIZE_IN = 123;
  uint8_t r;
  uint8_t buf[SIZE_IN];
  uint8_t masked_buf[SIZE_IN*(MASKING_ORDER+1)];
  uint8_t digest[64];
  uint8_t masked_digest[64*(MASKING_ORDER+1)];

  uint8_t comp[64];

  for(int i=0; i < SIZE_IN; ++i) buf[i] = (uint8_t)rand16();

  for(int i=0; i < SIZE_IN; ++i){
    masked_buf[i] = buf[i];
    for(int j=1; j < MASKING_ORDER+1; ++j){
      r = (uint8_t)rand16();
      masked_buf[i + j*SIZE_IN]  = r;
      masked_buf[i            ] ^= r;
    }
  }

  sha3_512(digest, buf, SIZE_IN);
  sha3_512_masked(masked_digest, masked_buf, SIZE_IN);

  for(int i=0; i < 64; ++i){
    comp[i] = masked_digest[i];
    for(int j=1; j < MASKING_ORDER+1; ++j){
      comp[i] ^= masked_digest[i + j*64];
    }
    if (comp[i] != digest[i]){
      printf("Test sha512 failed (%i, %X, %X)\n", i, comp[i], digest[i]);
      return;
    }
  } 
  printf("Test sha512 OK\n");

}

void test_masked_decryption(){
  uint8_t m[SABER_KEYBYTES] = {0xFA, 0xDC, 0xAF, 0xE0}; 
  uint8_t m2[SABER_KEYBYTES] = {0x00}; 
  uint8_t m3[SABER_KEYBYTES*(MASKING_ORDER+1)] = {0x00}; 
  uint8_t comp[SABER_KEYBYTES];
  uint8_t seed_sp[SABER_NOISE_SEEDBYTES];
  uint8_t sk[SABER_INDCPA_SECRETKEYBYTES];
  uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES];
  uint8_t ciphertext[SABER_BYTES_CCA_DEC];
	uint16_t s[SABER_L][SABER_N];
  uint16_t r;
  Masked masked_s[SABER_L][SABER_N];

  for(int i=0; i < SABER_NOISE_SEEDBYTES; ++i) seed_sp[i] = (uint8_t) rand16();

  indcpa_kem_keypair(pk, sk);
  
	BS2POLVECq(sk, s);

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

  indcpa_kem_enc(m, seed_sp, pk, ciphertext);
  indcpa_kem_dec(sk, ciphertext, m2);

  for(int i=0; i < SABER_KEYBYTES; ++i) printf("%X ", m2[i]);
  printf("\n");
  uint16_t b[SABER_L][SABER_N]; 
  uint16_t cm[SABER_N];

  masked_indcpa_kem_dec(masked_s, ciphertext, m3, b, cm);

  for(int i=0; i < SABER_KEYBYTES; ++i){
    comp[i] = m3[i];
    for(int j = 1; j < MASKING_ORDER+1; ++j){
      comp[i] ^= m3[i+j*SABER_KEYBYTES];
    }
    if (comp[i] != m2[i]){
      printf("Test masked decrypt failed (%i, %X, %X)\n", i, comp[i], m3[i]);
      return;
    }
  }

  for(int i=0; i < SABER_KEYBYTES; ++i) printf("%X ", comp[i]);
  printf("\n");
  
  printf("Test masked decrypt OK\n");

}


void test_masked_CCA(){
  uint8_t k[SABER_KEYBYTES], k2[SABER_KEYBYTES];
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

  printf("Masked Kem DEC\n");
  masked_indcca_dec(mk, ciphertext, z, pkh, pk, masked_s);
  unmask_bitstring(mk, 32);
  printf("Kem DEC\n");
  crypto_kem_dec(k2, ciphertext, sk);
  for(int i=0; i < 32; ++i) printf("%X ",k2[i]);
  printf("\n");
}


int main(){
  srand(1);
  test_masked_CCA();
}