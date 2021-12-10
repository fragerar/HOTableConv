#include "gadgets.h"
#include "random.h"
#include "poly_mul.h"
#include "fips202.h"

void convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q){

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


void masked_gen_secret(Masked s[SABER_L][SABER_N], const uint8_t masked_coins[SABER_NOISE_SEEDBYTES*(MASKING_ORDER+1)]){
  Masked t, arith;
  uint8_t masked_buf[SABER_L * SABER_POLYCOINBYTES * (MASKING_ORDER+1)];

  shake128_masked(masked_buf, SABER_L*SABER_POLYCOINBYTES, masked_coins, SABER_NOISE_SEEDBYTES);
  
  int offset;
  for(int i=0; i < SABER_L; ++i){
    #if SABER_MU == 8
    
    for(int j=0; j < SABER_N; ++j){
      offset = j+i*SABER_POLYCOINBYTES;
      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 0)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k]  = arith.shares[k];

      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 1)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k] += arith.shares[k];

      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 2)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k] += arith.shares[k];

      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 3)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k] += arith.shares[k];


      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 4)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k] -= arith.shares[k];

      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 5)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k] -= arith.shares[k];

      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 6)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k] -= arith.shares[k];

      for(int k=0; k < MASKING_ORDER+1; ++k) t.shares[k] = (masked_buf[offset + k*(SABER_POLYCOINBYTES*SABER_L)] >> 7)&1;
      convert_B2A(&t, &arith, 1, SABER_Q);
      for(int k=0; k < MASKING_ORDER+1; ++k) s[i][j].shares[k] -= arith.shares[k];
    }

    #endif
  }
}


void masked_poly_decrypt(Masked poly[SABER_N]){
  Masked t;
  for(int i=0; i < SABER_N; ++i){
    saber_decryption(&(poly[i]), &t);
    for(int j=0; j < MASKING_ORDER+1; ++j) poly[i].shares[j] = t.shares[j];
  }
}


void saber_decryption(Masked* x, Masked* b){
  Masked y;
  convert_A2B_CGV14(x, &y, SABER_EP, SABER_EP);
  for(int k=0; k < MASKING_ORDER+1; ++k) b->shares[k] = (y.shares[k] >> (SABER_EP-1))&1;
}


void masked_inner_product(const uint16_t b[SABER_L][SABER_N], const Masked s[SABER_L][SABER_N], Masked res[SABER_N]){
  uint16_t temp[SABER_N], temp_res[SABER_N];
  for(int k=0; k < MASKING_ORDER+1; ++k){
    for(int j=0; j < SABER_N; ++j) temp_res[j] = 0;
    for (int i=0; i < SABER_L; i++){
      for(int j=0; j < SABER_N; ++j) temp[j] = s[i][j].shares[k]; 
      poly_mul_acc(b[i], temp, temp_res);
    }
    for(int j=0; j < SABER_N; ++j) res[j].shares[k] = temp_res[j]; 
  }
}


void masked_matrix_vector_mul(const uint16_t A[SABER_L][SABER_L][SABER_N], const Masked s[SABER_L][SABER_N], Masked res[SABER_L][SABER_N], int16_t transpose)
{
  uint16_t temp[SABER_N], temp_res[SABER_N];
	for(int k=0; k < MASKING_ORDER+1; ++k){
    for (int i = 0; i < SABER_L; i++)
    {
      for(int j=0; j < SABER_N; ++j) temp_res[j] = 0;
      for (int j = 0; j < SABER_L; j++)
      { 
        for(int l=0; l < SABER_N; ++l) temp[l] = s[j][l].shares[k];
        if (transpose == 1)
        {
          poly_mul_acc(A[j][i], temp, temp_res);
        }
        else
        {
          poly_mul_acc(A[i][j], temp, temp_res);
        }	
      }
      for(int j=0; j < SABER_N; ++j) res[i][j].shares[k] = temp_res[j];
    }
  }
}


void masked_BS2POLmsg(const uint8_t m[SABER_KEYBYTES*(MASKING_ORDER+1)], Masked data[SABER_N]){
  for(int i=0; i < SABER_KEYBYTES; ++i){
    for(int j=0; j < 8; ++j){
      for(int k=0; k < MASKING_ORDER+1; ++k){
        data[i*8 + j].shares[k] = ((m[SABER_KEYBYTES*k+i] >> j)&0x1)<<(SABER_EP-1);
      }
    }
  }
}


void linear_refresh_masks(Masked* x, int q){
  uint16_t r;
  for(int i=1; i < MASKING_ORDER+1; ++i){
    r = rand16()%q;
    x->shares[i] = (x->shares[i] + r)%q;
    x->shares[0] = (x->shares[0] + q - r)%q;
  }
} 



